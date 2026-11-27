//! Spawning a ring-3 user domain from a flat code blob (PR-1.4).
//!
//! The bridge between the policy core and the hardware context: a lib
//! `Domain` (the identity the monitor audits and the gate snapshots)
//! plus per-domain page tables (PR-1.3) holding policy-mapped code
//! (RX), data (RW+NX), and stack (RW+NX) regions with real guard gaps
//! between them.
//!
//! Invariants:
//! - **Every region passes the ten-check policy first** — `map_region`
//!   is the only mapping path, so the user layout is gated exactly like
//!   any kernel-resident domain's memory.
//! - **Frames are pool-owned by the domain id**: a destroy
//!   (`pool.free_all_owned` + `Kernel::destroy_domain`) reclaims
//!   tables, pages, and the lib side in one sweep.
//! - **The blob never touches anything but its own code page**: it is
//!   copied through the direct map into the frame `map_region`
//!   allocated, before the first instruction of it can run.
//! - This module is unsafe-free: all raw access lives in `memops` and
//!   the allowlisted arch/sched modules.

use aegis_os::memory::AddressSpace;
use aegis_os::profile::DomainProfile;
use aegis_os::Kernel;

use crate::frames::FramePool;
use crate::memops;
use crate::mm::page_table::{MapError, PageTables, PoolSource};
use crate::mm::user_layout as layout;
use crate::sched::context::{UserContext, UserRun};

/// Why a spawn failed. All failures happen *before* any launch: either
/// the lib refused the domain, or the policy/pool refused a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// The lib refused the domain (duplicate id, table full, ...).
    Domain,
    /// The ten-check policy or the page-table walk refused a region.
    Map(MapError),
    /// The blob does not fit its code page.
    BlobTooLarge { len: usize, capacity: usize },
}

impl From<MapError> for SpawnError {
    fn from(e: MapError) -> Self {
        SpawnError::Map(e)
    }
}

/// Why building the exec image's tables failed. `CageViolation` is the
/// address policy: an exec'd image lives inside ITS OWN contract's
/// cage (`ExecLayout`, K22 — canonical for every earlier image, the
/// service cage for the package manager) — the ELF machinery honors
/// every header it was given, and the kernel's layout policy holds
/// where it always held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMapError {
    /// A PT_LOAD sits (even partially) outside the contract's image
    /// cage — the stack, trampoline, guard gaps, and everything above
    /// are kernel-provisioned and non-negotiable.
    CageViolation { vaddr: u64 },
    /// The ten-check policy or the page-table walk refused a region.
    Map(MapError),
}

impl From<MapError> for ExecMapError {
    fn from(e: MapError) -> Self {
        ExecMapError::Map(e)
    }
}

/// K22: the cage half of an exec, pure — every PT_LOAD must sit inside
/// `[layout.code_base, layout.cage_end)` (page-rounded extents). The
/// same function runs twice: as the pre-exec check (a plain refusal,
/// the old image untouched) and inside `exec_tables` (the mapper's own
/// gate — the pre-check is a courtesy, not a substitute).
pub fn exec_cage_check(
    plan: &aegis_os::elf::ExecPlan,
    contract: &layout::ExecLayout,
) -> Result<(), ExecMapError> {
    for seg in &plan.segments[..plan.n_segments] {
        let (first, last) = seg.page_range();
        if first < contract.code_base || last > contract.cage_end {
            return Err(ExecMapError::CageViolation { vaddr: seg.vaddr });
        }
    }
    Ok(())
}

/// Everything kmain needs to run one user domain: the lib identity,
/// the entry context, and the run state to install before launching.
pub struct UserSpawn {
    pub domain: u32,
    pub ctx: UserContext,
    pub run: UserRun,
}

/// Create lib domain `id`, build its page tables, map the canonical
/// user layout (code RX, data RW, stack RW), copy `blob` into the code
/// page and `data` into the data page, and assemble the launch context.
/// The kernel entries are installed in the fresh PML4 (shared kernel
/// half), and the gate snapshot is taken from the profile's syscall
/// mask — the same mask `create_domain` built the domain's live mask
/// from.
pub fn spawn_user_blob<const N: usize>(
    k: &mut Kernel<N>,
    pool: &mut FramePool<N>,
    id: u32,
    profile: DomainProfile,
    blob: &[u8],
    data: &[u8],
) -> Result<UserSpawn, SpawnError> {
    if blob.len() > layout::CODE_PAGES * 4096 {
        return Err(SpawnError::BlobTooLarge {
            len: blob.len(),
            capacity: layout::CODE_PAGES * 4096,
        });
    }
    if data.len() > layout::DATA_PAGES * 4096 {
        return Err(SpawnError::BlobTooLarge {
            len: data.len(),
            capacity: layout::DATA_PAGES * 4096,
        });
    }
    // Lib identity first (audit/accounting; the frame owner tag below
    // matches this id so a destroy reclaims everything at once).
    k.create_domain(id, profile)
        .map_err(|_| SpawnError::Domain)?;
    // Round J: the stdio triplet. fds 0/1/2 go to the runtime (the
    // console device alias lives behind fd 1), so the domain's own
    // pipe()/open() allocations begin at fd 3, Unix-style — the device
    // alias and the fd table can never collide. On a fresh domain this
    // cannot fail; the rollback below still covers the impossible
    // branch honestly.
    if k.reserve_stdio(id).is_err() {
        let _ = k.destroy_domain(id);
        return Err(SpawnError::Domain);
    }
    // N3: transactional from here on — the old code returned early on
    // any failure (PML4 alloc, a region map, pool exhaustion), leaving
    // the lib domain registered and frames owned by the id. Every
    // failure now rolls back every frame AND the lib identity (which
    // also clears the monitor state, F7) before returning.
    match build_user_tables(k, pool, id, blob, data, profile.quota_pages) {
        Ok((tables, space)) => {
            // Gate snapshot: the live mask starts as the profile's
            // mask, and a freshly created domain is never quarantined.
            let mask = profile.syscalls;
            Ok(UserSpawn {
                domain: id,
                ctx: UserContext::new(layout::CODE_BASE, layout::STACK_TOP),
                run: UserRun::new(tables, space, id, mask, false),
            })
        }
        Err(e) => {
            pool.free_all_owned(&mut k.frames, id);
            let _ = k.destroy_domain(id);
            Err(e)
        }
    }
}

/// The hardware half of a spawn: fresh tables, kernel half shared in,
/// layout mapped through the policy gate, blob/data copied in via the
/// direct map. Every frame it takes is pool-owned by `id`, so a single
/// `free_all_owned` (N3 rollback) reclaims it all.
fn build_user_tables<const N: usize>(
    k: &mut Kernel<N>,
    pool: &mut FramePool<N>,
    id: u32,
    blob: &[u8],
    data: &[u8],
    quota_pages: usize,
) -> Result<(PageTables, AddressSpace), SpawnError> {
    let mut src = PoolSource::new(pool, &mut k.frames, id);
    let mut tables = PageTables::new(&mut src)?;
    tables.install_kernel_entries();
    // Round N2: the spawn twin of the exec fix — the domain's quota is
    // its PROFILE's, not a hard-coded 16 (the same shape the round
    // flagged on the exec side; found while wiring that fix).
    let mut space = AddressSpace::new(quota_pages);
    tables.map_region(
        &mut space,
        layout::CODE_BASE,
        layout::CODE_PAGES * 4096,
        layout::code_flags(),
        &mut src,
    )?;
    tables.map_region(
        &mut space,
        layout::DATA_BASE,
        layout::DATA_PAGES * 4096,
        layout::data_flags(),
        &mut src,
    )?;
    tables.map_region(
        &mut space,
        layout::STACK_BASE,
        layout::STACK_PAGES * 4096,
        layout::stack_flags(),
        &mut src,
    )?;
    tables.map_region(
        &mut space,
        layout::TRAMPOLINE_BASE,
        layout::TRAMPOLINE_PAGES * 4096,
        layout::code_flags(),
        &mut src,
    )?;
    copy_into_frame(&tables, layout::CODE_BASE, blob);
    copy_into_frame(&tables, layout::DATA_BASE, data);
    copy_into_frame(&tables, layout::TRAMPOLINE_BASE, &layout::TRAMPOLINE);
    Ok((tables, space))
}

/// execve (ADR-0022 D4 / ADR-0003 slice 4): build the REPLACEMENT
/// image's tables from a validated ELF64 plan. The spawn twin for a
/// live domain: fresh PML4 with the kernel half shared in, every
/// PT_LOAD mapped AT ITS DECLARED vaddr with the header's
/// permissions, the fresh stack and signal trampoline provisioned at
/// their fixed addresses. The whole extent is zeroed EXPLICITLY
/// before the file bytes copy over its front — the pool scrubs freed
/// frames, but "bss is zero" is the syscall's CONTRACT, not a pool
/// implementation detail (the exec-target blob probes it live).
///
/// Every frame allocates under the caller's id via the same
/// `PoolSource` the spawn path uses, so a later `free_frames_of`
/// reclaims the new image exactly like the old one.
///
/// K22: the image runs under ITS OWN memory contract (`contract`) — the
/// registry names it per image. The canonical contract is the old
/// fixed layout ([CODE_BASE, STACK_BASE - 4096) for the image, the
/// stack at 0x408000, the trampoline at 0x40C000); the package
/// manager's service contract widens the image cage to 128 pages and
/// the stack to 64. Everything is taken from the layout — nothing in
/// here assumes the canonical addresses.
pub fn exec_tables<const N: usize>(
    k: &mut Kernel<N>,
    pool: &mut FramePool<N>,
    id: u32,
    plan: &aegis_os::elf::ExecPlan,
    image: &[u8],
    contract: &layout::ExecLayout,
    quota_pages: usize,
) -> Result<(PageTables, AddressSpace), ExecMapError> {
    exec_cage_check(plan, contract)?;
    let mut src = PoolSource::new(pool, &mut k.frames, id);
    let mut tables = PageTables::new(&mut src)?;
    tables.install_kernel_entries();
    // Round N2: the image's quota is the CALLER's live quota, not a
    // hard-coded 16 — every program was capped at 16 pages including
    // stack and trampoline, ignoring its profile.
    let mut space = AddressSpace::new(quota_pages);
    for seg in &plan.segments[..plan.n_segments] {
        let (first, last) = seg.page_range();
        let flags = if seg.writable {
            layout::data_flags()
        } else if seg.executable {
            layout::code_flags()
        } else {
            // Read-only data (rodata): PF_R alone — the validator
            // already refused W+X and zero-perm shapes.
            aegis_os::memory::MemFlags::READ
        };
        tables.map_region(&mut space, first, (last - first) as usize, flags, &mut src)?;
        zero_extent(&tables, first, last);
        let seg_bytes = &image[seg.offset as usize..(seg.offset + seg.filesz) as usize];
        copy_into_frame(&tables, seg.vaddr, seg_bytes);
    }
    tables.map_region(
        &mut space,
        contract.stack_base,
        contract.stack_pages * 4096,
        layout::stack_flags(),
        &mut src,
    )?;
    tables.map_region(
        &mut space,
        contract.trampoline_base,
        layout::TRAMPOLINE_PAGES * 4096,
        layout::code_flags(),
        &mut src,
    )?;
    copy_into_frame(&tables, contract.trampoline_base, &layout::TRAMPOLINE);
    Ok((tables, space))
}

/// Zero `[first, last)` — every page of the fresh image's segments,
/// INCLUDING the mid-page tails (bss). Called before the file bytes
/// copy over the front, so a segment's zero-fill does not depend on
/// the pool's scrub discipline: the zeroing is the loader's own act.
fn zero_extent(tables: &PageTables, first: u64, last: u64) {
    let mut page = first;
    while page < last {
        let Some(pa) = tables.translate(page) else {
            return; // unreachable: map_region just mapped this page
        };
        let mut off = 0u64;
        while off < 4096 {
            memops::write_u64(pa + off, 0);
            off += 8;
        }
        page += 4096;
    }
}

/// The frame half of a teardown: the ADR-0024 D2 shares-aware
/// reclaim — a frame another address space still maps is RELEASED,
/// not freed (the last holder frees, under the ORIGINAL owner's
/// tag); private frames free outright. NO lib-side removal happens
/// here. `destroy_user` = this + `destroy_domain` (the supervisor
/// path — the meta goes outright); the wait4 arm = this +
/// `exit_process` (the zombie stays for the parent to reap —
/// `destroy_domain` after a reap would kill the meta the parent is
/// about to read, found live in the slice-3 hunt).
#[cfg(not(test))]
pub fn free_frames_of<const N: usize>(k: &mut Kernel<N>, pool: &mut FramePool<N>, id: u32) {
    // The buffer is sized by the live owned count (no allocation).
    let owned = pool.owned_by(id);
    let mut buf = [const { None }; 1024];
    let buf = if owned <= buf.len() {
        &mut buf[..owned.max(1)]
    } else {
        &mut buf[..]
    };
    let freed = crate::mm::shares::reclaim_domain_frames(pool, &mut k.frames, id, buf);
    if freed != owned {
        // A short buffer or a cross-owner refusal leaked frames — the
        // loud place to catch it (the boot proof counts the reclaim).
        let mut b = [0u8; 20];
        crate::serial::write_str("[MM ] teardown domain ");
        crate::serial::write_str(crate::strutil::dec(u64::from(id), &mut b));
        crate::serial::write_str(": freed ");
        crate::serial::write_str(crate::strutil::dec(freed as u64, &mut b));
        crate::serial::write_str(" of ");
        crate::serial::write_str(crate::strutil::dec(owned as u64, &mut b));
        crate::serial::write_str(" owned frames\n");
    }
}

/// Free every frame the domain owns (tables + pages; the pool scrubs
/// each one) and withdraw the lib identity. The spawner's full
/// post-run cleanup, called from kmain after `resume_kernel`: frames,
/// then the lib removal (the supervisor path — no zombie; the
/// supervisor opted out of the wait protocol. The wait4 arm uses
/// `free_frames_of` + `exit_process` instead — the zombie stays).
#[cfg(not(test))]
pub fn destroy_user<const N: usize>(k: &mut Kernel<N>, pool: &mut FramePool<N>, id: u32) {
    free_frames_of(k, pool, id);
    let _ = k.destroy_domain(id);
}

/// Write `bytes` into the page mapped at `base` (zero-padded, one u64
/// at a time through the direct map). `base` must be a mapped region
/// start; the caller only ever passes layout bases whose regions were
/// just mapped.
///
/// Page-by-page (ADR-0029): a multi-page region's frames are NOT
/// physically contiguous — the pool allocates each page independently.
/// The old single-translate linear copy ran off the first frame's end
/// into whatever the pool held next (found live: the code region grew
/// to two pages, the blob crossed 4096 bytes, and the writer domain
/// died at its entry with a P=0 fetch fault — its page table frame had
/// been the spinner's overflow target). Translate EVERY page and copy
/// that page's slice.
fn copy_into_frame(tables: &PageTables, base: u64, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let page = base + (off / 4096) as u64 * 4096;
        let in_page = off % 4096;
        let Some(pa) = tables.translate(page) else {
            return; // unreachable: we just mapped this region
        };
        let chunk = core::cmp::min(4096 - in_page, bytes.len() - off);
        let mut o = 0usize;
        while o < chunk {
            let mut word = [0u8; 8];
            let n = core::cmp::min(8, chunk - o);
            word[..n].copy_from_slice(&bytes[off + o..off + o + n]);
            memops::write_u64(pa + (in_page + o) as u64, u64::from_le_bytes(word));
            o += n;
        }
        off += chunk;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_capacity_covers_the_examples() {
        // The proof blob crossed one page at ADR-0029 (4398 bytes);
        // two pages hold it with room for the TTY/shell proofs.
        const _: () = assert!(layout::CODE_PAGES * 4096 >= 128);
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use aegis_os::profile::service_profile;

    /// N3: a real host buffer standing in for the pool's physical
    /// memory (the runtime.rs FakePhys pattern): memops on the host is
    /// the identity map, so pool PAs are Vec addresses.
    struct Phys {
        _mem: Vec<u64>,
    }

    /// K22: 256 -> 4096 — the SERVICE contract's exec now provisions
    /// the manager's 2048-page (8 MiB) no_alloc stack in one call, and
    /// the pool must cover image + stack + trampoline (2080 frames).
    const N: usize = 4096;

    fn setup() -> (Kernel<N>, FramePool<N>, Phys) {
        // Page-align the backing buffer: the map path requires
        // page-aligned physical frames, and a Vec is only 8-aligned.
        let mem = vec![0u64; N * 512 + 1024];
        let base = ((mem.as_ptr() as u64) + 4095) & !4095u64;
        (
            Kernel::new_over_arena(),
            FramePool::new(base, memops::scrub_frame),
            Phys { _mem: mem },
        )
    }

    fn state<const M: usize>(k: &Kernel<M>, pool: &FramePool<M>) -> (usize, usize) {
        (k.frames.frames_in_use(), pool.owned_count())
    }

    /// N3: a duplicate id fails before any allocation — the baseline
    /// must be untouched.
    #[test]
    fn spawn_fails_cleanly_on_duplicate_id() {
        let (mut k, mut pool, _p) = setup();
        k.create_domain(7, service_profile()).unwrap();
        let b = state(&k, &pool);
        let r = spawn_user_blob(
            &mut k,
            &mut pool,
            7,
            service_profile(),
            &[0u8; 16],
            &[0u8; 4],
        );
        assert!(matches!(r, Err(SpawnError::Domain)));
        assert_eq!(state(&k, &pool), b);
    }

    /// N3: an oversized blob is refused before anything is allocated.
    #[test]
    fn spawn_fails_cleanly_when_blob_too_large() {
        let (mut k, mut pool, _p) = setup();
        let b = state(&k, &pool);
        let big = [0u8; layout::CODE_PAGES * 4096 + 1];
        let r = spawn_user_blob(&mut k, &mut pool, 7, service_profile(), &big, &[0u8; 4]);
        assert!(matches!(r, Err(SpawnError::BlobTooLarge { .. })));
        assert_eq!(state(&k, &pool), b);
        assert_eq!(k.domain_state(7), None);
    }

    /// N3: the heart of it — pool exhaustion at EVERY allocation point
    /// (measured, not assumed: a successful spawn takes `needed`
    /// frames; starving it by 1..=needed makes each successive
    /// allocation the failing one). After each failure: frames, owners
    /// and the domain table back to baseline, ballast fully recoverable.
    #[test]
    fn spawn_rolls_back_at_every_allocation_point() {
        // Measure what a successful spawn costs.
        let (mut k, mut pool, _p) = setup();
        spawn_user_blob(
            &mut k,
            &mut pool,
            7,
            service_profile(),
            &[0u8; 16],
            &[0u8; 4],
        )
        .unwrap();
        let needed = k.frames.frames_in_use();
        assert!(
            needed >= 4,
            "sanity: tables + regions cost frames (got {needed})"
        );
        // (k is simply shadowed by the loop's fresh bindings below)

        for deficit in 1..=needed {
            let (mut k, mut pool, _p) = setup();
            let ballast = N - (needed - deficit);
            for _ in 0..ballast {
                pool.alloc_for(&mut k.frames, 999).unwrap();
            }
            let r = spawn_user_blob(
                &mut k,
                &mut pool,
                7,
                service_profile(),
                &[0u8; 16],
                &[0u8; 4],
            );
            assert!(
                r.is_err(),
                "deficit {deficit}: the pool is short by exactly {deficit}"
            );
            assert_eq!(
                k.frames.frames_in_use(),
                ballast,
                "deficit {deficit}: spawn leaked frames"
            );
            assert_eq!(
                pool.owned_count(),
                ballast,
                "deficit {deficit}: spawn leaked owner tags"
            );
            assert_eq!(
                k.domain_state(7),
                None,
                "deficit {deficit}: the lib domain leaked"
            );
            let freed = pool.free_all_owned(&mut k.frames, 999);
            assert_eq!(freed, ballast, "deficit {deficit}: ballast recoverable");
            assert_eq!(k.frames.frames_in_use(), 0);
        }
    }

    // ── K22: the per-image memory contract ──

    /// A synthetic plan with the SHAPE of the package manager's image:
    /// text RX, read-only data (a guard page above), writable data (a
    /// guard page above that) — placed where a `SERVICE` image links.
    /// Returns the plan and the image bytes its offsets index into.
    fn service_shaped_plan() -> (aegis_os::elf::ExecPlan, Vec<u8>) {
        plan_of(&[
            (0x0040_0000, 0x2000, 0x2000, false, true),
            (0x0040_5000, 0x1000, 0x1000, false, false),
            (0x0040_8000, 0x0080, 0x0100, true, false),
        ])
    }

    /// A plan with the shape of every earlier image: one RX page at
    /// CODE_BASE, one RW page at DATA_BASE.
    fn canonical_shaped_plan() -> (aegis_os::elf::ExecPlan, Vec<u8>) {
        plan_of(&[
            (layout::CODE_BASE, 0x1000, 0x1000, false, true),
            (layout::DATA_BASE, 0x0080, 0x0100, true, false),
        ])
    }

    /// `(vaddr, filesz, memsz, writable, executable)` rows → a plan
    /// whose file bytes are laid out back to back (offset = the running
    /// sum), each byte carrying its own offset (so a copy is provable).
    fn plan_of(rows: &[(u64, u64, u64, bool, bool)]) -> (aegis_os::elf::ExecPlan, Vec<u8>) {
        use aegis_os::elf::{ExecPlan, SegmentPlan, MAX_SEGMENTS};
        let mut image = Vec::new();
        let mut segments = [SegmentPlan {
            vaddr: 0,
            offset: 0,
            filesz: 0,
            memsz: 0,
            readable: false,
            writable: false,
            executable: false,
        }; MAX_SEGMENTS];
        for (i, (vaddr, filesz, memsz, writable, executable)) in rows.iter().enumerate() {
            let offset = image.len() as u64;
            for b in 0..*filesz {
                image.push((b & 0xff) as u8 ^ (i as u8 * 0x5a));
            }
            segments[i] = SegmentPlan {
                vaddr: *vaddr,
                offset,
                filesz: *filesz,
                memsz: *memsz,
                readable: true,
                writable: *writable,
                executable: *executable,
            };
        }
        // Sum of the page-rounded extents, as the loader would count.
        let map_bytes = rows
            .iter()
            .map(|(v, _, m, _, _)| {
                let first = v & !4095;
                let last = (v + m + 4095) & !4095;
                last - first
            })
            .sum();
        let plan = ExecPlan {
            entry: rows[0].0,
            segments,
            n_segments: rows.len(),
            map_bytes,
        };
        (plan, image)
    }

    /// K22: the cage check is exact at both edges — the last cage page
    /// is image land, the page above it is not, and nothing sits below
    /// the code base.
    #[test]
    fn exec_cage_check_is_exact_at_both_edges() {
        for contract in [&layout::CANONICAL, &layout::SERVICE] {
            let (ok, _) = plan_of(&[(contract.cage_end - 4096, 0x10, 0x10, false, true)]);
            assert_eq!(exec_cage_check(&ok, contract), Ok(()), "{contract:?}");

            let (past, _) =
                plan_of(&[(contract.cage_end - 4096, 0x10, 0x1000 + 0x10, false, true)]);
            assert_eq!(
                exec_cage_check(&past, contract),
                Err(ExecMapError::CageViolation {
                    vaddr: contract.cage_end - 4096
                }),
                "{contract:?}: a segment crossing the cage end refuses"
            );
            let (below, _) = plan_of(&[(4096, 0x10, 0x10, false, true)]);
            assert_eq!(
                exec_cage_check(&below, contract),
                Err(ExecMapError::CageViolation { vaddr: 4096 }),
                "{contract:?}: below the code base refuses"
            );
        }
    }

    /// K22: a service-shaped image builds through the REAL mapper under
    /// the service contract — stack, trampoline and image exactly where
    /// the contract says — and the very same plan is a cage violation
    /// under the canonical one (the old fixed world refuses it up
    /// front, before any frame is spent).
    #[test]
    fn exec_tables_builds_a_service_image_under_its_own_contract() {
        use crate::mm::user_layout::SERVICE;
        let (plan, image) = service_shaped_plan();
        assert_eq!(
            exec_cage_check(&plan, &layout::CANONICAL),
            Err(ExecMapError::CageViolation { vaddr: 0x0040_8000 })
        );

        let (mut k, mut pool, _p) = setup();
        let (tables, space) = exec_tables(
            &mut k,
            &mut pool,
            7,
            &plan,
            &image,
            &SERVICE,
            aegis_os::profile::package_manager_profile().quota_pages,
        )
        .expect("the service-shaped image builds under SERVICE");
        // The image: every segment page present, the guard pages absent.
        for va in [0x0040_0000u64, 0x0040_1000, 0x0040_5000, 0x0040_8000] {
            assert!(tables.translate(va).is_some(), "{va:#x} mapped");
        }
        for va in [0x0040_2000u64, 0x0040_6000, 0x0040_9000] {
            assert!(tables.translate(va).is_none(), "{va:#x} is a guard page");
        }
        // The copied bytes: the RW segment's first 8 bytes are its own
        // image bytes (offset 0x3000, byte i = i ^ 0xb4 for row 2).
        let data_pa = tables.translate(0x0040_8000).unwrap();
        let mut want = [0u8; 8];
        want.copy_from_slice(&image[0x3000..0x3008]);
        assert_eq!(memops::read_u64(data_pa), u64::from_le_bytes(want));
        // The bss tail (memsz 0x100, filesz 0x80): zero, explicitly.
        assert_eq!(memops::read_u64(data_pa + 0xf8), 0);
        // The stack: 64 pages at 0x600000, both edges, nothing around.
        for va in [SERVICE.stack_base, SERVICE.stack_top() - 4096] {
            assert!(tables.translate(va).is_some(), "{va:#x} stack");
        }
        assert!(tables.translate(SERVICE.stack_base - 4096).is_none());
        assert!(tables.translate(SERVICE.stack_top()).is_none());
        // The trampoline: the real 9 bytes at the contract's address.
        let tramp_pa = tables.translate(SERVICE.trampoline_base).unwrap();
        assert_eq!(
            memops::read_u64(tramp_pa),
            u64::from_le_bytes(layout::TRAMPOLINE[..8].try_into().unwrap())
        );
        // Nothing from the canonical layout leaked in: the canonical
        // trampoline page is absent (the only canonical address this
        // plan does not happen to map as image land).
        assert!(tables.translate(layout::TRAMPOLINE_BASE).is_none());
        // The ledger: image pages + the contract's overhead.
        assert_eq!(
            space.used_pages(),
            (plan.map_bytes / 4096) as usize + SERVICE.overhead_pages()
        );
    }

    /// K22: nothing in the mapper is hard-coded to the wide contract —
    /// a canonical-shaped image builds under SERVICE too (its stack
    /// then lives at the service address), and the canonical plan still
    /// builds under CANONICAL exactly as before.
    #[test]
    fn either_contract_builds_either_legal_plan() {
        use crate::mm::user_layout::SERVICE;
        let (plan, image) = canonical_shaped_plan();
        let (mut k, mut pool, _p) = setup();
        let (tables, space) =
            exec_tables(&mut k, &mut pool, 7, &plan, &image, &layout::CANONICAL, 256)
                .expect("canonical image, canonical contract");
        assert!(tables.translate(layout::STACK_BASE).is_some());
        assert!(tables.translate(SERVICE.stack_base).is_none());
        assert_eq!(space.used_pages(), 2 + layout::CANONICAL.overhead_pages());

        let (mut k, mut pool, _p) = setup();
        let (tables, space) = exec_tables(
            &mut k,
            &mut pool,
            7,
            &plan,
            &image,
            &SERVICE,
            aegis_os::profile::package_manager_profile().quota_pages,
        )
        .expect("canonical image under the service contract");
        assert!(tables.translate(SERVICE.stack_base).is_some());
        assert!(tables.translate(SERVICE.stack_top() - 4096).is_some());
        assert!(tables.translate(layout::STACK_BASE).is_none());
        assert_eq!(space.used_pages(), 2 + SERVICE.overhead_pages());
    }
}
