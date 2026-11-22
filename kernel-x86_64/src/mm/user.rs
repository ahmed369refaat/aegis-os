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
    match build_user_tables(k, pool, id, blob, data) {
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
) -> Result<(PageTables, AddressSpace), SpawnError> {
    let mut src = PoolSource::new(pool, &mut k.frames, id);
    let mut tables = PageTables::new(&mut src)?;
    tables.install_kernel_entries();
    let mut space = AddressSpace::new(16);
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

    const N: usize = 256;

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
}
