//! Per-domain page tables (PR-1.3): the policy core's ten-check
//! `AddressSpace::map` stays the gate; what changes is that its accepted
//! decisions become hardware — real PML4→PDPT→PD→PT walks, every leaf a
//! live PTE with the U bit, NX on anything non-executable, and guard-gap
//! pages *absent* because they were never mapped.
//!
//! All raw access goes through `memops` (translated by the direct map on
//! the kernel, identity on the host) — this module is unsafe-free by
//! design, and host-tests the walk, the policy gating, and unmap against
//! a fake frame source built from a real host buffer.
//!
//! Table sharing (ADR-0002): every domain PML4 copies the kernel's
//! [273] (direct map) and [511] (image + stacks) entries — the same
//! physical tables, so the kernel half is identical in every address
//! space and its global leaves survive CR3 switches.

use crate::frames::FramePool;
use crate::memops;
use crate::mm::pte::{self, PteFlags, USER_LIMIT};
use aegis_os::memory::{AddressSpace, MemError, MemFlags, Region, PAGE_SIZE};
use aegis_os::prelude::BuddyAllocator;

use super::{ADDR_MASK, PAGE};

/// Why a mapping/unmapping attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// The lib's memory policy refused (ten checks: guard gap, overlap,
    /// W^X, quota, ...). Nothing was written.
    Policy(MemError),
    /// The frame pool refused (OOM / cross-owner free).
    Pool(crate::frames::FrameError),
    /// The VA is outside the user half — user PTEs never point above the
    /// split (ADR-0002 invariant).
    KernelHalf(u64),
    /// VA or PA not page-aligned.
    NotAligned(u64),
    /// Write+exec on one page: refused beneath the policy gate too
    /// (F5, defense in depth — the gate is the first line, this is the
    /// last: a caller that skips `map_region`'s gate still cannot get a
    /// W+X PTE).
    WriteExec(u64),
    /// A leaf PTE already exists at this VA (no remap: unmap first).
    AlreadyMapped(u64),
    /// No PTE at this VA on unmap.
    NotMapped(u64),
    /// ADR-0027: the frame-refcount table refused (MAX_SHARED entries
    /// live) — the transient capacity truth, never a policy stance.
    SharesFull,
    /// Policy and hardware disagree about a region (should be impossible;
    /// loud rather than silent).
    Desync {
        base: u64,
        policy_pages: usize,
        mapped_pages: usize,
    },
}

/// Where frames for page tables and mapped pages come from. The kernel
/// implements this over the boot pool (`PoolSource`); host tests over a
/// host buffer (`tests::TestSource`).
pub trait FrameSource {
    /// One scrubbed-on-free 4 KiB frame, tagged to the current owner.
    fn alloc_frame(&mut self) -> Result<u64, MapError>;
    /// Return a frame (the pool scrubs it before reuse).
    fn free_frame(&mut self, pa: u64) -> Result<(), MapError>;
}

/// The kernel's real frame source: the boot pool + the kernel's buddy
/// arena, tagging every frame with the owning "domain" id (domain ids
/// start at 1; 0 is the kernel itself).
pub struct PoolSource<'a, const N: usize> {
    pub pool: &'a mut FramePool<N>,
    pub buddy: &'a mut BuddyAllocator<N>,
    /// Current owner tag — switch it when building a different domain's
    /// tables with the same source.
    pub owner: u32,
}

impl<const N: usize> PoolSource<'_, N> {
    pub fn new<'a>(
        pool: &'a mut FramePool<N>,
        buddy: &'a mut BuddyAllocator<N>,
        owner: u32,
    ) -> PoolSource<'a, N> {
        PoolSource { pool, buddy, owner }
    }
}

impl<const N: usize> FrameSource for PoolSource<'_, N> {
    fn alloc_frame(&mut self) -> Result<u64, MapError> {
        self.pool
            .alloc_for(self.buddy, self.owner)
            .map_err(MapError::Pool)
    }
    fn free_frame(&mut self, pa: u64) -> Result<(), MapError> {
        self.pool
            .free(self.buddy, pa, self.owner)
            .map_err(MapError::Pool)
    }
}

/// ADR-0027: the shares-aware frame source. `alloc_frame` is the
/// pool's (table frames for grant_map's intermediates); `free_frame`
/// consults the refcount table — a SHARED frame is released (freed
/// only on the last release, under the ORIGINAL owner's tag, exactly
/// the reclaim rule), a private frame frees through the pool as
/// today. munmap and grant_map's rollback both come through here: a
/// frame another space still maps must never pool-free.
pub struct SharesSource<'a, const N: usize> {
    pub pool: &'a mut FramePool<N>,
    pub buddy: &'a mut BuddyAllocator<N>,
    pub owner: u32,
    pub shares: &'a mut aegis_os::frame_share::FrameShares,
}

impl<const N: usize> FrameSource for SharesSource<'_, N> {
    fn alloc_frame(&mut self) -> Result<u64, MapError> {
        self.pool
            .alloc_for(self.buddy, self.owner)
            .map_err(MapError::Pool)
    }
    fn free_frame(&mut self, pa: u64) -> Result<(), MapError> {
        if let Some(orig) = self.shares.owner_of(pa) {
            if matches!(self.shares.release(pa), Ok(true)) {
                // The last reference: free under the original owner's
                // tag (the reclaim rule — a cross-tag free would
                // corrupt the accounting).
                return self.pool.free(self.buddy, pa, orig).map_err(MapError::Pool);
            }
            return Ok(());
        }
        self.pool
            .free(self.buddy, pa, self.owner)
            .map_err(MapError::Pool)
    }
}

/// One domain's page tables, rooted at a PML4 frame.
pub struct PageTables {
    pml4_pa: u64,
}

/// ADR-0027: the grant's frame bundle — the granted PAs (in VA
/// order), the GRANTER's id (the refcount's owner-of-record), and
/// the shares table itself. One struct, one argument.
pub struct GrantFrames<'a> {
    pub pas: &'a [u64],
    pub owner: u32,
    pub shares: &'a mut aegis_os::frame_share::FrameShares,
}

impl PageTables {
    /// A fresh user address space: one PML4 frame, scrubbed to all-absent.
    pub fn new(src: &mut dyn FrameSource) -> Result<Self, MapError> {
        let pml4 = src.alloc_frame()?;
        memops::scrub_frame(pml4);
        Ok(PageTables { pml4_pa: pml4 })
    }

    /// Share the kernel's windows: copy PML4[273] (direct map) and
    /// PML4[511] (kernel image + guarded stacks) from the active tables.
    /// Same physical tables in every address space — the kernel half is
    /// byte-identical everywhere and its global leaves are TLB-stable.
    #[cfg(not(test))]
    pub fn install_kernel_entries(&mut self) {
        let kernel_pml4 = crate::hw::read_cr3() & ADDR_MASK;
        for idx in [273usize, 511] {
            let e = memops::read_u64(kernel_pml4 + idx as u64 * 8);
            memops::write_u64(self.pml4_pa + idx as u64 * 8, e);
        }
    }

    /// Host-build stand-in: there is no kernel half to share on the
    /// host (no CR3, no stub tables), so the host spawn path (N3
    /// transactional tests) installs nothing — the tests never launch
    /// and only assert frame/owner/domain-table accounting.
    #[cfg(test)]
    pub fn install_kernel_entries(&mut self) {}

    /// The CR3 value for these tables (physical, no PCID).
    #[must_use]
    pub fn cr3(&self) -> u64 {
        self.pml4_pa
    }

    /// Make these tables active. Only safe because `install_kernel_entries`
    /// ran: without the shared kernel entries, the very next instruction
    /// fetch would fault.
    #[cfg(not(test))]
    pub fn activate(&self) {
        crate::hw::write_cr3(self.pml4_pa);
    }

    // ── table walk (all reads/writes through `memops`: direct map on the
    //    kernel, host buffers in tests — no recursive mapping) ──

    fn indices(va: u64) -> (usize, usize, usize, usize) {
        (
            ((va >> 39) & 0x1FF) as usize, // PML4
            ((va >> 30) & 0x1FF) as usize, // PDPT
            ((va >> 21) & 0x1FF) as usize, // PD
            ((va >> 12) & 0x1FF) as usize, // PT
        )
    }

    fn entry(table_pa: u64, idx: usize) -> u64 {
        memops::read_u64(table_pa + idx as u64 * 8)
    }

    fn set_entry(table_pa: u64, idx: usize, v: u64) {
        memops::write_u64(table_pa + idx as u64 * 8, v);
    }

    /// Walk to the PT covering `va`, creating absent intermediate tables
    /// from `src` (each scrubbed). Returns the PT's physical address.
    fn pt_for(&mut self, va: u64, user: bool, src: &mut dyn FrameSource) -> Result<u64, MapError> {
        let (pml4i, pdpti, pdi, _) = Self::indices(va);

        let mut e = Self::entry(self.pml4_pa, pml4i);
        if e & pte::PTE_P == 0 {
            let pdpt = src.alloc_frame()?;
            memops::scrub_frame(pdpt);
            e = pdpt | PteFlags::table_bits(user);
            Self::set_entry(self.pml4_pa, pml4i, e);
        }
        let pdpt = e & ADDR_MASK;

        let mut e = Self::entry(pdpt, pdpti);
        if e & pte::PTE_P == 0 {
            let pd = src.alloc_frame()?;
            memops::scrub_frame(pd);
            e = pd | PteFlags::table_bits(user);
            Self::set_entry(pdpt, pdpti, e);
        }
        let pd = e & ADDR_MASK;

        let mut e = Self::entry(pd, pdi);
        if e & pte::PTE_P == 0 {
            let pt = src.alloc_frame()?;
            memops::scrub_frame(pt);
            e = pt | PteFlags::table_bits(user);
            Self::set_entry(pd, pdi, e);
        }
        Ok(e & ADDR_MASK)
    }

    /// Map one user page: `va → pa`, flags per `PteFlags`. Refuses the
    /// kernel half and non-page-aligned input, and never remaps.
    pub fn map_user_page(
        &mut self,
        va: u64,
        pa: u64,
        flags: PteFlags,
        src: &mut dyn FrameSource,
    ) -> Result<(), MapError> {
        if va >= USER_LIMIT {
            return Err(MapError::KernelHalf(va));
        }
        if !va.is_multiple_of(PAGE) || !pa.is_multiple_of(PAGE) {
            return Err(MapError::NotAligned(va));
        }
        // F5: W^X is architecture here as well as policy — refuse
        // before any table walk or PTE write.
        if flags.w && flags.x {
            return Err(MapError::WriteExec(va));
        }
        let pt = self.pt_for(va, flags.user, src)?;
        let (_, _, _, pti) = Self::indices(va);
        if Self::entry(pt, pti) & pte::PTE_P != 0 {
            return Err(MapError::AlreadyMapped(va));
        }
        Self::set_entry(pt, pti, (pa & ADDR_MASK) | flags.leaf_bits());
        Ok(())
    }

    /// **The** mapping path: the lib's ten-check policy runs FIRST and is
    /// the only thing that can accept a region; then every accepted page
    /// gets a fresh scrubbed frame and a live user PTE. Guard-gap pages
    /// are absent PTEs by construction — they are simply never mapped.
    /// On any hardware-side failure the pages mapped so far are rolled
    /// back and the policy region is withdrawn. (No allocation: the
    /// rollback re-walks the PTEs it is removing.)
    pub fn map_region(
        &mut self,
        space: &mut AddressSpace,
        base: u64,
        len: usize,
        flags: MemFlags,
        src: &mut dyn FrameSource,
    ) -> Result<Region, MapError> {
        if base >= USER_LIMIT || base.saturating_add(len as u64) > USER_LIMIT {
            return Err(MapError::KernelHalf(base));
        }
        // The policy gate: ten checks before any PTE write.
        space
            .map(base as usize, len, flags)
            .map_err(MapError::Policy)?;

        let pf = PteFlags::from_memflags(flags);
        let end = base + len as u64;
        let mut va = base;
        while va < end {
            let frame = match src.alloc_frame() {
                Ok(f) => f,
                Err(e) => {
                    self.rollback(space, base, va, src);
                    return Err(e);
                }
            };
            memops::scrub_frame(frame);
            match self.map_user_page(va, frame, pf, src) {
                Ok(()) => {}
                Err(e) => {
                    let _ = src.free_frame(frame);
                    self.rollback(space, base, va, src);
                    return Err(e);
                }
            }
            va += PAGE;
        }
        Ok(Region {
            base: base as usize,
            len,
            flags,
        })
    }

    /// ADR-0027: map EXISTING frames (a grant) into the user half —
    /// the same ten-check policy gate and the same rollback shape as
    /// `map_region`, but every leaf PTE points at `pas[i]` (the
    /// granter's frames). RW-only is HARDWIRED: a granted page never
    /// arrives executable. No scrub — the page's CONTENT is the
    /// point. Each page's refcount is acquired immediately before its
    /// PTE write; the failure paths release exactly what was taken
    /// (map_user_page's error frees through `src`, whose
    /// shares-awareness does the release; the rollback does the
    /// earlier pages the same way).
    pub fn grant_map(
        &mut self,
        space: &mut aegis_os::memory::AddressSpace,
        base: u64,
        len: usize,
        grant: &mut GrantFrames<'_>,
        src: &mut dyn FrameSource,
    ) -> Result<aegis_os::memory::Region, MapError> {
        let GrantFrames { pas, owner, shares } = grant;
        use aegis_os::memory::MemFlags;
        if base >= USER_LIMIT || base.saturating_add(len as u64) > USER_LIMIT {
            return Err(MapError::KernelHalf(base));
        }
        // The caller guarantees len == pas.len() * PAGE; a mismatch is
        // a kernel bookkeeping bug — refuse it loudly, map nothing.
        if len != pas.len() * PAGE as usize {
            return Err(MapError::NotAligned(len as u64));
        }
        // RW-only, hardwired (ADR-0027: no EXEC on a granted page).
        let flags = MemFlags(MemFlags::READ.0 | MemFlags::WRITE.0);
        // The policy gate: the receiver's own ten checks — a grant
        // cannot smuggle memory past a quota.
        space
            .map(base as usize, len, flags)
            .map_err(MapError::Policy)?;
        let pf = PteFlags::from_memflags(flags);
        let end = base + len as u64;
        let mut va = base;
        let mut i = 0usize;
        while va < end {
            let frame = pas[i];
            if shares.acquire(frame, *owner).is_err() {
                // The table is full: the transient refusal. Nothing of
                // THIS page was taken; the earlier pages unwind.
                self.rollback(space, base, va, src);
                return Err(MapError::SharesFull);
            }
            match self.map_user_page(va, frame, pf, src) {
                Ok(()) => {}
                Err(e) => {
                    // The acquire of THIS page unwinds through the
                    // source (shares-aware); the earlier pages through
                    // the rollback.
                    let _ = src.free_frame(frame);
                    self.rollback(space, base, va, src);
                    return Err(e);
                }
            }
            va += PAGE;
            i += 1;
        }
        Ok(aegis_os::memory::Region {
            base: base as usize,
            len,
            flags,
        })
    }

    /// ADR-0027: walk every PRESENT user leaf PTE and report
    /// (va, pa) — the exit-release rule's eyes. The user half only
    /// (PML4 slots < 256); kernel-half entries are never visited.
    pub fn walk_user_frames(&self, f: &mut dyn FnMut(u64, u64)) {
        for pml4i in 0..256usize {
            let pml4e = Self::entry(self.pml4_pa, pml4i);
            if pml4e & pte::PTE_P == 0 {
                continue;
            }
            for pdpti in 0..512usize {
                let pdpte = Self::entry(pml4e & ADDR_MASK, pdpti);
                if pdpte & pte::PTE_P == 0 {
                    continue;
                }
                for pdi in 0..512usize {
                    let pde = Self::entry(pdpte & ADDR_MASK, pdi);
                    if pde & pte::PTE_P == 0 {
                        continue;
                    }
                    let pt = pde & ADDR_MASK;
                    for pti in 0..512usize {
                        let pte = Self::entry(pt, pti);
                        if pte & pte::PTE_P == 0 || pte & pte::PTE_U == 0 {
                            continue;
                        }
                        let va = ((pml4i as u64) << 39)
                            | ((pdpti as u64) << 30)
                            | ((pdi as u64) << 21)
                            | ((pti as u64) << 12);
                        f(va, pte & ADDR_MASK);
                    }
                }
            }
        }
    }

    /// Undo a partial `map_region`: unmap every present page in
    /// `[base, upto)` (walking the very PTEs being removed — no
    /// allocation) and withdraw the policy region. Best-effort by
    /// necessity (the pool is exhausted or the walk broke); every step
    /// that can fail is allowed to.
    fn rollback(
        &mut self,
        space: &mut AddressSpace,
        base: u64,
        upto: u64,
        src: &mut dyn FrameSource,
    ) {
        let mut va = base;
        while va < upto {
            if let Some(pa) = self.translate(va) {
                if let Some(pt) = self.pt_of(va) {
                    let (_, _, _, pti) = Self::indices(va);
                    Self::set_entry(pt, pti, 0);
                }
                #[cfg(not(test))]
                pte::flush_tlb_page(va);
                let _ = src.free_frame(pa);
            }
            va += PAGE;
        }
        let _ = space.unmap(base as usize);
    }

    /// Walk to the PT covering `va` without creating anything; `None`
    /// when any level is absent.
    fn pt_of(&self, va: u64) -> Option<u64> {
        let (pml4i, pdpti, pdi, _) = Self::indices(va);
        let e = Self::entry(self.pml4_pa, pml4i);
        if e & pte::PTE_P == 0 {
            return None;
        }
        let e = Self::entry(e & ADDR_MASK, pdpti);
        if e & pte::PTE_P == 0 {
            return None;
        }
        let e = Self::entry(e & ADDR_MASK, pdi);
        if e & pte::PTE_P == 0 {
            return None;
        }
        Some(e & ADDR_MASK)
    }

    /// Free every TABLE frame of a (possibly partial) user-half tree
    /// by walking it — rollback for `clone_for_fork`. Frees tables
    /// only; leaf data frames are the caller's business.
    fn free_user_tree(pml4_pa: u64, src: &mut dyn FrameSource) {
        for pml4i in 0..256usize {
            let pml4e = Self::entry(pml4_pa, pml4i);
            if pml4e & pte::PTE_P == 0 {
                continue;
            }
            for pdpti in 0..512usize {
                let pdpte = Self::entry(pml4e & ADDR_MASK, pdpti);
                if pdpte & pte::PTE_P == 0 {
                    continue;
                }
                for pdi in 0..512usize {
                    let pde = Self::entry(pdpte & ADDR_MASK, pdi);
                    if pde & pte::PTE_P == 0 {
                        continue;
                    }
                    let _ = src.free_frame(pde & ADDR_MASK);
                }
                let _ = src.free_frame(pdpte & ADDR_MASK);
            }
            let _ = src.free_frame(pml4e & ADDR_MASK);
        }
    }

    /// ADR-0024 D2: fork's memory half — clone the whole USER half of
    /// this table tree into a child tree, sharing every mapped frame.
    ///
    /// TWO PASSES, in this order, so a failure never leaves the PARENT
    /// modified:
    /// 1. Build the child's tree top-down, copying every present user
    ///    PTE. WRITABLE user pages are copied READ-ONLY into the child
    ///    (the CoW demote-marker); every shared user frame's refcount
    ///    is acquired (owner = `owner`, the PARENT's domain — a frame
    ///    already shared from an earlier fork keeps its ORIGINAL owner
    ///    entry, which is exactly the provenance the last free needs).
    ///    Mid-way failure rolls back: the child's table frames free and
    ///    every acquired refcount releases.
    /// 2. Demote the PARENT's writable user PTEs to read-only (no
    ///    allocation, cannot fail) with a per-page `invlpg` — the
    ///    parent's CR3 is live at fork time.
    ///
    /// Both sides then see every shared writable page RO; the first
    /// write on either side faults, and the fault path's CoW branch
    /// copies the frame and remaps it RW privately.
    pub fn clone_for_fork(
        &self,
        src: &mut dyn FrameSource,
        shares: &mut aegis_os::frame_share::FrameShares,
        owner: u32,
    ) -> Result<PageTables, MapError> {
        // ── pass 1: the child's tree ──────────────────────────────
        let child_pml4 = src.alloc_frame()?;
        memops::scrub_frame(child_pml4);
        // (table|PTE_P|PTE_W|PTE_U — intermediate entries are plain
        // kernel-owned pointers into the user half's subtrees)
        let mid_flags = pte::PTE_P | pte::PTE_W | pte::PTE_U;

        // Rollback bookkeeping: every shared frame PA acquired so far
        // (released on rollback). The child's TABLE frames are freed
        // by walking the tree itself (no buffer bound).
        let mut acquired: [u64; aegis_os::frame_share::MAX_SHARED] =
            [0; aegis_os::frame_share::MAX_SHARED];
        let mut acquired_n = 0usize;

        let mut result: Result<(), MapError> = Ok(());
        'outer: for pml4i in 0..256usize {
            let p_pml4e = Self::entry(self.pml4_pa, pml4i);
            if p_pml4e & pte::PTE_P == 0 {
                continue;
            }
            let pdpt_pa = src.alloc_frame();
            let pdpt_pa = match pdpt_pa {
                Ok(f) => f,
                Err(e) => {
                    result = Err(e);
                    break 'outer;
                }
            };

            Self::set_entry(child_pml4, pml4i, pdpt_pa | mid_flags);
            for pdpti in 0..512usize {
                let p_pdpte = Self::entry(p_pml4e & ADDR_MASK, pdpti);
                if p_pdpte & pte::PTE_P == 0 {
                    continue;
                }
                // A 1-GiB leaf in the USER half: not a shape this
                // kernel builds (mm::init maps the kernel half's
                // direct map as leaves) — refuse rather than guess.
                if p_pdpte & pte::PTE_PS != 0 {
                    result = Err(MapError::KernelHalf(0));
                    break 'outer;
                }
                let pd_pa = match src.alloc_frame() {
                    Ok(f) => f,
                    Err(e) => {
                        result = Err(e);
                        break 'outer;
                    }
                };

                Self::set_entry(pdpt_pa, pdpti, pd_pa | mid_flags);
                for pdi in 0..512usize {
                    let p_pde = Self::entry(p_pdpte & ADDR_MASK, pdi);
                    if p_pde & pte::PTE_P == 0 {
                        continue;
                    }
                    if p_pde & pte::PTE_PS != 0 {
                        result = Err(MapError::KernelHalf(0));
                        break 'outer;
                    }
                    let pt_pa = match src.alloc_frame() {
                        Ok(f) => f,
                        Err(e) => {
                            result = Err(e);
                            break 'outer;
                        }
                    };

                    Self::set_entry(pd_pa, pdi, pt_pa | mid_flags);
                    for pti in 0..512usize {
                        let pte_v = Self::entry(p_pde & ADDR_MASK, pti);
                        if pte_v & pte::PTE_P == 0 {
                            continue;
                        }
                        let pa = pte_v & ADDR_MASK;
                        let flags = pte_v & !ADDR_MASK;
                        if flags & pte::PTE_U == 0 {
                            // A kernel leaf inside a user-half walk:
                            // not a shape this kernel builds; copy it
                            // verbatim without sharing (it is not
                            // domain-owned memory).
                            Self::set_entry(pt_pa, pti, pte_v);
                            continue;
                        }
                        let writable = flags & pte::PTE_W != 0;
                        if shares.acquire(pa, owner).is_err() {
                            // TableFull / Overflow: the share table
                            // refused — surface as the pool-shaped
                            // ENOMEM the ABI maps.
                            result = Err(MapError::KernelHalf(pa));
                            break 'outer;
                        }
                        if acquired_n < acquired.len() {
                            acquired[acquired_n] = pa;
                            acquired_n += 1;
                        }
                        // The child's copy: RO when the parent is
                        // writable (the demote marker).
                        let child_flags = if writable { flags & !pte::PTE_W } else { flags };
                        Self::set_entry(pt_pa, pti, pa | child_flags);
                    }
                }
            }
        }

        if let Err(e) = result {
            // Rollback: release what pass 1 acquired, then free the
            // child's whole table tree by WALKING it (every table
            // frame the partial build allocated). Best-effort, like
            // map_region's rollback. The parent was never touched.
            for pa in acquired[..acquired_n].iter() {
                let _ = shares.release(*pa);
            }
            Self::free_user_tree(child_pml4, src);
            let _ = src.free_frame(child_pml4);
            return Err(e);
        }

        // The SHARED KERNEL half (PML4[256..512] — the direct map at
        // 273, the image at 511): copied VERBATIM, the way a spawned
        // run's tables get it. Found live: without these entries the
        // child's CR3 has no kernel half, and the first kernel-side
        // access under it (the very stack the child's enter runs on)
        // faults at a half-present address.
        for pml4i in 256..512usize {
            let e = Self::entry(self.pml4_pa, pml4i);
            if e & pte::PTE_P != 0 {
                Self::set_entry(child_pml4, pml4i, e);
            }
        }

        // ── pass 2: demote the parent (cannot fail) ───────────────
        for pml4i in 0..256usize {
            let pml4e = Self::entry(self.pml4_pa, pml4i);
            if pml4e & pte::PTE_P == 0 {
                continue;
            }
            for pdpti in 0..512usize {
                let pdpte = Self::entry(pml4e & ADDR_MASK, pdpti);
                if pdpte & pte::PTE_P == 0 {
                    continue;
                }
                for pdi in 0..512usize {
                    let pde = Self::entry(pdpte & ADDR_MASK, pdi);
                    if pde & pte::PTE_P == 0 {
                        continue;
                    }
                    for pti in 0..512usize {
                        let pt_pa = pde & ADDR_MASK;
                        let pte_v = Self::entry(pt_pa, pti);
                        if pte_v & pte::PTE_P == 0 || pte_v & pte::PTE_U == 0 {
                            continue;
                        }
                        if pte_v & pte::PTE_W != 0 {
                            let pa = pte_v & ADDR_MASK;
                            let flags = pte_v & !ADDR_MASK;
                            Self::set_entry(pt_pa, pti, pa | (flags & !pte::PTE_W));
                            #[cfg(not(test))]
                            {
                                let va = ((pml4i as u64) << 39)
                                    | ((pdpti as u64) << 30)
                                    | ((pdi as u64) << 21)
                                    | ((pti as u64) << 12);
                                pte::flush_tlb_page(va);
                            }
                        }
                    }
                }
            }
        }

        Ok(PageTables {
            pml4_pa: child_pml4,
        })
    }

    /// ADR-0024 D2: repoint the present leaf at `va` at `new_pa`,
    /// forcing the writable bit to `writable` — the CoW copy path's
    /// remap. `false` when the walk finds no present leaf (the caller
    /// treats that as not-ours).
    pub fn replace_leaf(&mut self, va: u64, new_pa: u64, writable: bool) -> bool {
        let Some(pt) = self.pt_of(va) else {
            return false;
        };
        let (_, _, _, pti) = Self::indices(va);
        let old = Self::entry(pt, pti);
        if old & pte::PTE_P == 0 {
            return false;
        }
        let mut flags = old & !ADDR_MASK;
        if writable {
            flags |= pte::PTE_W;
        } else {
            flags &= !pte::PTE_W;
        }
        Self::set_entry(pt, pti, new_pa | flags);
        true
    }

    /// The raw leaf PTE at `va` (flags included), or `None` when absent.
    #[must_use]
    pub fn pte_of(&self, va: u64) -> Option<u64> {
        let pt = self.pt_of(va)?;
        let (_, _, _, pti) = Self::indices(va);
        let e = Self::entry(pt, pti);
        (e & pte::PTE_P != 0).then_some(e)
    }

    /// Virtual → physical for a present user page.
    #[must_use]
    pub fn translate(&self, va: u64) -> Option<u64> {
        self.pte_of(va).map(|e| e & ADDR_MASK)
    }

    /// Unmap the region at `base`: PTEs removed (+ per-page TLB flush on
    /// the target), frames freed through the source (the pool scrubs
    /// them on free), and only then the policy region withdrawn. The
    /// intermediate tables stay allocated for reuse — they are pool
    /// frames owned by the same owner, so a domain destroy reclaims
    /// them (`free_all_owned`). No allocation: pages are counted by
    /// walking the PTEs, then removed in the same order.
    pub fn unmap_region(
        &mut self,
        space: &mut AddressSpace,
        base: u64,
        src: &mut dyn FrameSource,
    ) -> Result<Region, MapError> {
        // Count the present pages of the region (contiguous by
        // construction: the policy only maps page-run regions).
        const PAGE_CAP: usize = 16 * 1024; // 64 MiB — unreachable under quotas
        let mut pages = 0usize;
        let mut va = base;
        while self.translate(va).is_some() {
            pages += 1;
            va += PAGE;
            if pages >= PAGE_CAP {
                break;
            }
        }
        if pages == 0 {
            return Err(MapError::NotMapped(base));
        }

        // Hardware first: PTE gone, TLB flushed, frame back (scrubbed by
        // the pool on free).
        let mut va = base;
        for _ in 0..pages {
            let pa = self.translate(va).expect("counted present a moment ago");
            if let Some(pt) = self.pt_of(va) {
                let (_, _, _, pti) = Self::indices(va);
                Self::set_entry(pt, pti, 0);
            }
            #[cfg(not(test))]
            pte::flush_tlb_page(va);
            src.free_frame(pa)?;
            va += PAGE;
        }

        // Then the policy's bookkeeping — and it must agree with what we
        // just unmapped, or something is deeply wrong.
        let region = space.unmap(base as usize).map_err(MapError::Policy)?;
        if region.len / PAGE_SIZE != pages {
            return Err(MapError::Desync {
                base,
                policy_pages: region.len / PAGE_SIZE,
                mapped_pages: pages,
            });
        }
        Ok(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memops;

    /// A fake frame source over a real host buffer: `n` page-aligned,
    /// 4 KiB-apart "frames" the table walks can actually write into
    /// (memops is identity-translated on the host).
    struct TestSource {
        _slab: Vec<u64>,
        free: Vec<u64>,
        live: usize,
    }

    impl TestSource {
        fn new(n: usize) -> Self {
            // Extra slack so the base can be page-aligned.
            let mut slab = vec![0u64; n * 512 + 512];
            let base = (slab.as_mut_ptr() as u64 + 4095) & !4095u64;
            let free = (0..n).map(|i| base + i as u64 * 4096).rev().collect();
            TestSource {
                _slab: slab,
                free,
                live: 0,
            }
        }
        fn available(&self) -> usize {
            self.free.len()
        }
        fn live_frames(&self) -> usize {
            self.live
        }
    }

    impl FrameSource for TestSource {
        fn alloc_frame(&mut self) -> Result<u64, MapError> {
            let pa = self
                .free
                .pop()
                .ok_or(MapError::Pool(crate::frames::FrameError::NotInPool(0)))?;
            self.live += 1;
            Ok(pa)
        }
        fn free_frame(&mut self, pa: u64) -> Result<(), MapError> {
            self.free.push(pa);
            self.live -= 1;
            Ok(())
        }
    }

    const BASE: u64 = 0x20_0000; // 2 MiB: a classic user mapping address

    fn rw() -> MemFlags {
        MemFlags::READ | MemFlags::WRITE
    }

    /// F5 regression (defense in depth): `map_user_page` is the layer
    /// *beneath* the policy gate — any caller that skips the gate must
    /// still never get a writable+executable PTE.
    #[test]
    fn map_user_page_refuses_write_exec_beneath_the_gate() {
        use crate::mm::pte::PteFlags;
        let mut src = TestSource::new(8);
        let mut pt = PageTables::new(&mut src).unwrap();
        // Direct call, bypassing map_region's policy gate on purpose.
        let wx = PteFlags::from_memflags(MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC);
        let r = pt.map_user_page(BASE, 0x0100_0000, wx, &mut src);
        assert!(
            matches!(r, Err(MapError::WriteExec(_))),
            "W+X must be refused beneath the policy gate, got {r:?}"
        );
        // And nothing was mapped by the failed attempt.
        assert!(pt.translate(BASE).is_none());
    }

    #[test]
    fn map_region_maps_every_page_with_user_bits() {
        let mut src = TestSource::new(16);
        let mut pt = PageTables::new(&mut src).unwrap();
        let mut space = AddressSpace::new(8);

        let region = pt
            .map_region(&mut space, BASE, 2 * PAGE_SIZE, rw(), &mut src)
            .unwrap();
        assert_eq!(region.base, BASE as usize);
        assert_eq!(region.len, 2 * PAGE_SIZE);

        let pa0 = pt.translate(BASE).expect("page 0 mapped");
        let pa1 = pt.translate(BASE + PAGE).expect("page 1 mapped");
        assert_ne!(pa0, pa1, "distinct pages get distinct frames");

        // Leaf bits: P | W | U | NX (RW data page), no G.
        let e = pt.pte_of(BASE).unwrap();
        assert!(e & pte::PTE_P != 0);
        assert!(e & pte::PTE_W != 0);
        assert!(e & pte::PTE_U != 0, "policy-accepted user pages carry U");
        assert!(e & pte::PTE_NX != 0, "data pages are non-executable");
        assert_eq!(e & pte::PTE_G, 0);
        assert_eq!(e & ADDR_MASK, pa0);

        // The guard gap after the region is an absent PTE.
        assert!(pt.pte_of(BASE + 2 * PAGE).is_none());
    }

    #[test]
    fn policy_gate_runs_before_any_pte_write() {
        let mut src = TestSource::new(16);
        let mut pt = PageTables::new(&mut src).unwrap();
        let mut space = AddressSpace::new(8);

        pt.map_region(&mut space, BASE, 2 * PAGE_SIZE, rw(), &mut src)
            .unwrap();

        // Adjacent mapping: the ten-check policy must refuse it with
        // GuardGap — and no PTE may exist for the refused page.
        let before = src.live_frames();
        let err = pt
            .map_region(&mut space, BASE + 2 * PAGE, PAGE_SIZE, rw(), &mut src)
            .unwrap_err();
        assert_eq!(err, MapError::Policy(MemError::GuardGap));
        assert!(
            pt.pte_of(BASE + 2 * PAGE).is_none(),
            "refused page has no PTE"
        );
        assert_eq!(src.live_frames(), before, "no frame consumed by a refusal");

        // One page further (the guard page left free): accepted.
        pt.map_region(&mut space, BASE + 3 * PAGE, PAGE_SIZE, rw(), &mut src)
            .unwrap();
        assert!(pt.pte_of(BASE + 3 * PAGE).is_some());
        // And the guard page between them is still absent.
        assert!(pt.pte_of(BASE + 2 * PAGE).is_none());
    }

    #[test]
    fn wx_and_null_and_kernel_half_are_refused() {
        let mut src = TestSource::new(16);
        let mut pt = PageTables::new(&mut src).unwrap();
        let mut space = AddressSpace::new(8);

        // W^X: refused by the policy, no PTE.
        let e = pt
            .map_region(
                &mut space,
                BASE,
                PAGE_SIZE,
                MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC,
                &mut src,
            )
            .unwrap_err();
        assert_eq!(e, MapError::Policy(MemError::WxViolation));
        assert!(pt.pte_of(BASE).is_none());

        // NULL page: the policy's first check.
        let e = pt
            .map_region(&mut space, 0, PAGE_SIZE, rw(), &mut src)
            .unwrap_err();
        assert_eq!(e, MapError::Policy(MemError::NullBase));

        // The kernel half is refused before the policy even runs.
        let kva = crate::mm::KERNEL_BASE;
        let e = pt
            .map_region(&mut space, kva, PAGE_SIZE, rw(), &mut src)
            .unwrap_err();
        assert_eq!(e, MapError::KernelHalf(kva));
        let e = pt
            .map_user_page(USER_LIMIT, 0x10_0000, PteFlags::USER_RW, &mut src)
            .unwrap_err();
        assert!(matches!(e, MapError::KernelHalf(_)));
    }

    #[test]
    fn two_domains_same_va_different_frames() {
        let mut src = TestSource::new(32);
        let mut a = PageTables::new(&mut src).unwrap();
        let mut b = PageTables::new(&mut src).unwrap();
        let mut sa = AddressSpace::new(8);
        let mut sb = AddressSpace::new(8);

        a.map_region(&mut sa, BASE, PAGE_SIZE, rw(), &mut src)
            .unwrap();
        b.map_region(&mut sb, BASE, PAGE_SIZE, rw(), &mut src)
            .unwrap();

        let pa = a.translate(BASE).unwrap();
        let pb = b.translate(BASE).unwrap();
        assert_ne!(pa, pb, "disjoint tables: same VA, different frames");
        // Both are valid host frames (the walk wrote real PTEs).
        memops::write_u64(pa, 0x1111);
        memops::write_u64(pb, 0x2222);
        assert_eq!(memops::read_u64(pa), 0x1111);
        assert_eq!(memops::read_u64(pb), 0x2222);
    }

    #[test]
    fn unmap_removes_ptes_frees_frames_and_policy_agrees() {
        let mut src = TestSource::new(16);
        let mut pt = PageTables::new(&mut src).unwrap();
        let mut space = AddressSpace::new(8);

        let start = src.available();
        pt.map_region(&mut space, BASE, 2 * PAGE_SIZE, rw(), &mut src)
            .unwrap();
        // Frames held by the region: PDPT + PD + PT (the PML4 itself
        // was allocated before `start`) + 2 data pages = 5.
        let tables = 3usize;
        assert_eq!(start - src.available(), tables + 2);

        let region = pt.unmap_region(&mut space, BASE, &mut src).unwrap();
        assert_eq!(region.len, 2 * PAGE_SIZE);
        assert!(pt.pte_of(BASE).is_none());
        assert!(pt.pte_of(BASE + PAGE).is_none());
        assert_eq!(pt.translate(BASE), None);
        // The two data frames went back; the 3 intermediate table
        // frames stay for reuse (documented; a domain destroy reclaims
        // them, as does the PML4).
        assert_eq!(start - src.available(), tables);
        // The policy released its quota.
        assert_eq!(space.used_pages(), 0);

        // Unmapping again is an error, not a no-op.
        assert!(matches!(
            pt.unmap_region(&mut space, BASE, &mut src),
            Err(MapError::NotMapped(_))
        ));
    }

    #[test]
    fn pool_exhaustion_mid_region_rolls_back() {
        // Exactly enough frames for the tables + one data page: the
        // second data page hits OOM and everything unwinds.
        let mut src = TestSource::new(5);
        let mut pt = PageTables::new(&mut src).unwrap();
        let mut space = AddressSpace::new(8);

        let e = pt
            .map_region(&mut space, BASE, 2 * PAGE_SIZE, rw(), &mut src)
            .unwrap_err();
        assert!(matches!(e, MapError::Pool(_)));
        assert!(pt.pte_of(BASE).is_none(), "rolled back: no PTE survives");
        assert!(pt.translate(BASE + PAGE).is_none());
        assert_eq!(space.used_pages(), 0, "policy region withdrawn");
    }
}
