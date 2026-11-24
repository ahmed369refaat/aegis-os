//! ADR-0032 section C: frame reference counts and the copy-on-write
//! decision — the pure root of fork's memory half.
//!
//! One refcount per PHYSICAL frame the pool owns, indexed by pool
//! frame number: a DENSE pair of arrays (`[u16; N]` counts, `[u32; N]`
//! original-owner tags), sized by the frame pool — O(1) on every
//! operation, and there is no table to fill. Private frames (the
//! overwhelmingly common case) hold a zero and nothing else; `refs ==
//! None` still means "not shared" to every CoW decision. A count of
//! exactly 1 is the shared-orphaned tier: the demote marker outlived
//! its reason (every sibling copied away) — a write Promotes in place,
//! and the owner tag stays valid so the last holder frees under the
//! original owner's tag. Overflow is a loud typed refusal, never a
//! silent drop or wrap.
//!
//! History (the round-A finding this replaces): a linear
//! `[Option<(pa, refs, owner)>; 64]` capped the WHOLE SYSTEM at 64
//! shared frames — any process with more than ~64 distinct pages
//! could not fork, the exhaustion was reported with the wrong error
//! variant (`KernelHalf`), and refs==1 entries held slots until
//! teardown.

/// ADR-0027 (page grants): the per-grant length bound, in pages.
/// Deliberately SEPARATE from the per-frame refcount table since
/// ADR-0032 section C — it rode on the old table's MAX_SHARED capacity
/// by accident. Configurable: a deployment with a different grant
/// appetite changes ONE constant, and the refcount table no longer
/// has a capacity to couple it to.
pub const MAX_GRANT_PAGES: usize = 64;

/// The reference-count word per frame. `u16`: 65534 concurrent
/// mappings of one frame is beyond any quota this kernel grants, and
/// the bound is CHECKED — `ShareError::Overflow` is typed, never a
/// wrap.
pub type RefCount = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareError {
    /// A release of a frame the table does not hold (an underflow
    /// guard: 0-1 must never wrap), or an address outside the pool's
    /// geometry (acquire of a frame the pool does not own — an
    /// impossible shape, loudly refused).
    NotHeld(u64),
    /// The count cannot grow past `RefCount::MAX`.
    Overflow(u64),
}

/// The per-frame reference counts, indexed by POOL FRAME NUMBER.
///
/// Generic over the pool size `N` (the kernel passes
/// `KERNEL_POOL_FRAMES`); constructed with the pool's base address and
/// frame size so `pa -> index` is pure arithmetic. The counts and the
/// original-owner tags live in `.bss`-shaped plain arrays — no
/// allocation, no slots, nothing to exhaust.
pub struct FrameShares<const N: usize> {
    pool_base: u64,
    frame_size: u64,
    /// 0 = private; 1 = shared-orphaned (the Promote tier — the
    /// owner tag is still live); >1 = shared.
    refs: [RefCount; N],
    /// The ORIGINAL pool owner per frame with `refs != 0`: the tag the
    /// last holder frees under (the re-tagging rule — a fork's child
    /// must never free an inherited frame under its own tag).
    owners: [u32; N],
}

impl<const N: usize> FrameShares<N> {
    /// `pool_base` must be frame-aligned; `frame_size` nonzero. Const-
    /// constructible (the kernel's static).
    #[must_use]
    pub const fn new(pool_base: u64, frame_size: u64) -> Self {
        FrameShares {
            pool_base,
            frame_size,
            refs: [0; N],
            owners: [0; N],
        }
    }

    /// pa -> pool frame index. Pure checked arithmetic; anything
    /// outside `[pool_base, pool_base + N*frame_size)` is refused.
    fn index(&self, pa: u64) -> Result<usize, ShareError> {
        if pa < self.pool_base || self.frame_size == 0 {
            return Err(ShareError::NotHeld(pa));
        }
        let off = pa - self.pool_base;
        if !off.is_multiple_of(self.frame_size) {
            return Err(ShareError::NotHeld(pa));
        }
        let idx = (off / self.frame_size) as usize;
        if idx >= N {
            return Err(ShareError::NotHeld(pa));
        }
        Ok(idx)
    }

    /// Add one NEW HOLDER of `pa`. Insertion semantics (unchanged from
    /// the linear-table era, found by the fork/reclaim model test
    /// before it ever ran on the kernel): a private frame becoming
    /// shared already has its original holder, so the count starts at
    /// TWO — the owner's own mapping plus this new one. A frame
    /// already counted just gains one (and keeps the ORIGINAL owner —
    /// the count is the frame's provenance, not the caller's).
    pub fn acquire(&mut self, pa: u64, owner: u32) -> Result<(), ShareError> {
        let idx = self.index(pa)?;
        if self.refs[idx] == 0 {
            self.refs[idx] = 2;
            self.owners[idx] = owner;
            return Ok(());
        }
        let next = self.refs[idx]
            .checked_add(1)
            .ok_or(ShareError::Overflow(pa))?;
        self.refs[idx] = next;
        Ok(())
    }

    /// Drop one reference. `Ok(true)` = that was the LAST one — the
    /// caller frees the frame through the pool. `Ok(false)` = the
    /// frame still has holders. `Err(NotHeld)` = an underflow attempt.
    /// A release to exactly 1 KEEPS the entry (the shared-orphaned
    /// tier: the owner tag must stay live for the last holder's
    /// tagged free, and a later write fault on the still-demoted page
    /// must Promote, not die).
    pub fn release(&mut self, pa: u64) -> Result<bool, ShareError> {
        let idx = self.index(pa)?;
        if self.refs[idx] == 0 {
            return Err(ShareError::NotHeld(pa));
        }
        if self.refs[idx] == 1 {
            self.refs[idx] = 0;
            self.owners[idx] = 0;
            return Ok(true);
        }
        self.refs[idx] -= 1;
        Ok(false)
    }

    /// The frame's ORIGINAL pool owner (the tag the last holder frees
    /// under), when the frame is counted at all.
    #[must_use]
    pub fn owner_of(&self, pa: u64) -> Option<u32> {
        let idx = self.index(pa).ok()?;
        if self.refs[idx] == 0 {
            return None;
        }
        Some(self.owners[idx])
    }

    /// The current count, or `None` when the frame is not shared.
    #[must_use]
    pub fn refs(&self, pa: u64) -> Option<u32> {
        let idx = self.index(pa).ok()?;
        if self.refs[idx] == 0 {
            return None;
        }
        Some(u32::from(self.refs[idx]))
    }

    /// Whether more than one holder maps `pa`.
    #[must_use]
    pub fn is_shared(&self, pa: u64) -> bool {
        self.refs(pa).is_some_and(|r| r > 1)
    }

    /// How many frames are currently in the SHARED tier (refs > 1) —
    /// the residue gauge: after both sides of a fork finish their
    /// copy-or-promote transitions, this must read zero.
    #[must_use]
    pub fn shared_frames(&self) -> usize {
        self.refs.iter().filter(|&&r| r > 1).count()
    }

    /// Test seam: plant an exact count (the overflow test's setup —
    /// no production caller).
    #[cfg(test)]
    pub fn set_refs_for_test(&mut self, pa: u64, refs: RefCount) {
        let idx = self.index(pa).expect("test seam: pa inside the pool");
        self.refs[idx] = refs;
        if refs != 0 {
            self.owners[idx] = 0;
        }
    }
}

impl<const N: usize> Default for FrameShares<N> {
    fn default() -> Self {
        // A zero-geometry default: every pa is NotHeld. Production
        // constructs with the real pool's base and frame size.
        Self::new(0, 0)
    }
}
/// What the fault path should do with a user page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowDecision {
    /// Copy the frame, remap RW at the copy, resume the faulting
    /// instruction (refs > 1: another address space still maps the
    /// original).
    Copy,
    /// Re-promote the PTE to writable IN PLACE — no copy (refs == 1:
    /// every sibling already copied; the last holder owns the frame
    /// outright, it just still wears the fork's demote). Found live:
    /// the first sibling's copy drops refs to one, and the second
    /// writer's identical fault was refused by the refs>1 premise.
    Promote,
    /// Not ours to fix: the existing fault semantics apply (the
    /// monitor's record and the domain's death).
    NotCow,
}

/// The copy-on-write decision, PURE over its inputs — the full truth
/// table is host-tested, and exactly one combination is `Copy`:
///
/// - the PTE is **present** (an absent page is a real fault — mmap is
///   eager, not demand-paged this round);
/// - the PTE is **user** (a kernel PTE in a user fault is a bug, and
///   a kernel-half access from CPL3 is a violation by definition);
/// - the PTE is **read-only** AND the **region** says writable — the
///   demote-marker fork left (a region that is itself read-only makes
///   the write a real violation);
/// - the frame is **shared** (`refs > 1` — a private demoted page has
///   no other holder to protect);
/// - the fault is a **WRITE** (a read fault on a demoted PTE is
///   served by the read-only mapping itself).
#[must_use]
pub fn cow_decision(
    pte_present: bool,
    pte_writable: bool,
    pte_user: bool,
    region_writable: bool,
    refs: Option<u32>,
    is_write: bool,
) -> CowDecision {
    if pte_present && pte_user && !pte_writable && region_writable && is_write {
        match refs {
            Some(r) if r > 1 => CowDecision::Copy,
            // A lone reference on a demoted page: the demote outlived
            // its reason — the frame is already private.
            Some(1) => CowDecision::Promote,
            // No entry: the page never shared (a plain read-only
            // mapping — the write is a real violation).
            _ => CowDecision::NotCow,
        }
    } else {
        CowDecision::NotCow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test pool: base 16 MiB, 4 KiB frames, 64 slots (geometry
    /// mirrors the kernel's constants, scaled down).
    fn table() -> FrameShares<64> {
        FrameShares::new(16 * 1024 * 1024, 4096)
    }
    fn pa(i: u64) -> u64 {
        16 * 1024 * 1024 + i * 4096
    }

    #[test]
    fn refcount_overflow_refuses_instead_of_saturating_silently() {
        let mut s = table();
        s.set_refs_for_test(pa(3), RefCount::MAX);
        assert_eq!(s.acquire(pa(3), 1), Err(ShareError::Overflow(pa(3))));
        // The count did not wrap.
        assert_eq!(s.refs(pa(3)), Some(u32::from(RefCount::MAX)));
    }

    #[test]
    fn insertion_starts_at_two_and_keeps_the_original_owner() {
        let mut s = table();
        s.acquire(pa(1), 7).unwrap();
        assert_eq!(s.refs(pa(1)), Some(2));
        assert_eq!(s.owner_of(pa(1)), Some(7));
        // A second sharer: the count grows, the provenance stays.
        s.acquire(pa(1), 9).unwrap();
        assert_eq!(s.refs(pa(1)), Some(3));
        assert_eq!(s.owner_of(pa(1)), Some(7));
    }

    #[test]
    fn release_to_one_keeps_the_orphaned_tier() {
        // refs 2 -> 1 keeps the entry (the Promote tier + the owner
        // tag for the last holder's tagged free); 1 -> 0 clears it.
        let mut s = table();
        s.acquire(pa(2), 5).unwrap();
        assert_eq!(s.release(pa(2)), Ok(false));
        assert_eq!(s.refs(pa(2)), Some(1));
        assert_eq!(s.owner_of(pa(2)), Some(5));
        assert!(!s.is_shared(pa(2)));
        assert_eq!(s.release(pa(2)), Ok(true));
        assert_eq!(s.refs(pa(2)), None);
        assert_eq!(s.owner_of(pa(2)), None);
        // Underflow is typed, never a wrap.
        assert_eq!(s.release(pa(2)), Err(ShareError::NotHeld(pa(2))));
    }

    #[test]
    fn out_of_pool_geometry_is_refused_loudly() {
        let mut s = table();
        assert_eq!(s.acquire(0x1000, 1), Err(ShareError::NotHeld(0x1000)));
        assert_eq!(
            s.acquire(pa(999_999), 1),
            Err(ShareError::NotHeld(pa(999_999)))
        );
        // Not frame-aligned inside the pool:
        assert_eq!(s.acquire(pa(1) + 8, 1), Err(ShareError::NotHeld(pa(1) + 8)));
    }

    /// ADR-0032 section C: the round-A finding, killed — a domain with
    /// 2000 distinct pages must fork. The old linear table refused at
    /// 64 SYSTEM-WIDE.
    #[test]
    fn a_2000_page_domain_forks() {
        // A pool-sized table (the kernel's real N).
        let mut s = FrameShares::<4096>::new(16 * 1024 * 1024, 4096);
        for i in 0..2000u64 {
            s.acquire(16 * 1024 * 1024 + i * 4096, 42).unwrap();
        }
        assert_eq!(s.shared_frames(), 2000);
        // Every count and owner is queryable, O(1), none lost.
        for i in 0..2000u64 {
            let p = 16 * 1024 * 1024 + i * 4096;
            assert_eq!(s.refs(p), Some(2));
            assert_eq!(s.owner_of(p), Some(42));
        }
    }

    /// ADR-0032 section C: repeated fork/exit cycles conserve the
    /// counts — nothing leaks into any tier.
    #[test]
    fn fork_exit_cycles_conserve_everything() {
        let mut s = table();
        for cycle in 0..50 {
            for i in 0..20u64 {
                s.acquire(pa(i), 3).unwrap();
            }
            for i in 0..20u64 {
                // holder 1 copies away (release), holder 2 exits
                // (release to zero, frees under the original tag).
                assert_eq!(s.release(pa(i)), Ok(false));
                assert_eq!(s.release(pa(i)), Ok(true));
            }
            assert_eq!(s.shared_frames(), 0, "cycle {cycle} left shared residue");
            for i in 0..20u64 {
                assert_eq!(s.refs(pa(i)), None, "cycle {cycle} leaked a count");
            }
        }
    }

    /// ADR-0032 section C: both sides of a fork finishing their
    /// copy-or-promote transitions leaves no residue — the shared tier
    /// reads zero and the orphaned tier holds only what still wears a
    /// demote marker.
    #[test]
    fn promote_leaves_no_residue() {
        let mut s = table();
        s.acquire(pa(4), 11).unwrap(); // fork: refs 2, both demoted
        s.acquire(pa(5), 11).unwrap();
        // Parent writes pa(4): Copy (refs>1) -> release to 1 + the
        // parent now maps a private copy.
        assert_eq!(s.release(pa(4)), Ok(false));
        // Child writes pa(4): Promote (refs==1) — in place, no copy;
        // the frame becomes fully private only when the child exits.
        assert_eq!(s.refs(pa(4)), Some(1));
        // Both sides of pa(5) write: two copies, the frame goes private.
        assert_eq!(s.release(pa(5)), Ok(false)); // first sibling
        assert_eq!(s.release(pa(5)), Ok(true)); // second sibling
        assert_eq!(s.refs(pa(5)), None);
        assert_eq!(s.shared_frames(), 0);
        // The orphaned tier is exactly the frames still wearing a
        // demote (pa(4), whose child has not exited yet).
        assert_eq!(s.owner_of(pa(4)), Some(11));
    }

    #[test]
    fn the_truth_table_has_exactly_one_copy() {
        for present in [false, true] {
            for pte_w in [false, true] {
                for user in [false, true] {
                    for region_w in [false, true] {
                        for refs in [None, Some(1), Some(2), Some(9)] {
                            for write in [false, true] {
                                let got = cow_decision(present, pte_w, user, region_w, refs, write);
                                // EQUIVALENCE, not a count: the Copy
                                // family exactly when the five page
                                // conditions hold AND a refcount exists;
                                // the family splits by the count
                                // (Copy >1, Promote ==1).
                                let page_conditions =
                                    present && !pte_w && user && region_w && write;
                                let want = if !page_conditions || refs.is_none() {
                                    CowDecision::NotCow
                                } else if refs == Some(1) {
                                    CowDecision::Promote
                                } else {
                                    CowDecision::Copy
                                };
                                assert_eq!(
                                    got, want,
                                    "({present}, {pte_w}, {user}, {region_w}, {refs:?}, {write})"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
