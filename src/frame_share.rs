//! ADR-0024 (Phase 3): frame reference counts and the copy-on-write
//! decision — the pure root of fork's memory half.
//!
//! One refcount per PHYSICAL frame that more than one address space
//! maps. Private frames (the overwhelmingly common case) never enter
//! the table at all: `refs == None` means "not shared" and every CoW
//! decision treats it as private. The table is kernel-global state in
//! the booted system (single CPU, one pool); the pure functions here
//! are host-tested against the full truth table.

/// How many frames may be shared at once. Bounded by design: shared
/// frames are the exception (fork windows), not the heap; overflow is
/// a loud typed refusal, never a silent drop of a count.
pub const MAX_SHARED: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareError {
    /// The table is full; the would-be share refuses loudly.
    TableFull,
    /// A release of a frame the table does not hold (an underflow
    /// guard: 0-1 must never wrap).
    NotHeld(u64),
    /// The count cannot grow past `u32::MAX`.
    Overflow(u64),
}

/// The per-frame reference table.
pub struct FrameShares {
    entries: [Option<(u64, u32)>; MAX_SHARED],
}

impl Default for FrameShares {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameShares {
    #[must_use]
    pub const fn new() -> Self {
        FrameShares {
            entries: [None; MAX_SHARED],
        }
    }

    /// Add one reference to `pa`, inserting it if this is the first.
    pub fn acquire(&mut self, pa: u64) -> Result<(), ShareError> {
        for slot in self.entries.iter_mut() {
            match *slot {
                Some((p, refs)) if p == pa => {
                    let next = refs.checked_add(1).ok_or(ShareError::Overflow(pa))?;
                    *slot = Some((pa, next));
                    return Ok(());
                }
                _ => {}
            }
        }
        // Absent: insert at the first free slot.
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some((pa, 1));
                return Ok(());
            }
        }
        Err(ShareError::TableFull)
    }

    /// Drop one reference. `Ok(true)` = that was the LAST one — the
    /// caller frees the frame through the pool. `Ok(false)` = the
    /// frame still has holders. `Err(NotHeld)` = an underflow attempt.
    pub fn release(&mut self, pa: u64) -> Result<bool, ShareError> {
        for slot in self.entries.iter_mut() {
            match *slot {
                Some((p, refs)) if p == pa => {
                    if refs == 1 {
                        *slot = None;
                        return Ok(true);
                    }
                    *slot = Some((pa, refs - 1));
                    return Ok(false);
                }
                _ => {}
            }
        }
        Err(ShareError::NotHeld(pa))
    }

    /// The current count, or `None` when the frame is not shared.
    #[must_use]
    pub fn refs(&self, pa: u64) -> Option<u32> {
        self.entries
            .iter()
            .flatten()
            .find(|&&(p, _)| p == pa)
            .map(|&(_, r)| r)
    }

    /// Whether more than one holder maps `pa`.
    #[must_use]
    pub fn is_shared(&self, pa: u64) -> bool {
        self.refs(pa).is_some_and(|r| r > 1)
    }

    /// Test seam: plant an exact count (the overflow test's setup —
    /// no production caller).
    #[cfg(test)]
    pub fn set_refs_for_test(&mut self, pa: u64, refs: u32) {
        for slot in self.entries.iter_mut() {
            if matches!(*slot, Some((p, _)) if p == pa) {
                *slot = Some((pa, refs));
                return;
            }
        }
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some((pa, refs));
                return;
            }
        }
    }
}

/// What the fault path should do with a user page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowDecision {
    /// Copy the frame, remap RW, resume the faulting instruction.
    Copy,
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
    if pte_present
        && pte_user
        && !pte_writable
        && region_writable
        && refs.is_some_and(|r| r > 1)
        && is_write
    {
        CowDecision::Copy
    } else {
        CowDecision::NotCow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refcount_overflow_refuses_instead_of_saturating_silently() {
        let mut s = FrameShares::new();
        s.set_refs_for_test(0x3000, u32::MAX);
        assert_eq!(s.acquire(0x3000), Err(ShareError::Overflow(0x3000)));
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
                                // EQUIVALENCE, not a count: Copy exactly
                                // when all six conditions hold.
                                let spelled_out = present
                                    && !pte_w
                                    && user
                                    && region_w
                                    && refs.is_some_and(|r| r > 1)
                                    && write;
                                assert_eq!(
                                    got,
                                    if spelled_out {
                                        CowDecision::Copy
                                    } else {
                                        CowDecision::NotCow
                                    },
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
