//! Per-domain address space model: W^X, guard gaps, alignment, quotas,
//! wraparound protection and scrub-on-release accounting.
//!
//! `map` performs every check in a fixed order (validation is itself
//! deterministic): length, null base, alignment, overflow, W^X, access bits,
//! overlap, guard gap, quota, slot availability. `unmap` returns the region
//! and counts its pages as scrubbed — in a real kernel the page allocator
//! zeroes the pages here before they re-enter the free pool.

pub const PAGE_SIZE: usize = 4096;
pub const MAX_REGIONS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemFlags(pub u8);

impl MemFlags {
    pub const READ: MemFlags = MemFlags(1 << 0);
    pub const WRITE: MemFlags = MemFlags(1 << 1);
    pub const EXEC: MemFlags = MemFlags(1 << 2);
    /// Region is a guard: mapping it is metadata-only, faults on touch.
    pub const GUARD: MemFlags = MemFlags(1 << 3);

    #[must_use]
    pub const fn contains(self, other: MemFlags) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn intersects(self, other: MemFlags) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for MemFlags {
    type Output = MemFlags;
    fn bitor(self, rhs: MemFlags) -> MemFlags {
        MemFlags(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: usize,
    pub len: usize,
    pub flags: MemFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    /// `len == 0`.
    ZeroLength,
    /// `base == 0`: the NULL page is never mappable.
    NullBase,
    /// Base or length not page-aligned.
    Unaligned,
    /// `base + len` would wrap the address space.
    Overflow,
    /// W and X set simultaneously.
    WxViolation,
    /// No R/W/X bit set at all.
    NoAccessBits,
    /// Overlaps an existing region.
    Overlap,
    /// Closer than one full page to an existing region.
    GuardGap,
    /// Would exceed the domain's page quota.
    QuotaExceeded,
    /// No free region slot.
    TableFull,
    /// No region mapped at this base.
    NotFound,
}

#[derive(Clone)]
pub struct AddressSpace {
    regions: [Option<Region>; MAX_REGIONS],
    quota_pages: usize,
    used_pages: usize,
    scrubbed_pages: usize,
    require_guard_gaps: bool,
}

impl AddressSpace {
    pub fn new(quota_pages: usize) -> Self {
        AddressSpace {
            regions: [None; MAX_REGIONS],
            quota_pages,
            used_pages: 0,
            scrubbed_pages: 0,
            require_guard_gaps: true,
        }
    }

    /// Map `[base, base+len)` with the given flags after full validation.
    pub fn map(&mut self, base: usize, len: usize, flags: MemFlags) -> Result<(), MemError> {
        if len == 0 {
            return Err(MemError::ZeroLength);
        }
        if base == 0 {
            return Err(MemError::NullBase);
        }
        if !base.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
            return Err(MemError::Unaligned);
        }
        // Wraparound: the end must be representable and strictly above base.
        let end = match base.checked_add(len) {
            Some(e) if e > base => e,
            _ => return Err(MemError::Overflow),
        };
        if flags.contains(MemFlags::WRITE) && flags.contains(MemFlags::EXEC) {
            return Err(MemError::WxViolation);
        }
        if !flags.intersects(MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC) {
            return Err(MemError::NoAccessBits);
        }

        let pages = len / PAGE_SIZE;
        match self.used_pages.checked_add(pages) {
            Some(total) if total <= self.quota_pages => {}
            _ => return Err(MemError::QuotaExceeded),
        }

        for slot in self.regions.iter().flatten() {
            let r_end = slot.base + slot.len; // stored regions never overflow
            if base < r_end && slot.base < end {
                return Err(MemError::Overlap);
            }
            if self.require_guard_gaps {
                // No overlap guaranteed: new region is fully above or fully below.
                let gap = if base >= r_end {
                    base - r_end
                } else {
                    slot.base - end
                };
                if gap < PAGE_SIZE {
                    return Err(MemError::GuardGap);
                }
            }
        }

        let entry = Region { base, len, flags };
        for slot in self.regions.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.used_pages += pages;
                return Ok(());
            }
        }
        Err(MemError::TableFull)
    }

    /// Unmap the region at `base`. Its pages are counted as scrubbed
    /// (zeroed before reuse in a real kernel) and the quota is released.
    pub fn unmap(&mut self, base: usize) -> Result<Region, MemError> {
        for slot in self.regions.iter_mut() {
            if let Some(r) = *slot {
                if r.base == base {
                    *slot = None;
                    let pages = r.len / PAGE_SIZE;
                    self.used_pages = self.used_pages.saturating_sub(pages);
                    self.scrubbed_pages = self.scrubbed_pages.saturating_add(pages);
                    return Ok(r);
                }
            }
        }
        Err(MemError::NotFound)
    }

    /// ADR-0022 D4: exec resets the region ledger — the new image
    /// maps fresh. Freed pages count as scrubbed; the quota survives.
    pub fn clear_for_exec(&mut self) {
        self.scrubbed_pages = self.scrubbed_pages.saturating_add(self.used_pages);
        self.used_pages = 0;
        self.regions = [None; MAX_REGIONS];
    }

    #[must_use]
    pub fn used_pages(&self) -> usize {
        self.used_pages
    }

    #[must_use]
    pub fn quota_pages(&self) -> usize {
        self.quota_pages
    }

    #[must_use]
    pub fn scrubbed_pages(&self) -> usize {
        self.scrubbed_pages
    }

    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.iter().flatten().count()
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: MemFlags = MemFlags::READ;
    const RW: MemFlags = MemFlags(0b0011);

    #[test]
    fn map_basic_ok_and_counters_track() {
        let mut as_ = AddressSpace::new(8);
        as_.map(0x1000, 2 * PAGE_SIZE, RW).unwrap();
        assert_eq!(as_.used_pages(), 2);
        assert_eq!(as_.region_count(), 1);
        assert_eq!(as_.quota_pages(), 8);
    }

    #[test]
    fn null_base_and_zero_len_rejected() {
        let mut as_ = AddressSpace::new(8);
        assert_eq!(as_.map(0, PAGE_SIZE, R), Err(MemError::NullBase));
        assert_eq!(as_.map(0x1000, 0, R), Err(MemError::ZeroLength));
    }

    #[test]
    fn unaligned_base_or_len_rejected() {
        let mut as_ = AddressSpace::new(8);
        assert_eq!(as_.map(0x1002, PAGE_SIZE, R), Err(MemError::Unaligned));
        assert_eq!(as_.map(0x1000, 100, R), Err(MemError::Unaligned));
        assert_eq!(as_.map(1, PAGE_SIZE, R), Err(MemError::Unaligned));
    }

    #[test]
    fn wx_enforced_but_x_only_and_w_only_allowed() {
        let mut as_ = AddressSpace::new(8);
        assert_eq!(
            as_.map(0x1000, PAGE_SIZE, MemFlags(0b0110)),
            Err(MemError::WxViolation)
        );
        assert!(as_.map(0x1000, PAGE_SIZE, MemFlags::EXEC).is_ok()); // X-only
        assert!(as_.map(0x3000, PAGE_SIZE, MemFlags::WRITE).is_ok()); // W-only
                                                                      // GUARD alone is not an access bit.
        assert_eq!(
            as_.map(0x5000, PAGE_SIZE, MemFlags::GUARD),
            Err(MemError::NoAccessBits)
        );
        assert_eq!(
            as_.map(0x5000, PAGE_SIZE, MemFlags(0)),
            Err(MemError::NoAccessBits)
        );
    }

    #[test]
    fn wraparound_rejected_at_top_of_address_space() {
        let mut as_ = AddressSpace::new(8);
        let base = usize::MAX - PAGE_SIZE + 1; // 0xFF...F000, aligned
        assert_eq!(as_.map(base, PAGE_SIZE, R), Err(MemError::Overflow));
    }

    #[test]
    fn overlap_rejected() {
        let mut as_ = AddressSpace::new(16);
        as_.map(0x10000, 4 * PAGE_SIZE, R).unwrap();
        // Fully inside.
        assert_eq!(as_.map(0x11000, PAGE_SIZE, R), Err(MemError::Overlap));
        // Straddling the end.
        assert_eq!(
            as_.map(0x14000 - 0x100, 2 * PAGE_SIZE, R),
            Err(MemError::Unaligned) // not aligned; use aligned straddle below
        );
        assert_eq!(as_.map(0x13000, 2 * PAGE_SIZE, R), Err(MemError::Overlap));
    }

    #[test]
    fn guard_gap_enforced_with_exact_one_page_boundary() {
        let mut as_ = AddressSpace::new(16);
        as_.map(0x10000, PAGE_SIZE, R).unwrap();
        // Adjacent (gap 0) -> rejected.
        assert_eq!(as_.map(0x11000, PAGE_SIZE, R), Err(MemError::GuardGap));
        // Gap of exactly one page -> allowed (boundary case).
        as_.map(0x12000, PAGE_SIZE, R).unwrap();
        assert_eq!(as_.region_count(), 2);
    }

    #[test]
    fn guard_gap_below_existing_region() {
        let mut as_ = AddressSpace::new(16);
        as_.map(0x20000, PAGE_SIZE, R).unwrap();
        // New region directly below with no gap.
        assert_eq!(as_.map(0x1F000, PAGE_SIZE, R), Err(MemError::GuardGap));
        // One page of gap below is fine.
        as_.map(0x1E000, PAGE_SIZE, R).unwrap();
        assert_eq!(as_.region_count(), 2);
    }

    #[test]
    fn quota_enforced_exact_fit_ok() {
        let mut as_ = AddressSpace::new(2);
        assert!(as_.map(0x10000, PAGE_SIZE, R).is_ok());
        // Exact fit: used(1) + 1 == quota(2).
        assert!(as_.map(0x12000, PAGE_SIZE, R).is_ok());
        assert_eq!(as_.used_pages(), 2);
        // Anything more exceeds the quota.
        assert_eq!(as_.map(0x14000, PAGE_SIZE, R), Err(MemError::QuotaExceeded));
    }

    #[test]
    fn zero_quota_rejects_everything() {
        let mut as_ = AddressSpace::new(0);
        assert_eq!(as_.map(0x1000, PAGE_SIZE, R), Err(MemError::QuotaExceeded));
    }

    #[test]
    fn region_table_full_at_max_regions() {
        let mut as_ = AddressSpace::new(MAX_REGIONS + 4);
        for i in 0..MAX_REGIONS {
            // Regions spaced 2 pages apart to respect guard gaps.
            let base = 0x10000 + i * 2 * PAGE_SIZE;
            as_.map(base, PAGE_SIZE, R).unwrap();
        }
        assert_eq!(as_.region_count(), MAX_REGIONS);
        assert_eq!(
            as_.map(0x10000 + MAX_REGIONS * 2 * PAGE_SIZE, PAGE_SIZE, R),
            Err(MemError::TableFull)
        );
    }

    #[test]
    fn unmap_not_found_and_double_unmap() {
        let mut as_ = AddressSpace::new(8);
        assert_eq!(as_.unmap(0x1000), Err(MemError::NotFound));
        as_.map(0x1000, PAGE_SIZE, R).unwrap();
        as_.unmap(0x1000).unwrap();
        assert_eq!(as_.unmap(0x1000), Err(MemError::NotFound));
    }

    #[test]
    fn unmap_releases_quota_for_remap_and_counts_scrub() {
        let mut as_ = AddressSpace::new(1);
        as_.map(0x1000, PAGE_SIZE, R).unwrap();
        assert_eq!(as_.map(0x3000, PAGE_SIZE, R), Err(MemError::QuotaExceeded));
        let r = as_.unmap(0x1000).unwrap();
        assert_eq!(r.base, 0x1000);
        assert_eq!(as_.scrubbed_pages(), 1);
        assert_eq!(as_.used_pages(), 0);
        // Quota released: remap works.
        assert!(as_.map(0x1000, PAGE_SIZE, R).is_ok());
        assert_eq!(as_.scrubbed_pages(), 1, "scrub counter is cumulative");
    }

    #[test]
    fn guard_gaps_near_top_of_address_space() {
        let mut as_ = AddressSpace::new(8);
        // Highest mappable region: ends exactly at usize::MAX - PAGE_SIZE.
        let top_base = usize::MAX - 2 * PAGE_SIZE + 1;
        as_.map(top_base, PAGE_SIZE, R).unwrap();
        // Region adjacent above it (would end past the address space).
        assert_eq!(
            as_.map(top_base + PAGE_SIZE, PAGE_SIZE, R),
            Err(MemError::Overflow)
        );
        // Region adjacent below it.
        assert_eq!(
            as_.map(top_base - PAGE_SIZE, PAGE_SIZE, R),
            Err(MemError::GuardGap)
        );
    }
}
