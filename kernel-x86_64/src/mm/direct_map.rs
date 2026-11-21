//! Direct-map translation (ADR-0002, the access rules restated by
//! ADR-0024 D3): every physical address below 1 GiB is reachable at
//! `DIRECT_MAP_BASE + pa`, RW, kernel-only, never executable. Pure
//! arithmetic — host-tested.
//!
//! WHO MAY REACH THROUGH IT (the ADR-0024 D3 rules, one place):
//! - THE KERNEL ITSELF, as the memory manager: every page-table walk,
//!   PTE edit, frame scrub, and page copy goes through this window —
//!   addressing all of RAM is the memory manager's job, exactly once,
//!   in one place (the allowlisted `memops` + the table walks).
//! - NOBODY ELSE. The identity map is DEAD (PML4[0] zeroed at `mm::init`
//!   and asserted by read-back — the `identity=pml4[0]:0` boot line);
//!   devices reach memory ONLY through the DMA broker's cookies on
//!   IOMMU lanes (ADR-0013 D6) or through pool-owned identity frames on
//!   the no-IOMMU lane (the documented degradation); ring-3 reaches
//!   memory ONLY through the ten-check policy's PTEs (spawn's layout
//!   or ADR-0024 D1's mmap windows). An ambient physical window for
//!   anyone but the manager is the thing ADR-0002 killed.
//! - If untrusted kernel modules ever arrive (ROADMAP: driver
//!   isolation), the per-owner windowing question reopens.

/// PML4[273]: the direct-map window base.
pub const DIRECT_MAP_BASE: u64 = 0xFFFF_8880_0000_0000;

/// How much physical memory the stub maps there: one 1 GiB huge page
/// (QEMU runs with 128 MiB; the frame pool at 16..17 MiB, the multiboot
/// info, and the stub's own tables all live well inside it).
pub const DIRECT_MAP_SIZE: u64 = 1 << 30;

/// Physical address → direct-map virtual address.
#[must_use]
pub const fn pa_to_va(pa: u64) -> u64 {
    DIRECT_MAP_BASE + pa
}

/// Direct-map virtual address → physical address, or `None` when `va`
/// is outside the window (below it, past its end, or in another region
/// entirely — user space, kernel image, non-canonical).
#[must_use]
pub const fn va_to_pa(va: u64) -> Option<u64> {
    if va >= DIRECT_MAP_BASE && va < DIRECT_MAP_BASE + DIRECT_MAP_SIZE {
        Some(va - DIRECT_MAP_BASE)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_within_the_window() {
        for pa in [0u64, 1, 4096, 0x1000_0000, DIRECT_MAP_SIZE - 1] {
            assert_eq!(va_to_pa(pa_to_va(pa)), Some(pa));
        }
    }

    #[test]
    fn the_window_boundaries_are_exact() {
        assert_eq!(pa_to_va(0), DIRECT_MAP_BASE);
        assert!(va_to_pa(DIRECT_MAP_BASE).is_some());
        assert!(va_to_pa(DIRECT_MAP_BASE + DIRECT_MAP_SIZE - 1).is_some());
        // One past the end is already unmapped.
        assert_eq!(va_to_pa(DIRECT_MAP_BASE + DIRECT_MAP_SIZE), None);
        // Below the window (the whole user half, the NULL page included).
        assert_eq!(va_to_pa(0), None);
        assert_eq!(va_to_pa(0x7FFF_FFFF_FFFF), None);
    }

    #[test]
    fn other_kernel_regions_are_rejected() {
        // The kernel image window is NOT the direct map.
        assert_eq!(va_to_pa(0xFFFF_FFFF_8000_0000), None);
        // Neither is the stack region.
        assert_eq!(va_to_pa(0xFFFF_FFFF_4000_0000), None);
        // Non-canonical addresses.
        assert_eq!(va_to_pa(0x0000_8000_0000_0000), None);
    }

    #[test]
    fn translation_is_offset_only_no_flags() {
        // No masking tricks: the VA is exactly base + pa.
        assert_eq!(pa_to_va(0x1234), DIRECT_MAP_BASE + 0x1234);
    }
}
