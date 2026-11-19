//! Multiboot v1 boot-information parsing (pure functions, host-testable).
//!
//! The raw words are read from the info struct by `kmain` (via `memops`,
//! since the struct sits at a loader-chosen physical address); everything
//! after that is decided here, deterministically, with tests.

/// The value a multiboot v1 loader leaves in EAX at entry.
pub const BOOT_MAGIC: u32 = 0x2BADB002;

/// "mem_lower/mem_upper valid" flag (bit 0 of the info flags word).
pub const FLAG_MEM_INFO: u32 = 1 << 0;

/// The three words of the multiboot info struct M1 cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemInfo {
    pub flags: u32,
    pub mem_lower_kb: u32,
    pub mem_upper_kb: u32,
}

impl MemInfo {
    /// Whether the loader provided the memory-size fields at all.
    #[must_use]
    pub fn has_mem(&self) -> bool {
        self.flags & FLAG_MEM_INFO != 0
    }

    /// Highest byte of low memory implied by `mem_upper`
    /// (which counts KiB *above* the 1 MiB mark).
    #[must_use]
    pub fn top_of_low_mem(&self) -> u64 {
        1024 * 1024 + self.mem_upper_kb as u64 * 1024
    }

    /// Whether `[base, base+len)` lies fully inside reported low RAM
    /// (and above the kernel load area). This is the gate for claiming
    /// the M1 frame pool.
    #[must_use]
    pub fn contains(&self, base: u64, len: u64) -> bool {
        self.has_mem()
            && base >= 1024 * 1024
            && base.checked_add(len).map_or(false, |end| end <= self.top_of_low_mem())
    }
}

/// Parse the raw words into a `MemInfo`.
#[must_use]
pub fn parse(flags: u32, mem_lower: u32, mem_upper: u32) -> MemInfo {
    MemInfo { flags, mem_lower_kb: mem_lower, mem_upper_kb: mem_upper }
}

#[cfg(test)]
mod tests {
    use super::*;

    // QEMU `-m 128M -machine pc` typically reports ~126 MiB upper.
    fn qemu_like() -> MemInfo {
        parse(FLAG_MEM_INFO, 639, 129_000)
    }

    #[test]
    fn magic_value_is_the_multiboot_one() {
        assert_eq!(BOOT_MAGIC, 0x2BADB002);
    }

    #[test]
    fn has_mem_follows_flag_bit() {
        assert!(parse(1, 0, 0).has_mem());
        assert!(!parse(0, 639, 129_000).has_mem());
        assert!(parse(0x7, 639, 129_000).has_mem(), "bit 0 set among others");
    }

    #[test]
    fn top_of_low_mem_counts_above_one_mib() {
        let mi = parse(FLAG_MEM_INFO, 639, 1);
        assert_eq!(mi.top_of_low_mem(), 1024 * 1024 + 1024);
    }

    #[test]
    fn contains_accepts_pool_inside_low_memory() {
        let mi = qemu_like();
        // The M1 pool: 16..17 MiB.
        assert!(mi.contains(16 * 1024 * 1024, 1024 * 1024));
    }

    #[test]
    fn contains_rejects_out_of_range_and_below_kernel() {
        let mi = qemu_like();
        // Above the reported top.
        assert!(!mi.contains(mi.top_of_low_mem(), 4096));
        // End exactly at the top is fine; one byte more is not.
        assert!(mi.contains(mi.top_of_low_mem() - 4096, 4096));
        assert!(!mi.contains(mi.top_of_low_mem() - 4096, 4097));
        // Below the 1 MiB kernel area (kernel image / loader data).
        assert!(!mi.contains(0, 4096));
        assert!(!mi.contains(512 * 1024, 4096));
        // Without the mem-info flag nothing may be claimed.
        let blind = parse(0, 639, 129_000);
        assert!(!blind.contains(16 * 1024 * 1024, 1024 * 1024));
    }

    #[test]
    fn contains_handles_wraparound_safely() {
        let mi = qemu_like();
        assert!(!mi.contains(u64::MAX, 1), "base+len must not wrap into 'fits'");
        assert!(!mi.contains(u64::MAX - 100, 4096));
    }
}
