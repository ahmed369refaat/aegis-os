//! PTE flag translation (PR-1.3): the bridge between the policy core's
//! `MemFlags` and x86-64 PTE bits. Pure — host-tested.
//!
//! Two ISA enables must be live for these bits to mean anything:
//! EFER.NXE (for `PTE_NX`) and CR4.PGE (for `PTE_G`); `mm::init` sets
//! both before the first user table exists.

use aegis_os::memory::MemFlags;

/// Page size as u64 (the lib's `PAGE_SIZE` is usize).
pub const PAGE_SIZE_U64: u64 = 4096;

/// User VAs live strictly below this (the non-canonical boundary); the
/// kernel half starts at `0xFFFF_8000_...` — nothing in between is ever
/// mapped (ADR-0002).
pub const USER_LIMIT: u64 = 1 << 47;

/// Present.
pub const PTE_P: u64 = 1;
/// Writable.
pub const PTE_W: u64 = 1 << 1;
/// User (Ring-3 reachable).
pub const PTE_U: u64 = 1 << 2;
/// Global — leaf entries only; survives CR3 switches (needs CR4.PGE).
pub const PTE_G: u64 = 1 << 8;
/// No-execute (needs EFER.NXE).
pub const PTE_NX: u64 = 1 << 63;
/// The page-size bit (PDE/PDPTE): a huge-page leaf. ADR-0024: the
/// user half is never built with leaves; a fork walk that meets one
/// refuses rather than guess at sharing its extent.
pub const PTE_PS: u64 = 1 << 7;

/// Flags for one mapped page, policy-flavored. `r` is kept for API
/// fidelity with `MemFlags`; on x86-64 a present PTE is always readable
/// (there is no read-disable bit), so it does not appear in `leaf_bits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PteFlags {
    pub r: bool,
    pub w: bool,
    pub x: bool,
    pub user: bool,
}

impl PteFlags {
    /// The classic user data page: RW, no execute.
    pub const USER_RW: PteFlags = PteFlags {
        r: true,
        w: true,
        x: false,
        user: true,
    };
    /// The classic user code page: RX (write is refused by policy and by
    /// the W bit; NX clear).
    pub const USER_RX: PteFlags = PteFlags {
        r: true,
        w: false,
        x: true,
        user: true,
    };

    /// Leaf PTE bits for a data/code page: present, W/U per flags, and
    /// **NX whenever the page is not executable** — W^X is a PTE
    /// property, not a hope.
    #[must_use]
    pub const fn leaf_bits(&self) -> u64 {
        let mut bits = PTE_P;
        if self.w {
            bits |= PTE_W;
        }
        if self.user {
            bits |= PTE_U;
        }
        if !self.x {
            bits |= PTE_NX;
        }
        bits
    }

    /// Bits for an intermediate table entry: present + writable (the
    /// page bits live in the leaf), plus U so Ring-3 walks can traverse
    /// user subtrees. Kernel-only tables pass `user: false`.
    #[must_use]
    pub const fn table_bits(user: bool) -> u64 {
        let mut bits = PTE_P | PTE_W;
        if user {
            bits |= PTE_U;
        }
        bits
    }

    /// Policy flags → PTE flags. Every mapping that went through the
    /// core's `AddressSpace::map` is a user mapping here (the kernel
    /// builds its own tables, it does not policy-map them).
    #[must_use]
    pub const fn from_memflags(f: MemFlags) -> Self {
        PteFlags {
            r: f.contains(MemFlags::READ),
            w: f.contains(MemFlags::WRITE),
            x: f.contains(MemFlags::EXEC),
            user: true,
        }
    }
}

/// Invalidate the TLB entry for one page (after unmapping it).
#[cfg(not(test))]
pub fn flush_tlb_page(va: u64) {
    crate::hw::invlpg(va);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rw_user_page_is_present_writable_user_and_nx() {
        let b = PteFlags::USER_RW.leaf_bits();
        assert!(b & PTE_P != 0);
        assert!(b & PTE_W != 0);
        assert!(b & PTE_U != 0);
        assert!(b & PTE_NX != 0, "data pages must be non-executable");
        assert_eq!(b & PTE_G, 0, "user pages are not global");
    }

    #[test]
    fn rx_user_page_is_executable_and_read_only() {
        let b = PteFlags::USER_RX.leaf_bits();
        assert!(b & PTE_P != 0);
        assert_eq!(b & PTE_W, 0, "code pages must not be writable");
        assert!(b & PTE_U != 0);
        assert_eq!(b & PTE_NX, 0, "exec pages clear NX");
    }

    #[test]
    fn table_bits_traverse_for_user_only_when_user() {
        assert!(PteFlags::table_bits(true) & PTE_U != 0);
        assert_eq!(PteFlags::table_bits(false) & PTE_U, 0);
        // Tables are always present + writable; NX belongs to leaves.
        assert!(PteFlags::table_bits(true) & PTE_P != 0);
        assert!(PteFlags::table_bits(true) & PTE_W != 0);
        assert_eq!(PteFlags::table_bits(true) & PTE_NX, 0);
    }

    #[test]
    fn memflags_translate_losslessly() {
        use aegis_os::memory::MemFlags;
        let rw = PteFlags::from_memflags(MemFlags::READ | MemFlags::WRITE);
        assert_eq!(rw, PteFlags::USER_RW);
        let rx = PteFlags::from_memflags(MemFlags::READ | MemFlags::EXEC);
        assert_eq!(rx, PteFlags::USER_RX);
        // A write-only region: present, writable, no read-disable exists,
        // still non-executable.
        let wo = PteFlags::from_memflags(MemFlags::WRITE);
        assert!(wo.leaf_bits() & PTE_W != 0);
        assert!(wo.leaf_bits() & PTE_NX != 0);
    }

    #[test]
    fn user_limit_is_the_canonical_boundary() {
        assert_eq!(USER_LIMIT, 0x0000_8000_0000_0000);
        // The kernel image and direct map are far above it — checked
        // at COMPILE time (clippy: assert_on_constants).
        const _: () = assert!(super::super::KERNEL_BASE > USER_LIMIT);
        const _: () = assert!(super::super::direct_map::DIRECT_MAP_BASE > USER_LIMIT);
    }
}
