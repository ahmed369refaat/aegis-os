//! Canonical ring-3 user layout (PR-1.4): where a user blob's code,
//! data, and stack live in the user half, and which policy flags each
//! region carries.
//!
//! Invariants:
//! - Every base is page-aligned, above the NULL page, and far below
//!   `pte::USER_LIMIT` — the user half is structural (ADR-0002).
//! - Guard gaps of at least one page separate all regions, as the core
//!   policy demands (`GuardGap` otherwise); here they are one-to-two
//!   and four pages wide (the code region grew to two pages in
//!   ADR-0029, narrowing the code→data gap to the policy minimum), so
//!   a runaway stack pointer or code fetch lands in an *absent* PTE,
//!   not a neighbor.
//! - Code is RX (NX clear), data and stack are RW with NX set — W^X at
//!   the hardware level, exactly as `mm::pte` translates it.
//! - The layout is policy-legal by construction: the host test maps all
//!   three regions through the real `AddressSpace` gate and proves an
//!   adjacent placement is still refused.

use aegis_os::memory::MemFlags;

/// User code: RX pages at the classic 4 MiB mark. Two pages since
/// ADR-0029 (the proof blob crossed 4096 bytes with mode 12 — 3372 →
/// 4398, a real capacity signal, not a one-off; the TTY/shell proofs
/// of the remaining M3 phases will only grow). The code→data guard
/// gap narrows from two pages to one — still a full absent-PTE page,
/// still policy-legal (the layout test pins it).
pub const CODE_BASE: u64 = 0x0040_0000;
pub const CODE_PAGES: usize = 2;
/// User data: one RW page, two guard pages above the code region.
pub const DATA_BASE: u64 = 0x0040_3000;
pub const DATA_PAGES: usize = 1;
/// User stack: one RW page; the initial RSP is its top (pushes go down).
/// Four guard pages separate it from the data region.
pub const STACK_BASE: u64 = 0x0040_8000;
pub const STACK_TOP: u64 = STACK_BASE + 4096;
pub const STACK_PAGES: usize = 1;

/// ADR-0023 D8: the signal trampoline — one RX page, clear of every
/// region and guard gap (after the stack region). Content: the 9-byte
/// `mov eax, 15; syscall; ud2` (rt_sigreturn; the ud2 catches a
/// kernel bug that would return instead of replacing the context).
pub const TRAMPOLINE_BASE: u64 = 0x0040_C000;
pub const TRAMPOLINE_PAGES: usize = 1;

/// The trampoline's exact bytes (mov eax,15 / syscall / ud2).
pub const TRAMPOLINE: [u8; 9] = [0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x0f, 0x0b];

/// Total pages a spawned user domain claims against its quota.
pub const TOTAL_PAGES: usize = CODE_PAGES + DATA_PAGES + STACK_PAGES + TRAMPOLINE_PAGES;

pub fn code_flags() -> MemFlags {
    MemFlags::READ | MemFlags::EXEC
}
pub fn data_flags() -> MemFlags {
    MemFlags::READ | MemFlags::WRITE
}
pub fn stack_flags() -> MemFlags {
    MemFlags::READ | MemFlags::WRITE
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_os::memory::{AddressSpace, MemError, PAGE_SIZE};

    /// The whole layout must be accepted by the real ten-check policy,
    /// and an adjacent placement must still be refused — the layout is
    /// legal by construction, not by hope.
    #[test]
    fn layout_passes_the_real_policy_gate() {
        let mut sp = AddressSpace::new(16);
        sp.map(CODE_BASE as usize, CODE_PAGES * PAGE_SIZE, code_flags())
            .expect("code region legal");
        sp.map(DATA_BASE as usize, DATA_PAGES * PAGE_SIZE, data_flags())
            .expect("data region legal");
        sp.map(STACK_BASE as usize, STACK_PAGES * PAGE_SIZE, stack_flags())
            .expect("stack region legal");
        // ADR-0023 D8: the signal trampoline (RX, after the stack
        // region, clear of every guard gap).
        sp.map(
            TRAMPOLINE_BASE as usize,
            TRAMPOLINE_PAGES * PAGE_SIZE,
            code_flags(),
        )
        .expect("trampoline region legal");
        assert_eq!(sp.used_pages(), TOTAL_PAGES);

        // Adjacent to the code region (no guard page) → refused.
        let adjacent = CODE_BASE + CODE_PAGES as u64 * 4096;
        assert_eq!(
            sp.map(adjacent as usize, PAGE_SIZE, data_flags()),
            Err(MemError::GuardGap)
        );
    }

    #[test]
    fn regions_are_aligned_gapped_and_below_the_split() {
        use crate::mm::pte::USER_LIMIT;
        for base in [CODE_BASE, DATA_BASE, STACK_BASE, TRAMPOLINE_BASE] {
            assert_eq!(base % 4096, 0, "{base:#x} aligned");
            assert!(base > 0, "NULL page never mappable");
            assert!(base < USER_LIMIT, "{base:#x} in the user half");
        }
        // Guard gaps: strictly more than one page between regions.
        let code_end = CODE_BASE + CODE_PAGES as u64 * 4096;
        let data_end = DATA_BASE + DATA_PAGES as u64 * 4096;
        assert!(DATA_BASE - code_end >= 4096, "code→data gap");
        assert!(STACK_BASE - data_end >= 4096, "data→stack gap");
        let stack_end = STACK_BASE + STACK_PAGES as u64 * 4096;
        assert!(TRAMPOLINE_BASE - stack_end >= 4096, "stack→trampoline gap");
        // W^X: no region is both writable and executable.
        assert!(!code_flags().contains(MemFlags::WRITE));
        assert!(!data_flags().contains(MemFlags::EXEC));
        assert!(!stack_flags().contains(MemFlags::EXEC));
    }
}
