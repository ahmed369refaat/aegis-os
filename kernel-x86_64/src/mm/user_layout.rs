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

/// K22: the per-image memory contract — where an exec'd image's
/// PT_LOADs may live, and where the kernel provisions its stack and
/// signal trampoline. The constants above are the CANONICAL contract
/// (every flat blob and every image so far); the package manager is
/// `no_alloc` by design — every buffer is a fixed stack array (the
/// measured worst direct-call chain is 57.6 KiB, the solver's
/// recursion budget deeper still) — so its image declares a contract
/// of its own: a wider cage for 134 KiB of code, and a 256 KiB stack.
///
/// Invariants (host-tested against the real ten-check policy gate):
/// - `code_base` is page-aligned and above the NULL page;
/// - the cage, the stack region and the trampoline are pairwise
///   separated by at least one absent page (the policy's `GuardGap`);
/// - everything sits below `pte::USER_LIMIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecLayout {
    /// The lowest address a PT_LOAD may start at.
    pub code_base: u64,
    /// One past the highest address a PT_LOAD may occupy: the image
    /// cage. The stack, the trampoline and every guard gap are
    /// kernel-provisioned and non-negotiable.
    pub cage_end: u64,
    /// The stack region's base; the initial RSP is its top.
    pub stack_base: u64,
    /// Stack pages (4 KiB each) charged against the domain's quota.
    pub stack_pages: usize,
    /// The signal trampoline page (RX, clear of every other region).
    pub trampoline_base: u64,
}

impl ExecLayout {
    /// The initial stack pointer: the top of the stack region (pushes
    /// go down).
    #[must_use]
    pub const fn stack_top(&self) -> u64 {
        self.stack_base + self.stack_pages as u64 * 4096
    }

    /// The lowest address mmap/grant windows may be placed at: one
    /// page above the trampoline (the spawn-time layout is below it
    /// and is freed by teardown, never by munmap).
    #[must_use]
    pub const fn window_floor(&self) -> u64 {
        self.trampoline_base + 4096
    }

    /// Pages this layout charges for the kernel-provisioned regions.
    #[must_use]
    pub const fn overhead_pages(&self) -> usize {
        self.stack_pages + TRAMPOLINE_PAGES
    }
}

/// The contract every flat blob and every earlier image runs under —
/// exactly the constants above. The cage stops ONE PAGE below the
/// stack: that page is the guard gap the ten-check policy demands
/// between an image's last segment and the stack region (`GuardGap`
/// otherwise — an image reaching 0x408000 would be refused by the
/// mapper, so the cage says so up front).
pub const CANONICAL: ExecLayout = ExecLayout {
    code_base: CODE_BASE,
    cage_end: STACK_BASE - 4096,
    stack_base: STACK_BASE,
    stack_pages: STACK_PAGES,
    trampoline_base: TRAMPOLINE_BASE,
};

/// K22: the service contract — the package manager's. The cage is
/// 128 pages (512 KiB) for a linked `no_alloc` image (the measured
/// `.text` + `.rodata` + `.data` is ~134 KiB, ~35 pages; the cage
/// leaves room for the image to grow without a layout change); the
/// stack is 64 pages (256 KiB) — 4.4× the measured worst direct-call
/// chain — two MiB above the cage's end.
pub const SERVICE: ExecLayout = ExecLayout {
    code_base: CODE_BASE,
    cage_end: 0x0048_0000,
    stack_base: 0x0060_0000,
    stack_pages: 64,
    trampoline_base: 0x0064_4000,
};

/// K22: the image cage in pages for a layout (what
/// `exec_quota_check` compares the plan's `map_bytes` against).
#[must_use]
pub const fn cage_pages(layout: &ExecLayout) -> usize {
    ((layout.cage_end - layout.code_base) / 4096) as usize
}

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

    /// K22: both contracts are whole-image legal — every region of
    /// each layout (the full cage as one image extent, the stack, the
    /// trampoline) passes the real ten-check policy, the pages sum to
    /// what the quota check will charge, and an image region touching
    /// the stack across the cage edge is still refused (`GuardGap`).
    #[test]
    fn every_exec_layout_passes_the_policy_gate_as_a_whole_image() {
        use crate::mm::pte::USER_LIMIT;
        for layout in [CANONICAL, SERVICE] {
            let mut sp = AddressSpace::new(1024);
            let cage = cage_pages(&layout) * PAGE_SIZE;
            sp.map(layout.code_base as usize, cage, code_flags())
                .expect("the whole cage is a legal image extent");
            sp.map(
                layout.stack_base as usize,
                layout.stack_pages * PAGE_SIZE,
                stack_flags(),
            )
            .expect("stack region legal");
            sp.map(
                layout.trampoline_base as usize,
                TRAMPOLINE_PAGES * PAGE_SIZE,
                code_flags(),
            )
            .expect("trampoline region legal");
            assert_eq!(
                sp.used_pages(),
                cage_pages(&layout) + layout.overhead_pages(),
                "{:?}",
                layout
            );
            // No image page may sit AT the cage end: canonical leaves
            // there the stack's guard page, service a guard gap — the
            // mapper refuses both (`GuardGap`), so the cage check is
            // what stands between an image and the mapper's refusal.
            assert_eq!(
                sp.map(layout.cage_end as usize, PAGE_SIZE, code_flags()),
                Err(MemError::GuardGap),
                "{:?}",
                layout
            );
            // The structural invariants.
            for base in [layout.code_base, layout.stack_base, layout.trampoline_base] {
                assert_eq!(base % 4096, 0, "{base:#x} aligned");
                assert!(base > 0 && base < USER_LIMIT, "{base:#x} in the user half");
            }
            assert_eq!(layout.cage_end % 4096, 0);
            assert!(
                layout.stack_base - layout.cage_end >= 4096,
                "cage→stack gap"
            );
            let stack_end = layout.stack_base + layout.stack_pages as u64 * 4096;
            assert_eq!(layout.stack_top(), stack_end);
            assert!(
                layout.trampoline_base - stack_end >= 4096,
                "stack→trampoline gap"
            );
            assert_eq!(layout.window_floor(), layout.trampoline_base + 4096);
            // The mmap window floor is free in a fresh image space.
            assert!(sp
                .find_free_window(PAGE_SIZE, layout.window_floor() as usize)
                .is_some());
        }
    }

    /// K22: the two contracts at a glance — the canonical one is the
    /// constants, the service one is wider on both axes, and the
    /// package manager's quota (192) covers its whole footprint.
    #[test]
    fn the_service_contract_is_wider_and_fits_the_pkg_quota() {
        assert_eq!(CANONICAL.stack_top(), STACK_TOP);
        assert_eq!(CANONICAL.window_floor(), TRAMPOLINE_BASE + 4096);
        assert_eq!(
            cage_pages(&CANONICAL),
            7,
            "8 pages minus the stack's guard page"
        );
        assert_eq!(cage_pages(&SERVICE), 128);
        assert_eq!(SERVICE.stack_pages, 64);
        assert_eq!(SERVICE.stack_top(), 0x0064_0000);
        assert_eq!(SERVICE.overhead_pages(), 65);
        // The measured image: ~35 pages. 35 + 65 = 100 ≤ 192.
        assert!(
            35 + SERVICE.overhead_pages()
                <= aegis_os::profile::package_manager_profile().quota_pages
        );
        // The canonical contract still fits the service quota, and
        // the service contract does NOT fit the app quota (64): only
        // a profile that budgeted for it may declare it.
        assert!(7 + CANONICAL.overhead_pages() <= aegis_os::profile::service_profile().quota_pages);
        assert!(128 + SERVICE.overhead_pages() > aegis_os::profile::app_profile().quota_pages);
    }
}
