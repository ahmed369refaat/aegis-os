//! The virtual address space layout of the booted kernel (ADR-0002).
//!
//! Pure constants and translation arithmetic — host-tested. The
//! bring-up mapping itself is built by the boot stub and torn down /
//! extended by `mm::init`, `mm::stacks`, and `mm::page_table` on the
//! target.
//!
//! ```text
//!   0x0000_0000_0000_0000 ┌────────────────────────────────────────┐
//!                         │ USER HALF — per-domain tables (PR-1.3):│
//!                         │ the ten-check policy gates every region;│
//!                         │ its decisions become real PTEs. The    │
//!                         │ stub's identity window is torn down in │
//!                         │ mm::init; guard gaps are absent PTEs.  │
//!   0xFFFF_8880_0000_0000 ├────────────────────────────────────────┤ PML4[273]
//!                         │ direct map: PA 0..1 GiB, RW+NX, G      │
//!   0xFFFF_FFFF_4000_0000 ├────────────────────────────────────────┤ PML4[511]·PDPT[509]
//!                         │ guarded kernel stacks (mm/stacks.rs)   │
//!   0xFFFF_FFFF_8000_0000 ├────────────────────────────────────────┤ PML4[511]·PDPT[510]
//!                         │ kernel image: RX text, RO data, RW     │
//!                         │ data+bss+boot stack (one 2 MiB huge    │
//!                         │ page @ PA 2 MiB)                       │
//!                         └────────────────────────────────────────┘
//! ```

pub mod direct_map;
pub mod image;
pub mod page_table;
pub mod pte;
pub mod stacks;
pub mod user;
pub mod user_layout;
pub mod user_range;

/// The kernel link base (one 2 MiB huge page at PA 2 MiB).
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Page/frame size in bytes.
pub const PAGE: u64 = 4096;

/// Present | Write (the flag bits every table mapping here uses).
pub const PTE_P_RW: u64 = 0x3;

/// Mask off flag bits to get a table/frame physical address from an entry.
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Tear down the stub's low identity window, arm the ISA features the
/// per-domain tables need (EFER.NXE, CR4.PGE), mark the shared kernel
/// leaves global (+ the direct map non-executable), and set up the
/// per-CPU state.
///
/// After this returns, low virtual addresses are UNMAPPED, W^X and NX
/// are hardware-enforced, and kernel entries survive CR3 switches. The
/// only ways to reach physical memory are the direct map and the kernel
/// window. Called once from `kmain`, right after `arch::init` (so any
/// fault in here is diagnosed, not triple-faulted).
#[cfg(not(test))]
pub fn init() {
    use crate::{arch, hw, memops, serial};

    // PML4[0] = 0: the identity window the stub needed for bring-up
    // dies here. The write itself goes through the direct map, which is
    // unaffected — PML4[273] is a different entry.
    let pml4_pa = hw::read_cr3() & ADDR_MASK;
    memops::write_u64(pml4_pa, 0);

    // EFER.NXE (bit 11): the XD bit in every PTE starts meaning
    // "instruction fetch denied" — W^X becomes a hardware property.
    const MSR_EFER: u32 = 0xC000_0080;
    let efer = hw::rdmsr(MSR_EFER);
    hw::wrmsr(MSR_EFER, efer | (1 << 11));

    // CR4.PGE (bit 7): global leaf entries survive CR3 switches, so the
    // kernel half stops thrashing the TLB the moment domains exist.
    let cr4 = hw::read_cr4();
    hw::write_cr4(cr4 | (1 << 7));

    // Mark the shared kernel leaves global, and the direct map
    // non-executable (ADR-0002: RW only, never X):
    //   pml4[273] → pdpt_dm[0]   (1 GiB direct map)       |= G | NX
    //   pml4[511] → pdpt_hh[510] → pd_hh[0] (kernel image) |= G
    let dm = memops::read_u64(pml4_pa + 273 * 8) & ADDR_MASK;
    memops::write_u64(dm, memops::read_u64(dm) | pte::PTE_G | pte::PTE_NX);
    let hh = memops::read_u64(pml4_pa + 511 * 8) & ADDR_MASK;
    let pd = memops::read_u64(hh + 510 * 8) & ADDR_MASK;
    memops::write_u64(pd, memops::read_u64(pd) | pte::PTE_G);

    // F15 (ADR-0006): replace the image's single RWX 2 MiB leaf with
    // per-4KiB PTEs (.text RX, .rodata RO+NX, .data/.bss RW+NX, gaps
    // and the boot-stack guard absent) and set CR0.WP — BEFORE the CR3
    // reload below, so one flush covers both.
    arch::image_map::install();

    // Reload CR3 (same value): flushes every non-global entry and
    // rebuilds the TLB under the new NXE/PGE semantics.
    hw::write_cr3(pml4_pa);
    // Prove the teardown through the direct map — if the write or the
    // flush were wrong, this is the loud place to fail (panic prints
    // its location and halts; formatted panic messages need core::fmt,
    // which the boot-path panic handler deliberately does without).
    assert!(memops::read_u64(pml4_pa) == 0);

    arch::percpu::init();

    let cpu = arch::percpu::get().cpu_id;
    let mut b = [0u8; 18];
    serial::write_str("[MM ] higher-half ok: base=");
    serial::write_str(crate::strutil::hex(KERNEL_BASE, &mut b));
    serial::write_str(" identity=pml4[0]:0 nx=on pge=on percpu:cpu=");
    let mut b2 = [0u8; 20];
    serial::write_str(crate::strutil::dec(cpu as u64, &mut b2));
    serial::write_str("\n");
}