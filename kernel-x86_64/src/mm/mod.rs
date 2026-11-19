//! The virtual address space layout of the booted kernel (ADR-0002).
//!
//! Pure constants and translation arithmetic — host-tested. The
//! bring-up mapping itself is built by the boot stub and torn down /
//! extended by `mm::init` and `mm::stacks` on the target.
//!
//! ```text
//!   0x0000_0000_0000_0000 ┌────────────────────────────────────────┐
//!                         │ user half (Ring-3, per-domain tables — │
//!                         │ PR-1.3/1.4; PML4[0..256] all absent    │
//!                         │ after the stub window is torn down)    │
//!   0xFFFF_8880_0000_0000 ├────────────────────────────────────────┤ PML4[273]
//!                         │ direct map: PA 0..1 GiB, RW, never X   │
//!   0xFFFF_FFFF_4000_0000 ├────────────────────────────────────────┤ PML4[511]·PDPT[509]
//!                         │ guarded kernel stacks (mm/stacks.rs)   │
//!   0xFFFF_FFFF_8000_0000 ├────────────────────────────────────────┤ PML4[511]·PDPT[510]
//!                         │ kernel image: RX text, RO data, RW     │
//!                         │ data+bss+boot stack (one 2 MiB huge    │
//!                         │ page @ PA 2 MiB)                       │
//!                         └────────────────────────────────────────┘
//! ```

pub mod direct_map;
pub mod stacks;

/// The kernel link base (one 2 MiB huge page at PA 2 MiB).
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Page/frame size in bytes.
pub const PAGE: u64 = 4096;

/// Present | Write (the flag bits every table mapping here uses).
pub const PTE_P_RW: u64 = 0x3;

/// Mask off flag bits to get a table/frame physical address from an entry.
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Tear down the stub's low identity window and arm the per-CPU state.
///
/// After this returns, low virtual addresses are UNMAPPED: the only ways
/// to reach physical memory are the direct map and the kernel window.
/// Called once from `kmain`, right after `arch::init` (so any fault in
/// here is diagnosed, not triple-faulted).
#[cfg(not(test))]
pub fn init() {
    use crate::{arch, hw, memops, serial};

    // PML4[0] = 0: the identity window the stub needed for bring-up
    // dies here. The write itself goes through the direct map, which is
    // unaffected — PML4[273] is a different entry.
    let pml4_pa = hw::read_cr3() & ADDR_MASK;
    memops::write_u64(pml4_pa, 0);
    // Reload CR3 (same value): flushes every non-global TLB entry, so
    // no stale low mapping survives.
    hw::write_cr3(pml4_pa);
    // Prove it through the direct map — if the write or the flush were
    // wrong, this is the loud place to fail (panic prints its location
    // and halts; formatted panic messages need core::fmt, which the
    // boot-path panic handler deliberately does without).
    assert!(memops::read_u64(pml4_pa) == 0);

    arch::percpu::init();

    let cpu = arch::percpu::get().cpu_id;
    let mut b = [0u8; 18];
    serial::write_str("[MM ] higher-half ok: base=");
    serial::write_str(crate::strutil::hex(KERNEL_BASE, &mut b));
    serial::write_str(" identity=pml4[0]:0 percpu:cpu=");
    let mut b2 = [0u8; 20];
    serial::write_str(crate::strutil::dec(cpu as u64, &mut b2));
    serial::write_str("\n");
}