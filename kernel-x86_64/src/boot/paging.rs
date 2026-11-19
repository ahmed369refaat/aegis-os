//! Identity page tables for boot.
//!
//! We map the first 1 GiB of physical memory into the same virtual
//! addresses with 512 × 2 MiB huge pages. That is all M1 needs: the kernel
//! image (1 MiB), the multiboot info (low memory) and the frame pool
//! (16..17 MiB) are all directly addressable, and "physical address ==
//! dereferenceable pointer" holds everywhere the kernel looks.
//!
//! Per-domain page tables (real isolation of user memory) are M2 work and
//! deliberately absent here.

use core::arch::asm;

/// A page-aligned page table (4 KiB, 512 entries).
#[repr(align(4096))]
pub struct PageTable(pub [u64; 512]);

// Statics referenced by name from the 32-bit entry stub (boot/asm.rs).
// They live in .bss (zero-initialized by the multiboot loader via
// p_memsz) and are then fully rewritten by `setup_page_tables` — nothing
// depends on any prior content.
#[unsafe(no_mangle)]
pub static mut BOOT_PML4: PageTable = PageTable([0; 512]);
#[unsafe(no_mangle)]
pub static mut BOOT_PDPT: PageTable = PageTable([0; 512]);
#[unsafe(no_mangle)]
pub static mut BOOT_PD: PageTable = PageTable([0; 512]);

const P_PRESENT: u64 = 1;
const P_WRITE: u64 = 1 << 1;
const P_HUGE: u64 = 1 << 7;

/// Fill the static boot tables: identity-map the first 1 GiB.
///
/// Called from the 32-bit entry stub, before paging is enabled. Link
/// addresses equal physical addresses (kernel linked at 1 MiB), so the
/// table entries hold directly usable addresses.
///
/// SAFETY: single-threaded boot context; the three statics are page-aligned
/// by `#[repr(align)]` and are written exactly once, before any of them is
/// loaded into CR3.
#[unsafe(no_mangle)]
pub extern "C" fn setup_page_tables() {
    // SAFETY: see the doc comment above; no aliasing is possible because
    // nothing else runs, and the statics are not read until CR3 loading
    // happens after this call returns. Raw references avoid interim
    // shared/mutable references to statics (static_mut_refs).
    unsafe {
        BOOT_PML4.0[0] = (&raw const BOOT_PDPT).addr() as u64 | P_PRESENT | P_WRITE;
        BOOT_PDPT.0[0] = (&raw const BOOT_PD).addr() as u64 | P_PRESENT | P_WRITE;
        let pd = &raw mut BOOT_PD;
        for (i, entry) in (*pd).0.iter_mut().enumerate() {
            *entry = ((i as u64) << 21) | P_PRESENT | P_WRITE | P_HUGE;
        }
    }
}

/// Invalidate the TLB entry for a page (used after scrubbing, where
/// hypervisor-induced caching could otherwise hide a stale line).
///
/// SAFETY: `invlpg` is a privileged instruction requiring CPL0; the kernel
/// always runs at CPL0 on the boot CPU.
#[allow(dead_code)]
pub fn invlpg(vaddr: u64) {
    // SAFETY: privileged ring-0 instruction; the address may be any
    // canonical value (invalid entries are a no-op).
    unsafe { asm!("invlpg [{0}]", in(reg) vaddr, options(nostack, preserves_flags)) }
}
