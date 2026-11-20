//! Target side of the image W^X map (F15, ADR-0006): fill the static
//! image page table from the pure `mm::image` section→flags mapping and
//! swap the stub's single RWX 2 MiB leaf for it. CR0.WP goes on here.
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (arch/,
//! scripts/check_unsafe.sh) — the PT is a `static mut` page in .bss
//! (writable, NOBITS — asserted by scripts/check-ist-sections.sh).

#![allow(unsafe_code)]

use crate::hw;
use crate::memops;
use crate::mm::image;
use crate::mm::pte;
use crate::mm::ADDR_MASK;

/// One page table for the image's 2 MiB window (512 × 4 KiB). The
/// page alignment is LOAD-BEARING: a PD entry pointing at a non-4KiB-
/// aligned table is invalid — the walk reads garbage and triple-faults.
#[repr(align(4096))]
struct PageTable([u64; 512]);

static mut IMAGE_PT: PageTable = PageTable([0; 512]);

pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
pub const KERNEL_PHYS_BASE: u64 = 0x0020_0000;

/// Rebuild the image mapping: .text RX, .rodata RO+NX, .data/.bss RW+NX,
/// gaps and the boot-stack guard page ABSENT; then set CR0.WP. Called
/// from mm::init before its CR3 reload (which flushes the old leaf).
pub fn install() {
    // SAFETY: single CPU, bring-up; the PT is written before the PD
    // entry ever points at it, and nothing else touches it afterwards.
    let pt_va = unsafe { core::ptr::addr_of_mut!(IMAGE_PT) } as u64;
    debug_assert!(pt_va % 4096 == 0, "IMAGE_PT must be page-aligned");
    let pt_pa = pt_va - KERNEL_BASE + KERNEL_PHYS_BASE;
    let bounds = image::section_bounds();
    for i in 0..512u64 {
        let va = KERNEL_BASE + i * 4096;
        let entry = match image::image_pte_flags(va, bounds.0, bounds.1, bounds.2, bounds.3, bounds.4) {
            Some(flags) => (KERNEL_PHYS_BASE + i * 4096) | flags,
            None => 0, // absent: gaps + the boot-stack guard
        };
        memops::write_u64_va(pt_va + i * 8, entry);
    }
    // Swap the PD entry: the RWX 2 MiB leaf becomes a pointer to the PT.
    // W is set at the DIRECTORY level too: x86 requires W at every
    // level, so a W-clear PD entry would make the whole image read-only
    // regardless of the PT bits (.bss writes — including every stack
    // push — would fault).
    let pml4_pa = hw::read_cr3() & ADDR_MASK;
    let hh = memops::read_u64(pml4_pa + 511 * 8) & ADDR_MASK;
    let pd = memops::read_u64(hh + 510 * 8) & ADDR_MASK;
    memops::write_u64(pd, pt_pa | pte::PTE_P | pte::PTE_W);
    // CR0.WP (bit 16): read-only pages are read-only for CPL0 too —
    // without it the kernel could write its own .text/.rodata freely.
    hw::write_cr0(hw::read_cr0() | (1 << 16));
}

/// The boot-stack guard page's virtual address (absent PTE; an overflow
/// below the stack faults on it — the terminal boot proof).
#[must_use]
pub fn boot_stack_guard_va() -> u64 {
    image::boot_stack_guard_va()
}
