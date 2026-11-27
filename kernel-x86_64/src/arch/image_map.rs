//! Target side of the image W^X map (F15, ADR-0006): fill the static
//! image page table from the pure `mm::image` section→flags mapping and
//! swap the stub's two RWX 2 MiB leaves for them. CR0.WP goes on here.
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

/// The image's page tables: TWO 2 MiB windows (512 × 4 KiB each). K22
/// grew the image past one leaf (/bin/pkg's 119 KiB image rides in
/// .rodata), so the stub maps PA 2..6 MiB and BOTH leaves below get
/// their own table. The page alignment is LOAD-BEARING: a PD entry
/// pointing at a non-4KiB-aligned table is invalid — the walk reads
/// garbage and triple-faults.
#[repr(align(4096))]
struct PageTable(
    /// Addressed only through `addr_of_mut!` (the alignment is the
    /// point; the field itself is never read by name).
    #[allow(dead_code)]
    [u64; 512],
);

static mut IMAGE_PTS: [PageTable; 2] = [PageTable([0; 512]), PageTable([0; 512])];

pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;
pub const KERNEL_PHYS_BASE: u64 = 0x0020_0000;

/// Rebuild the image mapping: .text RX, .rodata RO+NX, .data/.bss RW+NX,
/// gaps and the boot-stack guard page ABSENT; then set CR0.WP. Called
/// from mm::init before its CR3 reload (which flushes the old leaves).
pub fn install() {
    // addr_of_mut! on a static mut is safe (no reference is formed);
    // the PTs are written before the PD entries ever point at them.
    let pts_va = core::ptr::addr_of_mut!(IMAGE_PTS) as u64;
    debug_assert!(
        pts_va.is_multiple_of(4096),
        "IMAGE_PTS must be page-aligned"
    );
    let pts_pa = pts_va - KERNEL_BASE + KERNEL_PHYS_BASE;
    let bounds = image::section_bounds();
    // 4 MiB = 1024 pages: i < 512 lands in PT0 (PD_hh[0], PA 2 MiB),
    // 512..1024 in PT1 (PD_hh[1], PA 4 MiB — the K22 second leaf).
    // Pages the sections do not cover stay ABSENT: the second window is
    // mostly absent whenever the image fits one leaf, which is exactly
    // the honest mapping — nothing legitimate lives there.
    for i in 0..1024u64 {
        let va = KERNEL_BASE + i * 4096;
        let entry = match image::image_pte_flags(va, bounds) {
            Some(flags) => (KERNEL_PHYS_BASE + i * 4096) | flags,
            None => 0, // absent: gaps + the boot-stack guard
        };
        memops::write_u64_va(pts_va + i * 8, entry);
    }
    // Swap BOTH PD entries: each RWX 2 MiB leaf becomes a pointer to
    // its PT. W is set at the DIRECTORY level too: x86 requires W at
    // every level, so a W-clear PD entry would make the whole image
    // read-only regardless of the PT bits (.bss writes — including
    // every stack push — would fault).
    let pml4_pa = hw::read_cr3() & ADDR_MASK;
    let hh = memops::read_u64(pml4_pa + 511 * 8) & ADDR_MASK;
    let pd = memops::read_u64(hh + 510 * 8) & ADDR_MASK;
    memops::write_u64(pd, pts_pa | pte::PTE_P | pte::PTE_W);
    memops::write_u64(pd + 8, (pts_pa + 4096) | pte::PTE_P | pte::PTE_W);
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
