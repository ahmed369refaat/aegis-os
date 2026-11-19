//! Guarded kernel stacks (ADR-0002): on-demand mappings in the high
//! stack region, one 2 MiB slot per stack — page 0 of every slot is the
//! guard (absent PTE), the stack pages follow. Pure slot arithmetic is
//! host-tested; the mapping itself is target-only (needs CR3, the stub
//! tables, and the frame pool).
//!
//! Region: `0xFFFF_FFFF_4000_0000` (PML4[511] — the kernel-image PDPT —
//! at PDPT index 509, i.e. directly below the kernel image window). The
//! stub pre-builds PDPT[510] for the image; the kernel allocates and
//! installs PDPT[509] for stacks on the first `alloc`.
//!
//! This module is deliberately **unsafe-free**: the allocator state is
//! two atomics (single-CPU today, ready for SMP), and every raw access
//! goes through the allowlisted `memops`/`hw` primitives.

use crate::frames::FrameError;
use crate::mm::PAGE;

/// Stack region base (PML4[511], PDPT[509] — see the module diagram in
/// `mm/mod.rs`).
pub const STACK_REGION_BASE: u64 = 0xFFFF_FFFF_4000_0000;

/// One 2 MiB slot per stack: its own page table, its own guard page.
pub const SLOT_BYTES: u64 = 2 << 20;

/// Upper bound on stack pages (a PT holds 512 entries; one is the guard).
pub const MAX_PAGES: usize = 511;

/// Region size (one PDPT entry = one PD = 1 GiB of slots).
#[cfg(not(test))]
const REGION_BYTES: u64 = 1 << 30;

/// The kernel's pool owner tag (domain ids start at 1; 0 is the kernel).
#[cfg(not(test))]
const OWNER_KERNEL: u32 = 0;

// ─────────────────────────────────────────────────────────────────────────
// Pure slot arithmetic (host-tested).
// ─────────────────────────────────────────────────────────────────────────

/// Virtual base of stack slot `slot` (its guard page).
#[must_use]
pub const fn slot_base(slot: u32) -> u64 {
    STACK_REGION_BASE + slot as u64 * SLOT_BYTES
}

/// The guard-page address of `slot`: always page 0, never mapped.
#[must_use]
pub const fn guard_va(slot: u32) -> u64 {
    slot_base(slot)
}

/// Top-of-stack address for a slot holding `pages` mapped pages (guard
/// at page 0, stack pages 1..=pages, top = one past the last page).
#[must_use]
pub const fn top_va(slot: u32, pages: usize) -> u64 {
    slot_base(slot) + (pages as u64 + 1) * PAGE
}

/// Why a stack allocation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackError {
    /// More pages than one slot (PT minus the guard page) can hold, or
    /// zero.
    TooLarge(usize),
    /// The frame pool ran out.
    Pool(FrameError),
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only mapping.
// ─────────────────────────────────────────────────────────────────────────

/// A live guarded stack: its slot, its pool frames, and its page table.
#[cfg(not(test))]
pub struct KernelStack {
    /// Slot index (slots are never reused; the cursor is monotonic).
    pub slot: u32,
    /// How many mapped stack pages (guard excluded).
    pub pages: usize,
    frames: [u64; MAX_PAGES],
    pt_pa: u64,
}

#[cfg(not(test))]
impl KernelStack {
    /// Top-of-stack virtual address (one past the last mapped page).
    #[must_use]
    pub fn top_va(&self) -> u64 {
        top_va(self.slot, self.pages)
    }

    /// The guard-page virtual address of this stack's slot.
    #[must_use]
    pub fn guard_va(&self) -> u64 {
        guard_va(self.slot)
    }

    /// Physical address of mapped stack page `i` (0-based, guard
    /// excluded) — for cross-view checks through the direct map.
    #[must_use]
    pub fn frame_pa(&self, i: usize) -> Option<u64> {
        if i < self.pages { Some(self.frames[i]) } else { None }
    }
}

#[cfg(not(test))]
mod target {
    use super::{
        slot_base, KernelStack, StackError, OWNER_KERNEL, MAX_PAGES, PAGE, REGION_BYTES,
        SLOT_BYTES,
    };
    use crate::frames::FramePool;
    use crate::mm::{ADDR_MASK, PTE_P_RW};
    use crate::memops;
    use aegis_os::prelude::BuddyAllocator;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    // Single-CPU bring-up state. Atomics (not `static mut`): this module
    // stays unsafe-free, and the ordering is explicit for the day a second
    // CPU arrives (Stage 4).
    static NEXT_SLOT: AtomicU32 = AtomicU32::new(0);
    static REGION_PD_PA: AtomicU64 = AtomicU64::new(0);

    /// Physical address of the stub's kernel PDPT (PML4[511], flags
    /// stripped) — walked from CR3 through the direct map.
    fn pdpt_hh_pa() -> u64 {
        let pml4 = crate::hw::read_cr3() & ADDR_MASK;
        memops::read_u64(pml4 + 511 * 8) & ADDR_MASK
    }

    /// Allocate `pages` guarded stack pages in a fresh 2 MiB slot:
    /// PT[0] absent (the guard), PT[1..=pages] = pool frames RW.
    pub fn alloc(
        pool: &mut FramePool,
        buddy: &mut BuddyAllocator,
        pages: usize,
    ) -> Result<KernelStack, StackError> {
        if pages == 0 || pages > MAX_PAGES {
            return Err(StackError::TooLarge(pages));
        }

        // First allocation: install the region PD into the stub's kernel
        // PDPT (index 509 — the stub built 510 for the image window).
        // No TLB invalidation needed: the region was never mapped, so no
        // stale entry can exist.
        let mut pd_pa = REGION_PD_PA.load(Ordering::SeqCst);
        if pd_pa == 0 {
            let pd = pool.alloc_for(buddy, OWNER_KERNEL).map_err(StackError::Pool)?;
            memops::scrub_frame(pd);
            memops::write_u64(pdpt_hh_pa() + 509 * 8, pd | PTE_P_RW);
            REGION_PD_PA.store(pd, Ordering::SeqCst);
            pd_pa = pd;
        }

        let slot = NEXT_SLOT.fetch_add(1, Ordering::SeqCst);
        if slot as u64 * SLOT_BYTES >= REGION_BYTES {
            return Err(StackError::TooLarge(slot as usize)); // region exhausted
        }

        // The slot's page table: scrub to all-absent, link into the PD,
        // then map the stack pages. PT[0] stays absent — that IS the guard.
        let pt = pool.alloc_for(buddy, OWNER_KERNEL).map_err(StackError::Pool)?;
        memops::scrub_frame(pt);
        memops::write_u64(pd_pa + slot as u64 * 8, pt | PTE_P_RW);

        let mut frames = [0u64; MAX_PAGES];
        for (i, frame_pa) in frames.iter_mut().enumerate().take(pages) {
            let pa = pool.alloc_for(buddy, OWNER_KERNEL).map_err(StackError::Pool)?;
            memops::write_u64(pt + (i as u64 + 1) * 8, pa | PTE_P_RW);
            *frame_pa = pa;
        }

        Ok(KernelStack { slot, pages, frames, pt_pa: pt })
    }

    /// Release a stack: unmap its pages (invalidating each — they WERE
    /// mapped), scrub every frame on the way back to the pool, unhook and
    /// free the slot's page table.
    pub fn free(
        pool: &mut FramePool,
        buddy: &mut BuddyAllocator,
        stack: KernelStack,
    ) -> Result<(), StackError> {
        let pd_pa = REGION_PD_PA.load(Ordering::SeqCst);
        for i in 0..stack.pages {
            let va = slot_base(stack.slot) + (i as u64 + 1) * PAGE;
            memops::write_u64(stack.pt_pa + (i as u64 + 1) * 8, 0);
            crate::hw::invlpg(va);
            pool.free(buddy, stack.frames[i], OWNER_KERNEL)
                .map_err(StackError::Pool)?;
        }
        memops::write_u64(pd_pa + stack.slot as u64 * 8, 0);
        pool.free(buddy, stack.pt_pa, OWNER_KERNEL).map_err(StackError::Pool)?;
        Ok(())
    }
}

#[cfg(not(test))]
pub use target::{alloc, free};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_layout_guard_then_pages() {
        // Slot 0: guard at the region base, first stack page after it.
        assert_eq!(slot_base(0), STACK_REGION_BASE);
        assert_eq!(guard_va(0), STACK_REGION_BASE);
        assert_eq!(top_va(0, 1), STACK_REGION_BASE + 2 * PAGE);
        assert_eq!(top_va(0, 4), STACK_REGION_BASE + 5 * PAGE);
        // Slots are 2 MiB apart, so guards and pages never overlap: a
        // full slot (guard + 511 pages) ends exactly at the next guard.
        assert_eq!(slot_base(1), STACK_REGION_BASE + SLOT_BYTES);
        assert_eq!(slot_base(7) - slot_base(6), SLOT_BYTES);
        assert!(guard_va(1) >= top_va(0, MAX_PAGES));
        assert!(guard_va(1) > top_va(0, MAX_PAGES - 1));
    }

    #[test]
    fn the_region_sits_directly_below_the_kernel_image() {
        // PML4[511]·PDPT[509] (stacks) vs PDPT[510] (image): adjacent
        // PDPT entries, one GiB apart, image above stacks.
        assert_eq!(crate::mm::KERNEL_BASE - STACK_REGION_BASE, 1 << 30);
        // And the whole region is canonical high-half.
        assert!(STACK_REGION_BASE >= 0xFFFF_8000_0000_0000);
    }

    #[test]
    fn max_pages_leaves_room_for_the_guard() {
        assert!(MAX_PAGES < 512);
        assert_eq!(top_va(0, MAX_PAGES), slot_base(0) + 512 * PAGE);
    }
}
