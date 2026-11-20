//! Buddy page-frame allocator.
//!
//! Linux-like physical memory management in miniature: blocks are power-of-two
//! multiples of one frame, allocation splits larger blocks, freeing coalesces
//! buddies back up. All state is in fixed arrays — no allocation, no unsafe.
//!
//! Buddy invariant: the buddy of a block starting at frame `f` of order `o`
//! is `f ^ (1 << o)`. Two free buddies of order `o` merge into one block of
//! order `o + 1` starting at the lower frame.

use crate::memory::PAGE_SIZE;

/// Default arena size (the library's own tests and every existing call
/// site). The bootable kernel overrides with 4096 (16 MiB pool).
pub const FRAME_COUNT: usize = 256;
pub const MAX_ORDER: u32 = 5;
/// Largest block = 32 frames = 128 KiB at 4 KiB pages.
pub const MAX_BLOCK_FRAMES: usize = 1 << MAX_ORDER;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuddyError {
    /// Requested order exceeds `MAX_ORDER`.
    OrderTooLarge(u32),
    /// No free block large enough.
    OutOfMemory {
        requested_order: u32,
        largest_free_order: u32,
    },
    /// Frame index outside the arena (`0..N`).
    InvalidFrame(usize),
    /// Frame was never allocated (or already freed and coalesced away).
    NotAllocated(usize),
}

#[derive(Clone, Copy)]
struct FreeList<const N: usize> {
    frames: [u16; N],
    len: usize,
}

impl<const N: usize> FreeList<N> {
    const fn new() -> Self {
        FreeList {
            frames: [0; N],
            len: 0,
        }
    }
    fn push(&mut self, f: usize) {
        self.frames[self.len] = f as u16;
        self.len += 1;
    }
    fn pop(&mut self) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        // FIFO: lowest address first (deterministic, test-friendly).
        let f = self.frames[0] as usize;
        self.frames.copy_within(1..self.len, 0);
        self.len -= 1;
        Some(f)
    }
    fn remove(&mut self, f: usize) -> bool {
        if let Some(pos) = self.frames[..self.len]
            .iter()
            .position(|&x| x as usize == f)
        {
            self.frames[pos] = self.frames[self.len - 1];
            self.len -= 1;
            true
        } else {
            false
        }
    }
}

/// Buddy allocator over `N` frames (`N` must be a multiple of
/// `MAX_BLOCK_FRAMES`). Defaults to the library arena size; the kernel
/// uses `BuddyAllocator<4096>` for its 16 MiB pool.
pub struct BuddyAllocator<const N: usize = FRAME_COUNT> {
    free_lists: [FreeList<N>; MAX_ORDER as usize + 1],
    /// True for the first frame of every allocated block.
    allocated_start: [bool; N],
    /// Order of the allocated block starting at each start frame.
    order_of: [u8; N],
    frames_in_use: usize,
}

/// The default 256-frame arena (what `BuddyAllocator` without parameters
/// means, and what the library's own tests exercise).
pub type Buddy256 = BuddyAllocator<FRAME_COUNT>;

impl Buddy256 {
    /// Fresh allocator over the default 256-frame arena. Type-parameter
    /// defaults do not guide inference, so this pins it for the many
    /// existing `BuddyAllocator::new()` call sites and tests.
    pub fn new() -> Self {
        BuddyAllocator::new_over_arena()
    }
}

impl<const N: usize> BuddyAllocator<N> {
    /// A fresh allocator owning `N` frames as consecutive max-order
    /// blocks (e.g. 256 frames = 8 blocks of 32).
    pub fn new_over_arena() -> Self {
        assert!(
            N.is_multiple_of(MAX_BLOCK_FRAMES),
            "arena must be a multiple of the max block size"
        );
        let mut b = BuddyAllocator {
            free_lists: [FreeList::new(); MAX_ORDER as usize + 1],
            allocated_start: [false; N],
            order_of: [0; N],
            frames_in_use: 0,
        };
        // The arena is N frames split into consecutive
        // max-order blocks (e.g. 256 frames = 8 blocks of 32).
        let blocks = N / MAX_BLOCK_FRAMES;
        for i in 0..blocks {
            b.free_lists[MAX_ORDER as usize].push(i * MAX_BLOCK_FRAMES);
        }
        b
    }

    /// Allocate a block of `1 << order` frames; returns its start frame.
    pub fn alloc(&mut self, order: u32) -> Result<usize, BuddyError> {
        if order > MAX_ORDER {
            return Err(BuddyError::OrderTooLarge(order));
        }
        // Find the smallest free order >= requested.
        let mut found = None;
        for o in order..=MAX_ORDER {
            if self.free_lists[o as usize].len > 0 {
                found = Some(o);
                break;
            }
        }
        let Some(src_order) = found else {
            let largest = self.largest_free_order();
            return Err(BuddyError::OutOfMemory {
                requested_order: order,
                largest_free_order: largest,
            });
        };

        let start = self.free_lists[src_order as usize].pop().unwrap();
        // Split down to the requested order, freeing the upper buddy halves.
        let mut o = src_order;
        while o > order {
            o -= 1;
            let buddy = start + (1 << o);
            self.free_lists[o as usize].push(buddy);
        }
        self.allocated_start[start] = true;
        self.order_of[start] = order as u8;
        self.frames_in_use += 1usize << order;
        // Sanitize (defensive): start must be aligned to its block size.
        debug_assert_eq!(start % (1usize << order), 0);
        if !start.is_multiple_of(1usize << order) {
            return Err(BuddyError::InvalidFrame(start));
        }
        Ok(start)
    }

    /// Free a block previously returned by `alloc`. Coalesces buddies.
    pub fn free(&mut self, frame: usize) -> Result<(), BuddyError> {
        if frame >= N {
            return Err(BuddyError::InvalidFrame(frame));
        }
        if !self.allocated_start[frame] {
            return Err(BuddyError::NotAllocated(frame));
        }
        let order = self.order_of[frame] as u32;
        self.allocated_start[frame] = false;
        self.frames_in_use -= 1usize << order;

        // Coalesce upward while the buddy is a free block of the same order.
        let mut cur = frame;
        let mut o = order;
        while o < MAX_ORDER {
            let buddy = cur ^ (1usize << o);
            if self.free_lists[o as usize].remove(buddy) {
                cur = cur.min(buddy);
                o += 1;
            } else {
                break;
            }
        }
        self.free_lists[o as usize].push(cur);
        Ok(())
    }

    #[must_use]
    pub fn frames_in_use(&self) -> usize {
        self.frames_in_use
    }

    #[must_use]
    pub fn frames_free(&self) -> usize {
        N - self.frames_in_use
    }

    /// Order of the largest currently free block.
    #[must_use]
    pub fn largest_free_order(&self) -> u32 {
        (0..=MAX_ORDER)
            .rev()
            .find(|o| self.free_lists[*o as usize].len > 0)
            .unwrap_or(u32::MAX) // empty allocator
    }

    /// Frames contained in the largest free block (0 when empty).
    #[must_use]
    pub fn largest_free_block_frames(&self) -> usize {
        match self.largest_free_order() {
            o if o == u32::MAX => 0,
            o => 1usize << o,
        }
    }

    /// Total managed bytes.
    #[must_use]
    pub fn capacity_bytes(&self) -> usize {
        N * PAGE_SIZE
    }
}

impl<const N: usize> Default for BuddyAllocator<N> {
    fn default() -> Self {
        Self::new_over_arena()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_allocator_is_one_max_block() {
        let b = BuddyAllocator::new();
        assert_eq!(b.frames_free(), FRAME_COUNT);
        assert_eq!(b.frames_in_use(), 0);
        assert_eq!(b.largest_free_order(), MAX_ORDER);
        assert_eq!(b.largest_free_block_frames(), MAX_BLOCK_FRAMES);
    }

    #[test]
    fn alloc_single_page_splits_down() {
        let mut b = BuddyAllocator::new();
        let f = b.alloc(0).unwrap();
        assert_eq!(f, 0);
        assert_eq!(b.frames_in_use(), 1);
        assert_eq!(b.frames_free(), FRAME_COUNT - 1);
        // Other untouched max blocks remain; the split one lost a page.
        assert_eq!(b.largest_free_order(), MAX_ORDER);
    }

    #[test]
    fn alloc_full_arena_then_oom() {
        let mut b = BuddyAllocator::new();
        // The arena is 8 consecutive max-order blocks: take them all.
        let mut blocks = Vec::new();
        for i in 0..(FRAME_COUNT / MAX_BLOCK_FRAMES) {
            let f = b.alloc(MAX_ORDER).unwrap();
            assert_eq!(f, i * MAX_BLOCK_FRAMES, "blocks come out in address order");
            blocks.push(f);
        }
        assert_eq!(b.frames_in_use(), FRAME_COUNT);
        assert_eq!(b.frames_free(), 0);
        assert_eq!(
            b.alloc(0).unwrap_err(),
            BuddyError::OutOfMemory {
                requested_order: 0,
                largest_free_order: u32::MAX
            }
        );
        // Free everything in reverse: the whole arena comes back.
        for f in blocks.iter().rev() {
            b.free(*f).unwrap();
        }
        assert_eq!(b.frames_free(), FRAME_COUNT);
        assert_eq!(b.largest_free_order(), MAX_ORDER);
    }

    #[test]
    fn order_too_large_rejected() {
        let mut b = BuddyAllocator::new();
        assert_eq!(b.alloc(MAX_ORDER + 1), Err(BuddyError::OrderTooLarge(6)));
        assert_eq!(b.alloc(10), Err(BuddyError::OrderTooLarge(10)));
    }

    #[test]
    fn double_free_rejected() {
        let mut b = BuddyAllocator::new();
        let f = b.alloc(2).unwrap();
        b.free(f).unwrap();
        assert_eq!(b.free(f), Err(BuddyError::NotAllocated(f)));
    }

    #[test]
    fn free_of_never_allocated_frame_rejected() {
        let mut b = BuddyAllocator::new();
        // Frame 5 is inside the single free max block, not an allocated start.
        assert_eq!(b.free(5), Err(BuddyError::NotAllocated(5)));
        let f = b.alloc(0).unwrap();
        // An interior frame of an allocated block is not a start frame.
        assert_eq!(b.free(f + 1), Err(BuddyError::NotAllocated(f + 1)));
    }

    #[test]
    fn invalid_frame_index_rejected() {
        let mut b = BuddyAllocator::new();
        assert_eq!(
            b.free(FRAME_COUNT),
            Err(BuddyError::InvalidFrame(FRAME_COUNT))
        );
        assert_eq!(
            b.free(usize::MAX),
            Err(BuddyError::InvalidFrame(usize::MAX))
        );
    }

    #[test]
    fn buddies_coalesce_back_to_max_block() {
        let mut b = BuddyAllocator::new();
        // Two order-0 buddies inside the same order-1 block.
        let a = b.alloc(0).unwrap();
        let c = b.alloc(0).unwrap();
        assert_eq!(
            a ^ 1,
            c,
            "second single page must be the buddy of the first"
        );
        b.free(a).unwrap();
        // Freeing one buddy leaves the other allocated: no merge yet
        // (one page free; untouched max blocks still span the rest).
        assert_eq!(b.frames_free(), FRAME_COUNT - 1);
        assert_eq!(b.largest_free_order(), MAX_ORDER);
        b.free(c).unwrap();
        // Both buddies free: coalescing must restore the whole arena.
        assert_eq!(b.frames_free(), FRAME_COUNT);
        assert_eq!(b.largest_free_order(), MAX_ORDER);
    }

    #[test]
    fn multi_level_coalescing() {
        let mut b = BuddyAllocator::new();
        // Take 4 pages as one order-2 block, free it in pages: 0,1,2,3
        let block = b.alloc(2).unwrap();
        // Simulate page-granular free by re-allocating pages? Instead:
        // allocate order-1 buddies and free in worst order (higher first).
        let x = b.alloc(1).unwrap(); // first half of remaining
        let y = b.alloc(1).unwrap(); // buddy of x
        let _block2 = b.alloc(2).unwrap();
        b.free(y).unwrap(); // higher buddy first
        b.free(x).unwrap(); // then lower — must coalesce to order 1+
        assert!(b.largest_free_order() >= 1);
        // Free the rest; everything must merge back to one max block.
        b.free(block).unwrap();
        b.free(_block2).unwrap();
        assert_eq!(b.largest_free_order(), MAX_ORDER);
        assert_eq!(b.frames_in_use(), 0);
    }

    #[test]
    fn fragmentation_prevents_large_alloc_but_small_ok() {
        let mut b = BuddyAllocator::new();
        // Consume the entire arena as individual pages.
        for _ in 0..FRAME_COUNT {
            b.alloc(0).unwrap();
        }
        assert_eq!(b.frames_in_use(), FRAME_COUNT);
        // Punch two non-buddy holes (0's buddy is 1, 2's buddy is 3).
        b.free(0).unwrap();
        b.free(2).unwrap();
        // No order-1 (or larger) block can be formed: 0-1 and 2-3 are
        // both half-allocated pairs, so nothing coalesces.
        assert!(matches!(b.alloc(1), Err(BuddyError::OutOfMemory { .. })));
        // But single pages still fit into the holes.
        assert_eq!(b.alloc(0).unwrap(), 0);
        assert_eq!(b.alloc(0).unwrap(), 2);
        assert!(matches!(b.alloc(0), Err(BuddyError::OutOfMemory { .. })));
    }

    #[test]
    fn accounting_never_drifts() {
        let mut b = BuddyAllocator::new();
        let mut allocated = Vec::new();
        // Greedy mixed-size allocation pattern.
        for o in [0u32, 2, 1, 0, 3, 0] {
            if let Ok(f) = b.alloc(o) {
                allocated.push((f, o));
            }
        }
        let used = allocated.iter().map(|(_, o)| 1usize << o).sum::<usize>();
        assert_eq!(b.frames_in_use(), used);
        // Free in a scrambled order.
        for (f, _) in allocated.iter().rev() {
            b.free(*f).unwrap();
        }
        assert_eq!(b.frames_in_use(), 0);
        assert_eq!(b.frames_free(), FRAME_COUNT);
        assert_eq!(b.largest_free_order(), MAX_ORDER);
    }

    #[test]
    fn exhaustion_error_reports_largest_free() {
        let mut b = BuddyAllocator::new();
        // Take 7 of the 8 max blocks; split the last one with a page.
        for _ in 0..(FRAME_COUNT / MAX_BLOCK_FRAMES - 1) {
            b.alloc(MAX_ORDER).unwrap();
        }
        let _small = b.alloc(0).unwrap();
        // Largest free block is now MAX_ORDER-1; asking for MAX must fail
        // and report what is actually available.
        let e = b.alloc(MAX_ORDER).unwrap_err();
        assert_eq!(
            e,
            BuddyError::OutOfMemory {
                requested_order: MAX_ORDER,
                largest_free_order: MAX_ORDER - 1,
            }
        );
    }

    #[test]
    fn capacity_bytes_matches_frames() {
        let b = BuddyAllocator::new();
        assert_eq!(b.capacity_bytes(), FRAME_COUNT * PAGE_SIZE);
    }

    #[test]
    fn kernel_sized_arena_works_the_same() {
        // The bootable kernel's pool: 4096 frames = 16 MiB (PR-1.3).
        let mut b: BuddyAllocator<4096> = BuddyAllocator::new_over_arena();
        assert_eq!(b.frames_free(), 4096);
        assert_eq!(b.capacity_bytes(), 16 * 1024 * 1024);
        assert_eq!(b.largest_free_order(), MAX_ORDER);
        // Same FIFO max-block behavior, at the bigger scale.
        let first = b.alloc(MAX_ORDER).unwrap();
        assert_eq!(first, 0);
        let second = b.alloc(MAX_ORDER).unwrap();
        assert_eq!(second, MAX_BLOCK_FRAMES);
        assert_eq!(b.frames_in_use(), 2 * MAX_BLOCK_FRAMES);
        b.free(first).unwrap();
        b.free(second).unwrap();
        assert_eq!(b.frames_free(), 4096);
    }
}
