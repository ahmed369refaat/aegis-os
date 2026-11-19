//! The real physical frame pool: the existing policy-core buddy allocator
//! (the `Kernel.frames` field) plus per-frame ownership tracking and
//! scrub-on-free.
//!
//! The pool covers `[base_pa, base_pa + 256*4 KiB)` — real, identity-mapped
//! RAM claimed at boot after multiboot validation. Every `free` scrubs
//! (zeroes) the frame before returning it to the buddy allocator; the boot
//! path verifies the scrubbing by read-back.
//!
//! All of this is safe code: the volatile memory writes live in `memops`
//! (allowlisted), the buddy allocator comes from the policy core.

use aegis_os::buddy::{BuddyAllocator, BuddyError, FRAME_COUNT};

/// One frame = 4 KiB (matches `aegis_os::memory::PAGE_SIZE`).
pub const FRAME_SIZE: u64 = 4096;
/// Pool base: physical 16 MiB — safely above the kernel image and stack
/// (linker ASSERTs keep the image below 8 MiB).
pub const POOL_BASE: u64 = 16 * 1024 * 1024;
/// Total pool size: 256 frames = 1 MiB.
pub const POOL_LEN: u64 = FRAME_SIZE * FRAME_COUNT as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The buddy allocator refused (OOM / invalid free).
    Buddy(BuddyError),
    /// The frame is not owned by the caller — cross-domain free rejected.
    NotOwnedBy(u32),
    /// Address outside the pool.
    NotInPool(u64),
    /// Address inside the pool but not frame-aligned.
    Unaligned(u64),
}

/// Per-frame ownership + the scrub primitive. The buddy allocator itself
/// is passed in explicitly (it is the `Kernel.frames` field, so the pool
/// and the syscall layer share one instance — "managed by the existing
/// buddy allocator" is literal).
pub struct FramePool {
    base_pa: u64,
    scrub: fn(u64),
    owner: [Option<u32>; FRAME_COUNT],
    scrub_calls: u64,
}

impl FramePool {
    /// A pool over `[base_pa, base_pa + POOL_LEN)`. On the kernel,
    /// `scrub` is `memops::scrub_frame` over identity-mapped RAM; host
    /// tests pass the same function over a real host buffer.
    #[must_use]
    pub fn new(base_pa: u64, scrub: fn(u64)) -> Self {
        FramePool { base_pa, scrub, owner: [None; FRAME_COUNT], scrub_calls: 0 }
    }

    /// Physical address of frame index `f`.
    #[must_use]
    pub fn pa_of(&self, f: usize) -> u64 {
        self.base_pa + f as u64 * FRAME_SIZE
    }

    /// Frame index for a physical address (must be in-pool and aligned).
    pub fn frame_of(&self, pa: u64) -> Result<usize, FrameError> {
        if pa < self.base_pa || pa >= self.base_pa + POOL_LEN {
            return Err(FrameError::NotInPool(pa));
        }
        if pa % FRAME_SIZE != 0 {
            return Err(FrameError::Unaligned(pa));
        }
        Ok(((pa - self.base_pa) / FRAME_SIZE) as usize)
    }

    /// Allocate one frame and tag it for `owner`.
    pub fn alloc_for(
        &mut self,
        buddy: &mut BuddyAllocator,
        owner: u32,
    ) -> Result<u64, FrameError> {
        let f = buddy.alloc(0).map_err(FrameError::Buddy)?;
        self.owner[f] = Some(owner);
        Ok(self.pa_of(f))
    }

    /// Free one frame owned by `owner`: scrub first, then return to the
    /// buddy. Freeing a frame you do not own is an error, never a silent
    /// cross-domain release.
    pub fn free(
        &mut self,
        buddy: &mut BuddyAllocator,
        pa: u64,
        owner: u32,
    ) -> Result<(), FrameError> {
        let f = self.frame_of(pa)?;
        if self.owner[f] != Some(owner) {
            return Err(FrameError::NotOwnedBy(owner));
        }
        (self.scrub)(pa);
        self.scrub_calls += 1;
        self.owner[f] = None;
        buddy.free(f).map_err(FrameError::Buddy)
    }

    /// Free (and scrub) every frame owned by `owner` — the domain destroy
    /// path. Returns how many frames were released.
    pub fn free_all_owned(&mut self, buddy: &mut BuddyAllocator, owner: u32) -> usize {
        let mut released = 0;
        for f in 0..FRAME_COUNT {
            if self.owner[f] == Some(owner) {
                let pa = self.pa_of(f);
                (self.scrub)(pa);
                self.scrub_calls += 1;
                self.owner[f] = None;
                let _ = buddy.free(f);
                released += 1;
            }
        }
        released
    }

    #[must_use]
    pub fn owned_by(&self, owner: u32) -> usize {
        self.owner.iter().filter(|o| **o == Some(owner)).count()
    }

    /// True when no frame has an owner (all returned).
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.owner.iter().all(|o| o.is_none())
    }

    /// Count of frames with any owner.
    #[must_use]
    pub fn owned_count(&self) -> usize {
        self.owner.iter().flatten().count()
    }

    #[must_use]
    pub fn scrub_calls(&self) -> u64 {
        self.scrub_calls
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memops;

    /// A real 1 MiB host buffer standing in for the pool's physical memory.
    struct FakePhys {
        _mem: Vec<u64>,
        base: u64,
    }
    impl FakePhys {
        fn new() -> Self {
            // Extra 4 KiB so the base can be aligned up to a page
            // boundary (the pool's frame math requires it).
            let mem = vec![0u64; (POOL_LEN / 8 + 512) as usize];
            let base = (mem.as_ptr() as u64 + 4095) & !4095u64;
            FakePhys { _mem: mem, base }
        }
    }

    #[test]
    fn alloc_tags_owner_and_free_scrubs() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut buddy = BuddyAllocator::new();

        let pa = pool.alloc_for(&mut buddy, 7).unwrap();
        assert_eq!(pool.owned_by(7), 1);
        assert_eq!(buddy.frames_in_use(), 1);
        // Dirty the frame, then free: it must come back zeroed.
        memops::write_u64(pa, 0xAAAA_BBBB_CCCC_DDDD);
        memops::write_u64(pa + 4088, 0xAAAA_BBBB_CCCC_DDDD);
        pool.free(&mut buddy, pa, 7).unwrap();
        assert_eq!(pool.scrub_calls(), 1);
        assert!(memops::frame_is_zero(pa), "freed frame must be scrubbed");
        assert_eq!(buddy.frames_in_use(), 0);
        assert!(pool.is_clear());
    }

    #[test]
    fn free_by_non_owner_is_rejected() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut buddy = BuddyAllocator::new();
        let pa = pool.alloc_for(&mut buddy, 1).unwrap();
        assert_eq!(pool.free(&mut buddy, pa, 2), Err(FrameError::NotOwnedBy(2)));
        // Frame still owned and allocated; nothing was released.
        assert_eq!(pool.owned_by(1), 1);
        assert_eq!(buddy.frames_in_use(), 1);
    }

    #[test]
    fn out_of_pool_and_unaligned_addresses_rejected() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut buddy = BuddyAllocator::new();
        assert!(matches!(
            pool.free(&mut buddy, phys.base - FRAME_SIZE, 1),
            Err(FrameError::NotInPool(_))
        ));
        assert!(matches!(
            pool.free(&mut buddy, phys.base + POOL_LEN, 1),
            Err(FrameError::NotInPool(_))
        ));
        assert!(matches!(
            pool.free(&mut buddy, phys.base + 123, 1),
            Err(FrameError::Unaligned(_))
        ));
    }

    #[test]
    fn free_all_owned_releases_exactly_that_domain() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut buddy = BuddyAllocator::new();
        for _ in 0..4 {
            pool.alloc_for(&mut buddy, 10).unwrap();
        }
        for _ in 0..2 {
            pool.alloc_for(&mut buddy, 11).unwrap();
        }
        assert_eq!(buddy.frames_in_use(), 6);
        let released = pool.free_all_owned(&mut buddy, 10);
        assert_eq!(released, 4);
        assert_eq!(buddy.frames_in_use(), 2);
        assert_eq!(pool.owned_by(10), 0);
        assert_eq!(pool.owned_by(11), 2);
    }

    #[test]
    fn thousand_alloc_free_cycles_leave_zero_leaks() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut buddy = BuddyAllocator::new();
        for i in 0..1000u32 {
            let owner = 100 + i % 5;
            let a = pool.alloc_for(&mut buddy, owner).unwrap();
            let b = pool.alloc_for(&mut buddy, owner).unwrap();
            memops::write_u64(a, i as u64);
            memops::write_u64(b, i as u64);
            pool.free(&mut buddy, a, owner).unwrap();
            pool.free(&mut buddy, b, owner).unwrap();
            if i % 100 == 0 {
                assert_eq!(buddy.frames_in_use(), 0, "cycle {}", i);
            }
        }
        assert_eq!(buddy.frames_in_use(), 0);
        assert_eq!(buddy.frames_free(), FRAME_COUNT);
        assert!(pool.is_clear());
        assert_eq!(pool.scrub_calls(), 2000, "every free scrubs");
    }

    #[test]
    fn exhaustion_is_reported_not_silent() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut buddy = BuddyAllocator::new();
        for _ in 0..FRAME_COUNT {
            pool.alloc_for(&mut buddy, 1).unwrap();
        }
        assert!(matches!(
            pool.alloc_for(&mut buddy, 1),
            Err(FrameError::Buddy(BuddyError::OutOfMemory { .. }))
        ));
    }

    #[test]
    fn counting_scrub_stub_confirms_free_path_calls_it() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNT: AtomicU64 = AtomicU64::new(0);
        // A non-memops scrub proves the function pointer is honored.
        fn counting(_pa: u64) {
            COUNT.fetch_add(1, Ordering::SeqCst);
        }
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, counting);
        let mut buddy = BuddyAllocator::new();
        let pa = pool.alloc_for(&mut buddy, 3).unwrap();
        pool.free(&mut buddy, pa, 3).unwrap();
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }
}
