//! The real physical frame pool: the existing policy-core buddy allocator
//! (the `Kernel.frames` field) plus per-frame ownership tracking and
//! scrub-on-free.
//!
//! The pool covers `[base_pa, base_pa + N*4 KiB)` — real, direct-mapped
//! RAM claimed at boot after multiboot validation. Every `free` scrubs
//! (zeroes) the frame before returning it to the buddy allocator; the boot
//! path verifies the scrubbing by read-back. `N` defaults to the library
//! arena size (host tests); the kernel boots with `N = 4096` (16 MiB,
//! PR-1.3: per-domain page tables need the room).
//!
//! All of this is safe code: the volatile memory writes live in `memops`
//! (allowlisted), the buddy allocator comes from the policy core.

use aegis_os::buddy::{BuddyAllocator, BuddyError, FRAME_COUNT};

/// One frame = 4 KiB (matches `aegis_os::memory::PAGE_SIZE`).
pub const FRAME_SIZE: u64 = 4096;
/// Pool base: physical 16 MiB — safely above the kernel image and stack
/// (linker ASSERTs keep the image below 4 MiB).
pub const POOL_BASE: u64 = 16 * 1024 * 1024;
/// Default pool size (host tests): 256 frames = 1 MiB.
pub const POOL_LEN: u64 = FRAME_SIZE * FRAME_COUNT as u64;
/// The boot pool (PR-1.3): 4096 frames = 16 MiB, i.e. physical
/// 16..32 MiB of direct-mapped RAM.
pub const KERNEL_POOL_FRAMES: usize = 4096;
pub const KERNEL_POOL_LEN: u64 = FRAME_SIZE * KERNEL_POOL_FRAMES as u64;

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
pub struct FramePool<const N: usize = FRAME_COUNT> {
    base_pa: u64,
    scrub: fn(u64),
    owner: [Option<u32>; N],
    scrub_calls: u64,
}

impl<const N: usize> FramePool<N> {
    /// A pool over `[base_pa, base_pa + POOL_LEN)`. On the kernel,
    /// `scrub` is `memops::scrub_frame` over direct-mapped RAM; host
    /// tests pass the same function over a real host buffer.
    #[must_use]
    pub fn new(base_pa: u64, scrub: fn(u64)) -> Self {
        FramePool {
            base_pa,
            scrub,
            owner: [None; N],
            scrub_calls: 0,
        }
    }

    /// Physical address of frame index `f`.
    #[must_use]
    pub fn pa_of(&self, f: usize) -> u64 {
        self.base_pa + f as u64 * FRAME_SIZE
    }

    /// Frame index for a physical address (must be in-pool and aligned).
    pub fn frame_of(&self, pa: u64) -> Result<usize, FrameError> {
        if pa < self.base_pa || pa >= self.base_pa + N as u64 * FRAME_SIZE {
            return Err(FrameError::NotInPool(pa));
        }
        if !pa.is_multiple_of(FRAME_SIZE) {
            return Err(FrameError::Unaligned(pa));
        }
        Ok(((pa - self.base_pa) / FRAME_SIZE) as usize)
    }

    /// Allocate one frame and tag it for `owner`.
    pub fn alloc_for(
        &mut self,
        buddy: &mut BuddyAllocator<N>,
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
        buddy: &mut BuddyAllocator<N>,
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
    pub fn free_all_owned(&mut self, buddy: &mut BuddyAllocator<N>, owner: u32) -> usize {
        let mut released = 0;
        // F1: the pool is generic over N (the kernel uses 4096) — the
        // old `0..FRAME_COUNT` (256) bound silently leaked — and never
        // scrubbed — every frame past index 256 on the destroy path.
        for f in 0..N {
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

    /// G (review round 2): property test — frame conservation under
    /// random alloc/free/free_all interleavings (xorshift64*, fixed
    /// seeds). In-use frames and owner tags move together, and freeing
    /// every owner returns the pool to pristine.
    #[test]
    fn property_free_all_owned_and_alloc_conserve_frames() {
        use crate::mm::PAGE; // (page size constant for the buffer math)
        let _ = PAGE;
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn below(&mut self, n: u64) -> u64 {
                self.next() % n.max(1)
            }
        }
        const N: usize = 256;
        for seed in [3u64, 0xFEED_FACE, 777] {
            let mut rng = Rng(seed.max(1));
            let mem = vec![0u64; N * 512 + 1024];
            let base = ((mem.as_ptr() as u64) + 4095) & !4095u64;
            let mut pool = FramePool::<N>::new(base, memops::scrub_frame);
            let mut buddy = BuddyAllocator::<N>::new_over_arena();
            let mut live: [Vec<u64>; 6] = Default::default();
            for step in 0..1000usize {
                let owner = (1 + rng.below(5)) as usize;
                match rng.below(4) {
                    0 | 1 => {
                        if let Ok(pa) = pool.alloc_for(&mut buddy, owner as u32) {
                            live[owner].push(pa);
                        }
                    }
                    2 => {
                        let o = (1 + rng.below(5)) as usize;
                        if let Some(pa) = live[o].pop() {
                            pool.free(&mut buddy, pa, o as u32).unwrap();
                        }
                    }
                    _ => {
                        let o = (1 + rng.below(5)) as usize;
                        pool.free_all_owned(&mut buddy, o as u32);
                        live[o].clear();
                    }
                }
                assert_eq!(
                    buddy.frames_in_use(),
                    pool.owned_count(),
                    "seed {seed} step {step}: in-use frames and owner tags diverged"
                );
                let live_total: usize = live.iter().map(|v| v.len()).sum();
                assert_eq!(
                    buddy.frames_in_use(),
                    live_total,
                    "seed {seed} step {step}: tracking diverged from the pool"
                );
            }
            for o in 1..=5u32 {
                pool.free_all_owned(&mut buddy, o);
                live[o as usize].clear();
            }
            assert!(pool.is_clear());
            assert_eq!(buddy.frames_free(), N);
        }
    }

    /// F1 regression: `free_all_owned` used to loop `0..FRAME_COUNT`
    /// (256) instead of `0..N`, so a FramePool<4096> silently leaked —
    /// and never scrubbed — every frame past index 256 on destroy.
    #[test]
    fn free_all_owned_covers_indexes_beyond_256() {
        use core::sync::atomic::{AtomicU64, Ordering};
        static SCRUBS: AtomicU64 = AtomicU64::new(0);
        fn count_scrub(_pa: u64) {
            SCRUBS.fetch_add(1, Ordering::SeqCst);
        }
        let mut buddy = BuddyAllocator::<4096>::new_over_arena();
        let mut pool = FramePool::<4096>::new(POOL_BASE, count_scrub);
        // Allocate enough that the last frame's index is past 256.
        let mut last_pa = 0;
        for _ in 0..260 {
            last_pa = pool.alloc_for(&mut buddy, 77).unwrap();
        }
        let idx = ((last_pa - POOL_BASE) / FRAME_SIZE) as usize;
        assert!(
            idx >= 256,
            "test must reach past the old bound (last idx {idx})"
        );
        let before = SCRUBS.load(Ordering::SeqCst);
        let released = pool.free_all_owned(&mut buddy, 77);
        assert_eq!(
            released, 260,
            "every owned frame released, not just the first 256"
        );
        assert!(pool.is_clear(), "no owner tags survive");
        assert_eq!(buddy.frames_free(), 4096, "every frame back to the buddy");
        assert_eq!(
            SCRUBS.load(Ordering::SeqCst) - before,
            260,
            "every freed frame scrubbed exactly once"
        );
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
