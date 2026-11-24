//! ADR-0024 D2: the share-aware frame paths — the FrameSource the
//! fork world uses (frees consult the refcounts before the pool) and
//! the teardown walker that replaces blind `free_all_owned` for
//! domains that may hold shared frames.
//!
//! Unsafe-free by design: the share table itself lives behind
//! `context::shares_mut()` (the allowlisted sched/context slot), and
//! every operation here is plain policy over it.

use crate::frames::FramePool;
use core::sync::atomic::{AtomicU64, Ordering};

/// ADR-0024 D2: how many copy-on-write faults have been served (the
/// fork proof's marker reads it).
static COW_COPIES: AtomicU64 = AtomicU64::new(0);

/// The count of served CoW copies.
#[must_use]
pub fn cow_copies() -> u64 {
    COW_COPIES.load(Ordering::SeqCst)
}

/// Record one served CoW copy (the fault path).
pub fn note_cow_copy() {
    COW_COPIES.fetch_add(1, Ordering::SeqCst);
}
use crate::mm::page_table::{FrameSource, MapError, PoolSource};
use crate::sched::context;
use aegis_os::buddy::BuddyAllocator;

/// A `PoolSource` whose FREES are share-aware: a frame the table
/// holds is released (freed only on the last reference, under the
/// ORIGINAL owner's tag); a private frame frees outright under
/// `domain`. Allocations are the inner pool's (new frames are private
/// the moment they exist).
pub struct SharedSource<'a, const N: usize> {
    pub inner: PoolSource<'a, N>,
    pub domain: u32,
}

impl<'a, const N: usize> SharedSource<'a, N> {
    pub fn new(pool: &'a mut FramePool<N>, buddy: &'a mut BuddyAllocator<N>, domain: u32) -> Self {
        SharedSource {
            inner: PoolSource::new(pool, buddy, domain),
            domain,
        }
    }
}

impl<const N: usize> FrameSource for SharedSource<'_, N> {
    fn alloc_frame(&mut self) -> Result<u64, MapError> {
        self.inner.alloc_frame()
    }

    fn free_frame(&mut self, pa: u64) -> Result<(), MapError> {
        let shares = context::shares_mut();
        if let Some(owner) = shares.owner_of(pa) {
            // Shared: release one reference; the LAST holder frees
            // under the entry's original owner (the pool validates
            // the tag — a fork's child must not free an inherited
            // frame under its own).
            let last = matches!(shares.release(pa), Ok(true));
            if last {
                return self
                    .inner
                    .pool
                    .free(self.inner.buddy, pa, owner)
                    .map_err(MapError::Pool);
            }
            return Ok(());
        }
        self.inner
            .pool
            .free(self.inner.buddy, pa, self.domain)
            .map_err(MapError::Pool)
    }
}

/// ADR-0024 D2: the shares-aware teardown — every frame the pool
/// still tags `owner` is either private (free outright) or shared
/// (release; free on the last reference under the ORIGINAL owner).
/// Returns the frames actually returned to the buddy.
///
/// The buffer is caller-owned (no_std, no allocation); size it with
/// `pool.owned_by(owner)` — a short buffer leaks loudly by count (the
/// caller checks the return against `owned_by`).
/// ADR-0027 (the ADR-0024 D2 fix): release every frame the dying
/// domain MAPS BUT DOES NOT OWN — the borrowed side of each share
/// (fork-shared-from-parent, granted-in). The owner-owning side is
/// `reclaim_domain_frames`' business; the two rules are disjoint
/// (`owner_of(pa) != domain` here, `==` there). Release-to-zero frees
/// under the ORIGINAL owner's tag, exactly as reclaim does. Returns
/// how many borrowed references went back.
pub fn release_borrowed_frames<const N: usize>(
    tables: &crate::mm::page_table::PageTables,
    pool: &mut FramePool<N>,
    buddy: &mut BuddyAllocator<N>,
    domain: u32,
) -> usize {
    // Collect ONLY the borrowed frames, filtering DURING the walk: a
    // domain may map far more pages than MAX_SHARED, but its borrowed
    // shares cannot exceed the table (each needs an entry) — so the
    // buffer cannot truncate a real share.
    let mut pas = [0u64; aegis_os::frame_share::MAX_GRANT_PAGES];
    let mut n = 0usize;
    tables.walk_user_frames(&mut |_va, pa| {
        let shares = context::shares_mut();
        if let Some(orig) = shares.owner_of(pa) {
            if orig != domain && n < pas.len() {
                pas[n] = pa;
                n += 1;
            }
        }
    });
    let mut released = 0usize;
    for &pa in pas[..n].iter() {
        let shares = context::shares_mut();
        if let Some(orig) = shares.owner_of(pa) {
            if orig != domain {
                let last = matches!(shares.release(pa), Ok(true));
                released += 1;
                if last {
                    let _ = pool.free(buddy, pa, orig);
                }
            }
        }
    }
    released
}

pub fn reclaim_domain_frames<const N: usize>(
    pool: &mut FramePool<N>,
    buddy: &mut BuddyAllocator<N>,
    owner: u32,
    buf: &mut [Option<usize>],
) -> usize {
    let n = pool.collect_owned(owner, buf);
    let mut freed = 0usize;
    for f in buf[..n].iter().flatten() {
        let pa = pool.pa_of(*f);
        let shares = context::shares_mut();
        if let Some(orig) = shares.owner_of(pa) {
            let last = matches!(shares.release(pa), Ok(true));
            if last && pool.free(buddy, pa, orig).is_ok() {
                freed += 1;
            }
        } else if pool.free(buddy, pa, owner).is_ok() {
            freed += 1;
        }
    }
    freed
}
