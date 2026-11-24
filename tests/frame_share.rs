//! ADR-0024 (Phase 3) host tests: frame reference counts, the
//! copy-on-write decision, and the free-window allocator — the pure
//! halves of the memory round, red before the API exists.

use aegis_os::frame_share::{CowDecision, FrameShares, ShareError};
use aegis_os::memory::AddressSpace;

// ── the refcount table ──────────────────────────────────────────────

#[test]
fn refcounts_acquire_release_and_report_sharing() {
    let mut s = FrameShares::<64>::new(0x1000, 0x1000);
    assert_eq!(s.refs(0x5000), None, "absent frames carry no count");
    // One acquire = the private holder + this new sharer (insertion
    // counts the original mapping — the fork shape).
    s.acquire(0x5000, 7).unwrap();
    assert_eq!(s.refs(0x5000), Some(2));
    s.acquire(0x5000, 9).unwrap(); // any holder; the FIRST owner sticks
    assert_eq!(s.refs(0x5000), Some(3));
    assert!(s.is_shared(0x5000));
    // Releases that are not the last keep the frame.
    assert_eq!(s.release(0x5000), Ok(false));
    assert_eq!(s.refs(0x5000), Some(2));
    assert!(s.is_shared(0x5000));
    assert_eq!(s.release(0x5000), Ok(false));
    assert_eq!(
        s.refs(0x5000),
        Some(1),
        "the lone original holder still counts"
    );
    // The last release answers true: the CALLER frees the frame —
    // under the ORIGINAL owner's tag, which the table remembered.
    assert_eq!(s.owner_of(0x5000), Some(7));
    assert_eq!(s.release(0x5000), Ok(true));
    assert_eq!(s.refs(0x5000), None, "released-to-zero leaves the table");
    assert_eq!(s.owner_of(0x5000), None);
}

#[test]
fn releasing_an_absent_frame_is_a_typed_error_never_a_wraparound() {
    let mut s = FrameShares::<64>::new(0x1000, 0x1000);
    assert_eq!(s.release(0x7000), Err(ShareError::NotHeld(0x7000)));
    // acquire + releases down to the last: the insertion counts the
    // original holder, so ONE acquire holds TWO references.
    s.acquire(0x7000, 7).unwrap();
    assert_eq!(s.release(0x7000), Ok(false));
    assert_eq!(s.release(0x7000), Ok(true));
    assert_eq!(s.release(0x7000), Err(ShareError::NotHeld(0x7000)));
}

#[test]
fn the_dense_table_has_no_capacity_to_refuse() {
    // ADR-0032 section C: the round-A finding, killed at the
    // integration level — filling EVERY frame the pool indexes (the
    // old test filled MAX_SHARED=64 and expected TableFull; the dense
    // table has no capacity, so the SAME fill must simply work).
    let mut s = FrameShares::<64>::new(0x1000, 0x1000);
    for i in 0..64u64 {
        s.acquire(0x1000 + i * 0x1000, 7).unwrap();
    }
    assert_eq!(s.shared_frames(), 64);
    // Every entry is live and queryable, O(1).
    assert_eq!(s.refs(0x9000), Some(2));
    // Out-of-pool geometry is still a typed refusal — the bound is
    // the POOL, not a slot count.
    assert_eq!(
        s.acquire(0xF000_0000, 7),
        Err(ShareError::NotHeld(0xF000_0000))
    );
    // The refcount bound is typed, never a wrap (the u16 ceiling):
    // wind a single frame's count all the way up — the next acquire
    // must refuse with Overflow, and the count must not wrap.
    let mut t = FrameShares::<4>::new(0x1000, 0x1000);
    let mut acquires = 0u64;
    loop {
        match t.acquire(0x2000, 7) {
            Ok(()) => acquires += 1,
            Err(ShareError::Overflow(0x2000)) => break,
            Err(other) => panic!("unexpected refusal before the ceiling: {other:?}"),
        }
        assert!(acquires < 70_000, "the ceiling must arrive, not loop");
    }
    assert_eq!(
        t.refs(0x2000),
        Some(u32::from(aegis_os::frame_share::RefCount::MAX)),
        "the count sits exactly at the ceiling, unwrapped"
    );
}

// ── the CoW decision ────────────────────────────────────────────────

use aegis_os::frame_share::cow_decision;

#[test]
fn a_lone_demoted_page_promotes_instead_of_copying() {
    // The sibling already copied: refs==1, the PTE still demoted, the
    // region says writable — the write is served by re-promoting the
    // PTE in place (no copy, no allocation, no refcount change).
    assert_eq!(
        cow_decision(true, false, true, true, Some(1), true),
        CowDecision::Promote
    );
    // The same page READ (not written) stays NotCow.
    assert_eq!(
        cow_decision(true, false, true, true, Some(1), false),
        CowDecision::NotCow
    );
}

#[test]
fn cow_fires_exactly_on_shared_writable_region_writes_to_demoted_ptes() {
    // The one true Copy: present, user, PTE read-only, region
    // writable, shared, write fault.
    assert_eq!(
        cow_decision(true, false, true, true, Some(2), true),
        CowDecision::Copy
    );
}

#[test]
fn everything_else_is_not_cow() {
    /// (name, present, pte_writable, user, region_writable, refs, write)
    type Case = (&'static str, bool, bool, bool, bool, Option<u32>, bool);
    let cases: &[Case] = &[
        ("absent page", false, false, true, true, Some(2), true),
        ("kernel page", true, false, false, true, Some(2), true),
        (
            "pte already writable",
            true,
            true,
            true,
            true,
            Some(2),
            true,
        ),
        (
            "region read-only (a real violation)",
            true,
            false,
            true,
            false,
            Some(2),
            true,
        ),
        (
            "no refcount entry (private by construction)",
            true,
            false,
            true,
            true,
            None,
            true,
        ),
        (
            "a READ fault on a demoted pte",
            true,
            false,
            true,
            true,
            Some(2),
            false,
        ),
    ];
    for (name, present, pte_writable, user, region_writable, refs, write) in cases {
        assert_eq!(
            cow_decision(
                *present,
                *pte_writable,
                *user,
                *region_writable,
                *refs,
                *write
            ),
            CowDecision::NotCow,
            "case: {name}"
        );
    }
}

// ── the free-window allocator ───────────────────────────────────────

#[test]
fn the_allocator_finds_gaps_the_policy_actually_accepts() {
    // A space shaped like a spawned run: code, data, stack, trampoline
    // (the kernel layout's exact addresses — the allocator must pick
    // ABOVE them and leave guard gaps the ten-check policy accepts).
    let mut sp = AddressSpace::new(16);
    sp.map(
        0x400000,
        4096,
        aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::EXEC,
    )
    .unwrap();
    sp.map(
        0x403000,
        4096,
        aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE,
    )
    .unwrap();
    sp.map(
        0x408000,
        4096,
        aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE,
    )
    .unwrap();
    sp.map(
        0x40C000,
        4096,
        aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::EXEC,
    )
    .unwrap();

    let two_pages = sp
        .find_free_window(8192, 0x40D000)
        .expect("room above the trampoline");
    // Page-aligned, at or above the floor.
    assert_eq!(two_pages % 4096, 0);
    assert!(two_pages >= 0x40D000);
    // And the POLICY accepts it (gaps included) — the allocator may
    // not propose anything the ten checks would refuse.
    sp.map(
        two_pages,
        8192,
        aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE,
    )
    .expect("the proposed window passes the real policy gate");
}

#[test]
fn the_allocator_honors_the_floor_and_exhausts_honestly() {
    let mut sp = AddressSpace::new(4);
    sp.map(
        0x400000,
        4096,
        aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE,
    )
    .unwrap();
    // A floor above the mapped region: the window must be at/above it.
    let w = sp.find_free_window(4096, 0x410000).unwrap();
    assert!(w >= 0x410000);
    // Fill until the policy refuses — the allocator is quota-BLIND by
    // design (its doc says the caller may still refuse); the fill ends
    // at None (no window) or QuotaExceeded (no budget), whichever
    // comes first, and neither may wrap into occupied space.
    let mut refusals = 0;
    while let Some(base) = sp.find_free_window(4096, 0x410000) {
        if sp
            .map(
                base,
                4096,
                aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE,
            )
            .is_err()
        {
            refusals += 1;
            assert!(refusals == 1, "the refusal must be the quota, once");
            break;
        }
    }
    // The layering, pinned: the allocator is quota-BLIND (VA space
    // still exists above the fill) — the POLICY is the refuser.
    let still_free = sp.find_free_window(4096, 0x410000);
    assert!(
        still_free.is_some(),
        "VA windows still exist past the quota"
    );
    assert_eq!(
        sp.map(
            still_free.unwrap(),
            4096,
            aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE
        ),
        Err(aegis_os::memory::MemError::QuotaExceeded)
    );
    // The occupied regions are untouched and distinct.
    let mut count = 0;
    for r in sp.regions() {
        assert!(r.base >= 0x410000 || r.base == 0x400000);
        count += 1;
    }
    assert!(
        count >= 2,
        "the fill loop actually mapped something ({count})"
    );
}
