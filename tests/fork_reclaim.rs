//! ADR-0024 (Phase 3) host tests: the fork/reclaim stress MODEL —
//! the core's `fork_process`/`exit_process` churn replayed against a
//! frame-sharing model built on the REAL `FrameShares` table, ending
//! with every frame accounted for. The kernel-side page-table fork is
//! lane-proven; this model pins the REFCOUNT/RECLAIM half the lanes
//! only sample.

use aegis_os::frame_share::FrameShares;
use aegis_os::prelude::*;

const SUPERVISOR: u32 = 0;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One model process: the frame set it maps. A fork makes the child
/// map the parent's set (every frame acquired in the table); an exit
/// releases every frame (freeing on the last reference).
struct Model {
    frames: [Vec<u64>; 32],
    next_frame: u64,
    freed: u64,
    allocated: u64,
}

impl Model {
    fn spawn_root(&mut self, id: usize, pages: u64) {
        for _ in 0..pages {
            let pa = self.next_frame;
            self.next_frame += 0x1000;
            self.allocated += 1;
            self.frames[id].push(pa);
        }
    }

    fn fork(&mut self, parent: usize, child: usize, shares: &mut FrameShares) -> bool {
        // The child maps everything the parent maps (the clone's
        // verbatim copy); every shared frame is acquired.
        let parent_frames: Vec<u64> = self.frames[parent].clone();
        for &pa in &parent_frames {
            if shares.acquire(pa, (parent + 1) as u32).is_err() {
                // TableFull: the fork refuses (ENOMEM) — roll back
                // what this fork acquired so far.
                let acquired: Vec<u64> = self.frames[child].clone();
                for q in acquired {
                    let _ = shares.release(q);
                }
                self.frames[child].clear();
                return false;
            }
            self.frames[child].push(pa);
        }
        true
    }

    fn exit(&mut self, id: usize, shares: &mut FrameShares) {
        let owned: Vec<u64> = self.frames[id].clone();
        for pa in owned {
            if shares.refs(pa).is_some() {
                if matches!(shares.release(pa), Ok(true)) {
                    self.freed += 1;
                }
            } else {
                // Private: frees outright.
                self.freed += 1;
            }
        }
        self.frames[id].clear();
    }
}

#[test]
fn random_fork_exit_churn_reclaims_every_frame() {
    let mut k = Kernel::new();
    k.create_domain_with(SUPERVISOR, service_profile(), 0, 0, 0)
        .unwrap();
    // The live proc churn runs on the real core in lockstep: every
    // model fork is a real fork_process, every exit a real exit.
    let mut rng = Rng(0x5EED_C0DE);
    let mut shares = FrameShares::new();
    let mut model = Model {
        frames: core::array::from_fn(|_| Vec::new()),
        next_frame: 0x100_000,
        freed: 0,
        allocated: 0,
    };
    let mut live: Vec<u32> = Vec::new();
    // PIDs (the core's fork counter starts at 100) map to model
    // slots; static ids 1..=6 use their own slots.
    let mut slot_of: std::collections::BTreeMap<u32, usize> =
        (1u32..=6).map(|i| (i, i as usize)).collect();
    let mut free_slots: Vec<usize> = (7..32).collect();

    // Roots 1..=6 (supervisor is 0 and never exits).
    for id in 1..=6u32 {
        k.create_domain_with(id, service_profile(), 1000, 100, 0)
            .unwrap();
        model.spawn_root(id as usize, 3);
        live.push(id);
    }

    for _ in 0..600 {
        let n = live.len();
        if n == 0 {
            break;
        }
        let pick = rng.below(4);
        let idx = rng.below(n as u64) as usize;
        let id = live[idx];
        match pick {
            0 | 1 => {
                // FORK: the core must agree, the model must follow.
                if let Ok(child) = k.fork_process(id) {
                    let Some(&parent_slot) = slot_of.get(&id) else {
                        continue;
                    };
                    let Some(child_slot) = free_slots.pop() else {
                        let _ = k.exit_process(child, ExitStatus::normal(0));
                        continue;
                    };
                    if model.fork(parent_slot, child_slot, &mut shares) {
                        slot_of.insert(child, child_slot);
                        live.push(child);
                    } else {
                        // The share table refused — the kernel-side
                        // fork would refuse too (ENOMEM); undo.
                        let _ = k.exit_process(child, ExitStatus::normal(0));
                        free_slots.push(child_slot);
                    }
                }
            }
            2 | 3 if n > 2 => {
                // EXIT (leave the supervisor and one domain alive).
                k.exit_process(id, ExitStatus::normal(0)).unwrap();
                if let Some(slot) = slot_of.remove(&id) {
                    model.exit(slot, &mut shares);
                    if slot > 6 {
                        free_slots.push(slot);
                    }
                }
                live.swap_remove(idx);
            }
            _ => {}
        }
        // Invariant: nothing leaks mid-flight — allocated == live
        // frames (private + summed refs) + freed.
        // (The accounting check itself runs at the end — mid-flight
        // the identity is: held == Σ domain frame counts, which the
        // per-frame refs table must mirror exactly. Spot-check: every
        // PA in exactly-two live sets has refs == the number of sets
        // containing it.)
        let mut pa_counts: std::collections::BTreeMap<u64, u32> = std::collections::BTreeMap::new();
        for frames in model.frames.iter().skip(1) {
            for &pa in frames {
                *pa_counts.entry(pa).or_insert(0) += 1;
            }
        }
        for (pa, count) in &pa_counts {
            let refs = shares.refs(*pa);
            if *count == 1 {
                // A private frame may have no entry (never forked) or
                // an entry whose refs the releases will settle.
                let _ = refs;
            } else {
                assert_eq!(
                    refs,
                    Some(*count),
                    "pa {pa:#x} held by {count} sets but refs={refs:?}"
                );
            }
        }
    }

    // Teardown: exit everyone; every frame freed; the table empty.
    for id in live {
        k.exit_process(id, ExitStatus::normal(0)).unwrap();
        if let Some(slot) = slot_of.remove(&id) {
            model.exit(slot, &mut shares);
        }
    }
    assert_eq!(
        model.freed, model.allocated,
        "every allocated frame reclaimed (freed {} of {})",
        model.freed, model.allocated
    );
    // The share table's emptiness is structural: probe the whole PA
    // space the model used.
    let mut pa = 0x100_000u64;
    while pa < model.next_frame {
        assert_eq!(shares.refs(pa), None, "leftover ref at {pa:#x}");
        pa += 0x1000;
    }
    assert_eq!(k.live_domain_count(), 1, "only the supervisor remains");
}

#[test]
fn a_single_fork_and_two_exits_frees_under_the_original_owner() {
    let mut shares = FrameShares::new();
    // A parent-owned frame shared at fork: ONE acquire, and the
    // insertion itself accounts for both holders (parent + child).
    shares.acquire(0x2000, 5).unwrap();
    assert_eq!(shares.refs(0x2000), Some(2));
    // Both exit: two releases, the second is the last and names the
    // ORIGINAL owner for the pool free.
    assert_eq!(shares.release(0x2000), Ok(false));
    assert_eq!(
        shares.owner_of(0x2000),
        Some(5),
        "the owner survives releases"
    );
    assert_eq!(shares.release(0x2000), Ok(true));
    assert_eq!(shares.owner_of(0x2000), None);
}
