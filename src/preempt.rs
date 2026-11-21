//! Preemption policy (M2-W2 / ADR-0012): the decision layer between a
//! timer tick and a context switch.
//!
//! Per the multi-architecture discipline (ADR-0011 §D3), everything a
//! second architecture can reuse lives here, host-tested against the
//! real [`Scheduler`]: **what a tick means** (charge the running domain,
//! then pick), **when to switch** (only when the scheduler's pick
//! differs from the current domain), and **what an exit does** (hand
//! the CPU to the next runnable domain, or report the queue empty).
//! The hardware half — which interrupt, which frame layout, how the
//! registers travel — stays in the arch crates.
//!
//! Starvation freedom is the property this module exists for: a domain
//! that never yields (no syscalls, no faults — a pure spinner) is
//! charged one slice per tick exactly like everyone else, so the CFS
//! `pick_next` (smallest vruntime, ties by lowest id) rotates it out
//! within one tick. That is the M2 exit criterion "quarantine one
//! domain while others continue": the monitor's windows close on tick
//! even when the running domain would never call a syscall again.

use crate::sched::Scheduler;

/// What a timer tick decided. `Switch` carries the domain the CPU
/// should run next (never equal to `current` — a keep is `Keep`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickDecision {
    /// The current domain keeps the CPU (it is still the fair pick).
    Keep(u32),
    /// Another domain is the fair pick now; switch on the way out of
    /// the interrupt.
    Switch(u32),
}

/// The preemption decision layer over the real CFS scheduler.
///
/// Stateless by design: the vruntime, weights, and runnable set all
/// live in the [`Scheduler`] the caller owns (on the booted kernel,
/// `Kernel::sched` — the same instance the kernel-resident demo used,
/// so there is exactly one scheduler in the system).
pub struct Preemptor {
    /// How many timer ticks one scheduler slice is worth (the charge
    /// handed to `Scheduler::tick` per timer interrupt).
    slice_ticks: u64,
}

impl Preemptor {
    /// `slice_ticks` is clamped to >= 1 so a misconfiguration can never
    /// produce a zero charge (the progress guarantee then forces 1, but
    /// being explicit here documents the intent). Const-friendly max:
    /// `u64::max` is not const-stable on this toolchain.
    pub const fn new(slice_ticks: u64) -> Self {
        Preemptor {
            slice_ticks: if slice_ticks < 1 { 1 } else { slice_ticks },
        }
    }

    /// The timer fired while `current` was running. Charge `current`
    /// one slice, then ask the scheduler for the fair pick:
    /// - `current` is still the pick → `Keep` (the fast case: no frame
    ///   rewrite, the interrupt simply returns);
    /// - another domain is the pick → `Switch(next)`;
    /// - `current` is not registered (a bookkeeping bug in the caller,
    ///   or the tick raced a domain exit) → fall back to the pick
    ///   without charging anyone: the decision still names a runnable
    ///   domain, never a stall.
    pub fn on_tick(&self, sched: &mut Scheduler, current: u32) -> TickDecision {
        if sched.entity(current).is_some() {
            let _ = sched.tick(current, self.slice_ticks);
        }
        match sched.pick_next() {
            Some(next) if next != current => TickDecision::Switch(next),
            Some(_) => TickDecision::Keep(current),
            // No runnable domain at all (should be unreachable while a
            // run is active): keep the current one; the caller's idle
            // path handles the empty-queue case via `on_exit`.
            None => TickDecision::Keep(current),
        }
    }

    /// ADR-0023 D3: `current` volunteered the rest of its slice
    /// (`sched_yield`). The slice is charged IN FULL — volunteering
    /// must not buy priority, that is the CFS contract (a
    /// yield-loops-forever domain earns nothing but its own spin) —
    /// then the fair pick decides: `Some(other)` = the kernel parks and
    /// switches exactly as the tick path does; `None` = the caller is
    /// still the fair pick (or solo) and simply returns.
    pub fn on_yield(&self, sched: &mut Scheduler, current: u32) -> Option<u32> {
        if sched.entity(current).is_some() {
            let _ = sched.tick(current, self.slice_ticks);
        }
        sched.pick_next().filter(|next| *next != current)
    }

    /// `exited` finished (SYS_EXIT or a fault). Unregister it from the
    /// scheduler and name the next domain to run, or `None` when the
    /// queue is empty. The caller destroys the exited domain's
    /// resources — this only settles the scheduling question.
    pub fn on_exit(&self, sched: &mut Scheduler, exited: u32) -> Option<u32> {
        let _ = sched.unregister(exited);
        sched.pick_next()
    }
}

#[cfg(test)]
impl Preemptor {
    fn slice_ticks_dbg(&self) -> u64 {
        self.slice_ticks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The M2-W2 exit criterion, in miniature: a domain that NEVER
    /// yields cannot hold the CPU past one tick while another domain is
    /// runnable. Equal nice levels: the first tick charges the spinner,
    /// so the very next pick is the other domain.
    #[test]
    fn a_spinning_domain_cannot_starve_a_second() {
        let p = Preemptor::new(1);
        let mut s = Scheduler::new();
        s.register(1, 0).unwrap(); // the spinner
        s.register(2, 0).unwrap(); // the well-behaved domain

        // First tick: the spinner is charged but is still the fair pick
        // (tie at equal vruntime, lowest id wins) — or it keeps the CPU
        // for at most this one tick.
        let d = p.on_tick(&mut s, 1);
        assert!(matches!(d, TickDecision::Keep(1) | TickDecision::Switch(2)));

        // Whatever the first decision was, the spinner must lose the
        // CPU by the SECOND tick at the latest, and get it back after
        // the other domain is charged — alternation, not monopoly.
        let mut switches = 0u32;
        let mut current = 1;
        for _ in 0..20 {
            match p.on_tick(&mut s, current) {
                TickDecision::Keep(c) => assert_eq!(c, current),
                TickDecision::Switch(n) => {
                    assert_ne!(n, current);
                    current = n;
                    switches += 1;
                }
            }
        }
        assert!(
            switches >= 10,
            "20 ticks must rotate the CPU at least every other tick (got {switches})"
        );
        // And both domains actually ran: slices are charged per tick.
        assert!(s.entity(1).unwrap().slices >= 9);
        assert!(s.entity(2).unwrap().slices >= 9);
    }

    #[test]
    fn a_solo_domain_is_never_switched() {
        let p = Preemptor::new(1);
        let mut s = Scheduler::new();
        s.register(7, 0).unwrap();
        for _ in 0..50 {
            assert_eq!(p.on_tick(&mut s, 7), TickDecision::Keep(7));
        }
    }

    #[test]
    fn equal_nice_domains_alternate_exactly() {
        let p = Preemptor::new(1);
        let mut s = Scheduler::new();
        s.register(20, 0).unwrap();
        s.register(21, 0).unwrap();
        // 20 starts (tie → lowest id): 20,21,20,21,...
        let mut current = 20;
        let mut seq = vec![current];
        for _ in 0..10 {
            if let TickDecision::Switch(n) = p.on_tick(&mut s, current) {
                current = n;
            }
            seq.push(current);
        }
        for (i, id) in seq.iter().enumerate() {
            assert_eq!(*id, if i % 2 == 0 { 20 } else { 21 }, "slot {i}");
        }
    }

    #[test]
    fn exit_hands_over_to_the_survivor_then_reports_empty() {
        let p = Preemptor::new(1);
        let mut s = Scheduler::new();
        s.register(20, 0).unwrap();
        s.register(21, 0).unwrap();
        // 21 exits first (the writer finishing while the spinner runs).
        assert_eq!(p.on_exit(&mut s, 21), Some(20));
        // The exited domain is gone from the scheduler's view.
        assert!(s.entity(21).is_none());
        // Then the spinner exits: the queue is empty.
        assert_eq!(p.on_exit(&mut s, 20), None);
        assert!(s.is_empty());
    }

    #[test]
    fn nicer_domain_earns_proportionally_more_slices() {
        let p = Preemptor::new(1);
        let mut s = Scheduler::new();
        s.register(1, -5).unwrap(); // weight 3121
        s.register(2, 5).unwrap(); // weight 335
        let mut counts = [0u32; 2];
        let mut current = 1;
        for _ in 0..200 {
            match p.on_tick(&mut s, current) {
                TickDecision::Keep(c) => counts[(c - 1) as usize] += 1,
                TickDecision::Switch(n) => {
                    counts[(n - 1) as usize] += 1;
                    current = n;
                }
            }
        }
        assert!(
            counts[0] > counts[1] * 2,
            "nice -5 should dominate: {counts:?}"
        );
    }

    /// The tick raced a domain exit (or the caller forgot to register):
    /// the decision still names a runnable domain instead of stalling —
    /// and the unregistered current is never charged.
    #[test]
    fn unregistered_current_falls_back_to_the_pick_without_charging() {
        let p = Preemptor::new(4);
        let mut s = Scheduler::new();
        s.register(5, 0).unwrap();
        // Domain 9 was never registered (it just exited / a bookkeeping
        // bug): the tick must hand the CPU to the registered one.
        assert_eq!(p.on_tick(&mut s, 9), TickDecision::Switch(5));
        // And domain 5 was not charged for a domain it is not.
        assert_eq!(s.entity(5).unwrap().slices, 0);
    }

    #[test]
    fn slice_ticks_clamps_to_one() {
        assert_eq!(Preemptor::new(0).slice_ticks_dbg(), 1);
        assert_eq!(Preemptor::new(4).slice_ticks_dbg(), 4);
    }

    /// Exhaustion honesty: every registered domain that never exits
    /// still sees its slice count grow under a spinner monopoly — the
    /// scheduler's own progress guarantee, exercised through the
    /// preemptor.
    #[test]
    fn heavy_domain_progress_guarantee_survives_the_preemptor() {
        let p = Preemptor::new(1);
        let mut s = Scheduler::new();
        s.register(1, 19).unwrap(); // weight 15 — the heaviest nice
        s.register(2, 19).unwrap();
        let mut current = 1;
        let mut ran_2 = false;
        for _ in 0..100 {
            if let TickDecision::Switch(n) = p.on_tick(&mut s, current) {
                current = n;
            }
            if current == 2 {
                ran_2 = true;
            }
        }
        assert!(ran_2, "the heaviest-nice pair must still rotate");
    }
}
