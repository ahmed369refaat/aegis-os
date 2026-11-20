//! CFS-inspired fair scheduler (Linux Completely Fair Scheduler in miniature).
//!
//! - Every runnable domain has a virtual runtime (`vruntime`) and a weight
//!   derived from its nice level using the real Linux `sched_prio_to_weight`
//!   table (nice 0 = 1024, each step ≈ 1.25×).
//! - `pick_next` runs the domain with the smallest vruntime (ties broken by
//!   lowest domain id).
//! - `tick` charges `run_ticks * NICE_0_WEIGHT / weight` virtual time, so a
//!   heavy domain's vruntime grows slower — it earns proportionally more CPU.
//! - The charge is floored at 1 per tick so that even the heaviest domain
//!   cannot stall the others (starvation freedom).

pub const MAX_SCHED_ENTITIES: usize = 8;
pub const NICE_MIN: i8 = -20;
pub const NICE_MAX: i8 = 19;
pub const NICE0_WEIGHT: u32 = 1024;

/// Linux `sched_prio_to_weight` for nice -20..=19 (index = nice + 20).
pub const NICE_TO_WEIGHT: [u32; 40] = [
    88761, 71055, 56483, 45083, 35808, 28672, 22898, 18255, 14564, 11603, 9244, 7372, 5869, 4674,
    3723, 2966, 2362, 1881, 1496, 1193, 1024, 820, 655, 524, 420, 336, 272, 217, 173, 138, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedError {
    TableFull,
    UnknownDomain(u32),
}

#[derive(Debug, Clone, Copy)]
pub struct SchedEntity {
    pub domain_id: u32,
    pub vruntime: u64,
    pub nice: i8,
    pub weight: u32,
    pub runnable: bool,
    /// Total scheduler slices this entity received (for tests/telemetry).
    pub slices: u64,
}

#[derive(Default)]
pub struct Scheduler {
    /// F12: the floor every new or woken entity is placed at — without
    /// it, a late joiner starts at vruntime 0 and monopolizes the CPU.
    min_vruntime: u64,
    entities: [Option<SchedEntity>; MAX_SCHED_ENTITIES],
}

impl Scheduler {
    pub const fn new() -> Self {
        Scheduler {
            min_vruntime: 0,
            entities: [None; MAX_SCHED_ENTITIES],
        }
    }

    /// Register a domain with a nice level (clamped to -20..=19).
    pub fn register(&mut self, domain_id: u32, nice: i8) -> Result<(), SchedError> {
        if self
            .entities
            .iter()
            .flatten()
            .any(|e| e.domain_id == domain_id)
        {
            return Ok(()); // idempotent re-registration
        }
        for slot in self.entities.iter_mut() {
            if slot.is_none() {
                *slot = Some(SchedEntity {
                    domain_id,
                    vruntime: self.min_vruntime,
                    nice: nice.clamp(NICE_MIN, NICE_MAX),
                    weight: weight_for(nice),
                    runnable: true,
                    slices: 0,
                });
                return Ok(());
            }
        }
        Err(SchedError::TableFull)
    }

    pub fn unregister(&mut self, domain_id: u32) -> Result<(), SchedError> {
        for slot in self.entities.iter_mut() {
            if matches!(slot, Some(e) if e.domain_id == domain_id) {
                *slot = None;
                return Ok(());
            }
        }
        Err(SchedError::UnknownDomain(domain_id))
    }

    /// Change the nice level of a registered domain.
    pub fn set_nice(&mut self, domain_id: u32, nice: i8) -> Result<(), SchedError> {
        let e = self.entity_mut(domain_id)?;
        e.nice = nice.clamp(NICE_MIN, NICE_MAX);
        e.weight = weight_for(e.nice);
        Ok(())
    }

    fn entity_mut(&mut self, domain_id: u32) -> Result<&mut SchedEntity, SchedError> {
        self.entities
            .iter_mut()
            .flatten()
            .find(|e| e.domain_id == domain_id)
            .ok_or(SchedError::UnknownDomain(domain_id))
    }

    #[must_use]
    pub fn entity(&self, domain_id: u32) -> Option<SchedEntity> {
        self.entities
            .iter()
            .flatten()
            .find(|e| e.domain_id == domain_id)
            .copied()
    }

    /// Set the runnable flag (wake up / sleep).
    pub fn set_runnable(&mut self, domain_id: u32, runnable: bool) -> Result<(), SchedError> {
        // F12: a domain waking up is placed at max(own, min_vruntime) so
        // sleeping through everyone's work cannot buy it the CPU.
        if runnable {
            let floor = self.min_vruntime;
            if let Some(e) = self
                .entities
                .iter_mut()
                .flatten()
                .find(|e| e.domain_id == domain_id)
            {
                e.vruntime = e.vruntime.max(floor);
            }
        }
        self.entity_mut(domain_id)?.runnable = runnable;
        Ok(())
    }

    /// Pick the runnable domain with the smallest vruntime
    /// (ties → lowest domain id). Does not charge anything yet.
    #[must_use]
    pub fn pick_next(&self) -> Option<u32> {
        self.entities
            .iter()
            .flatten()
            .filter(|e| e.runnable)
            .min_by_key(|e| (e.vruntime, e.domain_id))
            .map(|e| e.domain_id)
    }

    /// Charge `run_ticks` of execution to a domain: weighted virtual time.
    pub fn tick(&mut self, domain_id: u32, run_ticks: u64) -> Result<u64, SchedError> {
        let new_vruntime = {
            let e = self.entity_mut(domain_id)?;
            let delta = (run_ticks.saturating_mul(NICE0_WEIGHT as u64) / e.weight as u64).max(1);
            e.vruntime = e.vruntime.saturating_add(delta);
            e.slices = e.slices.saturating_add(1);
            e.vruntime
        };
        // F12: the floor advances with the running entity so newcomers
        // and woken domains land at "now", not at 0.
        self.min_vruntime = self.min_vruntime.max(new_vruntime);
        Ok(new_vruntime)
    }

    /// Convenience: pick then charge one standard slice.
    pub fn schedule_slice(&mut self, slice_ticks: u64) -> Option<u32> {
        let next = self.pick_next()?;
        let _ = self.tick(next, slice_ticks);
        Some(next)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entities.iter().flatten().count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[must_use]
pub fn weight_for(nice: i8) -> u32 {
    let idx = (nice.clamp(NICE_MIN, NICE_MAX) as i32 - NICE_MIN as i32) as usize;
    NICE_TO_WEIGHT[idx]
}

#[cfg(test)]
mod f12_tests {
    use super::*;

    /// F12: a late joiner (or a woken domain) used to start at vruntime 0
    /// and monopolize the CPU. New/woken entities must be placed at
    /// max(own, min_vruntime).
    #[test]
    fn late_joiner_is_placed_at_min_vruntime_not_zero() {
        let mut s = Scheduler::new();
        s.register(1, 0).unwrap();
        s.register(2, 0).unwrap();
        for _ in 0..10 {
            s.tick(1, 5).unwrap();
            s.tick(2, 5).unwrap();
        }
        // Both runners are at vruntime 50; min_vruntime tracks the max
        // of the two.
        assert_eq!(s.entity(1).unwrap().vruntime, 50);
        s.register(3, 0).unwrap();
        let joined = s.entity(3).unwrap().vruntime;
        assert!(
            joined >= 50,
            "late joiner placed at min_vruntime (got {joined}, want >= 50) — a 0 would starve the runners"
        );
        // Same for a domain that slept through the work and wakes now.
        s.set_runnable(2, false).unwrap();
        for _ in 0..4 {
            s.tick(1, 5).unwrap();
        }
        s.set_runnable(2, true).unwrap();
        let woken = s.entity(2).unwrap().vruntime;
        assert!(
            woken >= 50,
            "woken domain placed at min_vruntime (got {woken})"
        );
        // Fair competition, no monopoly: 3 (behind at 50) is picked
        // first, catches up to the floor, and then the tie breaks by id
        // — a late birth buys at most a catch-up, never the CPU.
        assert_eq!(s.pick_next(), Some(3));
        while s.entity(3).unwrap().vruntime < 70 {
            s.tick(3, 5).unwrap();
        }
        assert_eq!(s.pick_next(), Some(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_table_matches_linux_values() {
        assert_eq!(weight_for(0), 1024);
        assert_eq!(weight_for(-20), 88761);
        assert_eq!(weight_for(19), 15);
        // Monotonically decreasing across the whole table.
        for i in 1..NICE_TO_WEIGHT.len() {
            assert!(NICE_TO_WEIGHT[i] < NICE_TO_WEIGHT[i - 1], "index {}", i);
        }
    }

    #[test]
    fn nice_is_clamped_on_register_and_set() {
        let mut s = Scheduler::new();
        s.register(1, -100).unwrap();
        assert_eq!(s.entity(1).unwrap().nice, NICE_MIN);
        s.set_nice(1, 100).unwrap();
        assert_eq!(s.entity(1).unwrap().nice, NICE_MAX);
        assert_eq!(s.entity(1).unwrap().weight, 15);
    }

    #[test]
    fn empty_scheduler_picks_none() {
        let mut s = Scheduler::new();
        assert_eq!(s.pick_next(), None);
        assert_eq!(s.schedule_slice(4), None);
        assert!(s.is_empty());
    }

    #[test]
    fn equal_nice_domains_alternate_fairly() {
        let mut s = Scheduler::new();
        s.register(1, 0).unwrap();
        s.register(2, 0).unwrap();
        // 10 slices: must alternate 1,2,1,2,... exactly.
        let mut picks = Vec::new();
        for _ in 0..10 {
            picks.push(s.schedule_slice(4).unwrap());
        }
        for (i, p) in picks.iter().enumerate() {
            let want = if i % 2 == 0 { 1 } else { 2 };
            assert_eq!(*p, want, "slice {}", i);
        }
        // Virtual runtimes stay together.
        assert_eq!(s.entity(1).unwrap().vruntime, s.entity(2).unwrap().vruntime);
        assert_eq!(s.entity(1).unwrap().slices, 5);
        assert_eq!(s.entity(2).unwrap().slices, 5);
    }

    #[test]
    fn tie_breaks_to_lowest_domain_id() {
        let mut s = Scheduler::new();
        s.register(7, 0).unwrap();
        s.register(3, 0).unwrap();
        assert_eq!(s.pick_next(), Some(3));
        s.tick(3, 4).unwrap();
        assert_eq!(s.pick_next(), Some(7));
    }

    #[test]
    fn nicer_domain_earns_proportionally_more_cpu() {
        let mut s = Scheduler::new();
        s.register(1, -5).unwrap(); // weight 3121
        s.register(2, 5).unwrap(); // weight 335
        let w1 = s.entity(1).unwrap().weight;
        let w2 = s.entity(2).unwrap().weight;
        assert!(w1 > w2);
        // Run many slices; the low-vruntime domain gets picked each time.
        let mut counts = [0u32; 2];
        for _ in 0..200 {
            let id = s.schedule_slice(1).unwrap();
            counts[(id - 1) as usize] += 1;
        }
        // Domain 1 (nice -5) must have received clearly more slices.
        assert!(
            counts[0] > counts[1] * 2,
            "nice -5 should dominate: {:?}",
            counts
        );
    }

    #[test]
    fn tick_charges_weighted_virtual_time() {
        let mut s = Scheduler::new();
        s.register(1, -20).unwrap(); // weight 88761
        s.register(2, 19).unwrap(); // weight 15
        let v1 = s.tick(1, 1000).unwrap();
        let v2 = s.tick(2, 1000).unwrap();
        // Same real time: the heavy domain is charged far less virtual time.
        assert!(v1 < v2 / 100);
        // Exactly: 1000 * 1024 / 88761 = 11; 1000 * 1024 / 15 = 68266.
        assert_eq!(v1, 11);
        assert_eq!(v2, 68266);
    }

    #[test]
    fn tick_progress_guarantee_prevents_starvation() {
        let mut s = Scheduler::new();
        s.register(1, 19).unwrap(); // weight 15
                                    // A tiny tick still advances vruntime by at least 1.
        let v = s.tick(1, 0).unwrap();
        assert_eq!(v, 1);
        let v = s.tick(1, 0).unwrap();
        assert_eq!(v, 2);
    }

    #[test]
    fn sleeping_domain_is_skipped_and_wakes_up() {
        let mut s = Scheduler::new();
        s.register(1, 0).unwrap();
        s.register(2, 0).unwrap();
        s.set_runnable(2, false).unwrap();
        // Only domain 1 is runnable.
        for _ in 0..5 {
            assert_eq!(s.schedule_slice(2).unwrap(), 1);
        }
        // Wake 2 (F12): placed at min_vruntime — it competes fairly
        // instead of winning outright with a stale 0 (the old behavior
        // let a sleeper monopolize the CPU on wake).
        s.set_runnable(2, true).unwrap();
        assert_eq!(s.entity(2).unwrap().vruntime, 10, "placed at the floor");
        assert_eq!(s.pick_next(), Some(1), "tie at the floor breaks by id");
    }

    #[test]
    fn vruntime_saturation_never_panics() {
        let mut s = Scheduler::new();
        s.register(1, 0).unwrap();
        {
            let e = s.entity_mut(1).unwrap();
            e.vruntime = u64::MAX;
        }
        let v = s.tick(1, u64::MAX).unwrap();
        assert_eq!(v, u64::MAX, "saturating add must clamp");
    }

    #[test]
    fn unregister_and_table_full() {
        let mut s = Scheduler::new();
        for id in 0..MAX_SCHED_ENTITIES as u32 {
            s.register(id, 0).unwrap();
        }
        assert_eq!(s.register(99, 0), Err(SchedError::TableFull));
        s.unregister(3).unwrap();
        assert_eq!(s.unregister(3), Err(SchedError::UnknownDomain(3)));
        s.register(99, 0).unwrap();
        assert_eq!(s.len(), MAX_SCHED_ENTITIES);
    }

    #[test]
    fn re_register_is_idempotent_keeps_vruntime() {
        let mut s = Scheduler::new();
        s.register(1, 0).unwrap();
        s.tick(1, 100).unwrap();
        s.register(1, 0).unwrap(); // no error, same slot
        assert_eq!(s.entity(1).unwrap().vruntime, 100);
        assert_eq!(s.len(), 1);
    }
}
