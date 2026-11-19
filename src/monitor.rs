//! The AI security behavior layer: per-domain behavioral signals, an integer
//! risk score, and a graduated response with anti-flap hysteresis.
//!
//! Scoring contract:
//! - Integer math only (deterministic, no FPU on the kernel path).
//! - u128 intermediates: u64::MAX inputs cannot overflow.
//! - Every sub-signal saturates at 100; the weighted sum saturates at 100.
//!
//! Response tiers (per profile sensitivity, thresholds shift down as
//! sensitivity rises):
//! - `Log`        — default; the event lands in the telemetry ring.
//! - `Tighten`    — after `hysteresis` consecutive windows at/above the
//!                  tighten threshold (remove network/spawn/ioctl/mmap/open).
//! - `Quarantine` — after `hysteresis` consecutive windows at/above the
//!                  quarantine threshold, or immediately at the instant
//!                  threshold (near-max multi-signal misbehavior).
//!
//! Anti-flap: streaks only reset on a *quiet* window (below the tighten
//! threshold); a single spiky window never escalates. The *reported* score
//! decays gradually so telemetry does not cliff-drop.

use crate::syscall::{SyscallMask, SYSCALL_COUNT};

/// Per-domain behavioral counters (fast-path accounting, slow-path input).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DomainStats {
    pub syscalls_total: u64,
    pub denied_syscalls: u64,
    pub faults: u64,
    pub net_ops: u64,
    pub file_ops: u64,
    pub ipc_ops: u64,
    /// Failed capability escalations / mask-widening attempts.
    pub escalation_attempts: u64,
    /// Syscall ids attempted in this window (spread signal).
    used_mask_bits: u64,
}

impl DomainStats {
    /// Record a syscall attempt (allowed or denied). Out-of-range ids are
    /// ignored — they are rejected earlier on the fast path.
    pub fn mark_used(&mut self, id: u8) {
        if (id as usize) < SYSCALL_COUNT as usize {
            self.used_mask_bits |= 1u64 << id;
        }
    }

    #[must_use]
    pub fn used_mask(&self) -> u64 {
        self.used_mask_bits
    }

    /// Syscalls attempted that are outside the domain's allowed surface.
    #[must_use]
    pub fn out_of_profile_bits(&self, allowed: &SyscallMask) -> u32 {
        (self.used_mask_bits & !allowed.bits()).count_ones()
    }
}

/// Sub-signal weights (percent). Default sums to exactly 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorWeights {
    pub denied: u32,
    pub faults: u32,
    pub escalation: u32,
    pub out_of_profile: u32,
    pub spike: u32,
}

impl Default for MonitorWeights {
    fn default() -> Self {
        MonitorWeights {
            denied: 20,
            faults: 25,
            escalation: 30,
            out_of_profile: 10,
            spike: 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorConfig {
    /// Score at/above which a window counts toward tightening.
    pub tighten_threshold: u8,
    /// Score at/above which a window counts toward quarantine.
    pub quarantine_threshold: u8,
    /// Near-max score quarantines immediately (single window).
    pub instant_quarantine_threshold: u8,
    /// Consecutive bad windows required before escalating.
    pub hysteresis: u8,
    /// Score decay per quiet window (reporting only).
    pub decay_per_quiet_window: u8,
    /// Expected syscalls per window (spike baseline).
    pub baseline_syscalls: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            tighten_threshold: 45,
            quarantine_threshold: 75,
            instant_quarantine_threshold: 95,
            hysteresis: 2,
            decay_per_quiet_window: 15,
            baseline_syscalls: 128,
        }
    }
}

/// F9: what the kernel does with a monitor verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MonitorMode {
    /// Verdicts are computed and logged to telemetry, but no mask
    /// change and no quarantine is applied — the calibration mode
    /// (SECURITY-MODEL.md): tune thresholds on real traffic before
    /// letting the monitor act.
    AuditOnly,
    /// Verdicts are applied (Log / Tighten / Quarantine). The default.
    #[default]
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// Record and continue.
    Log,
    /// Narrow the domain's syscall surface.
    Tighten,
    /// Cut the domain off except SYS_EXIT.
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub score: u8,
    pub response: Response,
}

/// F7: the state table is sized from the domain table, not a magic
/// number — monitor slots are domain slots' shadow (and destroy_domain
/// frees them).
pub const MAX_MONITORED: usize = crate::MAX_DOMAINS;
const MIN_TIGHTEN_THRESHOLD: u8 = 5;
const MIN_QUARANTINE_THRESHOLD: u8 = 15;

#[derive(Debug, Clone, Copy, Default)]
struct MonState {
    last_score: u8,
    tighten_streak: u8,
    quarantine_streak: u8,
    quarantined: bool,
}

pub struct BehaviorMonitor {
    config: MonitorConfig,
    weights: MonitorWeights,
    states: [Option<(u32, MonState)>; MAX_MONITORED],
    /// Set when the per-domain state table overflowed; streak-based
    /// decisions degrade to Log for unseen domains (instant quarantine
    /// still fires — fail-safe, not fail-open).
    degraded: bool,
}

impl BehaviorMonitor {
    pub fn new(config: MonitorConfig) -> Self {
        BehaviorMonitor {
            config,
            weights: MonitorWeights::default(),
            states: [None; MAX_MONITORED],
            degraded: false,
        }
    }

    #[must_use]
    pub fn config(&self) -> &MonitorConfig {
        &self.config
    }

    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    fn index_of(&self, id: u32) -> Option<usize> {
        self.states
            .iter()
            .position(|s| matches!(s, Some((sid, _)) if *sid == id))
    }

    fn insert_state(&mut self, id: u32) -> Option<usize> {
        if let Some(i) = self.index_of(id) {
            return Some(i);
        }
        let idx = self.states.iter().position(|s| s.is_none())?;
        self.states[idx] = Some((id, MonState::default()));
        Some(idx)
    }

    /// Pure scoring: 0..=100 from the window's stats. No state, no mutation.
    #[must_use]
    pub fn score(&self, stats: &DomainStats, allowed: &SyscallMask) -> u8 {
        let s_denied: u32 = if stats.syscalls_total == 0 {
            // Defensive: denied without total (should not happen) reads as
            // fully denied, never as clean.
            if stats.denied_syscalls > 0 {
                100
            } else {
                0
            }
        } else {
            let d = stats.denied_syscalls as u128;
            let t = stats.syscalls_total as u128;
            (d * 100 / t).min(100) as u32
        };
        let s_faults = (stats.faults as u128 * 20).min(100) as u32;
        let s_esc = (stats.escalation_attempts as u128 * 30).min(100) as u32;
        let s_out = (stats.out_of_profile_bits(allowed) as u128 * 25).min(100) as u32;
        let expected = (self.config.baseline_syscalls.max(1)) as u128;
        let ratio = (stats.syscalls_total as u128 * 100) / expected;
        let s_spike: u32 = if ratio > 100 {
            (ratio - 100).min(100) as u32
        } else {
            0
        };

        let w = &self.weights;
        let raw = s_denied * w.denied
            + s_faults * w.faults
            + s_esc * w.escalation
            + s_out * w.out_of_profile
            + s_spike * w.spike;
        (raw / 100).min(100) as u8
    }

    /// Effective thresholds for a domain of the given sensitivity (0..=100):
    /// every 4 points of sensitivity lowers both thresholds by 1, floored.
    fn effective_thresholds(&self, sensitivity: u8) -> (u8, u8) {
        let drop = sensitivity / 4;
        let t = self
            .config
            .tighten_threshold
            .saturating_sub(drop)
            .max(MIN_TIGHTEN_THRESHOLD);
        let q = self
            .config
            .quarantine_threshold
            .saturating_sub(drop)
            .max(MIN_QUARANTINE_THRESHOLD);
        (t, q)
    }

    /// Score a window and decide the graduated response.
    pub fn evaluate(
        &mut self,
        domain_id: u32,
        stats: &DomainStats,
        allowed: &SyscallMask,
        sensitivity: u8,
    ) -> Verdict {
        let raw = self.score(stats, allowed);

        // Instant quarantine is stateless-safe: fires even if the state
        // table is full (fail-safe).
        if raw >= self.config.instant_quarantine_threshold {
            if let Some(idx) = self.insert_state(domain_id) {
                if let Some((_, st)) = self.states[idx].as_mut() {
                    st.quarantined = true;
                    st.last_score = raw;
                }
            } else {
                self.degraded = true;
            }
            return Verdict { score: raw, response: Response::Quarantine };
        }

        let idx = match self.index_of(domain_id) {
            Some(i) => i,
            None => match self.insert_state(domain_id) {
                Some(i) => i,
                None => {
                    // State table full: no hysteresis available for a new
                    // domain — degrade to Log rather than guess.
                    self.degraded = true;
                    return Verdict { score: raw, response: Response::Log };
                }
            },
        };
        // Thresholds first: `effective_thresholds` borrows all of `self`,
        // so it must run before the per-slot mutable borrow below.
        let (t_eff, q_eff) = self.effective_thresholds(sensitivity);
        let (_, st) = self.states[idx].as_mut().expect("state ensured above");

        if st.quarantined {
            // Sticky: only an explicit admin reset revokes quarantine.
            st.last_score = st.last_score.max(raw);
            return Verdict { score: st.last_score, response: Response::Quarantine };
        }
        // Streaks are independent and only reset on a quiet window.
        if raw >= q_eff {
            st.quarantine_streak = st.quarantine_streak.saturating_add(1);
        }
        if raw >= t_eff {
            st.tighten_streak = st.tighten_streak.saturating_add(1);
        } else {
            st.tighten_streak = 0;
            st.quarantine_streak = 0;
        }

        let response = if st.quarantine_streak >= self.config.hysteresis {
            st.quarantined = true;
            Response::Quarantine
        } else if st.tighten_streak >= self.config.hysteresis {
            Response::Tighten
        } else {
            Response::Log
        };

        // Reported score decays gradually from the last window's level.
        let smoothed = raw.max(st.last_score.saturating_sub(self.config.decay_per_quiet_window));
        st.last_score = smoothed;
        Verdict { score: smoothed, response }
    }

    /// Admin-only: clear a domain's monitor state (un-quarantine path).
    /// Returns true if a state existed and was cleared.
    pub fn reset(&mut self, domain_id: u32) -> bool {
        match self.index_of(domain_id) {
            Some(i) => {
                self.states[i] = None;
                true
            }
            None => false,
        }
    }
}

impl Default for BehaviorMonitor {
    fn default() -> Self {
        Self::new(MonitorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::{
        SYS_EXIT, SYS_MMAP, SYS_NET_SEND, SYS_READ, SYS_SPAWN, SYS_WRITE,
    };

    fn stats(total: u64, denied: u64, faults: u64, esc: u64, used: &[u8]) -> DomainStats {
        let mut s = DomainStats {
            syscalls_total: total,
            denied_syscalls: denied,
            faults,
            escalation_attempts: esc,
            ..DomainStats::default()
        };
        for &id in used {
            s.mark_used(id);
        }
        s
    }

    fn allowed_all() -> SyscallMask {
        SyscallMask::ALL
    }

    #[test]
    fn empty_stats_score_zero_and_log() {
        let mut m = BehaviorMonitor::default();
        let v = m.evaluate(1, &DomainStats::default(), &allowed_all(), 0);
        assert_eq!(v, Verdict { score: 0, response: Response::Log });
    }

    #[test]
    fn mark_used_ignores_out_of_range_ids() {
        let mut s = DomainStats::default();
        s.mark_used(0);
        s.mark_used(63);
        s.mark_used(64); // out of range: ignored
        s.mark_used(255); // out of range: ignored
        assert_eq!(s.used_mask().count_ones(), 2);
    }

    #[test]
    fn score_exact_tighten_boundary_is_45() {
        // denied ratio 100 (20) + faults 5 (25) = 45 exactly.
        let m = BehaviorMonitor::default();
        let s = stats(2, 2, 5, 0, &[]);
        assert_eq!(m.score(&s, &allowed_all()), 45);
    }

    #[test]
    fn score_just_below_boundary_is_44() {
        // denied 70% (14) + faults 5 (25) + 2 out-of-profile bits (5) = 44.
        let m = BehaviorMonitor::default();
        let s = stats(10, 7, 5, 0, &[SYS_NET_SEND, SYS_SPAWN]);
        assert_eq!(m.score(&s, &SyscallMask::NONE), 44);
    }

    #[test]
    fn score_spikes_only_contributes_15_at_10x_baseline() {
        let m = BehaviorMonitor::default();
        let s = stats(1280, 0, 0, 0, &[]);
        assert_eq!(m.score(&s, &allowed_all()), 15);
        // Exactly at baseline: no spike signal.
        assert_eq!(m.score(&stats(128, 0, 0, 0, &[]), &allowed_all()), 0);
    }

    #[test]
    fn score_max_counters_do_not_overflow() {
        let m = BehaviorMonitor::default();
        let s = stats(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            &[SYS_NET_SEND, SYS_SPAWN, SYS_MMAP, SYS_WRITE],
        );
        assert_eq!(m.score(&s, &SyscallMask::NONE), 100);
    }

    #[test]
    fn score_denied_without_total_reads_as_fully_denied() {
        // Defensive: impossible in practice (total increments with every
        // attempt), but must not divide by zero nor read as clean.
        let m = BehaviorMonitor::default();
        let s = stats(0, 5, 0, 0, &[]);
        assert_eq!(m.score(&s, &allowed_all()), 20);
    }

    #[test]
    fn single_spike_never_escalates() {
        let mut m = BehaviorMonitor::default();
        // Score 80 for one window (den 100 + faults 100 + esc 100 + out 50).
        let bad = stats(2, 2, 5, 4, &[SYS_NET_SEND, SYS_SPAWN]);
        assert_eq!(m.score(&bad, &SyscallMask::NONE), 80);
        let v1 = m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        assert_eq!(v1.response, Response::Log, "first bad window only logs");
        // Next window is clean: streaks reset, no escalation ever.
        let v2 = m.evaluate(1, &DomainStats::default(), &allowed_all(), 0);
        assert_eq!(v2.response, Response::Log);
        assert!(v2.score < 75);
    }

    #[test]
    fn two_consecutive_bad_windows_quarantine() {
        let mut m = BehaviorMonitor::default();
        let bad = stats(2, 2, 5, 4, &[SYS_NET_SEND, SYS_SPAWN]); // score 80
        let v1 = m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        assert_eq!(v1.response, Response::Log);
        let v2 = m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        assert_eq!(v2.response, Response::Quarantine);
        // Sticky afterwards, even with clean stats.
        let v3 = m.evaluate(1, &DomainStats::default(), &allowed_all(), 0);
        assert_eq!(v3.response, Response::Quarantine);
    }

    #[test]
    fn moderate_scores_tighten_then_stay() {
        let mut m = BehaviorMonitor::default();
        // Score 55: den 100 (20) + faults 100 (25) + out 100 (10).
        let mid = stats(2, 2, 5, 0, &[SYS_NET_SEND, SYS_SPAWN, SYS_MMAP, SYS_WRITE]);
        assert_eq!(m.score(&mid, &SyscallMask::NONE), 55);
        assert_eq!(m.evaluate(1, &mid, &SyscallMask::NONE, 0).response, Response::Log);
        let v2 = m.evaluate(1, &mid, &SyscallMask::NONE, 0);
        assert_eq!(v2.response, Response::Tighten);
        // Many more windows at 55: tighten streak grows, quarantine never
        // fires (55 < 75).
        for _ in 0..5 {
            let v = m.evaluate(1, &mid, &SyscallMask::NONE, 0);
            assert_eq!(v.response, Response::Tighten);
        }
    }

    #[test]
    fn instant_quarantine_fires_on_first_window() {
        let mut m = BehaviorMonitor::default();
        let catastrophic = stats(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            &[SYS_NET_SEND, SYS_SPAWN, SYS_MMAP, SYS_WRITE],
        ); // score 100
        let v = m.evaluate(1, &catastrophic, &SyscallMask::NONE, 0);
        assert_eq!(v, Verdict { score: 100, response: Response::Quarantine });
    }

    #[test]
    fn sensitivity_lowers_thresholds() {
        // Score 60: den 25% (5) + faults 100 (25) + esc 100 (30).
        let s = stats(4, 1, 5, 4, &[]);
        assert_eq!(BehaviorMonitor::default().score(&s, &allowed_all()), 60);

        let mut jumpy = BehaviorMonitor::default();
        // Sensitivity 80: q_eff = 75 - 20 = 55 -> 60 counts toward quarantine.
        let v1 = jumpy.evaluate(1, &s, &allowed_all(), 80);
        assert_eq!(v1.response, Response::Log);
        let v2 = jumpy.evaluate(1, &s, &allowed_all(), 80);
        assert_eq!(v2.response, Response::Quarantine);

        let mut calm = BehaviorMonitor::default();
        // Sensitivity 0: q_eff = 75 -> 60 only counts toward tightening.
        let first = calm.evaluate(2, &s, &allowed_all(), 0);
        assert_eq!(first.response, Response::Log);
        for _ in 0..4 {
            let v = calm.evaluate(2, &s, &allowed_all(), 0);
            assert_eq!(v.response, Response::Tighten, "never quarantine at score 60");
        }
    }

    #[test]
    fn reported_score_decays_gradually() {
        let mut m = BehaviorMonitor::default();
        let bad = stats(2, 2, 5, 4, &[SYS_NET_SEND, SYS_SPAWN]); // 80
        m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        // Each quiet window reports last_score - decay, floored at 0.
        let expected = [65u8, 50, 35, 20, 5, 0];
        for want in expected {
            let v = m.evaluate(1, &DomainStats::default(), &allowed_all(), 0);
            assert_eq!(v.score, want, "decay sequence");
        }
    }

    #[test]
    fn quiet_then_flap_does_not_escalate_endlessly() {
        // Alternating bad/quiet windows: each quiet window resets streaks,
        // so the domain is logged but never escalated. (Human-review path.)
        let mut m = BehaviorMonitor::default();
        let bad = stats(2, 2, 5, 4, &[SYS_NET_SEND, SYS_SPAWN]);
        for _ in 0..6 {
            m.evaluate(1, &bad, &SyscallMask::NONE, 0);
            let v = m.evaluate(1, &DomainStats::default(), &allowed_all(), 0);
            assert_eq!(v.response, Response::Log);
        }
    }

    #[test]
    fn state_table_full_degrades_to_log_but_instant_still_fires() {
        let mut m = BehaviorMonitor::default();
        for id in 0..MAX_MONITORED as u32 {
            m.evaluate(id, &DomainStats::default(), &allowed_all(), 0);
        }
        assert!(!m.is_degraded());
        // 9th domain, moderate score: degraded to Log, no hysteresis guesses.
        let mid = stats(2, 2, 5, 0, &[SYS_NET_SEND, SYS_SPAWN, SYS_MMAP, SYS_WRITE]); // 55
        let v = m.evaluate(99, &mid, &SyscallMask::NONE, 0);
        assert_eq!(v.response, Response::Log);
        assert!(m.is_degraded());
        // 9th domain, catastrophic score: instant quarantine still fires.
        let catastrophic = stats(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            &[SYS_NET_SEND, SYS_SPAWN, SYS_MMAP, SYS_WRITE],
        );
        let v2 = m.evaluate(100, &catastrophic, &SyscallMask::NONE, 0);
        assert_eq!(v2.response, Response::Quarantine);
    }

    #[test]
    fn admin_reset_clears_state() {
        let mut m = BehaviorMonitor::default();
        let bad = stats(2, 2, 5, 4, &[SYS_NET_SEND, SYS_SPAWN]);
        m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        assert!(m.reset(1));
        // Fresh state: the same bad window only logs again.
        let v = m.evaluate(1, &bad, &SyscallMask::NONE, 0);
        assert_eq!(v.response, Response::Log);
        assert!(!m.reset(42), "unknown domain");
    }

    #[test]
    fn exit_never_counts_as_out_of_profile() {
        let mut s = DomainStats::default();
        s.mark_used(SYS_EXIT);
        s.mark_used(SYS_READ);
        assert_eq!(s.out_of_profile_bits(&SyscallMask::from_bits(1u64 << SYS_EXIT)), 1);
        assert_eq!(s.out_of_profile_bits(&SyscallMask::ALL), 0);
    }
}
