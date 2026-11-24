//! Graduated response application and telemetry events.
//!
//! `apply_response` is the *only* code path that mutates a domain's surface
//! based on a monitor verdict. Responses are strictly reductive:
//! - Log: record, continue.
//! - Tighten: intersect the mask with the tightened surface (removes
//!   spawn/net/ioctl/mmap/open — the paths every real attack needs).
//! - Quarantine: reduce to SYS_EXIT and flip the state.
//!
//! Every applied response emits a `SecurityEvent` into the telemetry ring;
//! a full ring drops the event and counts it (never blocks, never panics).

use crate::domain::Domain;
use crate::monitor::{Response, Verdict};
use crate::ringbuf::RingBuffer;
use crate::syscall::SyscallMask;

/// Telemetry ring capacity (power of two, required by the ring buffer).
pub const TELEMETRY_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    Log,
    Tighten,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityEvent {
    pub domain_id: u32,
    pub score: u8,
    pub action: EventAction,
}

impl Default for SecurityEvent {
    fn default() -> Self {
        SecurityEvent {
            domain_id: 0,
            score: 0,
            action: EventAction::Log,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Logged,
    /// The domain's mask after tightening.
    Tightened(SyscallMask),
    Quarantined,
}

/// Apply a monitor verdict to a domain and record the telemetry event.
/// Returns the concrete outcome for callers/tests to assert on.
pub fn apply_response(
    domain: &mut Domain,
    verdict: &Verdict,
    telemetry: &mut RingBuffer<SecurityEvent, TELEMETRY_CAPACITY>,
) -> Outcome {
    let action = match verdict.response {
        Response::Log => EventAction::Log,
        Response::Tighten => {
            // F8: the degraded surface is per-profile (strict subset of
            // the domain's own surface, EXIT always kept, core function
            // alive) — the old single global mask gutted driver and netd
            // and did nothing to plugin.
            let degraded = domain.profile.degraded_syscalls;
            domain.tighten(&degraded);
            EventAction::Tighten
        }
        Response::Quarantine => {
            domain.quarantine();
            EventAction::Quarantine
        }
    };
    // Full ring: drop and count — the fast path is never blocked by logging.
    let _ = telemetry.push(SecurityEvent {
        domain_id: domain.id,
        score: verdict.score,
        action,
    });
    match action {
        EventAction::Log => Outcome::Logged,
        EventAction::Tighten => Outcome::Tightened(domain.mask()),
        EventAction::Quarantine => Outcome::Quarantined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainState;
    use crate::monitor::Verdict as V;
    use crate::profile::{parser_profile, service_profile};
    use crate::syscall::{SYS_DEVREG, SYS_EXIT, SYS_NET_SEND, SYS_OPEN, SYS_READ};

    fn ring() -> RingBuffer<SecurityEvent, TELEMETRY_CAPACITY> {
        RingBuffer::new().unwrap()
    }

    #[test]
    fn tighten_applies_the_profile_degraded_surface() {
        // The per-profile table test lives in profile.rs; here we pin
        // the apply path for one representative of each shape.
        let mut d = Domain::new(5, crate::profile::driver_profile());
        let mut r = ring();
        let out = apply_response(
            &mut d,
            &V {
                score: 60,
                response: Response::Tighten,
            },
            &mut r,
        );
        match out {
            Outcome::Tightened(m) => {
                // v2: a tightened driver LOSES its channel by design —
                // a stopped driver, the same containment the device
                // core's refusal ladder enforces from its side — and
                // keeps the exit path (the profile's contract).
                assert!(
                    !m.is_allowed(SYS_DEVREG).unwrap(),
                    "driver: Tighten stops the channel"
                );
                assert!(m.is_allowed(SYS_EXIT).unwrap(), "exit stays reachable");
            }
            other => panic!("expected Tightened, got {:?}", other),
        }
    }

    #[test]
    fn log_response_leaves_domain_untouched() {
        let mut d = Domain::new(1, service_profile());
        let before = d.mask();
        let mut r = ring();
        let out = apply_response(
            &mut d,
            &V {
                score: 10,
                response: Response::Log,
            },
            &mut r,
        );
        assert_eq!(out, Outcome::Logged);
        assert_eq!(d.state(), DomainState::Running);
        assert_eq!(d.mask(), before);
        let ev = r.pop().unwrap();
        assert_eq!(
            ev,
            SecurityEvent {
                domain_id: 1,
                score: 10,
                action: EventAction::Log
            }
        );
    }

    #[test]
    fn tighten_narrows_monotonically_and_idempotently() {
        let mut d = Domain::new(2, service_profile());
        let mut r = ring();
        let before = d.mask();

        let out1 = apply_response(
            &mut d,
            &V {
                score: 60,
                response: Response::Tighten,
            },
            &mut r,
        );
        let m1 = match out1 {
            Outcome::Tightened(m) => m,
            other => panic!("expected Tightened, got {:?}", other),
        };
        assert!(m1.is_subset_of(&before));
        assert!(!m1.is_allowed(SYS_NET_SEND).unwrap() || !before.is_allowed(SYS_NET_SEND).unwrap());
        assert!(!m1.is_allowed(SYS_OPEN).unwrap());
        assert!(m1.is_allowed(SYS_READ).unwrap());
        assert_eq!(d.state(), DomainState::Tightened);

        // Tighten again: idempotent, never widens back.
        let out2 = apply_response(
            &mut d,
            &V {
                score: 65,
                response: Response::Tighten,
            },
            &mut r,
        );
        let m2 = match out2 {
            Outcome::Tightened(m) => m,
            other => panic!("expected Tightened, got {:?}", other),
        };
        assert_eq!(m1, m2);
        assert!(m2.is_subset_of(&before));
    }

    #[test]
    fn quarantine_cuts_to_exit_only() {
        let mut d = Domain::new(3, parser_profile());
        let mut r = ring();
        let out = apply_response(
            &mut d,
            &V {
                score: 90,
                response: Response::Quarantine,
            },
            &mut r,
        );
        assert_eq!(out, Outcome::Quarantined);
        assert_eq!(d.state(), DomainState::Quarantined);
        assert!(d.request_syscall(crate::syscall::SYS_READ).is_denied());
        assert_eq!(
            d.request_syscall(crate::syscall::SYS_EXIT),
            crate::domain::Decision::Allowed
        );
        let ev = r.pop().unwrap();
        assert_eq!(ev.action, EventAction::Quarantine);
        assert_eq!(ev.score, 90);
    }

    #[test]
    fn telemetry_overflow_never_panics_and_counts_drops() {
        let mut d = Domain::new(4, service_profile());
        let mut r = ring();
        // Fill the 16-slot ring and keep applying: drops counted, no panic.
        for i in 0..20u8 {
            let v = V {
                score: i,
                response: Response::Log,
            };
            let out = apply_response(&mut d, &v, &mut r);
            assert_eq!(out, Outcome::Logged);
        }
        assert_eq!(r.dropped(), 4);
        assert!(r.is_full());
        // The first 16 events are intact, in order.
        for i in 0..16u8 {
            let ev = r.pop().unwrap();
            assert_eq!(ev.score, i);
        }
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn events_record_domain_id_and_action_correctly() {
        let mut d1 = Domain::new(11, service_profile());
        let mut d2 = Domain::new(22, parser_profile());
        let mut r = ring();
        apply_response(
            &mut d1,
            &V {
                score: 30,
                response: Response::Tighten,
            },
            &mut r,
        );
        apply_response(
            &mut d2,
            &V {
                score: 95,
                response: Response::Quarantine,
            },
            &mut r,
        );
        // FIFO: d1's event was pushed first, so it pops first.
        let ev1 = r.pop().unwrap();
        let ev2 = r.pop().unwrap();
        assert_eq!(ev1.domain_id, 11);
        assert_eq!(ev1.action, EventAction::Tighten);
        assert_eq!(ev2.domain_id, 22);
        assert_eq!(ev2.action, EventAction::Quarantine);
    }
}
