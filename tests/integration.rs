//! End-to-end scenario tests against the public `Kernel` API.
//!
//! These exercise the *whole* pipeline: profile -> domain -> fast-path
//! dispatch -> per-window audit -> graduated response -> telemetry,
//! including the deliberate invariants of the design (attenuation-only
//! surfaces, quarantine terminality, neighbor isolation).

use aegis_os::prelude::*;

/// A busy but legitimate parser: many reads, nothing out of profile.
/// It must stay `Running` forever.
#[test]
fn benign_parser_is_never_escalated() {
    let mut k = Kernel::new();
    k.create_domain(1, parser_profile()).unwrap();

    for window in 0..10 {
        for _ in 0..200 {
            assert_eq!(k.dispatch(1, SYS_READ).unwrap(), Decision::Allowed);
        }
        let v = k.audit(1).unwrap();
        assert_eq!(v.response, Response::Log, "window {}", window);
        assert!(v.score < 45, "busy-but-clean parser stays low: {}", v.score);
        assert_eq!(k.domain_state(1), Some(DomainState::Running));
    }
    // Surface untouched.
    assert_eq!(k.domain_mask(1), Some(parser_profile().syscalls));
}

/// The headline scenario: a parser domain that starts probing network
/// syscalls, faulting and attempting escalation.
///
/// Window-by-window (parser sensitivity 70 -> tighten@28, quarantine@58,
/// hysteresis 2; per-window counters reset at each audit):
///   W1 score 55 -> Log          (first bad window only logs)
///   W2 score 50 -> Tighten      (2nd consecutive bad window)
///   W3 score 37 -> Tighten      (still >= tighten threshold after tighten)
///   W4 score 80 -> Tighten      (quarantine streak 1, re-tightens)
///   W5 score 80 -> Quarantine   (2 consecutive quarantine-level windows)
#[test]
fn escalating_parser_is_tightened_then_quarantined() {
    let mut k = Kernel::new();
    k.create_domain(1, parser_profile()).unwrap();
    k.create_domain(2, service_profile()).unwrap();

    // -- W1: denied network probes + faults + escalation attempts.
    for _ in 0..10 {
        assert_eq!(
            k.dispatch(1, SYS_NET_SEND).unwrap(),
            Decision::DeniedByMask(SYS_NET_SEND)
        );
    }
    for _ in 0..3 {
        k.report_fault(1).unwrap();
    }
    for _ in 0..2 {
        k.report_escalation_attempt(1).unwrap();
    }
    let v1 = k.audit(1).unwrap();
    assert_eq!((v1.score, v1.response), (55, Response::Log));
    assert_eq!(k.domain_state(1), Some(DomainState::Running));

    // -- W2: keeps misbehaving, worse.
    for _ in 0..4 {
        assert_eq!(
            k.dispatch(1, SYS_NET_SEND).unwrap(),
            Decision::DeniedByMask(SYS_NET_SEND)
        );
    }
    for _ in 0..2 {
        k.report_fault(1).unwrap();
    }
    for _ in 0..2 {
        k.report_escalation_attempt(1).unwrap();
    }
    let v2 = k.audit(1).unwrap();
    assert_eq!((v2.score, v2.response), (50, Response::Tighten));
    assert_eq!(k.domain_state(1), Some(DomainState::Tightened));
    // The tightened surface actually removed the dangerous syscalls.
    let mask = k.domain_mask(1).unwrap();
    assert!(!mask.is_allowed(SYS_MMAP).unwrap(), "MMAP dropped by tighten");
    assert!(mask.is_allowed(SYS_READ).unwrap(), "READ survives tighten");
    assert!(mask.is_subset_of(&parser_profile().syscalls));

    // -- W3: probes the surface it just lost (MMAP now denied by mask).
    for _ in 0..6 {
        assert_eq!(
            k.dispatch(1, SYS_MMAP).unwrap(),
            Decision::DeniedByMask(SYS_MMAP)
        );
    }
    for _ in 0..3 {
        k.report_fault(1).unwrap();
    }
    let v3 = k.audit(1).unwrap();
    assert_eq!((v3.score, v3.response), (37, Response::Tighten));
    assert_eq!(k.domain_state(1), Some(DomainState::Tightened));

    // -- W4: full attack pattern: spawn probes, network probes, faults, escalation.
    for _ in 0..10 {
        assert_eq!(
            k.dispatch(1, SYS_SPAWN).unwrap(),
            Decision::DeniedByMask(SYS_SPAWN)
        );
        assert_eq!(
            k.dispatch(1, SYS_NET_SEND).unwrap(),
            Decision::DeniedByMask(SYS_NET_SEND)
        );
    }
    for _ in 0..5 {
        k.report_fault(1).unwrap();
    }
    for _ in 0..4 {
        k.report_escalation_attempt(1).unwrap();
    }
    let v4 = k.audit(1).unwrap();
    assert_eq!((v4.score, v4.response), (80, Response::Tighten));

    // -- W5: same attack pattern, second consecutive window at 80.
    for _ in 0..10 {
        let _ = k.dispatch(1, SYS_SPAWN);
        let _ = k.dispatch(1, SYS_NET_SEND);
    }
    for _ in 0..5 {
        k.report_fault(1).unwrap();
    }
    for _ in 0..4 {
        k.report_escalation_attempt(1).unwrap();
    }
    let v5 = k.audit(1).unwrap();
    assert_eq!((v5.score, v5.response), (80, Response::Quarantine));
    assert_eq!(k.domain_state(1), Some(DomainState::Quarantined));

    // Quarantine is terminal: everything but EXIT is denied, and no
    // response can ever widen the mask again.
    assert_eq!(
        k.dispatch(1, SYS_READ).unwrap(),
        Decision::DeniedQuarantined(SYS_READ)
    );
    assert_eq!(k.dispatch(1, SYS_EXIT).unwrap(), Decision::Allowed);
    let v6 = k.audit(1).unwrap();
    assert_eq!(v6.response, Response::Quarantine, "sticky");
    assert_eq!(k.domain_state(1), Some(DomainState::Quarantined));
}

/// A quarantined neighbor must not affect a healthy service domain.
#[test]
fn quarantine_is_isolated_per_domain() {
    let mut k = Kernel::new();
    k.create_domain(1, parser_profile()).unwrap();
    k.create_domain(2, service_profile()).unwrap();

    // Drive domain 1 straight to instant-quarantine levels:
    // 4 out-of-profile syscall classes, total 2x baseline, maxed faults/esc.
    for _ in 0..64 {
        let _ = k.dispatch(1, SYS_SPAWN);
        let _ = k.dispatch(1, SYS_NET_SEND);
        let _ = k.dispatch(1, SYS_WRITE);
        let _ = k.dispatch(1, SYS_OPEN);
    }
    for _ in 0..8 {
        k.report_fault(1).unwrap();
        k.report_escalation_attempt(1).unwrap();
    }
    let v = k.audit(1).unwrap();
    assert_eq!(v.response, Response::Quarantine, "score {}", v.score);

    // The service domain keeps working through the entire incident.
    for syscall in [SYS_READ, SYS_WRITE, SYS_OPEN, SYS_CLOSE, SYS_IPC_SEND, SYS_IPC_RECV] {
        assert_eq!(k.dispatch(2, syscall).unwrap(), Decision::Allowed);
    }
    let v2 = k.audit(2).unwrap();
    assert_eq!(v2.response, Response::Log);
    assert_eq!(v2.score, 0);
    assert_eq!(k.domain_state(2), Some(DomainState::Running));
    assert_eq!(k.domain_mask(2), Some(service_profile().syscalls));
}

/// The telemetry ring must contain the full escalation timeline in order.
#[test]
fn telemetry_records_the_timeline() {
    let mut k = Kernel::new();
    k.create_domain(1, parser_profile()).unwrap();

    // Two bad windows -> Tighten; two worse -> Quarantine.
    for _ in 0..2 {
        for _ in 0..5 {
            let _ = k.dispatch(1, SYS_NET_SEND);
        }
        k.report_fault(1).unwrap();
        k.report_escalation_attempt(1).unwrap();
        let _ = k.audit(1).unwrap();
    }
    assert_eq!(k.domain_state(1), Some(DomainState::Tightened));
    for _ in 0..2 {
        for _ in 0..10 {
            let _ = k.dispatch(1, SYS_SPAWN);
            let _ = k.dispatch(1, SYS_NET_SEND);
        }
        for _ in 0..5 {
            k.report_fault(1).unwrap();
            k.report_escalation_attempt(1).unwrap();
        }
        let _ = k.audit(1).unwrap();
    }
    assert_eq!(k.domain_state(1), Some(DomainState::Quarantined));

    let mut actions = Vec::new();
    while let Some(ev) = k.pop_event() {
        assert_eq!(ev.domain_id, 1);
        actions.push(ev.action);
    }
    assert_eq!(
        actions,
        vec![
            EventAction::Log,
            EventAction::Tighten,
            EventAction::Tighten,
            EventAction::Quarantine
        ]
    );
}

/// Direct domain-level checks that the memory and capability policies hold
/// for real domain objects built from profiles.
#[test]
fn domain_memory_policy_and_capabilities() {
    let mut d = Domain::new(1, parser_profile());

    // Quota comes from the profile (64 pages).
    assert_eq!(d.space.quota_pages(), 64);
    d.space.map(0x10000, 16 * PAGE_SIZE, MemFlags::READ).unwrap();
    assert_eq!(d.space.used_pages(), 16);
    // W^X holds for domains too.
    assert_eq!(
        d.space.map(0x30000, PAGE_SIZE, MemFlags(0b0110)),
        Err(MemError::WxViolation)
    );
    // Quota exceeded.
    assert_eq!(
        d.space.map(0x50000, 49 * PAGE_SIZE, MemFlags::READ),
        Err(MemError::QuotaExceeded)
    );
    // Exact remaining quota fits.
    d.space.map(0x50000, 48 * PAGE_SIZE, MemFlags::READ).unwrap();
    assert_eq!(d.space.used_pages(), 64);

    // Capability: driver-style grant + attenuation, escalation rejected.
    let mut drv = Domain::new(2, driver_profile());
    let h = drv
        .caps
        .insert(Capability {
            resource: Resource::Device(9),
            rights: Rights::READ | Rights::WRITE | Rights::GRANT,
            generation: 0,
        })
        .unwrap();
    let child = drv.caps.attenuate(h, Rights::READ).unwrap();
    assert_eq!(
        drv.caps.attenuate(h, Rights::READ | Rights::EXEC),
        Err(CapError::Escalation)
    );
    assert!(child.rights.is_subset_of(Rights::READ | Rights::WRITE));
}

/// Kernel error surface + fast-path edge cases over the public API.
#[test]
fn kernel_error_surface() {
    let mut k = Kernel::new();
    k.create_domain(1, plugin_profile()).unwrap();
    assert_eq!(
        k.create_domain(1, plugin_profile()),
        Err(KernelError::DuplicateDomain(1))
    );
    assert_eq!(k.dispatch(9, SYS_READ), Err(KernelError::UnknownDomain(9)));
    // Out-of-range syscall id: BadSyscall, no counter side effects.
    assert_eq!(
        k.dispatch(1, SYSCALL_COUNT).unwrap(),
        Decision::BadSyscall(SYSCALL_COUNT)
    );
    // Plugin cannot touch the file system at all.
    assert_eq!(
        k.dispatch(1, SYS_OPEN).unwrap(),
        Decision::DeniedByMask(SYS_OPEN)
    );
}
