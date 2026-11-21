//! ADR-0023 sleep/wake/yield tests, through the public `Kernel` API and
//! the real `Preemptor`. The core stays unit-agnostic: `tick(now)` and
//! `nanosleep` speak whatever time unit the kernel feeds (TSC today).

use aegis_os::preempt::Preemptor;
use aegis_os::prelude::*;

const SUPERVISOR: u32 = 0;
const A: u32 = 1;
const B: u32 = 2;

/// Two domains and NOTHING else registered: the kernel's own
/// discipline (every kernel-resident domain is destroyed before the
/// timer is armed — a CFS entity that never runs must never be
/// preemptor-picked) applies to yield picks exactly as to tick picks.
fn kernel_with_pair() -> Kernel {
    let mut k = Kernel::new();
    k.create_domain_with(A, service_profile(), 1001, 100, 0)
        .unwrap();
    k.create_domain_with(B, service_profile(), 1002, 100, 0)
        .unwrap();
    k
}

#[test]
fn nanosleep_marks_unrunnable_and_wakes_on_tick() {
    let mut k = kernel_with_pair();
    // A sleeps 100 cycles from now=1000 (wake at 1100).
    match k
        .syscall(
            A,
            SysRequest::Nanosleep {
                now: 1000,
                cycles: 100,
            },
        )
        .unwrap()
    {
        SysValue::Count(wake) => assert_eq!(wake as u64, 1100),
        other => panic!("expected the wake deadline, got {other:?}"),
    }
    assert!(
        !k.sched.entity(A).unwrap().runnable,
        "the sleeper left the run queue"
    );
    // A tick before the deadline: still asleep.
    k.tick(1099);
    assert!(!k.sched.entity(A).unwrap().runnable);
    // The deadline tick wakes it.
    k.tick(1100);
    assert!(
        k.sched.entity(A).unwrap().runnable,
        "wake lands at the deadline"
    );
    // And exactly once.
    k.tick(1101);
    assert_eq!(
        k.sleeping(A),
        None,
        "the sleep entry is gone after the wake"
    );
}

#[test]
fn nanosleep_zero_is_a_plain_yield() {
    let mut k = kernel_with_pair();
    match k
        .syscall(
            A,
            SysRequest::Nanosleep {
                now: 500,
                cycles: 0,
            },
        )
        .unwrap()
    {
        SysValue::Count(wake) => assert_eq!(wake as u64, 500, "zero sleep wakes immediately"),
        other => panic!("expected a count, got {other:?}"),
    }
    assert!(
        k.sched.entity(A).unwrap().runnable,
        "no sleep entry was made"
    );
    assert_eq!(k.sleeping(A), None);
}

#[test]
fn a_second_sleep_replaces_the_first() {
    let mut k = kernel_with_pair();
    k.syscall(
        A,
        SysRequest::Nanosleep {
            now: 100,
            cycles: 50,
        },
    )
    .unwrap();
    match k
        .syscall(
            A,
            SysRequest::Nanosleep {
                now: 120,
                cycles: 500,
            },
        )
        .unwrap()
    {
        SysValue::Count(wake) => assert_eq!(wake as u64, 620),
        other => panic!("expected a count, got {other:?}"),
    }
    // The FIRST deadline (150) must not wake it.
    k.tick(150);
    assert!(!k.sched.entity(A).unwrap().runnable);
    k.tick(620);
    assert!(k.sched.entity(A).unwrap().runnable);
}

#[test]
fn a_woken_sleeper_gets_the_vruntime_floor() {
    let mut k = kernel_with_pair();
    // Charge B heavily so min_vruntime advances far past A's.
    for _ in 0..10 {
        let _ = k.sched.tick(B, 100);
    }
    let floor = k.sched.entity(B).unwrap().vruntime;
    k.syscall(
        A,
        SysRequest::Nanosleep {
            now: 0,
            cycles: 1000,
        },
    )
    .unwrap();
    k.tick(1000);
    let woke = k.sched.entity(A).unwrap();
    assert!(
        woke.vruntime >= floor,
        "a sleeper cannot wake at the front of the line"
    );
}

#[test]
fn sleepers_due_gives_the_idle_deadline() {
    let mut k = kernel_with_pair();
    assert_eq!(k.sleepers_due(0), None, "no sleepers yet");
    k.syscall(
        A,
        SysRequest::Nanosleep {
            now: 0,
            cycles: 300,
        },
    )
    .unwrap();
    k.syscall(
        B,
        SysRequest::Nanosleep {
            now: 0,
            cycles: 100,
        },
    )
    .unwrap();
    assert_eq!(k.sleepers_due(50), Some(100), "the earliest deadline wins");
    k.tick(100); // B due, A still asleep
    assert_eq!(k.sleepers_due(100), Some(300));
    k.tick(300);
    assert_eq!(k.sleepers_due(400), None);
}

#[test]
fn exiting_a_sleeper_cancels_its_sleep() {
    let mut k = kernel_with_pair();
    k.syscall(
        A,
        SysRequest::Nanosleep {
            now: 0,
            cycles: 500,
        },
    )
    .unwrap();
    assert!(k.sleeping(A).is_some());
    k.exit_process(A, ExitStatus::normal(0)).unwrap();
    assert_eq!(k.sleeping(A), None, "exit cancels the sleep entry");
    assert!(k.sched.entity(A).is_none(), "scheduler unregistered");
    // The wake later must not resurrect anything.
    k.tick(1000);
    assert!(k.domain(A).is_none());
}

#[test]
fn yield_charges_the_slice_and_hands_the_cpu_over() {
    let p = Preemptor::new(1);
    let mut k = kernel_with_pair();
    let mut sched = core::mem::take(&mut k.sched);
    let _ = &k;
    // Both runnable; A yields: B is the pick.
    assert_eq!(p.on_yield(&mut sched, A), Some(B));
    // Yielding does not buy priority: A's vruntime grew by the slice.
    let a_vr = sched.entity(A).unwrap().vruntime;
    assert!(a_vr > 0);
    // A solo yielder keeps the CPU (no other runnable domain).
    let _ = sched.set_runnable(B, false);
    assert_eq!(p.on_yield(&mut sched, A), None);
}

#[test]
fn yield_loops_earn_no_priority() {
    let p = Preemptor::new(1);
    let mut s = aegis_os::sched::Scheduler::new();
    s.register(A, 0).unwrap();
    s.register(B, 0).unwrap();
    let mut switches = 0u32;
    let mut current = A;
    for _ in 0..100 {
        if let Some(next) = p.on_yield(&mut s, current) {
            current = next;
            switches += 1;
        }
    }
    // 100 yields with both runnable must alternate (not keep A): the
    // yielding domain is charged exactly like a preempted one.
    assert!(switches >= 45, "yield must rotate (got {switches})");
    let (va, vb) = (s.entity(A).unwrap().vruntime, s.entity(B).unwrap().vruntime);
    let (sa, sb) = (s.entity(A).unwrap().slices, s.entity(B).unwrap().slices);
    assert!(
        va.max(vb) - va.min(vb) <= 2,
        "vruntimes stay within one slice: {va} vs {vb}"
    );
    assert!(sa >= 30 && sb >= 30, "both actually ran: slices {sa}/{sb}");
}

// ── the deterministic random wake/sleep/exit simulation ───────────────

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

#[test]
fn random_sleep_wake_exit_sequences_never_lose_a_wakeup() {
    let mut k = Kernel::new();
    k.create_domain_with(SUPERVISOR, service_profile(), 0, 0, 0)
        .unwrap();
    let mut live: Vec<u32> = Vec::new();
    for id in 1..=8u32 {
        k.create_domain_with(id, service_profile(), 1000 + id as u16, 100, 0)
            .unwrap();
        live.push(id);
    }

    let mut rng = Rng(0x5EED_0123);
    let mut now: u64 = 1_000_000;
    let mut deadline_log: Vec<(u32, u64)> = Vec::new();

    for _ in 0..600 {
        now += rng.below(50);
        // The timer fires as time passes — model it: a deadline can
        // never be "passed but unticked".
        k.tick(now);
        match rng.below(5) {
            0 | 1 => {
                // A live domain sleeps a random span.
                if live.is_empty() {
                    continue;
                }
                let id = live[rng.below(live.len() as u64) as usize];
                let cycles = 1 + rng.below(400);
                if let Ok(SysValue::Count(wake)) =
                    k.syscall(id, SysRequest::Nanosleep { now, cycles })
                {
                    // A second sleep replaces the first: forget any
                    // earlier log line for this domain.
                    deadline_log.retain(|(d, _)| *d != id);
                    deadline_log.push((id, wake as u64));
                }
            }
            2 => {
                // Extra ticks at the same instant (the wake pass is
                // idempotent — double ticks must not double-wake).
                for _ in 0..1 + rng.below(3) {
                    k.tick(now);
                }
            }
            3 => {
                // A random domain exits (cancelling any sleep).
                if live.len() > 2 {
                    let idx = rng.below(live.len() as u64) as usize;
                    let id = live.swap_remove(idx);
                    k.exit_process(id, ExitStatus::normal(0)).unwrap();
                    deadline_log.retain(|(d, _)| *d != id);
                }
            }
            _ => {
                // Drain everything due at once.
                k.tick(now);
                k.tick(now + 1);
            }
        }
        // Invariant: every logged deadline at or before `now` has been
        // honored — no lost wakeup. (tick(now) ran this iteration or the
        // deadline is still in the future.)
        let due: Vec<u32> = deadline_log
            .iter()
            .filter(|(_, at)| *at <= now)
            .map(|(d, _)| *d)
            .collect();
        for id in due {
            if k.domain(id).is_some() {
                assert!(
                    k.sched.entity(id).is_none_or(|e| e.runnable),
                    "domain {id} slept until a deadline <= {now} and never woke"
                );
                deadline_log.retain(|(d, _)| *d != id);
            }
        }
    }

    // Teardown: exit everyone, drain time — nothing left sleeping and no
    // sleeper remains in the scheduler.
    for id in live {
        let _ = k.exit_process(id, ExitStatus::normal(0));
    }
    k.tick(now + 10_000);
    for slot in 1..=8u32 {
        assert_eq!(
            k.sleeping(slot),
            None,
            "slot {slot} still sleeping after teardown"
        );
    }
    assert_eq!(k.live_domain_count(), 1, "only the supervisor remains");
}
