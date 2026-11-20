//! The timer tick (M2-W2 / ADR-0012): what happens when the LAPIC
//! interrupt arrives — EOI, monitor windows, the preemptor's decision,
//! and (when the decision says so) the context switch itself.
//!
//! SAFETY POLICY: this module is part of the `sched/` allowlist entry,
//! but it is **unsafe-free by design**: the frame rewrite, the parked
//! table, and the CR3/USER_RUN swap all live in `sched::context` (each
//! unsafe item carries its SAFETY note there). What remains here is
//! orchestration + counters.
//!
//! The split per ADR-0011 §D3: the *decision* is the host-tested policy
//! (`aegis_os::preempt::Preemptor`, driven against the real
//! `aegis_os::sched::Scheduler`); this module is the x86_64 hardware
//! half — which vector fires, how the register image travels, and what
//! an EOI is.
//!
//! Invariants:
//! - **The tick never touches GS.** It arrives from CPL3 (GS = the user
//!   value) and returns via the unwind's iretq without swapgs — nothing
//!   on this path may use `%gs:`-relative state or `percpu::get()` (the
//!   syscall entry's `swapgs` discipline does not apply here: the
//!   interrupt entry performs no swap of its own).
//! - **The kernel is never preempted.** CPL0 runs IF=0 (SYSCALL clears
//!   IF; no `sti` exists in the kernel), so a timer frame must be CPL3 —
//!   anything else is a kernel bug and halts loudly.
//! - **No nesting.** Interrupt gates mask IF on entry; the handler is
//!   strictly non-reentrant.

use crate::arch::frame::ExceptionFrame;
use crate::arch::lapic;
use crate::hw;
use crate::sched::context;
use crate::serial;
use crate::strutil;
use aegis_os::preempt::{Preemptor, TickDecision};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One timer tick in TSC cycles (TSC-deadline mode): ~10 ms at a
/// 2.5 GHz reference TSC. Only cadence — never correctness — depends
/// on this; the monitor windows carry their own clock.
pub const TICK_INTERVAL_TSC: u64 = 25_000_000;

/// The one preemptor: slice_ticks = 1 (one tick = one CFS slice
/// charge). Stateless over the real scheduler (`Kernel::sched`), so a
/// plain static — no unsafe to hold it.
static PREEMPTOR: Preemptor = Preemptor::new(1);

/// Ticks observed since the timer was armed.
static TICKS: AtomicU64 = AtomicU64::new(0);
/// Context switches performed by the tick path (park ↔ unpark).
static SWITCHES: AtomicU64 = AtomicU64::new(0);
/// Whether the LAPIC is in TSC-deadline mode (re-arm per tick) — set
/// once by `arm`.
static TSC_DEADLINE: AtomicBool = AtomicBool::new(false);

/// Bring the LAPIC up and arm the first tick. Called once from kmain,
/// after the ring-3 machinery is fully live and before the first
/// preemptible launch. Prints the mode line (the boot log must state
/// which timer mode the machine chose — the two are not equivalent
/// and adopters deserve to know which one they are on).
pub fn arm() {
    let tsc_deadline = lapic::init();
    TSC_DEADLINE.store(tsc_deadline, Ordering::SeqCst);
    if tsc_deadline {
        lapic::arm_deadline(hw::read_tsc() + TICK_INTERVAL_TSC);
        serial::write_str("[ARCH] lapic timer armed: mode=tsc-deadline vector=48\n");
    } else {
        // The fallback line is different ON PURPOSE: the periodic mode
        // is approximate (bus-clock derived), and the boot log must not
        // claim the deterministic mode when it is not active.
        serial::write_str("[ARCH] lapic timer armed: mode=periodic(div16) vector=48\n");
    }
}

/// The timer interrupt: called from the exception dispatch BEFORE any
/// fault handling (a timer frame from CPL3 would otherwise be mistaken
/// for the domain's death). Never returns early without arming the
/// next tick (TSC-deadline mode).
pub fn on_timer_tick(frame: &mut ExceptionFrame) {
    // Acknowledge first, re-arm first: the next deadline is a full
    // interval from now, so even a slow handler cannot livelock — the
    // worst case is prompt back-to-back ticks, bounded by handler cost.
    lapic::eoi();
    if TSC_DEADLINE.load(Ordering::SeqCst) {
        lapic::arm_deadline(hw::read_tsc() + TICK_INTERVAL_TSC);
    }

    // A tick can only interrupt CPL3: the kernel runs IF=0 (SYSCALL
    // clears IF; nothing in CPL0 ever does `sti`). A CPL0 timer frame
    // means the kernel got preempted — impossible by construction, so
    // halt loudly instead of switching stacks on a frame shape that
    // does not carry the CPL3 tail.
    if frame.cs & 3 != 3 {
        serial::write_str("[IRQ ] KERNEL BUG: timer tick from CPL0 — halting\n");
        hw::halt_forever();
    }

    TICKS.fetch_add(1, Ordering::SeqCst);

    // The monitor's windows close on tick — this is the exact line
    // that makes "quarantine one domain while others continue" real:
    // even a domain that never calls a syscall again cannot freeze the
    // window clock. Then the preemptor's decision, against the ONE
    // scheduler (`Kernel::sched`).
    let decision = {
        let Some(k) = context::kernel_mut() else {
            // No live kernel (host-test shape) — nothing to drive.
            return;
        };
        k.tick(hw::read_tsc());
        match context::active_domain() {
            Some(current) => PREEMPTOR.on_tick(&mut k.sched, current),
            // No active run (kmain between take and launch — the timer
            // was armed but nothing is on the CPU): nothing to preempt.
            None => return,
        }
    };

    match decision {
        TickDecision::Keep(_) => {} // the interrupt simply returns
        TickDecision::Switch(next) => {
            let current = match context::active_domain() {
                Some(id) => id,
                None => return, // raced an exit (single CPU: unreachable)
            };
            // Park the interrupted run from the frame, then install the
            // next one INTO the frame — the rewrite is the context
            // switch; CR3 + USER_RUN complete it.
            let (run, ctx) = context::park_from_frame(frame);
            context::stash_parked(run, ctx);
            match context::take_parked(next) {
                Some((next_run, next_ctx)) => {
                    context::unpark_into_frame(frame, &next_ctx);
                    // CR3 first (the kernel half is shared, so kernel
                    // code keeps running under either table), then the
                    // run state — from here on, USER_RUN is the domain
                    // the frame will iretq into.
                    next_run.tables.activate();
                    context::begin(next_run);
                    SWITCHES.fetch_add(1, Ordering::SeqCst);
                    let _ = current; // diagnostics only; see counters
                }
                None => {
                    // Registered in the scheduler but not parked: a
                    // bookkeeping bug (a kernel-resident domain leaked
                    // into the runnable set). Loud, never paper over.
                    let mut b = [0u8; 20];
                    serial::write_str("[SCHD] KERNEL BUG: preemptor picked unparked domain ");
                    serial::write_str(strutil::dec(next as u64, &mut b));
                    serial::write_str(" — halting\n");
                    hw::halt_forever();
                }
            }
        }
    }
}

/// Ticks observed since `arm` (kmain's summary line).
#[must_use]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::SeqCst)
}

/// Context switches performed by the tick path.
#[must_use]
pub fn switches() -> u64 {
    SWITCHES.load(Ordering::SeqCst)
}

/// A domain exited (SYS_EXIT or a fault): unregister it and name the
/// next runnable domain, if any (kmain's handover path).
pub fn on_exit(sched: &mut aegis_os::sched::Scheduler, exited: u32) -> Option<u32> {
    PREEMPTOR.on_exit(sched, exited)
}
