# ADR-0023: Preemptive ring-3 multitasking — the run queue, sleep, the clock, and signal frames

- **Status:** Accepted (M3 Phase 2; landing in slices, each with its own red-then-green proof)
- **Stage:** M3 → the process track (ADR-0022's lifecycle becomes concurrent)
- **Date:** 2026-11-21

## Context

ADR-0012 (M2-W2) built the preemption *machinery*: the LAPIC timer at
vector 48, the pure `Preemptor` decision layer over the real CFS
scheduler, and the interrupt-frame-rewrite context switch between
**parked** ring-3 runs. What it deliberately left gated and incomplete
is everything M3 actually needs:

- The proof (spinner vs writer) lives behind the `preempt-demo`
  feature gate — the default lanes never run it.
- `PARKED` holds 4 runs; `MAX_DOMAINS` is now 32 (ADR-0022).
- Nothing sleeps: a run is either on the CPU or parked-runnable.
  `nanosleep`, `sched_yield` and `clock_gettime` do not exist, and the
  kernel has no idle path — a tick arriving at CPL0 is treated as a
  kernel bug and halts.
- The tick interval is the 25M-TSC fallback; `set_tick_interval`
  exists with **no caller** (the HPET counter is live in the driver
  stack but nobody calibrates from it).
- Signals are policy-core state only (pending/blocked sets, kill
  delivery, Terminate = the monitor's quarantine-cut). No ring-3
  process has ever received one: no `rt_sigaction`, no signal frame,
  no `rt_sigreturn`, no trampoline.

This ADR decides how those close — single CPU, `kernel_mut()`'s
single-CPU assumptions intact (SMP is ADR-0028's business).

## Decision

### D1 — One time base, injected: the core stays unit-agnostic

`Kernel::tick(now)` already takes an abstract `now` (the kernel feeds
TSC today). The sleep queue stores wake deadlines in **the same units
the caller feeds `tick`** — the policy core never learns what a TSC
is. `tick(now)` gains a wake pass that runs on EVERY call (today it
early-returns when the monitor window does not change; audits stay
window-gated, wakes do not).

### D2 — Sleep is scheduler-unrunnable plus a deadline

`Kernel::nanosleep(domain, cycles)`: `set_runnable(domain, false)` +
a deadline entry in a fixed `[(domain, wake_at); MAX_DOMAINS]` table.
`Kernel::wake_due(now)` (called from `tick`) moves due sleepers back
to runnable **through the scheduler's wake path** — the min_vruntime
floor for wakers already exists (a long sleeper must not starve
others on wake; a freshly-woken sleeper must not monopolize either).
Overflow-checked deadline math; a zero/negative sleep is a plain
yield. `Kernel::sleepers_due(now)` gives the kernel side the "how
long may I idle" answer (the earliest deadline), which is exactly
what the idle loop needs.

### D3 — Yield is a decision, not a queue shuffle

`Preemptor::on_yield(sched, current) -> Option<u32>`: the current
domain volunteers the rest of its slice. If another domain is the
fair pick, the kernel parks and switches exactly as the tick path
does; `None` means "you are still the pick, just return". The current
domain's vruntime is charged the full slice (volunteering must not
buy priority — that is the CFS contract; a yield-loops-forever domain
earns nothing but its own spin).

### D4 — clock_gettime is kernel-side math over the calibrated TSC

The kernel keeps one static `TSC_HZ` (u64) calibrated at boot (D5).
`clock_gettime(CLOCK_MONOTONIC|CLOCK_REALTIME)`: `ns = tsc * 1e9 /
tsc_hz` in u128, copied out through the existing copy-out machinery
(a 16-byte `struct timespec` {sec, nsec}, byte-exact, user pointer
validated once). CLOCK_REALTIME equals CLOCK_MONOTONIC (no RTC
wiring yet — documented, not faked). Other clock ids: `-EINVAL`.

### D5 — The HPET calibrates the TSC once, at boot

The driver stack's HPET block is live (100 MHz counter). Boot-time
calibration: sample (tsc0, hpet0), wait a bounded HPET delta (≈10 ms,
by polling the HPET main counter — the boot is single-threaded here,
IF=0, no interference), sample (tsc1, hpet1);
`tsc_hz = tsc_delta * 100_000_000 / hpet_delta` (u128 math, a zero
delta refuses and keeps the 25M fallback — fail-closed to the known
cadence, never to a divide-by-zero). The result feeds
`preempt::set_tick_interval(tsc_hz / 100)` (10 ms tick) and the
`TSC_HZ` static for D4. The boot log prints the measured frequency —
the log never claims an unmeasured number.

### D6 — The proof leaves the feature gate; the run queue grows

- `PARKED` grows to `MAX_DOMAINS` (32): the parked table IS the run
  queue's storage; every runnable-but-not-running domain has exactly
  one entry, the running one is `USER_RUN` — the invariant the tick
  path's loud halt already enforces ("registered but not parked" is a
  bookkeeping bug, and it stays one).
- The ADR-0012 two-run proof (spinner 20 / writer 21) moves into the
  DEFAULT boot flow — ungated, with the named-static argument passing
  (the release+LTO workaround already in place) — and gains the M3
  marker `[M3] preempt: 2 runs interleaved (switches=N), hog starved
  nobody` which `boot.sh --verify*` greps (all three lanes; the grep
  and the marker land in the same commit, per the marker rule). The
  proof's criterion stays ADR-0012's: the writer's four writes all
  land while the spinner is still runnable, the spinner's no-syscall
  monopoly is broken by the timer alone, and both exits are clean.
- The `preempt-demo` feature flag dies; its cfg-gates go with it.

### D7 — Idle: an explicit, guarded quiescent state

Today a CPL0 timer frame halts ("the kernel is never preempted" —
true for kernel WORK). Idle is not work: kmain, with every remaining
run asleep and none runnable, enters the idle state — set
`percpu::IDLE`, `sti`, `hlt`, on wake `cli`, clear `IDLE`, and check
the scheduler. The tick handler's CPL0 guard gains exactly one
carve-out: a CPL0 frame with `IDLE` set is the idle loop being
ticked — acknowledge, re-arm, `k.tick(now)` (wakes happen there),
and return; the hlt resumes into kmain's loop, which finds the woken
run and resumes it through the parked handover. No other CPL0 tick
is ever legal (the carve-out is one flag, checked after the halt
message's conditions, before it). The ADR-0019 bounded windows
(pause_ticks/resume_ticks) keep their discipline: they never overlap
idle (idle is entered only with all windows closed).

### D8 — Signal frames: pure construction, pure validation, one trampoline

- **Pure, in the policy core** (`src/sigframe.rs`): the frame layout
  (saved `rip/cs/rflags/rsp/ss` + signum + a kernel-chosen cookie +
  the restorer slot), `SignalFrame::build(handler, ctx, signum,
  cookie)` producing the exact bytes to push, and
  `SignalFrame::validate(bytes, cookie)` for `rt_sigreturn`: every
  field re-checked — the cookie match (a forged or displaced frame
  refuses), `cs|3`, `ss|3`, user-range `rip`/`rsp`, canonical
  addresses, `rflags` with reserved bits masked and IOPL/IF forced
  sane, alignment. Host-tested plus a fuzz corpus of corrupted
  frames (bit flips, truncated, all-forged) — never panic, always a
  typed error.
- **Trampoline**: one page mapped RX into every user address space at
  a fixed VA (outside every blob's link range), containing
  `mov eax, __NR_rt_sigreturn; syscall; ud2`. `rt_sigreturn` is the
  ONLY syscall whose frame the kernel rebuilds state from, and it
  rebuilds it EXCLUSIVELY from validated fields — never from the
  unvalidated stack below the frame pointer.
- **Delivery**: one choke point — `deliver_pending(run, domain)` is
  called on the kernel→user boundary (the syscall return path and the
  unpark path): if the domain has a pending, unblocked, caught
  signal, the frame is built onto the USER stack (red-zone-safe,
  16-byte-aligned, the guard page checked — a handler with a blown
  stack faults into the normal fault path, not into the kernel), and
  the run's `rip` becomes the handler with `rdi = signum`. Uncaught
  signals keep today's semantics (Terminate = the monitor's cut —
  unchanged). SIGKILL/SIGSTOP are never catchable, never blocked
  (existing core invariants).
- **Registration**: `rt_sigaction(signum, handler, restorer, flags)`
  — a core executor storing the handler in the domain's signal state
  (host-tested: unknown signums, SIGKILL/SIGSTOP refusals, the
  unregistered default). No signal mask syscalls in this round
  (SIG_BLOCK etc. — ROADMAP; blocked sets exist in the core already,
  the ABI for changing them is Phase 5+).

### D9 — What is explicitly NOT here

- SMP, per-CPU run queues, TLB shootdowns (ADR-0028).
- Priority inheritance, realtime classes, timers/timerfd, alarm.
- A wait queue abstraction ( sleeps are the only waiter class; the
  fixed table is bounded by MAX_DOMAINS).
- exec/fork integration with sleep (a sleeping process's fork/exit
  bookkeeping is exercised in Phase 3+'s lifecycle fuzz, not here).

## Testing plan

- Pure (host): sleep-queue unit tests (deadline order, overflow,
  duplicate sleeps, wake-all-on-exit conservation); `on_yield`
  (no-priority-gain, solo-keeps); `tick`-driven wake simulation; the
  deterministic random wake/sleep/exit simulation (xorshift, fixed
  seed — no panic, conservation, no lost wakeups, a sleeper always
  wakes within one tick of its deadline); the sigframe build/
  validate suite + corrupted-frame fuzz; sigaction executor tests.
- Kernel lanes: the ungated preempt proof marker on all three lanes;
  `[M3] sleep:` — a blob that sleeps and is woken while a second runs
  (the wake must land); `[M3] clock:` — monotonic reads from ring 3
  are non-decreasing and non-zero; the signal lane: a blob registers
  a handler, gets SIGUSR1 from a sibling's kill, the handler runs,
  sigreturn resumes, exit is clean — plus the forged-frame refusal
  (a rogue frame → the process dies by the normal fault path, the
  kernel never trusts it).

## Consequences

- `Kernel` grows the sleep table (+8 bytes × 32) and
  `Domain.signals` grows handler slots (signum → handler+restorer,
  fixed 64-entry table keyed by signum ≤ 63).
- The tick handler's CPL0 halt gains the single IDLE carve-out — the
  invariant becomes "CPL0 ticks are illegal EXCEPT the idle hlt",
  which the guard comment must keep stating precisely.
- `boot.sh` greps grow (same-commit rule); the lanes get slower by
  the proof's TCG seconds — measured, recorded in the lane output.
- The blob family grows (`ring3-sleep`, `ring3-signal`), built by the
  same boot.sh recipe.

**Open items** (ROADMAP): sigprocmask ABI, alternate signal stacks
(`sigaltstack`), SA_SIGINFO three-arg frames, timerfd/alarm, the
scheduler's group scheduling.
