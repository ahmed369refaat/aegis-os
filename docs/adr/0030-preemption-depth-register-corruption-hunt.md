# ADR-0030: The preemption-depth register-corruption hunt — round X's "reproduction" was an artifact; round Y pinned the real bug it exposed (RESOLVED for the delta; the original flake remains OPEN)

## Status

**The round-X "reproduction on demand" was an instrument artifact —
round Y proved it and closed the real bug the artifact exposed: a
fragile hand-measured code delta in the ring3-preempt blob. The
ORIGINAL rare flake remains unexplained and OPEN — three shapes now
on record (the CoW-demo stall, the mode-13 wait4 loss, and the S5
session's CPL0-fault-in-grants) — with the tick-density lead
REFUTED.**

## The third shape (S5 session, 2026-11-23 — recorded, NOT a reproduction)

One occurrence in four boots of the `--verify-persist` lane (the
first run was 2/2 green; the second run's boot 2 died). Saved whole:
`boot-persist-FLAKE-cpl0fault-grants.txt` in the session bundle.

```
[M3] sync: 2 round-trips, call blocked and returned both replies, ...
[EXC] #PF vector=14 rip=0xffffffff8000063c cs=0x0030 err=0x0000000000000003 cr2=0x0000000000408ff8
[EXC] KERNEL BUG: CPL0 fault while a user run is active
```

The boot halted at that line (no verdict, no further output). Facts
that constrain any explanation:

- The fault is a SUPERVISOR WRITE (err=3, P=1 W=1 U/S=0) to a
  PRESENT USER page at `0x408ff8` — the grants demo's shared-page
  tail, an address the demo itself faults on from ring 3 as part of
  its normal flow (the green-probe log shows the same cr2 with
  err=7 at a user rip, handled).
- The printed rip is `syscall_entry`'s FIRST instruction (`swapgs`).
  swapgs cannot write memory, so either the frame was read from a
  stale/parked slot, or the run was parked-and-resumed at exactly
  that entry (the 3-byte `swapgs; cli` window is the one point where
  an IRQ can hit between the GS flip and IF=0 — a park there resumes
  at `swapgs` and flips GS a SECOND time; every later gs-relative
  access lands through the wrong base).
- It fired mid-audit-phase, BEFORE the driver stack (the S5 persist
  step had not run in that boot), in demo code untouched by the S5
  slices; the same tree booted green twice before and (see the
  session log) again after. Per this ADR's own rule: one occurrence
  on a changed tree is an OBSERVATION, not a reproduction — the next
  hunt round must sample pristine 10 ms boots with capture probes on
  the syscall-entry park window and the grants write path before
  claiming anything.

## Context

The ~1-in-5 boot flake recorded in the slice-4 changelog ("a lane
flake in the slice-3/preempt interplay") was picked up as round X's
target. Two distinct failure shapes had been observed once each at
the default 10 ms tick on pristine trees: the CoW demo failing with
`parent_ok=0 child_ok=0 copies=1` (the parent's store never
faulting — it never ran — and the child's read-back mismatching),
and round W's mode-13 wait4 failure (a child's completion entry
surfacing unconsumed in kmain's drain).

## Round X, corrected

Round X reported: "8x tick density fires the failure on every boot
(3/3), always the signal-demo victim dying inside its handler with
rdi=0xA." Round Y audited that claim against the build that actually
ran those boots and found it false:

- The failing boots (iso4-6, sig1-5) ran the **amplifier blob** —
  round X's temporary edit added a 50-iteration loop to mode 7,
  which sits between mode 3 and `sig_handler` in the flat blob. The
  handler address is registered as `next_instr + 0x947` — a
  HAND-MEASURED constant pinned against the old layout. The edit
  moved `sig_handler` by +0xC; the stale delta then delivered
  SIGUSR1 twelve bytes short — into the hex-print helper's tail.
- The victim entered at `dec %ecx` with `rdi=0xA` (the handler-entry
  signal argument), looped, and died at `mov %al,(%rdi)` with
  cr2=0xA. The dying register file confirmed it: `rsi=0x4030400` is
  the victim's `rem` pointer ROLed by the helper's `rol $0x4,%rsi`,
  and `rax=0x30` ('0') is the helper's nibble-to-ASCII mid-loop —
  the victim was executing HELPER code, not handler code.
- The "user-context struct fields in the callee-saved registers"
  (r12=0x2b the CS, r13=0x202 RFLAGS, r14=0x23 the domain id,
  r15=0x102000 a physical address) that round X read as the smoking
  gun are **launch-stub scratch leftovers** — `enter_ring3` loads
  the context fields through the callee-saved registers on its way
  to SYSRET and never zeroes them. Mode 3 (like most blobs) never
  reads a callee-saved register, so they survive untouched for the
  run's whole life. Harmless.
- The pristine tree does NOT fail at 8x density: dense1-4 (density
  knob only, pristine blob) were green 4/4, and 18 consecutive
  pristine boots at 10 ms were green. The original flake is not
  tick-density-correlated.

Every kernel capture site round X audited was individually clean on
re-read: `park_from_frame` (IRQ frame, symmetric gpr_at/set_gpr_at),
`parked_from_current_syscall` (stub slots + OFF_* frame table),
`from_user_context` (zeroed gprs), `deliver_to_parked` (correct
img mapping + rewrite), `sys_sigreturn` (probe-verified: no refusal
fired in any failing boot), `pop_catchable_signal` (reads the
registered table directly), and the syscall-entry stub's slot
discipline (one global USER_RBP/R12-15 set, written at entry, read
at park — snapshot-copied before any other excursion can overwrite).

## The real bug (round Y, FIXED)

`examples/ring3-preempt/src/lib.rs` mode 3 registers its SIGUSR1
handler as `next_instr + 0x947` because the toolchain's global_asm
pre-parser rejects rip-relative forms. `sig_handler` sat ~770 lines
LATER in the flat blob — the delta spanned every mode from 4 to 13.
Any code insertion in those modes silently moved the handler and the
stale delta delivered SIGUSR1 into arbitrary code — exactly what
round X's amplifier did by accident, and a trap for every future
round.

The fix, landed and gated:

1. **`sig_handler` relocated to sit IMMEDIATELY before mode 3's
   label.** The delta now spans only mode 3's own prologue
   (`next_instr − 0x1f`), so later-mode edits can never shift it,
   and a mode-3 edit is review-visible next to its own handler.
2. **A build pin: `scripts/check-blob-deltas.py`**, wired into
   `boot.sh` right after the blob rebuild. It objdumps the built
   blob, finds `next_instr`, and asserts the landing
   (`next_instr − 0x1f`) is exactly the flag-writer
   `mov $0x51515151,%rax; mov %rax,0x403060`. A stale delta now
   fails the BUILD instead of killing the victim at runtime.

Gates after the fix: 3/3 verify boots green with the pin running in
the build ("CHECK-BLOB-DELTA OK" in every boot log), the signal demo
green in all three, `cargo fmt --check` clean, clippy `-D warnings`
clean, host tests 425/0.

## The original flake — what actually remains

Two real failures on pristine trees, never reproduced since:

1. Round X run-1: the CoW demo failed `parent_ok=0 child_ok=0
   copies=1` — only the child's store faulted (its CoW served), the
   parent's store never ran, and both verdicts came out non-clean.
2. Round W: the mode-13 wait4 failure — a child's completion entry
   surfaced unconsumed in kmain's drain.

The tick-density lead is refuted (dense1-4 green). What varies
between boots remains: the HPET/TSC calibration, the wall-clock
position of stages (the rogue demo's 150k-strike escalation under
host load — the round-X "loaded boot hangs" were QEMU slowness, not
the bug), and host scheduling bursts. The next hunt should start
from the CoW failure's exact semantics (the parent's yield-resume
never happened) with capture probes on a pristine tree, sampling
many 10 ms boots — and must distinguish BUILD changes from BOOT
nondeterminism before claiming any reproduction (round X's central
mistake: its "3/3" was per-BUILD determinism misread as per-boot
randomness).
