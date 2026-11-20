# ADR-0010: Ring-3 reliability — four root causes, one honest record

- **Status:** Accepted
- **Stage:** 2 (M2-W2)
- **Date:** 2026-11-20
- **Replaces:** the "open issue (environment)" verdict of PR-14 in
  `docs/arch/syscall-entry.md`

## Context

PR-1.4 ended with the boot asserting `[RING3] launch blocked: ...` and
`boot.sh --verify` *accepting* that outcome as "environment-blocked in
this QEMU build (10.0.13, TCG)". That verdict was wrong. M2-W2 reopened
the case with three pieces of forensics added to the kernel itself:

1. **#DF frame dump** — on every #DF, print the eight raw words above
   the GPR frame plus CR2/CR3 at fault time.
2. **The full fault record** in the blocked path (vector/cr2/err/rip/rsp
   + the parked resume point + the run's telemetry).
3. **The QEMU monitor** (registers + disassembly) on the post-resume
   hang.

The evidence chain, step by step:

- The #DF arrived **without a CPU error code** (QEMU's contribution
  path), so the stub's error-code assumption shifted the parse by one
  slot: the printed `err` held the **real RIP (0x400000 — the first user
  instruction)**, `rip` held the real CS (0x2b), `cs` held the real
  RFLAGS (0x202). Every "shifted frame" symptom in the PR-1.4
  investigation is this parse shift.
- The raw tail decoded to the **pristine launch context**
  (rip=0x400000, cs=0x2b, rflags=0x202, rsp=0x409000=STACK_TOP,
  ss=0x23): a frame the CPU pushes when **delivering an event INTO the
  user context** — an interrupt frame, not a user execution.
- **CR2 was stale** (0x200000, from an earlier selftest): the original
  event was not a page fault. With IF=0 in CPL0 and IF=1 in
  USER_RFLAGS, the first moment an interrupt can fire is the SYSRET
  boundary itself.
- The IDT covered **vectors 0..=31 only**, and **nothing masked the
  PIC**. A stray legacy IRQ (the PIT is running) fired at the boundary,
  hit an absent gate, faulted mid-delivery, and escalated to #DF.

## Decision (the four fixes)

1. **IRQ discipline first.** `hw::pic_mask_all()` at the top of
   `arch::init()` (no IRQ source is armed until the LAPIC timer lands
   with preemption), plus IDT catch-alls for **32..=47** whose handler
   is a NAMED halt — `unexpected IRQ vector=N — no source is armed` —
   never again a #DF with a shifted frame. The IDT doc comment's old
   claim that "a stray IRQ double-faults loudly" was aspirational, not
   literal; now it is literal.
2. **The stub's slot table is code, not literals.** The syscall-entry
   stub's stack offsets were **mirror-inverted**: pushes execute in
   order, so the *last* push lands at `[rsp+0]`, but the stub read `nr`
   from offset 8 — the RBX slot. Every user syscall was a garbage-nr
   `-ENOSYS`; the PR-1.4 investigation's "gate refusals with -ENOSYS"
   were this bug, not the gate working. The offsets now live as named
   consts (`OFF_*`) in the host-visible `arch::syscall_frame` module,
   the naked asm reads them via const operands, and a host test pins
   the table against the `SyscallFrame` struct — the mirror map
   (slot(f) = 88 − struct_offset(f)) can never silently desynchronize
   again.
3. **The launch/resume register contract.** `resume_kernel` jumps to
   the launch label from mid-Rust (SYS_EXIT in the dispatch, the
   user-fault branch in the exception dispatch), so the kernel caller's
   callee-saved registers (RBX/RBP/R12–R15) crossed the user excursion
   with no one contract-bound to preserve them — the exception path
   left a live `&mut Kernel` in a register kmain was keeping
   `kernel_cr3` in, and `write_cr3` spun the CPU in a #GP loop (the
   monitor caught it: RIP parked on `mov %rax,%cr3`). `launch` now
   parks all six in statics and the resume label restores them before
   the epilogue; both exit paths inherit the fix.
4. **SYSRET entry, as documented.** `enter_ring3` had regressed to
   `iretq`, contradicting its own doc comment (and ADR-0004-era design
   notes): SYSRET performs no descriptor-validation stack-switch cycle,
   so the entry cannot fault mid-switch. The code now matches the
   documented design, and the comment records the regression.

Two supporting fixes surfaced in the same pass:

- **The telemetry ring must be drained.** It is a fixed 16-slot buffer
  that *refuses on overflow* (never overwrites — by design), and nobody
  drained it: run 5's spam filled it and run 6's AuditOnly verdicts
  dropped (the ring's own counter read **2076 dropped** at the first
  drain). kmain now drains between runs as the supervisor will (M2-PLAN
  R5: the console domain reads the ring over an endpoint), printing the
  honest per-action counts plus the drop counter.
- **`boot.sh`'s success marker said "4 runs"** while the kernel has
  printed "7 runs" for a while — the stale grep never fired because the
  full path never ran in this environment until now.

## Consequences

- The full ring-3 sequence passes in QEMU TCG: seven runs (hello /
  NX / kernel-VA / forged syscall / edge writes / live-monitor
  quarantine / audit-only), all markers green, `BOOT VERIFY: PASS`
  with no warning.
- The blocked outcome is **retired**: `boot.sh --verify` fails if the
  blocked line ever returns. Accepting it was accepting a regression.
- The #DF forensics stays permanently (a security kernel prints
  everything it knows when it double-faults); it adds one allowlisted
  unsafe block (raw words above the frame), raising the unsafe
  baseline **77 → 78** — this ADR is the required reference.
- Kernel host tests: 76 → 77 (`stub_offsets_mirror_the_frame_struct`).

## Alternatives considered

- *Blaming the environment permanently* — rejected: every "environment"
  symptom reproduced as one of four local bugs; the evidence chain is
  above, and each fix is individually regression-covered.
- *A heuristic re-parse of #DF frames* (sniffing for a plausible
  RIP/CS/RFLAGS shape) — rejected: the forensics dump makes the frame
  readable without guessing; heuristics in the fault path are how the
  shifted-frame confusion started.
- *IST stacks for every vector* — rejected: only the vectors with a
  stack-related failure mode (#DF/#NMI/#MC/#SS/#PF) need ISTs; the
  catch-alls deliver fine on RSP0 now that the PIC is masked.
