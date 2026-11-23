# ADR-0031: Signal-frame flag whitelist and entry flag hygiene — the restored context is always preemptible, and the kernel never inherits user flag state

- **Status:** Accepted (section A implemented this round; section B is the ITEM-7 measurement round)
- **Stage:** M3 security hardening (post-shell/exec/ext2 review, round A1/N3)
- **Date:** 2026-11-23

## Context

The round-A review proved two flag-state holes, both reproducible:

1. **The signal frame's return path used a blacklist.** `sigframe::validate`
   computed the restored RFLAGS as `(user_word & !RFLAGS_STRIP) |
   RFLAGS_FIXED_ONE` with `RFLAGS_STRIP = IOPL|NT|RF|VM|TF`. A process reads
   the cookie out of the frame the kernel pushed on its own stack (the cookie
   rides the frame by design — ADR-0023 D8), forges word 5 with `IF=0` and
   `AC=1`, and `rt_sigreturn` restores it: SYSRETQ loads R11 wholesale, so
   the process returns to ring 3 with **interrupts masked** — the LAPIC timer
   can no longer preempt it (single-CPU starvation; the ADR-0023
   starvation-freedom guarantee broken by the very mechanism that proves it),
   and with **AC=1** — every later syscall/exception entry inherits a set
   AC, and supervisor accesses stop being SMAP-checked. The pinned unit test
   (`forged_rflags_bits_are_stripped_not_trusted`, asserting `rflags ==
   RFLAGS_FIXED_ONE` for a zero frame) documented the floor but not the
   ceiling: nothing forced IF on, and AC/VIF/VIP/ID were not in the strip
   set at all.
2. **Nothing cleared AC at kernel entry.** `FMASK_IF_TF_DF` (the SYSCALL
   MSR mask) covers IF|TF|DF only, no entry stub executes `clac`, and ring
   3 can set AC by plain `pushfq`/`popfq` (POP F at CPL3 may modify AC) —
   no signal frame needed. ACR-0030 already measured that this environment
   (QEMU 10.0.13 TCG, `-cpu max`) does not reliably apply FMASK.IF across
   SYSCALL, so the entry self-enforces IF with `cli`; AC has neither an MSR
   bit nor self-enforcement.

The invariant these holes break: **kernel-relevant processor state is never
chosen by user data.** Interruptibility (IF) is a scheduling guarantee the
kernel gives every domain; AC is a supervisor-mode SMAP bypass the kernel
must never run with.

## Decision (section A — this round)

**Whitelist, not blacklist, for the restored context.** The pure validator
exports the exact set of RFLAGS bits a restored user context may choose:

- `RFLAGS_USER_ALLOWED = CF|PF|AF|ZF|SF|DF|OF` (bits 0, 2, 4, 6, 7, 10,
  11) — the arithmetic/status flags plus DF, which is per-thread calling
  convention state, meaningless to the kernel (the entry sanitizes its own
  copy; see section B).
- `RFLAGS_KERNEL_FIXED = IF|bit1` (bits 9 and 1) — a restored context is
  ALWAYS preemptible, and reserved bit 1 is always 1.
- Everything else — TF, IOPL, NT, RF, VM, AC, VIF, VIP, ID, and every
  reserved bit — is stripped, because a whitelist cannot go stale when the
  architecture grows a new flag: a new bit is non-allowed by default and
  needs an explicit decision to become restorable.

`validate` returns `(word & RFLAGS_USER_ALLOWED) | RFLAGS_KERNEL_FIXED`.
A delivery-time frame with plain `0x202` round-trips exactly (both its
bits are kernel-fixed), so the honest-handler contract is unchanged.

**AC joins the SYSCALL mask and the entries self-enforce it.**
`FMASK` is programmed with IF|TF|DF|**AC** (bit 18). Because FMASK is not
trusted (ADR-0030 measurement; section B re-measures with readback), every
kernel entry executes `clac` — gated on a boot-time byte
(`hw::ENTRY_CLAC_GATE`, set iff SMAP was enabled: CLAC without CPUID SMAP
support raises #UD) — as the first memory-touching instruction of:

- the SYSCALL stub (right after `swapgs` + `cli`), and
- `exception_common` (right after `cli`, before the GPR pushes).

Both `cli` and `swapgs` touch no memory, so no supervisor access happens
with an inherited AC. The CPU's own interrupt-frame push on the
CPL3→CPL0 exception path writes kernel stacks (TSS RSP0 or IST) where SMAP
does not apply, and the ADR-0030 IST6 wiring already covers the
CPL0-on-user-stack window for the interrupt family.

**The kernel's SMAP self-test becomes re-runnable and counted.**
`exceptions` keeps a probe-hit counter so the bootstrap can prove, after a
domain deliberately set AC and made a copy-free syscall excursion
(`sched_yield` — no STAC window anywhere on the path), that a CPL0 read of
a user page outside the window STILL faults. On an unfixed entry the
inherited AC silently suppresses that fault; the re-probe marker going
missing is the CI-visible failure.

## Consequences

- A forged frame can now restore exactly: the sanitized arithmetic flags,
  a canonical rip/rsp, and nothing else. IF=0 restores are impossible;
  AC never crosses the boundary in either direction.
- The whitelist is default-deny for future flag bits: adding one to the
  restorable set is a one-line, review-visible change to
  `RFLAGS_USER_ALLOWED`.
- The ring-3 blob grows three modes: the flag forger (mode 14 — forges
  IF=0+AC=1 through a REAL delivered frame and then proves by its own
  `pushfq` that it resumed with IF=1, AC=0, and still gets preempted
  while a writer co-runs), the AC setter (mode 15 — `pushfq`/`popfq` AC
  then a copy-free syscall), and the parameterized killer (mode 16 — the
  existing mode-4 shape with the target read from the data page, so the
  old hard-coded-pid ABI stays untouched). `check-blob-deltas.py` pins the
  forger's handler landing the same way it pins mode 3's.
- Tests that prove it: `every_rflags_bit_is_classified` (table over all
  64 bits), `property_random_flag_words_restore_the_fixed_floor`
  (10k seeded xorshift words: restored = allowed bits only, IF and bit 1
  always on), the rewritten `forged_rflags_bits_are_stripped_not_trusted`,
  the bit-flip corpus (unchanged meaning, new constants), plus the boot
  lanes (`--verify` greps the forge and AC markers; the forger's distinct
  exit codes name the step that failed).
- **Scenario placement is part of the design** (measured): the
  flag-forge scenario's heavy 400M-iteration preemption phase, first
  placed right after the ADR-0023 signal proof, broke the CoW demo's
  determinism assumption ("a tick stealing the child mid-run would race
  the exits") — q35-noiommu went 3/3 baseline passes to 1/3. Both
  ADR-0031 scenarios therefore run at the END of the boot sequence
  (after the Phase 7 PID-1 block, before the terminal guard-page
  proof), so every earlier demo keeps its pristine scheduler state;
  log order is irrelevant to the CI greps.
- **The delivery-deferral trap** (found live): a wake through the tick
  path defers signal delivery to the NEXT syscall — a forger without an
  explicit post-sleep `sched_yield` delivers on the EXIT syscall
  itself, the checks never execute, and the lane passes VACUOUSLY.
  Mode 14 carries the round-M yield belt (mode 3's discipline), and the
  red proof (exit 252 on the unfixed kernel) certifies the checks
  really run.
- What we explicitly do **not** do: no change to the delivery path (the
  interrupted image still rides the frame verbatim — the fix is entirely
  on the read-back side); no new syscalls; no change to the trampoline or
  the cookie discipline; DF stays restorable (user convention state — the
  kernel's own DF is handled by the entry sanitize in section B, not by
  policing user frames); VIF/VIP stay stripped (no virtual-8086 stories).

## Section B (ITEM 7, next in this round) — measurement first

Before any further flag work: read back `FMASK` after the write, capture
RFLAGS at the first kernel instruction after SYSCALL for blobs that set
DF, TF and AC, and record per-environment (TCG, KVM if present) whether
the MSR mask or the flags survive. Then, regardless of the measurement:
`cld` after `swapgs`, an explicit RFLAGS sanitize (clear TF/AC/DF/NT) in
the entry, and a safe IST #DB handler that classifies trap-vs-kernel-bug.
Recorded here because the two sections share the ADR's invariant: the
kernel never runs on flag state it did not choose.
