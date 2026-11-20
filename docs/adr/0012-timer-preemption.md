# ADR-0012: Timer Preemption — the LAPIC Tick, Parked Runs, and the Frame-Rewrite Switch

- **Status:** Accepted (machinery + policy landed; the boot demo is
  feature-gated `preempt-demo` pending §Open issues).
- **Date:** 2026-11-20
- **Related:** ADR-0002 (direct map), ADR-0005 (exception machinery),
  ADR-0010 (ring-3 reliability), ADR-0011 (HAL seam), `M2-PLAN.md` week 2,
  `GAP-ANALYSIS-v2.md` Phase 1.

## Context

M2's exit criteria ("quarantine one domain while others continue") are
meaningless while a running domain can starve the scheduler and the
monitor's window accounting: nothing ticked `Scheduler`, one ring-3 run
was active at a time (`begin`/`launch`/`take`), and the kernel ran with
no interrupt source at all. This ADR records the design that closes
that gap and the two environment findings the bring-up surfaced.

## Decision

1. **Timer**: the LAPIC (default MMIO 0xFEE00000), TSC-deadline mode
   when CPUID offers it, periodic divide-by-16 otherwise (QEMU 10.0.13
   TCG `-cpu max` reports no TSC-deadline → periodic in CI). The MMIO
   window is one extra 1 GiB PDPT entry in the direct map (PA
   0xC0000000..0x1_0000_0000, RW+NX+G, kernel-only) — every domain
   inherits it through `install_kernel_entries`. Vector 0x30 (48),
   above the legacy 8259 catch-alls; the spurious vector (0xFF, from
   SVR) is wired as a named no-op without EOI. All encodings are pure
   and host-tested (`arch/lapic.rs`).
2. **Policy split (ADR-0011 §D3)**: the decision layer is
   `src/preempt.rs` in the policy core — `Preemptor::on_tick` charges
   the running domain one slice via the real CFS `Scheduler` and
   switches only when the fair pick differs; `on_exit` hands the CPU
   to the next runnable domain. Fully host-tested (starvation freedom,
   fair alternation, nice weighting, exit handover, the unregistered-
   current fallback).
3. **The switch**: the tick parks the interrupted run from the
   interrupt frame (15 GPRs + iret words + the CPL3 tail), rewrites
   the frame with the target's `ParkedContext`, switches CR3 and
   `USER_RUN`, and returns through the stub unwind's `iretq` — the
   first iretq-to-CPL3 return in this kernel, and it worked. The
   handover path (another domain exited) resumes a parked run via a
   SYSRET-based naked entry (`enter_ring3_parked`) that restores every
   GPR except RCX/R11 (the SYSCALL-ABI pair — documented cost of the
   proven entry path; the frame-rewrite switch preserves everything).
   `ParkedContext` layout is pinned by a host test against the asm's
   literal offsets (the M2-W2 mirror-inversion lesson).
4. **Interrupt discipline**: the tick handler never touches GS (it
   arrives from CPL3 and returns via iretq without swapgs; nothing on
   the path may use `%gs:` state), EOI + re-arm come first, and a
   CPL0 timer frame is a loud kernel-bug halt.

## Evidence (what actually ran)

In the QEMU bring-up builds, the complete pipeline was demonstrated
end-to-end once: the timer armed (periodic), the first tick
interrupted the spinner mid-loop (frame `cs=0x2b rip=<spinner loop>`),
the switch entered the writer via the rewritten frame, the writer
performed its four gated SYS_WRITEs and exited(0) while the spinner
was still parked (the starvation-freedom proof), the handover resumed
the spinner mid-loop with its 400M-iteration counter intact (it
exited(7) on schedule), and the tick-driven monitor windows closed
throughout. The default boot does not run the demo yet — see below.

## Environment findings (both fixed in-tree)

1. **SYSCALL does not clear IF in this environment.** Despite
   `IA32_FMASK = 0x700` reading back correctly, the dispatch was
   measured running with `rflags.IF=1` (420k samples, one value). The
   kernel has effectively run IF=1 through every syscall since PR-1.4
   — invisible until the first interrupt source existed. Fix: the
   entry stub now executes `cli` right after `swapgs`; the no-nesting
   invariant is self-enforced, not trusted to the MSR.
2. **A release+LTO argument-codegen anomaly.** The demo's spawn call
   passed a garbage `data.as_ptr()` (stale stack value 0x800): the
   disassembly shows the argument slot reserved but never stored,
   for a promoted `&[0u8]` slice constant and again for a
   function-local named static that the optimizer left without a
   symbol. Host builds (no LTO, opt 0) are unaffected; the seven-run
   sequence's identical `&[0u8]` arguments are unaffected in the same
   binary. Worked around (named statics) and gated (below); the
   underlying miscompile is **not** root-caused.

## Consequences

- The boot demo (kmain step 12) is behind `preempt-demo` (default
  off): CI's boot gate stays green and honest while the anomaly is
  investigated; the machinery (LAPIC driver, IDT wiring, tick path,
  parked-run table, `src/preempt.rs` policy + its 8 host tests) is in
  the tree and exercised.
- Unsafe ratchet: 78 → 89 (the parked-run table, frame park/unpark
  tail writes, `enter_ring3_parked`/`resume_parked`, `cpuid1_ecx`,
  the full-frame fault dump). All in allowlisted modules with SAFETY
  notes.
- Next steps: (a) root-cause or bypass the codegen anomaly (try
  `lto = "thin"`, an argument-buffer refactor, or a rustc bump) and
  un-gate the demo with the boot.sh markers; (b) wire the
  quarantine-while-others-run boot test on top.
