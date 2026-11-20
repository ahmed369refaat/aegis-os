# M2 — Policy Kernel → Adoptable Core: Gap Analysis and Execution Plan

- **Status:** Active plan (supersedes the M2 sketch in ROADMAP v2 §"Stage 2+")
- **Basis:** commit `bf494f2` · 319 tests (243 lib+integration, 76 kernel) · CI green
- **Date:** 2026-11-20
- **Progress log:**
  - M2-W1 (commit `d94d25a`): ADR-0004 async IPC landed (15 tests).
  - M2-W2 (ADR-0012, in flight): the preemption machinery landed —
    LAPIC timer (periodic fallback proven in CI's TCG), vector 48 +
    spurious wiring, `src/preempt.rs` policy (8 host tests), the
    parked-run table, the interrupt-frame context switch, and the
    SYSRET handover resume. The end-to-end interleaving was
    demonstrated in bring-up builds (switch → writer runs → exits
    while the spinner is parked → handover → spinner resumes
    mid-loop); the boot demo is feature-gated `preempt-demo` pending
    the release+LTO codegen anomaly documented in ADR-0012 §Open
    issues. Also fixed in-tree: SYSCALL does not clear IF in this
    environment (stub now self-enforces with `cli`).
  - M2-W2 (ADR-0010): **ring-3 reliability closed** — the PR-1.4
    "environment-blocked" verdict was four local bugs (stray IRQ at the
    IF boundary + absent IDT gates; mirror-inverted stub offsets; the
    launch/resume register hole; an iretq regression). The full
    seven-run ring-3 sequence now passes in QEMU TCG and
    `boot.sh --verify` accepts only that outcome. Kernel tests 76 → 77;
    the supervisor telemetry drain (R5, stand-in form) is live.
- **Invariants (non-negotiable, restated):** attenuation-only privileges; a
  deterministic, allocation-free fast path; the BehaviorMonitor stays the
  single decision maker (heavier analysis joins later as a *monitored client
  domain*, never as a fast-path dependency).

---

## 1. Where the code actually is (grounded inventory)

Proven by tests today, symbol-level — this is the baseline every gap below
is measured against:

| Area | What exists | Proof |
|---|---|---|
| Syscall policy | 64-slot masks, AND+bit-test gate, `attenuate`/`try_narrow_to` subset-only, one shared `gate()` for kernel-resident and Ring-3 paths (PR-1.4) | `src/syscall.rs`, `src/domain.rs` |
| Capabilities | generation tables, `FsNode`/`Device`/`Domain`/`Endpoint` resources, `GRANT`-gated subset derivation, fail-closed stale handles | `src/capability.rs`, ADR-0009 |
| Memory | 10-check policy (`src/memory.rs`), buddy frames `Kernel<N>` const-generic, scrub-on-free read-back in the boot kernel | `src/buddy.rs`, `kernel-x86_64/src/frames.rs` |
| Linux-like layer | VFS + Unix DAC + chroot (now a *capability boundary*), pipes, signals, fd tables, kill semantics | `src/vfs.rs`, `src/pipe.rs`, `src/signal.rs` |
| Scheduling | CFS-style `Scheduler` (nice weights, slices, runnable set) — **library-level; no timer drives it in the boot kernel yet** | `src/sched.rs` |
| Network | brokered sockets: per-domain token buckets, `NetSend` accounting only (no packets) | `src/net.rs` |
| IPC | **ADR-0004 async half landed (this plan's week 1 slice)**: endpoint table with never-reused ids, capability-gated send/recv, bounded FIFO, EAGAIN-style overflow | `src/ipc.rs`, `src/sys.rs` executors |
| Monitor | integer scoring + hysteresis + Log→Tighten→Quarantine, `AuditOnly` rollout mode, organic signals from the fast path | `src/monitor.rs`, `src/response.rs` |
| Boot kernel | two-stage ELF32→ELF64 boot, SMEP/SMAP (ADR-0008), kernel W^X + CR0.WP (ADR-0006), IST stacks, user page tables, **Ring-3 demo limited to WRITE+EXIT** | `kernel-x86_64/`, CI boot job |

## 2. Gap analysis (prioritized; each gap: what exists → what is missing → why this rank)

### P0 — M2 exit-critical (weeks 1–6): "the core is real and schedulable"

1. **Ring-3 reliability (closed, M2-W2/ADR-0010) + syscall surface.**
   Reliability is done: the seven-run sequence (hello, NX, kernel-VA,
   forged syscall, edge writes, live-monitor quarantine, audit-only)
   passes end to end in QEMU TCG. What remains of this gap is the
   *surface*: the demo path executes WRITE and EXIT only; the lib
   executes ~20. The demo path dispatches
   WRITE and EXIT only; the lib executes ~20. Missing: a table-driven
   dispatch at the syscall entry so every profile-allowed syscall reaches the
   same executor the lib tests exercise. Rank #1 because every later feature
   (IPC from Ring-3, FS access, spawning) is unreachable from user space
   without it. Risk if skipped: the "multi-domain system" stays a kernel
   demo, not a system.
2. **No interrupts, no timer, no preemption.** `Scheduler` exists but
   nothing ticks it: no LAPIC timer calibration, no tick→`schedule_slice`,
   no preemption of a spinning Ring-3 domain. Missing: LAPIC timer + tick
   wiring + a preemptible idle loop. Rank #2: the M2 exit criterion
   ("quarantine one domain while others continue") is meaningless if a
   running domain can starve the monitor's window accounting.
3. **IPC: async half done; sync fast path and payload copy missing.**
   `src/ipc.rs` covers §2 of ADR-0004 (bounded queues, capability gates).
   Missing: `call/reply` blocking fast path with ≤64-byte payload copy
   (needs the scheduler from gap 2), and pipes-over-endpoints (§5). Rank #3:
   unblocks every later service (VFS server, telemetry export).
4. **No ELF loader.** Domains are compiled-in blobs (`spawn_user_blob`).
   Missing: ELF64 program-header walk, W^X-consistent mapping from file
   frames, cap-gated `open→exec`. Rank #4: blobs cannot be produced by a
   company's own build; ELF is the composability boundary for adopters.
5. **No demand paging, no COW.** All mappings are eager; `MAX_REGIONS=8`.
   Missing: page-fault path wired into the 10-check policy, zero-fill on
   demand, COW on domain clone. Rank #5: memory is the resource companies
   hit first; but it depends on the timer (fault retry needs preemption).
6. **Limits are toy-sized constants.** `MAX_DOMAINS=4`, `MAX_CAPABILITIES=16`,
   `MAX_INODES=32` (128 B/file), `MAX_REGIONS=8`, `MAX_ENDPOINTS=8`. Missing:
   measured headroom (the boot kernel's 4096-frame pool supports far more),
   const-generic or per-build configuration, and a capacity self-test that
   fails when a limit and the frame pool disagree. Rank #6: cheap, high
   signal for adopters, zero risk to invariants (limits are construction
   parameters, not policy).

### P1 — M3 (weeks 7–8 start): storage & drivers foundation

7. **No block layer, no disk filesystem.** The VFS is in-memory. Missing:
    `BlockDevice` trait, virtio-blk MMIO driver, read-only ext2, page cache.
    The mission's exit test: *a parser domain reads a real file from disk*.
8. **No IOMMU story.** Without VT-d any driver domain can DMA over the
    whole of memory — the security narrative collapses at the first real
    driver. Missing: ADR (design: per-domain DMA domains, identity-mapped
    windows only for the driver's own frames), then integration. Rank: the
    *design* must land in M3 week 7 even if silicon integration follows.

### P2 — M4: networking & userland bootstrap

9. Broker does accounting only — real TCP/IP + firewall sit on the broker
   as a monitored netd domain. 10. musl port + dynamic linker (rides the
   Linux-compatible ABI, ADR-0003). 11. init + service manager + shell
   (all ordinary domains under profiles).

### P3 — M5+: multi-arch & production readiness

12. HAL/BSP split (arch/ already isolates x86_64 specifics — the seam
    exists). 13. aarch64 (EL1/EL0/PAN; the lib already builds for
    `thumbv7em`), then RISC-V. 14. Security console (a domain, not kernel
    code). 15. Benchmark suite in CI (see §6).

## 3. Usability risks for adopters (the "too rigid" question) and design mitigations

The security model is the product; rigidity complaints are answered with
*sanctioned paths*, never with widening:

- **R1 "We cannot add a syscall right later."** Masks of live domains never
  widen — that is the invariant adopters buy. Mitigation: the **replacement
  pattern**, documented and supported by APIs that already exist: the
  supervisor creates a NEW domain with a wider profile and migrates state
  over IPC (endpoints are the migration channel); grants of *capabilities*
  (not mask bits) remain possible any time via the uid-0 APIs
  (`cap_grant_domain`, `ipc_endpoint_grant`). This is the difference between
  "policy is immutable" (false) and "policy only ever narrows per domain
  instance" (true, and exactly what auditors want).
- **R2 fixed sizes look like a toy.** Mitigation (week 1): lift limits to
  measured headroom as construction parameters, plus a capacity self-test
  that prints headroom per limit and fails on disagreement with the frame
  pool. Fail-loud errors already exist (`TooManyDomains`, `TableFull`,
  F14 discipline) — exhaustion is a policy event, never corruption.
- **R3 "Quarantine is harsh / false positives will kill production."**
  Mitigations already in the model: hysteresis (persistence across windows,
  not single events), graduated Log→Tighten (degraded profiles keep the
  IPC lifeline — see `plugin`/`service` degraded masks), `AuditOnly`
  rollout mode (F9). To add (week 5): the **supervisor drain runbook** —
  telemetry-ring export over an endpoint so a quarantined domain's audit
  trail is read *without* un-quarantining anything; release = destroy +
  respawn tighter. Never: an un-quarantine path.
- **R4 custom-ABI lock-in.** Mitigation: ADR-0003 pins Linux-compatible
  numbering; `ABI-VERSION.md` is a versioned contract; the supervisor API
  surface is the documented `pub fn` set of the lib (stable within a minor
  series). musl portability is a P2 deliverable precisely so adopters' code
  builds unmodified.
- **R5 observability for systems teams.** Telemetry ring exists in-kernel;
  week 5 exposes it as an endpoint the supervisor drains — the console is a
  *client*, keeping heavier analysis out of the fast path (per the
  non-negotiables).
- **R6 determinism vs SMP.** Preemption first (M2), SMP only in M4+ with
  per-CPU IST and a measured lock-free fast path; the moment a lock shows up
  on the syscall path, the benchmark suite (§6) fails the PR.

## 4. The 4–8 week plan

Process per ROADMAP v2: one stage at a time, PRs < 500 lines, ADR per
architectural decision, red→green tests for every slice, CI gate on every
commit. Each week ends with the full suite + boot verify green.

- **Week 1 — IPC + limits (started; async IPC landed in this commit).**
  Remaining: sync `call/reply` design ADR addendum (payload copy budget,
  blocking semantics on the scheduler), limits lift + capacity self-test,
  `MAX_ENDPOINTS` headroom note. Exit test: 2 domains exchange 10k messages
  in lib tests with zero cap/frame leaks (loop-count property test).
- **Week 2 — Timer + preemption.** LAPIC timer calibration (divider,
  periodic ticks), tick → `Scheduler::schedule_slice`, preemptible
  kernel-resident domain loop, Ring-3 time-slice preemption on
  `kernel-x86_64`. Exit test (boot verify): a spinning Ring-3 domain cannot
  starve a second domain; monitor windows still close on tick.
- **Week 3 — Full Ring-3 dispatch + ELF loader.** Table-driven dispatch at
  the entry (same `gate()`), fd passing for Ring-3 opens; ELF64 loader:
  program-header walk, W^X mapping, cap-gated exec. Exit test: a domain
  whose code is an ELF file (not a linked-in blob) performs
  open/read/write/close in Ring-3.
- **Week 4 — Demand paging + COW.** Page-fault handler consults the
  10-check policy (a fault is an organic monitor signal, like MMAP
  refusals); zero-fill on demand; clone shares frames RO, write fault
  copies (scrub-on-free reused). Exit test: fault-driven growth under a
  memory-policy cap; COW clone of N pages touches memory only on write.
- **Week 5 — M2 integration + measurement.** Quarantine-while-others-run
  boot test; IPC ping-pong bench (`bench/ipc.rs`, cycles via rdtsc);
  telemetry export endpoint (R5); supervisor drain runbook doc (R3).
  Exit test: **the M2 exit criteria of §5, asserted by CI.**
- **Week 6 — Hardening + v0.3.0.** Property tests for endpoint table
  invariants (id monotonicity under arbitrary create/destroy sequences),
  fuzz the syscall entry (random ids/args → no panic, every refusal
  precise), docs pass ("Building on AegisOS" draft), release cut.
- **Weeks 7–8 — M3 start: block layer + virtio-blk + ext2-ro + page
  cache; IOMMU design ADR.** Exit test: a parser domain reads a real file
  from a disk image through the capability + DAC + monitor chain unchanged.

## 5. M2 exit criteria (verbatim, CI-asserted)

1. Multi-domain system on QEMU: ≥3 domains, ≥1 in Ring-3, scheduled with
   timer preemption.
2. One domain is quarantined mid-run **while the others continue** (asserted
   by the boot test, not by inspection).
3. IPC: measured ping-pong (target: 100k async round-trips < 1 s in TCG,
   zero leaked capabilities/frames — ADR-0004's Stage-2 gate).
4. Every invariant test green: attenuation property tests, capability
   fail-closed suites, memory-policy suite, W^X/SMEP/SMAP boot assertions,
   unsafe allowlist, asm-pattern guard.
5. Benchmarks committed and reported: boot cycles, syscall gate cycles,
   IPC RTT, monitor window cost.

## 6. Metrics (continuous, per §"Continuous measurement")

`scripts/bench.sh` (week 5) emits a machine-readable row per CI run:
boot-to-init cycles · gate() cycles (rdtsc around the fast path) · IPC
async RTT · sync RTT (once week-1's fast path lands) · audit window cost ·
per-domain memory overhead (frames + tables). Regressions > 10% fail CI.

## 7. Non-goals for M2 (explicit, to protect the core)

SMP, TLS, USB/display/input, ACPI power management, RISC-V, dynamic
loading, and any kernel-side "AI analysis" — each has its stage; none may
appear inside the fast path or the monitor's decision loop. The monitor
stays integer-arithmetic + hysteresis; heavier analysis is a monitored
client domain (M5).
