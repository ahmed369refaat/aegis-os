# AegisOS — Staged Execution Roadmap

> Planning principle: every stage produces a **system that boots, runs, and proves itself by measurement** before the next one starts. The policy kernel in `src/` is the completed stage M0 — everything after it embeds the kernel without rewriting its policies.

## M0 — Policy kernel + Linux semantics (DONE — this repository)

**Output:** a `no_std`, zero-dependency library embodying the full isolation/monitoring/response policy set **and** the Linux-like semantics layer, 191 tests, `forbid(unsafe_code)`.

- Attenuation-only syscall masks; capability table with generations; full memory policy (W^X, guard gaps, quotas, scrub accounting, wraparound/NULL rejection).
- Buddy page-frame allocator with split/coalesce and exact accounting.
- VFS with Unix DAC (owner/group/other), traversal rules, chroot with `..` clamping and cwd hardening.
- Per-domain fd tables (lowest-free, dup2), refcounted bounded pipes (EOF/EPIPE/short I/O), POSIX signal sets with unblockable SIGKILL.
- CFS-style scheduler using the real Linux nice→weight table; brokered sockets with per-domain token-bucket rate limits.
- `BehaviorMonitor` (deterministic integer score + hysteresis + decay + sensitivity thresholds) and the graduated Log → Tighten → Quarantine response.
- Executing syscall layer (`sys.rs`): gate first, execute second, telemetry always.
- **Exit criteria (met):** `cargo test` 100% green (191 tests), clean build for bare-metal ARM (thumbv7em), the full security scenario (Log→Tighten→Quarantine + neighbor isolation) and all ten Linux-semantics scenarios pass.

## M1 — Boot and physical memory (DONE — x86_64; see `docs/M1-PLAN.md`)

**Output:** a binary that boots on QEMU and runs the M1 exit-criteria
sequence: hello domain, live memory-policy demo, monitor escalation,
1000-cycle create/destroy stress. Delivered for **x86_64** (multiboot);
aarch64 remains a follow-up target under this milestone's umbrella.

- Deterministic bring-up: multiboot v1 → own GDT → identity page tables
  (1 GiB, 2 MiB pages) → long mode → Rust `kmain`; boot TSC stamped at
  the first instruction.
- Real physical frames: 256 × 4 KiB pool at 16 MiB, claimed only after
  multiboot `mem_upper` validation, managed by the **existing** policy-core
  buddy allocator; per-frame ownership; scrub-on-free verified by
  read-back; boot-time entropy deferred to M2 (no consumer yet — not
  built speculatively).
- Guard gaps: the policy check runs live at boot (adjacent mapping
  rejected); hardware-enforced guard pages arrive with per-domain page
  tables in M2.
- Measurement: kernel prints TSC cycles entry→done; the CI boot job
  measures and reports the full QEMU run wall-clock (startup included).
- **Exit criteria (met):** boots reliably (CI `boot-test` job greps the
  `M1-EXIT-CRITERIA: PASS` verdict on every push; ELF sanity checks in
  the `kernel-build` job); hello domain runs (CFS slices, 3 real backed
  frames); 1000 create/destroy cycles → `leaked-frames=0` and
  `scrub-verified=yes` (asserted in-kernel, in host tests, and CI-grepped);
  all 196 core tests + 23 kernel host tests green; boot < 300 ms target
  measured by the runner. Full honesty note: domains are kernel-resident
  in M1 (no ring 3 / per-domain tables yet) — that boundary is M2 and is
  stated in the README.

## M2 — Scheduling and live domains (Months 2–4)

**Output:** multiple domains with preemptive scheduling and IPC.

- Preemptive slices driven by the CFS engine (vruntime, nice, wake/sleep); green threads inside a domain share its mask and capabilities.
- Hardened interrupt frame (no domain code ever runs in interrupt context).
- Capability IPC: point-to-point channels; sends are monitored copies (no default shared memory); channels are `IpcChannel` resources under GRANT/subset rules.
- Domain supervisor: creation = profile + derived capabilities; supervised respawn of quarantined domains; fd passing between domains over IPC (the missing piece for cross-domain pipes).
- **Exit criteria:** IPC ping-pong < 1 µs in QEMU (benchmarked in `bench/`); killing a domain mid-IPC never hangs the system (fault injection test).

## M3 — VFS and drivers (Months 4–7)

**Output:** `vfsd` and `devd` plus reference drivers as user domains.

- vfsd: real backing (ramfs, then read-only ext2) behind the existing DAC/chroot core; every open goes through derived `FsNode` capabilities.
- devd: owns device space; grants drivers exclusive `Device` capabilities (MMIO through bounded region maps; interrupts as IPC messages).
- Reference drivers: serial (boot output), then virtio-blk and virtio-net (consumed by netd alone).
- **Exit criteria:** a parser domain reads a file end to end from disk; a deliberately corrupt driver is auto-quarantined by the monitor and takes down nothing but its own domain.

## M4 — Full behavioral monitoring (Months 7–10)

**Output:** the security layer of `docs/ARCHITECTURE.md` §6 running on the real system.

- Wire every kernel signal (faults, escalations, denials, IPC/file/net mixes through the broker) into the window counters.
- Timed windows with atomic close; per-CPU rings then aggregation.
- Security console (admin domain): telemetry view, supervised `reset` (un-quarantine with human approval), per-profile threshold tuning.
- **Exit criteria:** a reference attack workload (syscall recon + faults + escalation) is auto-quarantined within ≤ 3 windows; a 24-hour clean workload with zero false escalations.

## M5 — Heavier analysis models (AI/ML) (Months 10–14)

**Output:** ML models as *clients* of the system, never parts of it.

- A monitoring domain consumes telemetry rings: a light sequence model (e.g. n-grams over syscall sequences) producing a per-domain confidence signal.
- The signal feeds the same graduated-response interface — the model holds no execution capability; its recommendations pass through the same thresholds and hysteresis.
- Offline training on exported ring traces; weights are never updated inside the kernel.
- **Exit criteria:** improved detection on the reference attack suite (ROC-AUC above the integer-score baseline) with zero fast-path latency regression (measured by M6).

## M6 — Continuous measurement (ongoing from M2)

**Structure:** `bench/` as a permanent measurement area run by CI.

| Measurement | Tool | Reference target |
|---|---|---|
| Boot time | early cycle counter | < 300 ms (QEMU), then < 150 ms on hardware |
| Allowed syscall (fast path) | rdtsc/pmu loop | < 100 ns with p99 ≈ p50 |
| Denied syscall | same | same class — denial is never slower than permission |
| IPC ping-pong | bench/ipc | < 1 µs |
| Monitoring window cost | measurement around `audit` | < 50 µs per domain (off the hot path) |
| Page alloc/free + scrub | bench/mm | regression gate fixed after M1 |

- Every measurement prints as line-oriented JSON into the same ring infrastructure used in production.
- CI runs tests + the no_std build for two targets (host + thumbv7em) + regression checks on core benches.

## Deliberately deferred (decide only with M6 data)

- Replacing CFS slices with dynamic priority: only if measurements show starvation or tail latency.
- Read-only page sharing between domains: needs reference counting through capabilities; not before a measured need.
- Real SMP: the design is ready for it (per-CPU SPSC rings), but insertion waits until after M4 — complexity is only paid when workload exists.
