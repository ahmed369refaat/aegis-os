# AegisOS — Gap Analysis v2: from M2 to a Company-Adoptable Multi-Architecture OS

- **Status:** Accepted — the master planning document; supersedes the gap
  list in `M2-PLAN.md` §2 (which stays valid for the M2 slice only).
- **Basis:** commit `f6d96a9` · 243 lib tests (225 unit + 18 integration)
  + 77 kernel host tests · CI green · `boot.sh --verify` passing the full
  seven-run ring-3 sequence.
- **Scope:** the full production-readiness brief — core execution &
  isolation, storage, drivers (incl. IOMMU), networking, userland,
  multi-architecture (x86_64 / aarch64 / RISC-V, extensible), and
  production/company-adoption readiness.
- **Method:** something "exists" only if a test, a CI job, or a grepped
  boot marker proves it. Everything else is a gap, however much code
  looks like it.

---

## 1. Where the code actually is (verified baseline)

| Area | What is proven today | Proof |
|---|---|---|
| Syscall policy | 64-slot masks, AND+bit-test gate, `attenuate`/`try_narrow_to` subset-only, one shared `gate()` for kernel-resident and Ring-3 paths | `src/syscall.rs`, `src/domain.rs`, property tests |
| Capabilities | generation tables, FsNode/Device/Domain/Endpoint resources, GRANT-gated derivation, fail-closed stale handles | `src/capability.rs`, ADR-0009 |
| Memory | 10-check policy, const-generic buddy, scrub-on-free read-back, per-domain PTEs, W^X/NX, guard gaps as absent PTEs | `src/memory.rs`, `kernel-x86_64/src/mm/` |
| Linux-like layer | VFS + Unix DAC + chroot (a capability boundary), pipes, signals, fd tables, kill semantics | `src/vfs.rs`, `src/pipe.rs`, `src/signal.rs` |
| Scheduling | CFS (real Linux weights, vruntime, F12 floor) — **library-level; nothing ticks it in the boot kernel** | `src/sched.rs` |
| Network | brokered sockets: per-domain token buckets, NET_SEND accounting only — no packets exist | `src/net.rs` |
| IPC | ADR-0004 async half: capability-gated endpoints, bounded FIFO, never-reused ids | `src/ipc.rs` |
| Monitor | integer scoring + hysteresis + Log→Tighten→Quarantine, AuditOnly mode, **live organic feeds from the ring-3 path** | `src/monitor.rs`, kmain runs 6–7 |
| Boot kernel | two-stage boot, SMEP/SMAP, kernel W^X + CR0.WP, IST stacks, #DF forensics, **7-run ring-3 sequence green in QEMU TCG** (hello / NX / kernel-VA / forged / edge / quarantine / audit-only) | `kernel-x86_64/`, `boot.sh --verify` |
| Supply chain | zero dependencies (CI-enforced), `forbid(unsafe)` core, allowlisted kernel unsafe at baseline **78** with a ratchet | `scripts/check_unsafe.sh` |

That is a strong, honest base. Everything below is measured against the
full brief.

## 2. The seven scope areas, ruthlessly

### 2.1 Core execution & isolation

- **Ring-3 reliability: DONE** (ADR-0010). **Ring-3 syscall surface: ~3%.
  The dispatch in `kernel-x86_64/src/syscall.rs` executes WRITE and EXIT
  only; the lib implements ~20.** Every profile-allowed syscall must
  reach the same executor the lib tests exercise, table-driven, through
  the same `gate()`. Until then, "multi-domain system" means "kernel demo
  with user-mode guest actors".
- **No interrupts, no timer, no preemption.** The kernel runs IF=0; user
  code runs IF=1 (`USER_RFLAGS=0x202`) but only the PIC-masked catch-all
  gates 32..=47 exist; nothing arms a source; the Scheduler is never
  ticked; one run at a time via `begin/launch/take` (`sched/context.rs`).
  A spinning domain starves every other domain and the monitor's window
  accounting. This is the #1 gap: M2's exit criteria ("quarantine one
  domain while others continue") are meaningless without it.
- **No SMP.** Single CPU, singleton percpu, `static mut` run state. Fine
  for M2; must not leak into shared code that aarch64/RISC-V will reuse.
- **No demand paging, no COW.** All mappings eager; `MAX_REGIONS=8`.
- **No ELF loader.** Domains are `include_bytes!` blobs; adopters cannot
  build their own domains. ELF64 program-header walk + W^X mapping +
  cap-gated exec is the composability boundary.
- **No fork/exec.** Depends on COW + the restructure below.
- **Domain supervisor is a kmain stand-in.** No respawn loop, no
  supervisor policy object; the telemetry drain is inline code.
- **Toy limits.** `MAX_DOMAINS=4`, `MAX_CAPABILITIES=16`, `MAX_INODES=32`
  (128 B files), `MAX_ENDPOINTS=8`, `MAX_SCHED_ENTITIES=8`. The frame
  pool (4096 frames) supports far more; limits must become measured,
  configurable construction parameters with a capacity self-test.

### 2.2 Storage

**Nothing real exists.** The VFS is in-memory only. Missing: block layer
(`BlockDevice` trait), virtio-blk, page cache, read-only ext2 (then
rw), dm-verity-style integrity, optional encryption. All storage ops
must stay under capability + DAC + chroot + monitor control — the VFS
policy half already exists and is tested, which is why this area is
*engineering*, not *research*.

### 2.3 Drivers & hardware

**No drivers exist.** Missing: driver model (drivers as restricted
domains), virtio (blk/net/console/rng), PCIe, NVMe, USB, display/input,
ACPI/DT, power. **The IOMMU gap is structural and mandatory:** today
nothing DMAs, so the hole is latent — but the first driver that can DMA
without VT-d/interrupt remapping breaks the entire security narrative
(any "restricted driver domain" can overwrite all of physical memory).
The IOMMU design ADR must land **before** the first DMA-capable driver
PR, not with it.

### 2.4 Networking

The broker (`src/net.rs`) does per-domain accounting under profile
control — the right *policy* shape. Missing: real TCP/IP as a monitored
`netd` domain on top of the broker, TLS, firewall rules as attenuated
capabilities. No packets exist anywhere.

### 2.5 Userland

Nothing: no libc port (musl planned, riding the Linux-compatible ABI of
ADR-0003), no dynamic linker, no init/service manager, no shell, no
coreutils, no package story. `ABI-VERSION.md` is a versioned contract
for a 2-s syscall surface — the surface itself is the 2.1 gap.

### 2.6 Multi-architecture — the structural gap

This is the gap the brief elevates to first-class, and it is the one
with a **deadline**, because it compounds:

- Only `src/` (the policy core) is architecture-agnostic — and it is
  *proven* agnostic only for `thumbv7em-none-eabihf` (CI `no-std` job),
  not for the actual target arches.
- **`kernel-x86_64/` mixes two kinds of code**: genuinely arch-specific
  code (`arch/`, `hw.rs`, `boot/`, `memops.rs` — correctly allowlisted)
  and **arch-agnostic kernel services that happen to live in the x86_64
  crate**: the mm policy→PTE bridge (`mm/page_table.rs` policy gating is
  portable; PTE formats are not), the run/context machinery, syscall
  dispatch glue, `runtime.rs`, kmain's demo sequence.
- The ROADMAP v2 "Stage 1 Track B" promised a `kernel/src` +
  `arch/{x86_64,aarch64}` restructure and CI on both arches "from Stage
  1B". **None of that happened.** There is no aarch64 CI job, no
  `boot-aarch64/`, no HAL traits.
- **Why this is urgent:** preemption, ELF loading, COW, the block layer
  and the driver model are all about to be written. If they land inside
  `kernel-x86_64/` as more arch-flavored monolith, every one of them is
  written again (differently, worse) for aarch64. The seam must be cut
  **before** the next feature wave, and the very next features should
  demonstrate the discipline (policy half in `src/`, hardware half
  behind the seam).
- RISC-V: same treatment (RV64GC, SBI + CLINT/PLIC), strictly behind
  the HAL; no third copy of policy code anywhere.

### 2.7 Production readiness & company adoption

- **Monitor on real signals: DONE at the ring-3 boundary** (denials,
  out-of-profile bits, rate spikes, -EFAULT feeds; telemetry drain with
  drop accounting). Still missing: telemetry export over an endpoint
  (R5) so a console domain reads it without kernel code.
- **No security console / admin domain.**
- **No benchmark suite.** One number exists (syscall round-trip at
  boot). Needed per §6 of M2-PLAN: boot cycles, gate cycles, IPC RTT,
  monitor window cost, per-domain memory overhead — machine-readable,
  CI-gated against >10% regressions.
- **Documentation drift (found while writing this analysis, all fixed
  in the same commit):**
  1. test counts disagree across docs (ARCHITECTURE.md "219", ROADMAP
     "196+23", README badge "320" vs raw 243 lib + 77 kernel);
  2. ARCHITECTURE.md module tree omits `src/ipc.rs` and
     `tests/property_tests.rs`;
  3. SECURITY-MODEL.md §1 still says per-domain page tables and ring-3
     "are M2 — not in place" (false since PR-1.3/ADR-0010);
  4. README badge/status/roadmap lines + Makefile header still describe
     the retired "environment-blocked" verdict;
  5. README unsafe section says four-module allowlist / baseline 61
     (reality: five entries incl. `sched/`, baseline 78);
  6. ROADMAP "not present at all" list still names Ring-3 isolation and
     per-domain page tables.
  Drift like this is exactly what an evaluating company catches first,
  and it is cheap to fix. `scripts/count-tests.sh` becomes the single
  source of truth for counts.
- **Adoption materials missing:** "Building on AegisOS" guide, profile
  system docs for operators (not just the tables), supervisor API docs,
  reference multi-domain systems, release/versioning process.

## 3. Highest-risk usability issues (adopters) and mitigations

Carried from M2-PLAN §3 (still correct), condensed:

- **R1 "cannot add a syscall right later"** → replacement pattern (spawn
  a new domain with a wider profile; migrate over IPC endpoints;
  *capabilities* remain grantable any time). Policy narrows per domain
  *instance*, not per system.
- **R2 fixed sizes look like a toy** → limits as construction parameters
  + capacity self-test (M2-W4).
- **R3 "quarantine is harsh"** → hysteresis + graduated Tighten with IPC
  lifeline + AuditOnly calibration + the supervisor drain runbook;
  release = destroy + respawn tighter. Never an un-quarantine.
- **R4 ABI lock-in** → Linux-compatible numbering (ADR-0003), versioned
  `ABI-VERSION.md`, musl port as the proof.
- **R5 observability** → telemetry export endpoint; console is a client.
- **R6 determinism vs SMP** → preemption first, SMP only after the bench
  suite exists to catch lock creep on the fast path.

New for the multi-arch brief:

- **R7 "second arch doubles my audit surface"** → the HAL contract (ADR
  0011) is the audit boundary: policy code above it is identical on all
  arches; per-arch code is a small, allowlisted, doc'd set; CI builds
  the policy core for aarch64 + riscv64 from day one so divergence is
  caught by the compiler, not by a porting project.
- **R8 "hardcoded x86 assumptions will bite us later"** → every new
  feature PR states which side of the HAL seam each hunk belongs to; the
  gap analysis in review asks it explicitly.

## 4. The plan (phases to 100% readiness)

Process unchanged: one phase at a time, PRs < 500 lines, ADR per
architectural decision, red→green tests per slice, CI gate per commit,
bootable at every stage. Durations assume the same cadence the project
has been keeping (M2-W1/W2 landed on schedule).

**Phase 0 — truth & guardrails (this commit, partly).**
Doc drift fixed; `scripts/count-tests.sh` is the single source for test
counts; **CI builds the policy core for `aarch64-unknown-none-softfloat`
and `riscv64imac-unknown-none-elf`** (arch-agnosticism enforced by the
compiler from now on); ADR-0011 accepted. Exit: green CI with the two
new target jobs; no stale claims anywhere in docs/.

**Phase 1 — the schedulable core (finish M2, ≈3 weeks).**
- W2 **preemption** (starts in this commit): LAPIC timer (TSC-deadline,
  vector 48) → tick → charge the CFS scheduler → interrupt-frame context
  switch between parked Ring-3 runs. Policy half in the new
  `src/preempt.rs` (host-tested); hardware half in `kernel-x86_64`.
  Exit test: a spinning Ring-3 domain cannot starve a second domain
  (CI-grepped boot markers, switch count > 0, writer finishes while the
  spinner is still runnable).
- W3: table-driven Ring-3 dispatch (every profile-allowed syscall
  reaches the lib executors) + fd passing; ELF64 loader (program-header
  walk, W^X mapping, cap-gated open→exec).
- W4: demand paging + COW (faults are organic monitor signals);
  limits lift + capacity self-test.
- W5: sync IPC call/reply fast path + pipes-over-endpoints; telemetry
  export endpoint (R5); quarantine-while-others-run boot test.
- W6: entry fuzzing + endpoint property tests; bench row in CI; v0.3.0.

**Phase 2 — the architecture seam + aarch64 (≈4 weeks).**
- Restructure per ADR-0011: `kernel/` (arch-agnostic core: mm bridge
  policy side, sched, run queue, syscall dispatch, runtime) +
  `arch/x86_64` + `arch/aarch64` behind the HAL traits; boot stubs per
  arch. Pure move-and-wire, no new features — the full test suite and
  boot verify must stay green pixel-for-pixel.
- aarch64 QEMU virt bring-up: EL1/EL0, stage-1 MMU, PL011, SVC entry,
  PAN, generic timer; the same ring-3 + preemption acceptance markers
  on `qemu-system-aarch64 -M virt`; CI matrix job.
- RISC-V RV64: build-only CI target now; full port scheduled in Phase 6.
Exit: both arches pass the same acceptance markers in CI.

**Phase 3 — storage & the first real driver (≈5 weeks).**
`BlockDevice` trait → virtio-blk (MMIO first, works on both arches) as
a restricted driver domain → page cache → read-only ext2 → dm-verity
style Merkle verification; **IOMMU design ADR lands in week 1** (per
domain DMA windows; identity maps only for the driver's own frames);
VT-d integration on q35 before any faster driver. Exit: a parser domain
reads a real file from a disk image through capability + DAC + monitor
unchanged; DMA is provably confined.

**Phase 4 — POSIX surface & userland (≈7 weeks).** Full
Linux-compatible dispatch per ADR-0003 (fork/exec on COW, signals,
mmap/brk, wait4, …); musl static; init + service manager + shell +
coreutils; every syscall denied-by-default outside profiles.

**Phase 5 — networking (≈3 weeks).** `netd` domain: TCP/IP over the
broker, firewall rules as attenuated capabilities, TLS as a library
domain; rate limits stay in the broker (already tested).

**Phase 6 — SMP, hardening, production (≈6 weeks).** SMP (per-CPU
everything, TLB shootdowns, IPIs); KASLR/ASLR; syscall fuzzing regime;
security console domain; bench suite in CI; RISC-V full port;
"Building on AegisOS"; release engineering; v1.0.

**Total to the full brief: ≈28 weeks of the current cadence.** That is
the honest number; the phasing above keeps the system bootable, tested,
and honest at every point, and nothing in it requires weakening a
single security invariant.

## 5. Non-goals (explicit, to protect the core)

In-kernel TLS/crypto (library domains only), in-kernel "AI analysis"
(monitored client domain, never a fast-path dependency), un-quarantine
paths, mask widening under any name, and merging per-arch forks of
policy code. Each has its stage or is permanently out.
