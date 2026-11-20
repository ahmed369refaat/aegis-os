# AegisOS — Roadmap v2: from Policy Kernel to a Usable Unix-like Core

> **Mission.** Evolve AegisOS from a research-grade policy kernel (M0/M1,
> v0.2.0) into a **usable Unix-like foundation**: a kernel that boots on
> QEMU (x86_64 + aarch64), runs `init` in Ring-3, a shell, a VFS server
> over a block device, and passes basic POSIX tests — with every step
> provable by automated QEMU runs, and without ever weakening the two
> invariants that make this project worth doing:
>
> 1. **Attenuation-only privileges.** No code path anywhere widens a live
>    domain's syscall mask or capabilities.
> 2. **W^X and isolation are enforced by hardware** (MMU), not just by
>    policy bookkeeping, from Stage 1 onward.
>
> Process rules for every stage: one stage at a time, no stage starts
> before the previous one's acceptance criteria pass in CI; PRs < 500
> lines; an ADR per architectural decision (`docs/adr/`); docs per new
> component (`docs/<component>.md` with invariants + threat model); CI on
> x86_64 and (from Stage 1B) aarch64 via QEMU. See `CONTRIBUTING.md`.

## Definition of Done (final, verbatim from the project brief)

A kernel that boots on QEMU (x86_64 + aarch64) and runs `init` in Ring-3,
a shell, a VFS server over a block device, and passes basic POSIX tests
(fork, exec, open, read, write, mmap, pipe, wait, kill, sigaction). Every
process in Ring-3; W^X enforced by the MMU; ASLR; capability-based
permissions; an audit trail for every sensitive syscall.

Mapping: Ring-3 → Stage 1 · IPC → Stage 2 · block+FS → Stage 3 ·
preemption/SMP → Stage 4 · POSIX ABI → Stage 5 · drivers → Stage 6 ·
hardening (ASLR/audit) → Stage 7 · compliance → Stage 8.

## Current state (v0.2.0, the honest baseline)

**Done and CI-proven:** the full policy core (attenuation-only masks,
capability generations, ten-check memory policy, in-memory VFS + Unix DAC
+ chroot, pipes, signals, fd tables, CFS, buddy allocator, rate-limited
brokered sockets, behavior monitor with graduated response) — 196 tests;
a bootable two-stage x86_64 kernel (ELF32 multiboot stub → ELF64 kernel)
with a real 256-frame pool, scrub-on-free verified by read-back, kernel-
resident domains, and a CI boot test asserting the M1 exit criteria — 23
kernel host tests; 219 total, zero external dependencies, unsafe confined
to the allowlist (arch/, boot/, hw.rs, memops.rs, sched/ — as defined in scripts/check_unsafe.sh).

**Not present at all (each gets its stage below):** Ring-3 isolation,
per-domain page tables, interrupts/exceptions, timers, IPC, block devices,
on-disk filesystems, preemption, SMP, a POSIX syscall ABI, drivers,
ASLR/KASLR, audit trail, seccomp-style filtering, compliance suites.

---

## Stage 1 — Ring-3 Isolation (the wall between kernel and user)

**Goal:** a user domain runs at CPL=3 on x86_64 with its own page tables;
the kernel enforces W^X, guard pages, and SMAP/SMEP; syscalls enter via
SYSCALL/SYSRET; unauthorized syscalls and memory faults become SIGSEGV
with an audit record. Track B (aarch64: EL1/EL0, SVC, PAN) brings the
second architecture to the same bar, and CI grows the aarch64 job.

**Why this first:** everything else (IPC, FS, POSIX, drivers) is untrusted
code talking through this wall. If the wall is soft, nothing after it
matters.

**Tasks (measurable):**
1. IDT + GDT/TSS + exception entry with IST stacks and kernel-stack guard
   pages; a deliberate CPL0 fault produces a diagnosed panic (PR-1.1).
2. Higher-half kernel layout (kernel at `0xFFFFFFFF80000000`, direct map
   of physical memory, user space in the low half) + per-CPU state via
   GS/swapgs (PR-1.2).
3. Per-domain page tables: `BuddyAllocator<const N>` scaled to ≥ 4096
   frames; region mapping runs the existing ten-check policy, then writes
   real PTEs — W^X via RW/XD bits, guard gaps as not-present PTEs (PR-1.3).
4. SYSCALL/SYSRET entry (MSRs STAR/LSTAR/FMASK), register frames, and the
   first Ring-3 hello domain (PR-1.4).
5. Fault classification (#PF/#GP) → SIGSEGV default action (terminate) +
   audit ring record + monitor `report_fault` wiring (PR-1.5).
6. Track B (aarch64): QEMU virt boot (PL011 serial, Image format), stage-1
   MMU tables, EL1→EL0, SVC entry, PAN, fault parity, CI matrix (PRs
   B1–B5, ~5 PRs; restructures the kernel crate into
   `kernel/src/arch/{x86_64,aarch64}`).

**File structure after Stage 1 (Track A + B):**

```text
kernel/src/                  arch-agnostic kernel core
├── mm/{mod,direct_map,page_table,pte,stacks,user}.rs
├── sched/context.rs         UserContext + ring-3 switch
├── audit/audit.rs           audit ring (reuses core ringbuf)
├── arch/x86_64/{mod,gdt,idt,exceptions,frame,stubs,syscall_entry,fault,percpu}.rs
├── arch/aarch64/{mod,mmu,exceptions,entry,percpu}.rs
boot-x86_64/                 stage-1 ELF32 stub (higher-half aware)
boot-aarch64/                aarch64 bring-up (Image header, EL setup)
examples/ring3-hello/        user blob crate (no_std static, objcopy → include_bytes!)
docs/arch/{exceptions,memory-layout,page-tables,syscall-entry,faults-signals}.md
```

**Acceptance (CI-grepped in QEMU):**
- `hello from ring 3 (CPL=3)` printed by a user domain via a debug syscall.
- A user domain issuing a syscall not in its mask → SIGSEGV, domain
  terminated, `[AUDIT]` line present, other domains unaffected, monitor
  counters advanced.
- Access to a guard page or an RX page for write from Ring-3 → SIGSEGV
  + audit.
- SYSCALL entry/exit round-trip cycles printed at boot (fast path stays
  allocation-free); boot wall-clock ≤ 400 ms; all prior tests green.
- Track B: the same three markers on `qemu-system-aarch64 -M virt`.

**Stage-1 risks:**

| Risk | L | I | Mitigation |
|---|---|---|---|
| Higher-half move breaks the two-stage boot (stale low-address assumptions) | M | H | PR-1.2 lands alone, behind a boot-time smoke check; keep the M1 identity path working in the stub until the kernel switches CR3; CI boots every PR |
| SMAP/SMEP absent under `-cpu qemu64` | H | M | Feature-detect via CPUID; CI uses `-cpu max`; without SMAP, `copy_*_user` falls back to explicit range checks (still safe, slower) |
| Per-domain tables + frame-pool growth destabilizes the 219-test core | M | H | Const-generic buddy is additive (M1-PLAN anticipated it); policy tests untouched; new host tests for table bookkeeping |
| swapgs/IST mistakes → silent corruption, hard to debug in TCG | M | H | PR-1.1 establishes exception machinery first so every later PR has diagnosable #GP/#DF panics instead of hangs |
| aarch64 track under-estimated (DTB, GIC, vector layout) | M | M | Track B starts only after Track A acceptance; its own PR series + ADR; no deadline pressure to merge early |

**Size:** Track A ≈ 5 PRs (see `docs/STAGE1-PR-PLAN.md`), Track B ≈ 5 PRs;
focused effort ≈ 4–6 weeks total.

---

## Stage 2 — IPC (capability endpoints, nothing ambient)

**Goal:** domains talk only through capability-mediated endpoints: a
synchronous call/reply fast path, async endpoints, shared memory grants,
and signals; pipes become a wrapper over endpoints (the existing lib pipe
semantics preserved on top).

**Tasks:**
1. Endpoint objects with capability handles (grant/revoke via the existing
   generation-based capability table); no send without a valid cap.
2. Sync fast path: `call(dst_cap, msg) -> reply` — bounded, fixed-size
   messages, zero allocation, measured in cycles.
3. Async endpoints: per-domain queues with caps, non-blocking semantics.
4. Shared memory: page-grant IPC (`grant_frames(dst_cap, frames)`), pages
   mapped into the receiver's tables as RW-only, never executable,
   revocable.
5. Pipes reimplemented as endpoint wrappers; existing pipe tests ported.
6. Benchmarks: 100k ping-pong between two Ring-3 domains; frame/cap leak
   asserts after every iteration batch.

**File structure:** `kernel/src/ipc/{mod,endpoint,sync,async,shm,pipe_shim}.rs`,
`docs/ipc.md`, `examples/ipc-pingpong/`, `bench/ipc.rs`.

**Acceptance:** 100k Ring-3↔Ring-3 ping-pong < 1 s in QEMU TCG with
zero leaked frames/caps (asserted, printed); IPC without a cap is denied
+ audited; all prior gates still green.

**Risks:** fast-path allocation creep (gate: no-alloc assert in debug
builds) · cap-revocation races once SMP lands later (Stage 4 revisits
with per-CPU disabling) · message-copy cost under SMAP (STAC/CLAC around
bounded copies, measured).

**Size:** ≈ 8–10 PRs, ≈ 3–4 weeks.

---

## Stage 3 — Block Layer + Persistent Filesystem

**Goal:** a virtio-blk driver (PCI on x86_64, MMIO on aarch64) under a
block abstraction; ext2 with a WAL for crash consistency; the existing
VFS/DAC/chroot policy mounted over the disk; a `vfsd` domain owns the
device and grants per-file capabilities.

**Tasks:**
1. `BlockDevice` trait + virtio-blk (x86_64 PCI first, aarch64 MMIO
   after) with DMA to pool frames only (no ambient kernel buffers).
2. ext2 reader/writer (inodes, dirs, block groups) mounted at the VFS
   layer; existing Unix DAC/chroot tests re-run against disk-backed VFS.
3. WAL: intent-log writes before metadata commits; replay on mount;
   fsync semantics.
4. Crash-consistency harness: QEMU snapshot kill at WAL-critical points,
   remount, assert invariants (`scripts/crash-test.sh`).
5. Reboot-persistence test in CI: write → poweroff → boot → read →
   byte-identical.

**File structure:** `kernel/src/drivers/{mod,virtio/{mod,pci,mmio,blk}.rs}`,
`kernel/src/fs/{mod,ext2,block_cache,wal}.rs`, `docs/{block,ext2,wal}.md`,
`bench/fs.rs`.

**Acceptance:** write/read survives a QEMU reboot (CI); crash-test kills
at N injection points → zero fs corruption; a parser domain reads a file
end-to-end through capabilities only; read/write throughput numbers
recorded in CI.

**Risks:** virtio PCI enumeration complexity (start poll-mode, interrupts
come with Stage 4) · ext2 write-path scope creep (ext4 explicitly out of
scope; FAT32 read-only later if wanted) · DMA safety (bounce buffers from
the pool; the device never gets kernel-frame addresses).

**Size:** ≈ 10–12 PRs, ≈ 5–7 weeks.

---

## Stage 4 — Preemption + SMP

**Goal:** timer-driven preemption (1 ms tick) and multi-core (4 vCPUs)
with per-CPU run queues, IPIs, and RT classes — on both architectures.

**Tasks:**
1. LAPIC timer (x86_64) / ARM Generic Timer (aarch64); 1 ms tick; timer
   wheel for nanosleep/clock.
2. Preemptive CFS: per-CPU run queues, load balancing, the existing
   vruntime math; SCHED_FIFO/RR classes above CFS.
3. SMP bring-up (SIPI on x86_64, PSCI on aarch64), per-CPU domain state,
   TLB shootdowns via IPI for page-table revocations.
4. IRQ-driven virtio (convert Stage-3 polling) + serial input.
5. Latency benchmarks: CPU-bound starves I/O-bound ≤ 10 ms; RT wakeup
   latency < 1 ms (measured in-kernel, printed, CI-gated).

**File structure:** `kernel/src/arch/*/timer.rs`,
`kernel/src/sched/{rt,runqueue,ipi}.rs`, `docs/{smp,timers}.md`,
`bench/latency.rs`.

**Acceptance:** 4 vCPUs; the two latency numbers above measured and
CI-gated; no hangs under a fault-injection + SMP stress run; all prior
gates green on both arches.

**Risks:** TLB shootdown correctness (the classic SMP footgun — start
with synchronous shootdowns, simple and slow) · lock discipline in
no_std (ticket spinlocks, documented; no priority inheritance yet) · TCG
timing fidelity (gates use in-kernel cycle counts, not wall clock, where
possible).

**Size:** ≈ 8–10 PRs, ≈ 4–6 weeks.

---

## Stage 5 — POSIX Syscall ABI (Linux-compatible)

**Goal:** a Linux x86_64-compatible syscall surface (numbers, argument
registers, errno values) so unmodified static musl/busybox binaries run —
gated, per-domain, through the policy core. This is the stage that turns
the kernel into a usable Unix.

**Tasks (per ADR-0003):** a Linux-ABI dispatch table in front of the
policy gate (internal ids stay; entry numbers are Linux's): fork (COW via
per-domain table clone), execve (ELF64 + PIE + early ASLR), exit/wait4,
kill/sigaction/sigprocmask (full signal delivery, frames on the user
stack), open/close/read/write/lseek/stat/fstat, mmap/munmap/mprotect,
brk, pipe2, dup2, getpid/getppid, clock_gettime, nanosleep, ioctl; errno
model; user-string/path copy helpers; the `init` domain (uid 0, root
profile) launching `/sbin/init`.

**File structure:** `kernel/src/sys/posix/{mod,dispatch,exec,elf,signal,cow,mm,fs,proc}.rs`,
`docs/ABI.md`, `docs/ABI-VERSION.md` bumped to v1, `examples/{init,shell-min}/`,
`bench/syscall.rs`.

**Acceptance:** ≥ 80% of the musl libc test suite passes (statically
linked, run under QEMU, pass rate reported per CI run); busybox
`ls, cat, echo, ps, kill, sleep` work; fork/exec stress (1000 cycles)
with zero frame leaks; every new syscall is denied-by-default outside
its profile.

**Risks:** musl assumes Linux semantics we must approximate (fsync,
termios, a minimal `/proc` for `ps`) — scope is an explicit allowlist,
documented in ABI.md · COW fault-path correctness (fault-on-write →
copy → remap, audited by counts) · signal-frame ABI exactness (validated
against musl binaries before the gate).

**Size:** ≈ 12–16 PRs, ≈ 6–8 weeks (the biggest stage).

---

## Stage 6 — Driver Framework + Devices

**Goal:** a trait-based driver model with capability-gated device access:
virtio net/console/blk/rng, 16550 + PL011 serial, text framebuffer —
drivers run as restricted domains where possible, not ambient kernel
code.

**Tasks:** `Driver` trait + device registry owned by `devd`; virtio-net
(only `netd` holds NET_SEND/RECV and the device cap); virtio-console;
virtio-rng feeding the entropy pool (upgrades ASLR); framebuffer text
console; capability grants for exclusive device access; a
malicious-driver test (a bad driver gets quarantined, nothing else dies).

**File structure:** `kernel/src/drivers/{mod,registry,serial_16550,serial_pl011,virtio/{net,console,rng},fb}.rs`,
`docs/drivers.md`.

**Acceptance:** a UDP echo through virtio-net (the `ping` equivalent);
console I/O; text-mode screen output; the malicious-driver quarantine
demo; entropy-pool health stats printed.

**Risks:** MSI-X/interrupt routing on both arches (needs the Stage-4 IRQ
layer solid first) · net stack scope (no in-kernel TCP — netd brokers
frames; a user-space stack is out of scope) · GPU/fb variance (stick to
text-mode virtio-gpu 2D with a VBE fallback).

**Size:** ≈ 8–10 PRs, ≈ 4–6 weeks.

---

## Stage 7 — Hardening

**Goal:** close the gap between "works" and "hard": KASLR + user ASLR
(done right, with real entropy), stack canaries, optional CET (where the
platform provides it), W^X audit, a seccomp-like BPF filter layer over
the policy gate, a full audit trail, and a sustained fuzzing regime.

**Tasks:** KASLR (kernel slide from the Stage-6 entropy pool) + per-exec
ASLR (mmap base, stack, heap); kernel stack canaries (custom no_std
support); CET shadow-stack/IBT behind CPU feature detection; a
BPF-classic filter interpreter evaluated after the mask and before
dispatch (compiled once per domain); audit ring extraction (console +
`auditd` domain); Ed25519 verified image signing (secure boot path); a
syscall fuzz harness (an in-kernel structured fuzzer domain, coverage
counters, persistent corpus).

**File structure:** `kernel/src/hardening/{kaslr,canary,cet,bpf,entropy,sigverify}.rs`,
`docs/{hardening,threat-model,bpf}.md`, `fuzz/` (corpus + runner).

**Acceptance:** 72 h cumulative syscall fuzzing without a kernel panic
(honestly chunked — see risks); a threat-model document covering every
attack surface added by Stages 1–6; a BPF deny test (a filter blocking
`open` blocks it even for a profile that allows it); KASLR on/off boots.

**Risks (stated honestly):** **CET shadow stack is not supported under
QEMU TCG** — shipped feature-gated, exercised on KVM/CPU models where
available, CI asserts graceful absence otherwise · GitHub Actions caps
jobs at 6 h → the 72 h fuzz target is cumulative across nightly chunked
runs with a persisted corpus, reported as such · early-boot entropy
before virtio-rng is jitter-seeded and low — KASLR lands only after the
rng pool exists (a Stage-6 dependency, deliberate).

**Size:** ≈ 10–12 PRs, ≈ 5–7 weeks.

---

## Stage 8 — POSIX Compliance & Release

**Goal:** prove it: ≥ 90% of the Open POSIX Test Suite, complete ABI
documentation, a UNIX-certification feasibility study, and the v1.0
release.

**Tasks:** OPTS integration (build + run + report in CI; the report is
committed at `docs/reports/opt-results.md`); a gap-burn-down list;
`docs/ABI.md` finalized; the certification study (cost, LSB vs UNIX vs
Linux-ABI reality); release engineering (versioning, CHANGELOG, signed
images).

**Acceptance:** ≥ 90% OPTS pass rate with the report committed; ABI.md
complete and reviewed; v1.0 tagged with all prior gates green.

**Risks:** OPTS is old and assumes behaviors beyond our scope (the test
manifest is chosen explicitly and exclusions documented) · 90% may
require touching Stage-5 semantics late (a fix window is budgeted).

**Size:** ≈ 4–6 PRs, ≈ 3–4 weeks.

---

## Cross-cutting risk matrix

| Risk | Stage exposure | Mitigation |
|---|---|---|
| Scope explosion (the classic OS-project death) | all | Stage gates are CI-verified and non-negotiable; anything not in the stage's task list becomes an ADR + roadmap entry, not a surprise PR |
| Regression of the 219-test core | all | Every PR runs the full suite + QEMU boot test; bench gates fail CI on > 5% hot-path regressions |
| unsafe creep | all | Allowlist + a committed unsafe-count baseline (`scripts/unsafe-count.txt`); CI fails if the count grows without a matching ADR (see CONTRIBUTING.md) |
| Coverage claims we cannot measure on bare metal | all | ≥ 80% coverage measured by `cargo llvm-cov` on host-testable logic crates; boot/arch paths covered by marker-grepped QEMU integration tests — the split is stated, not blurred |
| Dual-arch divergence | 1B onward | Shared `kernel/src` core; arch code isolated under `arch/`; both arches in CI from Stage 1B |
| Single-maintainer bus factor | all | ADRs + per-component docs + CONTRIBUTING from day one; small PRs |

## Estimated totals

≈ 65–80 PRs, ≈ 34–48 weeks of focused effort. Stages 1–5 deliver a
kernel a developer can actually use; 6–8 make it robust and provable.

---

## History (superseded milestones)

- **M0 (DONE, v0.1.0):** the policy core + Linux-like semantics library,
  191 tests, zero deps, `forbid(unsafe_code)`, no_std proven on
  thumbv7em.
- **M1 (DONE, v0.2.0):** two-stage boot on QEMU x86_64, real frame pool
  with scrub-on-free, kernel-resident domains, `Kernel::destroy_domain`,
  the M1 exit-criteria boot test in CI (measured: 0.21 s wall-clock).
  Details and honest boundaries: `docs/M1-PLAN.md`.
