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

**Execution plan:** stages 2–4 (plus full Ring-3 dispatch, ELF loader,
demand paging/COW, configurable limits) are scheduled week-by-week in
[`docs/M2-PLAN.md`](M2-PLAN.md); the **full-scope plan to production
readiness (all seven areas, multi-architecture first-class) is
[`docs/GAP-ANALYSIS-v2.md`](GAP-ANALYSIS-v2.md)**, and the architecture
seam it depends on is designed in
[`docs/adr/0011-multi-architecture-hal-bsp.md`](adr/0011-multi-architecture-hal-bsp.md).

Mapping: Ring-3 → Stage 1 · IPC → Stage 2 · block+FS → Stage 3 ·
preemption/SMP → Stage 4 (the *preemption half* of Stage 4 is pulled
into M2-W2 — a starvable system cannot pass M2 exit criteria; SMP
stays) · POSIX ABI → Stage 5 · drivers → Stage 6 · hardening
(ASLR/audit) → Stage 7 · compliance → Stage 8.

## Current state (the honest baseline)

**Done and CI-proven:** the full policy core (attenuation-only masks,
capability generations, ten-check memory policy, in-memory VFS + Unix DAC
+ chroot, pipes, signals, fd tables, CFS, buddy allocator, rate-limited
brokered sockets, capability-endpoint async IPC, behavior monitor with
graduated response) — 331 lib tests; a bootable two-stage x86_64 kernel
(ELF32 multiboot stub → ELF64 kernel) with a real 4096-frame pool,
scrub-on-free verified by read-back, per-domain page tables, SMEP/SMAP,
kernel-image W^X, SYSCALL/SYSRET ring-3 entry (with the user-RSP
park/restore round J exposed and fixed), and the eight-run ring-3
sequence asserted by the CI boot test — the eighth run is the file
lifecycle (OPEN/READ/WRITE/CLOSE/PIPE/DUP live on the lib kernel,
round J) — 265 kernel host tests; 596 total,
zero external dependencies, unsafe confined to the allowlist (arch/,
boot/, hw.rs, memops.rs, sched/ — as defined in scripts/check_unsafe.sh,
ratcheted at 101).

**Round 6 ("G", ADR-0019/0020):** the interrupt chain is live —
the broker-owned device vectors (49..=112), the IOAPIC line path
(the QMP key delivers end to end), x2APIC, virtio-net on MSI-X, and
VT-d interrupt remapping through broker-owned IRTEs (the
`--verify-q35-ir` lane) — plus multi-bus PCI over the ECAM seam
(devices behind root ports claim domains), FADT-sourced
power-off/reboot, HPET-calibrated TSC, live entropy sources
(RDRAND/RDSEED + virtio-rng), MONITOR/MWAIT idle, and GPT partition
parsing under the ext2 mount.

**Round 7 ("I"):** the EFI System Partition mounts — read-only
FAT32 (checklist item 16, the roadmap's sanctioned "later if
wanted"), with the policy core owning every bound: BPB validation
with the spec's own type determination (< 65525 clusters = refused
as `NotFat32`), the cluster-chain walk and its structural
termination proof (a loop-back re-reads a bounded cluster and still
ends; short chains and volume-long files refuse), 8.3 dirents with
hostile-refusal semantics — 7 host tests + a 2000-image fuzz.
`mkfat32.py` grows the ext2 disk with an honest 65600-cluster ESP as
GPT partition 2; the transport rides the LIVE AHCI port and reads
HELLO.ESP head-to-tail across three clusters on BOTH lanes. En
route, the hidden lane debt of rounds 6–H was paid: the CPUID RBX
destruction (the "bulletproof" push/store/pop pattern destroyed the
caller's callee-saved RBX — allocation luck decided when a release
build faulted on it; `xchg` restores the register while extracting
the word), the ECAM seam's missing third-GiB direct-map mapping (the
first q35 config read #PF'd — `mm::map_gib_windows` fixes it, span
math host-tested), the unclaimed-virtio DMA failure (rng/console/
balloon drove with dom 0; an unclaimed device's DMA fails closed at
the IOMMU — every completion timed out while claimed vblk/vnet
beside them completed; the three now walk the claim gate), the `..=`
GPT marker mismatch that kept every lane red since round 6 (and hid
all of it), the G/H fmt debt (1407 lines), and the q35/IR lane
timeouts (240s→600s: the M2 syscall audit alone emits ~390k lines
before the driver stack starts).

**The storage-modernization path (recorded here per the
scope-explosion rule; nothing below is claimed until its lane
proves it):** the block stack's stated direction is parity with the
modern Linux storage stack, one honest slice at a time —
(1) **ext4 read-only with extents** (the Linux default filesystem;
the extent-tree parser joins `aegis_os::ext2` in the policy core,
same fuzz discipline, rides the same AHCI port);
(2) **NVMe I/O queues live** (the admin qpair is proven; the prp1
anomaly — commands complete but identify lands at PA 0 — is the
documented open item; fixing it unlocks the modern multi-queue
interface the kernel already speaks at the admin level);
(3) **TRIM/DEALLOC** (DSM on SATA, DEALLOCATE on NVMe, DISCARD on
virtio-blk — the freed-page discipline the allocator's
scrub-on-free already enforces in DRAM, extended to the medium);
(4) **an async block interface** (submission/completion rings in
the driver-domain style of ADR-0004 — the io_uring-class model,
adapted to the capability-gated IPC the kernel already runs);
(5) **xHCI enumeration** (Enable Slot → Address Device → the
device descriptor, on the TRB machinery that is already proven).
Each slice lands only with its host tests, its lane marker, and its
honest-absence line on machines without the device.

**Not present at all (each gets its stage below):** timer interrupts and
preemption, SMP, demand paging/COW, the ELF loader, the full ring-3
syscall surface, block devices, on-disk filesystems, real networking,
the POSIX ABI surface, drivers, IOMMU, ASLR/KASLR, a seccomp-style
filter layer, compliance suites, and the second architecture (the HAL
seam of ADR-0011 — enforced in CI by cross-arch builds of the core —
with aarch64 bring-up as its Phase 2).

---

## Stage 1 — Ring-3 Isolation (the wall between kernel and user)

**Goal:** a user domain runs at CPL=3 on x86_64 with its own page tables;
the kernel enforces W^X, guard pages, and SMAP/SMEP; syscalls enter via
SYSCALL/SYSRET; unauthorized syscalls and memory faults become SIGSEGV
with an audit record. Track B (aarch64: EL1/EL0, SVC, PAN) brings the
second architecture to the same bar, and CI grows the aarch64 job.

**Status (M2-W2/ADR-0010):** the ring-3 machinery is now fully live —
   seven runs end to end in QEMU TCG (hello / NX / kernel-VA / forged
   syscall / edge writes / live-monitor quarantine / audit-only), the
   "environment-blocked" verdict retired (it was four local bugs), and
   `boot.sh --verify` accepts only the full outcome. The Stage-1 items
   that remain (full syscall surface from Ring-3, SMP) carry into M2
   weeks 2–3 per `docs/M2-PLAN.md`.

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

**Status (round Q, ADR-0029):** ALL SIX TASKS DONE. Async endpoints
(M2 week 1, ADR-0004) → ring-3 async (ADR-0025) → sync call/reply
over the park machinery (ADR-0026) → page grants (ADR-0027) → the
honest bench with measured numbers (ADR-0028) → **pipes as endpoint
byte channels (ADR-0029)**: the ambient `PipeTable` is deleted, the
ring engine rides inside `EndpointTable`, `pipe()` at the ABI creates
a channel endpoint (fds carry the endpoint id, F18 untouched — no cap
minting), and the cross-domain byte path (`pipe_read`/`pipe_write`,
internal nrs 30/31) is capability-gated with the
wake-without-consume rendezvous. ABI-VERSION v0.4 documents the full
internal surface with the Linux collision ledger.

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

**Status:** slice 1 LIVE (round S, ABI-VERSION v1) — the per-domain
ABI flag (`Abi::Linux`, supervisor-declared, fork-inherited) and the
**whitelist** translation table at the entry (translation before the
bounds check and the policy gate; unmapped nrs — including every
sub-64 collision, e.g. Linux's uname 63 vs the internal EXIT 63 —
answer `-ENOSYS` audited). Shape differences honored: pipe's
rax/rdx split, exit_group's alias, mmap's PRIVATE|ANON-only flags.
**Slice 2 (round T) landed `open(2)`**: the Linux O_* word translates
at the SYS_OPEN arm (access mode → O_READ/O_WRITE, O_CREAT/O_TRUNC
ride along; O_EXCL / O_APPEND / every un-honorable bit refuses
-EINVAL, never silently dropped), proven by blob mode 13 on all
three lanes — create / write / close / O_RDONLY reopen with
read-back, and both refusal probes. **Slice 3 (round U) landed
`wait4(2)`** on the ADR-0022 D7 core: the blocking path parks with
the rip-2 re-execute image (resume re-runs the arm; rax carries the
ORIGINAL nr from the frame's own RAX slot — found live: the
translated nr made the re-executed entry answer -ENOSYS), the
child's completion wakes the parent through the waiter registry, and
the re-executed arm consumes the completed entry (frames via
`free_frames_of`, then `exit_process` records the zombie) and
answers the pid + the Linux wstatus word; the blob proves
WNOHANG/block/reap (7 << 8)/ECHILD on all three lanes. Still ahead:
the execve arm (the ELF loader), the errno model's full sweep, and
the musl / busybox acceptance runs below.

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
