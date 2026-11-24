# AegisOS

**A secure OS core that actually boots: a `no_std`, zero-dependency policy kernel with Unix-philosophy semantics (VFS with Unix permissions and chroot, pipes, signals, fd tables, CFS scheduling, buddy allocator, brokered sockets) under strict per-domain isolation, a graduated behavior-driven security monitor — and a bootable x86_64 kernel that runs it all on real hardware memory.**

[![CI](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests: 760](https://img.shields.io/badge/tests-760%20passing-brightgreen.svg)](tests/)
[![Boot](https://img.shields.io/badge/boots%20in%20QEMU-ring--3%20isolation%20live%20%F0%9F%9F%A2-brightgreen.svg)](#quick-start)

> The name: **Aegis** (the shield). One rule shapes the whole design: everything runs inside an isolated `Domain`, and every privilege is granted once and can only ever shrink.

## Current status — honestly stated

- **The attenuation/security hardening round (ADR-0031 §A+§B, ADR-0032 §A/§B/§C, ADR-0033, + the exec image quota)** — six reviewer-found holes, each reproduced red, fixed, and guarded: **(1) sigreturn frame flag forgery (ADR-0031 §A)** — a CPL=3 domain can `pushfq`/`popfq` IF=0+AC=1 and sigreturn it into its own kernel-side frame; the resume path now whitelists the saved frame's flag bits, the restored context is always preemptible, and entries never inherit AC (the entry's gated `clac`, on `ENTRY_CLAC_GATE`). **(2) the entry never runs on user flag state (ADR-0031 §B)**: `cld` right after `cli`, an explicit RFLAGS sanitize (TF|IF|DF|NT|AC cleared through the pushed slot — pinned by a new asm-pattern guard rule), a **safe IST7 `#DB` handler** (the pure `classify_debug`: a user-set TF surviving SYSCALL traps inside the entry window → clear-TF-in-the-saved-frame and resume; ring-3 traps stay the domain's own death; everything else fails CLOSED to the forensics dump), and honest per-flag measurement: FMASK reads back exactly what was written yet the kernel still self-enforces every bit (DF is cleared at the TCG transition; AC and IF are not). Blob mode 18: DF/TF/AC rogues make copy-heavy excursions — payloads byte-exact, the TF rogue dies by its own trap in either reading, the kernel never halts. **(3) spawn attenuates on EVERY axis (ADR-0032 §A)** — `DomainProfile::is_attenuation_of`, a pure, exhaustively-destructured relation (adding a field breaks the build until it's classified): mask vs the parent's LIVE mask, quota vs LIVE quota, monitor sensitivity, the Tighten tier (strictly narrower, always keeping exit), fan-out strictly below, base rights never broader — before, a `max_children=2` parent ACCEPTED `sensitivity=0`+`degraded=syscalls`+`max_children=1000`; every axis violation is now a typed reason + an escalation attempt. **(4) exec ratchets, policy by IMAGE identity (ADR-0032 §B)** — the monitor mode can never turn off across exec (once Enforce, always; `None` = inherit for unlisted images), and the policy table is keyed by a 64-bit content hash of the image bytes, never a path string, with lexical `canonicalize_path` before the registry lookup — `//bin/./x` and `/bin/../bin/x` cannot dodge a declared policy. **(5) per-frame reference counts (ADR-0032 §C)** — the shared-frame table was a linear 64-entry array that capped the WHOLE SYSTEM at 64 shared pages (any fork of a >64-page domain was refused, with the wrong error variant, and the rollback silently leaked); it is now dense per-frame counts indexed by pool frame number — O(1), u16 checked (typed Overflow), rollback = exact tree rewalk, and a 2000-page fork is host-proven. **(6) ELF entry executable + exact `e_phoff`, and the exec image quota (ADR-0033 + N2)** — mutation fuzzing found 118 accepted images whose `e_entry` pointed into a NON-executable segment (dead on the first NX fetch); now refused typed, along with `e_phoff != 64`. And every program was capped at a hard-coded 16 pages by the exec mapper — the quota is now the caller's LIVE profile quota with a pure pre-check BEFORE the point of no return (an over-quota exec answers `-ENOMEM` with the old image intact — proven live by a five-page domain exec'ing the six-page shell). All lanes re-proven: `--verify` (every marker byte-exact), q35, q35-noiommu, and the shell lane green; the persist lane hits the documented ADR-0030 flake-family timeout. The round closes with **three seeded fuzz harnesses** (round A6/ITEM 8): the syscall storm (240k hostile ops — zero panics, zero mask-widening, live), the lifecycle storm (240k spawn/fork/exec/kill/exit ops — 17.8k guaranteed-widening spawn attacks, ALL refused; the exec monitor ratchet held), and the ELF mutation fuzzer (300k mutations of the two REAL registry images — 108k accepted plans, every loader invariant re-derived and held, 192k typed refusals).
- **M3: writable persistence, the TTY, and a CPL=3 shell (Phase 6 + Phase 7 / ADR-0025/0030)** — the ext2 write path runs over an honest raw-image store (`mkext2-rw`), and `--verify-persist` boots the SAME disk twice: boot 1 writes `persist.txt`, boot 2 reads it back through a second vblk session (frames from the image, one branch, no shortcuts). The TTY is serial RX by interrupt with a ring and a console-in alias; PID 1 runs at CPL=3 with the init pattern (fork, orphan reparenting, a blocking `wait4(-1)` loop reaping both children — ADR-0022 D7), `list_dir` gives the shell its `ls` (v1: `getdents64(259)`), and `--verify-shell` drives the whole interactive stack green. The ELF loader + `execve` are live (the registry's `/bin/sh` and `/bin/exec-target`, image-identity-keyed policy), fork + CoW are live (mode 13's fork-with-CoW-store, and the fork/write/exit model with Copy/Promote transitions), and the timer-preemption machinery landed with its ADR-0012 environment measurement (TCG does not apply `FMASK.IF` across SYSCALL — the entry self-enforces).

- **The Linux-compatible entry, slice 1 (round S / ADR-0003 / ABI-VERSION v1)**: a domain can now speak **Linux x86_64 syscall numbers at the entry**. A per-domain ABI flag (`Internal` default | `Linux`, supervisor-declared at spawn, inherited across fork) picks the number translation — a **whitelist**, not a pass-through, running BEFORE the bounds check and the policy gate; internal ids stay the policy space, so profiles never see a Linux number. The whitelist's edge is the round's found-live discovery: Linux nr 63 is `uname` while internal 63 is EXIT — a pass-through would exit a Linux binary on `uname()` — so every unmapped nr (including all sub-64 collisions) answers `-ENOSYS`, audited on the live domain. Shape differences are honored at the arm: `pipe(2)` answers rax=read/rdx=write (the x86_64 convention), `exit_group(231)` aliases exit, `mmap(2)` demands MAP_PRIVATE|MAP_ANONYMOUS; **Slice 2 (round T) landed `open(2)`**: the Linux O_* word is translated at the SYS_OPEN arm — the access mode (RDONLY=0, WRONLY=1, RDWR=2) becomes the internal O_READ/O_WRITE bits, O_CREAT and O_TRUNC ride along, and every bit whose semantics the internal VFS cannot honor (O_EXCL, O_APPEND, O_NONBLOCK, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC) refuses `-EINVAL` — never silently dropped. **Slice 3 (round U) landed `wait4(2)`** on the ADR-0022 D7 core (`wait_process`/`exit_process` were waiting in the lib since round K): the blocking path parks with the **rip-2 re-execute image** (rip ON the syscall instruction, rax = the ORIGINAL nr from the frame's RAX slot — resume re-runs the arm; the park machinery stays ABI-blind), the child's completion wakes the parent through the waiter registry (`set_runnable`, nanosleep's own primitive), the re-executed arm consumes the child's completed-mailbox entry (frames via `free_frames_of`, then `exit_process` records the zombie) and answers the pid + the Linux wstatus word (7 << 8); WNOHANG honored, unknown option bits refuse, and a CoW-RO wstatus target answers `-EFAULT` loudly (the kernel's direct write cannot service a CoW the user's own store would). (This bullet's `execve` refusal note is history: the ELF loader landed in M3 — see the exec/persistence bullet below.) Blob mode 13 proves the whole lane from CPL=3 speaking only Linux nrs — the pipe split, a byte round-trip, EOF after the write end closes, mmap + the MAP_SHARED refusal, the uname/getpid probes, fork with a CoW child store — red (nr 22 hit internal SCHED_YIELD, zero clean exits) then green on all three QEMU lanes.

**Done and proven (M0 + M1 + Stage 1 / PR-1.1..1.4 + M2-W1/W2):**

- The full policy kernel as a library: attenuation-only syscall masks, capability generations, W^X memory policy, VFS with Unix DAC + chroot, pipes/signals/fd tables, CFS scheduling, rate-limited brokered sockets, capability-endpoint async IPC (ADR-0004), behavior monitor with graduated response. **434 tests.**
- A bootable x86_64 system, two-stage (QEMU's `-kernel` loader rejects ELF64 — discovered on the first CI boot run): a pure-asm ELF32 multiboot stub (`boot-x86_64/`) sets up identity paging and long mode, then runs the 64-bit kernel (`kernel-x86_64/`, embedded at its 2 MiB link base) over real RAM: a physical frame pool (4096 × 4 KiB at 16..32 MiB, grown for per-domain page tables in PR-1.3) behind the policy core's buddy allocator with **scrub-on-free verified by read-back**, and the M1 exit-criteria sequence running on boot: a hello domain scheduled by CFS, the monitor escalating an attacker across five windows while the healthy neighbor keeps running, and 1000 create/destroy cycles with zero frame leaks.
- **SYSCALL/SYSRET entry + ring-3 machinery (Stage 1 / PR-1.4 + M2-W2/ADR-0010 + round J)**: the GDT carries the STAR slot arithmetic (host-test-pinned), the naked SYSCALL entry (swapgs, dedicated guarded stack, 12-quadword SysV-aligned frame, TSC round-trip, the user-RSP park/restore — SYSRET reloads only RIP/RFLAGS, so the stub carries the user's stack pointer itself; hidden since PR-1.4, exposed by the first `call` in ring-3 history), the shared policy gate in `syscall::gate` (one door for kernel-resident and ring-3 domains, full-width nr bounds check), SYS_WRITE with per-page user-pointer validation, and the CPL3-fault record/resume path. **Ring-3 isolation is fully live**: the eight-run sequence (hello / NX exec / kernel-VA read / forged syscall / tail-of-page + crossing writes / live-monitor quarantine / audit-only / the file lifecycle) boots green in QEMU TCG and `boot.sh --verify` asserts every marker — the earlier "environment-blocked" verdict was retired when its four root causes (stray IRQ at the IF boundary, mirror-inverted stub offsets, the launch/resume register hole, an `iretq` regression) were all found and fixed locally (ADR-0010).
- **The ring-3 file lifecycle (round J)**: OPEN, READ, WRITE, CLOSE, PIPE and DUP execute on the LIVE lib kernel — marshaled through the host-tested `sysabi` layer (the open-flag decoding, the complete SysError→errno table, the pipe fd-pair packing) and run by `Kernel::execute` on the same state the monitor reads, after the runtime's own gate pass. The stdio triplet (fds 0/1/2) is reserved at spawn Unix-style so the console device alias behind fd 1 can never collide with a real descriptor; user pointers are validated page-by-page through the domain's own tables in BOTH directions (the copy-out primitive and the page-check-as-you-go path reader are new), and the `ring3-files` blob proves the whole dance from CPL=3 with in-blob verification: pipe round-trip, dup keeping a pipe end alive past its original's close, file create/write/read-back through an independent cursor, and the -EBADF/-ENOENT refusals. The register tables — v0.4's internal surface and v1's Linux entry — are specified in `docs/ABI-VERSION.md`.
- **Per-domain page tables (Stage 1 / PR-1.3)**: the lib's ten-check memory policy is the gate, and its decisions become hardware — `map_region` policy-checks first, then backs every accepted page with a scrubbed pool frame and a live PTE (U set, NX unless executable, guard gaps as **absent** pages). Two domains, disjoint tables, the same VA resolving to different frames — proven live in QEMU, including an NX exec fault that resumes cleanly and a guard-gap read that faults with CR2 naming the page. Pool grows to 4096 frames (16..32 MiB); `mm` stays unsafe-free. **11 new host tests** pin the walk, the policy gating, and unmap/rollback.
- **Higher-half kernel + direct map (Stage 1 / PR-1.2, ADR-0002)**: the kernel links at `0xFFFFFFFF80000000` (loaded at PA 2 MiB via a linker `AT()` + objcopy-by-LMA split), the stub maps three windows before entry — kernel image, direct map (`0xFFFF888000000000`+PA, RW, never X), and a bring-up identity window the kernel **tears down and proves dead** right after entry. Guarded kernel stacks (absent-PTE guard pages, pool-backed, scrub-on-free) fault for real when run over; per-CPU state is anchored at the GS base. The `mm` layer itself is unsafe-free by design. **7 new host tests** pin the translation and slot arithmetic.
- **Exception machinery (Stage 1 / PR-1.1)**: a kernel-owned GDT/TSS/IDT with a uniform exception frame, IST stacks for `#DF/#NMI/#MC/#SS`, and a live negative test — the boot forces a hardware `#DE` and the dispatch prints the diagnosis and the selftest marker before powering off. Every fault from here on is diagnosed, not a silent hang. **11 new host tests pin the descriptor/frame encodings, including the boot-stub GDT literals as an ABI contract.**
- Unsafe policy enforced by machine, not convention: the policy core is `forbid(unsafe_code)`; the kernel is `deny(unsafe_code)` with a five-entry allowlist (`arch/`, `boot/`, `hw.rs`, `memops.rs`, `sched/`), every item carrying a `SAFETY` note, and a **ratchet** (`scripts/unsafe-count.txt`, baseline 78) that fails CI if the count grows without an ADR.

**Not yet (see [`docs/GAP-ANALYSIS-v2.md`](docs/GAP-ANALYSIS-v2.md), the master plan):** the REST of the ring-3 syscall surface (SPAWN/IPC/NET answer -ENOSYS at the ring-3 entry; the file family, MMAP/MUNMAP, KILL, CHROOT, MKDIR/UNLINK, LISTDIR, fork/exec and the wait family are live), real networking, musl/userland, and the second architecture (aarch64 — the HAL seam is designed in ADR-0011, enforced in CI by cross-arch builds of the core). Timer-preemption machinery, the ELF loader, fork+CoW and ext2 persistence are LIVE (see the bullets above); storage (AHCI/NVMe/virtio-blk + ext2 read/write, FAT32 read-only) is live on the driver-stack lanes. Fuzz harnesses for the syscall storm / lifecycle / ELF loader are the next item in flight. KVM and real hardware: not run in this sandbox (TCG only).

## The architecture in one line

> Unix gave us clarity, separation of concerns and stable interfaces; AegisOS adds one unbreakable rule on top: **attenuation-only privileges** — there is no code path anywhere in the kernel that can widen a live domain's syscall mask.

## Quick start

```bash
./boot.sh                 # build the kernel and boot it in QEMU (needs qemu-system-x86)
./boot.sh --verify        # ...and assert EVERY marker: M1 + selftests + ring-3 + M3 (persist-excluded)
./boot.sh --verify-q35    # the same machine on the q35 chipset
./boot.sh --verify-q35-noiommu   # q35 with the IOMMU off (the SMAP/NXE quirks differ)
./boot.sh --verify-persist  # TWO boots, one disk: boot 1 writes persist.txt, boot 2 reads it back
./boot.sh --verify-shell    # PID 1 + the TTY + the shell's ls/exec round-trip

cargo test                       # 464 policy-core tests
cargo test -p aegis-kernel       # 293 host tests: boot + arch/mm/gate/ring-3/sysabi/file-ABI/elf encodings
cargo build --target thumbv7em-none-eabihf   # the core still builds for bare-metal ARM
```

What the boot log shows (CI greps exactly these): the GDT/TSS/IDT going live, the higher-half switch (`[MM ] higher-half ok`, identity window torn down), multiboot memory validation, the frame pool claim, the guard-gap policy rejecting an adjacent mapping **live**, CFS slices, `Hello from AegisOS domain 1`, the five-window escalation `55 → 50 → 37 → 80 → 80` ending in quarantine with the neighbor healthy, `leaked-frames=0`, `scrub-verified=yes`, a single `M1-EXIT-CRITERIA: PASS` verdict line — then the selftests: a forced hardware `#DE` diagnosed and **returned from** (the unwind path Ring-3 signals will use); two domains with disjoint page tables — the same VA resolving to different frames, an **NX exec fault that resumes** (W^X enforced by the MMU), an RX page actually executing, and a policy guard-gap page faulting on read (`[MM ] per-domain tables: 2 domains, W^X + guards live`); a guarded kernel stack allocated/mapped/cross-viewed/freed-scrubbed; and a final write through a stack guard page → `#PF` → clean poweroff.

## What's inside

| Area | Module | Linux analog | Key invariants |
|---|---|---|---|
| Syscall gate | `syscall` | syscall table + seccomp | `u64` bitmask, O(1) AND+bit-test; masks only ever attenuate |
| Capabilities | `capability` | capabilities(7) | Generation counters make use-after-revoke impossible |
| Memory policy | `memory` | mmap + W^X | NULL/wraparound/overlap rejection, guard gaps, quotas, scrub accounting |
| Page frames | `buddy` | buddy allocator | Power-of-two blocks, split on alloc, coalesce on free |
| Boot + frames | `kernel-x86_64` | boot/paging | Multiboot → long mode → identity map; real pool, owner tracking, scrub-on-free |
| CPU tables + exceptions | `kernel-x86_64/src/arch` | GDT/TSS/IDT | Uniform frame, IST for #DF/#NMI/#MC/#SS (not #PF), DPL-0 gates, stub GDT = boot ABI |
| Memory layout | `kernel-x86_64/src/mm` | higher-half + direct map | Kernel at 0xFFFFFFFF80000000, direct map RW no-X, guarded stacks (absent-PTE guards), identity window torn down — unsafe-free |
| Filesystem | `vfs` | VFS + DAC + chroot(2) | owner/group/other `rwx`, execute-to-traverse, `..` clamped at chroot root |
| Descriptors | `fd` | open file table | lowest-free allocation, dup2 semantics |
| Pipes | `pipe` | pipe(2) | bounded ring, short I/O, EOF, EPIPE, dup-aware end refcounts |
| Signals | `signal` | signal(7) | pending/blocked masks, unblockable SIGKILL/SIGSTOP |
| Scheduling | `sched` | CFS | vruntime + the real Linux nice→weight table |
| Network | `net` | sockets + tc/tbf | brokered sockets, per-domain token buckets |
| Profiles | `profile` | service types | service / parser / driver / plugin / netd — least privilege |
| Monitoring | `monitor` + `response` | auditd/ML security | integer risk score, hysteresis, Log → Tighten → Quarantine |
| Telemetry | `ringbuf` | relay/perf rings | SPSC, drop-and-count when full — never blocks |

## The syscall pipeline

```text
            ┌──────────────────────────────────────────────────┐
            │  Kernel::syscall(domain, request)                │
            └───────────────┬──────────────────────────────────┘
                            │  1. GATE (deterministic fast path)
                            │     bounds check → quarantine check
                            │     → mask bit test → saturating counters
                            ▼
            allowed? ── no ──► Masked / Quarantined / BadSyscall
                            │  2. EXECUTE (Linux-like state)
                            ▼
     VFS (Unix perms, chroot) │ fd table │ pipes (refcounted ends)
     signals (kill rules)     │ sockets + token buckets │ scheduler
                            │  3. TELEMETRY
                            ▼
     SecurityEvent ring → behavior monitor (slow path, per window)
                       → Log → Tighten → Quarantine (EXIT-only, terminal)
```

On the booted kernel, all of this sits on real memory: `_start` → long mode → frame pool → `Kernel::new()` → the M1 sequence (see `kernel-x86_64/src/kmain.rs`).

## Behavior monitor (the security layer)

Five real signals from the fast path — denied ratio, faults, capability-escalation attempts, out-of-profile syscall bits, rate spikes — feed an integer-only risk score (u128 intermediates, deterministic, overflow-proof). Graduated response with anti-flap: a single bad window never escalates (hysteresis), reported scores decay, tightening keeps the app alive (it only drops spawn/net/ioctl/mmap/open), quarantine is terminal and passes only `SYS_EXIT`. If the monitor's state table fills, it degrades to logging — but instant quarantine at score ≥ 95 still fires. Fail-safe, not fail-open. On boot, the proven five-window escalation scenario runs live and its verdicts are printed.

Docs: [`docs/ROADMAP.md`](docs/ROADMAP.md) (roadmap v2: the eight stages to a usable Unix-like core) · [`docs/STAGE1-PR-PLAN.md`](docs/STAGE1-PR-PLAN.md) (the current stage, PR by PR) · [`docs/arch/exceptions.md`](docs/arch/exceptions.md) (PR-1.1 component doc) · [`docs/adr/`](docs/adr/) (architecture decision records) · [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) · [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/M1-PLAN.md`](docs/M1-PLAN.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) (the PR contract) · [`docs/ABI-VERSION.md`](docs/ABI-VERSION.md)

## Roadmap position

The master plan is now [`docs/GAP-ANALYSIS-v2.md`](docs/GAP-ANALYSIS-v2.md) (phases to the full production brief, ≈28 weeks of the current cadence); [`docs/ROADMAP.md`](docs/ROADMAP.md) keeps the stage detail and [`docs/M2-PLAN.md`](docs/M2-PLAN.md) the current milestone. **Current position: Stage 1 + M2 + the M3 security-hardening round complete (ADR-0031 flag hygiene live in the entry and the sigreturn path, ADR-0032 attenuation as a checked relation — spawn/exec/fork, ADR-0033 ELF hardening, persistence + TTY + shell + exec/ELF live); next: the fuzz harnesses (syscall storm / lifecycle / ELF mutations), then real networking and the aarch64 bring-up.** Multi-architecture is designed (ADR-0011: HAL/BSP seam) and enforced by CI cross-arch builds of the policy core.

## Repository layout

```text
boot-x86_64/              stage 1: the ELF32 multiboot boot stub (pure asm)
├── stub.S                  GDT, identity paging, long mode, kernel handoff
└── stub.ld                 1 MiB stub + kernel blob at its 2 MiB link base
kernel-x86_64/            stage 2: the bootable M1 kernel (x86_64)
├── linker.ld               2 MiB link base, pinned entry, 256 KiB stack
├── build.rs                -T linker script only for the bare-metal target
└── src/
    ├── arch/              UNSAFE ALLOWLIST (ADR-0005): GDT/TSS/IDT + exception entry
    ├── boot/               UNSAFE ALLOWLIST: naked 64-bit entry
    ├── hw.rs               UNSAFE ALLOWLIST: port I/O, rdtsc, cr2, poweroff
    ├── memops.rs           UNSAFE ALLOWLIST: volatile memory + scrub
    ├── serial.rs           COM1 output (safe, over hw primitives)
    ├── multiboot.rs        pure multiboot-info parsing (host-tested)
    ├── frames.rs           FramePool: owners + scrub over the core buddy
    ├── runtime.rs          the M1 sequence (host-tested, callback-driven)
    └── kmain.rs            live boot: validate → claim → run → verdict
src/                      the policy core (this is the aegis-os crate)
├── syscall.rs    capability.rs    memory.rs    buddy.rs
├── vfs.rs        fd.rs            pipe.rs     signal.rs
├── sched.rs      net.rs           profile.rs  domain.rs
├── monitor.rs    response.rs      ringbuf.rs  sys.rs
└── lib.rs        Kernel assembly (domains, VFS, scheduler, monitor)
tests/
├── integration.rs   security scenarios (escalation, isolation, telemetry)
└── linux_like.rs    Linux-semantics scenarios (VFS/pipe/signal/sched/net)
boot.sh                 one command: build + boot (+ --verify proof mode)
scripts/check_unsafe.sh the unsafe-allowlist policy + ratchet (CI-enforced)
docs/                   roadmap, stage plans, ADRs, component docs
```

## License

MIT — see [LICENSE](LICENSE).
