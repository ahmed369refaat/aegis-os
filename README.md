# AegisOS

**A secure OS core that actually boots: a `no_std`, zero-dependency policy kernel with Unix-philosophy semantics (VFS with Unix permissions and chroot, pipes, signals, fd tables, CFS scheduling, buddy allocator, brokered sockets) under strict per-domain isolation, a graduated behavior-driven security monitor — and a bootable x86_64 kernel that runs it all on real hardware memory.**

[![CI](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests: 237](https://img.shields.io/badge/tests-237%20passing-brightgreen.svg)](tests/)
[![Boot](https://img.shields.io/badge/boots%20in%20QEMU-higher--half%20kernel%20green-brightgreen.svg)](#quick-start)

> The name: **Aegis** (the shield). One rule shapes the whole design: everything runs inside an isolated `Domain`, and every privilege is granted once and can only ever shrink.

## Current status — honestly stated

**Done and proven (M0 + M1 + PR-1.1 + PR-1.2):**

- The full policy kernel as a library: attenuation-only syscall masks, capability generations, W^X memory policy, VFS with Unix DAC + chroot, pipes/signals/fd tables, CFS scheduling, rate-limited brokered sockets, behavior monitor with graduated response. **196 tests.**
- A bootable x86_64 system, two-stage (QEMU's `-kernel` loader rejects ELF64 — discovered on the first CI boot run): a pure-asm ELF32 multiboot stub (`boot-x86_64/`) sets up identity paging and long mode, then runs the 64-bit kernel (`kernel-x86_64/`, embedded at its 2 MiB link base) over real RAM: a physical frame pool (256 × 4 KiB at 16 MiB) behind the policy core's buddy allocator with **scrub-on-free verified by read-back**, and the M1 exit-criteria sequence running on boot: a hello domain scheduled by CFS, the monitor escalating an attacker across five windows while the healthy neighbor keeps running, and 1000 create/destroy cycles with zero frame leaks.
- **Higher-half kernel + direct map (Stage 1 / PR-1.2, ADR-0002)**: the kernel links at `0xFFFFFFFF80000000` (loaded at PA 2 MiB via a linker `AT()` + objcopy-by-LMA split), the stub maps three windows before entry — kernel image, direct map (`0xFFFF888000000000`+PA, RW, never X), and a bring-up identity window the kernel **tears down and proves dead** right after entry. Guarded kernel stacks (absent-PTE guard pages, pool-backed, scrub-on-free) fault for real when run over; per-CPU state is anchored at the GS base. The `mm` layer itself is unsafe-free by design. **7 new host tests** pin the translation and slot arithmetic.
- **Exception machinery (Stage 1 / PR-1.1)**: a kernel-owned GDT/TSS/IDT with a uniform exception frame, IST stacks for `#DF/#NMI/#MC/#SS`, and a live negative test — the boot forces a hardware `#DE` and the dispatch prints the diagnosis and the selftest marker before powering off. Every fault from here on is diagnosed, not a silent hang. **11 new host tests pin the descriptor/frame encodings, including the boot-stub GDT literals as an ABI contract.**
- Unsafe policy enforced by machine, not convention: the policy core is `forbid(unsafe_code)`; the kernel is `deny(unsafe_code)` with a four-module allowlist (`arch/`, `boot/`, `hw.rs`, `memops.rs`), every item carrying a `SAFETY` note, and a **ratchet** (`scripts/unsafe-count.txt`, baseline 33) that fails CI if the count grows without an ADR.

**Not yet (roadmap v2, see [`docs/ROADMAP.md`](docs/ROADMAP.md)):** the hardware isolation boundary itself — ring-3 user domains, per-domain page tables, SYSCALL/SYSRET entry (PR-1.3..1.5 of [`docs/STAGE1-PR-PLAN.md`](docs/STAGE1-PR-PLAN.md)), then IPC, block storage + ext2, preemption/SMP, the Linux-compatible syscall ABI, drivers, and hardening. M1 domains are still kernel-resident objects whose region mappings pass the full policy and whose pages are real tracked frames.

## The architecture in one line

> Unix gave us clarity, separation of concerns and stable interfaces; AegisOS adds one unbreakable rule on top: **attenuation-only privileges** — there is no code path anywhere in the kernel that can widen a live domain's syscall mask.

## Quick start

```bash
./boot.sh           # build the kernel and boot it in QEMU (needs qemu-system-x86)
./boot.sh --verify  # same, plus assert the M1 + exception-selftest markers

cargo test                       # 196 policy-core tests
cargo test -p aegis-kernel       # 41 host tests: boot logic + arch/mm encodings
cargo build --target thumbv7em-none-eabihf   # the core still builds for bare-metal ARM
```

What the boot log shows (CI greps exactly these): the GDT/TSS/IDT going live, the higher-half switch (`[MM ] higher-half ok`, identity window torn down), multiboot memory validation, the frame pool claim, the guard-gap policy rejecting an adjacent mapping **live**, CFS slices, `Hello from AegisOS domain 1`, the five-window escalation `55 → 50 → 37 → 80 → 80` ending in quarantine with the neighbor healthy, `leaked-frames=0`, `scrub-verified=yes`, a single `M1-EXIT-CRITERIA: PASS` verdict line — then the selftests: a forced hardware `#DE` diagnosed and **returned from** (`[EXC] #DE selftest ok: rip advanced, unwound to the caller` — the return path Ring-3 signals will use), a guarded stack allocated/mapped/cross-viewed against the direct map/freed-scrubbed (`[MM ] guarded stacks: … ok`), and a final write through a guard page → `#PF` with `cr2` naming exactly that page → clean poweroff.

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

Roadmap v2 turns this into a usable Unix-like core in eight stages (Ring-3 → IPC → storage → preemption/SMP → POSIX ABI → drivers → hardening → compliance; ≈ 65–80 PRs). **Current position: Stage 1, PR-1.1 + PR-1.2 merged** — exception machinery and the higher-half/direct-map layout are live and selftested on every boot. Next: PR-1.3 (per-domain page tables: policy → real PTEs), then ring-3 entry, then the first user domain. Every stage gate is CI-verified: a stage does not start before the previous one's acceptance markers pass in QEMU.

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
