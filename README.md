# AegisOS — Core

**A `no_std`, zero-dependency policy kernel for a modern operating system: Unix-philosophy foundations (VFS with Unix permissions, pipes, signals, fd tables, CFS-style scheduling, buddy allocator, brokered sockets) under strict per-domain isolation, plus a graduated AI security behavior monitor.**

[![CI](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests: 191](https://img.shields.io/badge/tests-191%20passing-brightgreen.svg)](tests/)

> The name: **Aegis** (the shield). One rule shapes the whole design: everything runs inside an isolated `Domain`, and every privilege is granted once and can only ever shrink.

## The architecture in one line

> Unix gave us clarity, separation of concerns and stable interfaces; AegisOS adds one unbreakable rule on top: **attenuation-only privileges** — there is no code path anywhere in the kernel that can widen a live domain's syscall mask.

## What's inside

| Area | Module | Linux analog | Key invariants |
|---|---|---|---|
| Syscall gate | `syscall` | syscall table + seccomp | `u64` bitmask, O(1) AND+bit-test; masks only ever attenuate |
| Capabilities | `capability` | capabilities(7) | Generation counters make use-after-revoke impossible; derivation requires `GRANT` + subset rights |
| Memory policy | `memory` | mmap + W^X | NULL/wraparound/overlap rejection, guard gaps, page quotas, scrub-on-release |
| Page frames | `buddy` | buddy allocator | Power-of-two blocks, split on alloc, coalesce on free, full accounting |
| Filesystem | `vfs` | VFS + DAC + chroot(2) | owner/group/other `rwx` bits, execute-to-traverse, `..` clamped at chroot root |
| Descriptors | `fd` | open file table | lowest-free allocation, dup2 semantics |
| Pipes | `pipe` | pipe(2) | bounded ring, short reads/writes, EOF, EPIPE, dup-aware end refcounts |
| Signals | `signal` | signal(7) | 1..=31 bitsets, pending/blocked masks, unblockable SIGKILL/SIGSTOP, lowest-number-first delivery |
| Scheduling | `sched` | CFS | vruntime + the real Linux nice→weight table (nice 0 = 1024), starvation-free ticks |
| Network | `net` | sockets + tc/tbf | brokered sockets, per-domain token-bucket rate limiting, deterministic refill math |
| Profiles | `profile` | service types | service / parser / driver / plugin / netd(broker) — least privilege by default |
| Domains | `domain` | processes | fast-path gate, quarantine = SYS_EXIT-only, frozen stats while quarantined |
| Monitoring | `monitor` + `response` | auditd/ML security | integer risk score, sensitivity-scaled thresholds, hysteresis + decay, Log → Tighten → Quarantine |
| Telemetry | `ringbuf` | relay/perf rings | SPSC, power-of-two masking, drop-and-count when full — never blocks |

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

## Quick start

```bash
cargo test                                  # 191 tests: 175 unit + 16 integration
cargo build --target thumbv7em-none-eabihf  # proves true no_std on bare-metal ARM
```

Zero external dependencies (the `[dependencies]` section is empty on purpose — the supply-chain surface is this repository alone), `#![forbid(unsafe_code)]` throughout.

## Sample Linux-like flows (all covered by tests)

```bash
cargo test --test linux_like
```

- **Unix permissions end to end**: a root-owned `0o644` file is readable by everyone but writable only by its owner; creating inside a `0o755` directory is denied for non-owners; uid 0 bypasses DAC.
- **chroot confinement**: a domain chrooted to `/pub` cannot reach `/home` — not via absolute paths, not via `..` climbing (clamped at the chroot root), not via unlink. Unlike Linux, the cwd moves with the new root, closing the classic chroot+cwd escape.
- **Pipes with dup semantics**: `pipe()`, write, `dup2` a second write end, close the original — the pipe stays alive until the *last* referencing descriptor closes, then readers see EOF.
- **Signals with Unix kill rules**: same-uid or uid-0 kill allowed, others denied; SIGTERM delivery applies the default action (quarantine); SIGUSR1 is ignored; invalid signal numbers rejected.
- **CFS fairness**: two nice-0 domains share exactly equally (25/25 slices over a settled cycle) while a nice+5 domain gets proportionally fewer (8); sleeping domains are skipped and wake with priority.
- **Rate-limited brokered sockets**: the netd broker domain bursts up to 64 bytes, then exact-deficit throttling kicks in; one 100-tick window later the bucket refills; non-broker profiles are masked out of `NET_SEND` entirely.
- **Buddy allocator**: 256 frames as eight max-order blocks, address-ordered allocation, worst-order frees coalesce the arena back whole.

## Behavior monitor (the AI security layer)

Five real signals from the fast path — denied ratio, faults, capability-escalation attempts, out-of-profile syscall bits, rate spikes — feed an integer-only risk score (u128 intermediates, deterministic, overflow-proof). Graduated response with anti-flap: a single bad window never escalates (hysteresis), reported scores decay, tightening keeps the app alive (it only drops spawn/net/ioctl/mmap/open), quarantine is terminal and passes only `SYS_EXIT`. If the monitor's state table fills, it degrades to logging — but instant quarantine at score ≥ 95 still fires. Fail-safe, not fail-open.

Full design rationale: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · Staged build-out plan: [`docs/ROADMAP.md`](docs/ROADMAP.md)

## Repository layout

```text
src/
├── syscall.rs    attenuation-only syscall masks (O(1) gate)
├── capability.rs capability table with generations
├── memory.rs     W^X / guard-gap / quota address spaces
├── buddy.rs      buddy page-frame allocator
├── vfs.rs        VFS with Unix DAC + chroot
├── fd.rs         per-domain file descriptor tables
├── pipe.rs       bounded pipes (refcounted ends)
├── signal.rs     POSIX-style signal sets
├── sched.rs      CFS-style fair scheduler
├── net.rs        brokered sockets + token buckets
├── profile.rs    service/parser/driver/plugin/netd profiles
├── domain.rs     the isolation unit + fast path
├── monitor.rs    risk scoring, hysteresis, graduated response
├── response.rs   response application + security telemetry
├── ringbuf.rs    non-blocking SPSC rings
├── sys.rs        the executing syscall layer
└── lib.rs        Kernel assembly
tests/
├── integration.rs   security scenarios (escalation, isolation, telemetry)
└── linux_like.rs    Linux-semantics scenarios (VFS/pipe/signal/sched/net)
```

## License

MIT — see [LICENSE](LICENSE).
