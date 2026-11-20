# AegisOS — Full Engineering Architecture

> Reference design document. The reference implementation embodies every policy described here and backs it with tests — 320 total: 243 policy-core (225 unit + 18 integration/property) plus 77 kernel host tests that run the boot-sequence and arch-encoding logic itself (single source of truth for counts: `scripts/count-tests.sh`). The kernel boots on QEMU, runs ring-3 domains, and CI asserts its exit criteria on every push.

## 1. The foundation: what we take from Unix, and why

| Unix foundation | AegisOS take | Engineering rationale |
|---|---|---|
| Everything is a file (unified VFS) | Every resource opens through a `Capability` to a `Resource` (FsNode/IpcChannel/Device/MemRegion) | One interface means one enforcement point for permissions |
| Processes and threads, efficient scheduling | The base unit is the **Domain**: a process + a full isolation envelope; threads inside a domain share its mask | Isolation enforced at the domain boundary, not the thread — cheaper and more precise |
| `syscall` as a stable interface | 64 fixed syscall slots + a `u64` bit mask per domain | Membership test = one AND + one bit test: a deterministic O(1) path |
| Drivers and structured I/O | A driver is a **driver domain** holding `IOCTL` only, no direct kernel access | Driver bugs and exploits stay outside the kernel |
| Clarity and separation of concerns | Every core module has one testable contract in isolation | 243 core tests + 77 kernel host tests, all without special setup = provability |
| POSIX process machinery | Pipes, signals, fd tables, dup2, nice levels, chroot — reimplemented under the mask | Familiar semantics, unfamiliar safety: every one of them is mask-gated |

What we deliberately **drop** from Unix: default trust in processes (root/suid), signals as a control-plane mechanism (kept as delivery semantics only), and UID-based resource ownership — replaced by capabilities and attenuation. One Linux-ism is kept on purpose: uid 0 bypasses DAC checks (documented, and still confined by chroot).

## 2. Full tree of the reference kernel

```text
aegis-os/
├── src/                          # the policy kernel (this repository)
│   ├── syscall.rs                  attenuation-only syscall masks, O(1) gate
│   ├── capability.rs               capability table: generations + GRANT + subset
│   ├── memory.rs                   address spaces: W^X, guard gaps, quotas, scrub
│   ├── buddy.rs                    buddy page-frame allocator (split/coalesce)
│   ├── vfs.rs                      VFS: Unix rwx bits, traversal, chroot clamp
│   ├── fd.rs                       per-domain fd tables: lowest-free, dup2
│   ├── pipe.rs                     bounded pipes: short I/O, EOF, EPIPE, refcounts
│   ├── signal.rs                   signal sets: pending/blocked, unblockable KILL
│   ├── sched.rs                    CFS: vruntime + Linux nice→weight table
│   ├── net.rs                      brokered sockets + token-bucket rate limits
│   ├── ipc.rs                      capability-endpoint IPC (ADR-0004, async half)
│   ├── ringbuf.rs                  SPSC telemetry rings: power-of-two, non-blocking
│   ├── profile.rs                  profiles: service/parser/driver/plugin/netd
│   ├── domain.rs                   the isolation unit + deterministic fast path
│   ├── monitor.rs                  risk score, hysteresis, sensitivity thresholds
│   ├── response.rs                 graduated response + SecurityEvent telemetry
│   ├── sys.rs                      the executing syscall layer (gate → execute)
│   └── lib.rs                      Kernel assembly (domains, VFS, sched, pipes…)
├── boot-x86_64/                   # stage 1: the ELF32 multiboot boot stub
│   ├── stub.S                        pure asm: GDT, identity paging, long mode
│   └── stub.ld                       1 MiB stub + kernel blob at 2 MiB
├── kernel-x86_64/                  # stage 2: the bootable M1 kernel (workspace member)
│   ├── linker.ld                     2 MiB link base, pinned entry, 256 KiB stack
│   ├── build.rs                      -T linker script (bare-metal target only)
│   └── src/
│       ├── boot/                     UNSAFE ALLOWLIST: naked 64-bit entry (bss, TSC, stack)
│       ├── hw.rs                     UNSAFE ALLOWLIST: port I/O, rdtsc, halt, QEMU poweroff
│       ├── memops.rs                 UNSAFE ALLOWLIST: volatile memory + frame scrub
│       ├── serial.rs                 COM1 output (safe, over hw primitives)
│       ├── multiboot.rs              pure boot-info parsing (host-tested)
│       ├── frames.rs                 FramePool: ownership + scrub over the core buddy
│       ├── runtime.rs                the M1 sequence (host-tested, callback-driven)
│       └── kmain.rs                  live boot: validate → claim pool → run → verdict
├── tests/integration.rs           # security scenarios (escalation, isolation)
├── tests/linux_like.rs            # Linux-semantics scenarios (VFS/pipe/sched/net)
└── tests/property_tests.rs        # attenuation/derivation properties (seeded, deterministic)
```

### 2.1 The boot path (M1, x86_64 — implemented, two-stage)

QEMU's `-kernel` multiboot loader only accepts ELF32, while the kernel is
64-bit Rust linked as ELF64 — so booting is two stages:

```text
QEMU -kernel aegis-boot.elf (ELF32 multiboot v1, -machine pc, 128 MiB)
 └─ stage 1: boot-x86_64/stub.S — pure-asm ELF32 stub at 1 MiB
     └─ stash multiboot regs + boot TSC, own GDT, stub stack
     └─ identity-map the first 1 GiB (2 MiB pages)
     └─ PAE → CR3 → EFER.LME → CR0.PG → far jump to 64-bit CS
     └─ hand off RDI=magic, RSI=info, RDX=TSC, RCX=kernel entry
         └─ stage 2: the 64-bit kernel, embedded in the stub image at
            its 2 MiB link base, entered via aegis_entry_64 (naked asm)
             └─ zero .bss, store the boot TSC, switch to the kernel stack
             └─ kmain: serial → multiboot validation (mem_upper gate)
                 → claim + scrub the 256-frame pool @ 16 MiB
                 → hello domain → monitor demo → 1000-cycle stress
                 → M1-EXIT-CRITERIA verdict → clean poweroff
```

The stub has no logic (it is the machine-state trust base, ~150 commented
assembly lines, also bootable by GRUB on real hardware); `boot.sh`
orchestrates the build: kernel ELF64 → `objcopy` flat binary → the stub
(`ld -m elf_i386`) with the blob `.incbin`'d at 2 MiB and the entry
address injected via `--defsym`. The 64-bit handoff is staged on the
stack by the 32-bit code because the i386 assembler cannot emit x86-64
relocations.

The pool is managed by the **policy core's own buddy allocator** (the
`Kernel.frames` instance): the kernel adds only per-frame ownership and
the physical scrub (volatile zeroing, read-back verified). Unsafe code is
confined to the three allowlisted modules; everything else in the kernel
crate is safe Rust, and CI enforces the boundary
(`scripts/check_unsafe.sh`).

Beyond this kernel, the target system adds: `mm/` (per-domain page
tables, scrub-on-release), `sched/` (preemptive slices), `ipc/`
(capability channels), and user-space system domains — `vfsd`, `netd`
(the sole NIC owner), `devd`, and one parser domain per file format.

## 3. Strict isolation & least privilege

### 3.1 The syscall mask: one-way attenuation

- A domain's mask starts at its profile's surface — the lifetime maximum.
- The only mutation anywhere is `attenuate(&tighter) = mask & tighter`. Mathematically, no bit can appear.
- Cross-domain grants go through `try_narrow_to`, which rejects any derivation that adds a bit (`WidenForbidden`).
- There is no widening code path in the kernel — provable by inspection: every write to a live mask goes through `attenuate`.
- `SYS_EXIT` is present in every profile: a domain can always exit on its own (no hostage-taking), and quarantined domains can do nothing else.

### 3.2 The capability table

- Handles are `{index, generation}` pairs, kernel-internal; forging is meaningless because the table validates both parts.
- `revoke` keeps the generation counter alive: any stale handle (use-after-revoke, or ABA after slot reuse) is rejected with `InvalidHandle`.
- Derivation requires `GRANT` on the parent and subset rights on the child. Escalation attempts return an error and feed the monitor as `escalation_attempts`.

### 3.3 Memory policy

`AddressSpace::map` runs ten fixed-order checks: non-zero length, non-NULL base, page alignment, `checked_add` wraparound rejection, W^X (X-only and W-only allowed), at least one access bit, no overlap, a **full guard page between any two regions**, page quota, and `unmap` accounting that counts released pages as scrubbed — and since M1, on the booted kernel the scrub is physical: freed pool frames are zeroed by volatile writes and verified by read-back. `buddy.rs` backs this with Linux-style physical frame management: power-of-two blocks, split on allocation, buddy coalescing on free, exact accounting.

### 3.4 Linux-like semantics, mask-gated

The `sys.rs` layer executes *after* the gate allows:

- **VFS + DAC**: owner/group/other `rwx` bits; execute bit required to traverse directories; uid 0 bypass (the one deliberate Linux-ism); `chmod` for owner or root only.
- **chroot(2) with hardening**: `..` clamps at the chroot root; absolute paths resolve from it. Unlike Linux, `chroot` also moves the cwd — closing the historical chroot+cwd escape (a process holding a pre-chroot cwd cannot walk out).
- **fd tables**: lowest-free descriptor allocation, `dup2` replacing targets silently, per-file read cursors.
- **pipes**: bounded 64-byte rings; short writes and reads; `WouldBlock` when full/empty; `Ok(0)` at EOF; `BrokenPipe` (EPIPE) when the read end is gone. Pipe ends are **reference-counted**: a dup'ed descriptor keeps the end open until the last referencing fd closes.
- **signals**: 1..=31 bitsets; blocked signals stay pending; SIGKILL/SIGSTOP cannot be blocked; delivery takes the lowest pending unblocked number; the fatal default action quarantines the domain; `kill` follows Unix permission rules (uid 0, same uid, or self).
- **CFS scheduling**: `vruntime` charged by `ticks × 1024 / weight` with the real Linux `sched_prio_to_weight` table (nice −20 = 88761 … nice +19 = 15); the charge floors at 1 per tick so heavy domains cannot starve anyone; sleeping domains are skipped and wake with earned priority.
- **brokered sockets with rate limits**: only the `netd` profile holds `NET_SEND`; every send passes a per-domain token bucket (burst 64, refill 64 per 100 ticks, capped accumulation) — throttling is exact-deficit and deterministic, a pure function of (bucket state, clock).

### 3.5 Profiles (initial, maximal surfaces)

| Profile | Syscall surface | Pages | Sensitivity |
|---|---|---|---|
| `service` | READ, WRITE, OPEN, CLOSE, IPC, **PIPE, DUP, KILL, CHROOT, MKDIR, UNLINK** | 256 | 40 |
| `parser` | READ, CLOSE, MMAP, MUNMAP | 64 | 70 |
| `driver` | READ, WRITE, IOCTL, IPC | 128 | 50 |
| `plugin` | READ, IPC | 32 | 80 |
| `netd` (broker) | READ, WRITE, CLOSE, IPC, **NET_SEND, NET_RECV** | 128 | 30 |

Cross-profile rules enforced by tests: nobody gets `SPAWN`; only `netd` gets `NET_*`; only `service` gets the process-management syscalls; every profile keeps `EXIT`.

## 4. The two paths

### 4.1 Fast path (per syscall)

```rust
if id >= SYSCALL_COUNT            { return BadSyscall }        // 1 compare
if quarantined && id != SYS_EXIT  { return DeniedQuarantined } // 1 compare + state
stats.mark_used(id); stats.syscalls_total += 1 (saturating)   // 2 ops
if !mask.is_allowed(id)           { return DeniedByMask }      // AND + bit test
```

No allocation, no locks (SPSC in this sample), no analysis in the hot path, no panic path (all arithmetic saturates). Telemetry leaves through `RingBuffer::push`: index masking `& (N-1)`, drop-and-count when full — the fast path is never blocked by logging.

### 4.2 Slow path (per monitoring window)

`Kernel::audit` snapshots the window counters, closes the window atomically, scores, applies the graduated response, and records a `SecurityEvent`. The heavier ML analysis (roadmap M5) runs *outside* the kernel in its own domain, reading the same rings — it never sits in the event path.

## 5. Flexibility & extensibility

The only extension interface is the triple **Syscalls / IPC / Capabilities** — which is itself the isolation toolkit. A new driver is a driver domain receiving a derived `Device` capability. A new filesystem is a service domain over `FsNode` capabilities. A new parser format is an existing profile, zero kernel code. A new ML model is another ring consumer in its own masked domain — the model itself is monitored. No extension can widen a live domain's surface.

## 6. The AI security behavior layer

### 6.1 Signals (all real, all from fast-path counters)

| Signal | Source | Weight |
|---|---|---|
| `denied/total` | mask-gate counters (recon probing) | 20% |
| `faults` | memory fault path (guard/quota/W^X) | 25% |
| `escalation_attempts` | failed capability derivations | 30% |
| `out_of_profile_bits` | syscalls attempted outside the allowed mask | 10% |
| `spike` | total vs. per-window baseline (floods) | 15% |

### 6.2 Score

Integer-only math (deterministic, reproducible), `u128` intermediates (no overflow even at `u64::MAX` counters), each sub-signal saturated at 100, the weighted sum saturated at 100.

### 6.3 Graduated response

| Effective score* | Response | Effect |
|---|---|---|
| < 45 | **Log** | SecurityEvent only; the user notices nothing |
| ≥ 45 for consecutive windows (hysteresis = 2) | **Tighten** | Mask ∩ reduced surface (drops SPAWN/NET/IOCTL/MMAP/OPEN); healthy apps keep working |
| ≥ 75 for consecutive windows | **Quarantine** | EXIT-only, stats frozen; terminal (recovery = supervised respawn) |
| ≥ 95 in a single window | **Instant quarantine** | Multi-signal attack patterns do not wait for confirmation |

* Thresholds drop with profile sensitivity (`threshold − sensitivity/4`, floors 5/15): parsers quarantine at 58, services at 65 (75 − 40/4).

### 6.4 Why this does not harass normal users

- One bad window never escalates (hysteresis); alternating bad/quiet windows reset the streaks.
- Tightening keeps READ/WRITE/CLOSE/IPC/EXIT — real work continues.
- Reported scores decay 15 points per quiet window (no cliff-drops).
- Monitor failure fails *safe*: a full state table degrades to Log, but instant quarantine at 95+ still fires.

## 7. What the tests prove

- `tests/integration.rs::escalating_parser_is_tightened_then_quarantined` — the full pipeline: Log(55) → Tighten(50) → Tighten(37) → Tighten(80) → Quarantine(80), with the mask verified after each step and a healthy neighbor unaffected.
- `tests/linux_like.rs::vfs_unix_permissions_end_to_end` — Unix DAC over the real syscall layer.
- `tests/linux_like.rs::chroot_confinement_through_syscalls` — absolute, `..`-climb, and unlink escapes all fail; the supervisor still sees the whole tree.
- `tests/linux_like.rs::pipe_lifecycle_with_dup_semantics` — dup-aware pipe ends, EOF, EPIPE.
- `tests/linux_like.rs::kill_permissions_and_fatal_signal_delivery` — Unix kill rules; fatal signals quarantine.
- `tests/linux_like.rs::cfs_scheduler_fairness_through_kernel` — exact 25/25/8 fair share over a settled cycle.
- `tests/linux_like.rs::net_broker_send_is_rate_limited` — burst, exact-deficit throttle, window refill, profile masking.
- Edge cases at every boundary: `usize::MAX - PAGE + 1` (wraparound), `u64::MAX` counters (saturation), stale handles after revoke, score exactly 45 vs 44, signal 0/32/31, nice clamping, empty/full rings and tables, OOM with largest-free reporting.

- `kernel-x86_64` host tests — the M1 sequence (hello domain, guard-gap rejection, frame backing, CFS slices, five-window escalation, 1000-cycle create/destroy) runs identically on the host and asserts zero leaks, scrub read-back, and the exact escalation scores.
- CI `boot-test` — QEMU boots the kernel; the run fails unless `M1-EXIT-CRITERIA: PASS`, the hello marker, `leaked-frames=0`, `scrub-verified=yes`, and `monitor-quarantined=yes` all appear in the serial log.
- CI `kernel-build` — the ELF is structurally checked: entry at `_start`, the multiboot magic within the first 8 KiB.
- `scripts/check_unsafe.sh` — unsafe exists only in the documented boot allowlist; the policy core has none.
