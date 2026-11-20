# The AegisOS Security Model — one page

**The claim:** every privilege in AegisOS is granted once at domain
creation and can only ever shrink. There is no code path — anywhere in
the kernel — that widens a live domain's syscall mask or capabilities.
Everything below is enforced by code and proven by tests, not by policy
documents.

## 1. Units and boundaries

- Everything runs in a **Domain**: an app, a service, a file parser, a
  driver, a plugin, the network broker. A domain holds: a syscall mask,
  a capability table, an address space, an fd table, signal state, and
  (on the booted kernel) real pool frames with per-frame ownership.
- Domains never share ambient authority. Cooperation happens through
  IPC and derived capabilities only.
- **Hardware boundary, stated plainly (live since PR-1.3 + ADR-0010):**
  user domains run at CPL=3 on per-domain page tables — every mapping
  passes the full memory policy *and* becomes a real PTE (W^X/NX, guard
  gaps as absent pages, U/S split), syscalls enter via SYSCALL/SYSRET
  through the same policy `gate()` as kernel-resident domains, and
  SMEP/SMAP plus kernel-image W^X are MMU-enforced. The seven-run
  ring-3 sequence (hello / NX / kernel-VA / forged syscall / edge
  writes / live-monitor quarantine / audit-only) is asserted by
  `boot.sh --verify` in CI. Kernel-resident domains remain for bring-up
  selftests and the M1 sequence only.

## 2. Attenuation-only privileges (the core invariant)

- A domain's mask starts at its profile's surface — the lifetime maximum.
- The only mutation anywhere is intersection (`mask & tighter`).
- Cross-domain derivation (`try_narrow_to`) rejects any result that would
  add a bit.
- `SYS_EXIT` is always present: tightening can never take a domain
  hostage.
- Supervisor operations (`destroy_domain`, quarantine handling) release
  resources; none of them widen anything.

## 3. What each layer enforces

| Layer | Enforcement |
|---|---|
| Syscall gate | O(1) mask bit-test before any execution; quarantine passes only `SYS_EXIT` |
| Capabilities | `{index, generation}` handles: revoked or reused handles are rejected; derivation needs `GRANT` + subset rights |
| Memory | Ten ordered checks: W^X, alignment, wraparound, overlap, one-page guard gaps, quotas; unmap counts pages as scrubbed |
| Physical frames (M1) | Pool frames are owned per-domain; freeing scrubs (zeroes) and is verified by read-back; freeing a frame you do not own is an error |
| VFS | Unix DAC: owner/group/other `rwx`, execute-to-traverse (including on `..` when *leaving* a directory), chmod owner-or-root; chroot clamps `..` and moves the cwd with the root; inode identity is (id, generation) — stale fds/cwd/chroot refs fail closed after slot reuse; open-time permission checks for the requested r/w access; truncation is an explicit flag, writes land at the fd offset |
| Network | Only the `netd` profile holds `NET_*`; every send passes a per-domain token bucket |
| Signals | Unix kill rules (uid 0, same uid, or self); SIGKILL/SIGSTOP unblockable |

## 4. The behavior monitor (graduated, fail-safe)

Real signals only — denied ratio, memory faults, escalation attempts,
out-of-profile syscall bits, rate spikes — scored with deterministic
integer math (u128 intermediates, no floats, no hidden state).

Every signal is fed **automatically**: denied syscalls by the gate
itself, memory-policy refusals (W^X/guard-gap/quota/overlap) and failed
capability operations (widening, missing grant, stale handle) by the
kernel's map and capability wrappers, windows by `Kernel::tick(now)`
(auditing every domain when a window boundary is crossed). The manual
`audit()` API remains for supervisors and tests.

| Condition | Response |
|---|---|
| below 45 | **Log** (telemetry only) |
| ≥ 45 for 2 consecutive windows | **Tighten** (mask ∩ the *profile's* degraded surface — a strict subset that keeps EXIT and the profile's core function; e.g. driver keeps IOCTL, netd keeps NET_*) |
| ≥ 75 for 2 consecutive windows | **Quarantine** (EXIT-only, terminal) |
| ≥ 95 in one window | **Instant quarantine** |

Thresholds shift down with profile sensitivity: every 4 points lower
them by 1, so the `service` profile (sensitivity 40) quarantines at
**65**, not 75.

**Audit-only mode (calibration).** `set_monitor_mode(MonitorMode::AuditOnly)`
computes and logs verdicts to telemetry (with the would-be action) but
applies nothing — no mask change, no quarantine. Enforce is the
default. Use AuditOnly to tune thresholds on real traffic before
letting the monitor act; the telemetry tells you what *would* have
happened.

Monitor state lives and dies with the domain: `destroy_domain` clears
it (a respawned id is born clean), and the supervisor-only
`reset_monitor(id)` is the un-quarantine path after human review.

Anti-harassment is part of the design: single bad windows never escalate,
scores decay 15/window when quiet, thresholds scale with profile
sensitivity, and tightening keeps normal work (READ/WRITE/CLOSE/IPC/EXIT)
alive. Monitor failure fails **safe**: a full state table degrades to
logging while instant quarantine still fires.

## 5. Supply chain and code-level guarantees

- **Zero external dependencies** — the dependency graph is this
  repository (CI-enforced, workspace-wide).
- The policy core is `#![forbid(unsafe_code)]`.
- The bootable kernel is `#![deny(unsafe_code)]` with a five-entry
  allowlist (`arch/`, `boot/`, `hw.rs`, `memops.rs`, `sched/`), every
  item carrying a `SAFETY` note — enforced by `scripts/check_unsafe.sh`
  in CI, with the count ratcheted in `scripts/unsafe-count.txt`.
- `no_std` throughout; the core builds for bare-metal ARM (thumbv7em)
  **and, since ADR-0011, for `aarch64-unknown-none-softfloat` and
  `riscv64imac-unknown-none-elf` in CI** — arch-agnosticism is enforced
  by the compiler, not by intention.

## 6. Where each claim is proven

| Claim | Proof |
|---|---|
| Masks never widen | `syscall` unit tests + profile cross-rule tests |
| Revoke is final | `capability` stale-handle tests |
| Guard gaps and W^X hold at boundaries | `memory` tests incl. `usize::MAX` wraparound |
| Freed frames are actually zeroed | `frames`/`memops` read-back tests + boot-time verification |
| chroot cannot be escaped | `vfs` tests + `linux_like` integration |
| Attacker quarantined, neighbor healthy | escalation scenario (integration + host test + live boot) |
| 1000 create/destroy cycles leak nothing | host test + live boot assertion, CI-grepped |
| Unsafe only in the allowlist | `scripts/check_unsafe.sh` (CI job) |
| The system boots | CI `boot-test` job in QEMU with exit-criteria grep |
