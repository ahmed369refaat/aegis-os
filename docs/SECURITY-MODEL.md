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
- **M1 boundary, stated plainly:** domains are kernel-resident objects
  whose region mappings pass the full memory policy and whose pages are
  real, tracked, scrubbed frames. Per-domain page tables and ring-3
  execution are M2 — the hardware user/kernel boundary is not yet in
  place, and we do not claim it is.

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
| VFS | Unix DAC: owner/group/other `rwx`, execute-to-traverse, chmod owner-or-root; chroot clamps `..` and moves the cwd with the root |
| Network | Only the `netd` profile holds `NET_*`; every send passes a per-domain token bucket |
| Signals | Unix kill rules (uid 0, same uid, or self); SIGKILL/SIGSTOP unblockable |

## 4. The behavior monitor (graduated, fail-safe)

Real signals only — denied ratio, memory faults, escalation attempts,
out-of-profile syscall bits, rate spikes — scored with deterministic
integer math (u128 intermediates, no floats, no hidden state).

| Condition | Response |
|---|---|
| below 45 | **Log** (telemetry only) |
| ≥ 45 for 2 consecutive windows | **Tighten** (mask ∩ reduced surface: drops SPAWN/NET/IOCTL/MMAP/OPEN) |
| ≥ 75 for 2 consecutive windows | **Quarantine** (EXIT-only, terminal) |
| ≥ 95 in one window | **Instant quarantine** |

Anti-harassment is part of the design: single bad windows never escalate,
scores decay 15/window when quiet, thresholds scale with profile
sensitivity, and tightening keeps normal work (READ/WRITE/CLOSE/IPC/EXIT)
alive. Monitor failure fails **safe**: a full state table degrades to
logging while instant quarantine still fires.

## 5. Supply chain and code-level guarantees

- **Zero external dependencies** — the dependency graph is this
  repository (CI-enforced, workspace-wide).
- The policy core is `#![forbid(unsafe_code)]`.
- The bootable kernel is `#![deny(unsafe_code)]` with a three-module
  allowlist (`boot/`, `hw.rs`, `memops.rs`), every item carrying a
  `SAFETY` note — enforced by `scripts/check_unsafe.sh` in CI.
- `no_std` throughout; the core also builds for bare-metal ARM
  (thumbv7em) to prove no host assumptions leak in.

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
