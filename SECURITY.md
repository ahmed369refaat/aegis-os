# Security Policy

AegisOS is a capability-based, no_std operating-system project: a
policy core (`src/`, `#![forbid(unsafe_code)]`), a bootable x86_64
kernel (`kernel-x86_64/`), ring-3 example blobs, and the host tooling
around them. Security is the product, so vulnerability reports are
treated as first-class contributions.

## Supported versions

Only the **latest tag** on `main` receives security fixes. The
project is pre-1.0 and moves fast; we do not backport to old tags.

| Version | Supported |
| ------- | --------- |
| latest tag on `main` | yes |
| anything older | no — rebase onto the latest tag |

## Scope

**In scope:**

- The policy core (`src/`): attenuation bypasses, capability
  confusion, syscall-mask escapes, monitor evasion, panics or
  out-of-bounds reachable from any untrusted input (ELF/FS images,
  device data, user pointers).
- The kernel (`kernel-x86_64/`): anything that weakens the documented
  invariants — `unsafe` outside the allowlisted sites
  (`scripts/check_unsafe.sh`, count pinned in
  `scripts/unsafe-count.txt`), SMAP/SMAP-bypass in the user-copy
  path, double-fetch of user memory, W+X mappings, IOMMU/IORT
  mapping escapes, ring-3 reachable kernel memory corruption.
- The syscall surface: uncounted denials, un-gated syscalls,
  unchecked user pointers (each must be validated once,
  byte-exact, SMAP-aware).
- Host tooling that gates releases (`scripts/*.sh`): a guard that
  silently passes (fails open) on the patterns it claims to catch.

**Out of scope:**

- QEMU, SeaBIOS, the Rust toolchain, or any third-party emulator
  bug — report those upstream; we may add workarounds, but they are
  not AegisOS vulnerabilities.
- Anything already documented as a known limitation in
  `docs/GAP-ANALYSIS-v2.md` or an ADR's "open items" section, unless
  you can show it is worse than documented.
- The example blobs (`examples/`, `kernel-x86_64/blob/`) — they are
  deliberately tiny test payloads, not a trusted computing base.
- Denial of service by resource exhaustion on a single-CPU,
  single-user research kernel where limits are documented as
  best-effort.

## Reporting

**Do not open a public issue for a vulnerability.**

1. Report privately to the maintainer via a GitHub
   **security advisory** on this repository
   (Report a vulnerability → Security advisories), or the private
   contact in `docs/adr/0021-ring3-syscall-surface.md`'s maintainer
   section if one is listed there.
2. Include: affected commit (SHA), the invariant you believe is
   broken, a reproducer (a fuzz seed, a corrupted image, a rogue
   blob, a QEMU lane invocation), and your assessment of the blast
   radius.
3. You will get an acknowledgement within 7 days. Fix windows
   depend on severity: invariant-breaking kernel bugs are treated as
   release blockers.

Please **do not** test vulnerabilities against any machine or
service you do not own or have explicit permission to test.

## Handling process

1. Reproduce under the project's own lanes (`boot.sh --verify*`) so
   the fix lands with a red-then-green test, not a claim.
2. Fix under the normal rules (ADR first if an architectural
   invariant moves; `scripts/check_unsafe.sh` /
   `check-asm-patterns.sh` / `check-ist-sections.sh` /
   `check-no-binaries.sh` must stay green).
3. Disclosure: coordinated, after the fix tag is published. Credits
   given in the release notes unless you prefer anonymity.

## Secrets and history hygiene

Committing a secret (token, key, core dump with environment data)
is an **incident, not a PR**: see
[`docs/incident-core-dump.md`](docs/incident-core-dump.md) for the
human runbook — token rotation first, then `git filter-repo`
history purge, force-push, and re-clone. The guards
`scripts/check-no-binaries.sh` and `scripts/check-history-clean.sh`
catch the known patterns at CI time; they are detection, not
absolution.
