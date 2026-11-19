# ABI Version

**Current: `v0.x (internal)`** — there is no stable userspace ABI yet.
The kernel's syscall entry (Stage 1) speaks a debug-only internal
surface; the policy core's operation ids are internal.

**Planned: `v1 (Linux-compatible)`** — lands with Stage 5 per
[ADR-0003](adr/0003-linux-compatible-syscall-abi.md): Linux x86_64
syscall numbers/registers/errno at the entry, translation to internal
ops before the policy gate. aarch64 gets its own Linux number table.

## Rules

- Any change to syscall numbers, argument/return conventions, structure
  layouts crossing the user boundary, or errno values **must** bump the
  version here and be called out in the PR + CHANGELOG.
- A version bump in the same major version is additive; removing or
  renumbering an exposed entry is a major bump.
- The full surface is documented in `docs/ABI.md` (created in Stage 5).
