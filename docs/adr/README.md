# Architecture Decision Records

Every decision that shapes the kernel's architecture gets an ADR: one
file, one decision, written **before** the code lands. If a PR changes
an architectural decision without a matching ADR (new or superseding),
it does not merge.

## Process

1. Copy `TEMPLATE.md` to `NNNN-short-title.md` (NNNN = next free number).
2. Status starts at `Proposed`; it becomes `Accepted` when the
   implementing PR(s) merge, or `Rejected`/`Superseded by NNNN` later.
3. ADRs are never edited after acceptance except to add a superseding
   link — corrections happen in a new ADR.
4. PRs that grow the unsafe allowlist or raise the unsafe-count baseline
   **must** reference the ADR that justifies it.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-two-stage-elf32-boot.md) | Two-stage ELF32 boot stub | Accepted (retroactive, M1) |
| [0002](0002-higher-half-kernel-layout.md) | Higher-half kernel + direct map | Proposed (Stage 1) |
| [0003](0003-linux-compatible-syscall-abi.md) | Linux-compatible syscall ABI | Proposed (Stage 5) |
| [0004](0004-capability-endpoint-ipc.md) | Capability-endpoint IPC | Proposed (Stage 2) |
