# ADR-0002: Higher-half kernel + direct map

- **Status:** Accepted (PR-1.2)
- **Stage:** 1 (Ring-3 isolation), PR-1.2
- **Date:** 2026-11-19

## Context

The kernel currently lives at identity-mapped 2 MiB. Ring-3 user domains
need the low half of the address space (that is where POSIX programs,
PIE binaries, and every conventional toolchain expect to live), so the
kernel must move out of the way before the first user domain exists.
Doing this later multiplies the churn: every per-domain table, every
syscall path, and KASLR (Stage 7) assume a stable kernel/user split.

## Decision

Adopt a fixed three-region virtual layout (KASLR later slides within it):

| Region | Range | Properties |
|---|---|---|
| User | `0x0000_0000_0000_0000` – `0x0000_7FFF_FFFF_FFFF` | per-domain tables, lowest region at 0x1000 (NULL page never mapped) |
| Direct map | `0xFFFF_8880_0000_0000` + PA | RW only, never executable, kernel-only |
| Kernel image | `0xFFFF_FFFF_8000_0000` (2 MiB-aligned) | RX text, RO data, RW data+bss; mapped into every table as global entries |

The boot stub (ADR-0001) additionally maps the higher-half window at
bring-up and the kernel enters at the high base. Frame-pool accesses
(including scrub) go through `mm::direct_map::pa_to_va`. Kernel stacks
are allocated from guarded stack regions in the direct map.

## Consequences

- New invariant (CI-tested): no user PTE may point above the user/reader
  split; no direct-map PTE may be executable; kernel entries are global
  (no per-domain TLB churn).
- `.bss` zeroing and the entry handoff move to the high base; the
  `--defsym=kernel_entry` mechanism is unchanged (just a different
  address).
- The M1 identity window survives only inside the stub's bring-up tables,
  and the kernel tears it down after switching — stated in
  `docs/arch/memory-layout.md`.
- All existing tests keep passing; only the kernel crate's link base and
  address constants change.

## Alternatives considered

- Keep the kernel at identity low addresses and place userspace elsewhere
  — breaks PIE conventions, complicates KASLR, leaks kernel addresses
  into every domain's tables.
- KPTI-style kernel/user table isolation — deferred to Stage 7 hardening
  as a measurable option; not needed for the Stage-1 gate and it doubles
  TLB pressure.
