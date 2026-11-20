# ADR-0008: SMEP/SMAP — MMU-enforced kernel/user separation

- Status: Accepted
- Date: 2026-11-20 (second deep review, Phase D / N4)
- Deciders: kernel maintainers
- Related: ADR-0002 (higher-half layout), ADR-0007 (user-copy model)

## Context

The kernel ran with CR4.SMEP and CR4.SMAP clear: CPL0 code could execute
user pages (SMEP off) and read/write user pages (SMAP off) with no MMU
complaint. The N1 fix made the *copy* provably fault-free, but nothing
prevented an accidental (or future buggy) kernel access to user memory —
the range checks were pure software.

## Decision

1. **Detect via CPUID leaf 7** (EBX bit 7 = SMEP, bit 20 = SMAP); the
   bit decoding and the CR4 image computation live in the pure,
   host-tested `arch/features.rs`.
2. **Enable CR4.SMEP/SMAP when present** at boot, after the per-domain
   table selftests (the existing RX selftest legitimately executes a
   user page from CPL0 — it runs before the bits go on; after that,
   executing or dereferencing a user VA from CPL0 is a fault by
   construction). Boot prints the live state: `[ARCH] smep=on smap=on`.
3. **Every intentional kernel access to user memory is wrapped in
   STAC/CLAC** (new allowlisted `hw::{stac,clac}`) when SMAP is on.
   There is exactly one such access today: the SYS_WRITE user copy
   (N1). The wrap is unconditional-on-support: a static flag set at
   boot (`hw::smap_active()`), so CPUs without SMAP keep the explicit
   range-check path unchanged.
4. **Absence is honest**: a CPU without the features keeps the software
   checks and the boot line says which protections are active
   (`[ARCH] smep=off smap=off` etc.).
5. **QEMU selftests with CI-grepped markers** (boot.sh runs
   `-cpu max`, which exposes both): a kernel jump into a user RX page
   faults under SMEP (armed, resume like the NX selftest); a kernel
   read of a user VA outside the STAC/CLAC window faults under SMAP
   (armed, resume like the guard-gap read).

## Consequences

- Kernel→user memory access is now an MMU property, not just a code
  review property; the N1 copy's STAC/CLAC window is the single blessed
  door.
- unsafe baseline +6: `cpuid7_ebx` (with the push/pop RBX dance),
  `stac`, `clac` (hw), the armed SMEP trigger's faulting jump and the
  armed SMAP trigger's faulting read, and the SMEP resume-slot read
  (exceptions) — all inside the existing hw/arch allowlist entries,
  referenced from this ADR in scripts/unsafe-count.txt.
- The RX selftest must precede the enable (documented at both sites).
