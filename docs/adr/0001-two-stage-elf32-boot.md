# ADR-0001: Two-stage ELF32 boot stub

- **Status:** Accepted (retroactive — documents the M1 design, commit f470ea9)
- **Stage:** M1 (boot)
- **Date:** 2026-11-19

## Context

QEMU's `-kernel` multiboot loader only accepts ELF32 images ("Cannot load
x86-64 image, give a 32bit one"), while the kernel is 64-bit Rust linked
as ELF64. The first CI boot run failed exactly this way; we needed a
direct, fast `-kernel` boot path (the < 300 ms boot gate) with no
bootloader dependency and no external crates.

## Decision

Boot in two stages. Stage 1 is a pure-assembly ELF32 multiboot-v1 stub
(`boot-x86_64/stub.S`, ~150 lines) linked at 1 MiB: it stashes the
multiboot registers and a first-instruction TSC stamp, loads its own GDT,
builds identity page tables for the first GiB, enables long mode, and
hands off RDI=magic, RSI=info, RDX=TSC, RCX=kernel-entry. Stage 2 is the
ELF64 kernel linked at 2 MiB, embedded in the stub image at its link base
via `.incbin` of its flattened binary; its entry (`aegis_entry_64`, naked
asm) zeroes `.bss`, stores the TSC, switches to the kernel stack, and
calls `kmain`. The kernel entry address is injected at stub link time
(`ld --defsym=kernel_entry=<addr>` from `readelf`).

## Consequences

- No copying at boot; the loader maps the kernel blob directly at 2 MiB.
- The 64-bit stub section is relocation-free (the i386 assembler cannot
  emit x86-64 relocations): the handoff is staged on the stack by the
  32-bit code.
- The stub is the machine-state trust base: no logic, heavily commented,
  not covered by the Rust unsafe allowlist (it is assembly by definition)
  — covered instead by structural CI checks (ELF32 class, multiboot magic
  position, blob byte-identity at 2 MiB) and the boot test itself.
- The same multiboot-v1 image boots under GRUB on real hardware.
- Stage 1 of Roadmap v2 (ADR-0002) extends the stub's tables with the
  higher-half kernel window; the stub's structure is unchanged.

## Alternatives considered

- GRUB ISO boot — works, but adds a GRUB dependency to every boot and
  ~1–2 s of wall-clock to the boot-time gate; kept as a hardware path,
  not the CI path.
- UEFI payload — heavy, unnecessary for the CI gate.
- ELF32-only 32-bit kernel — would abandon the x86_64 requirement.
