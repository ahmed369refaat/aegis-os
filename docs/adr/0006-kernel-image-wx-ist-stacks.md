# ADR-0006: Kernel image W^X, writable IST stacks, reusable guarded stacks

- Status: Implemented (F15, second review round; the first round
  landed the ADR + F16/F17, this one landed the image split)
- Date: 2026-11-19 (deep-review remediation, Phase 3)
- Deciders: kernel maintainers
- Supersedes: part of ADR-0002 (image mapping description); ADR-0002 stays
  authoritative for the VA layout itself.

## Context

The deep review (findings F15-F17) found three hardening gaps in the
bootable kernel:

1. **The kernel image is one 2 MiB huge page with flags 0x83** —
   present + RW + PS: writable AND executable, supervisor. CR0.WP is
   never set, so even marked-read-only pages would stay writable. The
   documentation claims RX/RO/RW splits that do not exist.
2. **The IST stacks are `static` (immutable) arrays** — they only work
   because the image is writable (they land in a writable mapping);
   once the image gains real permissions, exception entry would fault
   writing to its own stacks.
3. **`mm/stacks.rs` slot cursor only increments** — 512 stacks per
   boot, then allocation fails forever — and `alloc` leaks frames on
   partial failure (no rollback).

## Decision

1. **Per-4KiB-page image mapping (F15).** The kernel link script
   page-aligns `.text`, `.rodata`, `.data` and `.bss`, exports
   section-boundary symbols (`__text_start/__text_end`,
   `__rodata_*`, `__data_*`, `__bss_*`, plus the boot-stack guard
   region), and `mm::init` rebuilds the image's page-table entries
   through a dedicated PT: `.text` = R+X (NX clear), `.rodata` =
   R+NX, `.data`/`.bss`/stack = RW+NX, one absent page as a guard
   below the boot stack. CR0.WP is set. QEMU selftests (CI-grepped
   markers) prove a write to `.text` faults and an exec from `.data`
   faults (NX).
2. **IST stacks become writable `.bss` (F16).** The exception stacks
   move to `static mut` (documented in the unsafe allowlist as before)
   so they land in NOBITS (`.bss`), and a CI check asserts via
   `readelf`/`nm` that the `IST_*` symbols live in a writable NOBITS
   section — the property would have caught the original bug.
3. **Guarded-stack slot reuse with rollback (F17).** A pure, host-
   tested `StackSlots` bitmap tracks free slots; `alloc` takes the
   next free slot (not an ever-growing cursor) and rolls back every
   frame it allocated if any step fails; `free` returns the slot.
   Infinite alloc/free cycling is now bounded by memory, not by a
   boot-lifetime counter.

## Implementation notes (what the boot taught us)

- The PT lives in a `#[repr(align(4096))] static mut` in .bss — a PD
  entry pointing at a non-4KiB-aligned table triple-faults.
- The PD entry that points at the PT needs P|W: x86 checks W at every
  level, so a W-clear directory entry makes the whole image read-only
  regardless of the leaf bits (the first boot died on a stack push).
- `.got` is an orphan the script must place (in .data) — an orphaned
  section lands between .data and .bss, inside what the pure mapping
  leaves absent (the second boot died reading it).
- `cpuid7_ebx` must not move EBX through an `out(reg)` temporary: if
  the allocator picks RBX itself, the restore-pop clobbers the result.
  The store-into-the-pushed-slot pattern is immune.

## Consequences

- The image mapping is now what the docs always claimed; ADR-0002 and
  `docs/arch/memory-layout.md` are updated to describe the PT-based
  image mapping (and no longer claim a single 2 MiB leaf).
- Writing to `.text` or executing `.data` becomes a fault the
  exception machinery reports, not a silent success — the same
  machinery PR-1.1 built. The selftests reuse the armed-fault pattern
  (ADR-0005).
- IST stacks work under the real permissions; the writable-NOBITS
  check becomes part of the boot-image checks so a regression cannot
  hide.
- `unsafe` usage stays inside the documented allowlist; the ratchet
  moves only with this ADR's reference.
