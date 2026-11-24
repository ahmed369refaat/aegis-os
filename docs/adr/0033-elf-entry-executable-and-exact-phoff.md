# ADR-0033: The ELF entry must lie inside an EXECUTABLE segment, and the program-header table at exactly e_phoff == 64

- **Status:** Accepted
- **Stage:** M3 security hardening (round N1, ITEM 5)
- **Date:** 2026-11-24

## Context

Mutation fuzzing of the two real in-repo images (600k mutations) found
118 ACCEPTED plans whose `e_entry` pointed inside a NON-executable
segment: `build_exec_plan` checked only that the entry lies inside
SOME loadable segment, so the first instruction of such an image
faults on NX — accepted at load, dead at first fetch. The same
function also assumed the program-header table starts at offset 64
without ever reading `e_phoff`: a header claiming a different table
offset would be parsed at the wrong place — the fixed-layout reads
below walk from `EHDR_SIZE` unconditionally.

## Decision

1. **The entry must lie inside a segment with `executable == true`.**
   A new typed error, `ElfError::EntryNotExecutable`, distinct from
   `EntryOutsideSegments` (the entry outside every segment) — the two
   refusals name different bugs, and the audit trail should too.
2. **`e_phoff` must equal 64 exactly** (`ElfError::BadPhoff`). CHOICE
   RECORDED: the exact check, not a checked-arithmetic walk. The
   kernel's own linker scripts place the table at 64; a different
   offset is not a shape this kernel builds, the fixed-layout reader
   below does not implement walking from an arbitrary offset, and
   accepting one (bounds-checked) would silently bless a layout the
   rest of the loader never exercised. Fail closed.

## Consequences

- The 118-image class is refused at the gate, before any frame is
  spent (`sys_exec`'s quota pre-check, ITEM 6, runs on the plan — a
  refused plan costs nothing).
- Host tests: entry in an RW segment, entry in a read-only segment,
  `e_phoff` != 64 — one field mutated at a time, each refusal naming
  its rule — plus every existing loader test green. The fuzz harness
  (round ITEM 8) gains "entry inside an EXECUTABLE segment" as an
  accepted-plan invariant.
- Not done: no support for `e_phoff != 64` layouts, no PIE, no
  dynamic anything — unchanged refusals.
