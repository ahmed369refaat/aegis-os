# ADR-0005: Exception machinery and the arch/ unsafe allowlist

- **Status:** Accepted (PR-1.1)
- **Stage:** 1 (Ring-3 isolation), Track A
- **Date:** 2026-11-19

## Context

Stage 1 needs every later fault to be *diagnosed* instead of
triple-faulting: without a kernel-owned IDT, a bug in page-table or
syscall work is a silent hang, and the Ring-3 gate (`deny→SIGSEGV +
audit`) has no delivery path at all. Programming the GDT/TSS/IDT and the
entry assembly is raw CPU control — it cannot be safe Rust — so this PR
also extends the crate's unsafe allowlist (previously `boot`, `hw`,
`memops`; baseline count 14), which per `CONTRIBUTING.md` requires this
ADR.

## Decision

1. **Structure**: a new `kernel-x86_64/src/arch/` module owns the CPU
   tables and exception entry: `gdt.rs`, `idt.rs`, `frame.rs` (pure,
   host-tested encodings), `stubs.rs` + `exceptions.rs` (target-only
   naked entry + Rust dispatch). The existing boot stub is untouched.
2. **GDT mirrors the boot stub's selector map** (`0x08` 32-bit code,
   `0x10` data, `0x18` 64-bit code) instead of choosing a new layout and
   doing an `lretq` dance: the stub enters the kernel on CS=`0x18`, so
   keeping the map means the segment registers stay valid across
   `lgdt` with zero fragile control flow. A host test pins the kernel
   descriptors to the stub's literal GDT values.
3. **Uniform frame**: one stub shape (`[vector][error][rip][cs][rflags]`
   under 15 pushed GPRs), one dispatch. Vectors without a CPU error code
   push a zero. `#PF` is not on IST; `#DF/#NMI/#MC/#SS` are (rationale
   in `docs/arch/exceptions.md`).
4. **Acceptance is live and negative-tested**: the boot arms a selftest
   flag and forces a hardware `#DE` (inline `idiv` — Rust's `/` raises a
   software panic first, which would test nothing). The dispatch prints
   the diagnosis + marker and powers off; `boot.sh --verify` greps both.
5. **Allowlist**: `arch/` joins the unsafe allowlist; the count ratchet
   moves 14 → 23. The +9: five unsafe blocks (`gdt::load`, `idt::load`,
   the frame deref, the #DE trigger, `hw::read_cr2`) and four attribute
   lines. The 32 vector stubs expand from one macro, so they cost two
   source lines, not 32.

## Consequences

- Every later PR (higher-half, page tables, Ring-3 entry) inherits
  diagnosed faults instead of silent hangs — the cheapest debugging
  aid this project will ever buy.
- IST stacks are static 16-KiB `.bss` arrays for now; PR-1.2's guarded
  stack allocator replaces them (tracked in the evolution points of the
  component doc).
- The dispatch never returns in this PR (CPL0 faults are fatal); the
  unwind path is kept correct but dead, and becomes the Ring-3 signal
  path in PR-1.5.
- `ExceptionFrame` has no `rsp`/`ss` fields yet — CPL0 faults don't
  push them. PR-1.4 adds them; the change is localized to the struct
  and the frame test.
- Development found and fixed two real bugs in exactly the ways the
  design intends to catch: a const operand without an AT&T `$` pushed
  memory instead of an immediate (caught by reading the disassembly
  against the garbage `vector=0xf000ff53f000ff53` — the BIOS IVT at
  physical 0), and a GDT that shuffled the stub's selectors (caught by
  `cs=0x18` resolving to a user descriptor). Both are now pinned by
  tests or by the invariant doc.

## Alternatives considered

- Do nothing until Ring-3 work forces it — leaves the whole stage
  debugging blind, and the Stage-1 gate needs a fault→signal path
  anyway.
- `global_asm!` stubs instead of naked functions — equivalent, but the
  repo already standardized on `naked_asm!` with `#[unsafe(...)]`
  attributes; consistency wins.
- A per-vector Rust handler table (no common entry) — 32 copies of
  frame logic and no uniform frame; rejected.
- Far-return CS reload after `lgdt` — more fragile than keeping the
  stub's selector contract; rejected.
