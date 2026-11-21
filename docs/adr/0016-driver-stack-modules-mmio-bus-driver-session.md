# ADR-0016: Driver-stack module architecture — the split, MmioBus windows, one-close() DriverSession

- **Status:** Accepted (all three parts landed: the split, MmioBus, one-close() DriverSession)
- **Stage:** M3 driver stack (review round 4, F10 + the architecture Phase 6 builds on)
- **Date:** 2026-11-21

## Context

`kernel-x86_64/src/drvstack.rs` accreted to 4,389 lines across the
ADR-0013/0014/0015 PRs and the F4–F9 review round: the VT-d bring-up,
the broker demo, PCI enumeration, and eight drivers in one file. Three
structural problems came with it:

1. **Raw-address MMIO.** ~174 register accesses call
   `memops::read_u32/write_*` at physical addresses computed inline
   from BARs. F5 forced window checks on the virtio paths
   (`mmio_in_window`), but every other driver still trusts its own
   arithmetic per access — the F4–F8 class (device-supplied numbers
   becoming kernel addresses) is only half-retired.
2. **Hand-rolled lifetimes.** `revoke_or_quarantine` (ADR-0015 F2)
   unified the *teardown*, but each driver still owns its frame
   accounting by hand — and a mid-flight refusal (e.g. the ring-alloc
   loop hitting pool exhaustion at frame *i*) returns without freeing
   frames *0..i-1*. The teardown discipline cannot see those paths.
3. **Phase 6 needs a seam.** ADR-0017 (ring-3 driver domains) requires
   driver code that runs unchanged against either direct MMIO (ring 0)
   or a brokered channel (ring 3). Drivers written against raw
   `memops::` calls have no such seam.

## Decision

Three layers, landing as three commits in one phase:

1. **One module per subsystem** (`drvstack/{vtd,broker,pci,vblk,vnet,
   netutil,e1k,nvme,ahci,xhci,acpi,ext2,legacy}.rs` under a `mod.rs`
   that keeps only the shared helpers, the owner tags, and the step
   sequencing). The split is a **pure move**: signatures, markers, and
   lane greps stay byte-identical — the three boot lanes are the proof.
2. **`MmioBus`: every register access goes through a window.** A
   `MmioWindow{base,len}` is established ONCE per device — BAR sizing
   at enumeration (`pci.rs`), or a fixed platform address (ABAR, HPET)
   — refusing wrap/zero. The trait's accessors
   (`read8/16/32/64`, `write32/64`) take an *offset*, refuse
   out-of-window offsets by returning `None`/`false` (the F5
   `notify()` precedent: a refusal the caller must handle, never a
   panic, never a silent 0), and the bounds math is a pure default
   method — host-tested at the edges. `BarMmio` (direct volatile,
   target-only) is the first implementation; ADR-0017 adds `IpcMmio`
   over a ring-3 channel so the *same driver code* runs in both
   worlds. The volatile `unsafe` concentrates in one audited impl
   instead of 174 scattered call sites.
3. **`DriverSession`: one owner, one `close()`.** Every resource a
   driver run acquires — pool frames, broker regions, the PCI claim
   bits — is recorded in a session object as it is acquired.
   `session.close()` is the ONLY exit: it runs the F9b/F2 order (bus
   mastering off → `revoke_or_quarantine` → frames home) on every
   path — happy, refusal, or poison. A mid-flight refusal calls
   `close()` too, so the stranded-frame class dies by construction:
   there is no code path that allocates and does not close.

## Consequences

- The mid-flight refusal leak (pool exhaustion at frame *i* stranding
  *0..i-1*) becomes impossible, not merely absent — pinned by a host
  test (`session_no_frame_stranded_on_early_refusal`: fake broker +
  `FramePool`, drive an alloc loop into refusal, count frames home).
- Window math is proven at the edges (`window_bounds_edge_cases`:
  wrap at `u64::MAX`, zero-length refusal, `off+len` overflow, the
  last valid byte) — the same discipline F5 applied to virtio, now
  the default for every device the kernel talks to.
- The unsafe surface shrinks and centralizes: volatile access lives
  in `BarMmio` (+ the existing `memops`), each site accounted in the
  unsafe ledger; driver bodies become plain code over a trait.
- ADR-0017 gets its seam for free: `IpcMmio` is a second
  implementation of the same trait, and driver code does not change.
- Marker discipline is untouched: the lane greps pin the same bytes
  before and after (the split commit proves it; B and C keep it).
- What we do **not** do: no driver concurrency model (still
  step-sequenced bring-up), no IRQ-driven drivers (polling stays),
  and no attempt to move the *policy* decisions out of the kernel —
  that is ADR-0017's argument, not this one.

## Alternatives considered

- **Keep the monolith.** Lost: the file was the review round's worst
  reading surface; every finding cost cross-referencing 4,000 lines.
- **Panic/debug-assert on out-of-window access.** Rejected: a device
  (or our own arithmetic bug) must never halt the boot — F4's
  `attempt to add with overflow` kernel panic is the exact precedent.
  Refusals are verdicts; the boot continues and the marker says so.
- **A teardown trait without ownership.** Rejected: callbacks that
  *should* be called on every path are the leak class again — the
  session owns the resources, so destruction is not optional.
- **Per-driver window structs (no shared trait).** Rejected: it fixes
  the bounds bug but leaves ADR-0017 without its seam; the trait costs
  nothing at monomorphization and buys the ring-3 port.
