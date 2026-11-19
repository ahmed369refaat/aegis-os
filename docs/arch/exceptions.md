# arch: exception machinery (PR-1.1)

> Component doc for `kernel-x86_64/src/arch/` — the GDT/TSS/IDT, the
> uniform exception frame, and the entry path from fault to diagnosis.
> Stage-1 Track A, first PR of `docs/STAGE1-PR-PLAN.md`.

## What exists after this PR

- A **kernel-owned GDT** that mirrors the boot stub's selector map (the
  two-stage boot ABI — see Invariants), a **TSS** with RSP0 and four IST
  stacks, and an **IDT** covering all 32 CPU exception vectors.
- A **uniform exception frame**: every stub leaves the stack in exactly
  the same shape, so one Rust dispatch can read any fault.
- A **live selftest**: the boot deliberately raises a hardware `#DE`
  (integer divide by zero via inline `idiv`), the dispatch prints the
  diagnosis and the `[EXC] selftest: exception machinery ok` marker, and
  powers QEMU off cleanly. `boot.sh --verify` (and therefore CI) greps
  both lines; a broken entry path triple-faults and the markers are
  missing instead — the failure is loud either way.

## Design

```text
        CPU fault (CPL0, no IST)                CPU fault (IST vector)
        pushes rip,cs,rflags                    switches to TSS.ist[n-1],
            │                                   pushes ss,rsp,rip,cs,rflags
            ▼                                               ▼
   stub_vNN (naked fn): push $0 (no-err) or nothing (err), push $vector
            │  (tail jump)
            ▼
   exception_common (naked fn): push rax..r15  → ExceptionFrame
            │  align rsp, rdi = frame ptr
            ▼
   aegis_exception_dispatch (Rust): report(frame) → serial + poweroff/halt
```

- **Encoding is pure and host-tested.** `gdt::segment`,
  `gdt::tss_descriptor`, `idt::Entry::encode`, and the frame/vector tables
  compile on the host and are unit-tested, including a test that pins the
  kernel descriptors to the boot stub's literal GDT values. The `load`
  fns and the naked stubs are target-only (`#[cfg(not(test))]`).
- **IST policy** (why these four): `#DF` must leave the faulting stack
  alone (the stack may be the thing that is broken); `#NMI` can
  interrupt any context including other IST handlers; `#MC` gets its own
  stack by severity; `#SS` cannot trust the stack it faulted on.
  **`#PF` is deliberately NOT on IST**: page faults need the faulting
  context's stack (COW in Stage 5), and an IST `#PF` breaks nested-#PF
  debugging.
- **IST stacks today**: four 16-KiB `.bss` statics, zeroed by the entry
  stub. PR-1.2 replaces them with guarded, pool-backed stacks from the
  stack allocator; the interim is recorded in ADR-0005.
- **The unwind path in `exception_common` is dead code by design**: the
  dispatch never returns in a CPL0-only kernel (every unexpected fault
  halts). It is kept correct — `movq %rbx, %rsp` restore and full pop
  sequence — because PR-1.4/1.5 turn it into the live path for Ring-3
  fault → signal delivery.

## Invariants

1. **GDT slot map = boot ABI.** The stub enters with CS=`0x18`
   (64-bit code), DS/SS=`0x10`. The kernel GDT must keep those slots
   meaning the same thing; a kernel GDT that shuffles them silently
   repoints the live segment registers at the wrong descriptors after
   `lgdt` (observed as `cs=0x18` resolving to a user-code descriptor
   during development — fixed and pinned by
   `kernel_descriptors_match_the_boot_stub_literals`).
2. **Frame uniformity.** Every stub pushes exactly `[vector][error]`
   before `exception_common` pushes `[r15..rax]`; vectors without a CPU
   error code push a zero. The dispatch reads fields by `repr(C)`
   offsets — any stub that deviates corrupts every diagnosis at once
   (the host test `frame_layout_matches_the_push_order` pins the
   layout).
3. **DPL-0 gates only.** All exception gates are encoded with DPL 0:
   ring-3 code can never raise an exception vector with `int`.
4. **Vectors 32..255 stay absent.** No device IRQ exists yet (the timer
   arrives in Stage 4) and the boot keeps IF=0; a stray IRQ hits an
   absent gate and double-faults loudly instead of running undefined
   handlers.
5. **`Tss` is `packed(4)`** because the hardware layout puts RSP0 at
   byte 4 — plain `repr(C)` would pad and desynchronize the table
   (pinned by `tss_layout_matches_the_architecture_fixed_offsets`).
6. **The selftest arming is one-shot and explicit**: `SELFTEST_ARMED`
   is set immediately before the `idiv`; any *other* `#DE`, before or
   after, is reported as a kernel bug and halts.

## Threat model

- **Fault-based info leak**: the diagnosis prints only kernel-side data
  (vector, rip, cs, error code, CR2 for #PF) to the serial console.
  When Ring-3 faults arrive (PR-1.5), the same path must not print
  user-controlled data beyond the fault address, and the audit record —
  not just the console line — becomes the durable artifact.
- **Fault storms**: today every unexpected CPL0 fault halts, so no storm
  is possible. From PR-1.5, Ring-3 fault delivery must route through
  the existing monitor counters (rate-limiting/quarantine) before a
  domain can spin the fault path.
- **Entry-path integrity**: the stubs and `exception_common` are naked
  functions under the unsafe allowlist; nothing else may register IDT
  handlers (the registry is `stubs::vector_handler`, target-only). Any
  new gate encoding flows through the host-tested `Entry::encode`.
- **IST stack reuse**: an IST stack is only reused after its handler
  finished; with all handlers terminal today this is trivially true.
  PR-1.4+ must keep IST handlers off the IST stacks of *other* vectors
  (the #NMI ordering hazard is documented above).

## Evolution points

- PR-1.2: guarded kernel stacks replace the static IST stacks.
- PR-1.4: `ExceptionFrame` gains `rsp`/`ss` (Ring-3 faults always push
  them); the unwind path becomes live; RSP0 becomes the syscall/interrupt
  kernel stack.
- PR-1.5: `report()` splits into CPL0-fatal vs Ring-3 signal delivery,
  with audit records (`FaultKind` classification) and monitor wiring.
