# mm: higher-half kernel + direct map (PR-1.2)

> Component doc for `kernel-x86_64/src/mm/` — the virtual memory layout,
> the direct map, guarded kernel stacks, and the bring-up teardown that
> enforces it. Stage-1 Track A, second PR of `docs/STAGE1-PR-PLAN.md`;
> layout decided by `docs/adr/0002-higher-half-kernel-layout.md`.

## The map (as it exists after this PR)

```text
0x0000_0000_0000_0000 ┌────────────────────────────────────────────┐
                      │ USER HALF — entirely absent. The stub's     │
                      │ bring-up identity window (PML4[0]) is torn  │
                      │ down in mm::init before anything else runs; │
                      │ a low access today is a diagnosed #PF.      │
                      │ (Ring-3 domains get PML4[0..256] in 1.3/1.4)│
0xFFFF_8880_0000_0000 ├────────────────────────────────────────────┤ PML4[273]
                      │ DIRECT MAP — PA 0..1 GiB, RW, kernel-only,  │
                      │ never executable. One 1 GiB huge page built │
                      │ by the stub. All physical access (frame     │
                      │ pool, multiboot info, page tables, scrub)   │
                      │ goes through it: memops translates.         │
0xFFFF_FFFF_4000_0000 ├────────────────────────────────────────────┤ PML4[511]·PDPT[509]
                      │ GUARDED KERNEL STACKS — mm/stacks.rs. One   │
                      │ 2 MiB slot per stack: page 0 absent (the    │
                      │ guard), stack pages after it; PD + PT allo- │
                      │ cated from the frame pool on demand.        │
0xFFFF_FFFF_8000_0000 ├────────────────────────────────────────────┤ PML4[511]·PDPT[510]
                      │ KERNEL IMAGE — RX text, RO data, RW data +  │
                      │ bss + boot stack. Linked at this base,      │
                      │ loaded at PA 2 MiB (linker AT()), mapped by │
                      │ one 2 MiB huge page. Fits, or the link      │
                      │ fails (linker.ld ASSERT).                   │
                      └────────────────────────────────────────────┘
```

## What each piece proves, live, on every boot

`boot.sh --verify` greps all of these; a missing marker fails CI:

1. `[MM ] higher-half ok: base=… identity=pml4[0]:0 percpu:cpu=0` —
   `mm::init` wrote `PML4[0] = 0` **through the direct map**, reloaded
   CR3, and read the entry back to prove it; per-CPU state is anchored
   at the GS base.
2. The M1 sequence still passes with every physical access (multiboot
   info, pool scrub, pattern writes, read-back) flowing through the
   direct map — `memops` is the only physical-memory door, and its
   translation is `direct_map::pa_to_va` (host-tested round trips).
3. `[MM ] guarded stacks: alloc+map+cross-view ok, free+scrub ok` — a
   real stack lived its whole life: frames + PT from the pool, one word
   written through the stack VA, the **same word read through the
   direct map at the frame's physical address** (two views of one
   physical word must agree), then freed with scrub-on-free.
4. `[EXC] #PF vector=14 … cr2=<guard page>` + `[EXC] guard selftest:
   stack guard #PF ok` — a deliberate write through a fresh guard page
   faults, CR2 names exactly that page, and the run powers off cleanly.
   (Before that, the PR-1.1 `#DE` selftest now **returns**: the
   dispatch advances RIP past the faulting `idiv` and `exception_common`
   unwinds — the return path Ring-3 signal delivery will need.)

## Invariants

1. **The kernel never maps user pages into the kernel half, and no
   direct-map or stack-region PTE is executable** (the direct map is
   `RW`, stacks are `RW`; X only inside the kernel image window —
   W^X by construction until PR-1.3's per-domain tables make it a
   checked invariant of every table walk).
2. **Low virtual addresses are dead**: after `mm::init`, PML4[0] is 0
   and the TLB is flushed. Any low access is a #PF, not a silent alias.
   Ring-3 gets that half back in PR-1.3/1.4 with per-domain tables.
3. **Physical memory has exactly one kernel door**: `memops` (the
   allowlisted volatile layer) translates every "physical" access
   through `pa_to_va`; `mm` itself is unsafe-free and so is everything
   above `memops`. The `_va` variants exist only for already-virtual
   addresses (guarded stacks).
4. **A guard page is an absent PTE, not a check**: kernel stacks are
   unusable past their end — the MMU is the enforcer, proven by the
   live #PF selftest. Slots are 2 MiB apart and never reused
   (monotonic cursor).
5. **The kernel image must fit one 2 MiB huge page** (PA 2..4 MiB) —
   the linker ASSERT fails the build otherwise, which is also what
   keeps it clear of the frame pool at 16 MiB.
6. **Per-domain ownership even for kernel objects**: guarded-stack
   frames carry pool owner 0 (`OWNER_KERNEL`); domain ids start at 1,
   so `free_all_owned(domain)` can never sweep kernel frames.

## Threat model

- **Physical-address disclosure**: the direct map makes all RAM
  readable from kernel space — that is what kernel space is for; the
  Ring-3 gate (PR-1.5) must never let a domain's PTEs point into
  PML4[273..511]. PR-1.3's table builder enforces it structurally
  (user tables get only their own frames).
- **Exec-through-the-direct-map**: a kernel bug that jumps into the
  direct map would execute attacker-controlled pool data. The RW-only
  mapping makes that a #PF today; PR-1.3+ keeps it non-executable even
  when per-domain tables clone kernel entries.
- **Guard-page bypass**: nothing may map the guard page later — the
  allocator only writes PT[1..], and slots are never reused after
  free (a stale PT entry would be the only way back in; free zeroes
  them and invalidates).
- **TLB staleness**: every unmap path pairs the PTE write with
  `invlpg`; the teardown pairs the PML4[0] write with a CR3 reload.
  A stale mapping would silently break invariant 2.

## Evolution points

- PR-1.3: per-domain page tables (user half, policy → PTEs); the table
  builder reuses `mm`'s entry constants and the pool.
- PR-1.4: RSP0 ← `percpu::get().kstack_top`; ring-3 entry switches to a
  guarded stack; `ExceptionFrame` gains `rsp`/`ss`.
- Stage 7: KASLR slides the kernel image window inside PML4[511] and
  randomizes stack slots; both are layout-agnostic today.
