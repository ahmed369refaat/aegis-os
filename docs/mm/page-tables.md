# mm: per-domain page tables (PR-1.3)

> Component doc for `kernel-x86_64/src/mm/pte.rs` and
> `kernel-x86_64/src/mm/page_table.rs` — the lib's ten-check memory
> policy stays the gate; its accepted decisions become hardware. Third
> PR of `docs/STAGE1-PR-PLAN.md`; layout per
> `docs/adr/0002-higher-half-kernel-layout.md` (Accepted).

## The one idea

`PageTables::map_region` runs **the policy core's `AddressSpace::map`
first** — all ten checks (NULL page, alignment, wraparound, W^X,
overlap, **guard gaps**, quota, table-full) — and only then touches
hardware: every accepted page gets a fresh scrubbed pool frame and a
live leaf PTE with the **U bit set** and **NX set unless the region is
executable**. A refused region never writes a PTE (host-tested), and a
hardware-side failure mid-region rolls the partial mapping back and
withdraws the policy region (allocation-free: the rollback re-walks the
PTEs it is removing).

```text
  MemFlags (policy)                  PteFlags (mm/pte.rs)            leaf PTE
  ─────────────────                  ────────────────────            ────────
  R|W            ──►  r w !x user  ──►  P | W | U | NX        data page
  R|EXEC         ──►  r !w x user  ──►  P | U                 code page
  W|EXEC         ──►  rejected by the policy (WxViolation) — no PTE
  base+0, adjacent ─► rejected (GuardGap) — the gap page stays absent
```

## Structure

- **`PageTables`** — one PML4 frame per domain, walked and built through
  `memops` (direct map on the kernel; host buffers in tests — no
  recursive mapping, no unsafe in the whole module).
- **`install_kernel_entries`** — every domain PML4 copies the kernel's
  [273] (direct map) and [511] (image + stacks) entries: the *same
  physical tables*, so the kernel half is byte-identical in every
  address space and its global leaves survive CR3 switches.
- **`PoolSource`** — the kernel's `FrameSource`: boot pool + kernel
  buddy, tagging every frame with the owning domain id (0 = kernel);
  switch `owner` when building another domain's tables.
- **`map_user_page` / `map_region` / `unmap_region` / `translate` /
  `pte_of`** — the walk; `unmap_region` removes PTEs first (+ per-page
  `invlpg` on the target), frees the frames (the pool scrubs them),
  then withdraws the policy region and asserts the two agree.

## What the boot proves live (CI greps all of it)

1. Two domains, disjoint tables: **the same virtual address resolves to
   different physical frames** — each with its own pattern, read back
   through the user VA with that domain's CR3 active.
2. **W^X is a hardware property**: an instruction fetch into a domain's
   RW page faults with `err` P=1 + I/D=1 (NX violation), the dispatch
   resumes execution at the trigger's label, and a call into the RX
   page (holding a single `ret`) executes and returns.
3. **Guard gaps are absent PTEs**: reading the policy-forced gap page
   between two regions faults with CR2 naming exactly that page.

## Invariants

1. Every user PTE has **U set** and **comes from the policy gate** —
   there is exactly one mapping path, `map_region`, and it starts with
   `space.map`.
2. **No user PTE above the split**: `map_user_page` refuses
   `va >= USER_LIMIT` (0x8000_0000_0000), and `map_region` range-checks
   before the policy runs (host-tested) — the ADR-0002 user/kernel
   boundary is structural, not conventional.
3. **Guard-gap pages are absent PTEs** — never mapped, so the MMU (not
   a check) enforces them.
4. **No remap**: a present leaf refuses `map_user_page`
   (`AlreadyMapped`); unmap first.
5. **Kernel entries are shared, global, and identical** in every
   address space ([273] + [511] copied; PGE on; the direct map's 1 GiB
   leaf carries G + NX — RW, never X).
6. **Frame ownership is per-domain** — table frames and data frames
   carry the domain's owner tag; a domain destroy (`free_all_owned`)
   reclaims both.

## Threat model

- **Aliasing**: two domains mapping the same frame is *only* possible
  if someone hands out the same frame twice — the pool's owner tracking
  and the buddy make that a `NotOwnedBy`/OOM error, and `map_region`
  always takes fresh frames.
- **TLB staleness**: every unmap pairs the PTE write with `invlpg`
  (target-only); CR3 switches flush by construction. A stale mapping
  would silently break invariants 2/3.
- **Direct-map leakage into user hands**: a domain's tables contain the
  kernel's [273] — necessary while kernel and user share an address
  space (KPTI is a Stage-7 option). The Ring-3 gate (PR-1.5) must
  never let CPL3 *read* those entries' targets: CPL3 access to a U=0
  page faults regardless of which table maps it — the U bit, set only
  on policy-accepted user pages, is the enforcement.
- **Fault-resume stack discipline**: the NX probe deliberately executes
  a faulting *`jmp`* (not `call`): a faulting `call` pushes its return
  address **before** the fetch fault, and resuming with that push still
  on the stack silently slides every RSP-relative local in the caller —
  a real bug found by the live selftest, documented in
  `arch/exceptions.rs`.

## Evolution

- PR-1.4: `PageTables` moves into `Domain`; RSP0 ← a guarded stack;
  SYSCALL/SYSRET entry with the tables already correct.
- Stage 2 (IPC): shared frames appear — the aliasing threat model above
  becomes a deliberate, policy-gated capability.
- Stage 7 (KPTI): if the direct map-in-every-space cost is real, the
  per-domain copy becomes a trampoline-only kernel entry — the table
  builder already isolates that decision in `install_kernel_entries`.
