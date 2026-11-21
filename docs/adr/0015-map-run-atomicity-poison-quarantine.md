# ADR-0015: map_run atomicity and poisoned-region quarantine (review round 4, F1–F3)

- **Status:** Accepted (implemented in the same commit group)
- **Stage:** M2 driver stack, review round 4, Phase 2.
- **Date:** 2026-11-21
- **Depends on:** ADR-0013 (the broker/`DmaProt` contract), ADR-0014
  (the tables are load-bearing — atomicity and rollback now guard a
  translation path the device actually walks).
- **Note on numbering:** review round 4 reserved "ADR-0015" for the
  Phase-4 drvstack split and "ADR-0016" for Phase-6 driver domains,
  assuming no numbers consumed in between. ADR-0014 (Phase 1) shifted
  the sequence: this ADR takes 0015 as the next free number; the
  Phase-4 split becomes 0016 and Phase-6 domains 0017.

## Context

Three findings from review round 4, all in the IOMMU integrity layer:

- **F1 — `Vtd::map_run` is not atomic.** On a mid-run error (table
  budget exhausted at page k) the SLPTEs for pages 0..k stay written
  with no region recorded, and `self.table_cursor = cursor` runs only
  after the loop — so table frames already linked into the tree are
  handed out again by the next map. Two parents pointing at one table
  frame is table corruption: writes to one mapping silently rewrite
  another. Under ADR-0014 the tables are load-bearing, so this is now
  a live integrity bug, not a theoretical one.
- **F2 — `DmaBroker::revoke_all` ignores `unmap_run` errors** (`let _ =
  ...`), frees the region slots, and lets the caller reclaim the
  frames. If the hardware unmap failed, the device can still DMA into
  every page of that region — pages that may already be re-allocated
  to a new owner. That is exactly the fail-open path ADR-0013 exists
  to close.
- **F3 — cookies are not domain-scoped.** `unmap_region(cookie)` /
  `region_complete(cookie)` take a sequential cookie alone, so a
  driver that guesses (or overhears) another domain's cookie can
  complete or unmap that domain's regions — an oracle and a
  cross-domain interference primitive in one.

## Decision

1. **`map_run` is atomic — a `DmaProt` contract guarantee.** The
   implementation (a) computes the table demand of the run with a pure
   read-only walk (`tables_needed`) and refuses with `OutOfTables`
   BEFORE touching a single entry when the budget cannot cover it;
   (b) commits the table cursor for every frame it linked on every
   exit path, so a table frame is never referenced by two parents;
   (c) on any residual error, rolls back every page the call wrote
   (clear SLPTEs, one queued invalidation) so a refused map leaves the
   tables exactly as it found them. `mapped_pages` advances only on
   success.
2. **Revoke fails closed.** `revoke_all(dom)` returns
   `RevokeOutcome { revoked, poisoned }`. A region whose hardware
   unmap failed becomes **poisoned**: it stays recorded in a poison
   list (counted against the domain's region/byte quotas, because the
   hardware mapping is still live), its frames are re-tagged in the
   `FramePool` under a dedicated `QUARANTINE_OWNER` and never return
   to the allocator, and the teardown path clears the device's PCI
   bus mastering. `retry_poisoned()` re-attempts the unmap +
   invalidation; only on success does the region leave the poison
   list, and only then may the kernel free (and the pool scrub) those
   frames. Poisoned regions are reportable to the kernel
   (`poisoned_regions()`) for quarantine bookkeeping — the addresses
   stay kernel-internal (ADR-0013 D4).
3. **Cookies are domain-scoped.**
   `unmap_region(dom, cookie)` / `region_complete(dom, cookie)`; a
   cookie that belongs to a different domain returns the same
   `InvalidHandle` as an unknown cookie (no oracle), and the domain id
   always comes from the kernel, never from a driver.

## Consequences

- A refused map can no longer corrupt the tables (no aliasing) or leak
  mappings (no residual SLPTEs); the invariant is checkable at any
  time by the pure `check_no_table_aliasing` walk, exercised by a
  deterministic xorshift property test over random map/unmap
  sequences with a tiny budget.
- A failed teardown can no longer hand device-reachable frames to a
  new owner: the worst case is a bounded, counted, reportable
  quarantine — the fail-closed outcome ADR-0013 promised.
- Cross-domain cookie probing becomes indistinguishable from
  invalid-handle noise.
- New tests: `map_run_is_atomic_on_budget_exhaustion`,
  `xorshift_map_unmap_sequences_stay_atomic_and_unaliased` (Vtd),
  `check_no_table_aliasing` (pure), a reusable `dma::contract` harness
  (round trips, unmap idempotence, post-failure cleanliness) run
  against both the fake and the real `Vtd`, broker poison/retry tests
  with a failing fake, and cross-domain/stale/double-complete
  equality tests.
- The kernel teardown paths print honest outcomes (a poison line when
  one occurs; the happy-path markers stay byte-compatible with the
  lane greps). The full one-`close()`-per-driver unification remains
  Phase-4/F10 work.

## Alternatives considered

- **Fix only the cursor commit (no precompute).** Rejected: it stops
  the aliasing but leaves partial SLPTEs mapped on refusal — half the
  finding.
- **Poison by keeping the region in `slots` forever.** Rejected: a
  separate poison list keeps the live-region semantics honest (poison
  counts still hold quota) without overloading the grant path, and
  gives the kernel a clean enumeration for quarantine.
- **Retry unmap inside `revoke_all` until it succeeds.** Rejected:
  unbounded spin against failing hardware; the bounded, explicit
  `retry_poisoned()` keeps the failure visible and the caller in
  control.
- **Make cookies unguessable instead of domain-scoped.** Rejected as
  the primary fix: 64-bit random cookies raise the cost of guessing
  but leave the cross-domain confusion class intact; scoping closes
  it. (Random-looking cookie material may still be layered on later.)
