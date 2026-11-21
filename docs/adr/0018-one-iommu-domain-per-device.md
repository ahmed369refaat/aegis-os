# ADR-0018: One IOMMU domain per device — the isolation ADR-0013 promised

- **Status:** Accepted (implementation: review round 5, Phase A)
- **Stage:** M3 driver stack / Stage-1 isolation (closes the main remaining gap of ADR-0013)
- **Date:** 2026-11-21
- **Supersedes:** none; amends ADR-0013 (enforcement), ADR-0015 (domain-scoped cookies), ADR-0017 (a ring-3 driver domain owns its IOMMU domain)

## Context

Review round 5, Phase A finding: every device in the stack is assigned
to IOMMU **domain 0** — `assign_device(0, …)` at the five claim sites
in `drvstack/pci.rs` plus the VT-d hardware proof, every mapping is
`map_region(0, …)`, and every teardown is `revoke_all(0)` (≈21 sites,
all through `DriverSession` since ADR-0016). Three consequences:

1. **One shared second-level table.** All devices walk `dom_slpt[0]`,
   so any device can DMA into any other device's mapped buffers
   (IOVA == PA, identity). The isolation ADR-0013 claims between the
   machine and the kernel exists; between devices it does not.
2. **One driver's teardown is every driver's teardown.** A session's
   `revoke_all(0)` unmaps the regions of every concurrently mapped
   driver — the lane ordering hides it today only because the steps
   run sequentially.
3. **ADR-0015's domain-scoped cookies are dead weight** while every
   region lives in the same domain: a cookie handed to the wrong
   driver would be accepted, because the domain check always passes.

The hardware layer is NOT the gap: `Vtd` already keeps a per-domain
SLPT root (`dom_slpt: [Option<u64>; MAX_VTD_DOMAINS]`), programs
1-based DIDs (`DID = dom + 1`), and refuses out-of-range domain ids.
The gap is entirely in kernel orchestration.

## Decision

1. **A device owns exactly one IOMMU domain; a domain serves at most
   the devices assigned to it.** Domain **0 is the kernel's own
   domain** — the ADR-0013 hardware proof and the broker demo map
   there; a *device* is never assigned to it. Device domains are
   `1 .. MAX_VTD_DOMAINS-1`.
2. **Domain ids are kernel-allocated, never device- or
   driver-supplied.** A `DomainIds` bitmap allocator (session.rs)
   pre-reserves domain 0, hands out the rest, and refuses exhaustion
   with `None` (the caller claims the device later or refuses the
   driver step). `release` is explicit, refuses double-release, and a
   released id is reusable only after the device's context entry is
   cleared.
3. **`assign_device` refuses a device already assigned to a different
   domain** (the round-5 test list pins this), and gains
   **`unassign_device`**: clear the context entry, invalidate the
   context cache through the QI — the only way a device changes
   domains. The hardware proof assigns its probe device, proves, then
   **unassigns and releases** — the boot's later per-device claims
   start from a clean context table.
4. **`DriverSession` carries the domain id** (from the device's
   `PciDev.dom`, set at claim time by `pci_step` through the
   allocator): `map_region(dom, …)`, `region_complete` /
   `unmap_region(dom, …)`, and the teardown's `revoke_all(dom)` are
   all scoped by it. One session's teardown now provably leaves every
   other session's mappings alone.
5. **The table budget is sized by a pure worst-case function, not a
   guess.** `worst_case_tables(domains)` = shared (root + IQ + one
   context table for bus 0) + per-domain (SLPT root + PDPT + one PD +
   one PT per 2 MiB span of the 16 MiB identity-mapped pool — 8
   spans). `TABLE_BUDGET` = that function at `MAX_VTD_DOMAINS`; the
   frames still come from the pool with `VTD_TABLE_OWNER` accounting.
   Exhaustion stays a typed refusal (`OutOfTables`), `map_run` stays
   atomic (ADR-0015: partial failure leaves no residue, cursor
   consistent, no table aliasing), and the exhaustion test runs
   against the NEW multi-domain sizing.
6. **Teardown markers tell the truth.** `revoke_or_quarantine`
   reports `revoked`, `freed`, `quarantined` and `poisoned` counts,
   and never prints "frames return scrubbed" when any region was
   poisoned — quarantined frames do NOT return to the pool.
7. **The lane proves cross-device isolation live.** A negative probe
   step maps a page ONLY in a probe domain, then makes the e1000 (in
   ITS domain) DMA at it: the read must FAULT (FSTS.PPF set) and the
   lane grep requires the fault marker — `--verify-q35` FAILS if the
   cross-device DMA does not fault.

## Consequences

- Cross-device DMA becomes an IOMMU fault, not a silent success; one
  driver's teardown becomes scoped to its own mappings; ADR-0015's
  cookies finally have a second domain to be wrong in.
- The e1000/virtio-net device-DMA cluster findings of earlier rounds
  keep their per-device containment story: when those data paths are
  driven, their faults will be per-device.
- Budget cost: with 8 domains the worst case is 3 shared + 8 × 11
  per-domain tables = 91 pool frames (of 4096) — measurable, bounded,
  and asserted by test instead of assumed.
- Boot markers change where they lied ("→ dom 0 ok", "revoke_all(0)"):
  the greps are updated in the same commits, and the new markers carry
  the real domain id and the real counts.
- What does NOT change: `map_run` atomicity, poison quarantine,
  RW1C/claim discipline, the fail-closed verdicts. ADR-0017's model
  gains its concrete substrate: a ring-3 driver domain will own
  exactly one of these per-device domains.

## Alternatives considered

- **Keep domain 0 for everything and rely on audit.** Rejected: this
  is the finding; the shared-SLPT consequence is structural, not a
  bug to patch.
- **Per-device domains with ids chosen by the driver.** Rejected: a
  confused or hostile driver must not be able to name another
  device's domain; the allocator is kernel-side and ids ride with the
  claim, not the request.
- **One domain per DRIVER (not device).** Deferred: correct for
  multi-function devices and ring-3 driver domains (ADR-0017), but
  today every driver drives exactly one function; the release rules
  here are written so the owner can become a driver domain without
  changing the allocation rules.
- **Grow TABLE_BUDGET by fiat.** Rejected: an unproven budget is the
  same class of bug as the finding; the pure function + exhaustion
  test make the sizing a checked invariant.
