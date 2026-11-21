# ADR-0017: Ring-3 driver domains — drivers as monitored, brokered clients

- **Status:** Accepted (the first slice — the `IpcMmio` channel + device core — landed host-proven, round 5 Phase E; the ring-3 transport + boot integration is the next slice)
- **Stage:** M3 driver stack (the architecture ADR-0016 built its seams for)
- **Date:** 2026-11-21

## Context

Every driver in the stack runs at ring 0 today. The review rounds
(F4–F13) hardened the *code* — device-supplied numbers are validated,
windows are checked, lifetimes are owned — but the *consequence model*
is unchanged: a driver bug or a missed validation is still a kernel
compromise, because the driver shares the kernel's privilege. The
project's own invariants say that is the wrong shape: heavier logic
belongs in *monitored client domains*, never in the fast path
(GAP-ANALYSIS invariants, restated in every plan since).

Three sessions of groundwork made the migration possible without
rewriting the drivers:

1. **ADR-0016's `MmioBus`**: every driver is already written against
   a trait whose accessors take window-relative offsets and refuse
   out-of-window access. The seam an `IpcMmio` implementation needs
   exists and is host-tested.
2. **ADR-0016's `DriverSession`**: the teardown discipline is already
   one owner per run, generic over `DmaProt` — a driver domain's
   resources revoke identically whether the driver is in the kernel
   or outside it.
3. **ADR-0013/0015's broker**: DMA is already domain-scoped,
   cookie-addressed, quota'd, and poison-aware. A ring-3 driver
   cannot name a physical address even if it wants to.
4. **ADR-0018's per-device domains**: a ring-3 driver domain will
   own exactly one of the per-device IOMMU domains — the allocation,
   release and re-assignment rules are already written for that
   owner.
5. **ADR-0010's ring-3 machinery + ADR-0004's IPC + the monitor**:
   launch/resume, capability-gated endpoints, and organic-signal
   scoring all exist and are boot-proven.

## Decision

Drivers become **ring-3 driver domains**. The kernel keeps a minimal
ring-0 *device core* per driver — the window check, the volatile
access, the queue teardown — and everything else (handshakes, ring
walking, parsing, policy) runs in a domain with exactly four grants:

1. **An `MmioBus` channel, not the registers.** The domain's bus is
   `IpcMmio`: a register access becomes an IPC message
   (`Read{off,len}` / `Write{off,len,val}`) to the device core, which
   checks the offset against the SAME validated window (ADR-0016's
   `BarMmio` discipline) and performs the access. The driver code is
   unchanged — it was written against the trait.
2. **DMA only through the broker.** The domain's session maps frames
   into ITS domain id; the broker's domain-scoped cookies mean a
   confused-deputy driver can only revoke or use its own mappings.
3. **A monitor feed.** The device core reports organic signals the
   domain cannot forge or suppress: window violations, doorbell
   rates, completion-timeout patterns. The BehaviorMonitor — the
   single decision maker — scores them with the same
   Log→Tighten→Quarantine ladder as any other domain.
4. **A capability to the device.** The domain holds a `Device`
   capability (ADR-0009) for ITS device, granted at claim time;
   attenuation is the only way it reaches anything, and there is
   nothing else to reach — the MMIO window and the broker regions
   are the whole surface.

A driver domain that faults, loops, or spams is quarantined like the
ring-3 rogue in today's monitor demo: the device core stops serving
its channel, the session revokes, and the boot continues. The F4
history (a capability offset that could panic the kernel) becomes a
domain crash instead — the class of consequence the whole
architecture is for.

## Consequences

- **The consequence model matches the invariants**: a driver bug is a
  domain event, scored and contained, not a kernel compromise. The
  F4–F13 hardening stays (it is what makes the ring-0 device core
  small enough to trust) but stops being the only line.
- **Performance**: every register access is an IPC round trip. The
  polling drivers (NVMe/e1000 completion polls, the AHCI CI waits)
  pay per poll; the device core can batch (`Read{off,len>8}`) and the
  hot polls can move INTO the device core behind one message
  ("wait for doorbell/cycle bit, budget N") — the driver keeps the
  policy, the core keeps the spin. First slice measures before
  optimizing.
- **What we do NOT do in this phase**: no interrupt routing (drivers
  stay polling; IRQ delivery to ring 3 is a later ADR), no shared
  devices (one domain per device function), no dynamic driver
  loading (the domain image is built with the kernel like the
  ring-3 examples), and no user-space driver API — the domain talks
  IPC to its device core, and that protocol IS the contract.
- **Testing**: `IpcMmio` is host-testable through the same fake
  channel pattern as the `MmioBus` window tests (a driver written
  against the trait runs unchanged against a fake device — proven
  in ADR-0016's test module). The boot lane grows a
  `driver-domains=1` marker with the first migrated driver; the
  quarantined-driver-domain path gets the same lane treatment as the
  rogue-domain demo.

## Alternatives considered

- **Keep ring-0 drivers and keep auditing.** Rejected: F4 proved a
  capability offset away from a kernel panic; the audit surface
  grows with every driver. The invariants demand monitored clients.
- **Full L4-style microkernel drivers** (everything is IPC, the
  kernel has no driver code at all). Rejected for now: paging and
  address-space management for user drivers is a stage the roadmap
  has not opened; the device core's windowed access is 50 lines of
  auditable `unsafe`-adjacent code, not a driver.
- **IOMMU-only containment without ring 3.** Rejected: it contains
  DMA (ADR-0013/0015 did that) but not register access or the
  kernel-resident parsing that F4–F8/F13 kept finding. Ring 3 is the
  containment boundary for code; the IOMMU for data; both are
  needed.
- **`vDSO`-style shared-memory register windows.** Rejected:
  registers have side effects (RW1C status bits, doorbells); an
  unsynchronized writable mapping reintroduces exactly the
  device-steers-the-kernel class ADR-0016 closed.
