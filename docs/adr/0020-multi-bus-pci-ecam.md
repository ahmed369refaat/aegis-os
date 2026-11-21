# ADR-0020: Multi-bus PCI — the ECAM access seam and the recursive bridge walk

- **Status:** Accepted (implementation: review round 6, "G")
- **Stage:** M3 driver stack / discovery (closes the "PCI bridge/multi-bus walk and ECAM" row of the gap analysis)
- **Date:** 2026-11-21
- **Supersedes:** the F9 isolation refusal in `drvstack/pci.rs` (bus 0
  only); amends ADR-0013's discovery phase.

## Context

`pci::enumerate` walked bus 0 flat, dev 0..32 × fn 0..8, through
0xCF8/0xCFC. Bridges were DETECTED (type-1 headers, class 06) but
never traversed — `drvstack/pci.rs` printed the honest refusal
("devices behind it are NOT driven (isolation boundary, F9)") and
`check_claim` never saw them. The MCFG was parsed, validated, and
printed (`[MCFG] ECAM base …`) but never USED for access. On real
hardware this misses NVMe controllers and NICs behind root ports —
the reason the gap analysis carried a whole row for it.

The second half: CF8/CFC is a PC-compatibility interface. UEFI-only
servers can omit it; there the ONLY config access is the ECAM window
the MCFG declares (`base + (bus−start)<<20 | dev<<15 | fn<<12`).

## Decision

1. **The config-space access is a seam** (`pci::CfgAccess`):
   `LegacyPorts` (0xCF8/0xCFC — the bus rides the address word, so
   it covers every bus by itself) or `Ecam { base, start_bus,
   end_bus }` (the MCFG window). Both halves resolve through the
   same pure, bounds-checked address math (`ecam_addr`: checked
   arithmetic, dev<32, fn<8, bus inside the MCFG's declared window —
   a wrong address refuses, never faults). The boot step picks ECAM
   when the firmware's MCFG validates (`acpi::ecam_window`: dir walk
   → table_ok → first entry, segment 0 only) and prints WHICH seam
   the machine offered — the two are not equivalent and the log must
   not blur them.

2. **The walk is recursive through type-1 bridges**
   (`pci::enumerate_multi`): every recorded device's header is
   checked; a type-1 header's secondary bus (the dword at 0x18,
   decoded by the pure `bridge_buses`) is walked recursively.
   Guards: a **visited-bus set** (a bridge pointing at an
   already-walked bus — including a self-pointing bridge — is a
   topology loop: stopped, not followed) and a **depth cap of 8**
   (`MAX_WALK_DEPTH`; chains deeper than any real machine are
   malformed firmware). The per-device work (header, BAR sizing,
   capability walk) is the SAME code, now bus-parameterized — the
   `size_bars`/`walk_caps` signatures gained a `bus` argument
   instead of growing a parallel implementation.

3. **The F9 refusal is lifted.** Devices behind bridges land in the
   inventory with their REAL bus numbers and go through the same
   claim gate as any other endpoint: endpoint header, not
   bridge-class, live IOMMU verdict, not RMRR-covered, then the
   broker's `assign_device` into their own ADR-0018 domain. The old
   marker becomes the truth: "bridge at this slot — traversed:
   devices behind it ARE enumerated".

4. **The inventory cap rises 32 → 48** (q35 with one root port +
   one child lands ~24; 48 leaves room for a real NIC + NVMe card
   without silently dropping them — exhaustion stays fail-loud).

5. **The lane proves it end to end:** the q35 machine gains
   `-device pcie-root-port` with a second virtio-blk BEHIND it
   (SeaBIOS programs the bus numbers + BARs; the walk must traverse
   to find it). Markers: `[PCI ] config access: ECAM @…` (the q35
   MCFG window drives the scan), `[PCI ] bridge at this slot —
   traversed`, and the bus-1 device line (`[PCI ] 1:0.0 …`) — a
   device that DID NOT EXIST in the inventory before this ADR.

## Consequences

- **Discovery is real-machine-shaped:** NVMe/NICs behind root ports
  are found, sized, claimed, and domain-isolated like bus-0
  devices.
- **The drivers still read config through CF8** (via
  `pci::read_cfg32`) — correct on every PC and on QEMU, since the
  port pair covers all buses; migrating the per-device accessors to
  the seam is a mechanical follow-up for the first UEFI-only
  target, not a new decision.
- **Segment > 0 machines are out of scope** (stated, refused to the
  legacy seam) — multi-segment is a NUMA-server concern this stack
  does not model yet.
- **CardBus (type-2) headers are detected as non-type-1 and not
  traversed** — the honest cap; nothing on any target machine uses
  them.

## Tests

Host: the ECAM address math pinned field-by-field (bus<<20 relative
to the window start, dev bit 15, fn bit 12, dword-alignment mask)
with bound/overflow refusals; both seams' `resolve` behavior (a
narrow MCFG window refuses outside buses; legacy covers 0..255);
the type-1 dword decode; the walk against a fake config space — a
real bridge traversal recording the child's true (bus, dev, fn), a
self-pointing loop stopped by the visited set, and a 12-deep chain
cut at the depth cap (the bus-12 endpoint absent, bus-7 present).
Lane: the markers above, on the machine that has the root port.
