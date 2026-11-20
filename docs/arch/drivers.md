# The driver stack — architecture and status (2026-11-20)

This document is the map of every device driver in AegisOS: how a
device is claimed, how its DMA is brokered, what is proven on the
boot lane, and what remains. The companion evidence lives in the
boot markers (`boot.sh --verify-q35`) and
[DRIVER-STACK-CHECKLIST.md](../DRIVER-STACK-CHECKLIST.md) carries the
per-item ledger.

## The claim discipline (every DMA device)

No driver talks to a device directly. The path is always:

1. **PCI inventory** — the bus scan (dword port I/O, `hw::inl/outl`)
   reads vendor/class/caps. `0x1AF4` virtio, `0x1234` QEMU std VGA.
2. **The claim gate** (`pci::check_claim`) — an endpoint, not a
   bridge; not RMRR-covered; the IOMMU verdict must be live. Any
   refusal is fail-closed: the driver gets no device.
3. **Broker assignment** (`DmaBroker::assign_device`) — the VT-d
   context entry is written (P | TT=0b10 | SLPTPTR) and the device is
   bound to its domain.
4. **Map-then-tell** — every frame the device will DMA is
   `map_region`ed through the broker BEFORE any address reaches the
   device. The device never sees an unmapped address.
5. **Teardown** — `revoke_all` unmaps, frames return to the pool
   scrubbed (the M1 zero-leak accounting holds with live devices).

## The transport: virtio 1.0 over MMIO (virtio-pci modern)

One implementation drives every virtio device (`virtio.rs`):
cap-chain parse → BAR resolution → modern handshake
(ACK|DRIVER → features VERSION_1+ACCESS_PLATFORM → FEATURES_OK) →
queue setup → DRIVER_OK → ring publish + kick → bounded used-ring
poll. Device drivers build on it: **virtio-blk** (complete: sector
read, write+read-back, enforcement probe partial, teardown) and
**virtio-net** (see open items).

## The MMIO discipline (the hard-won rules)

QEMU dispatches device registers on **access address + width**. Three
bugs taught us the rules the hard way; all three are pinned in code
comments and tests:

- **Common-config registers need exact-width 2-byte accesses at the
  exact register address.** A u32 read-modify-write at the aligned
  base is dispatched as the BASE register (e.g. STATUS), silently
  eating QUEUE_SEL — queue selection was stuck at 0, invisible for
  virtio-blk (its only queue IS 0) and fatal for virtio-net's TX
  queue. Hence `memops::write_u16/read_u16` and the exact-width
  accessors in `MmioVirtio`.
- **The kick is `iowrite16(queue_index)` at the queue's own notify
  slot** (`notify_base + notify_off × multiplier`), exactly Linux's
  `vp_notify`. A 4-byte store is split by QEMU into two 2-byte
  dispatches (two `queue_notify` traces per kick); the RMW lane is
  forbidden (notify reads are undefined).
- **VT-d GCMD is written as one accumulated word** (Linux's pattern);
  QEMU interprets a missing enabled bit as a DISABLE command — a
  single-bit TE write silently disabled the invalidation queue. And
  the context entry's TT bits 3:2 = 0b10 select the four-level walk
  (QEMU decodes depth = 2 + TT).

## The classic devices (polling, no DMA, no broker)

- **Screen/GPU (`gfx_step`)** — bochs-dispi VBE mode set
  (0x1CE/0x1CF: 640×480×32 linear) on QEMU std VGA; the framebuffer
  BAR must sit inside the pre-mapped 4th-GiB MMIO window. The boot
  lane proves the whole path: QMP `screendump` captures what the card
  shows and the host verifies 7/7 sampled pixels against the drawn
  pattern (bands, checkerboard, bitmap-font text).
- **Keyboard (`ps2_step`)** — i8042 flush, self-test (0xAA→0x55),
  first-port enable, bounded poll. The boot lane's QMP driver
  injects a key on the "armed" marker; the received scancode 0x1e is
  a real host→guest input round trip.
- **Clock (`rtc_step`)** — MC146818 at 0x70/0x71, BCD-decoded,
  update-in-progress guarded; the marker carries the live host time.
- **Serial console** — the boot's primary output channel.

## Status and open items (honest ledger)

| Driver | Status | Proof |
| --- | --- | --- |
| virtio-blk | **complete** | sector read status=OK; write+read-back round trip; teardown revoke+scrub |
| virtio-blk enforcement probe | **partial** | request to a broker-unmapped page completed with status OK, no PPF — the denial/invalidation interplay on QEMU's caching is the open question (page-selective invalidation is the candidate) |
| virtio-net | **90%** | handshake, MAC/link, both queues, 8 broker-mapped frames, queue-1 readback, DHCP DISCOVER built (checksum vector-tested) and published+kicked, teardown |
| virtio-net TX consumption | **open (QEMU-side)** | the kick dispatches (`virtio_queue_notify n=1` in the trace), vring ready, zero VT-d faults, ISR clear, used ring never advances; guest-side state fully verified by readback — the gap is inside QEMU's TX bottom-half on this lane |
| screen/GPU (VBE) | **first slice, pixel-proven** | 7/7 sampled pixels match in the QMP screendump |
| PS/2 keyboard | **first slice, round-trip-proven** | QMP send-key → scancode 0x1e |
| RTC | **first slice** | live host time, BCD-decoded |
| USB (xHCI + HID) | **not started** | the plan stays checklist item 12: qemu-xhci on the lane, capability discovery (CAPLENGTH/MaxSlots/doorbell off) as the first slice, enumeration + one HID keyboard behind the broker |
| virtio-gpu | **not started** | would reuse the proven virtio transport + the VBE pixel-check harness |
| e1000 / NVMe / AHCI | **not started** | checklist items 10/6/7 |

## Why USB and the rest are sequenced after virtio

Every virtio device shares one audited transport; USB (xHCI) is a
whole second transport (event rings, TRBs, descriptors, hubs) and is
sized as its own phase (checklist item 12, hub/tree support
explicitly out of scope in its ADR). The broker discipline and the
MMIO lessons above apply to it unchanged.
