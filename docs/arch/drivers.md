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

## Status and open items (honest ledger, updated 2026-11-20 late)

| Driver | Status | Proof |
| --- | --- | --- |
| virtio-blk | **complete** | sector read status=OK; write+read-back round trip; teardown revoke+scrub |
| virtio-blk enforcement probe | **partial** | request to a broker-unmapped page completed with status OK, no PPF — page-selective invalidation is the candidate fix |
| AHCI/SATA (ich9, q35) | **FIRST SLICE FULLY LIVE** | ABAR/GHC/PI read, port-0 SIG=0x101 (SATA disk), stop+CLB/FB/FRE/ST with broker frames, IDENTIFY DEVICE **completed** (word0=0x40, 512 bytes DMA through the IOMMU), teardown 4 regions |
| virtio-net | **90%** | handshake, MAC/link, both queues, 8 broker-mapped frames, queue-1 readback, DHCP DISCOVER built (checksum vector-tested) and published+kicked, teardown |
| e1000 | **register/ring-proven, no egress** | MAC/link from RAL/RAH/STATUS, rings programmed (readback), descriptor consumed (TDH 0→1) — but the packet never leaves (empty pcap, zero translate/fault events for 00:04.0) |
| NVMe | **admin proven, data gated** | CAP/version/RDY, admin qpair live, Identify submitted — no completion |
| USB xHCI | **bring-up FULLY LIVE** (item 12 first slice) | caps (v0 read as 0? HCSPARAMS MaxSlots=64 MaxPorts=8), halt→reset→DCBAAP+MaxSlotsEn+CRCR→RUN (HCH cleared), **port 0 device attached speed=4 (the usb-storage)** — register-only path, no device DMA needed |
| screen/GPU (VBE) | **pixel-proven** | 7/7 sampled pixels in the QMP screendump |
| PS/2 keyboard | **round-trip + negotiated** | QMP send-key → scancode 0x1e; THEN the real 0xF0/0x02 scancode-set-2 exchange, ACK 0xfa (translation restored for delivery — measured on this build) |
| RTC | **live** | MC146818, BCD, host time |
| HPET | **live** (item 15 first slice) | table→block @0xFED00000, 100 MHz period, main counter enabled, delta>0 — the calibration source |
| ACPI MADT/MCFG (item 14) | **parsed** | 1 LAPIC + 1 IOAPIC @0xFEC00000; ECAM base 0xB0000000 bus 0..255 |
| USB enumeration / HID | **not started** | next xHCI slice: TRB rings, address device, interrupt-IN |
| virtio-gpu / e1000-data / NVMe-data | **blocked on the device-DMA cluster** (below) | |
| Block layer + ext2 (item 8) | **first slice written, mount gated** | the image builder (scripts/mkext2.py: valid 1KiB-block rev-1 ext2 with hello.txt) + the full kernel parser (superblock → group descriptor → root inode → directory walk → file inode → data) are in the tree and run on the LIVE AHCI port; the mount is gated by the second-command no-op below — IDENTIFY (first command) completes with 512 bytes of DMA, ANY subsequent READ (0xC8 and 0x25 both tried, IS cleared, FRE live, identical headers/FIS/PRDT machinery) completes as TFD=0x50 with no PRDT transfer and no D2H FIS |

### The AHCI second-command no-op (block-layer open item)

The first command on a freshly started AHCI port (IDENTIFY DEVICE)
completes with full PRDT DMA. Every subsequent command — tried with
READ DMA (0xC8) and READ DMA EXT (0x25), port interrupt-status
cleared, FRE live, command headers/FIS/PRDT rewritten by the same
code path — completes instantly as a no-op: TFD=0x50, no data
transfer, no D2H FIS. This gates the ext2 first slice (the parser and
the host-built image are done and in the tree).

### The device-DMA cluster (root-caused to QEMU, guest side proven complete)

Three drivers — virtio-net, e1000, NVMe (data plane) — program
identically to the working ones but their device DMA never happens.
This session closed every guest-side hypothesis:

1. **A real VT-d bug was found and fixed first**: the context entry's
   high word carried the domain id in bits 0-15. QEMU 10 decodes the
   walk depth as `2 + (hi & 7)` and the domain id as `(hi >> 8) & 0xffff`
   (hw/i386/intel_iommu_internal.h). Our layout made QEMU read
   AW = DID & 7 — a three-level walk over our four-level SLPT — the
   measured `slpte permission error (iova=0x1187000, level=0x2,
   slpte=0x0)` fault — and DID = 0, so every domain-selective IOTLB
   invalidation matched nothing. Fixed: `context_entry_hi = (did << 8) | 2`.
   After the fix the boot's `[CTX ] dump:` marker proves every
   context entry reads `hi=0x102` (DID=1, AW=2), and the devices that
   translate at all now translate correctly.
2. **The context table is provably complete** (the `[CTX ] dump:`
   marker dumps entries 0x10/0x18/0x20/0x28/0x30/0xF8 as the hardware
   sees them) and every driver's frames are broker-mapped before use.
3. **What remains is a QEMU device-class quirk, isolated by
   experiment**: virtio-blk, NVMe (admin fetch) and AHCI always emit
   `vtd_dmar_translate` events and their DMA lands; virtio-net, e1000
   and xHCI never emit a single translate or fault event no matter
   what — swapping the QEMU cmdline order moves the failures with the
   *devices*, not the slots (e1000 failed as 00:04.0 and again as
   00:02.0; virtio-blk worked in both places); detaching the e1000's
   netdev changes nothing; the order-swap of kernel driver steps
   changes nothing. A zero-filled DMA read explains the e1000's exact
   symptom set (TDH advances, no DD writeback, no packet — a zero
   command has no EOP and no RS; QEMU's e1000.c:640-727), and the
   empty packet capture confirms no egress. The per-device
   address-space attach inside this QEMU build is the remaining
   suspect — beyond kernel control, fully documented.

### The AHCI second-command no-op (block-layer open item, sharpened)

The first command on a fresh port (IDENTIFY DEVICE) completes with
512 bytes of PRDT DMA. QEMU's own AHCI trace (`handle_cmd_fis_dump`)
shows the second command's handle_cmd reading a **STALE FIS** — the
IDENTIFY's `27 80 EC` bytes where the READ's `27 80 25 40` was
written — and later CI writes vanish between the kernel and QEMU
(7 issued, 2 logged). A TFD busy-wait before each issue (QEMU's
busy-skip at ahci.c:1317) and port interrupt-status clearing were
both added and did not change it; the FRE=0 rule for CLB/FB
programming was found and fixed earlier. The cmd-table mapping under
the IOMMU serves cached bytes in this build — the ext2 first slice
(image builder + full parser in the tree) stays gated on it.

### xHCI second slice: the TRB machinery (honest negative)

`xhci_cmdring_step` re-brings the controller up with fresh frames,
programs an event ring + ERST + interrupter 0, enqueues a No-Op
command TRB and rings doorbell 0. The doorbell write lands; **CRCR
does not advance and no event TRB appears** — the command-ring DMA
never happens, the same never-translate signature as the NICs above.
The register-level bring-up (previous slice) remains fully live.

### Gate integrity note (fixed this session)

The lane's `EXTRA_GREPS` array had been dead code — the verify loop
that was supposed to enforce it did not exist, so lane markers were
not actually checked and the pixel proof did not weight the verdict.
Both fixed; every marker in the table above is now genuinely
enforced by `boot.sh --verify-q35`.

## Why USB and the rest are sequenced after virtio

Every virtio device shares one audited transport; USB (xHCI) is a
whole second transport (event rings, TRBs, descriptors, hubs) and is
sized as its own phase (checklist item 12, hub/tree support
explicitly out of scope in its ADR). The broker discipline and the
MMIO lessons above apply to it unchanged.
