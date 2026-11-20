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

### The device-DMA cluster: SOLVED — the missing PCI bus-master enable

For three sessions the NICs (virtio-net, e1000) and xHCI "never
DMA'd": zero translate events, zero faults, zero-filled descriptor
reads (TDH advances on a zero command — no EOP, no RS writeback, no
packet), while virtio-blk/NVMe/AHCI worked. The working set's secret:
**SeaBIOS had enabled bus mastering on the devices it probes for
boot.** Our kernel never wrote PCI COMMAND at all — the NICs sat with
BM off, and QEMU parks a BM-less device's `bus_master_enable_region`
disabled, so every device DMA dissolves into reads of nothing, never
reaching the IOMMU. That signature masqueraded as a QEMU attach bug
(see the retraction below).

The break came from a **control experiment**: a new identity mode for
the e1000 on the no-IOMMU lane (`q35-neg` + `--verify-q35-noiommu`,
`Vtd::absent()` + `Dmar::absent_stub()` placeholders so the driver
steps run against a refusing broker). Same driver, plain RAM, no
IOMMU — and TX still read zeros. A driver-side bug by elimination.
`pci::enable_bus_master()` (COMMAND |= MEM|BM at config offset 0x04)
now runs in every driver step before any ring is programmed.

Two follow-on bugs the now-working DMA exposed:

- **e1000 RX**: `RCTL` must be `0x8002` — BAM is **bit 15**
  (E1000_RCTL_BAM 0x8000 in e1000x_regs.h), not bit 19; and the RX
  poll must outlast QEMU's `flush_queue_timer`: `set_rx_control`
  arms it for **1000 ms of the virtual clock on every RCTL write**
  (e1000.c:424), so the OFFER (measured arriving 76 µs after the
  DISCOVER) sits queued for a full second before the first RX
  descriptor fetch. Budget 3 G spins.
- **virtio-net header**: 12 bytes, not 10 — QEMU's
  `virtio_net_apply()` sets `guest_hdr_len =
  sizeof(virtio_net_hdr_mrg_rxbuf)` **unconditionally for VERSION_1**
  (hw/net/virtio-net.c:646), mergeable-RX or not. Measured from the
  packet capture: the device skipped 12, the wire frame came out
  shifted by two (dst read ffffffff5254, len 288 = 300−12).

**Result**: both NICs now complete the full DHCP
DISCOVER→slirp→OFFER round trip **through the IOMMU** on the main
lane (`[VNET] RX: 602 bytes — DHCP OFFER yiaddr=10.0.2.15`, same for
`[E1K] RX: 594 bytes`), and the e1000 also does it in identity mode
on the no-IOMMU control lane. The e1000's TX DD poll reads desc+12
bit 0 (E1000_TXD_STAT_DD=0x1; a +14 detour was wrong and is
reverted — the writeback pci_dma_write()s the dword at +12).

### xHCI TRB: the No-Op command completes end-to-end

`xhci_cmdring_step` re-brings the controller up, programs an event
ring + ERST + interrupter 0, enqueues a No-Op command TRB and rings
doorbell 0. After fixing the ERSTSZ offset (**interrupter +0x08** —
IMAN+0, IMOD+4, ERSTSZ+8, ERSTBA+0x10, ERDP+0x18; +0x28 was
interrupter 1's) the event ring receives **type 33 — command
completion**: ring DMA, doorbell and event post all live. CRCR's
dequeue pointer is NOT a success metric (the controller never writes
it back); the marker now reports the event TRB type.

### Still open (with the evidence trail)

- **NVMe — one precisely-bounded anomaly: the device reads prp1 as 0**.

  The 2026-11-20 session took the NVMe from "no completion" to a
  nearly-complete admin flow. Four driver bugs fixed, each verified
  against QEMU source:

  1. **No reset cycle** — SeaBIOS drives the NVMe boot disk before us
     and leaves the controller ENABLED with its own queue state. Our
     old CC=1 write had no disable phase (queue registers are
     writable only at CC.EN=0, NVMe 1.4 §3.1.5) and no entry-size
     bits. Now: CC=0 → CSTS.RDY=0 → AQA/ASQ/ACQ → CC=0x0064_0001
     (EN | IOSQES=6 | IOCQES=4 — note 0x46_0001 has the nibbles
     swapped and behaves differently downstream).
  2. **cdw11 bit layouts** for Create I/O CQ/SQ — IV lives at bits
     16+ (our 1<<17 was read as IV=2 → err_invalid_create_cq_vector),
     PC is bit 0, CQID (SQ) bits 16+. Corrected: cdw11 = 1 (CQ) and
     1 | (1<<16) (SQ).
  3. **The CQE phase bit is bit 16** (byte 14, the P/SF u16 — QEMU
     nvme.c:1517 `cqe.status = (status << 1) | phase`), NOT bit 0 of
     the dword at +12: that byte is SQHD, whose LSB matched our
     phase==1 check **by accident** on slot 0. Fixed poll.
  4. **The nvme-ns device** — the lane's `-device nvme,drive=` is the
     pre-QEMU-8 form: the controller comes up with **zero
     namespaces** (NN=0 in the identify). Now `-device nvme-ns`.

  What works now: full reset cycle, Identify executes (cdw0/nsid/
  cdw10 all arrive), CreateIoCq/CreateIoSq execute, the CQE poll
  machinery is correct, and refusal paths tear down (revoke + scrub
  + free, the lane greps are count-agnostic).

  The remaining anomaly, with the evidence: **every executed command
  reads prp1 (SQ entry bytes 16-23) as 0** — the Identify's 4 KiB
  data write lands at **PA 0** (proven: the serial bytes "AEGI…"
  from serial=AEGISN1 read back at PA 0), and the CreateIoCq now
  refuses with SC=2 (invalid field — a CQ at address 0). Meanwhile
  bytes 0-7 and 40-43 of the SAME entry arrive correctly, our
  kernel's same-PA readback shows the written prp1, the vtd trace
  shows the SQ fetch translating iova 0x1189000 → gpa 0x1189000
  (identity), and the split-32-bit-store experiment made no
  difference. Eliminated: entry layout/size (NVME_SQES=6), doorbell
  offsets, register values (ASQ/AQA read back correct), u64 stores,
  the phase poll. Next experiment: the no-IOMMU control (an NVMe on
  the q35-neg lane pattern) to isolate the vtd pass-through fast
  path (`vtd_pt_enable_fast_path` fires at our doorbell).
- **AHCI second command** (gates the ext2 first slice): the first
  command on a fresh port (IDENTIFY) completes with 512 bytes of
  PRDT DMA; the second command reads a **STALE FIS** — the
  IDENTIFY's `27 80 EC` bytes where the READ's `27 80 25 40` was
  written — and later CI writes vanish between the kernel and QEMU
  (7 issued, 2 logged). A TFD busy-wait before each issue and port
  IS clearing were added and did not change it. **Retested after the
  bus-master/context-entry fixes: the signature is unchanged.** The
  NVMe prp1 anomaly (same session) shows devices can read SOME
  fields of a guest-written structure and not others — the AHCI
  stale-FIS has the same shape and should be re-examined with the
  same trace-driven method.

### Retraction

The previous conclusion — "a QEMU device-class quirk that keeps NIC
DMA from the IOMMU, proven by slot/order/netdev experiments" — is
**retracted**. Those experiments were sound but the premise was
wrong: the failures followed the devices because SeaBIOS's BM
footprint followed the devices. The control lane falsified it in one
boot. Kept here deliberately: the discipline of this checklist is
that retracted conclusions stay visible.

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
