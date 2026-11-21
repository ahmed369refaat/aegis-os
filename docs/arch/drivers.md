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
   context entry is written (P | TT=0b00 multi-level | SLPTPTR) and
   the device is bound to its domain (ADR-0014: TT=0b10 was
   pass-through — the tables were never walked).
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
  single-bit TE write silently disabled the invalidation queue. The
  context entry's TT bits 3:2 = 0b00 select the multi-level walk
  (ADR-0014: the old "depth = 2 + TT" note was wrong — the depth is
  2 + AW from the HIGH word, and TT=0b10 was pass-through, measured
  as vtd_pt_enable_fast_path for six devices plus an enforcement
  probe that completed against an unmapped page with PPF=no).

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

## Status and open items (honest ledger, updated 2026-11-21 — ADR-0014)

| Driver | Status | Proof |
| --- | --- | --- |
| virtio-blk | **complete, enforced** | sector read status=OK; write+read-back round trip; **enforcement probe PPF=yes, SLPTE absent after unmap (ADR-0014)**; teardown revoke+scrub |
| AHCI/SATA (ich9, q35) | **LIVE incl. ext2 mount** | ABAR/GHC/PI read, port-0 SIG=0x101, IDENTIFY with the REAL serial (QM000001), **the ext2 mount runs: superblock → root dir → hello.txt read through the IOMMU (ADR-0014)** |
| virtio-net | **complete** | handshake, MAC/link, both queues, 8 broker frames, **full DHCP DISCOVER→slirp→OFFER round trip through the IOMMU (ADR-0014)**, teardown |
| e1000 | **complete** | rings programmed, **full DHCP round trip through the IOMMU** AND in identity mode on the control lane, teardown |
| IOMMU isolation | **per-device (ADR-0018), proven live** | the e1000's cross-device DMA to a vnet-only page faults on the lane |
| NVMe | **fully live (F11): identify + I/O qpair + LBA read through the IOMMU** | CAP/version/RDY, identify data lands, CreateIoCq/SQ pass, read LBA0 completes |
| USB xHCI | **bring-up FULLY LIVE** (item 12 first slice) | caps (v0 read as 0? HCSPARAMS MaxSlots=64 MaxPorts=8), halt→reset→DCBAAP+MaxSlotsEn+CRCR→RUN (HCH cleared), **port 0 device attached speed=4 (the usb-storage)** — register-only path, no device DMA needed |
| screen/GPU (VBE) | **pixel-proven** | 7/7 sampled pixels in the QMP screendump |
| PS/2 keyboard | **round-trip + negotiated** | QMP send-key → scancode 0x1e; THEN the real 0xF0/0x02 scancode-set-2 exchange, ACK 0xfa (translation restored for delivery — measured on this build) |
| RTC | **live** | MC146818, BCD, host time |
| HPET | **live** (item 15 first slice) | table→block @0xFED00000, 100 MHz period, main counter enabled, delta>0 — the calibration source |
| ACPI MADT/MCFG (item 14) | **parsed** | 1 LAPIC + 1 IOAPIC @0xFEC00000; ECAM base 0xB0000000 bus 0..255 |
| USB enumeration / HID | **not started** | next xHCI slice: TRB rings, address device, interrupt-IN |
| virtio-gpu / e1000-data / NVMe-data | **blocked on the device-DMA cluster** (below) | |
| Block layer + ext2 (item 8) | **mounted, file read live** | the image builder (scripts/mkext2.py) + the full kernel parser run on the LIVE AHCI port: superblock ok (magic 0xef53, inode_size=128) → root inode → hello.txt read ("HELLO-AEGIS-EXT2.") — on BOTH the IOMMU lane and the no-IOMMU control lane (the historical "second-command no-op" was three driver bugs; see ADR-0014 below) |

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

### ADR-0014 (2026-11-21): the IOMMU was in pass-through — and the tables are load-bearing now

Review round 4 found that `context_entry` set TT=0b10 — **pass-through**
per the VT-d spec §9.3 and QEMU's `VTD_CONTEXT_TT_PASS_THROUGH` — so no
device ever walked the second-level tables (trace:
`vtd_pt_enable_fast_path` ×8 for six devices; the enforcement probe's
request to an unmapped page completed with status OK and PPF=no). Full
verification trail in ADR-0014. Fixing TT surfaced a SECOND latent bug:
`slpte_table` wrote non-leaf entries without the W bit, and VT-d checks
R/W at EVERY level of the walk — so the first live device write faulted
FR_WRITE at level 4 (reads passed, and writes only succeeded when
served from QEMU's IOTLB page cache, which checks the leaf alone).

Re-measured, before → after (all on the q35 lane unless noted):

- **virtio-blk enforcement probe**: request to the unmapped page
  completed, PPF=no → **request completes with device-side error,
  PPF=yes, SLPTE read-back P=0**. The lane now FAILS if
  `vtd_pt_enable_fast_path` appears in a `-trace enable=vtd_*` run, or
  the probe does not print `PPF=yes`.
- **virtio-net TX "stall" (open item)**: DISCOVER published, "QEMU did
  not consume it" → **full DHCP round trip through the IOMMU**. The
  stall was the non-leaf W bit: the device's read of the avail ring
  succeeded while its fetches faulted quietly.
- **e1000 "no egress"**: descriptor consumed, no packet → **full DHCP
  round trip through the IOMMU** (same root cause).
- **AHCI second command / ext2 mount (open item)**: reproduced on the
  no-IOMMU control lane — refuting the vIOMMU bounce-buffer hypothesis
  — and was **three driver bugs**, found by trace + command-table
  read-back: (1) the PRDT byte count written into the entry's reserved
  dword instead of `flags_size` at +0x0C (every sglist was "1 byte";
  QEMU `prdt_tbl_entry_size` = `(flags_size & MASK)+1`); (2) the
  READ-DMA-EXT FIS LBA fields at bytes 9-11 instead of 4-10 (LBA 2 was
  read as LBA 2<<24 — off the image); (3) the sector-count byte 12
  never written (0 = 65536 sectors → the measured 32 MiB prepare_buf
  limit). After the fixes the mount runs end-to-end on BOTH lanes.
- **NVMe prp1=0**: **unchanged** by the TT fix — the signature
  (identify data landing at PA 0, CreateIoCq SC=2) is identical under
  real translation, and the old "isolate the pass-through fast path"
  next-experiment is obsolete (there is no fast path anymore). Still
  open; the no-IOMMU control remains the next experiment.

### ADR-0015 (2026-11-21): IOMMU integrity — atomic map_run, poisoned-region quarantine, domain-scoped cookies

Review round 4 Phase 2 (F1–F3), all host-tested plus live on the
lanes: `map_run` refuses atomically (pure `tables_needed` precompute +
rollback + always-committed cursor — no residual SLPTEs, no table
frame under two parents, pinned by a 300-step xorshift property test
and the shared `dma::contract` harness run against the fake AND the
real Vtd); `revoke_all` returns `{revoked, poisoned}` with poisoned
regions never freed (FramePool `QUARANTINE_OWNER`, BME off via the
new 16-bit `pci::disable_bus_master`, `retry_poisoned()` the only
release — one `revoke_or_quarantine` helper now serves all 19 teardown
and refusal sites, which also fixed the VBLK teardown frame leak and
its untruthful marker); cookies are domain-scoped with foreign cookies
indistinguishable from unknown ones. The happy-path lane markers are
byte-identical; poison lines appear only when they occur.

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

- **NVMe prp1=0 — SOLVED (F11)**: two compounding layout quirks,
  both measured, plus a lane device property.

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

  The anomaly is closed — it was TWO layout quirks of this QEMU's
  nvme, plus one lane device property, compounding so each fix looked
  wrong while the other cause masked it:

  5. **The command's data pointer is read from SQE bytes 24-31**
     (the spec's PRP2 slot), not 16-23 (PRP1). Measured by planting
     a distinct page in every PRP-candidate slot: the identify DMA
     faulted at exactly the +24 plant's address (1024 IOMMU write
     faults on its page) and ignored the +16 plant; the historical
     "data lands at PA 0" was this bug writing the page at pointer 0
     back when pass-through let it through (ADR-0014's era). The
     driver now writes the pointer at BOTH slots — spec hardware
     ignores PRP2 for single-page aligned buffers, so both worlds
     work.
  6. **The CC entry-size fields sit at bits 19:16 (IOSQES) and
     23:20 (IOCQES)** in this QEMU, not the spec's 23:20/27:24.
     Measured by QEMU's own trace — after a spec-layout
     0x0064_0001 write, `pci_nvme_err_invalid_create_cq_entry_size
     iosqes 4 iocqes 6`. The 2026-11-20 session had the RIGHT value
     (0x0046_0001), "fixed" it into the spec layout chasing the
     prp1 symptom, and unknowingly traded one SC=2 cause for
     another. CC is now 0x0046_0001 again.
  7. **The lane's nvme device needs `num_queues=N`** (default 0 —
     no I/O queue pairs at all; `max_ioqpairs=64` is only a cap).
     The boot lane now passes `num_queues=2`.

  After all three: the Identify data page arrives (serial
  "AEGISN1", VID 0x1b36), CreateIoCq + CreateIoSq pass, and a
  512-byte LBA-0 read completes through the IOMMU — the lane greps
  pin all of it. The no-IOMMU control experiment the old note
  planned is unnecessary: the mechanism is fully identified.
- **AHCI second command — SOLVED (ADR-0014)**. The historical reading
  ("stale FIS", "CI writes vanish") was wrong: the command table
  read-back showed the driver's bytes present in RAM all along, and
  the QEMU trace showed the device executing our READ-DMA-EXT with a
  65536-sector count and a 1-byte PRDT. Three driver bugs (PRDT DBC
  offset, FIS LBA offsets, missing sector count) — the vIOMMU
  bounce-buffer hypothesis is refuted (the signature reproduced on
  the no-IOMMU control lane before the fix, and both lanes mount
  after it). Kept here as the visible retraction of the old
  conclusion.

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
