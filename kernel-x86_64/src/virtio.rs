//! virtio-blk driver over the DMA broker (driver stack Phase 2,
//! checklist item 5) — the first REAL device DMA in the system, and
//! ADR-0013's payoff: every device-visible buffer (the three
//! virtqueue rings, the request header, the data page) is a pool
//! frame mapped through the broker **before** the device can touch
//! it, and the enforcement probe at the end proves the IOMMU faults
//! an access to a page the broker has unmapped.
//!
//! ## Layout discipline (modern virtio 1.x only)
//!
//! QEMU's `virtio-blk-pci,disable-legacy=on,iommu_platform=on` (the
//! verified incantation on the q35 lane) exposes a vendor-capability
//! chain (id 0x09) naming four MMIO register blocks inside one BAR:
//! common config, notify, ISR, device config. The lane runs
//! `intremap=off` and we configure no MSI — every wait is a bounded
//! poll (ADR-0013's no-infinite-spin rule).
//!
//! ## Testability
//!
//! The capability parser is generic over a config-dword reader (the
//! kernel passes PCI-port-backed reads, host tests a fake config
//! image). The u16 read-modify-write helpers, descriptor/ring
//! encodings and the notify-address math are pure and host-tested.
//! Only the MMIO register access itself is target-only — through
//! `memops` at the BAR's physical address (the 4th-GiB window the
//! VT-d step already maps), zero unsafe of its own.

use crate::memops;

// ── virtio status bits (virtio 1.x §2.1) ──
pub const STATUS_ACK: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

// ── virtio feature bits ──
/// Low feature word (select 0).
pub const F_RING_INDIRECT: u32 = 1 << 28;
pub const F_RING_EVENT_IDX: u32 = 1 << 29;
/// High feature word (select 1), bit 0 = VIRTIO_F_VERSION_1.
pub const F1_VERSION_1: u32 = 1;
/// VIRTIO_F_ACCESS_PLATFORM (bit 33): DMA goes through a platform
/// IOMMU — the entire point of this driver stack. QEMU's
/// iommu_platform devices REQUIRE the driver to accept it.
pub const F1_ACCESS_PLATFORM: u32 = 1 << 1;

/// The feature set we negotiate: modern-only, platform-DMA (the
/// broker's IOMMU translations), no indirect descriptors, no event
/// indices — the simplest ring the spec allows.
pub const DRIVER_FEATURES_LOW: u32 = 0;
pub const DRIVER_FEATURES_HIGH: u32 = F1_VERSION_1 | F1_ACCESS_PLATFORM;

// ── common-config register offsets (virtio 1.x §4.1.4.3) ──
pub const CC_DEVICE_FEATURE_SEL: u64 = 0x00;
pub const CC_DEVICE_FEATURE: u64 = 0x04;
pub const CC_DRIVER_FEATURE_SEL: u64 = 0x08;
pub const CC_DRIVER_FEATURE: u64 = 0x0C;
pub const CC_NUM_QUEUES: u64 = 0x12;
pub const CC_STATUS: u64 = 0x14;
pub const CC_QUEUE_SEL: u64 = 0x16;
pub const CC_QUEUE_SIZE: u64 = 0x18;
pub const CC_QUEUE_ENABLE: u64 = 0x1C;
pub const CC_QUEUE_NOTIFY_OFF: u64 = 0x1E;
pub const CC_QUEUE_DESC: u64 = 0x20;
pub const CC_QUEUE_AVAIL: u64 = 0x28;
pub const CC_QUEUE_USED: u64 = 0x30;

/// Descriptor flags: NEXT chains, WRITE means device-writable.
pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2;

/// virtio-blk request types and statuses.
pub const BLK_T_IN: u32 = 0;
pub const BLK_T_OUT: u32 = 1;
pub const BLK_S_OK: u8 = 0;
pub const BLK_S_IOERR: u8 = 1;
pub const BLK_S_UNSUPP: u8 = 2;

// ── the vendor-capability parser (pure, over injected reads) ──

/// One virtio PCI capability region: BAR number + offset + length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapRegion {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

/// The four regions a modern virtio device names, plus the notify
/// multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioCaps {
    pub common: CapRegion,
    pub notify: CapRegion,
    pub notify_multiplier: u32,
    pub isr: CapRegion,
    pub device: CapRegion,
}

/// Parse the virtio vendor-capability chain. `read_cfg(off)` returns
/// the config dword at `off` (dword-aligned, first 256 bytes). The
/// cap header layout: vndr(0) next(1) len(2) cfg_type(3) bar(4)
/// pad(5..8) offset(8) length(12) [notify: multiplier(16)].
pub fn parse_virtio_caps(read_cfg: &mut dyn FnMut(u8) -> u32) -> Option<VirtioCaps> {
    let first = ((read_cfg(0x34)) & 0xFF) as u8 & 0xFC;
    if !(0x40..=0xFC).contains(&first) {
        return None;
    }
    let mut common = None;
    let mut notify = None;
    let mut multiplier = 0u32;
    let mut isr = None;
    let mut device = None;
    // Lists interleave other caps (QEMU: msix first, then the virtio
    // caps, measured) — skip non-virtio entries, protect with a
    // visited set.
    let mut seen: [u8; 16] = [0; 16];
    let mut seen_count = 0usize;
    let mut ptr = first;
    let mut guard = 0u8;
    while ptr != 0 && guard < 24 {
        if seen[..seen_count].contains(&ptr) {
            break;
        }
        if seen_count < seen.len() {
            seen[seen_count] = ptr;
            seen_count += 1;
        }
        let w0 = read_cfg(ptr);
        if (w0 & 0xFF) as u8 != 0x09 {
            ptr = ((w0 >> 8) & 0xFF) as u8 & 0xFC;
            guard += 1;
            continue; // someone else's cap: keep walking (seen-set guards)
        }
        let next = ((w0 >> 8) & 0xFF) as u8 & 0xFC;
        let len = ((w0 >> 16) & 0xFF) as u8;
        let cfg_type = (w0 >> 24) as u8;
        let w1 = read_cfg(ptr + 4);
        let bar = (w1 & 0xFF) as u8;
        let offset = read_cfg(ptr + 8);
        let length = read_cfg(ptr + 12);
        let region = CapRegion {
            bar,
            offset,
            length,
        };
        match cfg_type {
            1 => common = Some(region),
            2 => {
                notify = Some(region);
                if len >= 20 {
                    multiplier = read_cfg(ptr + 16);
                }
            }
            3 => isr = Some(region),
            4 => device = Some(region),
            _ => {}
        }
        ptr = next;
        guard += 1;
    }
    Some(VirtioCaps {
        common: common?,
        notify: notify?,
        notify_multiplier: multiplier,
        isr: isr?,
        device: device?,
    })
}

// ── u16 access at (2-aligned) addresses, over aligned u32 RMW ──
//
// memops owns exactly u32/u64 volatile primitives; virtio rings are
// full of u16 fields. These helpers are pure arithmetic over memops —
// no new unsafe, host-tested over plain buffers.

/// Read the u16 at `pa` (must be 2-aligned).
#[must_use]
pub fn read_u16_pa(pa: u64) -> u16 {
    debug_assert!(pa % 2 == 0);
    let w = memops::read_u32(pa & !3);
    ((w >> (8 * (pa & 2))) & 0xFFFF) as u16
}

/// Write the u16 at `pa` (must be 2-aligned) via u32 read-modify-write.
pub fn write_u16_pa(pa: u64, v: u16) {
    debug_assert!(pa % 2 == 0);
    let base = pa & !3;
    let shift = 8 * (pa & 2);
    let w = memops::read_u32(base);
    let cleared = w & !(0xFFFF << shift);
    memops::write_u32(base, cleared | ((v as u32) << shift));
}

/// Read the u8 at `pa` via its containing u32 word.
#[must_use]
pub fn read_u8_pa(pa: u64) -> u8 {
    let w = memops::read_u32(pa & !3);
    ((w >> (8 * (pa & 3))) & 0xFF) as u8
}

/// Write one descriptor table entry (16 bytes at `desc_pa`).
pub fn write_desc(desc_pa: u64, addr: u64, len: u32, flags: u16, next: u16) {
    memops::write_u64(desc_pa, addr);
    memops::write_u64(
        desc_pa + 8,
        u64::from(len) | (u64::from(flags) << 32) | (u64::from(next) << 48),
    );
}

/// The avail-ring slot address for ring index `i` (qsize entries).
#[must_use]
pub fn avail_slot_addr(avail_pa: u64, i: u16) -> u64 {
    avail_pa + 4 + 2 * u64::from(i)
}

/// The used-ring head index (`used.idx`, the u16 at used+2).
#[must_use]
pub fn used_idx(used_pa: u64) -> u16 {
    read_u16_pa(used_pa + 2)
}

/// The completion id from used-ring slot `i` (u32 at used+4+8i).
#[must_use]
pub fn used_entry_id(used_pa: u64, i: u16) -> u32 {
    let pa = used_pa + 4 + 8 * u64::from(i);
    memops::read_u32(pa)
}

/// The virtio-blk request header (16 bytes): type, reserved, sector.
pub fn write_blk_header(hdr_pa: u64, req_type: u32, sector: u64) {
    memops::write_u64(hdr_pa, u64::from(req_type));
    memops::write_u64(hdr_pa + 8, sector);
}

/// The notify address for a queue: the notify region base plus
/// `notify_off` scaled by the multiplier (the modern layout — the
/// address selects the queue).
#[must_use]
pub fn notify_addr(notify_base: u64, notify_off: u16, multiplier: u32) -> u64 {
    notify_base + u64::from(notify_off) * u64::from(multiplier)
}

/// The expected status word after a successful modern handshake.
#[must_use]
pub const fn live_status() -> u8 {
    STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK
}

// ── the live device (target-only: MMIO through the BAR) ──

/// A claimed virtio-blk, its register blocks resolved to physical
/// addresses inside the (already window-mapped) 4th GiB.
#[cfg(not(test))]
pub struct MmioVirtio {
    common_pa: u64,
    notify_base_pa: u64,
    multiplier: u32,
    device_cfg_pa: u64,
}

#[cfg(not(test))]
impl MmioVirtio {
    /// Resolve the capability regions against the device's BARs.
    #[must_use]
    pub fn from_caps(caps: &VirtioCaps, dev: &crate::pci::PciDev) -> Option<Self> {
        let common_base = crate::pci::mem_bar_base(dev, caps.common.bar)?;
        let notify_base = crate::pci::mem_bar_base(dev, caps.notify.bar)?;
        let device_base = crate::pci::mem_bar_base(dev, caps.device.bar)?;
        Some(MmioVirtio {
            common_pa: common_base + u64::from(caps.common.offset),
            notify_base_pa: notify_base + u64::from(caps.notify.offset),
            multiplier: caps.notify_multiplier,
            device_cfg_pa: device_base + u64::from(caps.device.offset),
        })
    }

    fn r32(&self, off: u64) -> u32 {
        memops::read_u32(self.common_pa + off)
    }

    fn w32(&self, off: u64, v: u32) {
        memops::write_u32(self.common_pa + off, v);
    }

    fn r16(&self, off: u64) -> u16 {
        read_u16_pa(self.common_pa + off)
    }

    fn w16(&self, off: u64, v: u16) {
        write_u16_pa(self.common_pa + off, v);
    }

    /// Read a device feature word (`select` 0 = bits 0..31, 1 = 32..).
    pub fn device_features(&self, select: u32) -> u32 {
        self.w32(CC_DEVICE_FEATURE_SEL, select);
        self.r32(CC_DEVICE_FEATURE)
    }

    /// Write a driver feature word.
    pub fn set_driver_features(&self, select: u32, v: u32) {
        self.w32(CC_DRIVER_FEATURE_SEL, select);
        self.w32(CC_DRIVER_FEATURE, v);
    }

    pub fn status(&self) -> u8 {
        (self.r32(CC_STATUS) & 0xFF) as u8
    }

    pub fn set_status(&self, v: u8) {
        self.w32(CC_STATUS, u32::from(v));
    }

    pub fn num_queues(&self) -> u16 {
        self.r16(CC_NUM_QUEUES)
    }

    /// Select a queue and return (size, notify_off).
    pub fn select_queue(&self, idx: u16) -> (u16, u16) {
        self.w16(CC_QUEUE_SEL, idx);
        (self.r16(CC_QUEUE_SIZE), self.r16(CC_QUEUE_NOTIFY_OFF))
    }

    /// Shrink the queue (queue_size is driver-writable in modern
    /// virtio): the boot proof's ring frames are one page each, which
    /// serves 256 descriptors — QEMU defaults to 1024.
    pub fn set_queue_size(&self, size: u16) -> u16 {
        self.w16(CC_QUEUE_SIZE, size);
        self.r16(CC_QUEUE_SIZE)
    }

    /// Hand the queue's ring addresses to the device and enable it.
    pub fn setup_queue(&self, desc_pa: u64, avail_pa: u64, used_pa: u64) {
        memops::write_u64(self.common_pa + CC_QUEUE_DESC, desc_pa);
        memops::write_u64(self.common_pa + CC_QUEUE_AVAIL, avail_pa);
        memops::write_u64(self.common_pa + CC_QUEUE_USED, used_pa);
        self.w16(CC_QUEUE_ENABLE, 1);
    }

    /// Kick a queue (the address carries the queue; the value is the
    /// queue index).
    pub fn notify(&self, queue_notify_off: u16) {
        let pa = notify_addr(self.notify_base_pa, queue_notify_off, self.multiplier);
        memops::write_u32(pa, 0);
    }

    /// The disk capacity in 512-byte sectors (device config +0).
    pub fn capacity_sectors(&self) -> u64 {
        memops::read_u64(self.device_cfg_pa)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake config space: dwords in a plain buffer, a virtio cap
    /// chain planted at 0x40.
    struct FakeCfg {
        d: Vec<u32>,
    }

    impl FakeCfg {
        fn new() -> Self {
            FakeCfg { d: vec![0; 64] }
        }
        fn read(&self, off: u8) -> u32 {
            self.d[(off / 4) as usize]
        }
        /// Plant one virtio cap; returns its offset.
        fn cap(
            &mut self,
            off: u8,
            next: u8,
            cfg_type: u8,
            bar: u8,
            region_off: u32,
            len: u32,
            multiplier: Option<u32>,
        ) {
            let i = (off / 4) as usize;
            // w0: vndr=9, next, len, cfg_type
            let cap_len: u32 = if multiplier.is_some() { 20 } else { 16 };
            self.d[i] = 0x09
                | (u32::from(next) << 8)
                | (u32::from(cap_len) << 16)
                | (u32::from(cfg_type) << 24);
            // w1: bar (+padding)
            self.d[i + 1] = u32::from(bar);
            // offset, length
            self.d[i + 2] = region_off;
            self.d[i + 3] = len;
            if let Some(m) = multiplier {
                self.d[i + 4] = m;
            }
        }
    }

    #[test]
    fn caps_parse_the_modern_chain() {
        let mut c = FakeCfg::new();
        c.d[13] = 0x40; // cap list head at 0x34
                        // Spaced 0x20 apart: the notify cap is 20 bytes wide.
        c.cap(0x40, 0x60, 1, 4, 0x0000, 0x38, None); // common
        c.cap(0x60, 0x80, 2, 4, 0x0040, 0x1000, Some(4)); // notify, mult 4
        c.cap(0x80, 0x90, 3, 4, 0x2040, 0x10, None); // isr
        c.cap(0x90, 0x00, 4, 4, 0x2050, 0x20, None); // device
        let caps = parse_virtio_caps(&mut |off| c.read(off)).expect("full chain parses");
        assert_eq!(
            caps.common,
            CapRegion {
                bar: 4,
                offset: 0,
                length: 0x38
            }
        );
        assert_eq!(
            caps.notify,
            CapRegion {
                bar: 4,
                offset: 0x40,
                length: 0x1000
            }
        );
        assert_eq!(caps.notify_multiplier, 4);
        assert_eq!(
            caps.isr,
            CapRegion {
                bar: 4,
                offset: 0x2040,
                length: 0x10
            }
        );
        assert_eq!(
            caps.device,
            CapRegion {
                bar: 4,
                offset: 0x2050,
                length: 0x20
            }
        );
    }

    #[test]
    fn caps_refuse_incomplete_or_absent_chains() {
        // No cap pointer.
        let c = FakeCfg::new();
        assert!(parse_virtio_caps(&mut |off| c.read(off)).is_none());
        // A chain missing regions: refused (all four are required).
        let mut c = FakeCfg::new();
        c.d[13] = 0x40;
        c.cap(0x40, 0x00, 2, 4, 0x0040, 0x1000, Some(4)); // only notify
        assert!(parse_virtio_caps(&mut |off| c.read(off)).is_none());
        // A looping chain (next <= ptr) TERMINATES without hanging —
        // and still refuses, because one common cap is not a device.
        let mut c = FakeCfg::new();
        c.d[13] = 0x40;
        c.cap(0x40, 0x40, 1, 4, 0, 0x38, None); // points at itself
        assert!(parse_virtio_caps(&mut |off| c.read(off)).is_none());
    }

    #[test]
    fn u16_helpers_cover_both_word_lanes() {
        let buf = vec![0u64; 8];
        let pa = buf.as_ptr() as u64;
        // Lane 0 (offset 0) and lane 1 (offset 2).
        write_u16_pa(pa, 0xBEEF);
        write_u16_pa(pa + 2, 0xCAFE);
        assert_eq!(read_u16_pa(pa), 0xBEEF);
        assert_eq!(read_u16_pa(pa + 2), 0xCAFE);
        // The RMW preserved the neighbor on each write.
        assert_eq!(memops::read_u32(pa), 0xCAFE_BEEF);
        write_u16_pa(pa + 2, 0x1234);
        assert_eq!(memops::read_u32(pa), 0x1234_BEEF);
        // Byte reads pick every lane.
        memops::write_u32(pa, 0x11_22_33_44);
        assert_eq!(read_u8_pa(pa), 0x44);
        assert_eq!(read_u8_pa(pa + 1), 0x33);
        assert_eq!(read_u8_pa(pa + 2), 0x22);
        assert_eq!(read_u8_pa(pa + 3), 0x11);
    }

    #[test]
    fn descriptor_encoding_is_pinned() {
        let buf = vec![0u64; 8];
        let pa = buf.as_ptr() as u64;
        write_desc(pa, 0x1234_5000, 512, DESC_F_NEXT | DESC_F_WRITE, 2);
        assert_eq!(memops::read_u64(pa), 0x1234_5000);
        let w1 = memops::read_u64(pa + 8);
        assert_eq!(w1 & 0xFFFF_FFFF, 512, "len in the low dword");
        assert_eq!((w1 >> 32) & 0xFFFF, 3, "flags NEXT|WRITE");
        assert_eq!((w1 >> 48) & 0xFFFF, 2, "next");
    }

    #[test]
    fn ring_math_is_pinned() {
        // avail slots walk 2-byte entries from avail+4.
        assert_eq!(avail_slot_addr(0x1000, 0), 0x1004);
        assert_eq!(avail_slot_addr(0x1000, 255), 0x1004 + 510);
        // used.idx lives at +2; entry ids at +4+8i.
        let buf = vec![0u64; 512];
        let used = buf.as_ptr() as u64;
        write_u16_pa(used + 2, 7);
        assert_eq!(used_idx(used), 7);
        memops::write_u32(used + 4 + 8 * 5, 3);
        assert_eq!(used_entry_id(used, 5), 3);
    }

    #[test]
    fn notify_address_scales_by_the_multiplier() {
        assert_eq!(notify_addr(0xFE00_0040, 0, 4), 0xFE00_0040);
        assert_eq!(notify_addr(0xFE00_0040, 1, 4), 0xFE00_0044);
        assert_eq!(notify_addr(0xFE00_0040, 2, 4), 0xFE00_0048);
    }

    #[test]
    fn blk_header_and_status_constants() {
        let buf = vec![0u64; 8];
        let pa = buf.as_ptr() as u64;
        write_blk_header(pa, BLK_T_IN, 42);
        assert_eq!(memops::read_u64(pa), 0); // type + reserved
        assert_eq!(memops::read_u64(pa + 8), 42); // sector
        write_blk_header(pa, BLK_T_OUT, 7);
        assert_eq!(memops::read_u64(pa) & 0xFFFF_FFFF, 1);
        assert_eq!(live_status(), 0x0F);
        assert_eq!(STATUS_FAILED, 128);
    }

    #[test]
    fn our_feature_set_is_the_simplest_ring() {
        assert_eq!(DRIVER_FEATURES_LOW, 0, "no indirect, no event idx");
        assert_eq!(
            DRIVER_FEATURES_HIGH, 3,
            "modern + platform DMA (the broker)"
        );
    }
}
