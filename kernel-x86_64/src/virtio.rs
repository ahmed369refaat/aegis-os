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
/// config_msix_vector: the config-change interrupt's MSI-X table
/// entry (write = request, read = the device's granted vector).
pub const CC_CONFIG_MSIX: u64 = 0x10;
/// queue_msix_vector: the SELECTED queue's interrupt entry (same
/// write-then-read grant semantics).
pub const CC_QUEUE_MSIX: u64 = 0x1A;
/// The virtio "no vector" value: a refused binding (or an unbound
/// queue) reads back as this — the device sends NO message for it.
pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xFFFF;

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
///
/// F4 (review round 4): the config space is HOSTILE INPUT. The old
/// code computed `ptr + 4/8/12/16` on a `u8` — a capability pointer
/// at 0xF4 overflows (release builds run `overflow-checks = true`:
/// a kernel PANIC from a hostile config space). Every capability must
/// now lie wholly inside the 256-byte space, carry `len >= 16`
/// (`>= 20` for notify, whose multiplier dword is mandatory), name a
/// legal BAR index (<= 5), and NEVER repeat a region type (a
/// duplicate is an ambiguous device: rejected, not last-wins).
pub fn parse_virtio_caps(read_cfg: &mut dyn FnMut(u8) -> u32) -> Option<VirtioCaps> {
    let first = (read_cfg(0x34) & 0xFF) as u8 & 0xFC;
    if !(0x40..=0xFC).contains(&first) {
        return None;
    }
    let mut common = None;
    let mut notify = None;
    let mut multiplier = 0u32;
    let mut isr = None;
    let mut device = None;
    // Bit i set = cfg_type i+1 already seen (duplicates reject).
    let mut types_seen = 0u8;
    // Lists interleave other caps (QEMU: msix first, then the virtio
    // caps, measured) — skip non-virtio entries, protect with a
    // visited set and a hard iteration bound.
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
        // The fixed 16-byte header must fit (arithmetic in u16 — the
        // u8 form overflowed at ptr >= 0xF4); the declared cap length
        // must cover it and fit the space too.
        let hdr_end = u16::from(ptr) + 16;
        if hdr_end > 256 || u16::from(len) < 16 || u16::from(ptr) + u16::from(len) > 256 {
            return None;
        }
        if (1..=4).contains(&cfg_type) {
            if types_seen & (1 << (cfg_type - 1)) != 0 {
                return None; // duplicate region type: ambiguous device
            }
            types_seen |= 1 << (cfg_type - 1);
        }
        // An unknown virtio cap type: skip it, the four-required rule
        // below governs acceptance.
        let w1 = read_cfg(ptr + 4);
        let bar = (w1 & 0xFF) as u8;
        if bar > 5 {
            return None; // no such BAR
        }
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
                // The multiplier dword at +16 is part of the notify
                // cap by definition: len >= 20 or the cap is malformed.
                if u16::from(len) < 20 || u16::from(ptr) + 20 > 256 {
                    return None;
                }
                notify = Some(region);
                multiplier = read_cfg(ptr + 16);
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

/// What can go wrong resolving capability regions against the BARs
/// (F5). Device-supplied values are untrusted: every variant is a
/// refusal, never a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The named BAR has no resolved memory region.
    NoBar(u8),
    /// `offset + length` exceeds the BAR's size.
    BeyondBar { bar: u8, end: u64, size: u64 },
    /// The region is below the register file's minimum length.
    TooSmall { cfg_type: u8, have: u32, need: u32 },
    /// The region offset is not 4-aligned (MMIO register access).
    Misaligned { cfg_type: u8, offset: u32 },
    /// The notify multiplier exceeds the sane band (QEMU uses 4;
    /// anything beyond 8 cannot produce an in-region notify slot for
    /// any real queue count).
    BadMultiplier(u32),
    /// The final physical address falls outside the pre-mapped MMIO
    /// window — dereferencing it would fault the kernel.
    OutsideWindow { pa: u64, len: u64 },
}

impl CapError {
    /// One honest line per refusal class (the boot markers).
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            CapError::NoBar(_) => "BAR unresolved",
            CapError::BeyondBar { .. } => "region beyond the BAR size",
            CapError::TooSmall { .. } => "region below the minimum length",
            CapError::Misaligned { .. } => "region offset not 4-aligned",
            CapError::BadMultiplier(_) => "notify multiplier out of the sane band",
            CapError::OutsideWindow { .. } => "register block outside the mapped MMIO window",
        }
    }
}

/// The four register blocks resolved to CHECKED physical addresses
/// (F5): every region fits its BAR, meets its minimum length, is
/// aligned, and lands inside the mapped MMIO window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedCaps {
    pub common_pa: u64,
    pub notify_base_pa: u64,
    pub notify_len: u32,
    pub notify_multiplier: u32,
    pub isr_pa: u64,
    pub device_cfg_pa: u64,
}

impl VirtioCaps {
    /// F5 (review round 4): resolve the capability regions against
    /// the device's BARs with checked math. The device chose these
    /// numbers; none of them is trusted: `offset + length <= size`
    /// per region, minimum lengths (common >= 0x38 registers, isr >=
    /// 1, device cfg >= 8, notify >= 2), 4-alignment, a sane
    /// multiplier, and every final physical address inside the mapped
    /// MMIO window — else refuse.
    pub fn resolve(&self, dev: &crate::pci::PciDev) -> Result<ResolvedCaps, CapError> {
        let resolve_region =
            |region: &CapRegion, cfg_type: u8, need: u32| -> Result<u64, CapError> {
                let bar =
                    crate::pci::mem_bar(dev, region.bar).ok_or(CapError::NoBar(region.bar))?;
                let off = u64::from(region.offset);
                let len = u64::from(region.length);
                // The common config carries u64 queue registers at
                // +0x20..0x30: its base must be 8-aligned; the other
                // blocks are u32/u16/u8 access — 4 suffices.
                let align: u64 = if cfg_type == 1 { 8 } else { 4 };
                if !off.is_multiple_of(align) {
                    return Err(CapError::Misaligned {
                        cfg_type,
                        offset: region.offset,
                    });
                }
                if region.length < need {
                    return Err(CapError::TooSmall {
                        cfg_type,
                        have: region.length,
                        need,
                    });
                }
                let end = off.checked_add(len).ok_or(CapError::BeyondBar {
                    bar: region.bar,
                    end: u64::MAX,
                    size: bar.size,
                })?;
                if end > bar.size {
                    return Err(CapError::BeyondBar {
                        bar: region.bar,
                        end,
                        size: bar.size,
                    });
                }
                let pa = bar
                    .base
                    .checked_add(off)
                    .ok_or(CapError::OutsideWindow { pa: u64::MAX, len })?;
                if !crate::arch::lapic::mmio_in_window(pa, len) {
                    return Err(CapError::OutsideWindow { pa, len });
                }
                Ok(pa)
            };
        let common_pa = resolve_region(&self.common, 1, 0x38)?;
        let notify_base_pa = resolve_region(&self.notify, 2, 2)?;
        let isr_pa = resolve_region(&self.isr, 3, 1)?;
        let device_cfg_pa = resolve_region(&self.device, 4, 8)?;
        if self.notify_multiplier > 8 {
            return Err(CapError::BadMultiplier(self.notify_multiplier));
        }
        Ok(ResolvedCaps {
            common_pa,
            notify_base_pa,
            notify_len: self.notify.length,
            notify_multiplier: self.notify_multiplier,
            isr_pa,
            device_cfg_pa,
        })
    }
}

/// F6 (review round 4): the words the driver actually negotiates —
/// `device & wanted`, refusing devices that do not offer VERSION_1
/// (bit 32: the modern layout this driver speaks) or
/// ACCESS_PLATFORM (bit 33: DMA goes through the IOMMU — the whole
/// broker design assumes it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureWords {
    pub low: u32,
    pub high: u32,
}

/// Negotiate: driver = device & wanted, with VERSION_1 and
/// ACCESS_PLATFORM REQUIRED to have been offered.
pub fn negotiate_features(device_low: u32, device_high: u32) -> Result<FeatureWords, &'static str> {
    if device_high & F1_VERSION_1 == 0 {
        return Err("VIRTIO_F_VERSION_1 not offered — not a modern device");
    }
    if device_high & F1_ACCESS_PLATFORM == 0 {
        return Err("VIRTIO_F_ACCESS_PLATFORM not offered — no IOMMU path");
    }
    Ok(FeatureWords {
        low: device_low & DRIVER_FEATURES_LOW,
        high: device_high & DRIVER_FEATURES_HIGH,
    })
}

/// F7 (review round 4): validate one used-ring completion against
/// what was actually submitted. The device wrote these fields; a
/// completion that names an id beyond the queue, an id that is not
/// the submitted head, or a length beyond the submitted buffer is a
/// hostile device — the caller takes the poison path.
pub fn validate_used(
    used_pa: u64,
    slot: u16,
    qsize: u16,
    want_head: u32,
    max_len: u32,
) -> Result<(u32, u32), &'static str> {
    let id = used_entry_id(used_pa, slot);
    let len = used_entry_len(used_pa, slot);
    if id >= u32::from(qsize) {
        return Err("completion id beyond the queue size");
    }
    if id != want_head {
        return Err("completion id is not the submitted head");
    }
    if len > max_len {
        return Err("completion length beyond the submitted buffer");
    }
    Ok((id, len))
}

// ── u16 access at (2-aligned) addresses, over aligned u32 RMW ──
//
// memops owns exactly u32/u64 volatile primitives; virtio rings are
// full of u16 fields. These helpers are pure arithmetic over memops —
// no new unsafe, host-tested over plain buffers.

/// Read the u16 at `pa` (must be 2-aligned).
#[must_use]
pub fn read_u16_pa(pa: u64) -> u16 {
    debug_assert!(pa.is_multiple_of(2));
    let w = memops::read_u32(pa & !3);
    ((w >> (8 * (pa & 2))) & 0xFFFF) as u16
}

/// Write the u16 at `pa` (must be 2-aligned) via u32 read-modify-write.
pub fn write_u16_pa(pa: u64, v: u16) {
    debug_assert!(pa.is_multiple_of(2));
    let base = pa & !3;
    let shift = 8 * (pa & 2);
    let w = memops::read_u32(base);
    let cleared = w & !(0xFFFF << shift);
    memops::write_u32(base, cleared | ((v as u32) << shift));
}

/// Write the u32 at `pa` (must be 4-aligned): a plain word store —
/// the virtio-serial port-id header and similar 4-byte structures.
pub fn write_u32_pa(pa: u64, v: u32) {
    debug_assert!(pa.is_multiple_of(4));
    memops::write_u32(pa, v);
}

/// Read the u8 at `pa` via its containing u32 word.
#[must_use]
pub fn read_u8_pa(pa: u64) -> u8 {
    let w = memops::read_u32(pa & !3);
    ((w >> (8 * (pa & 3))) & 0xFF) as u8
}

/// Write the u8 at `pa` via its containing u32 word (read-modify-
/// write; byte-granular stores for hand-built packets).
pub fn write_u8_pa(pa: u64, v: u8) {
    let base = pa & !3;
    let shift = 8 * (pa & 3);
    let w = memops::read_u32(base);
    let cleared = w & !(0xFF << shift);
    memops::write_u32(base, cleared | (u32::from(v) << shift));
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
    // The used ring starts with flags+idx (4 bytes), so entry `i`
    // sits at +4+8i — a u32 at a 4-aligned address on every ring
    // frame. Two u32 reads (not one u64 at +4, which is only
    // 4-aligned) keep the host UB-check clean and match the layout.
    memops::read_u32(used_pa + 4 + 8 * u64::from(i))
}

// ── virtio-net additions (the second driver on this transport) ──

/// The virtio-net header the device exchanges with the driver.
/// **12 bytes** with VIRTIO 1.0: QEMU's virtio_net_apply() sets
/// guest_hdr_len = sizeof(virtio_net_hdr_mrg_rxbuf) UNCONDITIONALLY
/// for version_1 (hw/net/virtio-net.c:646) — mergeable or not. We
/// negotiated VERSION_1, so every buffer reserves 12: all zero for a
/// plain frame (the extra 2 bytes are num_buffers, 0 on TX). Measured
/// the 10-byte assumption: the device skipped 12, the wire frame came
/// out shifted by 2 (dst read ffffffff5254, len 288 = 300-12).
pub const NET_HDR_LEN: u32 = 12;

/// Write the 10-byte virtio-net header at `pa` (plain frame: no
/// offloads, no GSO — everything this driver sends is
/// self-contained).
pub fn write_net_header(pa: u64) {
    memops::write_u64(pa, 0);
    memops::write_u64(pa + 8, 0);
    // 12 bytes total (see NET_HDR_LEN): the first 10 are the v1
    // header, the last 2 are num_buffers — zero on TX.
}

/// The Internet checksum (RFC 1071) over `len` bytes at `pa` —
/// 16-bit big-endian words, ones-complement fold. Used for the IPv4
/// header built in-kernel; the UDP checksum stays 0 (legal on IPv4).
pub fn ip_checksum(pa: u64, len: u32) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0u32;
    while i + 1 < len {
        let hi = read_u8_pa(pa + u64::from(i));
        let lo = read_u8_pa(pa + u64::from(i + 1));
        sum += (u32::from(hi) << 8) | u32::from(lo);
        i += 2;
    }
    if i < len {
        sum += u32::from(read_u8_pa(pa + u64::from(i))) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Length of completed transfer `i` in the used ring (the u32 at
/// entry+4 — the RX driver reads the frame size from here).
pub fn used_entry_len(used_pa: u64, i: u16) -> u32 {
    // The completed-length half of used entry `i` (u32 at +4+8i+4).
    memops::read_u32(used_pa + 4 + 8 * u64::from(i) + 4)
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
    notify_len: u32,
    multiplier: u32,
    device_cfg_pa: u64,
    isr_pa: u64,
}

#[cfg(not(test))]
impl MmioVirtio {
    /// Build the live register blocks from CHECKED resolutions
    /// (F5: `VirtioCaps::resolve` validated every device number —
    /// the old `from_caps` added device-supplied offsets to BAR
    /// bases with no checks at all).
    #[must_use]
    pub fn from_resolved(r: &ResolvedCaps) -> Self {
        MmioVirtio {
            common_pa: r.common_pa,
            notify_base_pa: r.notify_base_pa,
            notify_len: r.notify_len,
            multiplier: r.notify_multiplier,
            device_cfg_pa: r.device_cfg_pa,
            isr_pa: r.isr_pa,
        }
    }

    fn r32(&self, off: u64) -> u32 {
        memops::read_u32(self.common_pa + off)
    }

    fn w32(&self, off: u64, v: u32) {
        memops::write_u32(self.common_pa + off, v);
    }

    /// Exact-width, exact-address 2-byte common-config access.
    /// QEMU's common-config dispatches on the access address+width:
    /// the old u32-RMW-at-the-aligned-base form was dispatched as a
    /// STATUS write, silently eating QUEUE_SEL (queue selection was
    /// stuck at 0 — invisible for queue-0-only devices, fatal for
    /// queue 1).
    fn r16(&self, off: u64) -> u16 {
        memops::read_u16(self.common_pa + off)
    }

    /// Exact-width 2-byte common-config write (see `r16`).
    fn w16(&self, off: u64, v: u16) {
        memops::write_u16(self.common_pa + off, v)
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

    /// Bind the config-change interrupt to MSI-X table entry `entry`
    /// (config_msix_vector). The grant is read back: a modern device
    /// echoes the request or answers [`VIRTIO_MSI_NO_VECTOR`] when it
    /// refuses — the caller fail-closes on anything but the echo.
    pub fn set_config_vector(&self, entry: u16) -> u16 {
        self.w16(CC_CONFIG_MSIX, entry);
        self.r16(CC_CONFIG_MSIX)
    }

    /// Bind the SELECTED queue's completions to MSI-X table entry
    /// `entry` (queue_msix_vector). Same grant semantics as
    /// [`Self::set_config_vector`]. This write is what tells the
    /// device WHICH entry a completion fires — without it the queue's
    /// vector stays [`VIRTIO_MSI_NO_VECTOR`] and no completion ever
    /// sends a message, however the table itself is programmed (found
    /// live, round two of ADR-0019: entries armed, cap enabled, work
    /// queued and consumed — the delivery window still timed out every
    /// run until the binding).
    pub fn set_queue_vector(&self, entry: u16) -> u16 {
        self.w16(CC_QUEUE_MSIX, entry);
        self.r16(CC_QUEUE_MSIX)
    }

    /// Kick a queue. Per virtio 1.x §4.1.5.2 the VALUE written is the
    /// queue index (QEMU's modern notify dispatches on the value —
    /// measured: a value of 0 always kicks queue 0, which hid the
    /// net TX queue behind the RX kick); the address is still the
    /// queue's own notify slot from QUEUE_NOTIFY_OFF × multiplier.
    pub fn notify(&self, queue_index: u16, queue_notify_off: u16) -> bool {
        // F5 (review round 4): the device chose `queue_notify_off`
        // and the multiplier — the computed slot must land inside the
        // resolved notify region, or the write is REFUSED (no write,
        // the caller takes the poison path).
        let off = u64::from(queue_notify_off) * u64::from(self.multiplier);
        let end = match off.checked_add(2) {
            Some(e) => e,
            None => return false,
        };
        if end > u64::from(self.notify_len) {
            return false;
        }
        let pa = self.notify_base_pa + off;
        // EXACTLY Linux's kick: `iowrite16(index, notify_base +
        // off * multiplier)` — a 2-byte store at the queue's own
        // slot. A 4-byte store was measured to be split by QEMU into
        // two 2-byte dispatches (two queue_notify traces per kick);
        // the RMW lane is forbidden (notify reads are undefined).
        memops::write_u16(pa, queue_index);
        true
    }

    /// The disk capacity in 512-byte sectors (device config +0) —
    /// two ALIGNED u32 reads (F5): resolve() guarantees a 4-aligned
    /// block, and a single u64 read at a device-chosen address could
    /// still be 4-but-not-8 aligned.
    pub fn capacity_sectors(&self) -> u64 {
        u64::from(memops::read_u32(self.device_cfg_pa))
            | (u64::from(memops::read_u32(self.device_cfg_pa + 4)) << 32)
    }

    /// The ISR register (bit 0 = queue-activity poke). Diagnostics
    /// for the kick path: set when the device updates a used ring.
    #[must_use]
    pub fn isr(&self) -> u8 {
        read_u8_pa(self.isr_pa)
    }

    /// The SELECTED queue's ring addresses + enable bit, read back
    /// from common config (bring-up: proves the device holds what we
    /// mapped).
    #[must_use]
    pub fn queue_addresses(&self) -> (u64, u64, u64, u16) {
        (
            memops::read_u64(self.common_pa + CC_QUEUE_DESC),
            memops::read_u64(self.common_pa + CC_QUEUE_AVAIL),
            memops::read_u64(self.common_pa + CC_QUEUE_USED),
            self.r16(CC_QUEUE_ENABLE),
        )
    }

    /// The resolved notify lane (base physical address + the
    /// multiplier) — bring-up diagnostics for the kick path.
    #[must_use]
    pub fn notify_lane(&self) -> (u64, u32) {
        (self.notify_base_pa, self.multiplier)
    }

    /// The device-specific config base (blk: capacity; net: the MAC
    /// at +0 and status at +6).
    #[must_use]
    pub fn device_cfg_pa(&self) -> u64 {
        self.device_cfg_pa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The net header is 10 zero bytes (no offloads, no GSO).
    #[test]
    fn net_header_is_ten_zero_bytes() {
        // Test "physical" addresses are identity-translated host
        // pointers — hand in a REAL leaked buffer, never a literal.
        let buf: &'static mut [u64; 4] = Box::leak(Box::new([0u64; 4]));
        let pa = buf.as_ptr() as u64;
        memops::write_u64(pa, 0xFFFF_FFFF_FFFF_FFFF);
        write_u16_pa(pa + 8, 0xFFFF);
        write_net_header(pa);
        assert_eq!(memops::read_u64(pa), 0);
        assert_eq!(read_u16_pa(pa + 8), 0);
        assert_eq!(NET_HDR_LEN, 12);
    }

    /// The Internet checksum against the canonical worked example
    /// (4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7 → b861).
    #[test]
    fn ip_checksum_matches_the_reference_vector() {
        let buf: &'static mut [u64; 4] = Box::leak(Box::new([0u64; 4]));
        let pa = buf.as_ptr() as u64;
        let bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        for (i, &b) in bytes.iter().enumerate() {
            write_u8_pa(pa + i as u64, b);
        }
        assert_eq!(ip_checksum(pa, 20), 0xB861);
    }

    /// The used ring's completed-length field (entry+4).
    #[test]
    fn used_entry_len_reads_the_second_word() {
        let buf: &'static mut [u64; 4] = Box::leak(Box::new([0u64; 4]));
        let used = buf.as_ptr() as u64;
        memops::write_u32(used + 4, 7); // entry 0: id
        memops::write_u32(used + 8, 0x2A); // entry 0: len
        assert_eq!(used_entry_id(used, 0), 7);
        assert_eq!(used_entry_len(used, 0), 0x2A);
    }

    /// The MSI-X vector-binding registers sit at the SPEC offsets
    /// (§4.1.4.3): config_msix_vector at +0x10, queue_msix_vector at
    /// +0x1A — between num_queues (0x12) and queue_enable (0x1C). An
    /// offset drift here breaks message delivery SILENTLY, which is
    /// exactly how round one failed. Pinned at COMPILE time (an
    /// `assert!` in a `const` block — stronger than a test run); the
    /// write-then-read grant itself is target-only (MmioVirtio is
    /// `cfg(not(test))`) and is proven by the lane's [MSIX] DELIVERED
    /// marker.
    const _: () = {
        assert!(CC_CONFIG_MSIX == 0x10, "config_msix_vector offset");
        assert!(CC_QUEUE_MSIX == 0x1A, "queue_msix_vector offset");
        assert!(
            CC_NUM_QUEUES == 0x12 && CC_QUEUE_SEL == 0x16 && CC_QUEUE_ENABLE == 0x1C,
            "the layout neighbors pin the field map"
        );
        assert!(VIRTIO_MSI_NO_VECTOR == 0xFFFF, "the no-vector value");
    };

    /// Byte-granular writes land byte-exactly (the RMW lane).
    #[test]
    fn write_u8_pa_is_byte_exact() {
        let buf: &'static mut [u64; 4] = Box::leak(Box::new([0u64; 4]));
        let pa = buf.as_ptr() as u64;
        memops::write_u64(pa, 0x1111_1111_1111_1111);
        write_u8_pa(pa + 3, 0xAB);
        assert_eq!(read_u8_pa(pa + 3), 0xAB);
        assert_eq!(read_u8_pa(pa + 2), 0x11);
        assert_eq!(read_u8_pa(pa + 4), 0x11);
    }

    /// A fake config space: dwords in a plain buffer, a virtio cap
    /// chain planted at 0x40.
    struct FakeCfg {
        /// 64 dwords = the 256-byte config space, +4 slack dwords for
        /// cap fields that START inside the space but would overflow
        /// it (the parser must reject those caps without reading the
        /// overflow — the slack exists so the FIXTURE never panics).
        d: Vec<u32>,
    }

    impl FakeCfg {
        fn new() -> Self {
            FakeCfg { d: vec![0; 68] }
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

    /// F4 (review round 4): a hostile config space must never panic —
    /// the old code computed `ptr + 12` on a u8, and a capability at
    /// 0xF4 overflowed it (release runs overflow-checks: a kernel
    /// panic from device input). Every malformed shape fails closed.
    #[test]
    fn caps_hostile_config_fails_closed_never_panics() {
        // A cap at 0xF4: its 16-byte header ends at 0x104 — beyond
        // the 256-byte space. The u8 arithmetic overflowed HERE.
        let mut c = FakeCfg::new();
        c.d[13] = 0xF4;
        c.cap(0xF4, 0x00, 1, 4, 0, 0x38, None);
        assert!(
            parse_virtio_caps(&mut |off| c.read(off)).is_none(),
            "a cap must fit wholly inside the 256-byte space"
        );
        // Same for a cap at 0xFC whose header cannot fit either.
        let mut c = FakeCfg::new();
        c.d[13] = 0xFC;
        c.cap(0xFC, 0x00, 1, 4, 0, 0x38, None);
        assert!(parse_virtio_caps(&mut |off| c.read(off)).is_none());
        // len < 16: the offset/length dwords would read past the cap.
        let mut c = FakeCfg::new();
        c.d[13] = 0x40;
        c.d[(0x40 / 4) as usize] = 0x09 | (0x00 << 8) | (8 << 16) | (1 << 24); // len=8
        assert!(
            parse_virtio_caps(&mut |off| c.read(off)).is_none(),
            "len < 16 refused"
        );
        // A notify cap without the multiplier dword (len 16..19).
        let mut c = FakeCfg::new();
        c.d[13] = 0x40;
        c.d[(0x40 / 4) as usize] = 0x09 | (0x00 << 8) | (16 << 16) | (2 << 24); // notify, len=16
        assert!(
            parse_virtio_caps(&mut |off| c.read(off)).is_none(),
            "notify needs len >= 20"
        );
        // A BAR index that does not exist.
        let mut c = FakeCfg::new();
        c.d[13] = 0x40;
        c.cap(0x40, 0x00, 1, 7, 0, 0x38, None);
        assert!(
            parse_virtio_caps(&mut |off| c.read(off)).is_none(),
            "bar > 5 refused"
        );
        // A duplicate region type: ambiguous device, rejected (the
        // old code silently let the LAST one win).
        let mut c = FakeCfg::new();
        c.d[13] = 0x40;
        c.cap(0x40, 0x60, 1, 4, 0x0000, 0x38, None); // common #1
        c.cap(0x60, 0x80, 2, 4, 0x0040, 0x1000, Some(4));
        c.cap(0x80, 0x90, 1, 4, 0x9000, 0x38, None); // common #2 — dup
        c.cap(0x90, 0x00, 3, 4, 0x2040, 0x10, None);
        assert!(
            parse_virtio_caps(&mut |off| c.read(off)).is_none(),
            "duplicate cfg_type rejected"
        );
    }

    /// A minimal but complete PciDev with one memory BAR, for resolve.
    fn test_dev(slot: u8, base: u64, size: u64) -> crate::pci::PciDev {
        crate::pci::PciDev {
            bus: 0,
            dev: 3,
            func: 0,
            vendor: 0x1AF4,
            device: 0x1042,
            class: 0,
            header: 0,
            bars: [
                Some(crate::pci::Bar {
                    slot,
                    kind: crate::pci::BarKind::Mem32,
                    base,
                    size,
                    prefetchable: false,
                }),
                None,
                None,
                None,
                None,
                None,
            ],
            bar_count: 6,
            cap_ids: [0; crate::pci::MAX_CAPS],
            cap_ptrs: [0; crate::pci::MAX_CAPS],
            cap_count: 0,
            dom: 0,
        }
    }

    /// F5: resolve checks offset+length against the BAR size, the
    /// minimum lengths, alignment, the multiplier band, and the MMIO
    /// window — every refusal is typed, never a guess.
    #[test]
    fn resolve_checks_every_device_number() {
        // The healthy shape: BAR 4 at the window base, 8 KiB.
        let dev = test_dev(4, 0xE000_0000, 0x4000);
        let caps = VirtioCaps {
            common: CapRegion {
                bar: 4,
                offset: 0x0000,
                length: 0x38,
            },
            notify: CapRegion {
                bar: 4,
                offset: 0x0040,
                length: 0x1000,
            },
            notify_multiplier: 4,
            isr: CapRegion {
                bar: 4,
                offset: 0x2040,
                length: 0x10,
            },
            device: CapRegion {
                bar: 4,
                offset: 0x2050,
                length: 0x20,
            },
        };
        let r = caps.resolve(&dev).expect("the healthy shape resolves");
        assert_eq!(r.common_pa, 0xE000_0000);
        assert_eq!(r.notify_base_pa, 0xE000_0040);
        assert_eq!(r.notify_len, 0x1000);
        assert_eq!(r.notify_multiplier, 4);
        assert_eq!(r.isr_pa, 0xE000_2040);
        assert_eq!(r.device_cfg_pa, 0xE000_2050);

        // Region beyond the BAR: offset + length > size.
        let mut bad = caps;
        bad.common = CapRegion {
            bar: 4,
            offset: 0x3FF0,
            length: 0x38,
        };
        assert_eq!(
            bad.resolve(&dev),
            Err(CapError::BeyondBar {
                bar: 4,
                end: 0x4028,
                size: 0x4000
            })
        );
        // Below the minimum lengths (common needs 0x38).
        let mut bad = caps;
        bad.common = CapRegion {
            bar: 4,
            offset: 0,
            length: 0x30,
        };
        assert_eq!(
            bad.resolve(&dev),
            Err(CapError::TooSmall {
                cfg_type: 1,
                have: 0x30,
                need: 0x38
            })
        );
        // Unaligned region offset.
        let mut bad = caps;
        bad.isr = CapRegion {
            bar: 4,
            offset: 0x2042,
            length: 0x10,
        };
        assert_eq!(
            bad.resolve(&dev),
            Err(CapError::Misaligned {
                cfg_type: 3,
                offset: 0x2042
            })
        );
        // An insane multiplier.
        let mut bad = caps;
        bad.notify_multiplier = 0x1000;
        assert_eq!(bad.resolve(&dev), Err(CapError::BadMultiplier(0x1000)));
        // A BAR base OUTSIDE the mapped MMIO window (host RAM): the
        // final address must refuse, not fault.
        let dev_low = test_dev(4, 0x0010_0000, 0x4000);
        assert!(matches!(
            caps.resolve(&dev_low),
            Err(CapError::OutsideWindow { .. })
        ));
        // A BAR the device names but the enumeration never resolved.
        let dev_none = test_dev(2, 0xE000_0000, 0x4000);
        assert!(matches!(caps.resolve(&dev_none), Err(CapError::NoBar(4))));
    }

    /// F6: negotiation is device & wanted, with VERSION_1 and
    /// ACCESS_PLATFORM required offerings.
    #[test]
    fn negotiation_intersects_and_requires_the_modern_bits() {
        // A modern IOMMU device offering both required bits.
        let n = negotiate_features(0, F1_VERSION_1 | F1_ACCESS_PLATFORM | (1 << 5))
            .expect("modern device negotiates");
        assert_eq!(n.low, 0);
        assert_eq!(
            n.high,
            F1_VERSION_1 | F1_ACCESS_PLATFORM,
            "unwanted bits dropped"
        );
        // No VERSION_1: not a modern device — refuse.
        assert_eq!(
            negotiate_features(0, F1_ACCESS_PLATFORM),
            Err("VIRTIO_F_VERSION_1 not offered — not a modern device")
        );
        // No ACCESS_PLATFORM: no IOMMU path — refuse.
        assert_eq!(
            negotiate_features(0, F1_VERSION_1),
            Err("VIRTIO_F_ACCESS_PLATFORM not offered — no IOMMU path")
        );
    }

    /// F7: used-ring completions are validated against the submission.
    #[test]
    fn used_ring_completions_are_validated() {
        let buf: &'static mut [u64; 8] = Box::leak(Box::new([0u64; 8]));
        let used = buf.as_ptr() as u64;
        // entry 0: id 0, len 512 — the honest completion.
        memops::write_u32(used + 4, 0);
        memops::write_u32(used + 8, 512);
        assert_eq!(validate_used(used, 0, 256, 0, 529), Ok((0, 512)));
        // id beyond the queue.
        memops::write_u32(used + 4, 300);
        assert_eq!(
            validate_used(used, 0, 256, 0, 529),
            Err("completion id beyond the queue size")
        );
        // id is not the submitted head.
        memops::write_u32(used + 4, 1);
        assert_eq!(
            validate_used(used, 0, 256, 0, 529),
            Err("completion id is not the submitted head")
        );
        // length beyond the submitted buffer.
        memops::write_u32(used + 4, 0);
        memops::write_u32(used + 8, 4096);
        assert_eq!(
            validate_used(used, 0, 256, 0, 529),
            Err("completion length beyond the submitted buffer")
        );
    }

    /// F8 (review round 4): deterministic fuzz — random 256-byte
    /// config images and random BARs never panic the parser or the
    /// resolver, and every ACCEPTED result satisfies the bounds it
    /// was checked against.
    #[test]
    fn fuzz_caps_and_resolve_never_panic_oks_are_bounded() {
        let mut state = 0xABCD_1234_F00D_BEEFu64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut parsed = 0u32;
        let mut resolved = 0u32;
        for _ in 0..4000 {
            let mut c = FakeCfg::new();
            for w in c.d.iter_mut() {
                *w = next() as u32;
            }
            // Half the rounds PLANT four virtio caps with random
            // unvalidated fields (next pointers, offsets, lengths,
            // bars, multiplier) so the parser's accept/reject paths
            // and the resolver's math are actually exercised; the
            // other half is pure noise (must never panic either).
            if next() & 1 == 1 {
                let bar = (next() % 8) as u8; // includes illegal > 5
                c.d[13] = 0x40;
                let offs = [0x40u8, 0x60, 0x80, 0x90];
                let types = [1u8, 2, 3, 4];
                for i in 0..4 {
                    let next_ptr = if i == 3 { 0u8 } else { offs[i + 1] };
                    // Small, 4-aligned offsets and sane-ish lengths so
                    // the ACCEPT path is exercised too; the wild
                    // values still appear (bar > 5, multiplier band,
                    // occasional overflow) from the moduli.
                    let region_off = ((next() % 64) * 4) as u32;
                    let region_len = (8 + next() % 64) as u32;
                    let mult = if types[i] == 2 {
                        Some((next() % 16) as u32)
                    } else {
                        None
                    };
                    c.cap(
                        offs[i], next_ptr, types[i], bar, region_off, region_len, mult,
                    );
                }
            } else if next() & 1 == 1 {
                c.d[13] = (next() & 0xFF) as u32;
            }
            let caps = parse_virtio_caps(&mut |off| c.read(off)); // never panics
            let Some(caps) = caps else { continue };
            parsed += 1;
            // Random BARs; half the rounds inside the MMIO window so
            // the Ok path is exercised, half anywhere in PA space.
            let in_window = next() & 1 == 1;
            let base = if in_window {
                0xC000_0000 + (next() % 0x1000) * 4096
            } else {
                next() & 0x000F_FFFF_FFFF_F000
            };
            let size = 1 + (next() % 0x2000);
            let dev = test_dev(4, base, size);
            if let Ok(r) = caps.resolve(&dev) {
                resolved += 1;
                // Every accepted region lies inside its BAR and the
                // window, and meets its minimum.
                assert!(r.common_pa >= base);
                assert!(r.common_pa + u64::from(caps.common.length) <= base + size);
                assert!(crate::arch::lapic::mmio_in_window(
                    r.common_pa,
                    u64::from(caps.common.length)
                ));
                assert!(caps.common.length >= 0x38);
                assert!(caps.isr.length >= 1);
                assert!(caps.device.length >= 8);
                assert!(caps.notify.length >= 2);
                assert!(r.notify_multiplier <= 8);
                assert!(crate::arch::lapic::mmio_in_window(r.isr_pa, 1));
                assert!(crate::arch::lapic::mmio_in_window(r.device_cfg_pa, 8));
            }
        }
        // The fuzz must exercise BOTH outcomes, not just refusals.
        assert!(parsed > 0, "at least some images parse");
        assert!(
            resolved > 0,
            "at least some resolutions succeed (window rounds)"
        );
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
