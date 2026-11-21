//! PCI bus enumeration (driver stack Phase 1, checklist item 2).
//!
//! Bus 0 on this machine class (QEMU q35/pc: one PCI segment, every
//! interesting device on bus 0 — virtio-blk sits at 00:03.0 on the
//! driver lane). The scan walks devices/functions, decodes headers,
//! sizes every BAR (32/64-bit memory, I/O) with checked math, walks
//! the capability list (MSI 0x05, MSI-X 0x11, the virtio vendor cap
//! 0x09), and hands the inventory to the boot log.
//!
//! ## Config-space access: dword port I/O, and why
//!
//! The first cut composed CF8/CFC dwords out of byte port accesses to
//! keep the unsafe ratchet at 89. It read garbage on real QEMU q35,
//! and the reason is architectural: **0xCF9 is the chipset reset
//! control register**, not the second byte of the PCI address
//! register — byte-wise writes to CF8+1 hit reset control, the
//! address never latches, and every config read returns noise (the
//! measured failure: vendor 0x0008 on all 32 slots). The fix is the
//! spec-correct width: `hw::outl`/`inl` dword accesses, two new
//! one-instruction allowlisted wrappers in `hw.rs`, ratchet 89 → 91
//! with the ADR-0013 reference in `scripts/unsafe-count.txt`. The
//! lesson is recorded here so nobody "optimizes" it back.
//!
//! ## Testability
//!
//! The whole enumeration (`scan`, BAR sizing, capability walk, the
//! claim gate) is generic over a `read_cfg`/`write_cfg` pair: the
//! kernel passes port-backed closures, the host tests pass fake
//! config arrays — the identical code path, the memops discipline.
//!
//! ## Scope, stated honestly
//!
//! - ECAM/MCFG (extended config space beyond 256 B) is deferred: the
//!   virtio modern capabilities live inside the first 256 bytes via
//!   the 0x34 capability list, which CF8/CFC reaches. MCFG is present
//!   on q35 (measured in the RSDT directory); the day a device needs
//!   extended caps, MCFG parsing plugs in here.
//! - Hierarchical bus walks behind PCI-to-PCI bridges: this machine
//!   class keeps bus 0 flat; a bridge scan arrives with a machine
//!   that has one.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only users (driver steps and their helpers), so items only
// they use look dead there — they are used by the boot build.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables, unused_mut))]

use aegis_os::dma::DmaVerdict;

/// Devices the fixed inventory holds (fail-loud exhaustion). The flat
/// bus-0 world needed 32; the ADR-0020 bridge walk needs headroom for
/// a root port + its children on top of bus 0 (q35 with one root port
/// and one device lands ~24 — 48 leaves room for a real NIC + NVMe
/// card without silently dropping them).
pub const MAX_PCI_DEVICES: usize = 48;
/// Capability-list entries recorded per device (bounded walk).
pub const MAX_CAPS: usize = 8;

/// The I/O ports (fixed by the PCI spec).
pub const CFG_ADDR_PORT: u16 = 0xCF8;
pub const CFG_DATA_PORT: u16 = 0xCFC;

/// CF8 address encoding: enable bit 31, then bus/dev/fn/register.
#[must_use]
pub const fn cfg_addr(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC)
}

// ── pure header decode (over a [u32; 16] snapshot) ──

#[must_use]
pub fn vendor_id(h: &[u32; 16]) -> u16 {
    (h[0] & 0xFFFF) as u16
}

#[must_use]
pub fn device_id(h: &[u32; 16]) -> u16 {
    (h[0] >> 16) as u16
}

/// Class:subclass byte (offset 0x0B:0x0A).
#[must_use]
pub fn class_code(h: &[u32; 16]) -> u16 {
    ((h[2] >> 16) & 0xFFFF) as u16
}

/// Header type (offset 0x0E): bit 7 = multifunction, bits 6:0 = layout.
#[must_use]
pub fn header_type(h: &[u32; 16]) -> u8 {
    (h[3] >> 16) as u8
}

#[must_use]
pub fn is_multifunction(h: &[u32; 16]) -> bool {
    header_type(h) & 0x80 != 0
}

/// Is the header type 0 (an endpoint, not a bridge)?
#[must_use]
pub fn is_endpoint(h: &[u32; 16]) -> bool {
    header_type(h) & 0x7F == 0
}

/// The known-ID table — only IDs this driver stack actually knows how
/// to reason about; everything else prints as "?" (never invented).
#[must_use]
pub fn describe(vendor: u16, device: u16) -> &'static str {
    match (vendor, device) {
        (0x1AF4, 0x1001) | (0x1AF4, 0x1042) => "virtio-blk",
        (0x1AF4, _) => "virtio (other)",
        _ => "?",
    }
}

// ── BAR sizing (pure math over probe values) ──

/// A sized BAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bar {
    /// The BAR number this register pair lives at (0..=5); a 64-bit
    /// BAR reports its LOW slot. Virtio capabilities name BARs by
    /// this index.
    pub slot: u8,
    pub kind: BarKind,
    pub base: u64,
    pub size: u64,
    pub prefetchable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarKind {
    Mem32,
    Mem64,
    Io,
}

/// 64-bit memory-BAR size from a probe mask. The PCI sizing formula
/// (Linux's `pci_size`): the size is the **lowest set bit** of the
/// read-back — a high word of all-ones means those bits are decoded
/// (a ≥ 4 GiB BAR), a zero high word means a sub-4-GiB BAR. `None`
/// only for the dead patterns: zero, or raw all-ones.
#[must_use]
pub fn bar_size_from_mem64_mask(mask: u64) -> Option<u64> {
    if mask == 0 || mask == 0xFFFF_FFFF_FFFF_FFFF {
        return None;
    }
    let addr = mask & 0xFFFF_FFFF_FFFF_FFF0; // type/prefetch bits
    Some(addr.isolate_lowest_one()) // lowest set bit
}

/// 32-bit memory-BAR size from a probe mask, same lowest-set-bit
/// formula in 32-bit space. A raw all-ones read-back is the "no BAR
/// here" pattern, not a 4 GiB BAR.
#[must_use]
pub fn bar_size_from_mem32_mask(mask: u32) -> Option<u64> {
    if mask == 0 || mask == 0xFFFF_FFFF {
        return None;
    }
    let addr = mask & 0xFFFF_FFF0; // type/prefetch bits
    Some(u64::from(addr.isolate_lowest_one()))
}

/// I/O BAR size from a probe mask (16-bit port space, lowest-set-bit
/// formula, bits 0..1 stripped).
#[must_use]
pub fn bar_size_from_io_mask(mask: u32) -> Option<u64> {
    if mask == 0 || mask == 0xFFFF_FFFF {
        return None;
    }
    let addr = mask & 0xFFFF_FFFC;
    if addr == 0 {
        return None;
    }
    Some(u64::from(addr.isolate_lowest_one()))
}

// ── the device record ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDev {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u16,
    pub header: u8,
    pub bars: [Option<Bar>; 6],
    /// ADR-0018: this device's own IOMMU domain (set at claim time by
    /// the kernel's DomainIds allocator; 0 until claimed — domain 0
    /// is the kernel's own and never a device's).
    pub dom: u32,
    pub bar_count: usize,
    /// Capability ids in walk order (MSI 0x05, MSI-X 0x11, virtio 0x09).
    pub cap_ids: [u8; MAX_CAPS],
    pub cap_ptrs: [u8; MAX_CAPS],
    pub cap_count: usize,
}

/// The claim gate (ADR-0013 D2 + checklist item 4's first slice): a
/// DMA-capable device is claimable only when the IOMMU verdict is
/// live, the device is an endpoint, and no RMRR covers it. Host
/// bridge / bridge headers are never DMA claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    NotEndpoint,
    BridgeClass,
    NoIommu,
    RmrrCovered,
}

pub fn check_claim(
    dev: &PciDev,
    verdict: DmaVerdict,
    rmrr_covered: bool,
) -> Result<(), ClaimError> {
    if !is_endpoint_header(dev.header) {
        return Err(ClaimError::NotEndpoint);
    }
    // Class 06 (bridge) — includes the host bridge (0600) and PCI
    // bridges: not DMA devices for this driver stack.
    if dev.class >> 8 == 0x06 {
        return Err(ClaimError::BridgeClass);
    }
    if matches!(verdict, DmaVerdict::Absent { .. }) {
        return Err(ClaimError::NoIommu);
    }
    if rmrr_covered {
        return Err(ClaimError::RmrrCovered);
    }
    Ok(())
}

#[must_use]
pub fn is_endpoint_header(header: u8) -> bool {
    header & 0x7F == 0
}

/// One enumerated inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inventory {
    pub devices: [PciDev; MAX_PCI_DEVICES],
    pub count: usize,
}

impl Inventory {
    #[must_use]
    pub fn empty() -> Self {
        Inventory {
            devices: [EMPTY_DEV; MAX_PCI_DEVICES],
            count: 0,
        }
    }

    /// The first device matching vendor + class (the virtio-blk
    /// lookup: vendor 0x1AF4, class 0x01xx).
    #[must_use]
    pub fn find_by(&self, vendor: u16, class_hi: u8) -> Option<&PciDev> {
        self.devices[..self.count]
            .iter()
            .find(|d| d.vendor == vendor && (d.class >> 8) as u8 == class_hi)
    }

    /// ADR-0018 + round I: record a claimed device's domain by vendor
    /// + DEVICE id — the virtio family's class codes are ambiguous
    ///   (rng/console/balloon share "uncategorized"), so their claims
    ///   match the id. Returns false when no such device is held.
    pub fn set_dom_dev(&mut self, vendor: u16, device: u16, dom: u32) -> bool {
        match self.devices[..self.count]
            .iter()
            .position(|d| d.vendor == vendor && d.device == device)
        {
            Some(i) => {
                self.devices[i].dom = dom;
                true
            }
            None => false,
        }
    }

    /// ADR-0018: record the claimed device's IOMMU domain.
    pub fn set_dom(&mut self, vendor: u16, class_hi: u8, dom: u32) -> bool {
        match self.devices[..self.count]
            .iter()
            .position(|d| d.vendor == vendor && (d.class >> 8) as u8 == class_hi)
        {
            Some(i) => {
                self.devices[i].dom = dom;
                true
            }
            None => false,
        }
    }
}

const EMPTY_DEV: PciDev = PciDev {
    bus: 0,
    dev: 0,
    func: 0,
    vendor: 0xFFFF,
    device: 0xFFFF,
    class: 0xFFFF,
    header: 0xFF,
    bars: [None; 6],
    bar_count: 0,
    cap_ids: [0; MAX_CAPS],
    cap_ptrs: [0; MAX_CAPS],
    cap_count: 0,
    dom: 0,
};

// ── enumeration, generic over the config-space accessors ──

/// `read(bus, dev, fn, off)` → config dword at `off` (4-aligned).
/// `write` is used transiently for BAR sizing and always restores.
pub fn enumerate(
    read: &mut dyn FnMut(u8, u8, u8, u8) -> u32,
    write: &mut dyn FnMut(u8, u8, u8, u8, u32),
) -> Inventory {
    let mut inv = Inventory::empty();
    for dev in 0u8..32 {
        // Function 0 decides existence + multifunction-ness.
        let mut h = [0u32; 16];
        if !read_header(read, 0, dev, 0, &mut h) {
            continue;
        }
        let multifn = is_multifunction(&h);
        let funcs: u8 = if multifn { 8 } else { 1 };
        for func in 0u8..funcs {
            if !read_header(read, 0, dev, func, &mut h) {
                continue;
            }
            if inv.count == MAX_PCI_DEVICES {
                return inv; // loud enough: the log shows the cap
            }
            let mut d = EMPTY_DEV;
            d.bus = 0;
            d.dev = dev;
            d.func = func;
            d.vendor = vendor_id(&h);
            d.device = device_id(&h);
            d.class = class_code(&h);
            d.header = header_type(&h);
            size_bars(read, write, 0, dev, func, &mut h, &mut d);
            walk_caps(read, 0, dev, func, &h, &mut d);
            inv.devices[inv.count] = d;
            inv.count += 1;
        }
    }
    inv
}

/// Read the first 16 dwords (64 bytes) of a function's config space.
/// False when the function is absent (vendor 0xFFFF).
fn read_header(
    read: &mut dyn FnMut(u8, u8, u8, u8) -> u32,
    bus: u8,
    dev: u8,
    func: u8,
    h: &mut [u32; 16],
) -> bool {
    for i in 0..16u8 {
        h[i as usize] = read(bus, dev, func, i * 4);
    }
    vendor_id(h) != 0xFFFF
}

/// Size the BARs of a type-0 function: for each BAR, save, probe with
/// all-ones, decode the mask, restore. 64-bit BARs consume the next
/// register as their high half (checked: never past BAR5).
fn size_bars(
    read: &mut dyn FnMut(u8, u8, u8, u8) -> u32,
    write: &mut dyn FnMut(u8, u8, u8, u8, u32),
    bus: u8,
    dev: u8,
    func: u8,
    h: &mut [u32; 16],
    d: &mut PciDev,
) {
    if !is_endpoint(h) {
        return; // bridges: not claimed, not sized (bus 0 has none)
    }
    let bar_off = |i: usize| (0x10 + i * 4) as u8;
    let mut i = 0usize;
    while i < 6 {
        let lo_orig = h[4 + i];
        if lo_orig == 0 {
            i += 1;
            continue;
        }
        if lo_orig & 0x1 == 1 {
            // I/O BAR: probe, size (16-bit port space), restore.
            write(bus, dev, func, bar_off(i), 0xFFFF_FFFF);
            let mask = read(bus, dev, func, bar_off(i));
            write(bus, dev, func, bar_off(i), lo_orig);
            if let Some(size) = bar_size_from_io_mask(mask) {
                let bar = Bar {
                    slot: i as u8,
                    kind: BarKind::Io,
                    base: u64::from(lo_orig & 0xFFFF_FFFC),
                    size,
                    prefetchable: false,
                };
                d.bars[d.bar_count] = Some(bar);
                d.bar_count += 1;
            }
            i += 1;
        } else {
            let is_64 = (lo_orig >> 1) & 0x3 == 0x2;
            let prefetch = (lo_orig >> 3) & 0x1 == 1;
            if is_64 && i + 1 >= 6 {
                // A 64-bit BAR claiming BAR5 as its high half: malformed.
                i += 1;
                continue;
            }
            if is_64 {
                let hi_orig = h[4 + i + 1];
                write(bus, dev, func, bar_off(i), 0xFFFF_FFFF);
                write(bus, dev, func, bar_off(i + 1), 0xFFFF_FFFF);
                let lo_m = read(bus, dev, func, bar_off(i));
                let hi_m = read(bus, dev, func, bar_off(i + 1));
                write(bus, dev, func, bar_off(i), lo_orig);
                write(bus, dev, func, bar_off(i + 1), hi_orig);
                let mask = (u64::from(lo_m) & 0xFFFF_F000) | (u64::from(hi_m) << 32);
                if let Some(size) = bar_size_from_mem64_mask(mask) {
                    let bar = Bar {
                        slot: i as u8,
                        kind: BarKind::Mem64,
                        base: (u64::from(lo_orig) & 0xFFFF_F000) | (u64::from(hi_orig) << 32),
                        size,
                        prefetchable: prefetch,
                    };
                    d.bars[d.bar_count] = Some(bar);
                    d.bar_count += 1;
                }
                i += 2; // the high half is consumed
            } else {
                write(bus, dev, func, bar_off(i), 0xFFFF_FFFF);
                let mask = read(bus, dev, func, bar_off(i));
                write(bus, dev, func, bar_off(i), lo_orig);
                if let Some(size) = bar_size_from_mem32_mask(mask) {
                    let bar = Bar {
                        slot: i as u8,
                        kind: BarKind::Mem32,
                        base: u64::from(lo_orig & 0xFFFF_F000),
                        size,
                        prefetchable: prefetch,
                    };
                    d.bars[d.bar_count] = Some(bar);
                    d.bar_count += 1;
                }
                i += 1;
            }
        }
    }
}

/// Walk the capability list (offset 0x34): bounded to MAX_CAPS
/// entries and to the first 256 bytes; a malformed pointer just ends
/// the walk (the IDs are diagnostics, not authority).
fn walk_caps(
    read: &mut dyn FnMut(u8, u8, u8, u8) -> u32,
    bus: u8,
    dev: u8,
    func: u8,
    h: &[u32; 16],
    d: &mut PciDev,
) {
    // Only endpoints/bridges with a capabilities pointer (list head
    // must be 0x40..0xFF and dword-aligned).
    let cap_ptr = ((h[13] & 0xFF) as u8) & 0xFC;
    if !(0x40..=0xFC).contains(&cap_ptr) {
        return;
    }
    // NOTE: capability lists are NOT sorted — QEMU's virtio devices
    // walk DOWN (msix @ 0x98 → virtio caps @ 0x40, measured). Loop
    // protection comes from a visited set, not pointer monotonicity.
    let mut seen: [u8; 16] = [0; 16];
    let mut seen_count = 0usize;
    let mut ptr = cap_ptr;
    let mut guard = 0u8;
    while ptr != 0 && d.cap_count < MAX_CAPS && guard < 48 {
        let word = read(bus, dev, func, ptr);
        let id = (word & 0xFF) as u8;
        let next = ((word >> 8) & 0xFF) as u8 & 0xFC;
        d.cap_ids[d.cap_count] = id;
        d.cap_ptrs[d.cap_count] = ptr;
        d.cap_count += 1;
        if seen[..seen_count].contains(&ptr) {
            break; // a real loop: stop walking
        }
        if seen_count < seen.len() {
            seen[seen_count] = ptr;
            seen_count += 1;
        }
        ptr = next;
        guard += 1;
    }
}

/// Does the device carry the virtio vendor capability (0x09)?
#[must_use]
pub fn has_virtio_cap(dev: &PciDev) -> bool {
    dev.cap_ids[..dev.cap_count].contains(&0x09)
}

/// The resolved memory BAR for `slot` (F5: resolve needs the SIZE,
/// not just the base — offset+length is checked against it). None
/// for absent/IO BARs.
#[must_use]
pub fn mem_bar(dev: &PciDev, slot: u8) -> Option<&Bar> {
    dev.bars[..dev.bar_count]
        .iter()
        .flatten()
        .find(|b| b.slot == slot && b.kind != BarKind::Io)
}

pub fn mem_bar_base(dev: &PciDev, slot: u8) -> Option<u64> {
    dev.bars[..dev.bar_count]
        .iter()
        .flatten()
        .find(|b| b.slot == slot && b.kind != BarKind::Io)
        .map(|b| b.base)
}

// ── the kernel-side port accessors (target-only) ──

/// Read one config dword (the virtio cap parser and the virtio driver
/// need raw config reads at arbitrary dword offsets).
#[cfg(not(test))]
pub fn read_cfg32(dev: &PciDev, off: u8) -> u32 {
    // 0xCF8 dword select + 0xCFC dword read (see the module doc for
    // why this width is load-bearing).
    crate::hw::outl(CFG_ADDR_PORT, cfg_addr(dev.bus, dev.dev, dev.func, off));
    crate::hw::inl(CFG_DATA_PORT)
}

/// Write one config dword (0xCF8 select + 0xCFC write).
#[cfg(not(test))]
pub fn write_cfg32(dev: &PciDev, off: u8, v: u32) {
    crate::hw::outl(CFG_ADDR_PORT, cfg_addr(dev.bus, dev.dev, dev.func, off));
    crate::hw::outl(CFG_DATA_PORT, v);
}

/// PCI command-register bits (offset 0x04, the LOW 16 bits — the
/// high half is Status, write-1-to-clear, and must never be echoed).
pub const CMD_IO: u16 = 1 << 0;
pub const CMD_MEM: u16 = 1 << 1;
pub const CMD_BME: u16 = 1 << 2;

/// The 16-bit command value with MEMORY-SPACE + BUS-MASTER set (F9:
/// pure — the host RW1C test drives the write discipline through
/// this, proving the Status half is never touched).
#[must_use]
pub const fn cmd_with_bus_master(cur: u16) -> u16 {
    cur | CMD_MEM | CMD_BME
}

/// The 16-bit command value with MEMORY-SPACE only (the claim order,
/// F9e: MEM before the rings are mapped, BME only after the first
/// successful broker mapping).
#[must_use]
pub const fn cmd_mem_only(cur: u16) -> u16 {
    (cur | CMD_MEM) & !CMD_BME
}

/// The quiesced command value (F9c): IO, MEM and BME all off — the
/// state every endpoint is put into at enumeration, BEFORE the VT-d
/// unit is enabled.
#[must_use]
pub const fn cmd_quiesced(cur: u16) -> u16 {
    cur & !(CMD_IO | CMD_MEM | CMD_BME)
}

/// Clear BUS-MASTER in the command register — the F2 (ADR-0015)
/// poison path cuts the device's DMA at the source. A 16-bit COMMAND
/// write only: the Status half of 0x04 is write-1-to-clear, so a
/// 32-bit read-modify-write would silently eat pending error bits
/// (F9 converts the enable path to the same discipline).
/// The 16-bit command value with BUS-MASTER cleared (F2/F9: the
/// teardown and poison paths).
#[must_use]
pub const fn cmd_without_bus_master(cur: u16) -> u16 {
    cur & !CMD_BME
}

#[cfg(not(test))]
pub fn disable_bus_master(dev: &PciDev) {
    // Dword read is harmless (Status bits are only cleared by WRITES);
    // only the low word ever goes back out.
    let cmd = (read_cfg32(dev, 0x04) & 0xFFFF) as u16;
    crate::hw::outl(CFG_ADDR_PORT, cfg_addr(dev.bus, dev.dev, dev.func, 0x04));
    crate::hw::outw(CFG_DATA_PORT, cmd_without_bus_master(cmd));
}

/// Enable MEMORY-SPACE + BUS-MASTER in the command register (offset
/// 0x04). THE cluster fix: without bit 2 QEMU parks the device's
/// `bus_master_enable_region` disabled — every device DMA read
/// returns zeros with **zero** IOMMU translate or fault events (the
/// device's DMA never reaches the IOMMU at all), which masqueraded
/// as a QEMU attach bug across virtio-net/e1000/xHCI. The "working"
/// devices (virtio-blk/NVMe/AHCI) only worked because SeaBIOS had
/// enabled bus mastering on the devices it probes for boot. A kernel
/// that drives a device claims the bus-master duty itself.
///
/// Reads-modify-writes: I/O-space (bit 0) and INTx-disable (bit 10)
/// keep whatever the BAR probe / firmware left there.
#[cfg(not(test))]
pub fn enable_bus_master(dev: &PciDev) {
    // F9a: a 32-bit read-modify-write of 0x04 writes the STATUS half
    // back too — Status is write-1-to-clear, so pending error bits
    // (parity/abort) were silently eaten. A 16-bit COMMAND write
    // only; the dword READ is harmless.
    let cmd = read_cmd16(dev);
    write_cmd16(dev, cmd_with_bus_master(cmd));
}

/// Enable MEMORY-SPACE only (the F9e claim order: the device's
/// registers are reachable for bring-up, but it cannot DMA until the
/// broker has mapped the rings and the caller grants bus mastering).
#[cfg(not(test))]
pub fn enable_mem(dev: &PciDev) {
    let cmd = read_cmd16(dev);
    write_cmd16(dev, cmd_mem_only(cmd));
}

/// Read the 16-bit COMMAND register (the low half of 0x04).
#[cfg(not(test))]
fn read_cmd16(dev: &PciDev) -> u16 {
    (read_cfg32(dev, 0x04) & 0xFFFF) as u16
}

/// Write the 16-bit COMMAND register — never the Status half.
#[cfg(not(test))]
fn write_cmd16(dev: &PciDev, v: u16) {
    crate::hw::outl(CFG_ADDR_PORT, cfg_addr(dev.bus, dev.dev, dev.func, 0x04));
    crate::hw::outw(CFG_DATA_PORT, v);
}

/// F9c: put EVERY endpoint on bus 0 into the quiesced state (IO, MEM
/// and BME off) — run at enumeration, BEFORE the VT-d unit is
/// enabled, so no device decodes or DMAs while the IOMMU's own tables
/// are being built. BAR sizing later in the scan also runs with
/// decoding disabled (F9d: the probe writes all-ones into BAR
/// registers; a decoding device would answer those addresses).
/// Returns how many endpoints were quiesced.
#[cfg(not(test))]
pub fn quiesce_all() -> usize {
    let inv = enumerate_bus0();
    let mut n = 0usize;
    for d in &inv.devices[..inv.count] {
        if is_endpoint_header(d.header) {
            let cmd = read_cmd16(d);
            write_cmd16(d, cmd_quiesced(cmd));
            n += 1;
        }
    }
    n
}

#[cfg(not(test))]
mod ports {
    /// Latch the CF8 address (one dword write — see the module doc
    /// for why byte-wise composition is unsound on q35).
    fn select(bus: u8, dev: u8, func: u8, off: u8) {
        crate::hw::outl(super::CFG_ADDR_PORT, super::cfg_addr(bus, dev, func, off));
    }

    pub fn read32(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
        select(bus, dev, func, off);
        crate::hw::inl(super::CFG_DATA_PORT)
    }

    pub fn write32(bus: u8, dev: u8, func: u8, off: u8, v: u32) {
        select(bus, dev, func, off);
        crate::hw::outl(super::CFG_DATA_PORT, v);
    }
}

/// Enumerate bus 0 through the real CF8/CFC ports (target-only).
#[cfg(not(test))]
pub fn enumerate_bus0() -> Inventory {
    enumerate(&mut ports::read32, &mut ports::write32)
}

// ── ADR-0020: the config-space access seam (legacy ports vs ECAM) ────

/// The ECAM address of one config dword: base + (bus−start)<<20 |
/// dev<<15 | fn<<12 | off — checked arithmetic throughout; None on any
/// bound or overflow (a wrong address must refuse, never fault).
#[must_use]
pub fn ecam_addr(base: u64, start_bus: u8, bus: u8, dev: u8, func: u8, off: u8) -> Option<u64> {
    if dev >= 32 || func >= 8 {
        return None;
    }
    // The bus must sit at or after the window's start; the window's
    // END is the caller's bound (CfgAccess::resolve checks end_bus —
    // a u8 spread can never exceed it, and the old `> 255` arm here
    // was a tautology the compiler flagged).
    if bus < start_bus {
        return None;
    }
    let rel = u64::from(bus.wrapping_sub(start_bus));
    base.checked_add(rel << 20)?
        .checked_add(u64::from(dev) << 15)?
        .checked_add(u64::from(func) << 12)?
        .checked_add(u64::from(off & !0x3))
}

/// The config-space access seam: the legacy 0xCF8/0xCFC port pair
/// (every PC; bus field rides the address word) or the MCFG's ECAM
/// window (the UEFI-only servers where CF8 stops existing). The walk
/// and every driver are GENERIC over the seam — the lane prints which
/// one the machine offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgAccess {
    /// Ports 0xCF8/0xCFC.
    LegacyPorts,
    /// The MCFG ECAM window for [start_bus, end_bus] at `base`.
    Ecam {
        base: u64,
        start_bus: u8,
        end_bus: u8,
    },
}

impl CfgAccess {
    /// The window bounds this access answers for (informational: the
    /// address math is bounds-checked per access).
    #[must_use]
    pub fn bus_window(&self) -> (u8, u8) {
        match *self {
            CfgAccess::LegacyPorts => (0, 255),
            CfgAccess::Ecam {
                start_bus, end_bus, ..
            } => (start_bus, end_bus),
        }
    }

    /// Resolve one config dword's address through the seam — the
    /// pure half, host-tested; the target halves wrap it below.
    #[must_use]
    pub fn resolve(&self, bus: u8, dev: u8, func: u8, off: u8) -> Option<u64> {
        match *self {
            CfgAccess::LegacyPorts => {
                if dev >= 32 || func >= 8 {
                    return None;
                }
                Some(u64::from(cfg_addr(bus, dev, func, off)))
            }
            CfgAccess::Ecam {
                base,
                start_bus,
                end_bus,
            } => {
                if bus < start_bus || bus > end_bus {
                    return None;
                }
                ecam_addr(base, start_bus, bus, dev, func, off)
            }
        }
    }
}

#[cfg(not(test))]
impl CfgAccess {
    /// Read one config dword through the seam (target).
    pub fn read32(&self, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
        match self.resolve(bus, dev, func, off) {
            // ECAM: the dword sits at the resolved PA (direct map);
            // out-of-window refusals read as the absent pattern.
            Some(pa) if matches!(self, CfgAccess::Ecam { .. }) => crate::memops::read_u32(pa),
            _ => ports::read32(bus, dev, func, off),
        }
    }

    /// Write one config dword through the seam (target).
    pub fn write32(&self, bus: u8, dev: u8, func: u8, off: u8, v: u32) {
        match self.resolve(bus, dev, func, off) {
            Some(pa) if matches!(self, CfgAccess::Ecam { .. }) => crate::memops::write_u32(pa, v),
            _ => ports::write32(bus, dev, func, off, v),
        }
    }
}

// ── ADR-0020: the recursive bridge walk ──────────────────────────────

/// The walk's loop/depth guards: a visited-bus set (a bridge pointing
/// at an already-walked bus is a topology loop — recorded, not
/// followed) and a depth cap (bridges chained deeper than any real
/// machine are malformed firmware).
pub const MAX_WALK_DEPTH: u8 = 8;

/// The type-1 header dword at 0x18: primary(0x18) secondary(0x19)
/// subordinate(0x1A) — the decode for the walk.
#[must_use]
pub const fn bridge_buses(word18: u32) -> (u8, u8, u8) {
    (
        (word18 & 0xFF) as u8,
        ((word18 >> 8) & 0xFF) as u8,
        ((word18 >> 16) & 0xFF) as u8,
    )
}

/// Enumerate from `root_bus` THROUGH bridges: every type-1 header's
/// secondary bus is walked recursively (bounded by the visited set and
/// [`MAX_WALK_DEPTH`]). Devices behind bridges land in the same
/// inventory with their real bus numbers — and the claim gate treats
/// them like any other endpoint (ADR-0020 lifts the old bus-0-only
/// refusal).
pub fn enumerate_multi(
    read: &mut dyn FnMut(u8, u8, u8, u8) -> u32,
    write: &mut dyn FnMut(u8, u8, u8, u8, u32),
    root_bus: u8,
) -> Inventory {
    let mut inv = Inventory::empty();
    let mut visited = [false; 256];
    walk_bus(read, write, root_bus, 0, &mut visited, &mut inv);
    inv
}

/// One bus's sweep + the bridge recursion. The per-device work is the
/// same shape as `enumerate`'s body (header, BARs, caps); the bridge
/// branch reads secondary/subordinate from the type-1 header and
/// recurses.
fn walk_bus(
    read: &mut dyn FnMut(u8, u8, u8, u8) -> u32,
    write: &mut dyn FnMut(u8, u8, u8, u8, u32),
    bus: u8,
    depth: u8,
    visited: &mut [bool; 256],
    inv: &mut Inventory,
) {
    if depth > MAX_WALK_DEPTH || visited[bus as usize] {
        return; // a loop or a too-deep chain: stop, loudly enough
                // (the count shows the cap, not a hang)
    }
    visited[bus as usize] = true;
    for dev in 0u8..32 {
        let mut h = [0u32; 16];
        if !read_header(read, bus, dev, 0, &mut h) {
            continue;
        }
        let multifn = is_multifunction(&h);
        let funcs: u8 = if multifn { 8 } else { 1 };
        for func in 0u8..funcs {
            if !read_header(read, bus, dev, func, &mut h) {
                continue;
            }
            if inv.count == MAX_PCI_DEVICES {
                return; // the inventory is full: honest cap
            }
            let mut d = EMPTY_DEV;
            d.bus = bus;
            d.dev = dev;
            d.func = func;
            d.vendor = vendor_id(&h);
            d.device = device_id(&h);
            d.class = class_code(&h);
            d.header = header_type(&h);
            size_bars(read, write, bus, dev, func, &mut h, &mut d);
            walk_caps(read, bus, dev, func, &h, &mut d);
            inv.devices[inv.count] = d;
            inv.count += 1;
            // A PCI-to-PCI bridge (type-1 header): walk its secondary
            // bus. CardBus (type-2) stays out of scope. The visited
            // set catches self/ancestor loops; sec 0 is unprogrammed
            // firmware noise (bus 0 is always already visited).
            if d.header & 0x7F == 1 {
                let (_p, sec, _sub) = bridge_buses(read(bus, dev, func, 0x18));
                if sec != 0 {
                    walk_bus(read, write, sec, depth + 1, visited, inv);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round I: `set_dom_dev` is the id-matched claim recording — the
    /// virtio rng/console/balloon devices share ambiguous class codes,
    /// so their domains are recorded by vendor+device id. The right
    /// record moves, distractors do not, and a miss is a clean false.
    #[test]
    fn set_dom_dev_matches_by_vendor_and_device_id() {
        let mk = |vendor: u16, device: u16, dom: u32| PciDev {
            bus: 0,
            dev: 1,
            func: 0,
            vendor,
            device,
            class: 0xFF00,
            header: 0,
            bars: [None; 6],
            dom,
            bar_count: 0,
            cap_ids: [0; MAX_CAPS],
            cap_ptrs: [0; MAX_CAPS],
            cap_count: 0,
        };
        let mut inv = Inventory::empty();
        // A virtio-rng (modern 0x1044) beside same-vendor distractors.
        inv.devices[0] = mk(0x1AF4, 0x1044, 0);
        inv.devices[1] = mk(0x1AF4, 0x1042, 0); // virtio-blk
        inv.devices[2] = mk(0x8086, 0x1044, 0); // wrong vendor, same id
        inv.count = 3;
        assert!(inv.set_dom_dev(0x1AF4, 0x1044, 7));
        assert_eq!(inv.devices[0].dom, 7, "the rng record takes the domain");
        assert_eq!(inv.devices[1].dom, 0, "the blk distractor is untouched");
        assert_eq!(
            inv.devices[2].dom, 0,
            "the wrong-vendor record is untouched"
        );
        // A clean miss changes nothing and reports false.
        assert!(!inv.set_dom_dev(0x1AF4, 0x9999, 9));
        assert_eq!(inv.devices[0].dom, 7);
    }

    /// F9 (review round 4): the command-register discipline, modeled.
    /// The Status half of 0x04 is write-1-to-clear — the OLD 32-bit
    /// read-modify-write of the enable path wrote Status back and
    /// silently ATE pending error bits (proven by the model below).
    /// The new 16-bit writes never touch it, and the claim/teardown
    /// ORDER is pinned: quiesced -> MEM (before any ring is mapped)
    /// -> BME (only after the broker mapped the rings) -> BME off at
    /// teardown.
    #[test]
    fn command_writes_never_touch_rw1c_status_and_order_is_pinned() {
        let cmd: u16 = CMD_IO | CMD_MEM | CMD_BME; // SeaBIOS leftovers
        let status: u16 = 0x0008; // a pending parity-error bit (RW1C)

        // The OLD form, modeled: a 32-bit RMW writes the Status word
        // back; every set bit it echoes is CLEARED by RW1C semantics.
        let old_rmw32 = u32::from(cmd) | (u32::from(status) << 16) | 0x6;
        let status_after_old = status & !(old_rmw32 >> 16) as u16;
        assert_eq!(
            status_after_old, 0,
            "the old 32-bit RMW ate the pending error bit"
        );

        // The new discipline: quiesce -> MEM -> BME -> disable (the
        // write log is the sequence itself — 16-bit values only).
        let writes = [
            super::cmd_quiesced(cmd),
            super::cmd_mem_only(super::cmd_quiesced(cmd)),
            super::cmd_with_bus_master(super::cmd_mem_only(super::cmd_quiesced(cmd))),
            super::cmd_without_bus_master(super::cmd_with_bus_master(super::cmd_mem_only(
                super::cmd_quiesced(cmd),
            ))),
        ];
        // The pending error bit was never written: it survives.
        // (The model's status is only touched by 32-bit writes.)
        assert_eq!(status, 0x0008, "16-bit writes never reach Status");
        // The order, pinned.
        assert_eq!(writes.len(), 4);
        assert_eq!(
            writes[0] & (super::CMD_IO | super::CMD_MEM | super::CMD_BME),
            0,
            "enumeration quiesces decode + DMA"
        );
        assert_eq!(
            writes[1] & super::CMD_BME,
            0,
            "MEM before the rings exist: no BME"
        );
        assert_eq!(
            writes[1] & super::CMD_MEM,
            super::CMD_MEM,
            "registers reachable"
        );
        assert_eq!(
            writes[2] & super::CMD_BME,
            super::CMD_BME,
            "BME only after the broker mapped the rings"
        );
        assert_eq!(writes[3] & super::CMD_BME, 0, "teardown clears BME");
        assert_eq!(
            writes[3] & super::CMD_MEM,
            super::CMD_MEM,
            "MEM stays until unquiesce"
        );
    }

    /// A fake PCI bus: one 64-byte config image per (dev, fn) plus
    /// BAR-probe semantics — an all-ones write arms the probe, the
    /// next read of that BAR returns the size mask, a restore write
    /// disarms it. Exactly what real hardware does.
    struct FakeBus {
        cfg: Vec<[u32; 64]>,
        mask: [u64; 256], // size mask per (dev*8+fn), if any BAR
        mask_is64: [bool; 256],
        probing: [bool; 256],
        restores: usize,
        caps: Vec<(usize, u8, u32)>,
    }

    impl FakeBus {
        fn new() -> Self {
            // Absent functions read vendor 0xFFFF (dword0 all ones).
            FakeBus {
                cfg: vec![[0xFFFF_FFFFu32; 64]; 32 * 8],
                mask: [0; 256],
                mask_is64: [false; 256],
                probing: [false; 256],
                restores: 0,
                caps: vec![],
            }
        }

        fn idx(dev: u8, func: u8) -> usize {
            dev as usize * 8 + func as usize
        }

        /// Plant a type-0 function (a real device's unimplemented BARs
        /// and the command register read as zero, not all-ones).
        fn plant(&mut self, dev: u8, func: u8, vendor: u16, device: u16, class: u16) {
            let idx = Self::idx(dev, func);
            let h = &mut self.cfg[idx];
            *h = [0u32; 64];
            h[0] = (u32::from(device) << 16) | u32::from(vendor);
            h[2] = u32::from(class) << 16;
            h[3] = 0; // header type 0, single-function
        }

        /// Plant a 64-bit memory BAR pair at slot `bar_i`.
        fn plant_bar64(&mut self, dev: u8, func: u8, bar_i: usize, base: u64, size: u64) {
            let idx = Self::idx(dev, func);
            let h = &mut self.cfg[idx];
            h[4 + bar_i] = ((base as u32) & 0xFFFF_F000) | 0x4; // mem, 64-bit
            h[4 + bar_i + 1] = (base >> 32) as u32;
            self.mask[idx] = if size & 0xFFFF_FFFF == size {
                u64::from(!(size as u32 - 1))
            } else {
                !(size - 1)
            };
            self.mask_is64[idx] = true;
        }

        /// Plant a 32-bit memory BAR at slot `bar_i`.
        fn plant_bar32(&mut self, dev: u8, func: u8, bar_i: usize, base: u32, size: u32) {
            let idx = Self::idx(dev, func);
            self.cfg[idx][4 + bar_i] = (base & 0xFFFF_F000) | 0x0; // mem, 32-bit
            self.mask[idx] = u64::from(!(size - 1));
            self.mask_is64[idx] = false;
        }

        /// Plant a capability list: header dword 13 (offset 0x34)
        /// carries the first pointer; entry i reads (next<<8)|id at
        /// the offset the PREVIOUS entry points at (the real linked
        /// list, not consecutive dwords).
        fn plant_caps(&mut self, dev: u8, func: u8, first: u8, list: &[(u8, u8)]) {
            let idx = Self::idx(dev, func);
            self.cfg[idx][13] = u32::from(first); // at offset 0x34
            let mut ptr = first;
            for &(next, id) in list {
                self.caps
                    .push((idx, ptr, (u32::from(next) << 8) | u32::from(id)));
                ptr = next;
            }
        }

        fn read(&mut self, _bus: u8, dev: u8, func: u8, off: u8) -> u32 {
            let idx = Self::idx(dev, func);
            if self.probing[idx] {
                let m = self.mask[idx];
                let slot = ((off as usize) - 0x10) / 4;
                if self.mask_is64[idx] {
                    if slot % 2 == 0 {
                        (m as u32) & 0xFFFF_F000 | 0x4
                    } else {
                        (m >> 32) as u32
                    }
                } else {
                    (m as u32) & 0xFFFF_F000
                }
            } else if let Some(&(_, _, word)) =
                self.caps.iter().find(|(i, o, _)| *i == idx && *o == off)
            {
                word
            } else {
                self.cfg[idx][(off / 4) as usize]
            }
        }

        fn write(&mut self, _bus: u8, dev: u8, func: u8, _off: u8, v: u32) {
            let idx = Self::idx(dev, func);
            if v == 0xFFFF_FFFF {
                self.probing[idx] = true;
            } else {
                self.probing[idx] = false;
                self.restores += 1;
            }
        }
    }

    #[test]
    fn cfg_addr_is_the_spec_encoding() {
        assert_eq!(cfg_addr(0, 0, 0, 0), 0x8000_0000);
        assert_eq!(cfg_addr(0, 0x03, 0, 0x10), 0x8000_1810);
        assert_eq!(cfg_addr(0, 0x1F, 2, 0x34), 0x8000_FA34);
        assert_eq!(cfg_addr(2, 1, 7, 0xFC), 0x8002_0FFC);
        // The register field is dword-aligned by force.
        assert_eq!(cfg_addr(0, 0, 0, 0x13) & 0x3, 0);
        // Every byte lane decodes back.
        let a = cfg_addr(1, 2, 3, 0x40);
        assert_eq!(((a >> 16) & 0xFF) as u8, 1);
        assert_eq!(((a >> 11) & 0x1F) as u8, 2);
        assert_eq!(((a >> 8) & 0x7) as u8, 3);
        assert_eq!((a & 0xFC) as u8, 0x40);
    }

    #[test]
    fn header_decode_is_pinned() {
        let mut h = [0u32; 16];
        h[0] = (0x1042 << 16) | 0x1AF4; // virtio-blk modern
        h[2] = (0x0100 << 16) | 0x0002; // mass storage / rev 2
        h[3] = 0x0080_0000; // header type 0, multifunction bit
        assert_eq!(vendor_id(&h), 0x1AF4);
        assert_eq!(device_id(&h), 0x1042);
        assert_eq!(class_code(&h), 0x0100);
        assert_eq!(header_type(&h), 0x80);
        assert!(is_multifunction(&h));
        assert!(is_endpoint(&h));
        assert_eq!(describe(0x1AF4, 0x1042), "virtio-blk");
        assert_eq!(describe(0x1AF4, 0x1050), "virtio (other)");
        assert_eq!(describe(0x8086, 0x29C0), "?");
    }

    #[test]
    fn bar_size_math_is_pinned() {
        // 32-bit BARs: the complement stays in 32-bit space (a 4 KiB
        // BAR reads back 0xFFFF_F000; an 8 MiB one 0xFFE0_0000).
        assert_eq!(bar_size_from_mem32_mask(0xFFFF_F000), Some(0x1000));
        assert_eq!(bar_size_from_mem32_mask(0xFFE0_0000), Some(0x20_0000));
        assert_eq!(bar_size_from_mem32_mask(0), None);
        assert_eq!(bar_size_from_mem32_mask(0xFFFF_FFFF), None);
        // 64-bit BARs: a 1 GiB BAR clears bits 22.. of the full span;
        // a 4 KiB 64-bit BAR clears only the low 12 (hi word reads 0).
        assert_eq!(
            bar_size_from_mem64_mask(0xFFFF_FFFF_C000_0000),
            Some(0x4000_0000)
        );
        assert_eq!(
            bar_size_from_mem64_mask(0x0000_0000_FFFF_F000),
            Some(0x1000)
        );
        assert_eq!(bar_size_from_mem64_mask(0), None);
        assert_eq!(bar_size_from_mem64_mask(0xFFFF_FFFF_FFFF_FFFF), None);
        // Hi word all-ones = nothing addressable up there = not a BAR.
        // A 4 KiB BAR that decodes the full upper word (legal per spec).
        assert_eq!(
            bar_size_from_mem64_mask(0xFFFF_FFFF_FFFF_F000),
            Some(0x1000)
        );
        // I/O BAR: 16-byte port region.
        assert_eq!(bar_size_from_io_mask(0xFFFF_FFF0), Some(0x10));
        // 0xFFFF_FFFC: only bits 0..1 hardwired — a minimal 4-byte I/O region.
        assert_eq!(bar_size_from_io_mask(0xFFFF_FFFC), Some(4));
    }

    #[test]
    fn claim_gate_refuses_every_wrong_shape() {
        let mut d = EMPTY_DEV;
        d.header = 0x00; // endpoint
        d.class = 0x0100; // mass storage
        let ok = DmaVerdict::Available {
            haw_bits: 48,
            queued_invalidation: true,
        };
        assert!(check_claim(&d, ok, false).is_ok());
        d.header = 0x01; // bridge header
        assert_eq!(check_claim(&d, ok, false), Err(ClaimError::NotEndpoint));
        d.header = 0x00;
        d.class = 0x0600; // host bridge class
        assert_eq!(check_claim(&d, ok, false), Err(ClaimError::BridgeClass));
        d.class = 0x0100;
        let absent = DmaVerdict::Absent {
            reason: aegis_os::dma::DmaAbsentReason::NoDmar,
        };
        assert_eq!(check_claim(&d, absent, false), Err(ClaimError::NoIommu));
        assert_eq!(check_claim(&d, ok, true), Err(ClaimError::RmrrCovered));
    }

    #[test]
    fn walk_caps_stops_on_malformed_lists() {
        // A cap list that loops (next <= ptr) must terminate: the
        // walker's no-forward-progress rule.
        let mut d = EMPTY_DEV;
        let mut h = [0u32; 16];
        h[13] = 0x60; // cap pointer at 0x34
        let mut reads = 0u32;
        walk_caps(
            &mut |_bus, _dev, _func, _off| {
                reads += 1;
                0x0000_6009 // id 0x09 (virtio), next = 0x60 (no progress)
            },
            0,
            0,
            0,
            &h,
            &mut d,
        );
        // The same word forever: the visited-set protection records
        // the entry once more on its second visit, then stops.
        assert!(d.cap_count <= 2, "looping list must not spin");
        assert_eq!(d.cap_ids[0], 0x09);
        assert!(has_virtio_cap(&d));
        assert!(reads <= 3, "looping list must not spin");
    }

    #[test]
    fn enumerate_finds_sizes_and_caps_through_the_fake_bus() {
        let mut bus = FakeBus::new();
        bus.plant(0x03, 0, 0x1AF4, 0x1042, 0x0100); // virtio-blk modern
        bus.plant_bar64(0x03, 0, 0, 0xFE00_0000, 0x1000); // BAR0: 4 KiB MMIO64
        bus.plant_caps(0x03, 0, 0x40, &[(0x50, 0x11), (0x00, 0x09)]); // MSI-X then virtio
        bus.plant(0x00, 0, 0x8086, 0x29C0, 0x0600); // host bridge (no BARs)
        let b = core::cell::RefCell::new(bus);
        let inv = enumerate(
            &mut |bus_, d_, f_, o_| b.borrow_mut().read(bus_, d_, f_, o_),
            &mut |bus_, d_, f_, o_, v_| b.borrow_mut().write(bus_, d_, f_, o_, v_),
        );
        assert_eq!(inv.count, 2);
        let vblk = inv
            .find_by(0x1AF4, 0x01)
            .expect("virtio-blk found by vendor+class");
        assert_eq!((vblk.dev, vblk.func), (0x03, 0));
        assert_eq!(vblk.class, 0x0100);
        assert_eq!(vblk.bar_count, 1);
        let bar = vblk.bars[0].expect("BAR0 sized");
        assert_eq!(bar.kind, BarKind::Mem64);
        assert_eq!(bar.base, 0xFE00_0000);
        assert_eq!(bar.size, 0x1000);
        assert_eq!(vblk.cap_count, 2);
        assert_eq!(vblk.cap_ids[0], 0x11, "MSI-X first");
        assert_eq!(vblk.cap_ptrs[0], 0x40);
        assert_eq!(vblk.cap_ids[1], 0x09, "virtio vendor cap");
        assert!(has_virtio_cap(vblk));
        // The probe wrote all-ones and restored twice (lo + hi).
        assert_eq!(
            b.borrow().restores,
            2,
            "the 64-bit BAR.s two words were restored"
        );
        // The host bridge: present, no bars, not claimable.
        let host = &inv.devices[0];
        assert_eq!((host.dev, host.vendor), (0x00, 0x8086));
        assert_eq!(host.bar_count, 0);
        assert_eq!(
            check_claim(
                host,
                DmaVerdict::Available {
                    haw_bits: 48,
                    queued_invalidation: true
                },
                false
            ),
            Err(ClaimError::BridgeClass)
        );
    }

    #[test]
    fn enumerate_skips_absent_functions_and_honors_multifunction() {
        let mut b = FakeBus::new();
        b.plant(0x05, 0, 0x8086, 0x2922, 0x0106); // AHCI at 05.0
        b.plant(0x05, 1, 0x8086, 0x2922, 0x0106); // second fn
        b.cfg[FakeBus::idx(0x05, 0)][3] = 0x0080_0000; // multifunction bit
        let b = core::cell::RefCell::new(b);
        let inv = enumerate(
            &mut |bus_, d_, f_, o_| b.borrow_mut().read(bus_, d_, f_, o_),
            &mut |bus_, d_, f_, o_, v_| b.borrow_mut().write(bus_, d_, f_, o_, v_),
        );
        assert_eq!(inv.count, 2, "function 1 enumerated via the MF bit");
        assert_eq!(inv.devices[0].func, 0);
        assert_eq!(inv.devices[1].func, 1);
        // A single-function device's fn 1..8 are never touched.
        let mut b2 = FakeBus::new();
        b2.plant(0x03, 0, 0x1AF4, 0x1042, 0x0100);
        let b2 = core::cell::RefCell::new(b2);
        let inv2 = enumerate(
            &mut |bus_, d_, f_, o_| b2.borrow_mut().read(bus_, d_, f_, o_),
            &mut |bus_, d_, f_, o_, v_| b2.borrow_mut().write(bus_, d_, f_, o_, v_),
        );
        assert_eq!(inv2.count, 1);
    }

    #[test]
    fn fuzz_random_config_images_never_panic() {
        // Random 16-dword headers through the decoders: typed results,
        // never panics — the checklist's config-header fuzz item.
        let mut state = 0x0C0F_FEE0u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..4096 {
            let mut h = [0u32; 16];
            for w in h.iter_mut() {
                *w = (next() & 0xFFFF_FFFF) as u32;
            }
            let _ = vendor_id(&h);
            let _ = device_id(&h);
            let _ = class_code(&h);
            let _ = header_type(&h);
            let _ = is_multifunction(&h);
            let _ = is_endpoint(&h);
            let _ = describe(vendor_id(&h), device_id(&h));
        }
    }
}

#[cfg(test)]
mod walk_tests {
    use super::*;

    /// The ECAM address math, pinned: bus<<20 | dev<<15 | fn<<12 |
    /// off, relative to the window's start bus, with every bound and
    /// overflow refusing.
    #[test]
    fn ecam_addr_is_pinned_and_bounds_checked() {
        // The canonical q35 window: base 0xE000_0000, bus 0..255.
        let b = 0xE000_0000u64;
        assert_eq!(ecam_addr(b, 0, 0, 0, 0, 0x00), Some(b));
        assert_eq!(ecam_addr(b, 0, 0, 0, 0, 0x40), Some(b + 0x40));
        // dev rides bit 15, func bit 12.
        assert_eq!(ecam_addr(b, 0, 0, 1, 0, 0x00), Some(b + (1 << 15)));
        assert_eq!(ecam_addr(b, 0, 0, 0, 1, 0x00), Some(b + (1 << 12)));
        assert_eq!(ecam_addr(b, 0, 0, 31, 0, 0x00), Some(b + (31 << 15)));
        assert_eq!(ecam_addr(b, 0, 1, 0, 0, 0x00), Some(b + (1 << 20)));
        assert_eq!(
            ecam_addr(b, 0, 255, 0, 0, 0xFC),
            Some(b + (255 << 20) + 0xFC)
        );
        // A window starting at bus 1: the offset is RELATIVE.
        assert_eq!(ecam_addr(b, 1, 1, 0, 0, 0), Some(b));
        assert_eq!(ecam_addr(b, 1, 2, 0, 0, 0), Some(b + (1 << 20)));
        // The dword alignment mask: low bits are cleared, not trusted.
        assert_eq!(ecam_addr(b, 0, 0, 0, 0, 0x43), Some(b + 0x40));
        // Bounds: dev 32, fn 8, bus below the window.
        assert_eq!(ecam_addr(b, 0, 0, 32, 0, 0), None);
        assert_eq!(ecam_addr(b, 0, 0, 0, 8, 0), None);
        assert_eq!(ecam_addr(b, 5, 4, 0, 0, 0), None, "bus below start");
        // Overflow: a base near the top of memory.
        assert_eq!(ecam_addr(u64::MAX - 0x1000, 0, 255, 0, 0, 0), None);
    }

    /// The access seam resolves both halves: the port address word for
    /// legacy, the ECAM window for MCFG machines — and out-of-window
    /// buses refuse on the ECAM side.
    #[test]
    fn cfg_access_resolves_both_seams() {
        let legacy = CfgAccess::LegacyPorts;
        assert_eq!(
            legacy.resolve(0, 0, 0, 0x40),
            Some(u64::from(cfg_addr(0, 0, 0, 0x40)))
        );
        // Legacy covers every bus (the bus rides the address word).
        assert!(legacy.resolve(255, 31, 7, 0xFC).is_some());
        assert_eq!(legacy.resolve(0, 32, 0, 0), None, "dev bound");
        assert_eq!(legacy.bus_window(), (0, 255));

        let ecam = CfgAccess::Ecam {
            base: 0xE000_0000,
            start_bus: 0,
            end_bus: 255,
        };
        assert_eq!(ecam.bus_window(), (0, 255));
        assert_eq!(ecam.resolve(0, 0, 0, 0x40), Some(0xE000_0040));
        assert_eq!(ecam.resolve(1, 0, 0, 0), Some(0xE010_0000));
        // A narrow MCFG window: outside refuses.
        let narrow = CfgAccess::Ecam {
            base: 0xE000_0000,
            start_bus: 0,
            end_bus: 15,
        };
        assert!(narrow.resolve(15, 0, 0, 0).is_some());
        assert_eq!(narrow.resolve(16, 0, 0, 0), None, "bus above the window");
    }

    /// The type-1 dword decode: primary, secondary, subordinate.
    #[test]
    fn bridge_buses_decode_the_type1_dword() {
        // primary=0, secondary=1, subordinate=1 (a root port with one
        // device behind it).
        assert_eq!(bridge_buses(0x0001_0100), (0, 1, 1));
        assert_eq!(bridge_buses(0x0003_0200), (0, 2, 3));
        assert_eq!(bridge_buses(0xFFFF_FFFF), (0xFF, 0xFF, 0xFF));
        assert_eq!(bridge_buses(0), (0, 0, 0));
    }

    /// A fake config space for the walk tests. The dwords the walk
    /// reads: 0x00 vendor/device, 0x08 class, 0x0C header type, 0x10
    /// BAR0, 0x18 the type-1 bridge buses.
    struct FakeCfg {
        devices: [((u8, u8), (u16, u16, u16, u8, u32)); 20],
        bridges: [(u8, u8, u32); 20],
    }

    impl FakeCfg {
        const EMPTY: FakeCfg = FakeCfg {
            devices: [((0, 0), (0, 0, 0, 0, 0)); 20],
            bridges: [(0, 0, 0); 20],
        };

        fn with(
            devices: [((u8, u8), (u16, u16, u16, u8, u32)); 20],
            bridges: [(u8, u8, u32); 20],
        ) -> FakeCfg {
            FakeCfg { devices, bridges }
        }

        fn read(&self, bus: u8, dev: u8, off: u8) -> u32 {
            match off {
                0x00 => match self.devices.iter().find(|(k, _)| k.0 == bus && k.1 == dev) {
                    Some((_, (v, d, _, _, _))) => u32::from(*v) | (u32::from(*d) << 16),
                    None => 0xFFFF_FFFF,
                },
                0x08 => match self.devices.iter().find(|(k, _)| k.0 == bus && k.1 == dev) {
                    Some((_, (_, _, c, _, _))) => u32::from(*c) << 16,
                    None => 0xFFFF_FFFF,
                },
                0x0C => match self.devices.iter().find(|(k, _)| k.0 == bus && k.1 == dev) {
                    Some((_, (_, _, _, t, _))) => u32::from(*t) << 16,
                    None => 0xFFFF_FFFF,
                },
                0x10 => match self.devices.iter().find(|(k, _)| k.0 == bus && k.1 == dev) {
                    Some((_, (_, _, _, _, b0))) => *b0,
                    None => 0,
                },
                0x18 => match self.bridges.iter().find(|(b, d, _)| *b == bus && *d == dev) {
                    Some((_, _, w)) => *w,
                    None => 0,
                },
                _ => 0,
            }
        }
    }

    /// The walk finds devices behind a bridge: the root port on bus 0
    /// names bus 1, and the endpoint there lands in the inventory with
    /// its REAL bus number.
    #[test]
    fn the_walk_traverses_a_bridge_and_records_the_real_bus() {
        let mut devices = [((0u8, 0u8), (0u16, 0u16, 0u16, 0u8, 0u32)); 20];
        let mut bridges = [(0u8, 0u8, 0u32); 20];
        devices[0] = ((0, 0), (0x8086, 0x1237, 0x0600, 0x00, 0)); // host bridge
        devices[1] = ((0, 20), (0x8086, 0x3420, 0x0604, 0x01, 0)); // root port
        devices[2] = ((1, 0), (0x1AF4, 0x1042, 0x0180, 0x00, 0)); // virtio-blk behind it
        bridges[0] = (0, 20, 0x0001_0100);
        let cfg = FakeCfg::with(devices, bridges);
        let mut read = |b: u8, d: u8, _f: u8, o: u8| cfg.read(b, d, o);
        let mut write = |_b: u8, _d: u8, _f: u8, _o: u8, _v: u32| {};
        let inv = enumerate_multi(&mut read, &mut write, 0);
        assert_eq!(inv.count, 3, "host bridge + root port + the bus-1 endpoint");
        let behind = inv.devices[..inv.count]
            .iter()
            .find(|d| d.vendor == 0x1AF4)
            .expect("the device behind the root port is in the inventory");
        assert_eq!((behind.bus, behind.dev, behind.func), (1, 0, 0));
    }

    /// A self-pointing bridge (secondary == its own bus) is a loop:
    /// the visited set stops it, the walk still finishes.
    #[test]
    fn a_self_pointing_bridge_loop_is_stopped_by_the_visited_set() {
        let mut devices = [((0u8, 0u8), (0u16, 0u16, 0u16, 0u8, 0u32)); 20];
        let mut bridges = [(0u8, 0u8, 0u32); 20];
        devices[0] = ((0, 0), (0x8086, 0x1237, 0x0600, 0x00, 0));
        devices[1] = ((0, 5), (0x8086, 0x0999, 0x0604, 0x01, 0)); // a lying bridge
        bridges[0] = (0, 5, 0x0005_0500); // secondary = its own bus 5
        let cfg = FakeCfg::with(devices, bridges);
        let mut read = |b: u8, d: u8, _f: u8, o: u8| cfg.read(b, d, o);
        let mut write = |_b: u8, _d: u8, _f: u8, _o: u8, _v: u32| {};
        let inv = enumerate_multi(&mut read, &mut write, 0);
        assert_eq!(inv.count, 2, "no hang, no duplicated sweep");
    }

    /// A bridge chain deeper than MAX_WALK_DEPTH stops at the cap: the
    /// endpoint living 12 bridges down must NOT be recorded, and the
    /// walk still finishes every shallower bus.
    #[test]
    fn a_too_deep_bridge_chain_stops_at_the_depth_cap() {
        let mut devices = [((0u8, 0u8), (0u16, 0u16, 0u16, 0u8, 0u32)); 20];
        let mut bridges = [(0u8, 0u8, 0u32); 20];
        devices[0] = ((0, 0), (0x8086, 0x1237, 0x0600, 0x00, 0));
        // Bridge i sits at (bus i, dev 2) and names bus i+1; the
        // endpoint sits on bus 12, i.e. 12 levels below bus 0 — past
        // the 8-deep cap.
        for i in 0u8..12 {
            devices[(i + 1) as usize] = ((i, 2), (0x8086, 0x0B01, 0x0604, 0x01, 0));
            // primary 0, secondary i+1, subordinate 12.
            bridges[i as usize] = (i, 2, (0x0C_u32 << 16) | ((u32::from(i) + 1) << 8));
        }
        devices[13] = ((12, 0), (0x1AF4, 0x1042, 0x0180, 0x00, 0));
        let cfg = FakeCfg::with(devices, bridges);
        let mut read = |b: u8, d: u8, _f: u8, o: u8| cfg.read(b, d, o);
        let mut write = |_b: u8, _d: u8, _f: u8, _o: u8, _v: u32| {};
        let inv = enumerate_multi(&mut read, &mut write, 0);
        assert_eq!(MAX_WALK_DEPTH, 8);
        assert!(
            !inv.devices[..inv.count].iter().any(|d| d.bus == 12),
            "the bus-12 endpoint is past the depth cap"
        );
        // The chain's shallow part (within the cap) was still walked.
        assert!(
            inv.devices[..inv.count].iter().any(|d| d.bus == 7),
            "bus 7 is within the cap"
        );
    }
}
