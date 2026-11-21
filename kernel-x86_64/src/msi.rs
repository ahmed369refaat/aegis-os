//! MSI and MSI-X capability programming (ADR-0019's message half): a
//! device stops sharing a GSI and gets its own interrupt as a memory
//! write — the address/data pair the LAPIC turns into a vector. Until
//! now every virtio wait in this tree was a bounded poll; this module
//! is how that ends.
//!
//! Encodings are pure and host-tested; the programming path is
//! target-only and goes through the existing PCI config accessors
//! (`pci::read_cfg32`/`write_cfg32`) and the direct map (the MSI-X
//! table lives in a BAR — bounds-checked against the BAR's SIZE, the
//! F5 discipline, before any word is written).
//!
//! The xAPIC physical-destination message: address 0xFEE0_0000 |
//! (dest << 12), data = vector (delivery FIXED, edge) — the same
//! encoding the IOAPIC RTE carries, expressed as a write instead of a
//! line. The x2APIC/IRTE remappable format (address bit 4 set, the
//! handle in bits 19:5) is layered on top by the VT-d slice when the
//! DMAR declares interrupt remapping — see `arch::vtd`.

// Host-test builds compile this module without its device
// programming (it needs `hw`); the encodings and bounds run on the
// host against fixture words.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use crate::pci::PciDev;

/// MSI capability id.
pub const CAP_ID_MSI: u8 = 0x05;
/// MSI-X capability id.
pub const CAP_ID_MSIX: u8 = 0x11;

// ── MSI-X capability layout (PCI §6.8.2) ──────────────────────────────
// The capability header dword: bits 7:0 id, 15:8 next, 31:16 Message
// Control. Table Offset/BIR at cap+4, PBA Offset/BIR at cap+8.

/// Message Control bit 15: MSI-X enable.
pub const MSIX_ENABLE: u16 = 1 << 15;
/// Message Control bit 14: function mask (all vectors masked at once).
pub const MSIX_FUNC_MASK: u16 = 1 << 14;
/// Message Control bits 10:0: table size, N−1 encoded.
pub const MSIX_TABLE_SIZE_MASK: u16 = 0x7FF;

/// Decode the table size from a Message Control word (N−1 → N).
#[must_use]
pub const fn msix_table_size(mc: u16) -> u32 {
    ((mc & MSIX_TABLE_SIZE_MASK) as u32) + 1
}

/// The BIR (BAR index, 0..=5) from a Table-Offset/BIR dword.
#[must_use]
pub const fn msix_bir(word: u32) -> u32 {
    word & 0x7
}

/// The table offset (within the BAR) from a Table-Offset/BIR dword:
/// bits 31:3, dword-aligned.
#[must_use]
pub const fn msix_table_offset(word: u32) -> u32 {
    word & !0x7
}

// ── MSI-X table entry layout (16 bytes per entry) ──

pub const MSIX_ENTRY_SIZE: u32 = 16;
/// Entry word 0: message address, low 32 bits.
pub const ENTRY_ADDR_LO: u32 = 0;
/// Entry word 1: message address, high 32 bits (0 in 32-bit mode).
pub const ENTRY_ADDR_HI: u32 = 4;
/// Entry word 2: message data (16 bits defined; we write the vector).
pub const ENTRY_DATA: u32 = 8;
/// Entry word 3: vector control — bit 0 is the per-entry mask.
pub const ENTRY_VECTOR_CTRL: u32 = 12;
/// The per-entry masked bit.
pub const ENTRY_MASKED: u32 = 1;

// ── MSI capability layout (PCI §6.8.1) ────────────────────────────────

/// Message Control bit 0: MSI enable.
pub const MSI_ENABLE: u16 = 1 << 0;
/// Message Control bit 7: 64-bit address capable (device-reported).
pub const MSI_64BIT_CAPABLE: u16 = 1 << 7;
/// Message Control bits 6:4: multiple-message enable (log2 count).
pub const MSI_MME_MASK: u16 = 0x7 << 4;

// ── the message encodings (xAPIC physical destination) ────────────────

/// The Local APIC MSI address prefix: bits 31:20 = 0xFEE.
pub const MSI_ADDR_BASE: u64 = 0xFEE0_0000;

/// The 32-bit MSI address for a physical destination: 0xFEE0_0000 with
/// the 8-bit APIC ID in bits 19:12 (dest 0 = the BSP).
#[must_use]
pub const fn msi_addr(dest_apic_id: u8) -> u64 {
    MSI_ADDR_BASE | ((dest_apic_id as u64) << 12)
}

/// The MSI data word: the vector in bits 7:0, delivery FIXED and
/// edge-triggered (the zero fields) — identical semantics to an
/// IOAPIC edge RTE.
#[must_use]
pub const fn msi_data(vector: u8) -> u32 {
    vector as u32
}

// ── pure bounds: the entry's physical address inside the BAR ──

/// The physical address of MSI-X entry `index`'s 16 bytes, or None
/// when it does not fit the BAR (offset + index*16 + 16 > size) — the
/// F5 discipline: a wrong address must refuse, never write a
/// neighboring device's memory.
#[must_use]
pub fn entry_pa(bar_base: u64, bar_size: u64, table_off: u32, index: u32) -> Option<u64> {
    let off = u64::from(table_off.checked_add(index.checked_mul(MSIX_ENTRY_SIZE)?)?);
    let end = off.checked_add(u64::from(MSIX_ENTRY_SIZE))?;
    if end > bar_size {
        return None;
    }
    bar_base.checked_add(off)
}

/// The decoded MSI-X capability of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixInfo {
    /// The capability's config-space offset (dword-aligned, 0x40..0xFC
    /// — the walk's range).
    pub cap_ptr: u8,
    /// Table size in entries (decoded from MC bits 10:0).
    pub table_size: u32,
    /// The BAR the table lives in.
    pub bir: u32,
    /// The table's offset within that BAR.
    pub table_off: u32,
}

/// Read and decode a device's MSI-X capability (the cap walk already
/// recorded the ids; this reads the layout words). None when the
/// device has no MSI-X cap or the layout is malformed (a BIR naming a
/// BAR the device does not carry, or a table offset beyond the BAR).
#[cfg(not(test))]
pub fn read_msix(dev: &PciDev) -> Option<MsixInfo> {
    let cap_ptr = dev.cap_ptrs[..dev.cap_count]
        .iter()
        .zip(dev.cap_ids[..dev.cap_count].iter())
        .find(|(_, id)| **id == CAP_ID_MSIX)
        .map(|(ptr, _)| *ptr)?;
    // Message Control: the high half of the cap header dword.
    let mc = (crate::pci::read_cfg32(dev, cap_ptr) >> 16) as u16;
    // Table Offset/BIR dword at cap+4.
    let tob = crate::pci::read_cfg32(dev, cap_ptr + 4);
    let bir = msix_bir(tob);
    let table_off = msix_table_offset(tob);
    // The named BAR must exist as a memory BAR.
    let bar = crate::pci::mem_bar(dev, bir as u8)?;
    let table_size = msix_table_size(mc);
    // The whole table must fit the BAR: if the LAST entry does not
    // resolve, the layout is malformed — refuse the capability, not
    // the first out-of-bounds write.
    if table_size == 0 || entry_pa(bar.base, bar.size, table_off, table_size - 1).is_none() {
        return None;
    }
    Some(MsixInfo {
        cap_ptr,
        table_size,
        bir,
        table_off,
    })
}

/// Program one MSI-X table entry: masked first (the two-step), then
/// address, data, then unmask. Returns false on any bounds refusal —
/// nothing is written.
#[cfg(not(test))]
pub fn program_entry(dev: &PciDev, info: &MsixInfo, index: u32, addr: u64, data: u32) -> bool {
    let Some(bar) = crate::pci::mem_bar(dev, info.bir as u8) else {
        return false;
    };
    let Some(pa) = entry_pa(bar.base, bar.size, info.table_off, index) else {
        return false;
    };
    // The two-step: mask, write the payload, unmask — a half-written
    // entry must never deliver (the ioapic::program discipline).
    crate::memops::write_u32(pa + u64::from(ENTRY_VECTOR_CTRL), ENTRY_MASKED);
    crate::memops::write_u32(pa + u64::from(ENTRY_ADDR_LO), addr as u32);
    crate::memops::write_u32(pa + u64::from(ENTRY_ADDR_HI), (addr >> 32) as u32);
    crate::memops::write_u32(pa + u64::from(ENTRY_DATA), data & 0xFFFF);
    crate::memops::write_u32(pa + u64::from(ENTRY_VECTOR_CTRL), 0);
    true
}

/// Read one table entry back (the teardown/read-back proof): the
/// (addr, data, masked) triple the device holds.
#[cfg(not(test))]
pub fn read_entry(dev: &PciDev, info: &MsixInfo, index: u32) -> Option<(u64, u32, bool)> {
    let bar = crate::pci::mem_bar(dev, info.bir as u8)?;
    let pa = entry_pa(bar.base, bar.size, info.table_off, index)?;
    let lo = u64::from(crate::memops::read_u32(pa + u64::from(ENTRY_ADDR_LO)));
    let hi = u64::from(crate::memops::read_u32(pa + u64::from(ENTRY_ADDR_HI)));
    let data = crate::memops::read_u32(pa + u64::from(ENTRY_DATA));
    let masked = crate::memops::read_u32(pa + u64::from(ENTRY_VECTOR_CTRL)) & ENTRY_MASKED != 0;
    Some((lo | (hi << 32), data, masked))
}

/// Set the MSI-X enable (and clear the function mask when enabling).
/// The Message Control is the high half of the cap header dword; the
/// low half (id/next) must never be echoed — read, splice, write.
#[cfg(not(test))]
pub fn set_enable(dev: &PciDev, info: &MsixInfo, on: bool) {
    let word = crate::pci::read_cfg32(dev, info.cap_ptr);
    let mut mc = (word >> 16) as u16;
    if on {
        mc |= MSIX_ENABLE;
        mc &= !MSIX_FUNC_MASK;
    } else {
        mc &= !MSIX_ENABLE;
    }
    crate::pci::write_cfg32(dev, info.cap_ptr, (word & 0xFFFF) | (u32::from(mc) << 16));
}

/// The live Message Control word (diagnostics + tests).
#[cfg(not(test))]
pub fn message_control(dev: &PciDev, info: &MsixInfo) -> u16 {
    (crate::pci::read_cfg32(dev, info.cap_ptr) >> 16) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MSI address/data encodings, pinned bit by bit: dest 0 is
    /// the bare prefix, the dest rides bits 19:12, the data is the
    /// vector with FIXED/edge as zero fields.
    #[test]
    fn msi_message_encodings_are_pinned() {
        assert_eq!(msi_addr(0), 0xFEE0_0000);
        assert_eq!(msi_addr(1), 0xFEE0_1000);
        assert_eq!(msi_addr(0xFF), 0xFEEF_F000, "dest occupies bits 19:12");
        assert_eq!(msi_data(0x31), 0x31);
        assert_eq!(msi_data(0xFF), 0xFF);
    }

    /// The MSI-X control bits and the N−1 table-size decode.
    #[test]
    fn msix_control_bits_and_table_size_decode() {
        assert_eq!(MSIX_ENABLE, 1 << 15);
        assert_eq!(MSIX_FUNC_MASK, 1 << 14);
        assert_eq!(MSIX_TABLE_SIZE_MASK, 0x7FF);
        // QEMU virtio-pci: 3 entries (config + 2 queues) → MC=2.
        assert_eq!(msix_table_size(2), 3);
        assert_eq!(msix_table_size(0), 1, "N−1 encoding: zero is one entry");
        assert_eq!(msix_table_size(0x7FF), 2048, "the max field value");
        assert_eq!(
            msix_table_size(0xFFFF & !MSIX_ENABLE & !MSIX_FUNC_MASK),
            2048
        );
        // Enabled + masked + size 2 reads back consistently.
        let mc = MSIX_ENABLE | MSIX_FUNC_MASK | 2;
        assert_eq!(msix_table_size(mc), 3);
    }

    /// The BIR/offset split of the Table-Offset dword.
    #[test]
    fn bir_and_offset_split_the_dword() {
        // QEMU virtio-net-pci: table at BAR 4 offset 0 → dword 4.
        assert_eq!(msix_bir(4), 4);
        assert_eq!(msix_table_offset(4), 0);
        // A table at BAR 1, offset 0x2000: dword 0x2001.
        assert_eq!(msix_bir(0x2001), 1);
        assert_eq!(msix_table_offset(0x2001), 0x2000);
        // Bits 2:1 are reserved in the BIR field: masked out.
        assert_eq!(msix_bir(0xFFFF_FFFF), 0x7);
        assert_eq!(msix_table_offset(0xFFFF_FFF8), 0xFFFF_FFF8);
    }

    /// The entry-address bounds: entries that fit the BAR resolve,
    /// entries that do not refuse — including the wrap-around and
    /// multiplication-overflow hostiles.
    #[test]
    fn entry_addresses_are_bounds_checked_against_the_bar() {
        // A 4 KiB BAR with the table at 0: 256 entries fit.
        let base = 0xE000_0000u64;
        assert_eq!(entry_pa(base, 0x1000, 0, 0), Some(base));
        assert_eq!(entry_pa(base, 0x1000, 0, 255), Some(base + 255 * 16));
        // Entry 256 starts at 4096 — one past the end.
        assert_eq!(entry_pa(base, 0x1000, 0, 256), None);
        // A table offset near the end: only the fitting tail is valid.
        assert_eq!(entry_pa(base, 0x1000, 0xFF0, 0), Some(base + 0xFF0));
        assert_eq!(
            entry_pa(base, 0x1000, 0xFF0, 1),
            None,
            "16 bytes past the end"
        );
        // Multiplication overflow: index near u32::MAX.
        assert_eq!(entry_pa(base, u64::MAX, 0, u32::MAX), None);
        // Address-space wrap: the entry's base would cross u64::MAX.
        assert_eq!(entry_pa(u64::MAX - 0x8, 0x100, 0x10, 0), None);
        // Offset overflow: table_off + index*16 wraps u32.
        assert_eq!(entry_pa(base, u64::MAX, 0xFFFF_FFF0, 2), None);
    }

    /// The entry layout: 16 bytes, the four words at their offsets.
    #[test]
    fn the_entry_layout_is_16_bytes_of_four_words() {
        assert_eq!(MSIX_ENTRY_SIZE, 16);
        assert_eq!(ENTRY_ADDR_LO, 0);
        assert_eq!(ENTRY_ADDR_HI, 4);
        assert_eq!(ENTRY_DATA, 8);
        assert_eq!(ENTRY_VECTOR_CTRL, 12);
        assert_eq!(ENTRY_MASKED, 1);
    }

    /// The MSI control bits.
    #[test]
    fn msi_control_bits() {
        assert_eq!(MSI_ENABLE, 1);
        assert_eq!(MSI_64BIT_CAPABLE, 1 << 7);
        assert_eq!(MSI_MME_MASK, 0x70);
    }
}
