//! The I/O APIC (ADR-0019's line-interrupt half): register access and
//! redirection-entry encodings, pure and host-tested, with the
//! target-only programming path through `memops` — the same
//! physical-address discipline as the LAPIC (the window check refuses
//! an address outside the pre-mapped 4th GiB BEFORE any access).
//!
//! Register model (Intel 82093AA §3.1): two registers visible at a
//! time — IOREGSEL at +0x00 selects, IOWIN at +0x10 reads/writes.
//! Registers: ID 0x00, VERSION 0x01, ARB 0x02, and the redirection
//! table at 0x10 + 2*GSI (two 32-bit words per entry, low first).
//!
//! The redirection entry (RTE) is 64 bits; the encoding here is pinned
//! by host tests so a field drift cannot silently re-route a line:
//! vector in bits 7:0, delivery mode FIXED in bits 10:8, dest mode
//! PHYSICAL in bit 11, polarity ACTIVE-HIGH in bit 13, trigger EDGE in
//! bit 15, MASK in bit 16, and the 8-bit destination APIC ID in bits
//! 63:56 (physical destination).

// Host-test builds compile this module without its boot-only device
// accessors (they need `memops`); the encodings and bounds run on the
// host against fixture words.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

#[cfg(not(test))]
use crate::memops;

/// IOREGSEL: the register-select window at base + 0x00.
pub const REG_IOREGSEL: u64 = 0x00;
/// IOWIN: the data window at base + 0x10.
pub const REG_IOWIN: u64 = 0x10;
/// The ID register (8-bit APIC ID in bits 24:27).
pub const REG_ID: u32 = 0x00;
/// The VERSION register: version in bits 7:0, max redirection entries
/// in bits 23:16 (encoded as count − 1).
pub const REG_VERSION: u32 = 0x01;
/// The redirection-table base register index (word 0 of GSI 0).
pub const REG_RTBL_BASE: u32 = 0x10;

/// The q35 default IOAPIC MMIO base (MADT names it; the probe checks
/// the window anyway — this constant is the expected value, not
/// trusted input).
pub const Q35_MMIO_BASE: u64 = 0xFEC0_0000;

// ── the redirection entry (pure encoding) ──

/// Delivery mode FIXED (0b000) in bits 10:8.
pub const DELIVERY_FIXED: u64 = 0 << 8;
/// Destination mode PHYSICAL (0) in bit 11.
pub const DEST_PHYSICAL: u64 = 0 << 11;
/// Polarity ACTIVE-HIGH (0) in bit 13.
pub const POLARITY_ACTIVE_HIGH: u64 = 0 << 13;
/// Trigger mode EDGE (0) in bit 15.
pub const TRIGGER_EDGE: u64 = 0 << 15;
/// Trigger mode LEVEL (1) in bit 15 — the shared lines (PCIe
/// level-signaled through the IOAPIC) need it.
pub const TRIGGER_LEVEL: u64 = 1 << 15;
/// The mask bit (16).
pub const RTE_MASKED: u64 = 1 << 16;
/// The destination APIC ID lives in bits 63:56 (physical mode).
const RTE_DEST_SHIFT: u64 = 56;

/// Encode one redirection entry. Everything this driver stack routes
/// today is FIXED/physical/active-high; `trigger` and `masked` are the
/// two knobs the callers actually need. `dest_apic_id` is masked to 8
/// bits — the physical-mode field is 8 bits, and a wider value would
/// land in reserved bits (the hardware would ignore or fault on it).
#[must_use]
pub fn rte_encode(vector: u8, dest_apic_id: u8, trigger: u64, masked: bool) -> u64 {
    let mut rte = u64::from(vector) | DELIVERY_FIXED | DEST_PHYSICAL | POLARITY_ACTIVE_HIGH | trigger;
    if masked {
        rte |= RTE_MASKED;
    }
    rte | (u64::from(dest_apic_id) << RTE_DEST_SHIFT)
}

/// The vector field of an RTE (bits 7:0) — the decode used by tests
/// and the teardown print.
#[must_use]
pub fn rte_vector(rte: u64) -> u8 {
    (rte & 0xFF) as u8
}

/// Is the RTE's mask bit set?
#[must_use]
pub fn rte_is_masked(rte: u64) -> bool {
    rte & RTE_MASKED != 0
}

/// The 8-bit destination field (bits 63:56).
#[must_use]
pub fn rte_dest(rte: u64) -> u8 {
    (rte >> RTE_DEST_SHIFT) as u8
}

/// Max redirection entries from a VERSION register read-back:
/// bits 23:16 hold count − 1.
#[must_use]
pub fn max_redirections(version_reg: u32) -> u32 {
    ((version_reg >> 16) & 0xFF).saturating_add(1)
}

/// Is `gsi` programable on an IOAPIC reporting `version_reg`?
#[must_use]
pub fn gsi_in_range(gsi: u32, version_reg: u32) -> bool {
    gsi < max_redirections(version_reg)
}

/// The redirection-table register index pair for a GSI: (word0, word1).
#[must_use]
pub fn rtbl_regs(gsi: u32) -> (u32, u32) {
    (REG_RTBL_BASE + 2 * gsi, REG_RTBL_BASE + 2 * gsi + 1)
}

// ── target-only device programming ──

/// One IOAPIC, programmed through its MMIO window. `max_gsi` is
/// learned from the VERSION register at probe time — every program
/// call is bounds-checked against it, not against a hope.
#[cfg(not(test))]
pub struct IoApic {
    base: u64,
    max_gsi: u32,
}

#[cfg(not(test))]
impl IoApic {
    /// Probe the IOAPIC at `pa`: refuse (None) an address outside the
    /// pre-mapped 4th-GiB window (the LAPIC discipline — a wrong
    /// address must refuse, not fault), read VERSION, and sanity-check
    /// it (dead patterns are a refusal).
    pub fn probe(pa: u64) -> Option<IoApic> {
        if !crate::arch::lapic::mmio_in_window(pa, 0x20) {
            return None;
        }
        let ver = Self::read32(pa, REG_VERSION);
        if ver == 0 || ver == u32::MAX {
            return None;
        }
        Some(IoApic {
            base: pa,
            max_gsi: max_redirections(ver),
        })
    }

    pub fn max_gsi(&self) -> u32 {
        self.max_gsi
    }

    /// One register word through the select/data window pair.
    fn read32(base: u64, reg: u32) -> u32 {
        memops::write_u32(base + REG_IOREGSEL, reg);
        memops::read_u32(base + REG_IOWIN)
    }

    fn write32(base: u64, reg: u32, v: u32) {
        memops::write_u32(base + REG_IOREGSEL, reg);
        memops::write_u32(base + REG_IOWIN, v);
    }

    /// Read the ID register (the probe marker prints it).
    pub fn id(&self) -> u32 {
        Self::read32(self.base, REG_ID)
    }

    /// Read the VERSION register (the probe marker prints it).
    pub fn version(&self) -> u32 {
        Self::read32(self.base, REG_VERSION)
    }

    /// Program one GSI's redirection entry. Bounds-checked against the
    /// probed max — an out-of-range GSI refuses (`false`), never
    /// writes a neighboring entry.
    pub fn program(&self, gsi: u32, rte: u64) -> bool {
        if gsi >= self.max_gsi {
            return false;
        }
        let (w0, w1) = rtbl_regs(gsi);
        // Masked first, then the full entry, then unmask — the classic
        // two-step so a half-written entry can never deliver. Callers
        // that want it masked pass the masked RTE directly.
        Self::write32(self.base, w0, (rte | RTE_MASKED) as u32);
        Self::write32(self.base, w1, (rte >> 32) as u32);
        Self::write32(self.base, w0, rte as u32);
        true
    }

    /// Read back one RTE (the teardown proof: what we programmed is
    /// what the device holds).
    pub fn read_rte(&self, gsi: u32) -> Option<u64> {
        if gsi >= self.max_gsi {
            return None;
        }
        let (w0, w1) = rtbl_regs(gsi);
        Some(u64::from(Self::read32(self.base, w0)) | (u64::from(Self::read32(self.base, w1)) << 32))
    }

    /// Mask one GSI (read-modify-write its RTE with the mask bit).
    pub fn mask(&self, gsi: u32) -> bool {
        match self.read_rte(gsi) {
            Some(rte) => self.program(gsi, rte | RTE_MASKED),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned encoding: vector, fixed, physical, active-high,
    /// edge, unmasked, dest 0 — the exact word the proof lane's GSI 1
    /// carries, bit by bit.
    #[test]
    fn rte_encoding_is_pinned_field_by_field() {
        let rte = rte_encode(0x31, 0, TRIGGER_EDGE, false);
        assert_eq!(rte_vector(rte), 0x31);
        assert_eq!(rte_dest(rte), 0);
        assert!(!rte_is_masked(rte));
        assert_eq!(rte, 0x0000_0000_0000_0031, "fixed/physical/active-high/edge are all zero fields");
        // The masked variant differs ONLY in bit 16.
        let m = rte_encode(0x31, 0, TRIGGER_EDGE, true);
        assert_eq!(m, rte | RTE_MASKED);
        assert!(rte_is_masked(m));
        // Level trigger differs only in bit 15.
        let l = rte_encode(0x31, 0, TRIGGER_LEVEL, false);
        assert_eq!(l, rte | TRIGGER_LEVEL);
    }

    #[test]
    fn the_dest_lands_in_bits_63_56_and_is_masked_to_8_bits() {
        let rte = rte_encode(0x41, 0x2A, TRIGGER_EDGE, false);
        assert_eq!(rte_dest(rte), 0x2A);
        assert_eq!(rte >> 56, 0x2A, "dest occupies the top byte");
        // A wider-than-8-bit dest is truncated, never smeared into
        // reserved bits below 63:56.
        let wide = rte_encode(0x41, 0xFF, TRIGGER_EDGE, false);
        assert_eq!(rte_dest(wide), 0xFF);
    }

    #[test]
    fn max_redirections_decodes_count_minus_one() {
        // QEMU's IOAPIC: 24 redirection entries → bits 23:16 = 23.
        assert_eq!(max_redirections((23 << 16) | 0x11), 24);
        assert_eq!(max_redirections(0x11), 1, "zero count field is one entry");
        assert_eq!(max_redirections(u32::MAX), 0x100, "all-ones field saturates, never wraps to 0");
        assert_eq!(max_redirections(0), 1);
        // The bounds check uses it.
        assert!(gsi_in_range(23, (23 << 16) | 0x11));
        assert!(!gsi_in_range(24, (23 << 16) | 0x11));
        assert!(!gsi_in_range(0xFFFF_FFFF, (23 << 16) | 0x11));
    }

    #[test]
    fn rtbl_regs_walk_two_words_per_gsi() {
        assert_eq!(rtbl_regs(0), (0x10, 0x11));
        assert_eq!(rtbl_regs(1), (0x12, 0x13));
        assert_eq!(rtbl_regs(23), (0x3E, 0x3F), "the last QEMU entry");
        // The pair is dense — no GSI aliases another's words.
        let (a0, a1) = rtbl_regs(7);
        let (b0, b1) = rtbl_regs(8);
        assert_eq!(a1 + 1, b0);
        assert_ne!(a0, b1);
    }

    #[test]
    fn the_q35_base_sits_inside_the_lapic_window() {
        // The 4th-GiB direct-map window covers 0xC000_0000..
        // 0x1_0000_0000; the IOAPIC at 0xFEC0_0000 must land inside it
        // (the probe's refusal path exists for machines that move it).
        assert!(crate::arch::lapic::mmio_in_window(Q35_MMIO_BASE, 0x20));
        assert!(!crate::arch::lapic::mmio_in_window(0x0, 0x20));
        assert!(!crate::arch::lapic::mmio_in_window(0x1_0000_0000, 0x20));
    }

    /// The encode/decode round trip: every field the driver sets is
    /// the field the read-back decodes.
    #[test]
    fn encode_decode_round_trips() {
        for vector in [0x31u8, 0x41, 0x50, 0x6E, 0xFF] {
            for dest in [0u8, 1, 0xFF] {
                for masked in [false, true] {
                    let rte = rte_encode(vector, dest, TRIGGER_EDGE, masked);
                    assert_eq!(rte_vector(rte), vector);
                    assert_eq!(rte_dest(rte), dest);
                    assert_eq!(rte_is_masked(rte), masked);
                }
            }
        }
    }
}
