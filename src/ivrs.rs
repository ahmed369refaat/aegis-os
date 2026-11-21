//! AMD-Vi's firmware description — the IVRS table (the AMD counterpart
//! of Intel's DMAR that `dmar.rs` parses). The layouts below are
//! pinned against Linux's `include/acpi/actbl2.h` (struct
//! acpi_table_ivrs / acpi_ivrs_hardware_10/11 / the device-entry
//! encodings).
//!
//! HONEST SCOPE: this is the PARSE slice — the table view, its IVHD
//! hardware blocks (the IOMMU's MMIO base, its own PCI id, the
//! flags), and the device-entry topology (selects, ranges, aliases,
//! specials). The AMD-Vi register engine (device tables, command
//! buffers — a sibling of `arch/vtd.rs`) is the follow-up; without
//! it, an AMD machine still fails closed exactly like the no-IOMMU
//! lane. QEMU does not emulate AMD-Vi, so the lane prints the honest
//! absence; the host tests carry the parse proof.
//!
//! Layout, in one breath: the table header (36 bytes) carries `info`
//! at +36 (physical address size in bits 15:8) and subtables start at
//! +48. An IVHD (type 0x10 legacy / 0x11 with EFR) names one IOMMU:
//! its own device id in the subtable header, the control-register
//! base at +8, the PCI segment at +16, and — for 0x10 — 24 bytes of
//! header before the device entries; 0x11 carries attributes/EFR and
//! starts its entries at +44. Device entries are 4 or 8 bytes (the
//! length rides the top two bits of the type byte): 4-byte entries
//! SELECT a device or open/close a range; 8-byte entries carry
//! ALIAS/EXTENDED selectors or a SPECIAL (APIC/HPET-type) source.

// ── constants ─────────────────────────────────────────────────────────

pub const SIG: &[u8; 4] = b"IVRS";
/// Subtables begin after header(36) + info(4) + reserved(8).
pub const SUBTABLES_OFFSET: usize = 48;
/// info bits 15:8: the physical address size.
pub const INFO_PHYS_SIZE_MASK: u32 = 0x7F00;

/// Subtable types.
pub const TYPE_IVHD_LEGACY: u8 = 0x10;
pub const TYPE_IVHD_EFR: u8 = 0x11;
pub const TYPE_IVHD_TYPE3: u8 = 0x40;
pub const TYPE_IVMD1: u8 = 0x20;
pub const TYPE_IVMD2: u8 = 0x21;
pub const TYPE_IVMD3: u8 = 0x22;

/// IVHD flags.
pub const IVHD_PASS_PW: u8 = 1 << 1;
pub const IVHD_ISOC: u8 = 1 << 3;
pub const IVHD_IOTLB: u8 = 1 << 4;

/// Device-entry type bytes (the low 6 bits; the top two carry the
/// entry length: 0b00 = 4 bytes, 0b01 = 8 bytes).
pub const ENTRY_LENGTH_MASK: u8 = 0xC0;
pub const ENTRY_LEN4: u8 = 0x00;
pub const ENTRY_LEN8: u8 = 0x40;

pub const DE_PAD4: u8 = 0;
pub const DE_ALL: u8 = 1;
pub const DE_SELECT: u8 = 2;
pub const DE_START: u8 = 3;
pub const DE_END: u8 = 4;
pub const DE_PAD8: u8 = 64;
pub const DE_ALIAS_SELECT: u8 = 66;
pub const DE_ALIAS_START: u8 = 67;
pub const DE_EXT_SELECT: u8 = 70;
pub const DE_EXT_START: u8 = 71;
pub const DE_SPECIAL: u8 = 72;

/// How many IVHD blocks this parser records (multi-IOMMU machines
/// exist; more is out of scope and counted, not crashed).
pub const MAX_IVHD: usize = 2;
/// How many device entries this parser records per IVHD.
pub const MAX_DE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvrsError {
    Short,
    BadSignature,
    BadSubtableLength,
    UnknownSubtableType(u8),
    EntryOverrun,
    ReservedEntryLength,
}

/// One IVHD: an IOMMU unit as the firmware describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ivhd {
    /// The subtable type (0x10 legacy / 0x11 EFR / 0x40).
    pub ivhd_type: u8,
    pub flags: u8,
    /// The IOMMU's own PCI device id (bus:dev:fn packed as firmware
    /// writes it: bits 15:8 bus, 7:3 dev, 2:0 fn).
    pub device_id: u16,
    /// The control-register MMIO base.
    pub base_address: u64,
    pub segment: u16,
    /// The device entries' counts by kind (the topology summary).
    pub selects: u32,
    pub ranges: u32,
    pub aliases: u32,
    pub specials: u32,
    pub all_entries: bool,
    /// Whether every entry in the block was consumed inside its
    /// length (false = truncated: a refusal upstream).
    pub complete: bool,
}

/// The parsed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ivrs {
    /// Physical address size from `info` (bits 15:8).
    pub phys_addr_bits: u8,
    pub ivhds: [Option<Ivhd>; MAX_IVHD],
    pub ivhd_count: usize,
    pub ivmd_count: u32,
    /// Unity-map blocks seen (start, length) — the first one is
    /// marker material; more are counted.
    pub first_ivmd: Option<(u64, u64)>,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

/// Parse the WHOLE IVRS table (header included). Hostile inputs
/// refuse typed; what parsed stands only if the whole walk completed
/// (Ivrs is all-or-nothing: a truncated block is an Err).
pub fn parse_ivrs(bytes: &[u8]) -> Result<Ivrs, IvrsError> {
    if bytes.len() < SUBTABLES_OFFSET {
        return Err(IvrsError::Short);
    }
    if &bytes[..4] != SIG {
        return Err(IvrsError::BadSignature);
    }
    let phys_addr_bits = ((le32(bytes, 36) & INFO_PHYS_SIZE_MASK) >> 8) as u8;
    let mut out = Ivrs {
        phys_addr_bits,
        ivhds: [None; MAX_IVHD],
        ivhd_count: 0,
        ivmd_count: 0,
        first_ivmd: None,
    };
    // The table's own length (at +4) bounds the walk.
    let table_len = le32(bytes, 4) as usize;
    let end = table_len.min(bytes.len());
    let mut off = SUBTABLES_OFFSET;
    while off + 6 <= end {
        let t = bytes[off];
        let len = le16(bytes, off + 2) as usize;
        if len < 6 || off + len > end {
            return Err(IvrsError::BadSubtableLength);
        }
        match t {
            TYPE_IVHD_LEGACY | TYPE_IVHD_EFR | TYPE_IVHD_TYPE3 => {
                // The header sizes: 24 bytes for 0x10/0x40-style, 44
                // for the EFR-carrying 0x11 (both pinned against
                // acpi_ivrs_hardware_10/11).
                let hdr_len = match t {
                    TYPE_IVHD_EFR => 44,
                    _ => 24,
                };
                if len < hdr_len {
                    return Err(IvrsError::BadSubtableLength);
                }
                let mut ivhd = Ivhd {
                    ivhd_type: t,
                    flags: bytes[off + 1],
                    device_id: le16(bytes, off + 4),
                    base_address: le64(bytes, off + 8),
                    segment: le16(bytes, off + 16),
                    selects: 0,
                    ranges: 0,
                    aliases: 0,
                    specials: 0,
                    all_entries: false,
                    complete: true,
                };
                // The device-entry walk, bounded by the block length.
                let mut e = off + hdr_len;
                while e < off + len {
                    if e + 4 > off + len {
                        return Err(IvrsError::EntryOverrun);
                    }
                    let et = bytes[e];
                    // The entry length rides the top two bits; the
                    // 8-byte types (64..=79) EMBED those bits in
                    // their values — the match below compares the
                    // full byte, never a masked one.
                    let entry_len = match et & ENTRY_LENGTH_MASK {
                        ENTRY_LEN4 => 4,
                        ENTRY_LEN8 => 8,
                        _ => return Err(IvrsError::ReservedEntryLength),
                    };
                    if e + entry_len > off + len {
                        return Err(IvrsError::EntryOverrun);
                    }
                    match et {
                        DE_PAD4 | DE_PAD8 => {}
                        DE_ALL => ivhd.all_entries = true,
                        DE_SELECT | DE_EXT_SELECT => ivhd.selects += 1,
                        DE_START | DE_END | DE_EXT_START => ivhd.ranges += 1,
                        DE_ALIAS_SELECT | DE_ALIAS_START => ivhd.aliases += 1,
                        DE_SPECIAL => ivhd.specials += 1,
                        _ => return Err(IvrsError::UnknownSubtableType(et)),
                    }
                    e += entry_len;
                }
                if out.ivhd_count < MAX_IVHD {
                    out.ivhds[out.ivhd_count] = Some(ivhd);
                }
                out.ivhd_count += 1;
            }
            TYPE_IVMD1 | TYPE_IVMD2 | TYPE_IVMD3 => {
                // acpi_ivrs_memory: 32 bytes — aux_data, reserved,
                // start, length.
                if len < 32 {
                    return Err(IvrsError::BadSubtableLength);
                }
                if out.ivmd_count == 0 {
                    out.first_ivmd = Some((le64(bytes, off + 16), le64(bytes, off + 24)));
                }
                out.ivmd_count += 1;
            }
            _ => return Err(IvrsError::UnknownSubtableType(t)),
        }
        off += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic IVHD 0x10 fixture: one IOMMU at MMIO
    /// 0xFED8_0000, device id 0x00 (00:00.0), segment 0, IOTLB
    /// support flag, and a small entry set: ALL is NOT set; two
    /// SELECTs, one range (START/END), one ALIAS, one SPECIAL.
    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; SUBTABLES_OFFSET];
        b[..4].copy_from_slice(SIG);
        // info: 48-bit physical addresses (0x30 << 8).
        b[36..40].copy_from_slice(&(0x30u32 << 8).to_le_bytes());
        // The IVHD.
        let mut entries: Vec<u8> = Vec::new();
        fn de(entries: &mut Vec<u8>, t: u8, id: u16) {
            entries.push(t);
            entries.extend_from_slice(&id.to_le_bytes());
            entries.push(0); // data setting
        }
        de(&mut entries, DE_SELECT, 0x0110); // 00:02.0
        de(&mut entries, DE_SELECT, 0x0118); // 00:03.0
        de(&mut entries, DE_START, 0x0900);
        de(&mut entries, DE_END, 0x09FF);
        // The 8-byte alias: its type value (66 = 0x42) already embeds
        // the 8-byte length bits.
        de(&mut entries, DE_ALIAS_SELECT, 0x0A10);
        entries.extend_from_slice(&[0, 0x5A, 0, 0]); // alias id
        de(&mut entries, DE_SPECIAL, 0);
        entries.extend_from_slice(&[0x00, 0, 0, 0]); // handle/apic etc.
        let hdr = 24usize;
        let len = (hdr + entries.len()) as u16;
        let mut ivhd = Vec::new();
        ivhd.push(TYPE_IVHD_LEGACY);
        ivhd.push(IVHD_IOTLB);
        ivhd.extend_from_slice(&len.to_le_bytes());
        ivhd.extend_from_slice(&0x0000u16.to_le_bytes()); // device id 00:00.0
        ivhd.extend_from_slice(&0x40u16.to_le_bytes()); // capability offset
        ivhd.extend_from_slice(&0xFED8_0000u64.to_le_bytes()); // MMIO base
        ivhd.extend_from_slice(&0u16.to_le_bytes()); // segment
        ivhd.extend_from_slice(&0x0101u16.to_le_bytes()); // msi/unit info
        ivhd.extend_from_slice(&0u32.to_le_bytes()); // features
        ivhd.extend_from_slice(&entries);
        assert_eq!(ivhd.len(), hdr + entries.len());
        b.extend_from_slice(&ivhd);
        // The table length at +4.
        let total = b.len() as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn the_fixture_parses_to_the_expected_view() {
        let v = parse_ivrs(&fixture()).expect("parses");
        assert_eq!(v.phys_addr_bits, 0x30, "48-bit physical from info 15:8");
        assert_eq!(v.ivhd_count, 1);
        let i = v.ivhds[0].expect("the block");
        assert_eq!(i.ivhd_type, TYPE_IVHD_LEGACY);
        assert!(i.flags & IVHD_IOTLB != 0);
        assert_eq!(i.device_id, 0);
        assert_eq!(i.base_address, 0xFED8_0000);
        assert_eq!(i.segment, 0);
        // The fixture's six real entries: 2 SELECT + START + END +
        // 1 ALIAS + 1 SPECIAL. No ALL entry.
        assert_eq!(i.selects, 2);
        assert_eq!(i.ranges, 2, "START + END");
        assert_eq!(i.aliases, 1);
        assert_eq!(i.specials, 1);
        assert!(!i.all_entries);
        assert!(i.complete);
        assert_eq!(v.ivmd_count, 0);
        assert_eq!(v.first_ivmd, None);
    }

    #[test]
    fn all_entries_and_pads_count_correctly() {
        // An ALL entry + pads: the topology summary says "all" without
        // inflating the per-kind counts.
        let mut b = fixture();
        let entries_start = SUBTABLES_OFFSET + 24;
        b[entries_start] = DE_ALL;
        b[entries_start + 4] = DE_PAD4;
        let total = b.len() as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        let v = parse_ivrs(&b).expect("parses");
        let i = v.ivhds[0].expect("the block");
        assert!(i.all_entries);
        assert_eq!(i.selects, 0, "both SELECTs were replaced (ALL + PAD)");
        assert_eq!(i.specials, 1);
    }

    #[test]
    fn hostile_inputs_refuse_typed() {
        // Empty / short / wrong signature.
        assert_eq!(parse_ivrs(&[]), Err(IvrsError::Short));
        let mut b = fixture();
        b[0] = b'X';
        assert_eq!(parse_ivrs(&b), Err(IvrsError::BadSignature));
        // A block length shorter than its own header: refuse.
        let mut b = fixture();
        b[50..52].copy_from_slice(&20u16.to_le_bytes()); // 20 < 24
        let total = (SUBTABLES_OFFSET + 20) as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        b.truncate(total as usize);
        assert_eq!(parse_ivrs(&b), Err(IvrsError::BadSubtableLength));
        // An entry overrunning the block: declare the block two bytes
        // short of its last entry (the walk hits a partial entry).
        let mut b = fixture();
        let full = b.len();
        let short = full - 2;
        let ivhd_len = (short - SUBTABLES_OFFSET) as u16;
        b[50..52].copy_from_slice(&ivhd_len.to_le_bytes());
        let total = short as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        b.truncate(short);
        assert_eq!(parse_ivrs(&b), Err(IvrsError::EntryOverrun));
        // A reserved entry length (the 16/32-byte encodings, top bits
        // 0b10/0b11): refuse.
        let mut b = fixture();
        let entries_start = SUBTABLES_OFFSET + 24;
        b[entries_start] = 0x80 | DE_SELECT;
        let total = b.len() as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        assert_eq!(parse_ivrs(&b), Err(IvrsError::ReservedEntryLength));
        // An unknown subtable type.
        let mut b = fixture();
        b[48] = 0x77;
        let total = b.len() as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        assert!(matches!(
            parse_ivrs(&b),
            Err(IvrsError::UnknownSubtableType(_))
        ));
    }

    #[test]
    fn ivmd_blocks_are_counted_with_their_ranges() {
        let mut b = fixture();
        // Append one IVMD: type 0x20, 32 bytes, unity map at
        // 0x00_8000_0000 length 0x1000_0000.
        let mut ivmd = Vec::new();
        ivmd.push(TYPE_IVMD1);
        ivmd.push(1); // UNITY flag
        ivmd.extend_from_slice(&32u16.to_le_bytes());
        ivmd.extend_from_slice(&0u16.to_le_bytes()); // device id (0 = all)
        ivmd.extend_from_slice(&0u16.to_le_bytes()); // aux data
        ivmd.extend_from_slice(&0u64.to_le_bytes()); // reserved
        ivmd.extend_from_slice(&0x00_8000_0000u64.to_le_bytes()); // start
        ivmd.extend_from_slice(&0x1000_0000u64.to_le_bytes()); // length
        b.extend_from_slice(&ivmd);
        let total = b.len() as u32;
        b[4..8].copy_from_slice(&total.to_le_bytes());
        let v = parse_ivrs(&b).expect("parses");
        assert_eq!(v.ivmd_count, 1);
        assert_eq!(v.first_ivmd, Some((0x00_8000_0000, 0x1000_0000)));
        assert_eq!(v.ivhd_count, 1);
    }

    #[test]
    fn the_layout_constants_are_pinned_against_linux() {
        assert_eq!(SIG, b"IVRS");
        assert_eq!(SUBTABLES_OFFSET, 48);
        assert_eq!(INFO_PHYS_SIZE_MASK, 0x7F00);
        assert_eq!(TYPE_IVHD_LEGACY, 0x10);
        assert_eq!(TYPE_IVHD_EFR, 0x11);
        assert_eq!(TYPE_IVHD_TYPE3, 0x40);
        assert_eq!(TYPE_IVMD1, 0x20);
        assert_eq!(IVHD_IOTLB, 1 << 4);
        assert_eq!(ENTRY_LENGTH_MASK, 0xC0);
        assert_eq!(DE_ALL, 1);
        assert_eq!(DE_SELECT, 2);
        assert_eq!(DE_START, 3);
        assert_eq!(DE_END, 4);
        assert_eq!(DE_ALIAS_SELECT, 66);
        assert_eq!(DE_EXT_SELECT, 70);
        assert_eq!(DE_SPECIAL, 72);
    }
}
