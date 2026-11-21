//! ACPI table directory walk: HPET/MADT/MCFG discovery markers.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::strutil;
use crate::strutil::line;

// ── MADT, the interrupt view (ADR-0019) ────────────────────────────────
// The IOAPIC's MMIO address and the ISA-IRQ→GSI overrides live in MADT
// entries. The parse below is PURE over the table bytes (host-tested
// against fixtures and hostile truncations); the boot step trusts only
// its output, never a raw entry read.

/// How many IOAPICs this driver stack can route through (MADTs carry
/// one per interrupt-remapping scope; more is a machine this stack
/// does not model — counted, not crashed).
pub(crate) const MAX_IOAPICS: usize = 4;
/// How many interrupt-source overrides we record (q35 carries two:
/// irq0→gsi2 and the SCI line).
pub(crate) const MAX_OVERRIDES: usize = 16;

/// The MADT's interrupt-relevant content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MadtIrq {
    /// Processor-local APIC entries (type 0) — the CPU count.
    pub lapic_entries: u32,
    /// IOAPIC entries (type 1): (mmio base, gsi base).
    pub ioapics: [(u64, u32); MAX_IOAPICS],
    pub ioapic_count: usize,
    /// Interrupt-source overrides (type 2): (isa irq, gsi, flags).
    pub overrides: [(u8, u32, u16); MAX_OVERRIDES],
    pub override_count: usize,
    /// The LAPIC address override (type 5), if any (0 = none).
    pub lapic_addr_override: u64,
}

impl MadtIrq {
    pub(crate) fn empty() -> MadtIrq {
        MadtIrq {
            lapic_entries: 0,
            ioapics: [(0, 0); MAX_IOAPICS],
            ioapic_count: 0,
            overrides: [(0, 0, 0); MAX_OVERRIDES],
            override_count: 0,
            lapic_addr_override: 0,
        }
    }

    /// The first IOAPIC's MMIO base (the machine this stack boots has
    /// exactly one; more is future work).
    pub(crate) fn primary_ioapic(&self) -> Option<u64> {
        self.ioapics
            .first()
            .filter(|(_, g)| *g == 0)
            .map(|(a, _)| *a)
    }

    /// Map an ISA IRQ to its GSI through the overrides (the PIT's
    /// irq0 → gsi 2 on q35 is the famous one); unmapped IRQs pass
    /// through unchanged.
    pub(crate) fn gsi_of_isa_irq(&self, isa_irq: u8) -> u32 {
        for (src, gsi, _flags) in self.overrides[..self.override_count].iter() {
            if *src == isa_irq {
                return *gsi;
            }
        }
        u32::from(isa_irq)
    }
}

/// Parse the MADT's interrupt entries from `bytes` (the WHOLE table,
/// header included; entries start at offset 44). Hostile inputs stop
/// the walk at the first malformed entry — what parsed, stands.
pub(crate) fn parse_madt_irq(bytes: &[u8]) -> MadtIrq {
    let mut m = MadtIrq::empty();
    if bytes.len() < 44 {
        return m; // shorter than the header: nothing to walk
    }
    let mut off = 44usize;
    while off + 2 <= bytes.len() {
        let et = bytes[off];
        let el = bytes[off + 1] as usize;
        if el < 2 {
            break; // a zero/1-byte length is a malformed entry: stop
        }
        if off + el > bytes.len() {
            break; // truncated entry: stop, keep what parsed
        }
        let rd32 = |o: usize| -> u32 {
            u32::from(bytes[o])
                | (u32::from(bytes[o + 1]) << 8)
                | (u32::from(bytes[o + 2]) << 16)
                | (u32::from(bytes[o + 3]) << 24)
        };
        match et {
            0 if el >= 8 => m.lapic_entries = m.lapic_entries.saturating_add(1),
            1 if el >= 12 => {
                if m.ioapic_count < MAX_IOAPICS {
                    let addr = u64::from(rd32(off + 4));
                    let gsi_base = rd32(off + 8);
                    m.ioapics[m.ioapic_count] = (addr, gsi_base);
                    m.ioapic_count += 1;
                }
            }
            2 if el >= 10 => {
                if m.override_count < MAX_OVERRIDES {
                    let src = bytes[off + 3];
                    let gsi = rd32(off + 4);
                    let flags = u16::from(bytes[off + 8]) | (u16::from(bytes[off + 9]) << 8);
                    m.overrides[m.override_count] = (src, gsi, flags);
                    m.override_count += 1;
                }
            }
            5 if el >= 12 => {
                m.lapic_addr_override = u64::from(rd32(off + 4)) | (u64::from(rd32(off + 8)) << 32);
            }
            _ => {} // unknown or short entry: skip it, keep walking
        }
        off += el;
    }
    m
}

#[cfg(test)]
mod madt_tests {
    use super::*;

    /// A minimal-but-real MADT image: header (36 bytes) + the local
    /// APIC address/flags block (8 bytes) + one LAPIC entry + one
    /// IOAPIC @0xFEC00000 + the q35-style irq0→gsi2 override.
    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 44];
        // header sig "APIC" + a plausible length the parse ignores
        // (table_ok validated the real one; the parse only walks).
        b[..4].copy_from_slice(b"APIC");
        b[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        b[40..44].copy_from_slice(&1u32.to_le_bytes());
        // type 0: LAPIC, len 8
        b.extend_from_slice(&[0, 8, 0, 0, 0, 1, 1, 0]);
        // type 1: IOAPIC, len 12 (id 0, addr 0xFEC00000, gsi base 0)
        b.extend_from_slice(&[1, 12, 0, 0]);
        b.extend_from_slice(&0xFEC0_0000u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        // type 2: override, len 10 (bus 0, source 0 → gsi 2, flags 0)
        b.extend_from_slice(&[2, 10, 0, 0]);
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b
    }

    #[test]
    fn the_fixture_parses_to_the_expected_view() {
        let m = parse_madt_irq(&fixture());
        assert_eq!(m.lapic_entries, 1);
        assert_eq!(m.ioapic_count, 1);
        assert_eq!(m.ioapics[0], (0xFEC0_0000, 0));
        assert_eq!(m.override_count, 1);
        assert_eq!(m.overrides[0], (0, 2, 0));
        assert_eq!(m.primary_ioapic(), Some(0xFEC0_0000));
        // The override maps irq0 (the PIT) to gsi 2; irq1 (the
        // keyboard) passes through unmapped.
        assert_eq!(m.gsi_of_isa_irq(0), 2);
        assert_eq!(m.gsi_of_isa_irq(1), 1);
        assert_eq!(m.lapic_addr_override, 0);
    }

    #[test]
    fn hostile_inputs_stop_the_walk_and_keep_what_parsed() {
        // Empty / header-only: nothing.
        assert_eq!(parse_madt_irq(&[]).lapic_entries, 0);
        assert_eq!(parse_madt_irq(&[0u8; 36]).ioapic_count, 0);
        // A zero-length entry stops the walk before it.
        let mut b = fixture();
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let m = parse_madt_irq(&b);
        assert_eq!(m.ioapic_count, 1, "the valid prefix still parsed");
        // A truncated entry (length says 12, only 4 bytes left).
        let mut t = fixture();
        t.extend_from_slice(&[1, 12, 0, 0]);
        let m = parse_madt_irq(&t);
        assert_eq!(m.ioapic_count, 1, "the truncated IOAPIC is not recorded");
        // An entry length of 1 (header-only entry) stops the walk.
        let mut z = fixture();
        z.extend_from_slice(&[3, 1]);
        let m = parse_madt_irq(&z);
        assert_eq!(m.override_count, 1);
    }

    #[test]
    fn short_entries_of_a_known_type_are_skipped_not_parsed() {
        // A type-1 (IOAPIC) entry with length 6 (< 12): skipped as
        // malformed, but the walk continues after it (the entry is
        // exactly as long as its length byte claims).
        let mut b = vec![0u8; 44];
        b.extend_from_slice(&[1, 6, 0, 0, 0xEE, 0xEE]);
        // followed by a valid LAPIC entry
        b.extend_from_slice(&[0, 8, 0, 0, 0, 1, 1, 0]);
        let m = parse_madt_irq(&b);
        assert_eq!(m.ioapic_count, 0, "the short IOAPIC entry is not parsed");
        assert_eq!(m.lapic_entries, 1, "the walk continued past it");
    }

    #[test]
    fn capacity_is_bounded_not_overflowed() {
        // 8 IOAPICs and 20 overrides into a 4/16-capacity view: the
        // counts cap, nothing panics, nothing is lost from the parse
        // that preceded.
        let mut b = vec![0u8; 44];
        for _ in 0..8 {
            b.extend_from_slice(&[1, 12, 0, 0]);
            b.extend_from_slice(&0xFEC0_0000u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
        }
        for i in 0..20u8 {
            b.extend_from_slice(&[2, 10, 0, i]);
            b.extend_from_slice(&u32::from(i + 16).to_le_bytes());
            b.extend_from_slice(&[0, 0]);
        }
        let m = parse_madt_irq(&b);
        assert_eq!(m.ioapic_count, MAX_IOAPICS);
        assert_eq!(m.override_count, MAX_OVERRIDES);
        // And the mapping only sees recorded overrides.
        assert_eq!(m.gsi_of_isa_irq(0), 16);
        assert_eq!(
            m.gsi_of_isa_irq(19),
            19,
            "the 17th override was not recorded"
        );
    }

    #[test]
    fn the_lapic_address_override_is_captured() {
        let mut b = vec![0u8; 44];
        // type 5, len 12: the 64-bit LAPIC address at +4.
        b.extend_from_slice(&[5, 12, 0, 0]);
        b.extend_from_slice(&0xDEAD_BEEF_CAFE_0000u64.to_le_bytes());
        let m = parse_madt_irq(&b);
        assert_eq!(m.lapic_addr_override, 0xDEAD_BEEF_CAFE_0000);
    }
}

/// Decode one validated MCFG's first entry: base at +44, segment at
/// +52, start/end bus at +54/+55. None on a dead pattern (base 0, or
/// a window whose end precedes its start).
#[cfg(not(test))]
fn decode_mcfg(mcfg_pa: u64) -> Option<(u64, u16, u8, u8)> {
    let base = crate::memops::read_u64(mcfg_pa + 44);
    let seg = crate::memops::read_u16(mcfg_pa + 52);
    let sb = crate::arch::acpi::read_byte(mcfg_pa + 54);
    let eb = crate::arch::acpi::read_byte(mcfg_pa + 55);
    if base == 0 || eb < sb {
        return None;
    }
    Some((base, seg, sb, eb))
}

/// The PCI config access seam's MCFG half (ADR-0020): walk the
/// firmware table directory for a VALIDATED MCFG and decode its
/// first entry. Segment 0 only — the machines this driver stack
/// boots are single-segment; a different segment or an absent/corrupt
/// table yields None and the caller uses the legacy port pair (and
/// the acpi step prints the honest refusal for a corrupt one).
#[cfg(not(test))]
pub(crate) fn ecam_window(dir_pa: u64) -> Option<(u64, u16, u8, u8)> {
    let mut scratch = [0u8; 1024];
    let dir_sig: &[u8; 4] = if crate::arch::acpi::read_byte(dir_pa) == b'X' {
        b"XSDT"
    } else {
        b"RSDT"
    };
    let dir_len = crate::arch::acpi::table_ok(dir_pa, dir_sig, &mut scratch)?;
    let xsdt = dir_sig == b"XSDT";
    let stride: u64 = if xsdt { 8 } else { 4 };
    let n = ((dir_len as u64).saturating_sub(36)) / stride;
    let mut sig = [0u8; 8];
    for i in 0..n.min(64) {
        let entry_pa = if xsdt {
            crate::memops::read_u64(dir_pa + 36 + i * 8)
        } else {
            u64::from(crate::memops::read_u32(dir_pa + 36 + i * 4))
        };
        if entry_pa == 0 {
            continue;
        }
        crate::arch::acpi::read_bytes(entry_pa, &mut sig);
        if &sig[..4] == b"MCFG" {
            // present but corrupt: the legacy pair it is
            crate::arch::acpi::table_ok(entry_pa, b"MCFG", &mut scratch)?;
            return decode_mcfg(entry_pa);
        }
    }
    None
}

#[cfg(not(test))]
pub(crate) fn acpi_hpet_step(out: &mut dyn FnMut(&str), dir_pa: u64) -> Option<MadtIrq> {
    // F12: the directory itself must earn trust before its entry
    // pointers are read — signature, length, checksum.
    let mut scratch = [0u8; 1024];
    let dir_sig: &[u8; 4] = if crate::arch::acpi::read_byte(dir_pa) == b'X' {
        b"XSDT"
    } else {
        b"RSDT"
    };
    let Some(dir_len) = crate::arch::acpi::table_ok(dir_pa, dir_sig, &mut scratch) else {
        line(
            out,
            &["[ACPI] directory table failed validation (sig/length/checksum) — refusing the walk"],
        );
        return None;
    };
    let xsdt = dir_sig == b"XSDT";
    let stride: u64 = if xsdt { 8 } else { 4 };
    let n = ((dir_len as u64).saturating_sub(36)) / stride;
    let mut hpet_pa: u64 = 0;
    let mut madt_pa: u64 = 0;
    let mut mcfg_pa: u64 = 0;
    let mut facp_pa: u64 = 0;
    let mut ivrs_pa: u64 = 0;
    let mut sig = [0u8; 8];
    for i in 0..n.min(64) {
        let entry_pa = if xsdt {
            crate::memops::read_u64(dir_pa + 36 + i * 8)
        } else {
            u64::from(crate::memops::read_u32(dir_pa + 36 + i * 4))
        };
        if entry_pa == 0 {
            continue;
        }
        crate::arch::acpi::read_bytes(entry_pa, &mut sig);
        match &sig[..4] {
            b"HPET" => hpet_pa = entry_pa,
            b"APIC" => madt_pa = entry_pa,
            b"MCFG" => mcfg_pa = entry_pa,
            b"FACP" => facp_pa = entry_pa,
            b"IVRS" => ivrs_pa = entry_pa,
            _ => {}
        }
    }
    let mut hn = [0u8; 20];
    line(
        out,
        &[
            "[ACPI] directory walk (",
            strutil::dec(n, &mut hn),
            " entries): HPET=",
            if hpet_pa != 0 { "yes" } else { "no" },
            " MADT=",
            if madt_pa != 0 { "yes" } else { "no" },
            " MCFG=",
            if mcfg_pa != 0 { "yes" } else { "no" },
        ],
    );

    // MADT: the interrupt view. F12: validated first — a corrupted
    // MADT is a refusal, not a walk. The pure parser (host-tested)
    // turns the entries into the MadtIrq summary the irq step routes
    // from; the marker keeps its long-standing prefix.
    let mut mlen = 0u32;
    let mut madt_view = None;
    if madt_pa != 0 {
        match crate::arch::acpi::table_ok(madt_pa, b"APIC", &mut scratch) {
            Some(len) => mlen = len,
            None => {
                line(out, &["[MADT] table failed validation — refusing"]);
                madt_pa = 0;
            }
        }
    }
    if madt_pa != 0 {
        // The parse walks the table bytes directly; read what fits the
        // scratch buffer (a longer MADT parses its valid prefix).
        let n = (mlen as usize).min(scratch.len());
        crate::arch::acpi::read_bytes(madt_pa, &mut scratch[..n]);
        let m = parse_madt_irq(&scratch[..n]);
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        let mut c = [0u8; 18];
        let mut d = [0u8; 20];
        line(
            out,
            &[
                "[MADT] LAPIC entries=",
                strutil::dec(u64::from(m.lapic_entries), &mut a),
                " IOAPIC entries=",
                strutil::dec(m.ioapic_count as u64, &mut b),
                " @0x",
                strutil::hex(m.ioapics[0].0, &mut c),
                " (gsi base ",
                strutil::dec(u64::from(m.ioapics[0].1), &mut d),
                ")",
            ],
        );
        for (src, gsi, flags) in m.overrides[..m.override_count].iter() {
            let mut s1 = [0u8; 20];
            let mut s2 = [0u8; 20];
            let mut s3 = [0u8; 18];
            line(
                out,
                &[
                    "[MADT] irq override: isa irq ",
                    strutil::dec(u64::from(*src), &mut s1),
                    " → gsi ",
                    strutil::dec(u64::from(*gsi), &mut s2),
                    " flags=0x",
                    strutil::hex(u64::from(*flags), &mut s3),
                ],
            );
        }
        madt_view = Some(m);
    }

    // MCFG: the ECAM window. F12: validated first.
    if mcfg_pa != 0 && crate::arch::acpi::table_ok(mcfg_pa, b"MCFG", &mut scratch).is_none() {
        line(out, &["[MCFG] table failed validation — refusing"]);
        mcfg_pa = 0;
    }
    if mcfg_pa != 0 {
        match decode_mcfg(mcfg_pa) {
            Some((base, seg, sb, eb)) => {
                let mut c = [0u8; 18];
                let mut a = [0u8; 20];
                let mut b = [0u8; 20];
                let mut e = [0u8; 20];
                line(
                    out,
                    &[
                        "[MCFG] ECAM base 0x",
                        strutil::hex(base, &mut c),
                        " seg=",
                        strutil::dec(u64::from(seg), &mut a),
                        " bus ",
                        strutil::dec(u64::from(sb), &mut b),
                        "..",
                        strutil::dec(u64::from(eb), &mut e),
                    ],
                );
            }
            None => {
                line(out, &["[MCFG] entry decode refused — refusing"]);
            }
        }
    }

    // FADT: the power addresses (F12: validated first). The reset
    // register + PM1a install into arch::pwr — the kernel's power-off
    // and reboot paths become firmware-sourced instead of hardcoded.
    let mut facp_len = 0usize;
    if facp_pa != 0 {
        match crate::arch::acpi::table_ok(facp_pa, b"FACP", &mut scratch) {
            Some(len) => facp_len = (len as usize).min(scratch.len()),
            None => {
                line(
                    out,
                    &["[FADT] table failed validation — power paths stay on the legacy constants"],
                );
                facp_pa = 0;
            }
        }
    }
    if facp_pa != 0 {
        let n = facp_len;
        crate::arch::acpi::read_bytes(facp_pa, &mut scratch[..n]);
        if let Some(p) = crate::arch::pwr::parse_fadt_power(&scratch[..n]) {
            crate::arch::pwr::install(p);
            let mut pa = [0u8; 20];
            let mut ra = [0u8; 20];
            line(
                out,
                &[
                    "[PWR ] FADT: PM1a control @0x",
                    strutil::dec(p.pm1a_cnt, &mut pa),
                    ", reset reg ",
                    match p.reset_reg {
                        Some(g) => strutil::dec(g.address, &mut ra),
                        None => "absent",
                    },
                    match p.reset_reg {
                        Some(g) if g.space == 1 => " (I/O)",
                        Some(_) => " (memory)",
                        None => "",
                    },
                    " — power paths firmware-sourced",
                ],
            );
        } else {
            line(
                out,
                &["[FADT] power fields malformed — power paths stay on the legacy constants"],
            );
        }
    }

    // IVRS: AMD-Vi's firmware description. Absent on every QEMU
    // machine (no AMD-Vi emulation) — the honest absence marker; on
    // real AMD servers this parses the IVHD blocks (the IOMMU bases
    // + the device-entry topology) the AMD engine slice will consume.
    if ivrs_pa != 0 {
        match crate::arch::acpi::table_ok(ivrs_pa, b"IVRS", &mut scratch) {
            Some(len) => {
                let n = (len as usize).min(scratch.len());
                crate::arch::acpi::read_bytes(ivrs_pa, &mut scratch[..n]);
                match aegis_os::ivrs::parse_ivrs(&scratch[..n]) {
                    Ok(v) => {
                        let mut b1 = [0u8; 20];
                        let mut b2 = [0u8; 20];
                        let mut b3 = [0u8; 18];
                        let i = v.ivhds[0];
                        line(
                            out,
                            &[
                                "[IVRS] AMD-Vi: pa_bits=",
                                strutil::dec(u64::from(v.phys_addr_bits), &mut b1),
                                " ivhd=",
                                strutil::dec(v.ivhd_count as u64, &mut b2),
                                " base=0x",
                                strutil::hex(i.map(|x| x.base_address).unwrap_or(0), &mut b3),
                                " (parse slice; the engine follows)",
                            ],
                        );
                    }
                    Err(_) => {
                        line(out, &["[IVRS] table present but malformed — refusing"]);
                    }
                }
            }
            None => {
                line(out, &["[IVRS] table failed validation — refusing"]);
            }
        }
    } else {
        line(
            out,
            &["[IVRS] absent (no AMD-Vi on this machine — QEMU does not emulate it)"],
        );
    }

    // HPET: table +44 = the block's base address (space at +40).
    // HPET. F12: validated first — the block pointer at +44 is only
    // read from a table that passed sig/length/checksum.
    if hpet_pa != 0 && crate::arch::acpi::table_ok(hpet_pa, b"HPET", &mut scratch).is_none() {
        line(out, &["[HPET] table failed validation — skipping"]);
        hpet_pa = 0;
    }
    if hpet_pa != 0 {
        let space = crate::arch::acpi::read_byte(hpet_pa + 40);
        let block = crate::memops::read_u64(hpet_pa + 44);
        if space == 0 && block != 0 {
            // ADR-0016: a FixedMmio window for the block — the
            // table's address is trusted only as far as the window
            // math allows (HPET blocks are 1024 bytes; the counter
            // at +0xF0 and the config at +0x10 must both fit).
            use crate::mmio::{FixedMmio, MmioBus};
            let Some(bus) = FixedMmio::new(block, 0x1000) else {
                line(
                    out,
                    &["[HPET] block address malformed (wrapping) — skipped"],
                );
                return madt_view;
            };
            if bus.window().len() < 0xF0 + 8 {
                line(out, &["[HPET] window math failed — skipped"]);
                return madt_view;
            }
            let (Some(caps), Some(cfg)) = (bus.read64(0), bus.read64(0x10)) else {
                line(out, &["[HPET] register window refused a read — skipped"]);
                return madt_view;
            };
            let period = caps >> 32; // femtoseconds
            let freq = 1_000_000_000_000_000u64.checked_div(period).unwrap_or(0);
            // Enable the main counter, read it twice.
            if !bus.write64(0x10, cfg | 1) {
                line(
                    out,
                    &["[HPET] register window refused the enable — skipped"],
                );
                return madt_view;
            }
            let Some(c1) = bus.read64(0xF0) else {
                line(
                    out,
                    &["[HPET] register window refused a counter read — skipped"],
                );
                return madt_view;
            };
            // The calibration pair: TSC stamped around the same window
            // the counter advances (the platform slice — the preempt
            // tick's cadence stops being a guessed constant).
            let t1 = crate::hw::read_tsc();
            let mut spins = 0u64;
            while spins < 2_000_000 {
                spins += 1;
            }
            let c2 = bus.read64(0xF0).unwrap_or(c1);
            let t2 = crate::hw::read_tsc();
            let mut c = [0u8; 18];
            let mut f = [0u8; 20];
            let mut dd = [0u8; 20];
            line(
                out,
                &[
                    "[HPET] block @0x",
                    strutil::hex(block, &mut c),
                    " freq=",
                    strutil::dec(freq, &mut f),
                    " Hz; counter delta=",
                    strutil::dec(c2.wrapping_sub(c1), &mut dd),
                    " (enabled, live — the calibration source)",
                ],
            );
            // TSC calibration: elapsed femtoseconds = counter delta ×
            // period; tsc_hz = tsc_delta × 1e15 / elapsed. Guards: a
            // dead period, a zero delta, and a quotient beyond any
            // real CPU (≥ 16 GHz) all keep the fallback. Round I: the
            // arithmetic moved to u128 — the old
            // `tsc_delta.checked_mul(1e15)` overflowed u64 for ANY
            // real window (a 2M-spin calibration is millions of TSC
            // ticks, and the product with 10^15 exceeds 2^64 ten
            // times over), so the "calibrated" marker had never
            // printed — hidden behind the round-6 lane crash, like
            // every other proof on this lane.
            if period > 0 && c2 != c1 {
                let elapsed_fs = u128::from(c2.wrapping_sub(c1)) * u128::from(period);
                let tsc_delta = u128::from(t2.wrapping_sub(t1));
                let hz128 = tsc_delta * 1_000_000_000_000_000u128 / elapsed_fs;
                if (1_000_000u128..16_000_000_000u128).contains(&hz128) {
                    let hz = hz128 as u64;
                    crate::sched::preempt::set_tick_interval(hz / 100); // 10 ms
                                                                        // ADR-0023: the same measurement is THE clock —
                                                                        // clock_gettime and ns↔cycle conversions read it.
                    crate::clock::set_calibrated(hz);
                    let mut m = [0u8; 20];
                    line(
                        out,
                        &[
                            "[TSC ] calibrated: ",
                            strutil::dec(hz / 1_000_000, &mut m),
                            " MHz (HPET-sourced; the preempt tick rides it now)",
                        ],
                    );
                } else {
                    line(out, &["[TSC ] calibration quotient out of band — keeping the fallback cadence"]);
                }
            } else {
                line(out, &["[TSC ] calibration window degenerate (no counter advance) — keeping the fallback cadence"]);
            }
        } else {
            line(
                out,
                &["[HPET] table present but not memory-space — skipped"],
            );
        }
    }
    // The MADT's interrupt view (None when the MADT was absent or
    // failed validation — the irq step refuses closed on it).
    madt_view
}

// ── Block layer + ext2, first slice (checklist item 8): read-only
// ext2 over AHCI — superblock validation, root inode, directory
// walk, file content. The image is built by scripts/mkext2.py and
// attached as the q35 lane's SATA disk ──
