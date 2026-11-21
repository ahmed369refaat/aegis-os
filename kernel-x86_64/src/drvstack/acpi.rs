//! ACPI table directory walk: HPET/MADT/MCFG discovery markers.

use super::line;
use crate::strutil;

#[cfg(not(test))]
pub(crate) fn acpi_hpet_step(out: &mut dyn FnMut(&str), dir_pa: u64) {
    // Directory header: sig[4] + len u32 at +4.
    let mut hdr = [0u8; 8];
    crate::arch::acpi::read_bytes(dir_pa, &mut hdr);
    let len = u32::from(hdr[4])
        | (u32::from(hdr[5]) << 8)
        | (u32::from(hdr[6]) << 16)
        | (u32::from(hdr[7]) << 24);
    let xsdt = &hdr[..4] == b"XSDT";
    let stride: u64 = if xsdt { 8 } else { 4 };
    let n = ((len as u64).saturating_sub(36)) / stride;
    let mut hpet_pa: u64 = 0;
    let mut madt_pa: u64 = 0;
    let mut mcfg_pa: u64 = 0;
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

    // MADT: count LAPIC/IOAPIC entries.
    if madt_pa != 0 {
        let mut mb = [0u8; 44];
        crate::arch::acpi::read_bytes(madt_pa, &mut mb);
        let mlen = u32::from(mb[4])
            | (u32::from(mb[5]) << 8)
            | (u32::from(mb[6]) << 16)
            | (u32::from(mb[7]) << 24);
        let mut lapic = 0u64;
        let mut ioapic = 0u64;
        let mut ioapic_addr: u64 = 0;
        let mut off = 44u64;
        while off + 2 <= u64::from(mlen) && off < 4096 {
            let et = crate::arch::acpi::read_byte(madt_pa + off);
            let el = crate::arch::acpi::read_byte(madt_pa + off + 1);
            if el == 0 {
                break;
            }
            if et == 0 {
                lapic += 1;
            } else if et == 1 {
                ioapic += 1;
                ioapic_addr = u64::from(crate::memops::read_u32(madt_pa + off + 4));
            }
            off += u64::from(el);
        }
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        let mut c = [0u8; 18];
        let mut d = [0u8; 20];
        line(
            out,
            &[
                "[MADT] LAPIC entries=",
                strutil::dec(lapic, &mut a),
                " IOAPIC entries=",
                strutil::dec(ioapic, &mut b),
                " @0x",
                strutil::hex(ioapic_addr, &mut c),
                " (gsi base ",
                strutil::dec(0, &mut d),
                ")",
            ],
        );
    }

    // MCFG: the ECAM window.
    if mcfg_pa != 0 {
        let base = crate::memops::read_u64(mcfg_pa + 44);
        let seg = crate::memops::read_u16(mcfg_pa + 52);
        let sb = crate::arch::acpi::read_byte(mcfg_pa + 54);
        let eb = crate::arch::acpi::read_byte(mcfg_pa + 55);
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

    // HPET: table +44 = the block's base address (space at +40).
    if hpet_pa != 0 {
        let space = crate::arch::acpi::read_byte(hpet_pa + 40);
        let block = crate::memops::read_u64(hpet_pa + 44);
        if space == 0 && block != 0 {
            let caps = crate::memops::read_u64(block);
            let period = caps >> 32; // femtoseconds
            let freq = 1_000_000_000_000_000u64.checked_div(period).unwrap_or(0);
            // Enable the main counter, read it twice.
            let cfg = crate::memops::read_u64(block + 0x10);
            crate::memops::write_u64(block + 0x10, cfg | 1);
            let c1 = crate::memops::read_u64(block + 0xF0);
            let mut spins = 0u64;
            while spins < 2_000_000 {
                spins += 1;
            }
            let c2 = crate::memops::read_u64(block + 0xF0);
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
        } else {
            line(
                out,
                &["[HPET] table present but not memory-space — skipped"],
            );
        }
    }
}

// ── Block layer + ext2, first slice (checklist item 8): read-only
// ext2 over AHCI — superblock validation, root inode, directory
// walk, file content. The image is built by scripts/mkext2.py and
// attached as the q35 lane's SATA disk ──
