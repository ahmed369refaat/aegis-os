//! ACPI table directory walk: HPET/MADT/MCFG discovery markers.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::strutil;
use crate::strutil::line;

#[cfg(not(test))]
pub(crate) fn acpi_hpet_step(out: &mut dyn FnMut(&str), dir_pa: u64) {
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
        return;
    };
    let xsdt = dir_sig == b"XSDT";
    let stride: u64 = if xsdt { 8 } else { 4 };
    let n = ((dir_len as u64).saturating_sub(36)) / stride;
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

    // MADT: count LAPIC/IOAPIC entries. F12: validated first — a
    // corrupted MADT is a refusal, not a walk.
    let mut mlen = 0u32;
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

    // MCFG: the ECAM window. F12: validated first.
    if mcfg_pa != 0 && crate::arch::acpi::table_ok(mcfg_pa, b"MCFG", &mut scratch).is_none() {
        line(out, &["[MCFG] table failed validation — refusing"]);
        mcfg_pa = 0;
    }
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
                return;
            };
            if bus.window().len() < 0xF0 + 8 {
                line(out, &["[HPET] window math failed — skipped"]);
                return;
            }
            let (Some(caps), Some(cfg)) = (bus.read64(0), bus.read64(0x10)) else {
                line(out, &["[HPET] register window refused a read — skipped"]);
                return;
            };
            let period = caps >> 32; // femtoseconds
            let freq = 1_000_000_000_000_000u64.checked_div(period).unwrap_or(0);
            // Enable the main counter, read it twice.
            if !bus.write64(0x10, cfg | 1) {
                line(
                    out,
                    &["[HPET] register window refused the enable — skipped"],
                );
                return;
            }
            let Some(c1) = bus.read64(0xF0) else {
                line(
                    out,
                    &["[HPET] register window refused a counter read — skipped"],
                );
                return;
            };
            let mut spins = 0u64;
            while spins < 2_000_000 {
                spins += 1;
            }
            let c2 = bus.read64(0xF0).unwrap_or(c1);
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
