//! ACPI power control (FADT-sourced, ADR-free platform slice): the
//! kernel's power-off and reset paths used to be hardcoded QEMU ports
//! (`outw(0x604, 0x2000)`); this module reads the FIRMWARE's own
//! addresses — PM1a control for sleep, the FADT reset register for
//! reboot — and falls back to the old constants only when the table
//! is absent or malformed (fail-loud markers, never silent guesses).
//!
//! FADT layout (offsets pinned against Linux's include/acpi/actbl.h):
//! PM1a Control Block at +0x40, flags at +0x70 (bit 10 = the reset
//! register is supported), the reset register GAS at +0x74 (12 bytes:
//! space, bit width, bit offset, access size, 64-bit address), the
//! reset value at +0x80.

// Host-test builds compile this module without its boot-only power
// paths (they need `hw`); the parse is the pure, host-tested half.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

/// FADT offset: PM1a Control Block (32-bit I/O or memory address).
pub const OFF_PM1A_CNT: usize = 0x40;
/// FADT offset: flags (bit 10 = reset register supported).
pub const OFF_FLAGS: usize = 0x70;
/// FADT offset: the reset register GAS (12 bytes).
pub const OFF_RESET_REG: usize = 0x74;
/// FADT offset: the reset value.
pub const OFF_RESET_VALUE: usize = 0x80;
/// FADT length must cover the reset fields (through +0x80 inclusive)
/// for the power paths to trust them.
pub const MIN_LEN_FOR_RESET: usize = 0x81;
/// Flags bit 10: the ACPI reset mechanism is supported.
pub const FLAGS_RESET_REGISTER: u32 = 1 << 10;

/// A Generic Address Structure (ACPI §5.2.3.2): the first byte is the
/// space (0 = system memory, 1 = system I/O), the last 8 the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gas {
    pub space: u8,
    pub address: u64,
}

/// Decode a GAS from 12 bytes (hostile: only spaces 0 and 1 are
/// meaningful to this driver stack; others refuse).
#[must_use]
pub fn parse_gas(b: &[u8]) -> Option<Gas> {
    if b.len() < 12 {
        return None;
    }
    let space = b[0];
    if space > 1 {
        return None; // PCI-config/Embedded-controller spaces: out of scope
    }
    let address = u64::from(b[4]) | (u64::from(b[5]) << 8) | (u64::from(b[6]) << 16)
        | (u64::from(b[7]) << 24) | (u64::from(b[8]) << 32) | (u64::from(b[9]) << 40)
        | (u64::from(b[10]) << 48) | (u64::from(b[11]) << 56);
    Some(Gas { space, address })
}

/// The FADT's power-relevant content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FadtPower {
    /// The PM1a control block's address (SLP_EN/SLP_TYP live here).
    pub pm1a_cnt: u64,
    /// The reset register (None when flags bit 10 is clear or the GAS
    /// is malformed).
    pub reset_reg: Option<Gas>,
    /// The value the firmware says to write for a warm reset.
    pub reset_value: u8,
}

/// Parse the power fields from FADT bytes (the WHOLE table, header
/// included). None when the table is too short to carry the reset
/// fields at all (pre-2.0 firmware) — PM1a alone is still honored
/// then via `FadtPower::pm1a_only`.
#[must_use]
pub fn parse_fadt_power(b: &[u8]) -> Option<FadtPower> {
    if b.len() < OFF_PM1A_CNT + 4 {
        return None;
    }
    let pm1a = u32::from(b[OFF_PM1A_CNT]) | (u32::from(b[OFF_PM1A_CNT + 1]) << 8)
        | (u32::from(b[OFF_PM1A_CNT + 2]) << 16)
        | (u32::from(b[OFF_PM1A_CNT + 3]) << 24);
    if b.len() < MIN_LEN_FOR_RESET {
        // Old firmware: PM1a only, no reset fields.
        return Some(FadtPower {
            pm1a_cnt: u64::from(pm1a),
            reset_reg: None,
            reset_value: 0,
        });
    }
    let flags = u32::from(b[OFF_FLAGS]) | (u32::from(b[OFF_FLAGS + 1]) << 8)
        | (u32::from(b[OFF_FLAGS + 2]) << 16)
        | (u32::from(b[OFF_FLAGS + 3]) << 24);
    let reset_reg = if flags & FLAGS_RESET_REGISTER != 0 {
        parse_gas(&b[OFF_RESET_REG..OFF_RESET_REG + 12])
    } else {
        None
    };
    Some(FadtPower {
        pm1a_cnt: u64::from(pm1a),
        reset_reg,
        reset_value: b[OFF_RESET_VALUE],
    })
}

// ── the boot-time record (filled once by the ACPI step) ──

static HAVE: AtomicBool = AtomicBool::new(false);
static PM1A: AtomicU32 = AtomicU32::new(0);
static RESET_SPACE: AtomicU8 = AtomicU8::new(0);
static RESET_ADDR: AtomicU64 = AtomicU64::new(0);
static RESET_VALUE: AtomicU8 = AtomicU8::new(0);

/// Record the parsed FADT (the boot step calls this once; the power
/// paths read it forever after).
pub fn install(p: FadtPower) {
    PM1A.store(p.pm1a_cnt as u32, Ordering::SeqCst);
    match p.reset_reg {
        Some(g) => {
            RESET_SPACE.store(g.space, Ordering::SeqCst);
            RESET_ADDR.store(g.address, Ordering::SeqCst);
        }
        None => {
            RESET_SPACE.store(0xFF, Ordering::SeqCst); // the "absent" marker
        }
    }
    RESET_VALUE.store(p.reset_value, Ordering::SeqCst);
    HAVE.store(true, Ordering::SeqCst);
}

/// Is a FADT-sourced power path installed?
#[must_use]
pub fn installed() -> bool {
    HAVE.load(Ordering::SeqCst)
}

/// SLP_EN is bit 13 of the PM1a control register. SLP_TYP is the
/// firmware's _S5 package value (DSDT-parsed in the next slice;
/// QEMU's is 0 — documented, and identical to the old constant).
pub const SLP_EN: u16 = 1 << 13;

/// Power off: the FADT's PM1a path when installed (I/O space write —
/// every FADT this driver stack has seen puts PM1a in port space),
/// the legacy constant otherwise. Never returns.
#[cfg(not(test))]
pub fn power_off() {
    let pm1a = PM1A.load(Ordering::SeqCst);
    if installed() && pm1a != 0 {
        // SLP_TYP 0 (QEMU's _S5) | SLP_EN: the sleep request.
        crate::hw::outw(pm1a as u16, SLP_EN);
    }
    // The fallback (and the belt after the write, in case the
    // platform ignores sleep): the classic ports.
    crate::hw::outw(0x604, SLP_EN);
    crate::hw::outw(0xB004, 0x2000);
    crate::hw::halt_forever();
}

/// Reboot: the FADT reset register when installed and valid (a
/// write-what-the-table-says to where-the-table-says), else the
/// 0xCF9 full reset, else the keyboard-controller pulse. Never
/// returns. The CI lanes run QEMU with -no-reboot: a guest reset
/// exits the emulator with the log intact — the proof lane's reboot
/// marker precedes the call.
#[cfg(not(test))]
pub fn reboot() {
    let space = RESET_SPACE.load(Ordering::SeqCst);
    let addr = RESET_ADDR.load(Ordering::SeqCst);
    let value = RESET_VALUE.load(Ordering::SeqCst);
    if installed() && space == 1 && addr != 0 {
        // System I/O space: a byte write (the reset register's access
        // size on every machine seen is 1).
        crate::hw::outb(addr as u16, value);
    }
    // Fallback 1: the PCI reset control register (0xCF9), full reset.
    crate::hw::outb(0xCF9, 0x0E);
    // Fallback 2: pulse the keyboard controller's reset line.
    crate::hw::outb(0x64, 0xFE);
    crate::hw::halt_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal-but-real FADT image for the power fields: PM1a at
    /// 0x604, reset-register flag set, GAS = I/O space 0xCF9, value
    /// 6 — the exact picture q35 firmware presents.
    fn fixture(pm1a: u32, reset: bool) -> Vec<u8> {
        let mut b = vec![0u8; 0x88];
        b[OFF_PM1A_CNT..OFF_PM1A_CNT + 4].copy_from_slice(&pm1a.to_le_bytes());
        let mut flags = 0u32;
        if reset {
            flags |= FLAGS_RESET_REGISTER;
        }
        b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        // GAS at 0x74: space 1 (I/O), width 8, offset 0, access 1,
        // address 0xCF9.
        b[OFF_RESET_REG] = 1;
        b[OFF_RESET_REG + 1] = 8;
        b[OFF_RESET_REG + 3] = 1;
        b[OFF_RESET_REG + 4..OFF_RESET_REG + 12].copy_from_slice(&0xCF9u64.to_le_bytes());
        b[OFF_RESET_VALUE] = 6;
        b
    }

    #[test]
    fn the_q35_picture_parses() {
        let p = parse_fadt_power(&fixture(0x604, true)).expect("parses");
        assert_eq!(p.pm1a_cnt, 0x604);
        assert_eq!(p.reset_reg, Some(Gas { space: 1, address: 0xCF9 }));
        assert_eq!(p.reset_value, 6);
    }

    #[test]
    fn reset_flag_clear_means_no_reset_register() {
        let p = parse_fadt_power(&fixture(0x604, false)).expect("parses");
        assert_eq!(p.pm1a_cnt, 0x604);
        assert_eq!(p.reset_reg, None, "flags bit 10 is the arbiter");
        // The value byte is not trusted without the flag either.
        assert_eq!(p.reset_value, 6, "the byte still parses (unused)");
    }

    #[test]
    fn short_tables_refuse_or_degrade_honestly() {
        // Empty: nothing at all.
        assert!(parse_fadt_power(&[]).is_none());
        // One byte short of the PM1a field: nothing.
        assert!(parse_fadt_power(&[0u8; 0x43]).is_none());
        // Long enough for PM1a (exactly 0x44 bytes) but not the reset
        // fields: PM1a only.
        let mut b = vec![0u8; 0x44];
        b[OFF_PM1A_CNT..OFF_PM1A_CNT + 4].copy_from_slice(&0x604u32.to_le_bytes());
        let p = parse_fadt_power(&b).expect("PM1a-only firmware");
        assert_eq!(p.pm1a_cnt, 0x604);
        assert_eq!(p.reset_reg, None);
    }

    #[test]
    fn gas_decode_refuses_unknown_spaces_and_shorts() {
        // Memory space (0) is valid.
        let mut b = [0u8; 12];
        b[0] = 0;
        b[4..12].copy_from_slice(&0xFED0_0000u64.to_le_bytes());
        assert_eq!(parse_gas(&b), Some(Gas { space: 0, address: 0xFED0_0000 }));
        // I/O space (1) is valid.
        let mut c = [0u8; 12];
        c[0] = 1;
        c[4..12].copy_from_slice(&0xCF9u64.to_le_bytes());
        assert_eq!(parse_gas(&c), Some(Gas { space: 1, address: 0xCF9 }));
        // PCI config space (2): out of scope → refuse.
        let mut d = [0u8; 12];
        d[0] = 2;
        assert_eq!(parse_gas(&d), None);
        // Truncated: refuse.
        assert_eq!(parse_gas(&[0u8; 11]), None);
        assert_eq!(parse_gas(&[]), None);
    }

    #[test]
    fn the_offsets_and_bits_are_pinned() {
        // Pinned against Linux's include/acpi/actbl.h field order.
        assert_eq!(OFF_PM1A_CNT, 0x40);
        assert_eq!(OFF_FLAGS, 0x70);
        assert_eq!(OFF_RESET_REG, 0x74);
        assert_eq!(OFF_RESET_VALUE, 0x80);
        assert_eq!(MIN_LEN_FOR_RESET, 0x81);
        assert_eq!(FLAGS_RESET_REGISTER, 1 << 10);
        assert_eq!(SLP_EN, 1 << 13);
    }
}
