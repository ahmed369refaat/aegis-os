//! The watchdogs (the gap row that named them): **iTCO_wdt** — the
//! TCO block every ICH9 LPC carries, at PMBASE+0x60 — and the
//! **i6300esb** PCI card. Both register maps are pinned against
//! QEMU's own sources (`include/hw/acpi/ich9_tco.h`,
//! `include/hw/southbridge/ich9.h`, `hw/watchdog/wdt_i6300esb.c`)
//! because those are the machines the lanes boot.
//!
//! CI SAFETY, stated plainly: a watchdog that fires mid-boot would
//! reset the machine and eat the log. The iTCO probe refuses to
//! reprogram the timer unless the chipset's NO_REBOOT bit (GCS bit 5,
//! read through the RCBA) is SET — QEMU's default, which is exactly
//! why the proof can exercise the write path; the i6300esb sequence
//! arms generously (≈4 s per stage), reloads, reads back, and
//! DISABLES the card before returning. The boot never depends on a
//! timer it forgot.

// Host-test builds compile this module without its boot-only step
// (it needs `hw`); the encodings and port math run on the host.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use crate::strutil;
use crate::strutil::line;

// ── iTCO: the ICH9 LPC's TCO block ────────────────────────────────────
// PMBASE: the LPC bridge's (00:1f.0) config register 0x40 — bits 15:7
// the I/O base, bit 0 the runtime-table enable (QEMU's
// ICH9_LPC_PMBASE_BASE_ADDRESS_MASK / _RTE).

/// Config offset of PMBASE on the LPC bridge.
pub const LPC_PMBASE_CFG: u8 = 0x40;
/// PMBASE occupies bits 15:7 (a 512-byte I/O window).
pub const PMBASE_MASK: u32 = 0xFF80;
/// PMBASE bit 0: the runtime enable.
pub const PMBASE_RTE: u32 = 1;
/// The TCO block lives at PMBASE + 0x60 (ICH9_PMIO_TCO_RLD).
pub const TCO_OFFSET: u32 = 0x60;

/// TCO register offsets from PMBASE+0x60.
pub const TCO_RLD: u16 = 0x00;
#[allow(dead_code)] // register map pinned against QEMU sources; the slice that reads it is next
pub const TCO1_STS: u16 = 0x04;
pub const TCO2_STS: u16 = 0x06;
pub const TCO1_CNT: u16 = 0x08;
#[allow(dead_code)] // register map pinned against QEMU sources; the slice that reads it is next
pub const TCO2_CNT: u16 = 0x0A;
#[allow(dead_code)] // register map pinned against QEMU sources; the slice that reads it is next
pub const TCO_WDCNT: u16 = 0x0E;
pub const TCO_TMR: u16 = 0x12;

/// TCO1_STS bits: a timeout happened (W1C).
#[allow(dead_code)] // register map pinned against QEMU sources; the slice that reads it is next
pub const TCO_TIMEOUT: u16 = 1 << 3;
/// TCO1_CNT bit 11: halt the timer.
pub const TCO_TMR_HLT: u16 = 1 << 11;
/// TCO1_CNT bit 12: firmware lock (writes refuse after).
pub const TCO_LOCK: u16 = 1 << 12;
/// TCO2_STS bits: the second-stage timeout / boot-status records.
pub const TCO_SECOND_TO_STS: u16 = 1 << 1;
#[allow(dead_code)] // register map pinned against QEMU sources; the slice that reads it is next
pub const TCO_BOOT_STS: u16 = 1 << 2;
/// The timer field's width.
pub const TCO_TMR_MASK: u16 = 0x3FF;

/// Decode PMBASE from the config dword at 0x40: None when the runtime
/// enable bit is clear (the block is not decoding).
#[must_use]
pub const fn pmbase_from_dword(w: u32) -> Option<u32> {
    if w & PMBASE_RTE == 0 {
        None
    } else {
        Some(w & PMBASE_MASK)
    }
}

/// The TCO port for a register, bounds-checked (the 16-bit port space
/// must not wrap; the classic 0xCF8/0xCFC PCI pair must not collide).
#[must_use]
pub const fn tco_port(pmbase: u32, reg: u16) -> Option<u16> {
    if pmbase == 0 {
        return None;
    }
    let pa = pmbase + TCO_OFFSET + reg as u32;
    if pa > 0xFFFF {
        return None;
    }
    // The PCI config port pair: a TCO window overlapping it is
    // firmware madness — refuse rather than talk to the wrong device.
    let aligned = pa & 0xFFFE;
    if aligned >= 0xCF8 && aligned <= 0xCFF {
        return None;
    }
    Some(pa as u16)
}

// ── iTCO: the RCBA + GCS NO_REBOOT gate ───────────────────────────────
// The chipset config registers live behind the RCBA (LPC config 0xF0,
// bits 31:14 the base, bit 0 the enable); GCS at +0x3410 carries
// NO_REBOOT at bit 5 — set means "a TCO timeout does NOT reset".

/// Config offset of the RCBA.
pub const LPC_RCBA_CFG: u8 = 0xF0;
/// RCBA base occupies bits 31:14.
pub const RCBA_MASK: u32 = 0xFFFF_C000;
/// RCBA bit 0: enable.
pub const RCBA_EN: u32 = 1;
/// GCS register offset within the RCBA.
pub const GCS_OFFSET: u64 = 0x3410;
/// GCS bit 5: NO_REBOOT.
pub const GCS_NO_REBOOT: u32 = 1 << 5;

/// Decode the RCBA base from its config dword: None when disabled.
#[must_use]
pub const fn rcba_from_dword(w: u32) -> Option<u64> {
    if w & RCBA_EN == 0 {
        None
    } else {
        Some((w & RCBA_MASK) as u64)
    }
}

// ── i6300esb: the PCI watchdog card ───────────────────────────────────

pub const ESB_VENDOR: u16 = 0x8086;
pub const ESB_DEVICE: u16 = 0x25AB;
/// PCI config: the config register (16-bit decoded — the dword write
/// lands as two halfword writes, so values are duplicated into both
/// halves).
pub const ESB_CONFIG_REG: u8 = 0x60;
/// PCI config: the lock register (8-bit decoded; bookkeeping only in
/// QEMU's model — the REAL unlock lives on the MMIO reload register).
#[allow(dead_code)] // register map pinned against QEMU sources; the slice that reads it is next
pub const ESB_LOCK_REG: u8 = 0x68;
/// MMIO (BAR0): timer 1 (stage 1 preload) — write-only.
pub const ESB_TIMER1: u64 = 0x00;
/// MMIO (BAR0): timer 2 (stage 2 preload) — write-only.
pub const ESB_TIMER2: u64 = 0x04;
/// MMIO (BAR0): the reload register — the unlock pair (0x80 then
/// 0x86) AND the ping (bit 8) AND the reboot-flag clears (bits 9/12)
/// all land here.
pub const ESB_RELOAD_REG: u64 = 0x0C;
/// Config register bit 5: SET means reboot-on-timeout is MASKED.
pub const ESB_WDT_REBOOT: u32 = 1 << 5;
/// The unlock pair (order matters — QEMU enforces the sequence, and
/// the state consumes itself on the next write: every preload needs
/// its OWN pair).
pub const ESB_UNLOCK1: u32 = 0x80;
pub const ESB_UNLOCK2: u32 = 0x86;
/// The reload/ping bit.
pub const ESB_RELOAD: u32 = 1 << 8;
/// The maximum preload the device takes (val & 0xFFFFF) — ≈ a
/// quarter hour per stage at the 1 kHz scale; the proof programs it
/// and masks the reboot besides.
pub const ESB_MAX_PRELOAD: u32 = 0xF_FFFF;

/// The i6300esb unlock sequence as the (a, b) pair the register wants.
#[must_use]
pub const fn esb_unlock_pair() -> (u32, u32) {
    (ESB_UNLOCK1, ESB_UNLOCK2)
}

/// The watchdog step: the iTCO probe (LPC → PMBASE → TCO registers →
/// the NO_REBOOT gate → optionally reprogram+reload the timer) and
/// the i6300esb sequence (unlock → enable → program both stages →
/// reload → read back → disable). Every refusal is a marker, never a
/// crash; the machine's boot continues either way.
#[cfg(not(test))]
pub(crate) fn wdt_step(out: &mut dyn FnMut(&str), inv: &crate::pci::Inventory) {
    itco_step(out, inv);
    esb_step(out, inv);
}

/// The iTCO half. The LPC bridge (class 0601) carries PMBASE at
/// config 0x40; the TCO block is PMBASE+0x60.
#[cfg(not(test))]
fn itco_step(out: &mut dyn FnMut(&str), inv: &crate::pci::Inventory) {
    use crate::hw;
    // The LPC bridge: class 06/01 (ISA bridge) — the one device the
    // walk always finds on bus 0.
    let Some(lpc) = inv.devices[..inv.count]
        .iter()
        .find(|d| d.class >> 8 == 0x06 && d.class & 0xFF == 0x01)
        .copied()
    else {
        line(
            out,
            &["[WDT ] iTCO: no ISA bridge on this machine — skipped"],
        );
        return;
    };
    let word = crate::pci::read_cfg32(&lpc, LPC_PMBASE_CFG);
    let Some(pmbase) = pmbase_from_dword(word) else {
        line(
            out,
            &["[WDT ] iTCO: PMBASE runtime-disabled (RTE clear) — skipped"],
        );
        return;
    };
    // The register ports, bounds-checked before any I/O.
    let port = |reg: u16| -> Option<u16> { tco_port(pmbase, reg) };
    let (Some(cnt1_p), Some(tmr_p), Some(rld_p), Some(sts2_p)) =
        (port(TCO1_CNT), port(TCO_TMR), port(TCO_RLD), port(TCO2_STS))
    else {
        let mut b = [0u8; 20];
        line(
            out,
            &[
                "[WDT ] iTCO: PMBASE 0x",
                strutil::hex(u64::from(pmbase), &mut [0u8; 18]),
                " out of port bounds (reg ",
                strutil::dec(u64::from(pmbase + TCO_OFFSET), &mut b),
                ") — refused",
            ],
        );
        return;
    };
    let cnt1 = hw::inw(cnt1_p);
    let tmr = hw::inw(tmr_p) & TCO_TMR_MASK;
    let sts2 = hw::inw(sts2_p);

    // The NO_REBOOT gate: read GCS through the RCBA. Without it SET,
    // this driver refuses to reprogram the timer (CI safety — a TCO
    // timeout with NO_REBOOT clear resets the machine).
    let rcba_word = crate::pci::read_cfg32(&lpc, LPC_RCBA_CFG);
    let no_reboot = rcba_from_dword(rcba_word)
        .and_then(|rcba| {
            let gcs_pa = rcba + GCS_OFFSET;
            // The RCBA lives in the firmware's 4th-GiB window — the
            // same direct-map discipline as every other MMIO probe.
            if !crate::arch::lapic::mmio_in_window(gcs_pa, 8) {
                return None;
            }
            Some(crate::memops::read_u32(gcs_pa) & GCS_NO_REBOOT != 0)
        })
        .unwrap_or(false);

    let mut b1 = [0u8; 18];
    let mut b2 = [0u8; 18];
    let mut b3 = [0u8; 18];
    let mut b4 = [0u8; 20];
    let mut b5 = [0u8; 20];
    line(
        out,
        &[
            "[WDT ] iTCO live: PMBASE 0x",
            strutil::hex(u64::from(pmbase), &mut b1),
            " TCO@0x",
            strutil::hex(u64::from(pmbase + TCO_OFFSET), &mut b2),
            " — cnt1=0x",
            strutil::hex(u64::from(cnt1), &mut b3),
            " tmr=",
            strutil::dec(u64::from(tmr), &mut b4),
            "s no_reboot=",
            if no_reboot { "1" } else { "0" },
            " second_to=",
            strutil::dec(u64::from((sts2 & TCO_SECOND_TO_STS) >> 1), &mut b5),
        ],
    );
    // Reload first (harmless: extends whatever timer is running) —
    // the read-back is the remaining ticks, useful marker material.
    hw::outw(rld_p, 0x1); // reload: extend the running timer
    if !no_reboot {
        line(out, &["[WDT ] iTCO: NO_REBOOT clear — timer reprogramming refused (a timeout would reset the machine)"]);
        return;
    }
    if cnt1 & TCO_LOCK != 0 {
        line(
            out,
            &["[WDT ] iTCO: TCO_LOCK set by firmware — the timer is frozen (probe-only)"],
        );
        return;
    }
    if cnt1 & TCO_TMR_HLT != 0 {
        line(
            out,
            &["[WDT ] iTCO: timer halted by firmware (TMR_HLT) — leaving it halted"],
        );
        return;
    }
    // Program a short, visible timeout and reload: under NO_REBOOT
    // even its expiry is inert; the read-back proves the write path.
    hw::outw(tmr_p, 0x0A & TCO_TMR_MASK);
    hw::outw(rld_p, 0x1);
    let tmr_back = hw::inw(tmr_p) & TCO_TMR_MASK;
    let rld_back = hw::inw(rld_p) & 0x3FF;
    let mut t1 = [0u8; 20];
    let mut t2 = [0u8; 20];
    line(
        out,
        &[
            "[WDT ] iTCO: programmed 10s → read-back ",
            strutil::dec(u64::from(tmr_back), &mut t1),
            if tmr_back == 0x0A {
                "s (ok), ticks="
            } else {
                "s (MISMATCH?!), ticks="
            },
            strutil::dec(u64::from(rld_back), &mut t2),
            " — inert under NO_REBOOT, proven by read-back",
        ],
    );
}

/// The i6300esb half. The device's real shape (from QEMU's
/// wdt_i6300esb.c): every MMIO read returns zero — the registers are
/// WRITE-ONLY — so the proof is the SEQUENCE (unlock → preload →
/// ping, each preload behind its own unlock pair) plus the one thing
/// that is configuration, not MMIO: masking reboot-on-timeout (config
/// 0x60 bit 5) so even a hypothetical expiry is inert. The preloads
/// are the maximum the device takes (0xFFFFF ≈ a quarter hour per
/// stage at the 1 kHz scale).
#[cfg(not(test))]
fn esb_step(out: &mut dyn FnMut(&str), inv: &crate::pci::Inventory) {
    let Some(dev) = inv.devices[..inv.count]
        .iter()
        .find(|d| d.vendor == ESB_VENDOR && d.device == ESB_DEVICE)
        .copied()
    else {
        line(
            out,
            &["[WDT ] i6300esb: card absent on this machine — skipped"],
        );
        return;
    };
    let Some(bar) = crate::pci::mem_bar(&dev, 0) else {
        line(out, &["[WDT ] i6300esb: no memory BAR — refused"]);
        return;
    };
    let base = bar.base;
    // The card decodes only when memory-space is on (F9e).
    crate::pci::enable_mem(&dev);
    // Each preload needs its OWN unlock pair (the unlock state
    // consumes itself on the next write) — the sequence, in order:
    //   unlock(0x80, 0x86) → write TIMER1
    //   unlock            → write TIMER2
    //   unlock            → ping the reload register (restart stage 1)
    for (stage, reg) in [(1u8, ESB_TIMER1), (2, ESB_TIMER2)] {
        let (u1, u2) = esb_unlock_pair();
        crate::memops::write_u32(base + ESB_RELOAD_REG, u1);
        crate::memops::write_u32(base + ESB_RELOAD_REG, u2);
        crate::memops::write_u32(base + reg, ESB_MAX_PRELOAD);
        let _ = stage;
    }
    // The ping: restart the timer at stage 1 (the running watchdog).
    let (u1, u2) = esb_unlock_pair();
    crate::memops::write_u32(base + ESB_RELOAD_REG, u1);
    crate::memops::write_u32(base + ESB_RELOAD_REG, u2);
    crate::memops::write_u32(base + ESB_RELOAD_REG, ESB_RELOAD);
    // Mask reboot-on-timeout: config 0x60 bit 5 SET means the second
    // stage's expiry does NOT reset the machine. The config write is
    // 16-bit-decoded: a dword write lands as two halfword writes
    // (0x60 and 0x62), so the value is duplicated into both halves —
    // both halves set the bit, neither clears it by accident.
    let mask = ESB_WDT_REBOOT | (ESB_WDT_REBOOT << 16);
    crate::pci::write_cfg32(&dev, ESB_CONFIG_REG, mask);
    let mut b1 = [0u8; 18];
    let mut b2 = [0u8; 18];
    line(
        out,
        &[
            "[WDT ] i6300esb driven: unlock×3, timer1/2=0x",
            strutil::hex(u64::from(ESB_MAX_PRELOAD), &mut b1),
            " (max preload ≈ a quarter hour), pinged, reboot-on-timeout MASKED (cfg 0x",
            strutil::hex(
                u64::from(crate::pci::read_cfg32(&dev, ESB_CONFIG_REG) & 0xFFFF),
                &mut b2,
            ),
            ") — the registers are write-only on this device, so the sequence order is the proof",
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PMBASE decode: the enable bit arbitrates, the base masks to
    /// bits 15:7 — pinned against QEMU's ICH9_LPC_PMBASE defines.
    #[test]
    fn pmbase_decodes_enabled_and_masked() {
        assert_eq!(
            pmbase_from_dword(0x0601),
            Some(0x600),
            "q35 SeaBIOS PMBASE 0x600"
        );
        assert_eq!(pmbase_from_dword(0x0401), Some(0x400));
        // Disabled (RTE clear): refuse even with a base present.
        assert_eq!(pmbase_from_dword(0x0600), None);
        assert_eq!(pmbase_from_dword(0), None);
        // Bits below 7 never leak into the base.
        assert_eq!(pmbase_from_dword(0xFFFF_FFFF), Some(0xFF80));
        assert_eq!(PMBASE_MASK, 0xFF80);
        assert_eq!(PMBASE_RTE, 1);
    }

    /// TCO port math: the +0x60 window lands where expected, wraps
    /// refuse, and the PCI config port pair is never touched.
    #[test]
    fn tco_ports_are_bounds_checked() {
        assert_eq!(tco_port(0x600, TCO_RLD), Some(0x660));
        assert_eq!(tco_port(0x600, TCO1_CNT), Some(0x668));
        assert_eq!(tco_port(0x600, TCO_TMR), Some(0x672));
        assert_eq!(TCO_OFFSET, 0x60);
        assert_eq!(TCO_RLD, 0x00);
        assert_eq!(TCO1_CNT, 0x08);
        assert_eq!(TCO_TMR, 0x12);
        // A PMBASE that would push the TMR port past 0xFFFF refuses.
        assert_eq!(tco_port(0xFFC0, TCO_TMR), None);
        // Zero PMBASE (a masked-away base): refuse.
        assert_eq!(tco_port(0, TCO_RLD), None);
        // The window must not overlap 0xCF8/0xCFC.
        assert_eq!(tco_port(0x0C98, TCO_RLD), None, "RLD would land on 0xCF8");
        assert_eq!(
            tco_port(0x0CA8, TCO_RLD),
            Some(0xD08),
            "past the pair, fine"
        );
    }

    /// The TCO bit encodings, pinned against ich9_tco.h.
    #[test]
    fn tco_bits_are_pinned_against_qemu() {
        assert_eq!(TCO_TIMEOUT, 1 << 3);
        assert_eq!(TCO_TMR_HLT, 1 << 11);
        assert_eq!(TCO_LOCK, 1 << 12);
        assert_eq!(TCO_SECOND_TO_STS, 1 << 1);
        assert_eq!(TCO_BOOT_STS, 1 << 2);
        assert_eq!(TCO_TMR_MASK, 0x3FF);
    }

    /// The RCBA/GCS gate: base bits 31:14, enable bit 0, GCS offset
    /// and NO_REBOOT bit 5 — the CI-safety read the probe depends on.
    #[test]
    fn the_rcba_gate_decodes() {
        assert_eq!(rcba_from_dword(0xFED1_C001), Some(0xFED1_C000));
        assert_eq!(rcba_from_dword(0xFED1_C000), None, "disabled");
        assert_eq!(rcba_from_dword(0), None);
        assert_eq!(RCBA_MASK, 0xFFFF_C000);
        assert_eq!(GCS_OFFSET, 0x3410);
        assert_eq!(GCS_NO_REBOOT, 1 << 5);
        // QEMU's GCS default (0x20) IS no-reboot-set — the fact that
        // makes the lane's write path safe.
        assert!(0x20 & GCS_NO_REBOOT != 0);
    }

    /// The i6300esb encodings, pinned against wdt_i6300esb.c.
    #[test]
    fn esb_encodings_are_pinned_against_qemu() {
        assert_eq!((ESB_VENDOR, ESB_DEVICE), (0x8086, 0x25AB));
        assert_eq!(ESB_CONFIG_REG, 0x60);
        assert_eq!(ESB_LOCK_REG, 0x68);
        assert_eq!(ESB_TIMER1, 0x00);
        assert_eq!(ESB_TIMER2, 0x04);
        assert_eq!(ESB_RELOAD_REG, 0x0C);
        // Bit 5 SET in config masks reboot-on-timeout (QEMU:
        // reboot_enabled = (data & ESB_WDT_REBOOT) == 0).
        assert_eq!(ESB_WDT_REBOOT, 1 << 5);
        assert_eq!(esb_unlock_pair(), (0x80, 0x86));
        assert_eq!(ESB_RELOAD, 1 << 8);
        // The max preload the device latches (val & 0xfffff).
        assert_eq!(ESB_MAX_PRELOAD, 0xF_FFFF);
    }
}
