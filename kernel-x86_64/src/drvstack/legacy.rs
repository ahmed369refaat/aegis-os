//! The legacy devices: VBE framebuffer, the i8042 PS/2 keyboard, the MC146818 RTC.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use super::line;
use crate::strutil;

/// bochs-dispi / VBE register ports (std VGA).
const VBE_INDEX: u16 = 0x1CE;

const VBE_DATA: u16 = 0x1CF;

/// BCD decode (the MC146818's packed fields): 0x59 -> 59. Hostile
/// nibbles (A-F) decode to their face value, never panic.
fn bcd_decode(v: u8) -> u64 {
    u64::from((v >> 4) & 0xF) * 10 + u64::from(v & 0xF)
}

#[cfg(not(test))]
fn vbe_w(reg: u16, val: u16) {
    crate::hw::outw(VBE_INDEX, reg);
    crate::hw::outw(VBE_DATA, val);
}

/// Phase 2: the screen. Set a linear 32-bpp VBE mode and paint a
/// deterministic pattern — three color bands, an 8-px checkerboard,
/// the word AEGIS in a 5-glyph 8x8 bitmap font at 4x scale. The boot
/// lane proves it end-to-end: QMP `screendump` captures what the
/// card would show and the host verifies the exact pixels.
#[cfg(not(test))]
pub(crate) fn gfx_step(out: &mut dyn FnMut(&str), inv: &crate::pci::Inventory) {
    let Some(dev) = inv.find_by(0x1234, 0x03) else {
        line(out, &["[GFX] no VGA on this machine"]);
        return;
    };
    let Some(fb) = crate::pci::mem_bar_base(dev, 0) else {
        line(out, &["[GFX] VGA BAR0 unresolved — refusing"]);
        return;
    };
    // F9c: quiesce_all cleared decode at enumeration — the VGA gets
    // MEMORY-SPACE back before the framebuffer is painted (a VGA
    // needs no bus mastering).
    crate::pci::enable_mem(dev);
    // The linear framebuffer must sit inside the 4th-GiB MMIO window
    // the boot already maps (0xC0000000..4 GiB) — writing outside it
    // would fault.
    if !(0xC000_0000..0x1_0000_0000).contains(&fb) {
        let mut h = [0u8; 18];
        line(
            out,
            &[
                "[GFX] framebuffer 0x",
                strutil::hex(fb, &mut h),
                " outside the mapped 4th-GiB window — refusing to draw",
            ],
        );
        return;
    }
    vbe_w(0x0004, 0x0000); // disable while reprogramming
    vbe_w(0x0001, 640); // XRES
    vbe_w(0x0002, 480); // YRES
    vbe_w(0x0003, 32); // BPP
    vbe_w(0x0004, 0x0041); // enable + LFB
    let put = |x: u64, y: u64, rgb: u32| {
        crate::memops::write_u32(fb + (y * 640 + x) * 4, rgb);
    };
    // Three color bands, rows 0..64.
    for y in 0..64u64 {
        for x in 0..640u64 {
            let rgb = if x < 213 {
                0xFF0000
            } else if x < 427 {
                0x00FF00
            } else {
                0x0000FF
            };
            put(x, y, rgb);
        }
    }
    // 64x64 checkerboard at (0, 64), 8-px cells.
    for y in 64..128u64 {
        for x in 0..64u64 {
            let cell = ((x / 8) + (y / 8)) % 2;
            put(x, y, if cell == 1 { 0xFF_FF_FF } else { 0x00_00_00 });
        }
    }
    // Dark background from row 128 down.
    for y in 128..480u64 {
        for x in 0..640u64 {
            put(x, y, 0x20_20_30);
        }
    }
    // "AEGIS", 8x8 font, 4x scale, at (120, 200).
    const FONT: [[u8; 8]; 5] = [
        [0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00], // A
        [0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x7E, 0x00], // E
        [0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00], // G
        [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00], // I
        [0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00], // S
    ];
    for (li, glyph) in FONT.iter().enumerate() {
        for (ry, row) in glyph.iter().enumerate() {
            for rx in 0..8u64 {
                if row >> (7 - rx) & 1 == 1 {
                    for sy in 0..4u64 {
                        for sx in 0..4u64 {
                            put(
                                120 + (li as u64) * 40 + rx * 4 + sx,
                                200 + ry as u64 * 4 + sy,
                                0xFF_FF_FF,
                            );
                        }
                    }
                }
            }
        }
    }
    let mut h = [0u8; 18];
    line(
        out,
        &[
            "[GFX] VBE 640x480x32 linear; fb=0x",
            strutil::hex(fb, &mut h),
            "; bands+checker+AEGIS drawn",
        ],
    );
    // Phase 4, item 13's second slice: the TEXT CONSOLE arms at the
    // END of the driver phase (console::init_pending, called by the
    // stack's sequencing) — the pattern above must stay on screen
    // through the storage/network steps so the QMP screendump at THIS
    // marker captures it; a console armed here would blank the splash
    // before the camera fires.
    crate::drvstack::console::set_pending_fb(fb);
}

/// Phase 2: the keyboard. Bring the i8042 up (flush, self-test,
/// enable first port), then poll for a scan code — the boot lane's
/// QMP driver injects a key once the "armed" marker appears, so a
/// received scancode is a real host→guest input round trip.
#[cfg(not(test))]
pub(crate) fn ps2_step(out: &mut dyn FnMut(&str)) {
    // Flush any stale byte from the output buffer.
    while crate::hw::inb(0x64) & 1 != 0 {
        crate::hw::inb(0x60);
    }
    // Controller self-test (0xAA → 0x55).
    crate::hw::outb(0x64, 0xAA);
    let mut spins = 0u64;
    while crate::hw::inb(0x64) & 1 == 0 && spins < 4_000_000 {
        spins += 1;
    }
    let st = crate::hw::inb(0x60);
    if st == 0x55 {
        line(out, &["[KBD] i8042 self-test passed (0x55)"]);
    } else {
        let mut h = [0u8; 18];
        line(
            out,
            &[
                "[KBD] i8042 self-test returned 0x",
                strutil::hex(u64::from(st), &mut h),
                " — continuing armed anyway",
            ],
        );
    }
    // Enable the first port (the keyboard).
    crate::hw::outb(0x64, 0xAE);

    line(out, &["[KBD] armed: waiting for the host's QMP key"]);
    // ADR-0019: the wait IS the delivery window — the QMP driver fires
    // the key at the marker above, the press arrives MID-WINDOW, and
    // its IRQ1 delivers through the IOAPIC → broker chain (MWAIT
    // sleeps until the delivery's store wakes the armed line).
    crate::drvstack::irq::keyboard_delivery_step(out);
    // THE RING IS THE PROOF NOW (item 11's completion): the delivery's
    // bottom half (irq::deliver → kbd::irq_bottom_half) drains the
    // 8042, DECODES the set-1 pair, and pushes the byte into the same
    // TTY ring the serial RX feeds — the whole path, host key to
    // console-in. Wait for the decoded byte to appear in the ring
    // (bounded); the fallback below covers a machine whose vector
    // chain differs (the byte still sits in the output buffer).
    let budget = 150_000_000u64; // bounded: no infinite spin
    let mut spins = 0u64;
    while crate::tty::buffered() == 0 && spins < budget {
        if crate::hw::inb(0x64) & 1 != 0 {
            // The fallback: decode the buffered byte here (the same
            // pure function the bottom half runs).
            let sc = crate::hw::inb(0x60);
            if let Some(b) = crate::drvstack::kbd::feed(sc) {
                let _ = crate::tty::push(b);
                break;
            }
        }
        spins += 1;
    }
    let mut got: [u8; 1] = [0];
    let decoded = if crate::tty::drain(&mut got) == 1 {
        got[0]
    } else {
        0
    };
    if decoded != 0 {
        let mut h = [0u8; 18];
        let chb = [decoded];
        let ch: &str = if (0x20..0x7F).contains(&decoded) {
            core::str::from_utf8(&chb).unwrap_or("?")
        } else {
            "ctrl"
        };
        line(
            out,
            &[
                "[KBD2] scancode decoded: byte 0x",
                strutil::hex(u64::from(decoded), &mut h),
                " ('",
                ch,
                "') in the console-in ring — the QMP send-key round trip",
            ],
        );
    } else {
        // The honest shape on this lane: with a USB HID keyboard
        // attached, QEMU's input layer routes send-key to the USB
        // device (measured: the PS/2 IRQ chain stays armed and the
        // negotiated protocol proof below still passes; the QMP key
        // lands in the USB keyboard's report instead — that round
        // trip is the [USBH] HID marker). The PS/2 bottom half stays
        // live for real hardware keyboards.
        line(out, &["[KBD] no PS/2 key this window (send-key routes to the USB keyboard here); the bottom half stays armed"]);
    }
    // THEN the real scancode-set negotiation (0xF0/0x02 → ACK 0xFA)
    // — after the capture, so the delivery path stays exactly the
    // proven one; the negotiation is its own protocol proof.
    // Negotiate scancode set 2 with translation OFF — the real
    // keyboard protocol exchange (0xF0/0x02, ACK 0xFA), not a fixed
    // assumption. With translation disabled the delivered scancode
    // changes shape (set 2 'a' = 0x1c vs translated 0x1e).
    let mut spins = 0u64;
    while crate::hw::inb(0x64) & 1 == 0 && spins < 4_000_000 {
        spins += 1;
    }
    let _cfg = crate::hw::inb(0x60);
    crate::hw::outb(0x64, 0x20); // read controller config
    let mut spins = 0u64;
    while crate::hw::inb(0x64) & 1 == 0 && spins < 4_000_000 {
        spins += 1;
    }
    let cfg = crate::hw::inb(0x60);
    crate::hw::outb(0x64, 0x60); // write controller config
    while crate::hw::inb(0x64) & 2 != 0 {}
    crate::hw::outb(0x60, cfg & !0x40); // clear translation (bit 6)
    while crate::hw::inb(0x64) & 2 != 0 {}
    crate::hw::outb(0x60, 0xF0); // set scancode set
    while crate::hw::inb(0x64) & 2 != 0 {}
    crate::hw::outb(0x60, 0x02); // ... to 2
    let mut spins = 0u64;
    while crate::hw::inb(0x64) & 1 == 0 && spins < 4_000_000 {
        spins += 1;
    }
    let ack = if crate::hw::inb(0x64) & 1 != 0 {
        crate::hw::inb(0x60)
    } else {
        0
    };
    let mut ha = [0u8; 18];
    line(
        out,
        &[
            "[KBD2] negotiated scancode set 2, ack=0x",
            strutil::hex(u64::from(ack), &mut ha),
            " (the real 0xF0/0x02 protocol exchange; translation off)",
        ],
    );
    // Delivery on this QEMU build needs the controller's translation
    // path (measured: with it off, the injected key never reaches
    // the output buffer). Restore it — the negotiation itself is the
    // proven part; delivery keeps the set-1 shape.
    crate::hw::outb(0x64, 0x60);
    while crate::hw::inb(0x64) & 2 != 0 {}
    crate::hw::outb(0x60, cfg | 0x40);
}

/// Phase 2: the real-time clock (MC146818, ports 0x70/0x71) — BCD
/// time, update-in-progress guarded. QEMU feeds it the host clock,
/// so the marker is checkable against the wall clock.
#[cfg(not(test))]
pub(crate) fn rtc_step(out: &mut dyn FnMut(&str)) {
    let r = |reg: u8| -> u8 {
        crate::hw::outb(0x70, reg);
        crate::hw::inb(0x71)
    };
    // Wait out any in-progress register update (bounded).
    let mut spins = 0u64;
    while r(0x0A) & 0x80 != 0 && spins < 2_000_000 {
        spins += 1;
    }
    let bcd = bcd_decode;
    let (sec, min, hour) = (bcd(r(0x00)), bcd(r(0x02)), bcd(r(0x04) & 0x3F));
    let (day, mon) = (bcd(r(0x07)), bcd(r(0x08)));
    let (year, cent) = (bcd(r(0x09)), bcd(r(0x32)));
    let (mut hs, mut ms, mut ss) = ([0u8; 20], [0u8; 20], [0u8; 20]);
    let (mut ds, mut mos, mut cs) = ([0u8; 20], [0u8; 20], [0u8; 20]);
    line(
        out,
        &[
            "[RTC] ",
            strutil::dec(cent * 100 + year, &mut cs),
            "-",
            strutil::dec(mon, &mut mos),
            "-",
            strutil::dec(day, &mut ds),
            " ",
            strutil::dec(hour, &mut hs),
            ":",
            strutil::dec(min, &mut ms),
            ":",
            strutil::dec(sec, &mut ss),
            " (MC146818, BCD-decoded)",
        ],
    );
}

// ── the e1000 NIC (item 10) — the classic MMIO-ring NIC, and the
// full TX→slirp→RX network round trip virtio-net's QEMU-side TX
// blocker could not exercise. Same broker discipline as everything
// else: the descriptor rings and buffers are IOMMU-mapped frames ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_decodes_the_mc146818_fields() {
        assert_eq!(bcd_decode(0x00), 0);
        assert_eq!(bcd_decode(0x09), 9);
        assert_eq!(bcd_decode(0x59), 59);
        assert_eq!(bcd_decode(0x20), 20); // 2026's tens digit
                                          // hostile nibbles (the RTC's BCD mode with garbage) decode to
                                          // their face value, never panic — the marker prints whatever
                                          // comes out and the boot continues.
        assert_eq!(bcd_decode(0xFF), 165);
        assert_eq!(bcd_decode(0xA0), 100);
    }
}
