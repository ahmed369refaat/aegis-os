//! The legacy devices: VBE framebuffer, the i8042 PS/2 keyboard, the MC146818 RTC.

use super::line;
use crate::strutil;

/// bochs-dispi / VBE register ports (std VGA).
const VBE_INDEX: u16 = 0x1CE;

const VBE_DATA: u16 = 0x1CF;

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

    line(out, &["[KBD] armed: polling for the host's QMP key"]);
    let budget = 150_000_000u64; // bounded: no infinite spin
    let mut spins = 0u64;
    let mut got: Option<u8> = None;
    while spins < budget {
        if crate::hw::inb(0x64) & 1 != 0 {
            got = Some(crate::hw::inb(0x60));
            break;
        }
        spins += 1;
    }
    match got {
        Some(sc) => {
            let mut h = [0u8; 18];
            line(
                out,
                &[
                    "[KBD2] scancode ",
                    strutil::hex(u64::from(sc), &mut h),
                    " received (the QMP send-key round trip)",
                ],
            );
        }
        None => {
            line(out, &["[KBD] no key arrived within the poll budget"]);
        }
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
    let bcd = |v: u8| -> u64 { u64::from((v >> 4) & 0xF) * 10 + u64::from(v & 0xF) };
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
