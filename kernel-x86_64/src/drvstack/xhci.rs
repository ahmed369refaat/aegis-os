//! xHCI: the operational + runtime registers, port detection, the command ring.

use crate::frames::FramePool;
use crate::mmio::{BarMmio, MmioBus};
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for xHCI frames (DCBAA + command ring).
pub const XHCI_OWNER: u32 = 48;

/// The port-scan cap: the register window must cover this many port
/// status registers before the scan trusts `max_ports` at all.
const PORT_SCAN_CAP: u64 = 16;

#[cfg(not(test))]
pub(crate) fn xhci_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x1B36, 0x0C) else {
        line(out, &["[XHCI] no xHCI to drive on this machine"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[XHCI] broker verdict absent — refusing to drive"]);
        return;
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[XHCI] BAR0 unresolved — refusing"]);
        return;
    };
    // ADR-0016: one window; the caps block first, then — once the
    // DEVICE-DERIVED caplen is read through it — the operational block
    // and the port bank, door-checked against the same window.
    let Some(bus) = BarMmio::new(bar.base, bar.size) else {
        line(
            out,
            &["[XHCI] BAR0 window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    if bus.window().len() < 0x20 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[XHCI] BAR0 window too small for the caps block (len=0x",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    // F9e: MEM now; BME after the bring-up frames are mapped.
    crate::pci::enable_mem(dev);
    let (Some(caplen8), Some(ver), Some(hcs1)) = (bus.read8(0), bus.read16(2), bus.read32(4))
    else {
        line(
            out,
            &["[XHCI] register window refused a caps read — refusing"],
        );
        return;
    };
    let caplen = u64::from(caplen8);
    let max_slots = hcs1 & 0xFF;
    let max_ports = hcs1 >> 24;
    let op = caplen; // window-relative operational base (device-derived)
    let ports = u64::from(max_ports).min(PORT_SCAN_CAP);
    if bus.window().len() < op + 0x400 + 0x10 * ports + 4 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[XHCI] BAR0 window too small for the port bank (len=0x",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    let mut h = [0u8; 20];
    let mut h2 = [0u8; 20];
    let mut h3 = [0u8; 20];
    line(
        out,
        &[
            "[XHCI] v",
            strutil::dec(u64::from(ver), &mut h),
            " caps: MaxSlots=",
            strutil::dec(u64::from(max_slots), &mut h2),
            " MaxPorts=",
            strutil::dec(u64::from(max_ports), &mut h3),
        ],
    );

    // Halt, reset, program, run.
    if !bus.write32(op, 0) {
        line(
            out,
            &["[XHCI] register window refused a USBCMD write — refusing"],
        );
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & 1 == 0) && spins < 4_000_000 {
        spins += 1;
    }
    let halted = bus.read32(op + 4).is_some_and(|v| v & 1 != 0);
    if !bus.write32(op, 2) {
        line(
            out,
            &["[XHCI] register window refused a USBCMD write — refusing"],
        );
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & (1 << 11) != 0) && spins < 8_000_000 {
        spins += 1;
    } // CNR clear

    // ADR-0016/F10: the session owns the bring-up frames; every exit
    // below is one close().
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        XHCI_OWNER,
        false,
        "[XHCI] teardown: revoke_all(0) → ",
        "",
    );
    let mut frames = [0u64; 2];
    for slot in frames.iter_mut() {
        match session.frame() {
            Some(pa) => *slot = pa,
            None => {
                line(out, &["[XHCI] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [dcbaa, cmdring] = frames;
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(out, &["[XHCI] broker refused a frame — refusing"]);
            return;
        }
    }
    // The frames are mapped — a refused write from here on is a full
    // teardown (the device is one BME grant from DMAing).
    if !(bus.write64(op + 0x30, dcbaa)
        && bus.write32(op + 0x38, max_slots)
        && bus.write64(op + 0x18, cmdring | 1)
        && bus.write32(op, 1))
    {
        line(
            out,
            &["[XHCI] register window refused a bring-up write — teardown"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & 1 != 0) && spins < 8_000_000 {
        spins += 1;
    }
    let running = bus.read32(op + 4).is_some_and(|v| v & 1 == 0);
    line(
        out,
        &[
            "[XHCI] halted=",
            if halted { "1" } else { "0" },
            " → reset → DCBAAP+MaxSlotsEn+CRCR → RUN=",
            if running { "1" } else { "0" },
            " (HCH cleared, broker frames 2)",
        ],
    );
    // F9e: the DCBAAP/CRCR frames are broker-mapped — DMA may start.
    crate::pci::enable_bus_master(dev);

    // Port scan: find the attached usb-kbd.
    let mut found: Option<(u32, u32)> = None;
    for p in 0..ports {
        let Some(psc) = bus.read32(op + 0x400 + 0x10 * p) else {
            line(
                out,
                &["[XHCI] port scan refused by the register window — stopping"],
            );
            break;
        };
        if psc & 1 != 0 {
            found = Some((p as u32, (psc >> 10) & 0xF));
            break;
        }
    }
    match found {
        Some((p, sp)) => {
            let mut hp = [0u8; 20];
            let mut hs = [0u8; 20];
            line(
                out,
                &[
                    "[XHCI] port ",
                    strutil::dec(u64::from(p), &mut hp),
                    " device attached, speed=",
                    strutil::dec(u64::from(sp), &mut hs),
                    " (1=full 2=low 3=high — the attached device detected)",
                ],
            );
        }
        None => {
            line(
                out,
                &["[XHCI] no device on any port (expected the usb-storage)"],
            );
        }
    }
    session.close(out);
}

/// Issue a No-Op command TRB on the command ring + doorbell 0, then
/// read back CRCR (the dequeue pointer advances only if the
/// controller DMAs the TRB) and the event-ring head.
#[cfg(not(test))]
pub(crate) fn xhci_cmdring_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x1B36, 0x0C) else {
        line(out, &["[XTRB] no xHCI — skipping"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[XTRB] broker verdict absent — refusing"]);
        return;
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[XTRB] BAR0 unresolved — refusing"]);
        return;
    };
    let Some(bus) = BarMmio::new(bar.base, bar.size) else {
        line(
            out,
            &["[XTRB] BAR0 window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    if bus.window().len() < 0x20 {
        line(
            out,
            &["[XTRB] BAR0 window too small for the caps block — refusing"],
        );
        return;
    }
    let (Some(caplen8), Some(dboff_raw), Some(rtsoff)) =
        (bus.read8(0), bus.read32(0x14), bus.read32(0x18))
    else {
        line(
            out,
            &["[XTRB] register window refused a caps read — refusing"],
        );
        return;
    };
    let caplen = u64::from(caplen8);
    let op = caplen; // window-relative operational base
    let dboff = u64::from(dboff_raw & 0xFFFF);
    // Interrupter 0 lives at rtsoff+0x20; its registers reach +0x18+8.
    let intr = u64::from(rtsoff) + 0x20;
    if bus.window().len() < op + 0x38 + 4
        || bus.window().len() < intr + 0x18 + 8
        || bus.window().len() < dboff + 4
    {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[XTRB] BAR0 window too small for the op/runtime/doorbell registers (len=0x",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    // The xHCI bring-up slice (xhci_step) already ran: RUN is on,
    // DCBAAP/CRCR point at ITS frames — which were freed+scrubbed at
    // its teardown! Re-bring-up with fresh frames here.
    if !bus.write32(op, 0) {
        line(
            out,
            &["[XTRB] register window refused a USBCMD write — refusing"],
        );
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & 1 == 0) && spins < 4_000_000 {
        spins += 1;
    }
    if !bus.write32(op, 2) {
        line(
            out,
            &["[XTRB] register window refused a USBCMD write — refusing"],
        );
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & (1 << 11) != 0) && spins < 8_000_000 {
        spins += 1;
    }

    // ADR-0016/F10: the session owns the ring frames; every exit
    // below is one close().
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        XHCI_OWNER,
        false,
        "[XTRB] teardown: revoke_all(0) → ",
        "",
    );
    // Frames: DCBAA, command ring, event ring, ERST (segment table).
    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match session.frame() {
            Some(pa) => *slot = pa,
            None => {
                line(out, &["[XTRB] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [dcbaa, cmdring, evring, erst] = frames;
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(out, &["[XTRB] broker refused a frame — refusing"]);
            return;
        }
    }
    // ERST entry 0: the event-ring segment (64 TRBs).
    crate::memops::write_u64(erst, evring);
    crate::memops::write_u64(erst + 8, 64);

    // The frames are mapped — refusals from here on are full teardowns.
    if !(bus.write64(op + 0x30, dcbaa)
        && bus.write32(op + 0x38, 1)
        && bus.write64(op + 0x18, cmdring | 1)
        // Interrupter 0: ERSTSZ=1, ERSTBA, ERDP.
        // (ERSTSZ: IMAN+0, IMOD+4, ERSTSZ+8)
        && bus.write32(intr + 0x08, 1)
        && bus.write64(intr + 0x10, erst)
        && bus.write64(intr + 0x18, evring)
        && bus.write32(op, 1))
    {
        line(
            out,
            &["[XTRB] register window refused a bring-up write — teardown"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & 1 != 0) && spins < 8_000_000 {
        spins += 1;
    }
    let crcr0 = bus.read64(op + 0x18).unwrap_or(0) & 0xFFFF_FFF0;

    // No-Op command TRB at slot 0: type=8 (bits 10-15 of dword 3),
    // cycle bit set to match CRCR's RCS=1.
    crate::memops::write_u64(cmdring, 0);
    crate::memops::write_u64(cmdring + 8, 0);
    crate::memops::write_u64(cmdring + 16, 0);
    crate::memops::write_u32(cmdring + 12, (8u32 << 10) | 1);
    if !bus.write32(dboff, 0) {
        // doorbell 0 = command ring
        line(
            out,
            &["[XTRB] register window refused the doorbell — teardown"],
        );
        session.close(out);
        return;
    }

    let mut spins = 0u64;
    let mut crcr1 = bus.read64(op + 0x18).unwrap_or(0) & 0xFFFF_FFF0;
    while crcr1 == crcr0 && spins < 10_000_000 {
        crcr1 = bus.read64(op + 0x18).unwrap_or(0) & 0xFFFF_FFF0;
        spins += 1;
    }
    let advanced = crcr1 != crcr0;
    // Event ring: a command-completion event TRB (type=33) at slot 0?
    let ev0 = crate::memops::read_u64(evring);
    let ev3 = crate::memops::read_u64(evring + 12);
    let ev_type = (crate::memops::read_u32(evring + 12) >> 10) & 0x3F;
    let _ = (ev0, ev3);
    // Success signal: the EVENT RING, not CRCR — the controller never
    // writes the dequeue pointer back into CRCR (it is load-bearing
    // only at halt); the command-completion event TRB (type 33) in
    // the event ring is the real proof the full TRB machinery ran:
    // ring DMA → execution → event post.
    let completed = ev_type == 33;
    let mut ha = [0u8; 20];
    line(
        out,
        &[
            "[XTRB] No-Op command: event-ring slot0 type=",
            strutil::dec(u64::from(ev_type), &mut ha),
            if completed {
                " = COMMAND COMPLETION — the command ring executed end-to-end (DMA + doorbell + event post)"
            } else {
                " (expected 33 = command completion)"
            },
        ],
    );
    let _ = advanced;
    session.close(out);
}
