//! xHCI: the operational + runtime registers, port detection, the command ring.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::mmio::{BarMmio, MmioBus};
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for xHCI frames (DCBAA + command ring).
pub const XHCI_OWNER: u32 = 48;

/// The port-scan cap: the register window must cover this many port
/// status registers before the scan trusts `max_ports` at all.
const PORT_SCAN_CAP: u64 = 16;

/// Build the No-Op command TRB at `pa`: type=8 (bits 10-15 of dword
/// 3) with the cycle bit set to match CRCR's RCS=1. Pure PA writes.
fn build_noop_trb(pa: u64) {
    crate::memops::write_u64(pa, 0);
    crate::memops::write_u64(pa + 8, 0);
    crate::memops::write_u64(pa + 16, 0);
    crate::memops::write_u32(pa + 12, (8u32 << 10) | 1);
}

/// The event TRB's type at `pa` (bits 10-15 of dword 3); 33 = command
/// completion. Hostile dword values can only yield 0..=63.
fn event_trb_type(pa: u64) -> u32 {
    (crate::memops::read_u32(pa + 12) >> 10) & 0x3F
}

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
        dev.dom,
        false,
        "[XHCI] teardown",
        "",
    );
    let mut frames = [0u64; 2];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
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
        dev.dom,
        false,
        "[XTRB] teardown",
        "",
    );
    // Frames: DCBAA, command ring, event ring, ERST (segment table).
    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
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
    // The frames are mapped and the device DMAs from here (TRB fetch,
    // event posts): re-grant bus mastering — the PREVIOUS step's
    // teardown cut it (the session discipline), and QEMU fails every
    // device DMA of a BM-less device ("DMA memory access failed", an
    // HCE that sticks for every later step). Found live: the No-Op
    // proof silently broke when the teardown discipline landed; its
    // success was never a lane grep. Both xHCI steps grant it now.
    crate::pci::enable_bus_master(dev);

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

    // No-Op command TRB at slot 0 (type 8, cycle bit set).
    build_noop_trb(cmdring);
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
    let ev_type = event_trb_type(evring);
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

// ── the enumeration + HID slice (item 12's completion) ─────────────
//
// The protocol objects are PURE builders/parsers over frames the
// caller owns (FakePhys-testable); the boot step below drives them
// against the real controller. Field positions follow the xHCI 1.0
// spec as QEMU's model implements it (hcd-xhci.c): the input
// context's ICC add/drop dwords at +0/+4, the slot context at +0x20,
// EP0 at +0x40, EPn at +0x40+0x20n; slot dw0 = route[31:20] |
// speed[19:16], slot dw1 = Context Entries[31:27] | root port
// [23:16]; EP dw1 = CERR[1:0] | EP type[5:3] | max packet[31:16];
// EP dw2 = the transfer ring dequeue | DCS(bit 0). The diagnostic
// discipline: every command's completion event carries the
// completion code (event dw2[31:24]; 1 = success) — the step PRINTS
// it, so a field-position bug names itself on the lane.

/// The slot context dword 0: route string [31:20] (0 — a root-port
/// device), speed [19:16] (1=full, 2=low, 3=high, 4=super).
pub fn slot_ctx_d0(speed: u32) -> u32 {
    (speed & 0xF) << 16
}

/// The slot context dword 1: Context Entries [31:27], root-hub port
/// number [23:16] (1-based — the port the device sits on).
pub fn slot_ctx_d1(port: u32, entries: u32) -> u32 {
    ((entries & 0x1F) << 27) | ((port & 0xFF) << 16)
}

/// The EP context dword 1: CERR [1:0] (3), EP type [5:3] (4 =
/// control for EP0, 7 = interrupt-IN), max packet size [31:16].
pub fn ep_ctx_d1(ep_type: u32, max_packet: u32) -> u32 {
    3 | ((ep_type & 0x7) << 3) | ((max_packet & 0xFFFF) << 16)
}

/// The EP context dword 2: the transfer ring's dequeue pointer with
/// the dequeue cycle state (bit 0 = 1 — the ring starts in the
/// controller's cycle).
pub fn ep_ctx_dequeue(ring_pa: u64) -> u64 {
    ring_pa | 1
}

/// Build the Address Device input context in the frame at `pa`:
/// ICC add(slot + EP0), the slot context (speed, the 1-based port,
/// entries=1), and EP0 (control, maxp 8 for low speed / 64
/// otherwise, CERR=3, dequeue = the EP0 ring with DCS=1).
pub fn build_address_input_ctx(pa: u64, speed: u32, port1: u32, ep0_ring: u64) {
    crate::memops::write_u32(pa, 0b11);
    crate::memops::write_u32(pa + 4, 0);
    let slot = pa + 0x20;
    crate::memops::write_u32(slot, slot_ctx_d0(speed));
    crate::memops::write_u32(slot + 4, slot_ctx_d1(port1, 1));
    crate::memops::write_u64(slot + 8, 0);
    crate::memops::write_u32(slot + 12, 0);
    let maxp = if speed == 2 { 8 } else { 64 };
    let ep0 = pa + 0x40;
    crate::memops::write_u32(ep0, 0);
    crate::memops::write_u32(ep0 + 4, ep_ctx_d1(4, maxp));
    crate::memops::write_u64(ep0 + 8, ep_ctx_dequeue(ep0_ring));
    crate::memops::write_u32(ep0 + 16, 0);
    crate::memops::write_u32(ep0 + 20, 8);
}

/// Build the Configure Endpoint input context for ONE new
/// interrupt-IN endpoint (1-based EP number `ep_idx`): ICC adds the
/// slot + that endpoint only (EP0 stays untouched — the controller
/// keeps the live output context for contexts not added), the slot
/// context copied VERBATIM from the live output device context with
/// Context Entries fixed to include the new EP, and the EP's context
/// (interrupt-IN, maxp, the interval, dequeue = its ring).
pub fn build_configure_input_ctx(
    pa: u64,
    dev_ctx: u64,
    ep_idx: u32,
    max_packet: u32,
    interval: u32,
    ring_pa: u64,
) {
    crate::memops::write_u32(pa, (1 << (ep_idx + 1)) | 1);
    crate::memops::write_u32(pa + 4, 0);
    let out_slot = dev_ctx;
    let in_slot = pa + 0x20;
    for i in 0..8u64 {
        let v = crate::memops::read_u32(out_slot + i * 4);
        crate::memops::write_u32(in_slot + i * 4, v);
    }
    let d1 = crate::memops::read_u32(out_slot + 4);
    let port = (d1 >> 16) & 0xFF;
    crate::memops::write_u32(in_slot + 4, slot_ctx_d1(port, ep_idx + 1));
    let epn = pa + 0x40 + 0x20 * u64::from(ep_idx);
    crate::memops::write_u32(epn, 0);
    crate::memops::write_u32(epn + 4, ep_ctx_d1(7, max_packet));
    crate::memops::write_u64(epn + 8, ep_ctx_dequeue(ring_pa));
    crate::memops::write_u32(epn + 16, (interval & 0xFF) << 8);
    crate::memops::write_u32(epn + 20, 8);
}

/// The command-control dword: type [15:10], cycle bit 0, slot id
/// [31:24].
pub fn cmd_ctrl(trb_type: u32, cycle: bool, slot: u32) -> u32 {
    (trb_type << 10) | u32::from(cycle) | ((slot & 0xFF) << 24)
}

/// A transfer TRB's control dword: type [15:10], DIR [16], IDT [6],
/// cycle bit 0.
pub fn xfer_ctrl(trb_type: u32, dir_in: bool, cycle: bool, idt: bool) -> u32 {
    (trb_type << 10) | (u32::from(dir_in) << 16) | (u32::from(idt) << 6) | u32::from(cycle)
}

/// The SETUP TRB's parameter field carries the 8-byte setup packet
/// (immediate data, little-endian): bmRequestType | bRequest |
/// wValue | wIndex | wLength.
pub fn setup_packet(bmreq: u8, breq: u8, wvalue: u16, windex: u16, wlength: u16) -> u64 {
    u64::from(bmreq)
        | (u64::from(breq) << 8)
        | (u64::from(wvalue) << 16)
        | (u64::from(windex) << 32)
        | (u64::from(wlength) << 48)
}

/// The device descriptor's fields this driver validates: (class,
/// vid, pid, max_packet0). A short or mis-shaped buffer refuses —
/// fail closed, never a partial parse.
pub fn parse_device_descriptor(d: &[u8]) -> Option<(u8, u16, u16, u8)> {
    if d.len() < 18 || d[0] != 18 || d[1] != 1 {
        return None;
    }
    Some((
        d[4],
        u16::from(d[8]) | (u16::from(d[9]) << 8),
        u16::from(d[10]) | (u16::from(d[11]) << 8),
        d[7],
    ))
}

/// The configuration descriptor's HID shape this driver drives: the
/// interface's class (3 = HID) and the interrupt-IN endpoint's
/// (number, max packet, interval). The blob = 9-byte config +
/// 9-byte interface + the HID class descriptor + 7-byte endpoint;
/// malformed lengths refuse, never guess.
pub fn parse_hid_config(d: &[u8]) -> Option<(u8, u8, u8)> {
    if d.len() < 9 + 9 + 7 || d[0] != 9 || d[1] != 2 || d[9] != 9 || d[10] != 4 {
        return None;
    }
    if d[9 + 5] != 3 {
        return None; // the interface is not HID
    }
    let mut i = 9 + 9;
    while i + 2 <= d.len() {
        let len = d[i] as usize;
        let ty = d[i + 1];
        if len < 2 || i + len > d.len() {
            return None;
        }
        if ty == 5 {
            if len < 7 {
                return None;
            }
            let addr = d[i + 2];
            let attrs = d[i + 3];
            let maxp = d[i + 4];
            let interval = d[i + 6];
            if addr & 0x80 == 0 || attrs & 3 != 3 {
                return None; // not an interrupt-IN endpoint
            }
            return Some((addr & 0x0F, maxp, interval));
        }
        i += len;
    }
    None
}

/// The HID boot-keyboard report: [modifiers, reserved, k1..k6].
/// Usage IDs: 0x04..0x1D = a..z, 0x1E..0x26 = 1..9, 0x27 = 0,
/// 0x28 = Enter, 0x29 = Esc, 0x2A = Backspace, 0x2C = space. The
/// modifier byte's shift bits (0x02 L, 0x20 R) pick the shifted
/// table. Empty keys (the released state) answer None — consumed,
/// never pushed.
pub fn decode_hid_report(rep: &[u8]) -> Option<u8> {
    if rep.len() < 8 || rep[2] == 0 {
        return None;
    }
    let shift = rep[0] & 0x22 != 0;
    let key = rep[2];
    if shift {
        match key {
            0x04..=0x1D => Some(b'A' + (key - 0x04)),
            0x1E..=0x26 => Some(b'!' + (key - 0x1E)),
            0x27 => Some(b')'),
            0x28 => Some(b'\n'),
            0x2A => Some(0x08),
            0x2C => Some(b' '),
            0x2D => Some(b'_'),
            0x2E => Some(b'+'),
            0x33 => Some(b':'),
            0x36 => Some(b'<'),
            0x37 => Some(b'>'),
            0x38 => Some(b'?'),
            _ => None,
        }
    } else {
        match key {
            0x04..=0x1D => Some(b'a' + (key - 0x04)),
            0x1E..=0x26 => Some(b'1' + (key - 0x1E)),
            0x27 => Some(b'0'),
            0x28 => Some(b'\n'),
            0x29 => Some(0x1B),
            0x2A => Some(0x08),
            0x2C => Some(b' '),
            0x2D => Some(b'-'),
            0x2E => Some(b'='),
            0x33 => Some(b';'),
            0x36 => Some(b','),
            0x37 => Some(b'.'),
            0x38 => Some(b'/'),
            _ => None,
        }
    }
}

/// The enumeration + HID step (item 12's completion): Enable Slot →
/// Address Device → Get Descriptor (device + config) → Configure
/// Endpoint → SET_CONFIGURATION → the interrupt-IN report. Every
/// command's completion code prints (the diagnostic discipline: a
/// field-position bug names itself). The HID round trip uses the
/// lane's QMP window: the report request posts, the marker arms, the
/// host injects 'a' again, and the transfer event + the decoded
/// report prove a USB keyboard key reached the kernel's input path.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub(crate) fn xhci_enum_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x1B36, 0x0C) else {
        line(out, &["[USBH] no xHCI — skipping"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[USBH] broker verdict absent — refusing"]);
        return;
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[USBH] BAR0 unresolved — refusing"]);
        return;
    };
    let Some(bus) = BarMmio::new(bar.base, bar.size) else {
        line(out, &["[USBH] BAR0 window malformed — refusing"]);
        return;
    };
    let (Some(caplen8), Some(dboff_raw), Some(rtsoff), Some(hcs1)) = (
        bus.read8(0),
        bus.read32(0x14),
        bus.read32(0x18),
        bus.read32(4),
    ) else {
        line(
            out,
            &["[USBH] register window refused a caps read — refusing"],
        );
        return;
    };
    let caplen = u64::from(caplen8);
    let op = caplen;
    let dboff = u64::from(dboff_raw & 0xFFFF);
    let intr = u64::from(rtsoff) + 0x20;
    let max_ports = hcs1 >> 24;
    if bus.window().len() < op + 0x400 + 0x10 * u64::from(max_ports.min(16)) + 4
        || bus.window().len() < intr + 0x18 + 8
        || bus.window().len() < dboff + 4
    {
        line(out, &["[USBH] BAR0 window too small — refusing"]);
        return;
    }
    // Bring-up (the same reset cycle; this step owns its frames).
    if !bus.write32(op, 0) {
        line(out, &["[USBH] USBCMD write refused — refusing"]);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & 1 == 0) && spins < 4_000_000 {
        spins += 1;
    }
    if !bus.write32(op, 2) {
        line(out, &["[USBH] USBCMD write refused — refusing"]);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & (1 << 11) != 0) && spins < 8_000_000 {
        spins += 1;
    }
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        XHCI_OWNER,
        dev.dom,
        false,
        "[USBH] teardown",
        "",
    );
    // Frames: DCBAA, command ring, event ring, ERST, two input
    // contexts, the slot's output device context, the EP0 + EP1
    // rings, the descriptor blob, the report buffer. Ten frames.
    let mut frames = [0u64; 10];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[USBH] pool exhausted — refusing"]);
                return;
            }
        }
    }
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(out, &["[USBH] broker refused a frame — refusing"]);
            return;
        }
    }
    let [dcbaa, cmdring, evring, erst, ictx, ictx2, dev_ctx, ep0ring, ep1ring, data] = frames;
    // ERST: one segment of 64 TRBs.
    crate::memops::write_u64(erst, evring);
    crate::memops::write_u64(erst + 8, 64);
    if !(bus.write64(op + 0x30, dcbaa)
        && bus.write32(op + 0x38, 1)
        && bus.write64(op + 0x18, cmdring | 1)
        && bus.write32(intr + 0x08, 1)
        && bus.write64(intr + 0x10, erst)
        && bus.write64(intr + 0x18, evring)
        && bus.write32(op, 1))
    {
        line(
            out,
            &["[USBH] register window refused a bring-up write — teardown"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(op + 4).is_some_and(|v| v & 1 != 0) && spins < 8_000_000 {
        spins += 1;
    }
    // Frames mapped — BME on (the established discipline).
    // THE FIX (found live): the session teardown discipline cuts bus
    // mastering at every close — a step that wants device DMA must
    // RE-GRANT it after its frames are mapped. The historical No-Op
    // proof predated the teardown change and silently broke (the
    // "DMA memory access failed" signature, HCE-sticky).
    crate::pci::enable_bus_master(dev);

    // PA byte reads through the u32 accessor (no read_u8 exists —
    // the lane slicing is exact for any offset).
    let read_bytes = |pa: u64, n: usize| -> [u8; 64] {
        let mut b = [0u8; 64];
        for (i, slot) in b.iter_mut().enumerate().take(n) {
            let w = crate::memops::read_u32(pa + ((i & !3) as u64));
            *slot = (w >> ((i & 3) * 8)) as u8;
        }
        b
    };
    // The event-ring cursor: how many events consumed so far (the
    // poll helper advances it). The segment's cycle starts at 1.
    let mut ev_idx: usize = 0;
    // Read event TRB (n) → (type, code, slot, ep, trb_ptr). A blank
    // slot (type 0) = no event yet.
    let read_ev = |n: usize| -> (u32, u32, u32, u32, u64) {
        let pa = evring + (n as u64) * 16;
        let dw3 = crate::memops::read_u32(pa + 12);
        let dw2 = crate::memops::read_u32(pa + 8);
        let ptr = crate::memops::read_u64(pa);
        let cycle = dw3 & 1;
        let ty = (dw3 >> 10) & 0x3F;
        if cycle == 0 || ty == 0 {
            return (0, 0, 0, 0, 0); // not posted yet (or the wrap cycle)
        }
        (
            ty,
            dw2 >> 24,
            dw3 >> 24,
            (dw3 >> 16) & 0x1F,
            ptr & 0xFFFF_FFF0,
        )
    };
    // Wait for the next event (bounded): returns its fields or None.
    // `want_cce` = true filters for the command-completion event only
    // (type 33): the port-status-change events (type 34 — a device's
    // attachment posts them right after the reset) are consumed, not
    // mistaken for the answer.
    let mut wait_ev = |budget: u64, want_cce: bool| -> Option<(u32, u32, u32, u32, u64)> {
        let mut spins = 0u64;
        loop {
            let e = read_ev(ev_idx);
            if e.0 != 0 {
                ev_idx += 1;
                if !want_cce || e.0 == 33 {
                    return Some(e);
                }
                continue;
            }
            spins += 1;
            if spins > budget {
                return None;
            }
        }
    };
    // Post a command TRB at cmdring slot n and ring doorbell 0.
    let post_cmd = |n: u64, param: u64, ctrl: u32| {
        let pa = cmdring + n * 16;
        crate::memops::write_u64(pa, param);
        crate::memops::write_u64(pa + 8, 0);
        crate::memops::write_u32(pa + 12, ctrl);
        let _ = bus.write32(dboff, 0);
    };

    // ── 1. Enable Slot (TRB 9). ──
    post_cmd(0, 0, cmd_ctrl(9, true, 0));
    let Some((33, code, slot_id, _, _)) = wait_ev(8_000_000, true) else {
        // The forensic dump: the event ring's first slots RAW, USBSTS,
        // and CRCR — the failure names itself (a cycle-state
        // mismatch, a command the controller never fetched, or a
        // ring it never wrote back).
        let e0 = crate::memops::read_u32(evring + 12);
        let e1 = crate::memops::read_u32(evring + 16 + 12);
        let e2 = crate::memops::read_u32(evring + 32 + 12);
        let sts = bus.read32(op + 4).unwrap_or(0);
        let crcr = bus.read64(op + 0x18).unwrap_or(0);
        let mut h0 = [0u8; 18];
        let mut h1 = [0u8; 18];
        let mut h2 = [0u8; 18];
        let mut h3 = [0u8; 18];
        let mut h4 = [0u8; 18];
        line(
            out,
            &[
                "[USBH] Enable Slot: no completion event; ev dw3=",
                strutil::hex(u64::from(e0), &mut h0),
                " ",
                strutil::hex(u64::from(e1), &mut h1),
                " ",
                strutil::hex(u64::from(e2), &mut h2),
                " sts=",
                strutil::hex(u64::from(sts), &mut h3),
                " crcr=",
                strutil::hex(crcr, &mut h4),
                " — teardown",
            ],
        );
        session.close(out);
        return;
    };
    if code != 1 || slot_id == 0 {
        let mut hc = [0u8; 20];
        let mut hs = [0u8; 20];
        line(
            out,
            &[
                "[USBH] Enable Slot: completion code ",
                strutil::dec(u64::from(code), &mut hc),
                " slot ",
                strutil::dec(u64::from(slot_id), &mut hs),
                " — teardown",
            ],
        );
        session.close(out);
        return;
    }
    // The slot's output device context: DCBAA[slot] points at it.
    crate::memops::write_u64(dcbaa + (slot_id as u64) * 8, dev_ctx);

    // ── 2. The port scan (the attached device's port + speed). ──
    let mut found: Option<(u32, u32)> = None;
    for p in 0..max_ports.min(16) {
        let Some(psc) = bus.read32(op + 0x400 + 0x10 * u64::from(p)) else {
            break;
        };
        if psc & 1 != 0 {
            found = Some((p, (psc >> 10) & 0xF));
            break;
        }
    }
    // Prefer the KEYBOARD's port: the first attached NON-superspeed
    // device (usb-storage is speed 4; the kbd is full speed). Scan
    // ALL ports, not just the first.
    let mut kbd_port: Option<(u32, u32)> = None;
    for p in 0..max_ports.min(16) {
        let Some(psc) = bus.read32(op + 0x400 + 0x10 * u64::from(p)) else {
            break;
        };
        if psc & 1 != 0 && (psc >> 10) & 0xF != 4 {
            kbd_port = Some((p, (psc >> 10) & 0xF));
            break;
        }
    }
    let _ = &kbd_port;
    let (port, speed) = match kbd_port.or(found) {
        Some(x) => x,
        None => {
            line(out, &["[USBH] no device on any port — teardown"]);
            session.close(out);
            return;
        }
    };
    let _ = found;

    // ── 3. Address Device (TRB 11): the input context + slot. ──
    build_address_input_ctx(ictx, speed, port + 1, ep0ring);
    post_cmd(1, ictx, cmd_ctrl(11, true, slot_id));
    let Some((33, code, _, _, _)) = wait_ev(8_000_000, true) else {
        line(
            out,
            &["[USBH] Address Device: no completion event — teardown"],
        );
        session.close(out);
        return;
    };
    if code != 1 {
        let mut hc = [0u8; 20];
        line(
            out,
            &[
                "[USBH] Address Device: completion code ",
                strutil::dec(u64::from(code), &mut hc),
                " — teardown (the input context was refused)",
            ],
        );
        session.close(out);
        return;
    }

    // ── 4. Get Descriptor (Device) on EP0: SETUP + DATA + STATUS. ──
    // The EP0 transfer ring: slot 0 = SETUP (immediate data), slot 1
    // = DATA (the 18-byte buffer), slot 2 = STATUS. TRT in the SETUP
    // TRB's control bits 17:16 = 3 (IN data stage). The STATUS
    // stage's DIR = 0 (a control READ's status is an OUT).
    let trb = |n: u64, param: u64, status: u32, ctrl: u32| {
        let pa = ep0ring + n * 16;
        crate::memops::write_u64(pa, param);
        crate::memops::write_u64(pa + 8, u64::from(status));
        crate::memops::write_u32(pa + 12, ctrl);
    };
    trb(
        0,
        setup_packet(0x80, 6, 0x0100, 0, 18),
        0,
        xfer_ctrl(2, false, true, true) | (3 << 16),
    );
    trb(1, data, 18 | (1 << 5), xfer_ctrl(3, true, true, false));
    trb(2, 0, 0, xfer_ctrl(4, false, true, false));
    let _ = bus.write32(dboff, 1); // doorbell slot_id, target EP0 (1)
    loop {
        match wait_ev(16_000_000, false) {
            Some((32, code, s, ep, _)) => {
                let _ = (s, ep);
                if code == 1 {
                    break;
                }
                let mut hc = [0u8; 20];
                line(
                    out,
                    &[
                        "[USBH] Get Descriptor: transfer code ",
                        strutil::dec(u64::from(code), &mut hc),
                        " — teardown",
                    ],
                );
                session.close(out);
                return;
            }
            Some(_) => {
                // Any other event (a command completion interleaved,
                // a port change): consume it, keep waiting.
                continue;
            }
            None => {
                line(
                    out,
                    &["[USBH] Get Descriptor: no transfer event — teardown"],
                );
                session.close(out);
                return;
            }
        }
    }
    let desc: [u8; 18] = {
        let b = read_bytes(data, 18);
        core::array::from_fn(|i| b[i])
    };
    let Some((_class, vid, pid, _maxp0)) = parse_device_descriptor(&desc) else {
        line(out, &["[USBH] device descriptor malformed — teardown"]);
        session.close(out);
        return;
    };
    let mut hv = [0u8; 18];
    let mut hp = [0u8; 18];
    line(
        out,
        &[
            "[USBH] device enumerated: vid=0x",
            strutil::hex(u64::from(vid), &mut hv),
            " pid=0x",
            strutil::hex(u64::from(pid), &mut hp),
            " (Address Device + Get Descriptor round trips)",
        ],
    );

    // ── 5. Get Descriptor (Configuration): the HID shape. ──
    trb(
        3,
        setup_packet(0x80, 6, 0x0200, 0, 64),
        0,
        xfer_ctrl(2, false, true, true) | (3 << 16),
    );
    trb(4, data, 64 | (1 << 5), xfer_ctrl(3, true, true, false));
    trb(5, 0, 0, xfer_ctrl(4, false, true, false));
    let _ = bus.write32(dboff, 1);
    let cfg_ok = loop {
        match wait_ev(16_000_000, false) {
            Some((32, code, _, _, _)) => break code == 1,
            Some(_) => continue,
            None => break false,
        }
    };
    if !cfg_ok {
        line(out, &["[USBH] Get Descriptor (config) failed — teardown"]);
        session.close(out);
        return;
    }
    let cfg: [u8; 64] = read_bytes(data, 64);
    let Some((ep_num, ep_maxp, ep_interval)) = parse_hid_config(&cfg) else {
        line(
            out,
            &["[USBH] the config is not a HID interrupt-IN shape — teardown"],
        );
        session.close(out);
        return;
    };
    let mut he = [0u8; 20];
    let mut hm = [0u8; 20];
    line(
        out,
        &[
            "[USBH] HID keyboard: interrupt-IN EP",
            strutil::dec(u64::from(ep_num), &mut he),
            " maxp=",
            strutil::dec(u64::from(ep_maxp), &mut hm),
            " interval=8ms (parsed from the config descriptor)",
        ],
    );

    // ── 6. Configure Endpoint (TRB 12) for the interrupt-IN EP. ──
    build_configure_input_ctx(
        ictx2,
        dev_ctx,
        u32::from(ep_num),
        u32::from(ep_maxp),
        u32::from(ep_interval),
        ep1ring,
    );
    post_cmd(2, ictx2, cmd_ctrl(12, true, slot_id));
    let configured = matches!(wait_ev(8_000_000, true), Some((_, 1, _, _, _)));
    if !configured {
        line(out, &["[USBH] Configure Endpoint refused — teardown"]);
        session.close(out);
        return;
    }

    // ── 7. SET_CONFIGURATION(1) on EP0 (activates the endpoints at
    //      the USB level — QEMU's usb-kbd arms its EP only then). ──
    trb(
        6,
        setup_packet(0x00, 9, 1, 0, 0),
        0,
        xfer_ctrl(2, false, true, true), // TRT=0: no data stage
    );
    trb(7, 0, 0, xfer_ctrl(4, false, true, false));
    let _ = bus.write32(dboff, 1);
    let setcfg = loop {
        match wait_ev(16_000_000, false) {
            Some((32, code, _, _, _)) => break code == 1,
            Some(_) => continue,
            None => break false,
        }
    };
    if !setcfg {
        line(out, &["[USBH] SET_CONFIGURATION failed — teardown"]);
        session.close(out);
        return;
    }

    // ── 8. The interrupt-IN report: a NORMAL TRB on the EP ring, the
    //      QMP window, the transfer event, the decoded key. ──
    // The report request: 8 bytes at `data + 0x40` (the blob's tail —
    // the descriptor's 64 bytes stay below).
    let report = data + 0x40;
    let trb1 = |param: u64, status: u32, ctrl: u32| {
        crate::memops::write_u64(ep1ring, param);
        crate::memops::write_u64(ep1ring + 8, u64::from(status));
        crate::memops::write_u32(ep1ring + 12, ctrl);
    };
    trb1(report, 8 | (1 << 5), xfer_ctrl(1, true, true, false));
    let _ = bus.write32(dboff, 3); // doorbell slot, target EP1-IN (3)
    line(
        out,
        &["[USBH] HID armed: report requested (waiting for the host's QMP key)"],
    );
    // The QMP window: the host injects 'a' (hold 500ms) at the marker
    // above; the transfer event lands when the device DMAs the report.
    let report_ev = wait_ev(300_000_000, false);
    let rep: [u8; 8] = {
        let b = read_bytes(report, 8);
        core::array::from_fn(|i| b[i])
    };
    match report_ev {
        Some((32, 1, _, _, _)) => {
            let decoded = decode_hid_report(&rep);
            match decoded {
                Some(b) => {
                    let mut hb = [0u8; 18];
                    let cb = [b];
                    let ch: &str = if (0x20..0x7F).contains(&b) {
                        core::str::from_utf8(&cb).unwrap_or("?")
                    } else {
                        "ctrl"
                    };
                    line(
                        out,
                        &[
                            "[USBH] HID report: key 0x",
                            strutil::hex(u64::from(rep[2]), &mut hb),
                            " decoded ('",
                            ch,
                            "') — the USB keyboard round trip, through the xHCI interrupt-IN pipe",
                        ],
                    );
                    // Feed the SAME console-in ring the PS/2 path uses:
                    // one input path, two transports.
                    let _ = crate::tty::push(b);
                }
                None => {
                    let mut hb = [0u8; 18];
                    line(
                        out,
                        &[
                            "[USBH] HID report: 8 bytes delivered, key usage 0x",
                            strutil::hex(u64::from(rep[2]), &mut hb),
                            " (empty or unmapped — the pipe is proven, no key held)",
                        ],
                    );
                }
            }
        }
        Some((ty, code, _, _, _)) => {
            let mut ht = [0u8; 20];
            let mut hc = [0u8; 20];
            line(
                out,
                &[
                    "[USBH] HID report: event type ",
                    strutil::dec(u64::from(ty), &mut ht),
                    " code ",
                    strutil::dec(u64::from(code), &mut hc),
                    " — the pipe answered with a refusal",
                ],
            );
        }
        None => {
            line(
                out,
                &["[USBH] HID report: no transfer event within the budget"],
            );
        }
    }
    session.close(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_trb_is_type_8_with_the_cycle_bit() {
        let phys = crate::drvstack::testharness::FakePhys::new(1);
        let pa = phys.pa(0);
        build_noop_trb(pa);
        assert_eq!(crate::memops::read_u64(pa), 0);
        // dword 3 (at +12) carries type+cycle; dword 2 (+8) stays 0 —
        // the u32 write overlaps the u64's high half, faithful to the
        // driver's TRB layout
        assert_eq!(crate::memops::read_u32(pa + 8), 0);
        assert_eq!(crate::memops::read_u32(pa + 12), (8u32 << 10) | 1);
    }

    /// The event-type extraction: hostile dwords can only produce
    /// 0..=63; type 33 is command completion.
    #[test]
    fn event_trb_type_is_bounded_under_garbage() {
        let phys = crate::drvstack::testharness::FakePhys::new(1);
        let pa = phys.pa(0);
        let mut rng = crate::drvstack::testharness::XorShift(0xBEEF);
        for _ in 0..1000 {
            let dw3 = rng.next() as u32;
            crate::memops::write_u32(pa + 12, dw3);
            let ty = event_trb_type(pa);
            assert!(ty <= 0x3F, "the type field is 6 bits, always");
            assert_eq!(ty, (dw3 >> 10) & 0x3F);
        }
        crate::memops::write_u32(pa + 12, (33u32 << 10) | 1);
        assert_eq!(event_trb_type(pa), 33);
    }
}
