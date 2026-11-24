//! xHCI: the operational + runtime registers, port detection, the command ring.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::drvstack::xhci_proto;
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
                "[XHCI] BAR0 window too small for the caps block (len=",
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
                "[XHCI] BAR0 window too small for the port bank (len=",
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
    // Stop the controller BEFORE the teardown hands its DCBAA/CRCR
    // frames back: a running xHC keeps fetching from whatever
    // memory those registers name.
    let _ = xhci_proto::halt_controller(&bus, op, xhci_proto::REG_SPINS);
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
                "[XTRB] BAR0 window too small for the op/runtime/doorbell registers (len=",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    // The xHCI bring-up slice (xhci_step) already ran and halted the
    // controller before its teardown; re-bring-up with fresh frames.
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
        let _ = xhci_proto::halt_controller(&bus, op, xhci_proto::REG_SPINS);
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
    let ev_type = event_trb_type(evring);
    // Success signal: the EVENT RING, not CRCR — the controller never
    // writes the dequeue pointer back into CRCR (it is load-bearing
    // only at halt); the command-completion event TRB (type 33) in the
    // event ring is the real proof the full TRB machinery ran:
    // ring DMA → execution → event post. The completion code rides the
    // event's status dword (bits 31:24) and is PRINTED, not assumed
    // (found live: a decode that also demanded a guessed cycle state
    // refused QEMU's real event and silently broke the pinned marker).
    let ev_code = crate::memops::read_u32(evring + 8) >> 24;
    let ev_slot = crate::memops::read_u32(evring + 12) >> 24;
    let mut ha = [0u8; 20];
    let mut hb = [0u8; 20];
    let mut hc = [0u8; 20];
    line(
        out,
        &[
            "[XTRB] No-Op command: event-ring slot0 type=",
            strutil::dec(u64::from(ev_type), &mut ha),
            if ev_type == 33 {
                " = COMMAND COMPLETION — code="
            } else {
                " (expected 33 = command completion) code="
            },
            strutil::dec(u64::from(ev_code), &mut hb),
            " slot=",
            strutil::dec(u64::from(ev_slot), &mut hc),
        ],
    );
    let _ = advanced;
    session.close(out);
}

// ── the enumeration + HID slice (item 12's completion) ─────────────
//
// One bounded pass over the root hub, on the session discipline of the
// two steps above. The controller is reset BEFORE the session owns a
// frame (register-only), then brought up on nine broker-mapped frames.
// For every attached port: bus reset → Enable Slot → Address Device →
// device descriptor → (Evaluate Context when EP0's max packet differs
// from the speed's default) → config descriptor → Configure Endpoint for
// a HID boot keyboard's interrupt-IN pipe → SET_CONFIGURATION, SET_IDLE,
// SET_PROTOCOL. The first keyboard is then armed: one interrupt-IN TD,
// the QMP key's report decoded and pushed to the tty. The controller is
// halted BEFORE the teardown revokes the rings. This is a one-shot
// proof inside the driver phase, not a resident interrupt-driven HID
// driver (no MSI/MSI-X, no permanent queue) — that is the next slice.

/// The xHCI speed encoding of PORTSC bits 13:10.
#[cfg(not(test))]
fn speed_name(speed: u32) -> &'static str {
    match speed {
        1 => "full-speed",
        2 => "low-speed",
        3 => "high-speed",
        4 => "super-speed",
        _ => "unknown-speed",
    }
}

/// bMaxPacketSize0's encoding (USB 2 §9.6.1): 9 = 512 bytes for
/// super-speed devices, otherwise the packet size itself.
#[cfg(not(test))]
fn ep0_packet(max_packet0: u8) -> u32 {
    if max_packet0 == 9 {
        512
    } else {
        u32::from(max_packet0)
    }
}

#[cfg(not(test))]
fn proto_err_name(e: xhci_proto::ProtoErr) -> &'static str {
    match e {
        xhci_proto::ProtoErr::Window => "refused by the register window",
        xhci_proto::ProtoErr::Timeout => "timed out",
        xhci_proto::ProtoErr::Controller => "controller error (USBSTS.HCE)",
        xhci_proto::ProtoErr::RingFull => "ring full",
    }
}

#[cfg(not(test))]
pub(crate) fn xhci_enum_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;
    use xhci_proto::{
        build_address_input_ctx, build_configure_input_ctx, build_erst, build_evaluate_input_ctx,
        cmd_ctrl, control, decode_hid_report, ep0_max_packet, ep_ctx_index, interval_exponent,
        kick_transfer, parse_boot_keyboard, parse_device_descriptor, port_status, probe,
        read_bytes, reset_controller, reset_port, setup_packet, start_controller, xfer_ctrl,
        BootKeyboard, DataStage, Ticker, Trb, CC_SHORT_PACKET, CC_SUCCESS, CR_ADDRESS_DEVICE,
        CR_CONFIGURE_ENDPOINT, CR_DISABLE_SLOT, CR_ENABLE_SLOT, CR_EVALUATE_CONTEXT,
        EP_INTERRUPT_IN, ER_TRANSFER, REG_SPINS, TRB_IOC, TR_NORMAL,
    };

    struct TscTicker;
    impl Ticker for TscTicker {
        fn now(&mut self) -> u64 {
            crate::hw::read_tsc()
        }
    }

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
        line(
            out,
            &["[USBH] BAR0 window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    crate::pci::enable_mem(dev);
    let Some(g) = probe(&bus) else {
        line(
            out,
            &[
                "[USBH] BAR0 window cannot hold the caps/op/port/runtime/doorbell registers (len=",
                strutil::hex(bus.window().len(), &mut [0u8; 18]),
                ") — refusing",
            ],
        );
        return;
    };
    let mut ticker = TscTicker;
    let cmd_budget = crate::clock::ns_to_cycles(500_000_000).unwrap_or(1 << 30);

    // Register-only, before any frame exists: nothing to leak here.
    if let Err(e) = reset_controller(&bus, &g) {
        line(
            out,
            &["[USBH] controller reset ", proto_err_name(e), " — refusing"],
        );
        return;
    }

    // ADR-0016/F10: the session owns every ring/context/buffer frame;
    // every exit below is one close().
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
    // Frames: DCBAA, command ring, event ring, ERST, input context,
    // device (output) context, EP0 ring, EP1-IN ring, DMA data buffer.
    let mut frames = [0u64; 9];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[USBH] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [dcbaa, cmdring, evring, erst, ictx, dev_ctx, ep0ring, ep1ring, data] = frames;
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(out, &["[USBH] broker refused a frame — refusing"]);
            return;
        }
    }
    for &pa in frames.iter() {
        crate::memops::scrub_frame(pa);
    }
    build_erst(erst, evring);
    crate::pci::enable_bus_master(dev);
    let mut rings = xhci_proto::Rings::new(cmdring, evring);

    // The controller is halted BEFORE the teardown hands its frames
    // back: a running xHC keeps fetching from, and posting into,
    // whatever memory its pointers name.
    macro_rules! finish {
        () => {{
            let _ = xhci_proto::halt_controller(&bus, g.op, REG_SPINS);
            session.close(out);
        }};
    }
    macro_rules! drop_slot {
        ($slot:expr) => {
            let _ = rings.command(
                &bus,
                &g,
                &mut ticker,
                0,
                cmd_ctrl(CR_DISABLE_SLOT, true, $slot),
                cmd_budget,
            );
        };
    }
    // One EP0 control transfer at ring slot `$next`; `Err(u64::MAX)`
    // when the wait itself failed (already printed), else the code.
    macro_rules! ep0 {
        ($what:expr, $slot:expr, $next:expr, $setup:expr, $data:expr) => {{
            match control(
                &mut rings,
                &bus,
                &g,
                &mut ticker,
                ep0ring,
                $next,
                $slot,
                $setup,
                $data,
                cmd_budget,
            ) {
                Ok(e) if e.code == CC_SUCCESS || e.code == CC_SHORT_PACKET => Ok(()),
                Ok(e) => Err(u64::from(e.code)),
                Err(e) => {
                    line(out, &["[USBH] ", $what, " ", proto_err_name(e)]);
                    Err(u64::MAX)
                }
            }
        }};
    }

    if let Err(e) = start_controller(&bus, &g, dcbaa, cmdring, erst, evring) {
        line(out, &["[USBH] bring-up ", proto_err_name(e), " — teardown"]);
        finish!();
        return;
    }

    // The EP0 ring is scrubbed and re-based per device: Address Device
    // points the new slot's EP0 dequeue at the ring BASE (DCS=1), so
    // every device's control sequence restarts at TRB slot 0 and queues
    // back-to-back from there (found live: the second device's
    // transfers, left at the first device's slot, made QEMU read a
    // scrubbed slot and time out on Get Descriptor).
    let mut kbd: Option<(u32, BootKeyboard)> = None;
    'ports: for port in 0..g.max_ports {
        let Ok((connected, _, speed)) = port_status(&bus, &g, port) else {
            continue;
        };
        if !connected {
            continue;
        }
        line(
            out,
            &[
                "[USBH] port ",
                strutil::dec(u64::from(port), &mut [0u8; 20]),
                " device attached, speed=",
                strutil::dec(u64::from(speed), &mut [0u8; 20]),
                " (",
                speed_name(speed),
                ")",
            ],
        );
        // The bus reset: QEMU's usb_device_reset → hid_reset flushes the
        // key queue and the address — the enumeration starts clean.
        if let Err(e) = reset_port(&bus, &g, port) {
            line(
                out,
                &[
                    "[USBH] port ",
                    strutil::dec(u64::from(port), &mut [0u8; 20]),
                    " bus reset ",
                    proto_err_name(e),
                ],
            );
            continue;
        }
        for pa in [ictx, dev_ctx, ep0ring, ep1ring, data] {
            crate::memops::scrub_frame(pa);
        }
        // The scrubbed EP0 ring restarts at slot 0 for this device (the
        // comment above the port loop is the why).
        let mut next = 0usize;
        // Enable Slot: the controller picks the first free slot id.
        let slot = match rings.command(
            &bus,
            &g,
            &mut ticker,
            0,
            cmd_ctrl(CR_ENABLE_SLOT, true, 0),
            cmd_budget,
        ) {
            Ok(e) if e.code == CC_SUCCESS && (1..=g.max_slots).contains(&e.slot) => e.slot,
            Ok(e) => {
                line(
                    out,
                    &[
                        "[USBH] Enable Slot: completion code ",
                        strutil::dec(u64::from(e.code), &mut [0u8; 20]),
                        " — stopping the port scan",
                    ],
                );
                break 'ports;
            }
            Err(e) => {
                line(
                    out,
                    &[
                        "[USBH] Enable Slot ",
                        proto_err_name(e),
                        " — stopping the port scan",
                    ],
                );
                break 'ports;
            }
        };
        crate::memops::write_u64(dcbaa + 8 * u64::from(slot), dev_ctx);
        // Address Device: the slot context (root-hub port, speed, route
        // string 0) + EP0 at the speed's default max packet.
        build_address_input_ctx(ictx, speed, port + 1, ep0ring);
        match rings.command(
            &bus,
            &g,
            &mut ticker,
            ictx,
            cmd_ctrl(CR_ADDRESS_DEVICE, true, slot),
            cmd_budget,
        ) {
            Ok(e) if e.code == CC_SUCCESS => {}
            Ok(e) => {
                line(
                    out,
                    &[
                        "[USBH] Address Device: completion code ",
                        strutil::dec(u64::from(e.code), &mut [0u8; 20]),
                    ],
                );
                drop_slot!(slot);
                continue;
            }
            Err(e) => {
                line(out, &["[USBH] Address Device ", proto_err_name(e)]);
                drop_slot!(slot);
                continue;
            }
        }

        // GET_DESCRIPTOR device: 18 bytes.
        let got = ep0!(
            "Get Descriptor(device)",
            slot,
            next,
            setup_packet(0x80, 6, 0x0100, 0, 18),
            Some(DataStage {
                buf: data,
                len: 18,
                dir_in: true
            })
        );
        next += 3;
        if let Err(code) = got {
            if code != u64::MAX {
                line(
                    out,
                    &[
                        "[USBH] Get Descriptor(device): completion code ",
                        strutil::dec(code, &mut [0u8; 20]),
                    ],
                );
            }
            drop_slot!(slot);
            continue;
        }
        let mut d = [0u8; 18];
        read_bytes(data, &mut d);
        let Some(dd) = parse_device_descriptor(&d) else {
            line(
                out,
                &["[USBH] device descriptor malformed (length/type/bMaxPacketSize0)"],
            );
            drop_slot!(slot);
            continue;
        };
        // bMaxPacketSize0 may differ from the speed's default (USB 3's
        // encoding): tell the controller before any bigger transfer.
        let max_packet0 = ep0_packet(dd.max_packet0);
        if max_packet0 != ep0_max_packet(speed) {
            build_evaluate_input_ctx(ictx, max_packet0, ep0ring);
            match rings.command(
                &bus,
                &g,
                &mut ticker,
                ictx,
                cmd_ctrl(CR_EVALUATE_CONTEXT, true, slot),
                cmd_budget,
            ) {
                Ok(e) if e.code == CC_SUCCESS => {}
                Ok(e) => {
                    line(
                        out,
                        &[
                            "[USBH] Evaluate Context: completion code ",
                            strutil::dec(u64::from(e.code), &mut [0u8; 20]),
                        ],
                    );
                    drop_slot!(slot);
                    continue;
                }
                Err(e) => {
                    line(out, &["[USBH] Evaluate Context ", proto_err_name(e)]);
                    drop_slot!(slot);
                    continue;
                }
            }
        }

        // GET_DESCRIPTOR config: the 9-byte header names wTotalLength,
        // then the whole descriptor (the event's length field is a
        // residual, not a byte count — the header is the only source).
        let head = ep0!(
            "Get Descriptor(config header)",
            slot,
            next,
            setup_packet(0x80, 6, 0x0200, 0, 9),
            Some(DataStage {
                buf: data + 0x800,
                len: 9,
                dir_in: true
            })
        );
        next += 3;
        if let Err(code) = head {
            if code != u64::MAX {
                line(
                    out,
                    &[
                        "[USBH] Get Descriptor(config header): completion code ",
                        strutil::dec(code, &mut [0u8; 20]),
                    ],
                );
            }
            drop_slot!(slot);
            continue;
        }
        let mut hdr = [0u8; 9];
        read_bytes(data + 0x800, &mut hdr);
        let total = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
        if hdr[0] != 9 || hdr[1] != 2 || !(18..=1024).contains(&total) {
            line(
                out,
                &["[USBH] config descriptor header malformed or wTotalLength out of range"],
            );
            drop_slot!(slot);
            continue;
        }
        let cfg = ep0!(
            "Get Descriptor(config)",
            slot,
            next,
            setup_packet(0x80, 6, 0x0200, 0, total as u16),
            Some(DataStage {
                buf: data,
                len: total as u16,
                dir_in: true
            })
        );
        next += 3;
        if let Err(code) = cfg {
            if code != u64::MAX {
                line(
                    out,
                    &[
                        "[USBH] Get Descriptor(config): completion code ",
                        strutil::dec(code, &mut [0u8; 20]),
                    ],
                );
            }
            drop_slot!(slot);
            continue;
        }
        let mut cfg_buf = [0u8; 1024];
        read_bytes(data, &mut cfg_buf[..total]);

        let Some(kbd_ep) = parse_boot_keyboard(&cfg_buf[..total]) else {
            line(
                out,
                &[
                    "[USBH] port ",
                    strutil::dec(u64::from(port), &mut [0u8; 20]),
                    ": vid=",
                    strutil::hex(u64::from(dd.vid), &mut [0u8; 18]),
                    " pid=",
                    strutil::hex(u64::from(dd.pid), &mut [0u8; 18]),
                    " class=",
                    strutil::dec(u64::from(dd.class), &mut [0u8; 20]),
                    " — not a HID boot keyboard, left unconfigured",
                ],
            );
            drop_slot!(slot);
            continue;
        };
        let Some(exp) = interval_exponent(kbd_ep.b_interval, speed >= 3) else {
            line(
                out,
                &["[USBH] HID keyboard with bInterval=0 (invalid) — left unconfigured"],
            );
            drop_slot!(slot);
            continue;
        };
        // Configure Endpoint: add the slot (Context Entries raised) and
        // the interrupt-IN endpoint's own context.
        build_configure_input_ctx(
            ictx,
            dev_ctx,
            ep_ctx_index(kbd_ep.ep_num, true),
            EP_INTERRUPT_IN,
            u32::from(kbd_ep.max_packet),
            exp,
            ep1ring,
            u32::from(kbd_ep.max_packet),
        );
        match rings.command(
            &bus,
            &g,
            &mut ticker,
            ictx,
            cmd_ctrl(CR_CONFIGURE_ENDPOINT, true, slot),
            cmd_budget,
        ) {
            Ok(e) if e.code == CC_SUCCESS => {}
            Ok(e) => {
                line(
                    out,
                    &[
                        "[USBH] Configure Endpoint: completion code ",
                        strutil::dec(u64::from(e.code), &mut [0u8; 20]),
                    ],
                );
                drop_slot!(slot);
                continue;
            }
            Err(e) => {
                line(out, &["[USBH] Configure Endpoint ", proto_err_name(e)]);
                drop_slot!(slot);
                continue;
            }
        }

        // The boot protocol, on the keyboard's interface.
        let iface = u16::from(kbd_ep.interface);
        let mut failed = false;
        for (what, setup) in [
            ("SET_CONFIGURATION", setup_packet(0x00, 9, 1, 0, 0)),
            ("SET_IDLE", setup_packet(0x21, 0x0A, 0, iface, 0)),
            ("SET_PROTOCOL", setup_packet(0x21, 0x0B, 1, iface, 0)),
        ] {
            match control(
                &mut rings,
                &bus,
                &g,
                &mut ticker,
                ep0ring,
                next,
                slot,
                setup,
                None,
                cmd_budget,
            ) {
                Ok(e) if e.code == CC_SUCCESS => {}
                Ok(e) => {
                    line(
                        out,
                        &[
                            "[USBH] ",
                            what,
                            ": completion code ",
                            strutil::dec(u64::from(e.code), &mut [0u8; 20]),
                        ],
                    );
                    failed = true;
                }
                Err(e) => {
                    line(out, &["[USBH] ", what, " ", proto_err_name(e)]);
                    failed = true;
                }
            }
            next += 2;
            if failed {
                break;
            }
        }
        if failed {
            drop_slot!(slot);
            continue;
        }
        line(
            out,
            &[
                "[USBH] device enumerated: vid=",
                strutil::hex(u64::from(dd.vid), &mut [0u8; 18]),
                " pid=",
                strutil::hex(u64::from(dd.pid), &mut [0u8; 18]),
                " (Address Device + Get Descriptor round trips)",
            ],
        );
        line(
            out,
            &[
                "[USBH] HID keyboard: interrupt-IN EP",
                strutil::dec(u64::from(kbd_ep.ep_num), &mut [0u8; 20]),
                " maxp=",
                strutil::dec(u64::from(kbd_ep.max_packet), &mut [0u8; 20]),
                " interval=",
                strutil::dec(1u64 << exp, &mut [0u8; 20]),
                " (bInterval=",
                strutil::dec(u64::from(kbd_ep.b_interval), &mut [0u8; 20]),
                ", ",
                speed_name(speed),
                "; parsed from the config descriptor)",
            ],
        );
        line(
            out,
            &[
                "[USBH] bMaxPacketSize0=",
                strutil::dec(u64::from(dd.max_packet0), &mut [0u8; 20]),
                ", device class=",
                strutil::dec(u64::from(dd.class), &mut [0u8; 20]),
                ", slot ",
                strutil::dec(u64::from(slot), &mut [0u8; 20]),
            ],
        );
        kbd = Some((slot, kbd_ep));
        break 'ports;
    }

    let Some((slot, kbd_ep)) = kbd else {
        line(
            out,
            &["[USBH] no HID boot keyboard on the root hub — nothing to arm"],
        );
        finish!();
        return;
    };
    // The interrupt-IN pipe: EP id = 2n + 1, doorbell = the SLOT's.
    let ep_id = 2 * u32::from(kbd_ep.ep_num) + 1;
    let report = Trb {
        param: data,
        status: 8,
        ctrl: xfer_ctrl(TR_NORMAL, true, true, false) | TRB_IOC,
    };
    let is_report =
        |e: &xhci_proto::Event| e.kind == ER_TRANSFER && e.slot == slot && e.ep == ep_id;
    let short_wait = crate::clock::ns_to_cycles(60_000_000).unwrap_or(1 << 26);
    // The PS/2 window's key may already sit in the keyboard's queue
    // (QEMU routes send-key to the USB keyboard first): drain until the
    // pipe is quiet, so the armed report is a key pressed AFTER arming.
    let mut drained = 0u32;
    let mut ix = 0usize;
    for _ in 0..4 {
        if kick_transfer(&bus, &g, ep1ring, ix, &[report], slot, ep_id).is_err() {
            break;
        }
        ix += 1;
        match rings.wait_event(&bus, &g, &mut ticker, short_wait, is_report) {
            Ok(_) => drained += 1,
            Err(_) => break,
        }
    }
    crate::memops::scrub_frame(data);
    line(
        out,
        &[
            "[USBH] HID pipe quiet (",
            strutil::dec(u64::from(drained), &mut [0u8; 20]),
            " report(s) drained from before arming)",
        ],
    );
    if let Err(e) = kick_transfer(&bus, &g, ep1ring, ix, &[report], slot, ep_id) {
        line(out, &["[USBH] arming refused: ", proto_err_name(e)]);
        drop_slot!(slot);
        finish!();
        return;
    }
    line(
        out,
        &["[USBH] HID armed: report requested (waiting for the host's QMP key)"],
    );
    let long_wait = crate::clock::ns_to_cycles(10_000_000_000).unwrap_or(1 << 34);
    match rings.wait_event(&bus, &g, &mut ticker, long_wait, is_report) {
        Ok(e) if e.code == CC_SUCCESS || e.code == CC_SHORT_PACKET => {
            let mut rep = [0u8; 8];
            read_bytes(data, &mut rep);
            match decode_hid_report(&rep) {
                Some(b @ 0x20..=0x7E) => {
                    crate::tty::push(b);
                    line(
                        out,
                        &[
                            "[USBH] HID report: key ",
                            strutil::hex(u64::from(rep[2]), &mut [0u8; 18]),
                            " decoded ('",
                            core::str::from_utf8(&[b]).unwrap_or("?"),
                            "') — the USB keyboard round trip, through the xHCI interrupt-IN pipe",
                        ],
                    );
                }
                Some(b) => {
                    crate::tty::push(b);
                    line(
                        out,
                        &[
                            "[USBH] HID report: key ",
                            strutil::hex(u64::from(rep[2]), &mut [0u8; 18]),
                            " decoded to control byte ",
                            strutil::hex(u64::from(b), &mut [0u8; 18]),
                            " — delivered through the xHCI interrupt-IN pipe and pushed to the tty",
                        ],
                    );
                }
                None => line(
                    out,
                    &[
                        "[USBH] HID report: key ",
                        strutil::hex(u64::from(rep[2]), &mut [0u8; 18]),
                        " arrived but decodes to no character (a modifier is held, or every key slot is empty) — not pushed",
                    ],
                ),
            }
        }
        Ok(e) => line(
            out,
            &[
                "[USBH] HID report: completion code ",
                strutil::dec(u64::from(e.code), &mut [0u8; 20]),
                " — the interrupt-IN pipe did not deliver",
            ],
        ),
        Err(e) => line(
            out,
            &[
                "[USBH] HID report: ",
                proto_err_name(e),
                " — no report within 10 s of arming",
            ],
        ),
    }
    drop_slot!(slot);
    finish!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drvstack::testharness::{FakePhys, XorShift};

    #[test]
    fn noop_trb_is_type_8_with_the_cycle_bit() {
        let phys = FakePhys::new(1);
        let pa = phys.pa(0);
        build_noop_trb(pa);
        assert_eq!(event_trb_type(pa), 8);
        assert_ne!(crate::memops::read_u32(pa + 12) & 1, 0);
        assert_eq!(crate::memops::read_u64(pa), 0);
        assert_eq!(crate::memops::read_u64(pa + 8) & 0xFFFF_FFFF, 0);
    }

    #[test]
    fn event_trb_type_is_bounded_under_garbage() {
        let phys = FakePhys::new(1);
        let pa = phys.pa(0);
        let mut rng = XorShift(0x5843_4843);
        for _ in 0..4096 {
            let v = rng.next();
            crate::memops::write_u32(pa + 12, v as u32);
            assert!(event_trb_type(pa) <= 63);
        }
    }
}
