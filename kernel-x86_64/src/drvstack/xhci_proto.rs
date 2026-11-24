//! xHCI protocol layer: the TRB / context / descriptor / HID encoding as
//! PURE builders and parsers, and the register protocol generic over
//! `MmioBus` (the same bounds-checked window every driver uses).
//!
//! Field positions follow xHCI 1.0 as QEMU's model checks them
//! (`hcd-xhci.c`: `xhci_address_slot`, `xhci_configure_slot`,
//! `xhci_fire_ctl_transfer`, `xhci_xfer_create_sgl`, `xhci_event`) and as
//! Linux lays them out (`xhci.h`, `xhci-mem.c`). The host tests below
//! replay those checks bit for bit.

#![cfg_attr(test, allow(dead_code))]

use crate::memops::{read_u32, read_u64, write_u32, write_u64};
use crate::mmio::MmioBus;

// ── register map (xHCI 1.0, chapter 5) ─────────────────────────────

/// Capability registers.
const CAP_HCSPARAMS1: u64 = 0x04;
const CAP_DBOFF: u64 = 0x14;
const CAP_RTSOFF: u64 = 0x18;
/// Operational registers, relative to the device-derived CAPLENGTH.
const OP_USBCMD: u64 = 0x00;
const OP_USBSTS: u64 = 0x04;
const OP_CRCR: u64 = 0x18;
const OP_DCBAAP: u64 = 0x30;
const OP_CONFIG: u64 = 0x38;
const OP_PORTSC: u64 = 0x400;
const PORT_STRIDE: u64 = 0x10;
/// Interrupter n's block: RTSOFF + 0x20 * (n + 1).
const INTR_OFF: u64 = 0x20;
const RT_ERSTSZ: u64 = 0x08;
const RT_ERSTBA: u64 = 0x10;
const RT_ERDP: u64 = 0x18;

const USBCMD_RS: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBSTS_HCH: u32 = 1 << 0;
const USBSTS_CNR: u32 = 1 << 11;
const USBSTS_HCE: u32 = 1 << 12;
const CRCR_RCS: u64 = 1;
const ERDP_EHB: u64 = 1 << 3;

const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_PED: u32 = 1 << 1;
const PORTSC_PR: u32 = 1 << 4;
const PORTSC_PP: u32 = 1 << 9;
const PORTSC_SPEED_SHIFT: u32 = 10;
/// The write-1-to-clear change bits, CSC..CEC (bits 17..=23).
const PORTSC_CHANGE: u32 =
    (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);

/// The port-scan cap: the register window must cover this many port
/// status registers before the scan trusts `max_ports` at all.
const PORT_SCAN_CAP: u32 = 16;
/// Bounded register polls (reads). In QEMU's model every transition
/// below is one write away, so a real wait here means a dead controller.
pub(crate) const REG_SPINS: u64 = 8_000_000;
/// One 4-KiB frame of TRBs: the command ring, the event ring (one
/// segment, the size QEMU's `xhci_er_reset` accepts: 16..=4096), EP rings.
pub(crate) const RING_TRBS: usize = 256;
const EV_TRBS: usize = 256;

// ── TRB fields (xHCI 1.0 §4.11.1) ──────────────────────────────────

const TRB_CYCLE: u32 = 1 << 0;
pub(crate) const TRB_IOC: u32 = 1 << 5;
#[cfg(test)]
const TRB_IDT: u32 = 1 << 6;
#[cfg(test)]
const TRB_DIR_IN: u32 = 1 << 16;
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_SLOT_SHIFT: u32 = 24;

pub(crate) const TR_NORMAL: u32 = 1;
const TR_SETUP: u32 = 2;
const TR_DATA: u32 = 3;
const TR_STATUS: u32 = 4;
pub(crate) const CR_ENABLE_SLOT: u32 = 9;
pub(crate) const CR_DISABLE_SLOT: u32 = 10;
pub(crate) const CR_ADDRESS_DEVICE: u32 = 11;
pub(crate) const CR_CONFIGURE_ENDPOINT: u32 = 12;
pub(crate) const CR_EVALUATE_CONTEXT: u32 = 13;
pub(crate) const ER_TRANSFER: u32 = 32;
pub(crate) const ER_COMMAND_COMPLETE: u32 = 33;
/// ER_HOST_CONTROLLER: the "event ring full" (or fatal) notice.
pub(crate) const ER_HOST_CONTROLLER: u32 = 37;

pub(crate) const CC_SUCCESS: u32 = 1;
pub(crate) const CC_SHORT_PACKET: u32 = 13;

/// Endpoint context types (§6.2.3, the EP type field, bits [5:3] of
/// the EP context's second dword). The values are pinned against
/// QEMU's own EPType enum (ref: hcd-xhci.c — ET_CONTROL=4,
/// ET_INTR_IN=7): the previous constants were misread as 7/6, which
/// QEMU's loose direction dispatch (`in_xfer = type >> 2`) silently
/// tolerated on the K17 lane, while the semantics were wrong (EP0
/// ran the interrupt-in path, the HID pipe the bulk-in path). Found
/// by the host test this round — and it had been failing unnoticed
/// because `cargo test`'s default members never included this crate.
const EP_CONTROL: u32 = 4;
pub(crate) const EP_INTERRUPT_IN: u32 = 7;
/// Context size, and context 1's offset (the slot); context n sits at
/// `CTX_SLOT + CTX_SIZE * n`.
const CTX_SIZE: u64 = 0x20;
const CTX_SLOT: u64 = 0x20;

// ── the pure half ──────────────────────────────────────────────────

/// One Transfer Request Block: the three fields a ring slot carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Trb {
    /// Dwords 0-1: the parameter field.
    pub param: u64,
    /// Dword 2: TD size [23:17] | buffer length [16:0].
    pub status: u32,
    /// Dword 3: slot id [31:24] | DIR/TRT [17:16] | type [15:10] | flags | cycle.
    pub ctrl: u32,
}

/// The command-control dword: type [15:10], cycle bit 0, slot id [31:24].
pub(crate) fn cmd_ctrl(trb_type: u32, cycle: bool, slot: u32) -> u32 {
    (trb_type << TRB_TYPE_SHIFT) | u32::from(cycle) | ((slot & 0xFF) << TRB_SLOT_SHIFT)
}

/// A transfer TRB's control dword: type [15:10], DIR [16], IDT [6],
/// cycle bit 0.
pub(crate) fn xfer_ctrl(trb_type: u32, dir_in: bool, cycle: bool, idt: bool) -> u32 {
    (trb_type << TRB_TYPE_SHIFT)
        | (u32::from(dir_in) << 16)
        | (u32::from(idt) << 6)
        | u32::from(cycle)
}

/// The SETUP TRB's parameter: the 8-byte setup packet (immediate data,
/// little-endian): bmRequestType | bRequest | wValue | wIndex | wLength.
pub(crate) fn setup_packet(bmreq: u8, breq: u8, wvalue: u16, windex: u16, wlength: u16) -> u64 {
    u64::from(bmreq)
        | (u64::from(breq) << 8)
        | (u64::from(wvalue) << 16)
        | (u64::from(windex) << 32)
        | (u64::from(wlength) << 48)
}

/// A control transfer's data stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataStage {
    /// The DMA buffer.
    pub buf: u64,
    /// wLength == the buffer's size.
    pub len: u16,
    /// true = the device sends data to the host (IN).
    pub dir_in: bool,
}

/// Encode one EP0 control transfer (§4.11.2) as 2 TRBs (no data stage)
/// or 3: SETUP (length 8, IDT, TRT), DATA (DIR from bmRequestType —
/// QEMU refuses a disagreement), STATUS (the opposite direction, IOC on
/// the last TRB so one event reports the whole TD).
pub(crate) fn control_transfer(
    setup: u64,
    data: Option<DataStage>,
    cycle: bool,
) -> ([Trb; 3], usize) {
    // TRT: 0 = no data stage, 2 = IN data, 3 = OUT data.
    let trt = match data {
        None => 0,
        Some(d) => 2 + u32::from(!d.dir_in),
    };
    let mut trbs = [Trb {
        param: 0,
        status: 0,
        ctrl: 0,
    }; 3];
    trbs[0] = Trb {
        param: setup,
        // TD size = the TRBs left in this TD (STATUS, plus DATA when present).
        status: 8 | ((1 + u32::from(data.is_some())) << 17),
        ctrl: xfer_ctrl(TR_SETUP, false, cycle, true) | (trt << 16),
    };
    match data {
        None => {
            trbs[1] = Trb {
                param: 0,
                status: 0,
                ctrl: xfer_ctrl(TR_STATUS, true, cycle, false) | TRB_IOC,
            };
            (trbs, 2)
        }
        Some(d) => {
            trbs[1] = Trb {
                param: d.buf,
                status: u32::from(d.len) | (1 << 17),
                ctrl: xfer_ctrl(TR_DATA, d.dir_in, cycle, false),
            };
            trbs[2] = Trb {
                param: 0,
                status: 0,
                ctrl: xfer_ctrl(TR_STATUS, !d.dir_in, cycle, false) | TRB_IOC,
            };
            (trbs, 3)
        }
    }
}

/// Write one TRB at ring slot `n`.
pub(crate) fn put_trb(ring_pa: u64, n: usize, t: &Trb) {
    let pa = ring_pa + 16 * n as u64;
    write_u64(pa, t.param);
    write_u32(pa + 8, t.status);
    write_u32(pa + 12, t.ctrl);
}

/// Read one TRB at ring slot `n`: (parameter, status, control).
pub(crate) fn get_trb(ring_pa: u64, n: usize) -> (u64, u32, u32) {
    (
        read_u64(pa16(ring_pa, n)),
        read_u32(pa16(ring_pa, n) + 8),
        read_u32(pa16(ring_pa, n) + 12),
    )
}

fn pa16(ring_pa: u64, n: usize) -> u64 {
    ring_pa + 16 * n as u64
}

/// One decoded event TRB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    /// The event type (32 transfer, 33 command completion, 34 port status change).
    pub kind: u32,
    /// The completion code (1 = success).
    pub code: u32,
    /// The slot id the event belongs to.
    pub slot: u32,
    /// The endpoint id the event belongs to.
    pub ep: u32,
}

/// Decode an event TRB. `None` when the slot is not a posted event for
/// the cursor's cycle state: a zeroed slot, one left from the previous
/// lap of the ring, or a reserved type.
pub(crate) fn decode_event(param: u64, status: u32, ctrl: u32, cycle: bool) -> Option<Event> {
    let _ = param;
    if ctrl & TRB_CYCLE != u32::from(cycle) {
        return None;
    }
    let kind = (ctrl >> TRB_TYPE_SHIFT) & 0x3F;
    if kind == 0 {
        return None;
    }
    Some(Event {
        kind,
        code: status >> 24,
        slot: ctrl >> TRB_SLOT_SHIFT,
        ep: (ctrl >> 16) & 0x1F,
    })
}

/// The event-ring consumer's position: which slot the next event lands
/// at, and the cycle state it must carry (the producer's cycle state,
/// 1 after (re)initialization, flipped on every lap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventCursor {
    /// The ring index the next event lands at.
    pub next: usize,
    /// The cycle bit the next posted event carries.
    pub cycle: bool,
}

impl EventCursor {
    /// The position after a reset: slot 0, cycle 1.
    pub(crate) const fn new() -> Self {
        Self {
            next: 0,
            cycle: true,
        }
    }

    /// Step past the event just consumed.
    pub(crate) fn advance(&mut self) {
        self.next += 1;
        if self.next >= EV_TRBS {
            self.next = 0;
            self.cycle = !self.cycle;
        }
    }

    /// The ERDP value acknowledging everything before the cursor, EHB
    /// set. Always inside the segment — QEMU calls `xhci_die` on an
    /// ERDP outside it.
    pub(crate) fn erdp(&self, ev: u64) -> u64 {
        (ev + 16 * self.next as u64) | ERDP_EHB
    }
}

/// The context index of endpoint `ep_num` with direction `dir_in`:
/// 2 * ep + dir_in: the endpoint id, which is also the context index and the add-flag bit (EP1-IN = 3).
pub(crate) fn ep_ctx_index(ep_num: u8, dir_in: bool) -> u32 {
    2 * u32::from(ep_num.max(1)) + u32::from(dir_in)
}

/// Slot context dword 0: route string [19:0] (0 — a device on a root-hub
/// port), speed [23:20] in the PORTSC encoding, Context Entries [31:27].
pub(crate) fn slot_ctx_d0(speed: u32, entries: u32) -> u32 {
    ((speed & 0xF) << 20) | ((entries & 0x1F) << 27)
}

/// Slot context dword 1: Max Exit Latency [15:0] (0) | root-hub port
/// number [23:16] (1-based) | Number of Ports [31:24] (0 on a root hub).
pub(crate) fn slot_ctx_d1(port1: u32) -> u32 {
    (port1 & 0xFF) << 16
}

/// Endpoint context dword 0: Interval [23:16] (an exponent in 125-µs micro-frames).
pub(crate) fn ep_ctx_d0(interval_exp: u8) -> u32 {
    u32::from(interval_exp) << 16
}

/// Endpoint context dword 1: CErr [2:1] (3), EP type [5:3], Max Packet
/// Size [31:16].
pub(crate) fn ep_ctx_d1(ep_type: u32, max_packet: u32) -> u32 {
    (3 << 1) | ((ep_type & 0x7) << 3) | ((max_packet & 0xFFFF) << 16)
}

fn put_words(pa: u64, words: &[u32]) {
    for (i, w) in words.iter().enumerate() {
        write_u32(pa + 4 * i as u64, *w);
    }
}

/// EP0's max packet before the device descriptor is read (the USB 2/3
/// defaults §4.5.2): 512 super-speed, 8 low-speed, 64 full/high-speed.
pub(crate) fn ep0_max_packet(speed: u32) -> u32 {
    match speed {
        4 => 512,
        2 => 8,
        _ => 64,
    }
}

/// The Address Device input context: add flags = slot + EP0 (the two
/// dwords QEMU demands be exactly 0/3), the slot context, EP0 (control,
/// CErr 3, the ring with DCS=1, average TRB length 8).
pub(crate) fn build_address_input_ctx(pa: u64, speed: u32, port1: u32, ep0_ring: u64) {
    put_words(pa, &[0, 0b11]);
    put_words(
        pa + CTX_SLOT,
        &[slot_ctx_d0(speed, 1), slot_ctx_d1(port1), 0, 0],
    );
    let ep0 = pa + 2 * CTX_SIZE;
    put_words(
        ep0,
        &[
            ep_ctx_d0(0),
            ep_ctx_d1(EP_CONTROL, ep0_max_packet(speed)),
            (ep0_ring | 1) as u32,
            (ep0_ring >> 32) as u32,
            8,
        ],
    );
}

/// The Evaluate Context input context: add flags = EP0 ONLY (bit 1; the
/// slot context is not re-added), EP0 with the max packet the device
/// descriptor reported.
pub(crate) fn build_evaluate_input_ctx(pa: u64, max_packet0: u32, ep0_ring: u64) {
    put_words(pa, &[0, 0b10]);
    let ep0 = pa + 2 * CTX_SIZE;
    put_words(
        ep0,
        &[
            ep_ctx_d0(0),
            ep_ctx_d1(EP_CONTROL, max_packet0),
            (ep0_ring | 1) as u32,
            (ep0_ring >> 32) as u32,
            8,
        ],
    );
}

/// The Configure Endpoint input context: add flags = slot + this one
/// endpoint (bits 0 and the context index), the slot context copied from
/// the live OUTPUT context with Context Entries raised to the endpoint's
/// index, the endpoint's own context at its index (QEMU reads it at
/// `ictx + 32 + 32 * index`).
#[allow(clippy::too_many_arguments)] // a full endpoint context: seven endpoint fields, one builder
pub(crate) fn build_configure_input_ctx(
    pa: u64,
    dev_ctx: u64,
    ctx_index: u32,
    ep_type: u32,
    max_packet: u32,
    interval_exp: u8,
    ring_pa: u64,
    avg_len: u32,
) {
    put_words(pa, &[0, 1 | (1 << (ctx_index & 0x1F))]);
    let d0 = read_u32(dev_ctx) & !(0x1F << 27);
    put_words(
        pa + CTX_SLOT,
        &[
            d0 | ((ctx_index & 0x1F) << 27),
            read_u32(dev_ctx + 4),
            read_u32(dev_ctx + 8),
            read_u32(dev_ctx + 12),
        ],
    );
    let ep = pa + CTX_SLOT + CTX_SIZE * u64::from(ctx_index & 0x1F);
    put_words(
        ep,
        &[
            ep_ctx_d0(interval_exp),
            ep_ctx_d1(ep_type, max_packet),
            (ring_pa | 1) as u32,
            (ring_pa >> 32) as u32,
            avg_len,
        ],
    );
}

/// The event-ring segment table: one segment of `EV_TRBS` TRBs.
pub(crate) fn build_erst(erst: u64, ev: u64) {
    write_u64(erst, ev);
    write_u32(erst + 8, EV_TRBS as u32);
}

/// bInterval → the endpoint context's Interval field (an exponent in
/// 125-µs micro-frames), the way Linux computes it (`xhci_get_endpoint_
/// interval` in drivers/usb/host/xhci.c): high/super-speed →
/// clamp(bInterval, 1, 16) − 1; full/low-speed → fls(8 · bInterval) − 1
/// clamped 3..=10. `None` for a zero bInterval (invalid).
pub(crate) fn interval_exponent(b_interval: u8, high_or_super: bool) -> Option<u8> {
    if b_interval == 0 {
        return None;
    }
    if high_or_super {
        Some(b_interval.clamp(1, 16) - 1)
    } else {
        Some(((u32::from(b_interval) * 8).ilog2() as u8).clamp(3, 10))
    }
}

/// The device descriptor's fields this driver uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeviceDescriptor {
    /// bDeviceClass.
    pub class: u8,
    /// idVendor.
    pub vid: u16,
    /// idProduct.
    pub pid: u16,
    /// bMaxPacketSize0.
    pub max_packet0: u8,
}

/// Parse a device descriptor; a short or mis-shaped buffer refuses.
pub(crate) fn parse_device_descriptor(d: &[u8]) -> Option<DeviceDescriptor> {
    if d.len() < 18 || d[0] != 18 || d[1] != 1 || !(1..=64).contains(&d[7]) {
        return None;
    }
    Some(DeviceDescriptor {
        class: d[4],
        vid: u16::from_le_bytes([d[8], d[9]]),
        pid: u16::from_le_bytes([d[10], d[11]]),
        max_packet0: d[7],
    })
}

/// The HID boot keyboard's interrupt-IN endpoint, as the config
/// descriptor names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BootKeyboard {
    /// bEndpointAddress & 0x0F.
    pub ep_num: u8,
    /// wMaxPacketSize (11 bits).
    pub max_packet: u16,
    /// The endpoint's bInterval (frames at full/low speed, 125-µs units at high speed).
    pub b_interval: u8,
    /// The interface the endpoint belongs to (for SET_IDLE / SET_PROTOCOL).
    pub interface: u8,
}

/// Walk a configuration descriptor (bounded by its own wTotalLength) and
/// return the HID boot-keyboard interface's interrupt-IN endpoint: class
/// 3, subclass 1, protocol 1. Malformed lengths refuse, never guess.
pub(crate) fn parse_boot_keyboard(d: &[u8]) -> Option<BootKeyboard> {
    if d.len() < 9 || d[0] != 9 || d[1] != 2 {
        return None;
    }
    let total = u16::from_le_bytes([d[2], d[3]]) as usize;
    if total < 9 || total > d.len() {
        return None;
    }
    let d = &d[..total];
    let mut i = 9usize;
    // (interface number, class, subclass, protocol) of the interface being walked.
    let mut iface: Option<(u8, [u8; 3])> = None;
    while i + 2 <= d.len() {
        let len = d[i] as usize;
        let ty = d[i + 1];
        if len < 2 || i + len > d.len() {
            return None;
        }
        match ty {
            4 => {
                if len < 9 {
                    return None;
                }
                iface = Some((d[i + 2], [d[i + 5], d[i + 6], d[i + 7]]));
            }
            5 => {
                if len < 7 {
                    return None;
                }
                let addr = d[i + 2];
                let attrs = d[i + 3];
                let is_kbd = iface.is_some_and(|(_, c)| c == [3, 1, 1]);
                if is_kbd && addr & 0x80 != 0 && attrs & 0x03 == 0x03 && addr & 0x0F != 0 {
                    return Some(BootKeyboard {
                        ep_num: addr & 0x0F,
                        max_packet: u16::from_le_bytes([d[i + 4], d[i + 5]]),
                        b_interval: d[i + 6],
                        interface: iface.map_or(0, |(n, _)| n),
                    });
                }
            }
            _ => {} // the HID descriptor (0x21) and anything else: no field the driver needs
        }
        i += len;
    }
    None
}

/// One usage id → ASCII (the US boot-keyboard layout).
fn usage_to_ascii(usage: u8, shift: bool) -> Option<u8> {
    let pick = |plain: u8, shifted: u8| Some(if shift { shifted } else { plain });
    match usage {
        0x04..=0x1D => pick(b'a' + (usage - 0x04), b'A' + (usage - 0x04)),
        0x1E..=0x26 => pick(b'1' + (usage - 0x1E), b'!' + (usage - 0x1E)),
        0x27 => pick(b'0', b')'),
        0x28 => Some(b'\n'),
        0x29 => Some(0x1B),
        0x2A => Some(0x08),
        0x2B => Some(0x09),
        0x2C => Some(b' '),
        0x2D => pick(b'-', b'_'),
        0x2E => pick(b'=', b'+'),
        0x2F => pick(b'[', b'{'),
        0x30 => pick(b']', b'}'),
        0x31 => pick(b'\\', b'|'),
        0x33 => pick(b';', b':'),
        0x34 => pick(b'\'', b'"'),
        0x35 => pick(b'`', b'~'),
        0x36 => pick(b',', b'<'),
        0x37 => pick(b'.', b'>'),
        0x38 => pick(b'/', b'?'),
        0x4C => Some(0x7F),
        _ => None,
    }
}

/// The HID boot-keyboard report: [modifiers, reserved, key1..key6]. The
/// first non-zero key usage decodes; either shift bit (0x02, 0x20) picks
/// the shifted table; Ctrl/Alt/GUI held, an empty report or an unmapped
/// key answer `None` — consumed, never pushed.
pub(crate) fn decode_hid_report(rep: &[u8]) -> Option<u8> {
    // Ctrl (0x11), Alt (0x44) and GUI (0x88) bits: not a plain character.
    if rep.len() < 8 || rep[0] & 0xDD != 0 {
        return None;
    }
    let shift = rep[0] & 0x22 != 0;
    rep[2..8]
        .iter()
        .find(|&&k| k != 0)
        .and_then(|&k| usage_to_ascii(k, shift))
}

/// Read `out.len()` bytes from a frame-aligned DMA buffer (dword reads,
/// little-endian lanes).
pub(crate) fn read_bytes(pa: u64, out: &mut [u8]) {
    for (i, b) in out.iter_mut().enumerate() {
        let w = read_u32(pa + (i & !3) as u64);
        *b = (w >> (8 * (i & 3))) as u8;
    }
}

// ── the protocol half (generic over the register surface) ──────────

/// A monotonic tick source for the bounded waits: the TSC on boot, a
/// counted fake in the host tests.
pub(crate) trait Ticker {
    fn now(&mut self) -> u64;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtoErr {
    /// A register access fell outside the validated BAR window.
    Window,
    /// The controller never answered within the budget.
    Timeout,
    /// USBSTS.HCE: the controller asserted a host controller error (a DMA it could not complete).
    Controller,
    /// A ring is out of free TRBs, or the controller reported the event ring full.
    RingFull,
}

/// The register geometry read from the capability block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    /// The operational base (= CAPLENGTH), window-relative.
    pub op: u64,
    /// Interrupter 0's block.
    pub intr: u64,
    /// Doorbell 0 (the command ring); doorbell n follows at + 4n.
    pub doorbells: u64,
    /// MaxSlots.
    pub max_slots: u32,
    /// MaxPorts, capped at the port-scan cap.
    pub max_ports: u32,
}

/// Read the capability block and prove the BAR window holds every
/// register this driver touches: the operational block, the port bank,
/// interrupter 0, and a doorbell per slot.
pub(crate) fn probe<B: MmioBus>(bus: &B) -> Option<Geometry> {
    let caplen = u64::from(bus.read8(0)?);
    let hcs1 = bus.read32(CAP_HCSPARAMS1)?;
    let op = caplen;
    let doorbells = u64::from(bus.read32(CAP_DBOFF)? & 0xFFFF);
    let intr = u64::from(bus.read32(CAP_RTSOFF)?) + INTR_OFF;
    let max_slots = hcs1 & 0xFF;
    let max_ports = (hcs1 >> 24).min(PORT_SCAN_CAP);
    let len = bus.window().len();
    let ports = u64::from(max_ports);
    let fits = len >= op + OP_PORTSC + PORT_STRIDE * ports + 4
        && len >= intr + RT_ERDP + 8
        && len >= doorbells + 4 * u64::from(max_slots) + 4;
    fits.then_some(Geometry {
        op,
        intr,
        doorbells,
        max_slots,
        max_ports,
    })
}

fn usbsts<B: MmioBus>(bus: &B, g: &Geometry) -> Result<u32, ProtoErr> {
    bus.read32(g.op + OP_USBSTS).ok_or(ProtoErr::Window)
}

/// Poll one register until `done`, at most `REG_SPINS` reads.
fn spin_until<B: MmioBus>(bus: &B, off: u64, done: impl Fn(u32) -> bool) -> Result<(), ProtoErr> {
    for _ in 0..REG_SPINS {
        if done(bus.read32(off).ok_or(ProtoErr::Window)?) {
            return Ok(());
        }
    }
    Err(ProtoErr::Timeout)
}

/// 64-bit register write, low dword then high — the order the spec (and
/// QEMU's register handlers, which act on the high half) require.
fn write64_lo_hi<B: MmioBus>(bus: &B, off: u64, v: u64) -> Result<(), ProtoErr> {
    if bus.write32(off, v as u32) && bus.write32(off + 4, (v >> 32) as u32) {
        Ok(())
    } else {
        Err(ProtoErr::Window)
    }
}

/// Stop the controller: RUN off, then wait for Halted. Called BEFORE the
/// rings are revoked — a running xHC keeps fetching TRBs from, and
/// posting events into, whatever memory its pointers name.
pub(crate) fn halt_controller<B: MmioBus>(bus: &B, op: u64, spins: u64) -> Result<(), ProtoErr> {
    let cmd = bus.read32(op + OP_USBCMD).ok_or(ProtoErr::Window)?;
    if cmd & USBCMD_RS != 0 {
        bus.write32(op + OP_USBCMD, cmd & !USBCMD_RS)
            .ok_or(ProtoErr::Window)?;
    }
    for _ in 0..spins {
        if bus.read32(op + OP_USBSTS).ok_or(ProtoErr::Window)? & USBSTS_HCH != 0 {
            return Ok(());
        }
    }
    Err(ProtoErr::Timeout)
}

/// Halt, then reset (HCRST), then wait out Controller Not Ready.
pub(crate) fn reset_controller<B: MmioBus>(bus: &B, g: &Geometry) -> Result<(), ProtoErr> {
    halt_controller(bus, g.op, REG_SPINS)?;
    bus.write32(g.op + OP_USBCMD, USBCMD_HCRST)
        .ok_or(ProtoErr::Window)?;
    spin_until(bus, g.op + OP_USBSTS, |v| v & USBSTS_CNR == 0)
}

/// Bring the controller up on a fresh DCBAA, command ring and a
/// one-segment event ring; returns once RUN is on and HCH has cleared.
pub(crate) fn start_controller<B: MmioBus>(
    bus: &B,
    g: &Geometry,
    dcbaa: u64,
    cmdring: u64,
    erst: u64,
    evring: u64,
) -> Result<(), ProtoErr> {
    write64_lo_hi(bus, g.op + OP_DCBAAP, dcbaa)?;
    bus.write32(g.op + OP_CONFIG, g.max_slots)
        .ok_or(ProtoErr::Window)?;
    write64_lo_hi(bus, g.op + OP_CRCR, cmdring | CRCR_RCS)?;
    // Interrupter 0. The segment table exists (ERSTSZ, ERSTBA — the
    // high half of ERSTBA makes the controller read it) before the
    // dequeue pointer names a slot inside it.
    bus.write32(g.intr + RT_ERSTSZ, 1).ok_or(ProtoErr::Window)?;
    write64_lo_hi(bus, g.intr + RT_ERSTBA, erst)?;
    write64_lo_hi(bus, g.intr + RT_ERDP, evring)?;
    bus.write32(g.op + OP_USBCMD, USBCMD_RS)
        .ok_or(ProtoErr::Window)?;
    spin_until(bus, g.op + OP_USBSTS, |v| v & USBSTS_HCH == 0)
}

/// Ring a doorbell: target 0 = the command ring (value 0), target n =
/// slot n (value = the endpoint id to kick).
pub(crate) fn ring_doorbell<B: MmioBus>(
    bus: &B,
    g: &Geometry,
    target: u32,
    value: u32,
) -> Result<(), ProtoErr> {
    bus.write32(g.doorbells + 4 * u64::from(target), value)
        .ok_or(ProtoErr::Window)
}

/// One port's status: (connected, enabled, speed in the PORTSC encoding).
pub(crate) fn port_status<B: MmioBus>(
    bus: &B,
    g: &Geometry,
    port: u32,
) -> Result<(bool, bool, u32), ProtoErr> {
    let v = bus
        .read32(g.op + OP_PORTSC + PORT_STRIDE * u64::from(port))
        .ok_or(ProtoErr::Window)?;
    Ok((
        v & PORTSC_CCS != 0,
        v & PORTSC_PED != 0,
        (v >> PORTSC_SPEED_SHIFT) & 0xF,
    ))
}

/// Reset one port (the USB bus reset every enumeration starts with) and
/// wait for its enable bit; a second write clears the change bits the
/// reset raised, keeping the port powered.
pub(crate) fn reset_port<B: MmioBus>(bus: &B, g: &Geometry, port: u32) -> Result<(), ProtoErr> {
    let reg = g.op + OP_PORTSC + PORT_STRIDE * u64::from(port);
    // PR is write-1-to-start; PP must stay 1 (a 0 powers the port off).
    bus.write32(reg, PORTSC_PP | PORTSC_PR)
        .ok_or(ProtoErr::Window)?;
    spin_until(bus, reg, |v| v & PORTSC_PED != 0)?;
    let raised = bus.read32(reg).ok_or(ProtoErr::Window)? & PORTSC_CHANGE;
    bus.write32(reg, PORTSC_PP | raised).ok_or(ProtoErr::Window)
}

/// The command ring + event ring pair one step drives.
pub(crate) struct Rings {
    cmd: u64,
    cmd_next: usize,
    ev: u64,
    cursor: EventCursor,
}

impl Rings {
    pub(crate) fn new(cmd: u64, ev: u64) -> Self {
        Self {
            cmd,
            cmd_next: 0,
            ev,
            cursor: EventCursor::new(),
        }
    }

    /// Write the next command TRB and ring the command doorbell.
    pub(crate) fn post_command<B: MmioBus>(
        &mut self,
        bus: &B,
        g: &Geometry,
        param: u64,
        ctrl: u32,
    ) -> Result<(), ProtoErr> {
        if self.cmd_next >= RING_TRBS {
            return Err(ProtoErr::RingFull);
        }
        put_trb(
            self.cmd,
            self.cmd_next,
            &Trb {
                param,
                status: 0,
                ctrl,
            },
        );
        self.cmd_next += 1;
        ring_doorbell(bus, g, 0, 0)
    }

    /// Post a command and wait for its completion event.
    pub(crate) fn command<B: MmioBus, T: Ticker>(
        &mut self,
        bus: &B,
        g: &Geometry,
        ticker: &mut T,
        param: u64,
        ctrl: u32,
        budget: u64,
    ) -> Result<Event, ProtoErr> {
        self.post_command(bus, g, param, ctrl)?;
        self.wait_event(bus, g, ticker, budget, |e| e.kind == ER_COMMAND_COMPLETE)
    }

    fn ack<B: MmioBus>(&self, bus: &B, g: &Geometry) -> Result<(), ProtoErr> {
        write64_lo_hi(bus, g.intr + RT_ERDP, self.cursor.erdp(self.ev))
    }

    /// Wait for the next event `accept` answers for, consuming (and
    /// acknowledging) everything before it — a port status change is
    /// never mistaken for a command's answer. Each consumed event
    /// advances ERDP, so the ring never reports full.
    pub(crate) fn wait_event<B: MmioBus, T: Ticker>(
        &mut self,
        bus: &B,
        g: &Geometry,
        ticker: &mut T,
        budget: u64,
        accept: impl Fn(&Event) -> bool,
    ) -> Result<Event, ProtoErr> {
        let start = ticker.now();
        loop {
            let (param, status, ctrl) = get_trb(self.ev, self.cursor.next);
            if let Some(ev) = decode_event(param, status, ctrl, self.cursor.cycle) {
                self.cursor.advance();
                self.ack(bus, g)?;
                if ev.kind == ER_HOST_CONTROLLER {
                    return Err(ProtoErr::RingFull);
                }
                if accept(&ev) {
                    return Ok(ev);
                }
            } else if ticker.now().wrapping_sub(start) > budget {
                // A controller that died (HCE) never posts again — name it.
                return Err(if usbsts(bus, g).is_ok_and(|v| v & USBSTS_HCE != 0) {
                    ProtoErr::Controller
                } else {
                    ProtoErr::Timeout
                });
            }
        }
    }
}

/// Queue a TD on a transfer ring at slot `next` and kick its endpoint
/// (doorbell `slot`, value = the endpoint id: 1 for EP0, 2n + 1 for EPn-IN).
/// TRBs are appended behind the controller's dequeue pointer and the
/// slots after them are zero, so the cycle state ends the TD exactly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn kick_transfer<B: MmioBus>(
    bus: &B,
    g: &Geometry,
    ring: u64,
    next: usize,
    trbs: &[Trb],
    slot: u32,
    ep_id: u32,
) -> Result<(), ProtoErr> {
    if next + trbs.len() > RING_TRBS {
        return Err(ProtoErr::RingFull);
    }
    for (i, t) in trbs.iter().enumerate() {
        put_trb(ring, next + i, t);
    }
    ring_doorbell(bus, g, slot, ep_id)
}

/// One EP0 control transfer: queue the TRBs, kick EP0, wait for its
/// completion event. `next` = the ring slot to build at.
#[allow(clippy::too_many_arguments)]
pub(crate) fn control<B: MmioBus, T: Ticker>(
    rings: &mut Rings,
    bus: &B,
    g: &Geometry,
    ticker: &mut T,
    ring: u64,
    next: usize,
    slot: u32,
    setup: u64,
    data: Option<DataStage>,
    budget: u64,
) -> Result<Event, ProtoErr> {
    let (trbs, n) = control_transfer(setup, data, true);
    kick_transfer(bus, g, ring, next, &trbs[..n], slot, 1)?;
    rings.wait_event(bus, g, ticker, budget, |e| {
        e.kind == ER_TRANSFER && e.slot == slot && e.ep == 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drvstack::testharness::{FakeBus, FakePhys, RegScript};

    /// A counted tick source: `step` ticks per call.
    struct FakeTicker(u64);
    impl Ticker for FakeTicker {
        fn now(&mut self) -> u64 {
            self.0 += 1;
            self.0
        }
    }

    fn qw(pa: u64, w: &[u32]) {
        put_words(pa, w);
    }

    #[test]
    fn address_input_ctx_passes_the_model_checks() {
        let phys = FakePhys::new(1);
        let pa = phys.pa(0);
        let ring = phys.pa(0x1000);
        build_address_input_ctx(pa, 3, 2, ring);
        // xhci_address_slot: ictl_ctx[0] == 0 && ictl_ctx[1] == 3.
        assert_eq!(read_u32(pa), 0);
        assert_eq!(read_u32(pa + 4), 3);
        // xhci_lookup_uport: root port = slot_ctx[1] >> 16, route string 0.
        assert_eq!((read_u32(pa + 0x24) >> 16) & 0xFF, 2);
        assert_eq!(
            read_u32(pa + 0x20) & 0xFFFFF,
            0,
            "a nonzero route string names a hub port"
        );
        assert_eq!((read_u32(pa + 0x20) >> 20) & 0xF, 3);
        assert_eq!(read_u32(pa + 0x20) >> 27, 1);
        // xhci_init_epctx on the EP0 words.
        let d0 = read_u32(pa + 0x40);
        let d1 = read_u32(pa + 0x44);
        assert_eq!((d1 >> 3) & 7, 4, "EP type control (spec + QEMU ET_CONTROL)");
        assert_eq!((d1 >> 3) & 7, EP_CONTROL, "…and the constant agrees");
        assert_eq!((d1 >> 1) & 3, 3, "CErr 3");
        assert_eq!(d1 >> 16, 64);
        assert_eq!(d1 & 0xFFFF, (3 << 1) | (4 << 3));
        assert_eq!(1u32 << ((d0 >> 16) & 0xFF), 1);
        assert_eq!(read_u64(pa + 0x48), ring | 1, "dequeue | DCS");
        assert_eq!(read_u32(pa + 0x50), 8);
    }

    #[test]
    fn configure_input_ctx_adds_exactly_the_slot_and_ep1_in() {
        let phys = FakePhys::new(2);
        let (ictx, octx) = (phys.pa(0), phys.pa(0x1000));
        let ring = phys.pa(0x2000);
        // The live output slot context QEMU wrote at Address Device.
        qw(octx, &[(3 << 20) | (1 << 27), 2 << 16, 0, (2 << 27) | 1]);
        build_configure_input_ctx(
            ictx,
            octx,
            ep_ctx_index(1, true),
            EP_INTERRUPT_IN,
            8,
            6,
            ring,
            8,
        );
        // xhci_configure_slot: (ictl[0] & 3) == 0 && (ictl[1] & 3) == 1.
        assert_eq!(read_u32(ictx) & 3, 0);
        assert_eq!(read_u32(ictx + 4) & 3, 1);
        assert_eq!(read_u32(ictx + 4), 1 | (1 << 3));
        assert_eq!(ep_ctx_index(1, true), 3);
        assert_eq!(
            read_u32(ictx + 0x20) >> 27,
            3,
            "Context Entries = the new index"
        );
        assert_eq!(read_u32(ictx + 0x20) & 0x07FF_FFFF, 3 << 20);
        assert_eq!(read_u32(ictx + 0x24), 2 << 16);
        // The endpoint context at ictx + 32 + 32 * 3 = +0x80.
        let d0 = read_u32(ictx + 0x80);
        let d1 = read_u32(ictx + 0x84);
        assert_eq!((d1 >> 3) & 7, EP_INTERRUPT_IN);
        assert_eq!((d1 >> 1) & 3, 3);
        assert_eq!(d1 >> 16, 8);
        assert_eq!(1u32 << ((d0 >> 16) & 0xFF), 64, "2^6 micro-frames = 8 ms");
        assert_eq!(read_u64(ictx + 0x88), ring | 1);
        assert_eq!(read_u32(ictx + 0x90), 8);
        // Evaluate Context re-adds EP0 only.
        build_evaluate_input_ctx(ictx, 8, ring);
        assert_eq!(read_u32(ictx), 0);
        assert_eq!(read_u32(ictx + 4) & 3, 2);
        assert_eq!(read_u32(ictx + 0x44) >> 16, 8);
    }

    #[test]
    fn control_transfer_trbs_pass_the_model_checks() {
        let dir = |t: &Trb| t.ctrl & TRB_DIR_IN != 0;
        let ty = |t: &Trb| (t.ctrl >> TRB_TYPE_SHIFT) & 0x3F;
        let buf = FakePhys::new(1).pa(0x100);
        // An IN transfer (GET_DESCRIPTOR): xhci_fire_ctl_transfer's four checks.
        let (t, n) = control_transfer(
            setup_packet(0x80, 6, 0x0100, 0, 18),
            Some(DataStage {
                buf,
                len: 18,
                dir_in: true,
            }),
            true,
        );
        assert_eq!(n, 3);
        assert_eq!(ty(&t[0]), 2);
        assert_eq!(t[0].status & 0x1FFFF, 8, "the Setup length must be 8");
        assert_eq!(ty(&t[2]), 4, "the last TRB must be STATUS");
        assert_ne!(t[0].ctrl & TRB_IDT, 0, "the Setup TRB must have IDT");
        assert_eq!((t[0].ctrl >> 16) & 3, 2, "TRT = IN data");
        assert_eq!(
            (t[0].ctrl >> 16) & 1,
            0,
            "no DIR on the Setup TRB (TRT IN = 0b10)"
        );
        assert!(
            dir(&t[1]),
            "an IN data stage carries DIR (xhci_xfer_create_sgl)"
        );
        assert!(!dir(&t[2]), "an IN transfer's status stage is OUT");
        assert_eq!(t[1].status & 0x1FFFF, 18);
        assert_eq!(t[1].param, buf);
        assert_ne!(t[2].ctrl & TRB_IOC, 0);
        assert_eq!(t[2].status & 0x1FFFF, 0);
        // An OUT transfer: the data stage drops DIR, the status stage is IN.
        let (t, n) = control_transfer(
            setup_packet(0x21, 0x09, 0x0200, 0, 2),
            Some(DataStage {
                buf,
                len: 2,
                dir_in: false,
            }),
            true,
        );
        assert_eq!(n, 3);
        assert!(!dir(&t[1]));
        assert!(dir(&t[2]));
        assert_eq!((t[0].ctrl >> 16) & 3, 3, "TRT = OUT data");
        // No data stage (SET_CONFIGURATION): SETUP + STATUS only.
        let (t, n) = control_transfer(setup_packet(0x00, 9, 1, 0, 0), None, true);
        assert_eq!(n, 2);
        assert_eq!((t[0].ctrl >> 16) & 3, 0, "TRT = no data");
        assert_eq!(ty(&t[1]), 4);
        assert!(dir(&t[1]));
        assert_ne!(t[1].ctrl & TRB_IOC, 0);
        assert_eq!(t[0].ctrl & TRB_CYCLE, 1);
        let (t, _) = control_transfer(0, None, false);
        assert_eq!(t[0].ctrl & TRB_CYCLE, 0);
        assert_eq!(setup_packet(0x80, 6, 0x0200, 0, 9), 0x0009_0000_0200_0680);
    }

    #[test]
    fn event_cursor_tracks_the_producer_cycle() {
        let phys = FakePhys::new(1);
        let ev = phys.pa(0);
        let mut c = EventCursor::new();
        // A zeroed slot (or one left from the previous lap) is not an event.
        assert_eq!(decode_event(0, 0, 0, true), None);
        assert_eq!(decode_event(0, 0, (33 << 10) | 1, false), None);
        assert_eq!(decode_event(0, 0, 1, true), None, "reserved type 0");
        // A command completion for slot 5: QEMU's event TRB layout.
        qw(ev, &[0, 0, 1 << 24, (5u32 << 24) | (33 << 10) | 1]);
        assert_eq!(
            decode_event(
                get_trb(ev, 0).0,
                get_trb(ev, 0).1,
                get_trb(ev, 0).2,
                c.cycle
            ),
            Some(Event {
                kind: 33,
                code: 1,
                slot: 5,
                ep: 0
            })
        );
        // A stalled transfer event (code 6) on EP1-IN (3) of slot 1.
        assert_eq!(
            decode_event(
                0x1000,
                6 << 24,
                (1 << 24) | (3 << 16) | (32 << 10) | 1,
                true
            ),
            Some(Event {
                kind: 32,
                code: 6,
                slot: 1,
                ep: 3
            })
        );
        assert_eq!(c.erdp(ev), ev | ERDP_EHB);
        for _ in 0..EV_TRBS {
            c.advance();
        }
        assert_eq!(
            c,
            EventCursor {
                next: 0,
                cycle: false
            },
            "one lap flips the cycle"
        );
        // The ERDP acknowledge always lands inside the segment (xhci_event's bounds check).
        for _ in 0..EV_TRBS {
            c.advance();
            let e = c.erdp(ev);
            assert!((ev..ev + 16 * EV_TRBS as u64).contains(&(e & !ERDP_EHB)));
        }
        assert!(c.cycle);
    }

    #[test]
    fn interval_and_packet_defaults() {
        assert_eq!(interval_exponent(7, true), Some(6)); // QEMU's high-speed usb-kbd: 8 ms
        assert_eq!(interval_exponent(10, false), Some(6)); // full-speed frames → 80 µ-frames
        assert_eq!(interval_exponent(1, false), Some(3));
        assert_eq!(interval_exponent(255, true), Some(15));
        assert_eq!(interval_exponent(0, true), None);
        assert_eq!(
            (
                ep0_max_packet(4),
                ep0_max_packet(3),
                ep0_max_packet(1),
                ep0_max_packet(2)
            ),
            (512, 64, 64, 8)
        );
    }

    /// QEMU's own usb-kbd descriptors (hw/usb/dev-hid.c): one config,
    /// one HID boot-keyboard interface, EP 0x81, maxp 8.
    fn qemu_keyboard_config(b_interval: u8) -> [u8; 64] {
        let mut c = [0u8; 64];
        let body: [u8; 34] = [
            9, 2, 34, 0, 1, 1, 0, 0xA0, 50, // config
            9, 4, 0, 0, 1, 3, 1, 1, 0, // interface: HID, boot, keyboard
            9, 0x21, 0x11, 1, 0, 1, 0x22, 0x3F, 0, // HID descriptor
            7, 5, 0x81, 3, 8, 0, b_interval, // interrupt-IN EP1
        ];
        c[..34].copy_from_slice(&body);
        c
    }

    #[test]
    fn the_config_walk_selects_the_boot_keyboard_only() {
        let k = parse_boot_keyboard(&qemu_keyboard_config(7)).unwrap();
        assert_eq!(
            (k.ep_num, k.max_packet, k.b_interval, k.interface),
            (1, 8, 7, 0)
        );
        let mut c = qemu_keyboard_config(0x0A);
        c[16] = 2; // the mouse's protocol
        assert_eq!(parse_boot_keyboard(&c), None);
        c[16] = 1;
        c[29] = 0x01; // an OUT endpoint address
        assert_eq!(parse_boot_keyboard(&c), None);
        c[29] = 0x81;
        c[2] = 35; // wTotalLength past the delivered bytes
        assert_eq!(parse_boot_keyboard(&c[..34]), None);
        c[2] = 34;
        // Walking only the delivered length is enough.
        assert!(parse_boot_keyboard(&c[..34]).is_some());
        // A mouse-only config (protocol 2, no boot subclass).
        let mut m = qemu_keyboard_config(0x0A);
        m[15] = 0;
        m[16] = 2;
        assert_eq!(parse_boot_keyboard(&m), None);
    }

    #[test]
    fn parsers_never_panic_on_garbage() {
        let mut rng = crate::drvstack::testharness::XorShift(0x5843_4843);
        let mut buf = [0u8; 128];
        for _ in 0..4000 {
            let n = (rng.next() % 128) as usize;
            for b in &mut buf[..n] {
                *b = rng.next() as u8;
            }
            let _ = parse_device_descriptor(&buf[..n]);
            let _ = parse_boot_keyboard(&buf[..n]);
            let _ = decode_hid_report(&buf[..n]);
        }
        // The QEMU device descriptor: class 0, vid 0x0627, pid 0x0001, EP0 64.
        let mut d = [0u8; 18];
        d[0] = 18;
        d[1] = 1;
        d[7] = 64;
        d[8] = 0x27;
        d[9] = 0x06;
        d[10] = 0x01;
        let p = parse_device_descriptor(&d).unwrap();
        assert_eq!((p.class, p.vid, p.pid, p.max_packet0), (0, 0x0627, 1, 64));
        d[7] = 0;
        assert_eq!(parse_device_descriptor(&d), None);
        d[7] = 64;
        assert_eq!(parse_device_descriptor(&d[..17]), None);
    }

    #[test]
    fn hid_reports_decode_the_boot_layout() {
        let mut rep = [0u8; 8];
        rep[2] = 0x04;
        assert_eq!(decode_hid_report(&rep), Some(b'a'));
        rep[0] = 0x02;
        assert_eq!(decode_hid_report(&rep), Some(b'A'));
        rep[0] = 0x20;
        assert_eq!(decode_hid_report(&rep), Some(b'A'));
        rep[0] = 0x01;
        assert_eq!(
            decode_hid_report(&rep),
            None,
            "Ctrl held is not a character"
        );
        rep[0] = 0;
        for (usage, plain, shifted) in [
            (0x1Eu8, b'1', b'!'),
            (0x22, b'5', b'%'),
            (0x27, b'0', b')'),
            (0x2C, b' ', b' '),
            (0x2D, b'-', b'_'),
            (0x2E, b'=', b'+'),
            (0x2F, b'[', b'{'),
            (0x30, b']', b'}'),
            (0x31, b'\\', b'|'),
            (0x33, b';', b':'),
            (0x34, b'\'', b'"'),
            (0x35, b'`', b'~'),
            (0x36, b',', b'<'),
            (0x37, b'.', b'>'),
            (0x38, b'/', b'?'),
        ] {
            rep[2] = usage;
            assert_eq!(decode_hid_report(&rep), Some(plain));
            rep[0] = 0x22;
            assert_eq!(decode_hid_report(&rep), Some(shifted));
            rep[0] = 0;
        }
        rep[2] = 0x28;
        assert_eq!(decode_hid_report(&rep), Some(b'\n'));
        rep[2] = 0x2A;
        assert_eq!(decode_hid_report(&rep), Some(0x08));
        rep[2] = 0x2B;
        assert_eq!(decode_hid_report(&rep), Some(0x09));
        rep[2] = 0x4F; // right arrow
        assert_eq!(decode_hid_report(&rep), None);
        rep[2] = 0;
        rep[7] = 0x04;
        assert_eq!(
            decode_hid_report(&rep),
            Some(b'a'),
            "the first non-zero key slot"
        );
        rep[7] = 0;
        assert_eq!(decode_hid_report(&rep), None, "the released state");
        assert_eq!(decode_hid_report(&[0, 0, 4]), None, "a short report");
    }

    #[test]
    fn read_bytes_assembles_dword_lanes() {
        let phys = FakePhys::new(1);
        let pa = phys.pa(0);
        qw(pa + 4, &[0x4433_2211]);
        let mut out = [0u8; 8];
        read_bytes(pa, &mut out);
        assert_eq!(out, [0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44]);
    }

    /// QEMU's register layout behind a scripted bus: CAPLENGTH 0x40,
    /// DBOFF 0x2000, RTSOFF 0x1000, 64 slots, 8 ports.
    fn qemu_bus(len: u64) -> FakeBus {
        let mut bus = FakeBus::new(0xFEB0_0000, len);
        bus.set(0x00, RegScript::Constant(0x0100_0040));
        bus.set(0x04, RegScript::Constant((8 << 24) | (1 << 8) | 64));
        bus.set(0x14, RegScript::Constant(0x2000));
        bus.set(0x18, RegScript::Constant(0x1000));
        bus
    }

    #[test]
    fn probe_requires_room_for_every_register() {
        let g = probe(&qemu_bus(0x4000)).unwrap();
        assert_eq!(
            g,
            Geometry {
                op: 0x40,
                intr: 0x1020,
                doorbells: 0x2000,
                max_slots: 64,
                max_ports: 8
            }
        );
        // Too small for the doorbells (0x2000 + 4 * 64 + 4): refused.
        assert!(probe(&qemu_bus(0x2000)).is_none());
        assert!(probe(&qemu_bus(0x2104)).is_some());
        assert!(probe(&qemu_bus(0x480)).is_none(), "no port bank");
        // A hostile HCSPARAMS1 (255 ports, 255 slots) still only asks
        // for what the window can hold: capped ports, every doorbell.
        let mut bus = qemu_bus(0x4000);
        bus.set(0x04, RegScript::Constant(u32::MAX));
        let g = probe(&bus).unwrap();
        assert_eq!((g.max_ports, g.max_slots), (16, 255));
        let mut hostile = qemu_bus(0x23F8);
        hostile.set(0x04, RegScript::Constant(u32::MAX));
        assert!(probe(&hostile).is_none());
        assert_eq!(probe(&qemu_bus(0x23F8)).unwrap().max_slots, 64);
    }

    #[test]
    fn bring_up_and_tear_down_write_the_model_registers() {
        let mut bus = qemu_bus(0x4000);
        // USBSTS reads: not halted, halted (the halt wait), CNR clear,
        // then HCH clear once RUN is written.
        bus.set(0x44, RegScript::Sequence(vec![0, 1, 0, 0, 0]));
        let g = probe(&bus).unwrap();
        reset_controller(&bus, &g).unwrap();
        assert_eq!(bus.write_log.borrow()[&0x40], USBCMD_HCRST);
        start_controller(&bus, &g, 0x1000_0000, 0x1001_0000, 0x1002_0000, 0x1003_0000).unwrap();
        let log = bus.write_log.borrow();
        assert_eq!(
            (log[&0x70], log[&0x74]),
            (0x1000_0000, 0),
            "DCBAAP low then high"
        );
        assert_eq!(log[&0x78], 64, "MaxSlotsEn");
        assert_eq!((log[&0x58], log[&0x5C]), (0x1001_0001, 0), "CRCR | RCS");
        assert_eq!(log[&0x1028], 1, "ERSTSZ");
        assert_eq!(
            log[&0x1030], 0x1002_0000,
            "ERSTBA low (the high write arms it)"
        );
        assert_eq!(log[&0x1034], 0);
        assert_eq!(log[&0x1038], 0x1003_0000, "ERDP inside the segment");
        assert_eq!(log[&0x40], USBCMD_RS);
        drop(log);
        // Doorbells: the command ring, and slot 3's EP1-IN (xhci_doorbell_write).
        ring_doorbell(&bus, &g, 0, 0).unwrap();
        ring_doorbell(&bus, &g, 3, 3).unwrap();
        assert_eq!(bus.write_log.borrow()[&0x2000], 0);
        assert_eq!(bus.write_log.borrow()[&0x200C], 3);
        // The port reset: PR | PP, then the change bits cleared with PP kept.
        bus.set(0x440, RegScript::Constant(0x00A2_0003));
        reset_port(&bus, &g, 0).unwrap();
        let log = bus.write_log.borrow();
        assert_eq!(
            log[&0x440],
            PORTSC_PP | 0x00A2_0000,
            "PP kept, the three raised change bits cleared"
        );
        assert_eq!(0x00A2_0001 & PORTSC_CHANGE, 0x00A2_0000);
        assert_eq!(
            0x00A2_0001 & PORTSC_CHANGE & 1,
            0,
            "CCS is never written back"
        );
        drop(log);
        bus.set(0x44, RegScript::Constant(1));
        bus.set(0x40, RegScript::Constant(USBCMD_RS));
        halt_controller(&bus, g.op, 64).unwrap();
        assert_eq!(
            bus.write_log.borrow()[&0x40],
            0,
            "RUN off before the rings go home"
        );
        // A window that cannot hold the registers: refused, nothing sent.
        let small = qemu_bus(0x20);
        assert_eq!(halt_controller(&small, 0x40, 8), Err(ProtoErr::Window));
        assert!(small.write_log.borrow().is_empty());
    }

    #[test]
    fn event_waits_consume_skip_and_time_out() {
        let phys = FakePhys::new(3);
        let (ev, cmd) = (phys.pa(0), phys.pa(0x1000));
        let mut bus = qemu_bus(0x4000);
        let g = probe(&bus).unwrap();
        let mut rings = Rings::new(cmd, ev);
        let mut ticker = FakeTicker(0);
        // Nothing posted: a bounded wait answers Timeout (no HCE).
        assert_eq!(
            rings.wait_event(&bus, &g, &mut ticker, 50, |_| true),
            Err(ProtoErr::Timeout)
        );
        // A port status change (34) then the command completion for slot 2.
        qw(ev, &[0, 0, 1, (34 << 10) | 1]);
        qw(
            ev + 16,
            &[cmd as u32, 0, 1 << 24, (2 << 24) | (33 << 10) | 1],
        );
        let e = rings
            .wait_event(&bus, &g, &mut ticker, 1000, |e| {
                e.kind == ER_COMMAND_COMPLETE
            })
            .unwrap();
        assert_eq!(
            e,
            Event {
                kind: 33,
                code: 1,
                slot: 2,
                ep: 0
            }
        );
        assert_eq!(rings.cursor.next, 2, "both events consumed");
        assert_eq!(
            bus.write_log.borrow()[&0x1038],
            (ev + 32) as u32 | ERDP_EHB as u32
        );
        assert_eq!(bus.write_log.borrow()[&0x103C], ((ev + 32) >> 32) as u32);
        // The controller died (HCE): named, not a silent timeout.
        bus.set(0x44, RegScript::Constant(1 << 12));
        assert_eq!(
            rings.wait_event(&bus, &g, &mut ticker, 50, |_| true),
            Err(ProtoErr::Controller)
        );
        // The command ring posts at successive slots and rings doorbell 0.
        rings
            .post_command(&bus, &g, 0x1000_0000, cmd_ctrl(CR_ADDRESS_DEVICE, true, 2))
            .unwrap();
        assert_eq!(get_trb(cmd, 0), (0x1000_0000, 0, cmd_ctrl(11, true, 2)));
        assert_eq!(bus.write_log.borrow()[&0x2000], 0);
        let e = decode_event(
            get_trb(ev + 32, 2).0,
            1 << 24,
            (2 << 24) | (33 << 10) | 1,
            true,
        )
        .unwrap();
        assert_eq!(e.code, CC_SUCCESS);
        // A TD lands on the EP ring and its doorbell is the SLOT's.
        let (trbs, n) = control_transfer(setup_packet(0x80, 6, 0x0100, 0, 18), None, true);
        kick_transfer(&bus, &g, ev + 0x800, 4, &trbs[..n], 2, 1).unwrap();
        assert_eq!(
            get_trb(ev + 0x800, 4),
            (trbs[0].param, trbs[0].status, trbs[0].ctrl)
        );
        assert_eq!(
            get_trb(ev + 0x800, 6).2 & TRB_CYCLE,
            0,
            "the slot after the TD ends the chain"
        );
        assert_eq!(bus.write_log.borrow()[&0x2008], 1);
        assert_eq!(
            kick_transfer(&bus, &g, ev + 0x800, 255, &trbs[..n], 2, 1),
            Err(ProtoErr::RingFull)
        );
        let erst = phys.pa(0x2000);
        build_erst(erst, ev);
        assert_eq!((read_u64(erst), read_u32(erst + 8)), (ev, EV_TRBS as u32));
    }
}
