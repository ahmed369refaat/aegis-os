//! xHCI: the operational + runtime registers, port detection, the command ring.

use super::{line, revoke_or_quarantine};
use crate::frames::FramePool;
use crate::strutil;

/// The pool owner tag for xHCI frames (DCBAA + command ring).
pub const XHCI_OWNER: u32 = 48;

#[cfg(not(test))]
pub(crate) fn xhci_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::{DmaDir, DmaVerdict};

    let Some(dev) = inv.find_by(0x1B36, 0x0C) else {
        line(out, &["[XHCI] no xHCI to drive on this machine"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[XHCI] broker verdict absent — refusing to drive"]);
        return;
    }
    let Some(base) = crate::pci::mem_bar_base(dev, 0) else {
        line(out, &["[XHCI] BAR0 unresolved — refusing"]);
        return;
    };
    // F9e: MEM now; BME after the bring-up frames are mapped.
    crate::pci::enable_mem(dev);
    let caplen = u64::from(crate::virtio::read_u8_pa(base));
    let ver = crate::memops::read_u16(base + 2);
    let hcs1 = crate::memops::read_u32(base + 4);
    let max_slots = hcs1 & 0xFF;
    let max_ports = hcs1 >> 24;
    let op = base + caplen;
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
    crate::memops::write_u32(op, 0); // !RUN
    let mut spins = 0u64;
    while crate::memops::read_u32(op + 4) & 1 == 0 && spins < 4_000_000 {
        spins += 1;
    }
    let halted = crate::memops::read_u32(op + 4) & 1 != 0;
    crate::memops::write_u32(op, 2); // HCRST
    let mut spins = 0u64;
    while crate::memops::read_u32(op + 4) & (1 << 11) != 0 && spins < 8_000_000 {
        spins += 1;
    } // CNR clear

    let mut frames = [0u64; 2];
    for slot in frames.iter_mut() {
        match pool.alloc_for(&mut k.frames, XHCI_OWNER) {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[XHCI] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [dcbaa, cmdring] = frames;
    for &pa in frames.iter() {
        if broker
            .map_region(0, pa, 4096, DmaDir::Bidirectional)
            .is_err()
        {
            line(out, &["[XHCI] broker refused a frame — refusing"]);
            return;
        }
    }
    crate::memops::write_u64(op + 0x30, dcbaa); // DCBAAP
    crate::memops::write_u32(op + 0x38, max_slots); // MaxSlotsEn
    crate::memops::write_u64(op + 0x18, cmdring | 1); // CRCR + cycle
    crate::memops::write_u32(op, 1); // RUN
    let mut spins = 0u64;
    while crate::memops::read_u32(op + 4) & 1 != 0 && spins < 8_000_000 {
        spins += 1;
    }
    let running = crate::memops::read_u32(op + 4) & 1 == 0;
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
    for p in 0..max_ports.min(16) {
        let psc = crate::memops::read_u32(op + 0x400 + 0x10 * u64::from(p));
        if psc & 1 != 0 {
            found = Some((p, (psc >> 10) & 0xF));
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
    revoke_or_quarantine(
        k,
        pool,
        out,
        broker,
        XHCI_OWNER,
        &frames,
        Some(dev),
        "[XHCI] teardown: revoke_all(0) → ",
    );
}

// ── ACPI table completion (item 14) + HPET (item 15): walk the
// RSDT/XSDT the discovery already found, then drive the HPET's main
// counter (register-only: fully proven) ──

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
    use aegis_os::dma::{DmaDir, DmaVerdict};

    let Some(dev) = inv.find_by(0x1B36, 0x0C) else {
        line(out, &["[XTRB] no xHCI — skipping"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[XTRB] broker verdict absent — refusing"]);
        return;
    }
    let Some(base) = crate::pci::mem_bar_base(dev, 0) else {
        line(out, &["[XTRB] BAR0 unresolved — refusing"]);
        return;
    };
    let caplen = u64::from(crate::virtio::read_u8_pa(base));
    let op = base + caplen;
    // The xHCI bring-up slice (xhci_step) already ran: RUN is on,
    // DCBAAP/CRCR point at ITS frames — which were freed+scrubbed at
    // its teardown! Re-bring-up with fresh frames here.
    crate::memops::write_u32(op, 0); // !RUN
    let mut spins = 0u64;
    while crate::memops::read_u32(op + 4) & 1 == 0 && spins < 4_000_000 {
        spins += 1;
    }
    crate::memops::write_u32(op, 2); // HCRST
    let mut spins = 0u64;
    while crate::memops::read_u32(op + 4) & (1 << 11) != 0 && spins < 8_000_000 {
        spins += 1;
    }
    let dboff = u64::from(crate::memops::read_u32(base + 0x14) & 0xFFFF);
    let rtsoff = u64::from(crate::memops::read_u32(base + 0x18));

    // Frames: DCBAA, command ring, event ring, ERST (segment table).
    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match pool.alloc_for(&mut k.frames, XHCI_OWNER) {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[XTRB] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [dcbaa, cmdring, evring, erst] = frames;
    for &pa in frames.iter() {
        if broker
            .map_region(0, pa, 4096, DmaDir::Bidirectional)
            .is_err()
        {
            line(out, &["[XTRB] broker refused a frame — refusing"]);
            return;
        }
    }
    // ERST entry 0: the event-ring segment (64 TRBs).
    crate::memops::write_u64(erst, evring);
    crate::memops::write_u64(erst + 8, 64);

    crate::memops::write_u64(op + 0x30, dcbaa); // DCBAAP
    crate::memops::write_u32(op + 0x38, 1); // MaxSlotsEn (one slot is plenty)
    crate::memops::write_u64(op + 0x18, cmdring | 1); // CRCR + cycle
                                                      // Interrupter 0: ERSTSZ=1, ERSTBA, ERDP.
    let intr = base + rtsoff + 0x20;
    crate::memops::write_u32(intr + 0x08, 1); // ERSTSZ: IMAN+0,IMOD+4,ERSTSZ+8
    crate::memops::write_u64(intr + 0x10, erst); // ERSTBA
    crate::memops::write_u64(intr + 0x18, evring); // ERDP (segment 0)
    crate::memops::write_u32(op, 1); // RUN
    let mut spins = 0u64;
    while crate::memops::read_u32(op + 4) & 1 != 0 && spins < 8_000_000 {
        spins += 1;
    }
    let crcr0 = crate::memops::read_u64(op + 0x18) & 0xFFFF_FFF0;

    // No-Op command TRB at slot 0: type=8 (bits 10-15 of dword 3),
    // cycle bit set to match CRCR's RCS=1.
    crate::memops::write_u64(cmdring, 0);
    crate::memops::write_u64(cmdring + 8, 0);
    crate::memops::write_u64(cmdring + 16, 0);
    crate::memops::write_u32(cmdring + 12, (8u32 << 10) | 1);
    crate::memops::write_u32(base + dboff, 0); // doorbell 0 = command ring

    let mut spins = 0u64;
    let mut crcr1 = crate::memops::read_u64(op + 0x18) & 0xFFFF_FFF0;
    while crcr1 == crcr0 && spins < 10_000_000 {
        crcr1 = crate::memops::read_u64(op + 0x18) & 0xFFFF_FFF0;
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
    revoke_or_quarantine(
        k,
        pool,
        out,
        broker,
        XHCI_OWNER,
        &frames,
        Some(dev),
        "[XTRB] teardown: revoke_all(0) → ",
    );
}
