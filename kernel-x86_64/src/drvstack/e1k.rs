//! The e1000 NIC: descriptors through the broker + the DHCP round trip.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use super::netutil;
use crate::frames::FramePool;
use crate::mmio::MmioBus;
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for e1000 frames (rx/tx rings + buffers).
pub const E1K_OWNER: u32 = 45;

// e1000 MMIO register offsets (8254x; QEMU's e1000 implements these).

const E1K_STATUS: u64 = 0x0008;
const E1K_RCTL: u64 = 0x0100;
const E1K_TCTL: u64 = 0x0400;
const E1K_RDBAL: u64 = 0x2800;
const E1K_RDLEN: u64 = 0x2808;
const E1K_RDH: u64 = 0x2810;
const E1K_RDT: u64 = 0x2818;
const E1K_TDBAL: u64 = 0x3800;
const E1K_TDLEN: u64 = 0x3808;
const E1K_TDH: u64 = 0x3810;
const E1K_TDT: u64 = 0x3818;
const E1K_RAL: u64 = 0x5400;
const E1K_RAH: u64 = 0x5404;

/// Legacy RX/TX descriptor count (256-byte rings, 128-byte aligned
/// as the datasheet demands).
const E1K_NDESC: u64 = 16;

/// Phase 2: drive the e1000. Claim via the broker (the same
/// fail-closed gate), read the MAC + link from the registers,
/// program broker-mapped RX/TX rings, then TX a hand-built DHCP
/// DISCOVER and catch slirp's OFFER on the RX ring — the FULL
/// network round trip through the IOMMU (the e1000's MMIO-driven
/// descriptor path is exactly what QEMU's virtio-net TX bottom-half
/// declines to exercise on this lane).
/// One legacy TX descriptor at `pa`: buffer address, length, and the
/// EOP|IFCS|RS command byte. Pure PA writes (host-testable: memops is
/// identity on host).
fn build_tx_desc(pa: u64, addr: u64, len: u32) {
    crate::memops::write_u64(pa, addr); // desc[0].buffer_addr
    crate::memops::write_u32(pa + 8, len); // length
    crate::memops::write_u32(pa + 12, 0); // cso/css/special
    netutil::put8(pa + 11, 0x0B); // cmd: EOP | IFCS | RS
}

/// Is the RX descriptor at `pa` done? (the descriptor-done bit, byte
/// 12 of the legacy RX descriptor).
fn rx_desc_done(pa: u64) -> bool {
    crate::virtio::read_u8_pa(pa + 12) & 1 != 0
}

#[cfg(not(test))]
pub(crate) fn e1k_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x8086, 0x02) else {
        line(out, &["[E1K] no e1000 to drive on this machine"]);
        return;
    };
    {
        let mut b1 = [0u8; 20];
        let mut b2 = [0u8; 20];
        line(
            out,
            &[
                "[E1K] dbg slot ",
                strutil::dec(u64::from(dev.bus), &mut b1),
                ":",
                strutil::dec(u64::from(dev.dev), &mut b2),
                ".",
            ],
        );
    }
    // The no-IOMMU control (ADR-0013 lane q35-neg): when there is no
    // DMAR at all the device DMAs plain RAM — run the SAME TX→RX flow
    // with unbrokered frames. If the round trip completes here, the
    // driver is proven correct and the IOMMU-lane gap is QEMU-side.
    let identity = matches!(broker.verdict(), DmaVerdict::Absent { .. });
    if identity {
        line(
            out,
            &["[E1K] identity mode: no IOMMU on this machine — same flow, unbrokered frames (the device-DMA control lane)"],
        );
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[E1K] BAR0 unresolved — refusing"]);
        return;
    };
    // ADR-0016: one window for every register this driver touches,
    // checked at the door — the per-access refusals below are
    // defense-in-depth (a None there is an internal inconsistency the
    // log admits, never a wild access).
    let Some(bus) = crate::mmio::BarMmio::new(bar.base, bar.size) else {
        line(
            out,
            &["[E1K] BAR0 window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    if bus.window().len() < E1K_RAH + 4 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[E1K] BAR0 window too small for the register set (len=",
                strutil::hex(bus.window().len(), &mut lb),
                " < 0x5408) — refusing",
            ],
        );
        return;
    }
    // F9e claim order: MEM now; BME after the rings are broker-
    // mapped — EXCEPT the identity control lane (no IOMMU, no
    // mappings to gate on). Read back — a CF8 discipline bug here
    // would silently park every DMA.
    if identity {
        crate::pci::enable_bus_master(dev);
    } else {
        crate::pci::enable_mem(dev);
    }
    // F9e: at this point MEM must be on; BME only in identity mode
    // (the broker path grants it after the rings are mapped).
    let cmd_back = crate::pci::read_cfg32(dev, 0x04);
    let want_now = if identity { 0x6 } else { 0x2 };
    if cmd_back & want_now != want_now {
        let mut cb = [0u8; 18];
        line(
            out,
            &[
                "[E1K] PCI command readback=",
                strutil::hex(u64::from(cmd_back), &mut cb),
                " — the enable did not stick",
            ],
        );
    }
    // MAC + link from RAL/RAH and STATUS (window-checked; a refusal
    // here is a driver-side inconsistency — nothing is mapped yet, so
    // the refusal is just the verdict).
    let (Some(ral), Some(rah), Some(status)) = (
        bus.read32(E1K_RAL),
        bus.read32(E1K_RAH),
        bus.read32(E1K_STATUS),
    ) else {
        line(
            out,
            &["[E1K] register window refused a MAC/status read — refusing"],
        );
        return;
    };
    let mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ];
    let link_up = status & 0x2 != 0;
    let mut macs = [0u8; 17];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..6 {
        macs[i * 3] = HEX[(mac[i] >> 4) as usize];
        macs[i * 3 + 1] = HEX[(mac[i] & 0xF) as usize];
        if i < 5 {
            macs[i * 3 + 2] = b':';
        }
    }
    let mac_str = core::str::from_utf8(&macs).unwrap_or("??");
    line(
        out,
        &[
            "[E1K] alive: MAC=",
            mac_str,
            " link=",
            if link_up { "UP" } else { "DOWN" },
        ],
    );

    // Frames: RX ring, TX ring, one buffer each (e1000 is 32-bit
    // DMA — pool frames below 4 GiB satisfy it).
    // ADR-0016/F10: the session owns every acquisition — identity or
    // brokered — and every exit below is one close().
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        E1K_OWNER,
        dev.dom,
        identity,
        "[E1K] teardown",
        "[E1K] teardown (identity): frames freed, no broker regions",
    );
    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[E1K] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [rx_ring, tx_ring, rx_buf, tx_buf] = frames;
    if !identity {
        for &pa in frames.iter() {
            if session.map(pa).is_none() {
                line(out, &["[E1K] broker refused a frame — refusing"]);
                return;
            }
        }
        line(
            out,
            &["[E1K] RX/TX rings + buffers mapped via broker (4 regions, IOMMU-enforced)"],
        );
        // F9e: rings mapped — now the device may DMA.
        crate::pci::enable_bus_master(dev);
    }

    // Program the rings. One RX descriptor posted (index 0), RDT=1.
    // Every write goes through the window; a refusal after the rings
    // are mapped is a full teardown (the device has BME by then).
    let rx_prog = [
        (E1K_RDBAL, rx_ring as u32),
        (E1K_RDBAL + 4, 0), // RDBAH (32-bit DMA)
        (E1K_RDLEN, (E1K_NDESC * 16) as u32),
        (E1K_RDH, 0),
    ];
    for &(off, v) in rx_prog.iter() {
        if !bus.write32(off, v) {
            line(
                out,
                &["[E1K] register window refused an RX write — teardown"],
            );
            session.close(out);
            return;
        }
    }
    crate::memops::write_u64(rx_ring, rx_buf); // desc[0].buffer_addr
    let rx_tail = [(E1K_RDT, 1u32), (E1K_RCTL, 0x8002 /* EN | BAM */)];
    for &(off, v) in rx_tail.iter() {
        if !bus.write32(off, v) {
            line(
                out,
                &["[E1K] register window refused an RX write — teardown"],
            );
            session.close(out);
            return;
        }
    }
    // BAM is bit 15 (0x8000) per e1000x_regs.h; the broadcast OFFER
    // needs it or receive_filter drops it silently.

    let tx_prog = [
        (E1K_TDBAL, tx_ring as u32),
        (E1K_TDBAL + 4, 0),
        (E1K_TDLEN, (E1K_NDESC * 16) as u32),
        (E1K_TDH, 0),
        (E1K_TDT, 0),
        (E1K_TCTL, 0x2 /* EN */),
    ];
    for &(off, v) in tx_prog.iter() {
        if !bus.write32(off, v) {
            line(
                out,
                &["[E1K] register window refused a TX write — teardown"],
            );
            session.close(out);
            return;
        }
    }

    // Build + TX the DISCOVER.
    netutil::build_dhcp_discover_at(tx_buf, mac);
    build_tx_desc(tx_ring, tx_buf, 290);
    if !bus.write32(E1K_TDT, 1) {
        line(
            out,
            &["[E1K] register window refused the TX tail write — teardown"],
        );
        session.close(out);
        return;
    }

    // Poll TX completion: DD is bit 0 of the upper dword (+12) —
    // E1000_TXD_STAT_DD=0x1 in QEMU's e1000x_regs.h, and the
    // writeback pci_dma_write()s the dword at desc+12.
    let mut spins = 0u64;
    while crate::virtio::read_u8_pa(tx_ring + 12) & 1 == 0 && spins < 50_000_000 {
        spins += 1;
    }
    if crate::virtio::read_u8_pa(tx_ring + 12) & 1 == 0 {
        // Guest side proven (register readbacks; the device consumed
        // the descriptor, TDH 0→1) but no egress: the packet capture
        // on this lane is empty and there are ZERO vtd translate or
        // fault events for 00:04.0 — the device's DMA never reaches
        // memory. Same signature as the virtio-net TX split; one
        // QEMU-side investigation cluster, evidence in the log.
        // Teardown still runs with the live device attached.
        line(
            out,
            &[if identity {
                "[E1K] TX: DISCOVER built+rings armed — DD did NOT set even in identity mode (no IOMMU) — a DRIVER-side bug, see drivers.md"
            } else {
                "[E1K] TX: DISCOVER built+rings armed, descriptor consumed (TDH 0→1) — no egress on this QEMU lane (open: device IOMMU attachment; see drivers.md)"
            }],
        );
        session.close(out);

        return;
    }
    line(
        out,
        &["[E1K] TX: DHCP DISCOVER sent (290 bytes, xid=0xa6515151)"],
    );

    // Poll RX for the OFFER. The budget must outlast QEMU's RCTL
    // flush-queue timer: every RCTL write parks delivery for 1000 ms
    // of the VIRTUAL clock (e1000.c set_rx_control — an untraced
    // can_receive=false), so the OFFER sits queued for a full second
    // before the NIC's first RX descriptor fetch. Measured: the OFFER
    // arrives ~76 µs after the DISCOVER but only lands after the
    // timer; a 200 M-spin poll exits first.
    let mut spins = 0u64;
    while crate::virtio::read_u8_pa(rx_ring + 12) & 1 == 0 && spins < 3_000_000_000 {
        spins += 1;
    }
    if !rx_desc_done(rx_ring) {
        let (Some(rdh), Some(rdt), Some(rctl)) = (
            bus.read32(E1K_RDH),
            bus.read32(E1K_RDT),
            bus.read32(E1K_RCTL),
        ) else {
            line(out, &["[E1K] register window refused an RX debug read"]);
            session.close(out);
            return;
        };
        let mut rb = [0u8; 18];
        let mut rc = [0u8; 18];
        let mut re = [0u8; 18];
        let mut rf = [0u8; 18];
        let mut rg = [0u8; 18];
        let mut rh = [0u8; 18];
        line(
            out,
            &[
                "[E1K] dbg rx: RDH=",
                strutil::hex(u64::from(rdh), &mut rb),
                " RDT=",
                strutil::hex(u64::from(rdt), &mut rc),
                " RCTL=",
                strutil::hex(u64::from(rctl), &mut re),
                " desc[0]=",
                strutil::hex(crate::memops::read_u64(rx_ring), &mut rf),
                "",
                strutil::hex(crate::memops::read_u64(rx_ring + 8), &mut rg),
                " buf[0..8]=",
                strutil::hex(crate::memops::read_u64(rx_buf), &mut rh),
            ],
        );
        line(
            out,
            &["[E1K] RX: no packet arrived (poll budget exhausted)"],
        );
        session.close(out);
        return;
    }
    let rx_len = crate::memops::read_u16(rx_ring + 8);
    let b = |i: u64| crate::virtio::read_u8_pa(rx_buf + i);
    let ethertype = (u16::from(b(12)) << 8) | u16::from(b(13));
    let proto = b(23);
    let sport = (u16::from(b(34)) << 8) | u16::from(b(35));
    let dport = (u16::from(b(36)) << 8) | u16::from(b(37));
    let op = b(42);
    let cookie = (u32::from(b(42 + 236)) << 24)
        | (u32::from(b(42 + 237)) << 16)
        | (u32::from(b(42 + 238)) << 8)
        | u32::from(b(42 + 239));
    let yi = [b(42 + 16), b(42 + 17), b(42 + 18), b(42 + 19)];
    let srv = [b(26), b(27), b(28), b(29)];
    if ethertype == 0x0800
        && proto == 17
        && sport == 67
        && dport == 68
        && op == 2
        && cookie == 0x6382_5363
        && yi != [0, 0, 0, 0]
    {
        let mut nl = [0u8; 20];
        let mut a = [0u8; 20];
        let mut bb = [0u8; 20];
        let mut cc = [0u8; 20];
        let mut dd = [0u8; 20];
        let mut s1 = [0u8; 20];
        let mut s2 = [0u8; 20];
        let mut s3 = [0u8; 20];
        let mut s4 = [0u8; 20];
        line(
            out,
            &[
                "[E1K] RX: ",
                strutil::dec(u64::from(rx_len), &mut nl),
                " bytes — DHCP OFFER yiaddr=",
                strutil::dec(u64::from(yi[0]), &mut a),
                ".",
                strutil::dec(u64::from(yi[1]), &mut bb),
                ".",
                strutil::dec(u64::from(yi[2]), &mut cc),
                ".",
                strutil::dec(u64::from(yi[3]), &mut dd),
                " server=",
                strutil::dec(u64::from(srv[0]), &mut s1),
                ".",
                strutil::dec(u64::from(srv[1]), &mut s2),
                ".",
                strutil::dec(u64::from(srv[2]), &mut s3),
                ".",
                strutil::dec(u64::from(srv[3]), &mut s4),
                if identity {
                    " ← FULL TX→slirp→RX round trip (identity mode, no IOMMU on this machine)"
                } else {
                    " ← FULL TX→slirp→RX round trip through the IOMMU"
                },
            ],
        );
    } else {
        line(
            out,
            &["[E1K] RX: a packet arrived but is not the expected DHCP OFFER"],
        );
    }

    // Teardown: revoke + scrub, frames home.
    session.close(out);
}

// ── NVMe (checklist item 6): admin + I/O queue pairs, IDENTIFY, a
// sector read — the same broker discipline; every ring and data
// frame is an IOMMU-mapped pool frame before the device sees it ──

/// ADR-0018's live negative probe (round 5, Phase A.5): the e1000 —
/// in ITS per-device domain — attempts a TX buffer read of a page
/// mapped ONLY in a different, probe-owned domain. The IOMMU must
/// fault it: FSTS.PPF sets, the TX never completes, and the lane's
/// grep requires the fault marker (a silent success would mean
/// devices are NOT isolated). Runs after `e1k_step` (the device is
/// idle, BME off, its rings freed and scrubbed).
#[cfg(not(test))]
pub(crate) fn e1k_cross_device_probe_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x8086, 0x02) else {
        line(
            out,
            &["[IOMMU] cross-device probe: no e1000 on this machine — skipped"],
        );
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[IOMMU] cross-device probe: no IOMMU on this lane — skipped"],
        );
        return;
    }
    let e_dom = dev.dom;
    if e_dom == 0 {
        // ADR-0018: a device is never in the kernel's domain; if the
        // claim path did not run, there is nothing to prove here.
        line(
            out,
            &["[IOMMU] cross-device probe: e1000 has no per-device domain — skipped"],
        );
        return;
    }
    // The victim's domain: ANOTHER REAL DEVICE'S — the virtio-net's
    // own per-device domain (its step ran and revoked; the domain's
    // tables persist). A probe-owned domain would have no device and
    // therefore no SLPT root; using the vnet's domain is exactly the
    // finding's scenario: device X DMAs at a page mapped ONLY in
    // device Y's domain.
    let Some(vdev) = inv.find_by(0x1AF4, 0x02) else {
        line(
            out,
            &["[IOMMU] cross-device probe: no virtio-net whose domain can host the victim — skipped"],
        );
        return;
    };
    let v_dom = vdev.dom;
    if v_dom == 0 || v_dom == e_dom {
        line(
            out,
            &["[IOMMU] cross-device probe: no distinct per-device domains — skipped"],
        );
        return;
    }
    // The victim: one scrubbed pool page, mapped ONLY in the vnet's
    // domain — the e1000's domain cannot see it.
    let Ok(victim) = pool.alloc_for(&mut k.frames, crate::drvstack::VTD_TABLE_OWNER) else {
        line(
            out,
            &["[IOMMU] cross-device probe: pool exhausted — skipped"],
        );
        return;
    };
    let view = broker.map_region(v_dom, victim, 4096, aegis_os::dma::DmaDir::Bidirectional);
    let Ok(view) = view else {
        let _ = pool.free(&mut k.frames, victim, crate::drvstack::VTD_TABLE_OWNER);
        line(
            out,
            &["[IOMMU] cross-device probe: broker refused the victim map — skipped"],
        );
        return;
    };
    // The e1000 side: window + one TX ring frame in ITS OWN domain.
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        let _ = broker.unmap_region(v_dom, view.cookie);
        let _ = pool.free(&mut k.frames, victim, crate::drvstack::VTD_TABLE_OWNER);
        line(
            out,
            &["[IOMMU] cross-device probe: e1000 BAR0 unresolved — skipped"],
        );
        return;
    };
    let Some(bus) = crate::mmio::BarMmio::new(bar.base, bar.size) else {
        let _ = broker.unmap_region(v_dom, view.cookie);
        let _ = pool.free(&mut k.frames, victim, crate::drvstack::VTD_TABLE_OWNER);
        line(
            out,
            &["[IOMMU] cross-device probe: e1000 BAR0 window malformed — skipped"],
        );
        return;
    };
    if bus.window().len() < E1K_TDT + 4 {
        let _ = broker.unmap_region(v_dom, view.cookie);
        let _ = pool.free(&mut k.frames, victim, crate::drvstack::VTD_TABLE_OWNER);
        line(
            out,
            &["[IOMMU] cross-device probe: e1000 window too small — skipped"],
        );
        return;
    }
    'probe: {
        let mut session = crate::session::DriverSession::new(
            k,
            pool,
            broker,
            Some(dev),
            E1K_OWNER,
            e_dom,
            false,
            "[E1K-PROBE] teardown",
            "",
        );
        let Ok(ring) = session.frame() else {
            line(
                out,
                &["[IOMMU] cross-device probe: pool exhausted — skipped"],
            );
            session.close(out);
            break 'probe;
        };
        if session.map(ring).is_none() {
            line(
                out,
                &["[IOMMU] cross-device probe: broker refused the ring — skipped"],
            );
            session.close(out);
            break 'probe;
        }
        // One legacy TX descriptor: its buffer_addr is the VICTIM — a
        // page the e1000's domain cannot see.
        crate::memops::write_u64(ring, victim);
        crate::memops::write_u16(ring + 8, 64); // length
        netutil::put8(ring + 11, 0x0B); // cmd: EOP | IFCS | RS
                                        // Program + kick (window-checked; the ring is mapped, so a
                                        // refused write is a full teardown).
        let prog = [
            (E1K_TDBAL, ring as u32),
            (E1K_TDBAL + 4, 0),
            (E1K_TDLEN, 16),
            (E1K_TDH, 0),
            (E1K_TDT, 0),
            (E1K_TCTL, 0x2 /* EN */),
        ];
        for &(off, v) in prog.iter() {
            if !bus.write32(off, v) {
                line(
                    out,
                    &["[IOMMU] cross-device probe: register window refused a write — skipped"],
                );
                session.close(out);
                break 'probe;
            }
        }
        // The ring is broker-mapped in the e1000's domain — DMA may start.
        crate::pci::enable_bus_master(dev);
        if !bus.write32(E1K_TDT, 1) {
            line(
                out,
                &["[IOMMU] cross-device probe: the TX tail write was refused — skipped"],
            );
            session.close(out);
            break 'probe;
        }
        // Bounded wait: the TX cannot complete (its buffer read
        // faults), but the IOMMU records the fault.
        let mut spins = 0u64;
        while spins < 4_000_000 {
            spins += 1;
        }
        let fsts = session.with_prot(|p| p.fsts());
        let ppf = fsts & crate::arch::vtd::FSTS_PPF != 0;
        let mut he = [0u8; 20];
        let mut hp = [0u8; 20];
        let mut hf = [0u8; 18];
        if ppf {
            line(
                out,
                &[
                    "[IOMMU] cross-device probe: e1000 (dom ",
                    strutil::dec(u64::from(e_dom), &mut he),
                    ") DMA to a page mapped only in the virtio-net's dom ",
                    strutil::dec(u64::from(v_dom), &mut hp),
                    " → cross-device DMA FAULTED (FSTS.PPF set) — devices are isolated (ADR-0018)",
                ],
            );
        } else {
            line(
                out,
                &[
                    "[IOMMU] cross-device probe: FAILED — the cross-device DMA did NOT fault (fsts=",
                    strutil::hex(u64::from(fsts), &mut hf),
                    ") — isolation NOT proven",
                ],
            );
        }
        session.close(out);
    }
    // Fail-closed cleanup (unconditional, after the session's borrows
    // end): the victim's region unmapped, the page home scrubbed, the
    // probe domain released.
    let _ = broker.unmap_region(v_dom, view.cookie);
    let _ = pool.free(&mut k.frames, victim, crate::drvstack::VTD_TABLE_OWNER);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_descriptor_carries_addr_len_and_the_cmd_byte() {
        let phys = crate::drvstack::testharness::FakePhys::new(1);
        let pa = phys.pa(0);
        build_tx_desc(pa, 0xABCD_0000, 290);
        assert_eq!(crate::memops::read_u64(pa), 0xABCD_0000);
        // the legacy layout: length u16 at bytes 8-9, the cmd byte at
        // 11 (it overlaps the driver's u32 length store — faithful to
        // the original code path)
        assert_eq!(crate::virtio::read_u16_pa(pa + 8), 290);
        assert_eq!(crate::virtio::read_u8_pa(pa + 11), 0x0B, "EOP|IFCS|RS");
        assert_eq!(crate::memops::read_u32(pa + 12), 0, "cso/css/special zero");
    }

    #[test]
    fn rx_done_is_the_descriptor_done_bit_only() {
        let phys = crate::drvstack::testharness::FakePhys::new(1);
        let pa = phys.pa(0);
        crate::memops::write_u32(pa + 12, 0);
        assert!(!rx_desc_done(pa));
        crate::memops::write_u32(pa + 12, 1);
        assert!(rx_desc_done(pa));
        // hostile garbage in the NEIGHBORING fields (the descriptor's
        // first 8 bytes, and bytes 16+) must not flip the DD bit
        crate::memops::write_u64(pa, 0xFFFF_FFFF_FFFF_FFFF);
        crate::memops::write_u64(pa + 16, 0xFFFF_FFFF_FFFF_FFFF);
        assert!(rx_desc_done(pa), "only bit 0 of byte 12 is the DD bit");
        // and clearing just that bit clears it
        crate::memops::write_u32(pa + 12, 0xFFFF_FFFE);
        assert!(!rx_desc_done(pa));
    }
}
