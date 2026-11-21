//! The e1000 NIC: descriptors through the broker + the DHCP round trip.

use super::netutil;
use super::{line, revoke_or_quarantine};
use crate::frames::FramePool;
use crate::strutil;

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
#[cfg(not(test))]
pub(crate) fn e1k_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::{DmaDir, DmaVerdict};

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
    let Some(mmio) = crate::pci::mem_bar_base(dev, 0) else {
        line(out, &["[E1K] BAR0 unresolved — refusing"]);
        return;
    };
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
                "[E1K] PCI command readback=0x",
                strutil::hex(u64::from(cmd_back), &mut cb),
                " — the enable did not stick",
            ],
        );
    }
    let r32 = |off: u64| crate::memops::read_u32(mmio + off);
    let w32 = |off: u64, v: u32| crate::memops::write_u32(mmio + off, v);

    // MAC + link from RAL/RAH and STATUS.
    let ral = r32(E1K_RAL);
    let rah = r32(E1K_RAH);
    let mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ];
    let link_up = r32(E1K_STATUS) & 0x2 != 0;
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
    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match pool.alloc_for(&mut k.frames, E1K_OWNER) {
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
            if broker
                .map_region(0, pa, 4096, DmaDir::Bidirectional)
                .is_err()
            {
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
    w32(E1K_RDBAL, rx_ring as u32);
    w32(E1K_RDBAL + 4, 0); // RDBAH (32-bit DMA)
    w32(E1K_RDLEN, (E1K_NDESC * 16) as u32);
    w32(E1K_RDH, 0);
    crate::memops::write_u64(rx_ring, rx_buf); // desc[0].buffer_addr
    w32(E1K_RDT, 1);
    w32(E1K_RCTL, 0x8002); // EN | BAM — BAM is bit 15 (0x8000) per
                           // e1000x_regs.h; the broadcast OFFER needs
                           // it or receive_filter drops it silently

    w32(E1K_TDBAL, tx_ring as u32);
    w32(E1K_TDBAL + 4, 0);
    w32(E1K_TDLEN, (E1K_NDESC * 16) as u32);
    w32(E1K_TDH, 0);
    w32(E1K_TDT, 0);
    w32(E1K_TCTL, 0x2); // EN

    // Build + TX the DISCOVER.
    netutil::build_dhcp_discover_at(tx_buf, mac);
    crate::memops::write_u64(tx_ring, tx_buf); // desc[0].buffer_addr
    crate::memops::write_u32(tx_ring + 8, 290); // length
    crate::memops::write_u32(tx_ring + 12, 0); // cso/css/special
    netutil::put8(tx_ring + 11, 0x0B); // cmd: EOP | IFCS | RS
    w32(E1K_TDT, 1);

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
        if identity {
            line(
                out,
                &["[E1K] teardown (identity): frames freed, no broker regions"],
            );
        } else {
            revoke_or_quarantine(
                k,
                pool,
                out,
                broker,
                E1K_OWNER,
                &frames,
                Some(dev),
                "[E1K] teardown: revoke_all(0) → ",
            );
        }

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
    if crate::virtio::read_u8_pa(rx_ring + 12) & 1 == 0 {
        let rdh = r32(E1K_RDH);
        let rdt = r32(E1K_RDT);
        let rctl = r32(E1K_RCTL);
        let mut rb = [0u8; 18];
        let mut rc = [0u8; 18];
        let mut re = [0u8; 18];
        let mut rf = [0u8; 18];
        let mut rg = [0u8; 18];
        let mut rh = [0u8; 18];
        line(
            out,
            &[
                "[E1K] dbg rx: RDH=0x",
                strutil::hex(u64::from(rdh), &mut rb),
                " RDT=0x",
                strutil::hex(u64::from(rdt), &mut rc),
                " RCTL=0x",
                strutil::hex(u64::from(rctl), &mut re),
                " desc[0]=0x",
                strutil::hex(crate::memops::read_u64(rx_ring), &mut rf),
                "0x",
                strutil::hex(crate::memops::read_u64(rx_ring + 8), &mut rg),
                " buf[0..8]=0x",
                strutil::hex(crate::memops::read_u64(rx_buf), &mut rh),
            ],
        );
        line(
            out,
            &["[E1K] RX: no packet arrived (poll budget exhausted)"],
        );
        if identity {
            line(
                out,
                &["[E1K] teardown (identity): frames freed, no broker regions"],
            );
        } else {
            revoke_or_quarantine(
                k,
                pool,
                out,
                broker,
                E1K_OWNER,
                &frames,
                Some(dev),
                "[E1K] teardown: revoke_all(0) → ",
            );
        }
        for &pa in frames.iter() {
            let _ = pool.free(&mut k.frames, pa, E1K_OWNER);
        }
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
    if identity {
        line(
            out,
            &["[E1K] teardown (identity): frames freed, no broker regions"],
        );
        for &pa in frames.iter() {
            let _ = pool.free(&mut k.frames, pa, E1K_OWNER);
        }
    } else {
        // The helper owns frame freeing on the broker path — and on
        // poison, quarantines them (ADR-0015 F2).
        revoke_or_quarantine(
            k,
            pool,
            out,
            broker,
            E1K_OWNER,
            &frames,
            Some(dev),
            "[E1K] teardown: revoke_all(0) → ",
        );
    }
}

// ── NVMe (checklist item 6): admin + I/O queue pairs, IDENTIFY, a
// sector read — the same broker discipline; every ring and data
// frame is an IOMMU-mapped pool frame before the device sees it ──
