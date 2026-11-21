//! virtio-net: RX/TX rings through the broker, the DHCP round trip.

use super::netutil;
use super::{line, revoke_or_quarantine};
use crate::frames::FramePool;
use crate::strutil;

/// The pool owner tag for virtio-net frames (rings ×2, RX/TX buffer
/// pages) — distinct from every other holder in the M1 accounting.
pub const VNET_OWNER: u32 = 44;

/// One queue's ring set, broker-mapped before the device ever sees
/// an address (the same discipline as virtio-blk).
///
/// `notify_off` and `desc_pa` are the per-queue bookkeeping the
/// per-region teardown rework (driver-stack phases 3/4) consumes;
/// today's teardown goes through revoke_all, which does not read them.
#[allow(dead_code)]
struct NetQueue {
    qsize: u16,
    notify_off: u16,
    desc_pa: u64,
    avail_pa: u64,
    used_pa: u64,
}

/// Publish head descriptor `desc_idx` on the queue's avail ring.
#[cfg(not(test))]
fn net_publish(q: &NetQueue, desc_idx: u16) -> u16 {
    use crate::virtio as v;
    let idx = v::read_u16_pa(q.avail_pa + 2);
    v::write_u16_pa(v::avail_slot_addr(q.avail_pa, idx % q.qsize), desc_idx);
    v::write_u16_pa(q.avail_pa + 2, idx.wrapping_add(1));
    idx.wrapping_add(1)
}

/// Bounded used-ring poll; returns the completed transfer length.
#[cfg(not(test))]
fn net_poll(q: &NetQueue, want: u16, budget: u64) -> Option<u32> {
    use crate::virtio as v;
    let mut spins = 0u64;
    loop {
        if v::used_idx(q.used_pa) == want {
            return Some(v::used_entry_len(q.used_pa, want.wrapping_sub(1) % q.qsize));
        }
        if spins >= budget {
            return None;
        }
        spins += 1;
    }
}

/// Phase 2: drive the claimed virtio-net. Handshake on the same
/// modern transport, read the MAC/link from device config, post an
/// RX buffer, then hand-craft a DHCP DISCOVER (Ethernet + IPv4 with
/// an in-kernel header checksum + UDP + DHCP) and TX it. QEMU's
/// user-mode network stack (slirp) answers with a DHCP OFFER —
/// catching it on the RX queue is a full TX→slirp→RX round trip
/// through the broker's IOMMU mappings. Teardown proves the revoke
/// path again with a live device attached.
#[cfg(not(test))]
pub(crate) fn net_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::virtio as v;
    use aegis_os::dma::{DmaDir, DmaVerdict};

    let Some(dev) = inv
        .find_by(0x1AF4, 0x02)
        .filter(|d| crate::pci::has_virtio_cap(d))
    else {
        line(out, &["[VNET] no virtio-net to drive on this machine"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[VNET] broker verdict absent — refusing to drive"]);
        return;
    }
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(dev, off)) else {
        line(out, &["[VNET] vendor caps incomplete — refusing"]);
        return;
    };
    // F9e: MEM now, BME only after the rings are broker-mapped.
    crate::pci::enable_mem(dev);
    let resolved = match caps.resolve(dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[VNET] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);

    // ── the modern handshake (identical discipline to virtio-blk) ──
    mmio.set_status(0);
    let feat_low = mmio.device_features(0);
    let feat_high = mmio.device_features(1);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
    let negotiated = match v::negotiate_features(feat_low, feat_high) {
        Ok(n) => n,
        Err(why) => {
            line(
                out,
                &["[VNET] feature negotiation refused: ", why, " — refusing"],
            );
            return;
        }
    };
    mmio.set_driver_features(0, negotiated.low);
    mmio.set_driver_features(1, negotiated.high);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
    if mmio.status() & v::STATUS_FEATURES_OK == 0 {
        line(out, &["[VNET] FEATURES_OK not accepted — refusing"]);
        return;
    }

    // ── device config: MAC (offset 0, 6 bytes) and status (+6) ──
    let cfg = mmio.device_cfg_pa();
    // F5: byte reads — the device-cfg offset is 4-aligned, a u64
    // read there could be 4-but-not-8 aligned and fault.
    let mac = [
        v::read_u8_pa(cfg),
        v::read_u8_pa(cfg + 1),
        v::read_u8_pa(cfg + 2),
        v::read_u8_pa(cfg + 3),
        v::read_u8_pa(cfg + 4),
        v::read_u8_pa(cfg + 5),
    ];
    let nstatus = v::read_u16_pa(cfg + 6);
    let link_up = nstatus & 1 != 0;
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
            "[VNET] alive: MAC=",
            mac_str,
            " link=",
            if link_up { "UP" } else { "DOWN" },
        ],
    );

    // ── queues: 0 = RX, 1 = TX (the virtio-net layout) ──
    let (qs0_raw, n0) = mmio.select_queue(0);
    let qs0 = if qs0_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qs0_raw
    };
    let (qs1_raw, n1) = mmio.select_queue(1);
    let qs1 = if qs1_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qs1_raw
    };
    if qs0 == 0 || qs1 == 0 || qs0 > 2048 || qs1 > 2048 {
        line(
            out,
            &["[VNET] queue size out of the supported band — refusing"],
        );
        return;
    }

    // ── frames: two ring sets + one buffer page each ──
    let mut frames = [0u64; 8];
    for (i, slot) in frames.iter_mut().enumerate() {
        match pool.alloc_for(&mut k.frames, VNET_OWNER) {
            Ok(pa) => *slot = pa,
            Err(_) => {
                let mut b = [0u8; 20];
                line(
                    out,
                    &[
                        "[VNET] pool exhausted at frame ",
                        strutil::dec(i as u64, &mut b),
                        " — refusing",
                    ],
                );
                return;
            }
        }
    }
    let [rx_desc, rx_avail, rx_used, tx_desc, tx_avail, tx_used, rx_buf, tx_buf] = frames;
    for &pa in frames.iter() {
        if broker
            .map_region(0, pa, 4096, DmaDir::Bidirectional)
            .is_err()
        {
            line(
                out,
                &["[VNET] broker refused a frame — refusing (the device gets no addresses)"],
            );
            return;
        }
    }
    line(
        out,
        &["[VNET] rings + buffers mapped via broker (8 regions, IOMMU-enforced)"],
    );
    // F9e: rings mapped — now the device may DMA.
    crate::pci::enable_bus_master(dev);

    // ── queue setup (selection precedes each setup — common-config
    // registers address the SELECTED queue) ──
    mmio.select_queue(0);
    mmio.setup_queue(rx_desc, rx_avail, rx_used);
    mmio.select_queue(1);
    mmio.setup_queue(tx_desc, tx_avail, tx_used);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK | v::STATUS_DRIVER_OK);
    if mmio.status() & v::STATUS_DRIVER_OK == 0 {
        line(out, &["[VNET] DRIVER_OK not accepted — refusing"]);
        return;
    }
    let rxq = NetQueue {
        qsize: qs0,
        notify_off: n0,
        desc_pa: rx_desc,
        avail_pa: rx_avail,
        used_pa: rx_used,
    };
    let txq = NetQueue {
        qsize: qs1,
        notify_off: n1,
        desc_pa: tx_desc,
        avail_pa: tx_avail,
        used_pa: tx_used,
    };

    // DIAGNOSTIC (bring-up): the queue geometry + notify lane.
    {
        let (qs0d, n0d) = mmio.select_queue(0);
        let (qs1d, n1d) = mmio.select_queue(1);
        let mut h1 = [0u8; 20];
        let mut h2 = [0u8; 20];
        let mut h3 = [0u8; 20];
        let mut h4 = [0u8; 20];
        let (nb, nm) = mmio.notify_lane();
        let mut hx = [0u8; 18];
        let mut h5 = [0u8; 20];
        line(
            out,
            &[
                "[VNET] dbg q0=(size=",
                strutil::dec(u64::from(qs0d), &mut h1),
                ",off=",
                strutil::dec(u64::from(n0d), &mut h2),
                ") q1=(size=",
                strutil::dec(u64::from(qs1d), &mut h3),
                ",off=",
                strutil::dec(u64::from(n1d), &mut h4),
                ") notify_base=0x",
                strutil::hex(nb, &mut hx),
                " mult=",
                strutil::dec(u64::from(nm), &mut h5),
            ],
        );
        // What the DEVICE holds for queue 1 (queue-1-selected reads
        // from common cfg) — must match the frames we mapped.
        let rb = mmio.queue_addresses();
        line(
            out,
            &[
                "[VNET] dbg q1 readback: desc=0x",
                strutil::hex(rb.0, &mut hx),
                " avail=0x",
                strutil::hex(rb.1, &mut [0u8; 18]),
                " used=0x",
                strutil::hex(rb.2, &mut [0u8; 18]),
                " enable=",
                strutil::dec(u64::from(rb.3), &mut h5),
            ],
        );
    }

    // ── arm RX: one buffer = 10-byte header + one Ethernet frame ──
    v::write_net_header(rx_buf);
    v::write_desc(rx_desc, rx_buf, v::NET_HDR_LEN + 1514, v::DESC_F_WRITE, 0);
    net_publish(&rxq, 0);
    if !mmio.notify(0, n0) {
        line(
            out,
            &["[VNET] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }

    // ── build the DHCP DISCOVER at tx_buf + NET_HDR_LEN ──
    let p = tx_buf + u64::from(v::NET_HDR_LEN);
    for i in 0..320u64 {
        netutil::put8(p + i, 0);
    }
    // Ethernet: broadcast, our MAC, ethertype 0x0800.
    for i in 0..6u64 {
        netutil::put8(p + i, 0xFF);
        netutil::put8(p + 6 + i, mac[i as usize]);
    }
    netutil::put8(p + 12, 0x08);
    netutil::put8(p + 13, 0x00);
    // IPv4 (20 bytes): total 276, TTL 64, proto 17 (UDP),
    // 0.0.0.0 → 255.255.255.255, checksum filled after the sum.
    let ip = p + 14;
    netutil::put8(ip, 0x45);
    netutil::put8(ip + 1, 0x00);
    netutil::put16be(ip + 2, 276);
    netutil::put16be(ip + 4, 0x0001);
    netutil::put16be(ip + 6, 0x0000);
    netutil::put8(ip + 8, 64);
    netutil::put8(ip + 9, 17);
    netutil::put16be(ip + 10, 0);
    for i in 0..4u64 {
        netutil::put8(ip + 12 + i, 0);
        netutil::put8(ip + 16 + i, 0xFF);
    }
    netutil::put16be(ip + 10, v::ip_checksum(ip, 20));
    // UDP: 68 → 67, length 256, checksum 0 (legal on IPv4).
    let udp = p + 34;
    netutil::put16be(udp, 68);
    netutil::put16be(udp + 2, 67);
    netutil::put16be(udp + 4, 256);
    netutil::put16be(udp + 6, 0);
    // DHCP: BOOTREQUEST, xid 0xa6515151, broadcast flag, chaddr=MAC.
    let d = p + 42;
    netutil::put8(d, 1);
    netutil::put8(d + 1, 1);
    netutil::put8(d + 2, 6);
    netutil::put8(d + 3, 0);
    netutil::put32be(d + 4, 0xA651_5151);
    netutil::put16be(d + 8, 0);
    netutil::put16be(d + 10, 0x8000);
    for i in 0..6u64 {
        netutil::put8(d + 28 + i, mac[i as usize]);
    }
    // Magic cookie (0x63825363) then options: 53=DISCOVER,
    // 61=client-id, 255=end.
    let c = d + 236;
    netutil::put8(c, 63);
    netutil::put8(c + 1, 82);
    netutil::put8(c + 2, 83);
    netutil::put8(c + 3, 63);
    netutil::put8(c + 4, 53);
    netutil::put8(c + 5, 1);
    netutil::put8(c + 6, 1);
    netutil::put8(c + 7, 61);
    netutil::put8(c + 8, 7);
    netutil::put8(c + 9, 1);
    for i in 0..6u64 {
        netutil::put8(c + 10 + i, mac[i as usize]);
    }
    netutil::put8(c + 16, 255);

    // ── TX the DISCOVER ──
    v::write_net_header(tx_buf);
    v::write_desc(tx_desc, tx_buf, v::NET_HDR_LEN + 290, 0, 0);
    let want_tx = net_publish(&txq, 0);
    if !mmio.notify(1, n1) {
        line(
            out,
            &["[VNET] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    let mut spins = 0u64;
    while crate::virtio::used_idx(tx_used) != want_tx && spins < 20_000_000 {
        // F7: the device may not run the used index past the one
        // request we submitted.
        if crate::virtio::used_idx(tx_used) > want_tx {
            line(
                out,
                &["[VNET] used-ring POISON: used.idx ran past the submission"],
            );
            return;
        }
        spins += 1;
    }
    // Re-kick once (QEMU's TX bottom-half re-enables notifications
    // when it finds the queue; a second kick re-triggers it).
    if crate::virtio::used_idx(tx_used) != want_tx {
        if !mmio.notify(1, n1) {
            line(
                out,
                &["[VNET] notify slot outside the notify region — refusing (F5)"],
            );
            return;
        }
        while crate::virtio::used_idx(tx_used) != want_tx && spins < 50_000_000 {
            if crate::virtio::used_idx(tx_used) > want_tx {
                line(
                    out,
                    &["[VNET] used-ring POISON: used.idx ran past the submission"],
                );
                return;
            }
            spins += 1;
        }
    }
    if crate::virtio::used_idx(tx_used) != want_tx {
        let mut h1 = [0u8; 18];
        let mut h2 = [0u8; 18];
        let mut h3 = [0u8; 18];
        let mut h4 = [0u8; 18];
        let d0 = crate::memops::read_u64(tx_desc);
        let d1 = crate::memops::read_u64(tx_desc + 8);
        line(
            out,
            &[
                "[VNET] dbg TX stall: isr=0x",
                strutil::hex(u64::from(mmio.isr()), &mut [0u8; 18]),
                " tx_avail.idx=",
                strutil::hex(u64::from(crate::virtio::read_u16_pa(tx_avail + 2)), &mut h1),
                " tx_used.idx=",
                strutil::hex(u64::from(crate::virtio::used_idx(tx_used)), &mut h2),
                " desc0=(0x",
                strutil::hex(d0, &mut h3),
                ",0x",
                strutil::hex(d1, &mut h4),
                ")",
            ],
        );
        // The guest side is proven (readback above); QEMU's TX
        // bottom-half does not consume the posted chain — open item,
        // evidence in the boot log. Fall through to teardown so the
        // revoke path still runs with a live device attached.
        line(
            out,
            &["[VNET] TX: DISCOVER published+kicked (290 bytes, xid=0xa6515151) — QEMU did not consume it (open: TX bh)"],
        );
        revoke_or_quarantine(
            k,
            pool,
            out,
            broker,
            VNET_OWNER,
            &frames,
            Some(dev),
            "[VNET] teardown: revoke_all(0) → ",
        );
        return;
    }
    line(
        out,
        &["[VNET] TX: DHCP DISCOVER sent (290 bytes, xid=0xa6515151)"],
    );

    // Nudge the RX queue (queued packets drain on notify), then
    // catch the OFFER.
    mmio.notify(0, n0);
    let Some(rx_len) = net_poll(&rxq, 1, 200_000_000) else {
        line(
            out,
            &["[VNET] RX: no DHCP OFFER arrived (poll budget exhausted)"],
        );
        return;
    };
    let r = rx_buf + u64::from(v::NET_HDR_LEN);
    let b = |i: u64| crate::virtio::read_u8_pa(r + i);
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
                "[VNET] RX: ",
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
                " ← full TX→slirp→RX round trip through the IOMMU",
            ],
        );
    } else {
        line(
            out,
            &["[VNET] RX: a packet arrived but is not the expected DHCP OFFER — refusing to claim it"],
        );
    }

    // ── teardown: revoke + scrub (the broker discipline) ──
    revoke_or_quarantine(
        k,
        pool,
        out,
        broker,
        VNET_OWNER,
        &frames,
        Some(dev),
        "[VNET] teardown: revoke_all(0) → ",
    );
}

// ── the classic PC devices: screen (VBE on QEMU's std VGA), keyboard
// (PS/2 i8042), clock (MC146818 RTC) — polling drivers, no DMA, so
// the broker is not involved; the framebuffer is CPU-written MMIO ──
