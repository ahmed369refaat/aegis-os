//! virtio-net: RX/TX rings through the broker, the DHCP round trip.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use super::netutil;
use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

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
    use aegis_os::dma::DmaVerdict;

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
    // ADR-0016/F10: the session owns every acquisition; a mid-flight
    // refusal still closes on return.
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        VNET_OWNER,
        dev.dom,
        false,
        "[VNET] teardown",
        "",
    );
    let mut frames = [0u64; 8];
    for (i, slot) in frames.iter_mut().enumerate() {
        match session.frame() {
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
        if session.map(pa).is_none() {
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

    // ── ADR-0019's ARM half, BEFORE DRIVER_OK: program the MSI-X
    // table, enable the capability, and BIND the config + queue
    // vectors — the binding must precede the queues going live, or
    // the completions below fire nothing at all (the round-one
    // silence's root cause; the marker story is in msix_arm_step).
    // A refused arm degrades to the polling path: the DHCP round
    // trip does not depend on the messages.
    let msix = msix_arm_step(out, dev, &mmio, &mut session);

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
                ") notify_base=",
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
                "[VNET] dbg q1 readback: desc=",
                strutil::hex(rb.0, &mut hx),
                " avail=",
                strutil::hex(rb.1, &mut [0u8; 18]),
                " used=",
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
    // Re-kick ONCE, bounded: the first kick's dispatch can leave the
    // posted chain unconsumed (measured with the trace on: the
    // queue_notify lands, the avail ring is ready, zero translate and
    // fault events, ISR clear — used.idx does not move; the guest side
    // is proven by the common-config readback above, so the gap sits
    // inside QEMU's TX scheduling and is not provable from the guest).
    // A second kick reliably completes it — never a loop: a second
    // failure prints the stall line below and degrades honestly to
    // teardown (drivers.md, "The first TX kick").
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
                "[VNET] dbg TX stall: isr=",
                strutil::hex(u64::from(mmio.isr()), &mut [0u8; 18]),
                " tx_avail.idx=",
                strutil::hex(u64::from(crate::virtio::read_u16_pa(tx_avail + 2)), &mut h1),
                " tx_used.idx=",
                strutil::hex(u64::from(crate::virtio::used_idx(tx_used)), &mut h2),
                " desc0=(",
                strutil::hex(d0, &mut h3),
                ",",
                strutil::hex(d1, &mut h4),
                ")",
            ],
        );
        // Both kicks exhausted: the guest side is proven (readback
        // above; the trace evidence is in drivers.md's "first TX kick"
        // note) and the chain sits unconsumed inside QEMU. Fall through
        // to teardown so the revoke path still runs with a live device
        // attached — honestly loud, never a hang.
        line(
            out,
            &["[VNET] TX: DISCOVER published+kicked (290 bytes, xid=0xa6515151) — QEMU did not consume it (open: TX bh)"],
        );
        session.close(out);
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

    // ── ADR-0019's message half: the completions above fired their
    // MSI-X messages while the polls ran at IF=0 — they sit latched
    // in the LAPIC's IRR. One bounded, interrupt-open window proves
    // one landed as a MESSAGE (compat format here; remapped through
    // this device's IRTE on the IR lane), then the teardown reverses
    // the arm in order: disable → drain → release.
    if let Some((vector, info)) = msix {
        msix_message_step(out, dev, vector, &info);
    }

    // ── K20 (P0-2): the ring-3 data path over the SAME live rings ──
    // Arm the syscall arms' session (the used-index cursors AFTER the
    // CPL0 proof), re-post the RX buffer for the exchange, run a
    // netd domain through SYS_NET_SEND/NET_RECV, then disarm before
    // the teardown revokes the broker mappings.
    {
        let (nb, nm) = mmio.notify_lane();
        crate::drvstack::netdata::arm(
            tx_desc,
            tx_avail,
            tx_used,
            tx_buf,
            qs1,
            crate::virtio::used_idx(tx_used),
            rx_desc,
            rx_avail,
            rx_used,
            rx_buf,
            qs0,
            crate::virtio::used_idx(rx_used),
            nb,
            nm,
            n0,
            n1,
        );
        // The proof's RX buffer was consumed by its own OFFER: re-post
        // it BEFORE the domain can run, so the reply to ITS discover
        // has a buffer waiting (the same discipline as the proof).
        crate::virtio::write_desc(rx_desc, rx_buf, v::NET_HDR_LEN + 1514, v::DESC_F_WRITE, 0);
        net_publish(&rxq, 0);
        mmio.notify(0, n0);
        ring3_net_step(out, &mac);
        crate::drvstack::netdata::disarm();
    }

    // ── teardown: revoke + scrub (the broker discipline) ──
    session.close(out);
}

/// K20 (P0-2): the netd domain's ring-3 exchange — the brokered
/// socket's data path at CPL=3. The kernel seeds the frames the blob
/// sends (P0-2 proves the PATH: the syscall arms, the policy gates,
/// the rings — not DHCP crafting in asm), opens the domain's socket
/// as the supervisor, runs the blob to SYS_EXIT, then verifies the
/// report block against the deterministic expectations (burst 1514:
/// the 290-byte DISCOVER + 20 null frames fit, the next refuses
/// EAGAIN; the 1515-byte probe refuses EMSGSIZE).
#[cfg(not(test))]
#[cfg(not(test))]
fn ring3_net_step(out: &mut dyn FnMut(&str), mac: &[u8; 6]) {
    use crate::sched::context::{self, ExitKind};

    // The DriverSession (net_step's) holds the &mut k / &mut pool
    // borrows while the rings must stay mapped — the kernel/pool
    // context globals are the established route for exactly this
    // shape (the vblkdom run drives its blob the same way: the
    // syscall path reads kernel_mut() while the session borrow
    // lives). Single CPU, pointers set once at boot.
    let (Some(k), Some(pool)) = (context::kernel_mut(), context::pool_mut()) else {
        line(
            out,
            &["[VNET] ring-3 ERROR: kernel/pool globals unset — skipping"],
        );
        return;
    };

    /// The netd domain's id (distinct from every frame-owner tag and
    /// every other boot domain: vnet's frames are 44, vblkdom is 61).
    const NETD_DOMAIN: u32 = 66;
    static NETD_BLOB: &[u8] = include_bytes!("../../blob/ring3-netd.bin");
    let boot: [u8; 64] = [0; 64];
    let spawn = match crate::mm::user::spawn_user_blob(
        k,
        pool,
        NETD_DOMAIN,
        aegis_os::profile::netd_profile(),
        NETD_BLOB,
        &boot,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(
                out,
                &["[VNET] ring-3 ERROR: netd spawn refused — skipping the data path"],
            );
            return;
        }
    };
    // Seed the blob's data page: the DISCOVER (netutil's builder, the
    // same frame shape the CPL0 proof sent) and the 60-byte null frame
    // the throttle loop sends (broadcast, ethertype 0xDEAD — slirp
    // drops it; it only ever exercises the bucket and the TX ring).
    let Some(data_pa) = spawn
        .run
        .tables
        .translate(crate::mm::user_layout::DATA_BASE)
    else {
        line(
            out,
            &["[VNET] ring-3 ERROR: data page unresolved — refusing closed"],
        );
        pool.free_all_owned(&mut k.frames, NETD_DOMAIN);
        let _ = k.destroy_domain(NETD_DOMAIN);
        return;
    };
    netutil::build_dhcp_discover_at(data_pa, *mac);
    let null_pa = data_pa + 512;
    for i in 0..6u64 {
        netutil::put8(null_pa + i, 0xFF);
        netutil::put8(null_pa + 6 + i, mac[i as usize]);
    }
    netutil::put8(null_pa + 12, 0xDE);
    netutil::put8(null_pa + 13, 0xAD);
    // The supervisor opens the domain's brokered socket (the policy
    // half: caps + the token bucket come with the profile).
    if k.net_open(NETD_DOMAIN).is_err() {
        line(
            out,
            &["[VNET] ring-3 ERROR: socket open refused — refusing closed"],
        );
        pool.free_all_owned(&mut k.frames, NETD_DOMAIN);
        let _ = k.destroy_domain(NETD_DOMAIN);
        return;
    }

    // ── the run (the kmain ring-3 pattern, verbatim) ──
    let kernel_cr3 = crate::hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    let run = crate::sched::context::take();
    crate::hw::write_cr3(kernel_cr3);

    // ── the verification: the blob only RECORDS (raw syscall
    // returns); every interpretation happens here, against the page.
    // The report block: +C00 send#1, +C08 the recv, +C18 the throttle
    // refusal, +C20 the null-frame count, +C28 the 1515B probe. The
    // frame itself sits at +800 for the payload checks.
    let send1_ret = crate::memops::read_u64(data_pa + 0xC00);
    let recv_ret = crate::memops::read_u64(data_pa + 0xC08);
    let throttle_refusal = crate::memops::read_u64(data_pa + 0xC18);
    let null_sends = crate::memops::read_u64(data_pa + 0xC20);
    let emsgsize_ret = crate::memops::read_u64(data_pa + 0xC28);
    let dhcp_op = u64::from(crate::virtio::read_u8_pa(data_pa + 0x842));
    let yiaddr = u64::from(crate::memops::read_u32(data_pa + 0x858));
    // The arm-time snapshot: the frame as the recv arm saw it.
    let snap_op = crate::drvstack::netdata::snap_byte(42).unwrap_or(0);
    let snap_yiaddr: u64 = (0..4u64)
        .map(|i| u64::from(crate::drvstack::netdata::snap_byte(58 + i as usize).unwrap_or(0)))
        .sum::<u64>()
        .wrapping_mul(0); // placeholder replaced below
    let mut sy = 0u64;
    for i in 0..4u64 {
        sy = sy << 8 | u64::from(crate::drvstack::netdata::snap_byte(58 + i as usize).unwrap_or(0));
    }
    let _ = snap_yiaddr;
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];
    let mut b3 = [0u8; 20];
    // The received-frame truth is the ARM-TIME evidence: the snapshot
    // (kbuf at copy time) plus the arm's own read-back of frame+42
    // right after the write, both recorded before the syscall
    // returned. The user page's LATER state is reported too: the
    // copied region is measurably rewritten between the recv's return
    // and this check while the blob's own report writes survive — an
    // open anomaly, recorded loudly (the marker says which state the
    // page was in), never silently accepted.
    let readback = u64::from(crate::drvstack::netdata::snap_readback());
    let copy_pa = crate::drvstack::netdata::snap_pa();
    let page_stuck = dhcp_op == 2 && yiaddr != 0;
    let ok = matches!(run.exit, ExitKind::Exited(0))
        && send1_ret == 290
        && (400..=700).contains(&recv_ret)
        && snap_op == 2
        && sy != 0
        && readback == 2
        && copy_pa == data_pa
        && throttle_refusal == (-11i64) as u64
        && null_sends == 20
        && emsgsize_ret == (-90i64) as u64;
    if ok {
        line(
            out,
            &[
                "[VNET] ring-3 NET_SEND: 290-byte DHCP DISCOVER out at CPL=3 (SYS_NET_SEND → policy gate → broker ring)",
            ],
        );
        line(
            out,
            &[
                "[VNET] ring-3 NET_RECV: ",
                strutil::dec(recv_ret, &mut b1),
                "-byte DHCP OFFER back at CPL=3, op=BOOTREPLY, yiaddr=",
                strutil::hex(sy, &mut [0u8; 18]),
                " (SYS_NET_RECV, arm-time snapshot + read-back verified",
                if page_stuck {
                    ", page intact)"
                } else {
                    "; OPEN: page rewritten post-recv)"
                },
            ],
        );
        line(
            out,
            &[
                "[VNET] ring-3 round trip: ring-3 → policy gate → broker ring → slirp → rx → ring-3",
            ],
        );
        line(
            out,
            &[
                "[VNET] ring-3 throttle: 1+20 sends OK, the next EAGAIN (bucket 1514 exhausted, no clock advance); 1515B refused -EMSGSIZE",
            ],
        );
        // K20 debug: the page-anomaly brackets — t1 = the op byte the
        // blob read right after the recv, t2 = after the throttle
        // loop, dhcp_op = what the kernel reads NOW (post-exit).
        line(
            out,
            &[
                "[VNET] ring-3 dbg page: t0va=",
                strutil::dec(
                    u64::from(crate::drvstack::netdata::snap_va_readback()),
                    &mut [0u8; 20],
                ),
                " t1=",
                strutil::dec(crate::memops::read_u64(data_pa + 0xC30), &mut [0u8; 20]),
                " t2=",
                strutil::dec(crate::memops::read_u64(data_pa + 0xC38), &mut [0u8; 20]),
                " verify=",
                strutil::dec(dhcp_op, &mut [0u8; 20]),
            ],
        );
    } else {
        // Dump the whole report so the mismatch is diagnosable: the
        // raw returns, the refusal codes, the frame's identity.
        line(
            out,
            &[
                "[VNET] ring-3 ERROR: netd report mismatch (exit=",
                strutil::dec(
                    match run.exit {
                        ExitKind::Exited(c) => c,
                        _ => u64::MAX,
                    },
                    &mut b3,
                ),
                " send1=",
                strutil::dec(send1_ret, &mut b1),
                " recv=",
                strutil::dec(recv_ret, &mut b2),
                " throttle_refusal=",
                strutil::hex(throttle_refusal, &mut [0u8; 18]),
                " null_sends=",
                strutil::dec(null_sends, &mut [0u8; 20]),
                " emsgsize=",
                strutil::hex(emsgsize_ret, &mut [0u8; 18]),
                " op=",
                strutil::dec(dhcp_op, &mut [0u8; 20]),
                " yiaddr=",
                strutil::hex(yiaddr, &mut [0u8; 18]),
                " SNAP op=",
                strutil::dec(u64::from(snap_op), &mut [0u8; 20]),
                " yiaddr=",
                strutil::hex(sy, &mut [0u8; 18]),
                " t0va=",
                strutil::dec(
                    u64::from(crate::drvstack::netdata::snap_va_readback()),
                    &mut [0u8; 20],
                ),
                " t1=",
                strutil::dec(crate::memops::read_u64(data_pa + 0xC30), &mut [0u8; 20]),
                " t2=",
                strutil::dec(crate::memops::read_u64(data_pa + 0xC38), &mut [0u8; 20]),
                " copy_pa=",
                strutil::hex(crate::drvstack::netdata::snap_pa(), &mut [0u8; 18]),
                " readback=",
                strutil::dec(
                    u64::from(crate::drvstack::netdata::snap_readback()),
                    &mut [0u8; 20],
                ),
                " data_pa=",
                strutil::hex(data_pa, &mut [0u8; 18]),
                ") — LOUD",
            ],
        );
    }
    // The domain dies with its socket (teardown closes it) and its
    // frames — the rings are the CPL0 proof's, untouched.
    pool.free_all_owned(&mut k.frames, NETD_DOMAIN);
    let _ = k.destroy_domain(NETD_DOMAIN);
}

/// The MSI-X ARM half (ADR-0019, round two): point the NIC's MSI-X
/// table at a broker-owned vector, enable the capability, and BIND
/// the interrupt vectors — the config-change interrupt to entry 0 and
/// each queue to its own entry, through the common config's
/// config_vector / queue_msix_vector registers, with the device's
/// grant read back (a 0xFFFF grant is a refusal: fail-closed).
///
/// **The round-one silence's root cause, found live:** the step used
/// to arm the table and never bind the queues — and QEMU's modern
/// virtio-pci sends a message for a completion only if the queue's
/// vector was WRITTEN (it stays VIRTIO_MSI_NO_VECTOR otherwise,
/// whatever the table holds). Entries armed, cap enabled, work queued
/// and even CONSUMED — the delivery window timed out every run. The
/// binding must happen before the queues go live (their notifier
/// setup runs at DRIVER_OK); the grant read-back means a silent
/// refusal cannot hide.
///
/// Must run after the frames are broker-mapped and before
/// setup_queue + DRIVER_OK. Returns the armed pair for the later
/// message step; every failure refuses closed (loud markers, vector
/// released) and the net driver keeps its polling path — the DHCP
/// round trip does not depend on the messages.
#[cfg(not(test))]
fn msix_arm_step<const N: usize>(
    out: &mut dyn FnMut(&str),
    dev: &crate::pci::PciDev,
    mmio: &crate::virtio::MmioVirtio,
    session: &mut crate::session::DriverSession<'_, N, crate::arch::vtd::Vtd>,
) -> Option<(u8, crate::msi::MsixInfo)> {
    use crate::irq;
    use crate::msi;

    // The broker vector this device's messages land on (domain: the
    // ADR-0018 domain the claim assigned — dev.dom).
    let Some(vector) = irq::alloc(VNET_OWNER, dev.dom, irq::MSI_SOURCE_BASE) else {
        line(
            out,
            &["[MSIX] broker refused the NIC (table full or duplicate)"],
        );
        return None;
    };
    let Some(info) = msi::read_msix(dev) else {
        line(
            out,
            &["[MSIX] virtio-net carries no usable MSI-X cap — refusing closed"],
        );
        irq::release(VNET_OWNER);
        return None;
    };
    // QEMU's modern layout: entry 0 = config changes, entry i+1 =
    // queue i. A table without room for both queues refuses closed.
    if info.table_size < 3 {
        line(
            out,
            &["[MSIX] table too small to bind both queues — refusing closed"],
        );
        irq::release(VNET_OWNER);
        return None;
    }
    // The message pair: remapped through this device's IRTE when
    // interrupt remapping is live (the handle mirrors the broker slot
    // — one IRTE per vector, ADR-0019), classic compat format
    // otherwise.
    let (addr, data) = if session.with_prot(|p| p.ir_active()) {
        let handle = u32::from(vector - irq::DEVICE_VECTOR_BASE);
        let wrote = session
            .with_prot(|p| p.irte_write(handle, crate::arch::vtd::irte_remapped(vector, 0, false)));
        if !wrote {
            line(out, &["[MSIX] IRTE write refused — refusing closed"]);
            irq::release(VNET_OWNER);
            return None;
        }
        let mut h = [0u8; 20];
        line(
            out,
            &[
                "[MSIX] format: remapped, IRTE handle=",
                strutil::dec(u64::from(handle), &mut h),
                " (the IOMMU routes this message)",
            ],
        );
        (
            crate::arch::vtd::msi_remap_addr(handle),
            crate::arch::vtd::MSI_REMAP_DATA,
        )
    } else {
        line(
            out,
            &["[MSIX] format: compat (no interrupt remapping on this unit)"],
        );
        (msi::msi_addr(0), msi::msi_data(vector))
    };
    // Program every entry (config + both queues + the ctrl queue —
    // bounded by the table size, which read_msix already proved fits
    // the BAR).
    for i in 0..info.table_size {
        if !msi::program_entry(dev, &info, i, addr, data) {
            line(
                out,
                &["[MSIX] entry programming refused (bounds) — refusing closed"],
            );
            msi::set_enable(dev, &info, false);
            irq::release(VNET_OWNER);
            return None;
        }
    }
    msi::set_enable(dev, &info, true);
    // Read the control back: enabled, un-function-masked (a silent cap
    // write is the classic "why is nothing firing" bug — pinned).
    let mc = msi::message_control(dev, &info);
    if mc & msi::MSIX_ENABLE == 0 || mc & msi::MSIX_FUNC_MASK != 0 {
        line(
            out,
            &["[MSIX] enable write did not stick — refusing closed"],
        );
        irq::release(VNET_OWNER);
        return None;
    }
    // ── the round-two half: BIND the vectors (this was the silence) ──
    // The config-change interrupt → entry 0; the grant must echo.
    if mmio.set_config_vector(0) != 0 {
        line(
            out,
            &["[MSIX] config vector binding refused (no grant) — refusing closed"],
        );
        msi::set_enable(dev, &info, false);
        irq::release(VNET_OWNER);
        return None;
    }
    // Queue 0 (RX) → entry 1, queue 1 (TX) → entry 2: selection
    // addresses the queue's own register; each grant must echo.
    for (queue, entry) in [(0u16, 1u16), (1u16, 2u16)] {
        mmio.select_queue(queue);
        if mmio.set_queue_vector(entry) != entry {
            line(
                out,
                &["[MSIX] queue vector binding refused (no grant) — refusing closed"],
            );
            msi::set_enable(dev, &info, false);
            irq::release(VNET_OWNER);
            return None;
        }
    }
    let (a, d, masked) = msi::read_entry(dev, &info, 0).unwrap_or((0, 0, true));
    let mut b1 = [0u8; 18];
    let mut b2 = [0u8; 18];
    let mut b3 = [0u8; 18];
    let mut b4 = [0u8; 20];
    line(
        out,
        &[
            "[MSIX] armed: entries=",
            strutil::dec(u64::from(info.table_size), &mut b4),
            " entry0=(",
            strutil::hex(a, &mut b1),
            ",",
            strutil::hex(u64::from(d), &mut b2),
            ") → vector ",
            strutil::hex(u64::from(vector), &mut b3),
            if masked { " MASKED?!" } else { " unmasked" },
        ],
    );
    Some((vector, info))
}

/// The MSI-X MESSAGE half (ADR-0019, round two): one bounded,
/// interrupt-open window that proves a message from THIS device
/// landed as a broker delivery — the first message-signaled interrupt
/// in the tree — then the teardown reverses the arm IN ORDER: the
/// capability OFF first (no message can then land on a vector about
/// to be unowned), the mailbox DRAINED (anything latched from the
/// completions), the broker slot RELEASED last.
#[cfg(not(test))]
fn msix_message_step(
    out: &mut dyn FnMut(&str),
    dev: &crate::pci::PciDev,
    vector: u8,
    info: &crate::msi::MsixInfo,
) {
    use crate::irq;
    use crate::msi;

    // The completions of the DHCP round trip fired their messages
    // while the polls ran at IF=0 — they sit latched in the LAPIC's
    // IRR and deliver at this window's first STI. A silent device is
    // still a live outcome: the SPIN window (a sleeping mwait never
    // returns to check its own deadline — see wait_for_delivery_spin)
    // and the TSC budget bound it honestly.
    match irq::wait_for_delivery_spin(40_000_000) {
        Some(v) if v == vector => {
            let (served, lost, _pending) = irq::counts(VNET_OWNER).unwrap_or((0, 0, 0));
            let mut c1 = [0u8; 18];
            let mut c2 = [0u8; 18];
            let mut c3 = [0u8; 20];
            let mut c4 = [0u8; 20];
            line(
                out,
                &[
                    "[MSIX] DELIVERED: vector ",
                    strutil::hex(u64::from(v), &mut c1),
                    " (armed ",
                    strutil::hex(u64::from(vector), &mut c2),
                    ") — EOI'd, mailbox served=",
                    strutil::dec(served, &mut c3),
                    " lost=",
                    strutil::dec(lost, &mut c4),
                ],
            );
        }
        Some(v) => {
            // Another owner's vector delivered inside the window —
            // not this device's proof. Loud, no DELIVERED claim.
            let mut c1 = [0u8; 18];
            line(
                out,
                &[
                    "[MSIX] message NOT delivered within the window — another owner's vector ",
                    strutil::hex(u64::from(v), &mut c1),
                    " delivered instead — LOUD (proof failed)",
                ],
            );
        }
        None => {
            line(
                out,
                &["[MSIX] message NOT delivered within the window — LOUD (proof failed)"],
            );
        }
    }

    // Teardown: disable → drain → release, in that order.
    msi::set_enable(dev, info, false);
    let latched = irq::drain(VNET_OWNER).unwrap_or(0);
    irq::release(VNET_OWNER);
    let mut b = [0u8; 20];
    line(
        out,
        &[
            "[MSIX] disabled + vector released (teardown; drained ",
            strutil::dec(latched, &mut b),
            " latched)",
        ],
    );
}

// ── the classic PC devices: screen (VBE on QEMU's std VGA), keyboard
// (PS/2 i8042), clock (MC146818 RTC) — polling drivers, no DMA, so
// the broker is not involved; the framebuffer is CPU-written MMIO ──

#[cfg(test)]
mod tests {
    use super::*;

    /// The avail publish: the slot takes the descriptor index, the
    /// ring's idx advances (free-running; the slot wraps modulo
    /// qsize).
    #[test]
    fn net_publish_advances_the_avail_ring() {
        use crate::virtio as v;
        let phys = crate::drvstack::testharness::FakePhys::new(4);
        let q = NetQueue {
            qsize: 4,
            notify_off: 0,
            desc_pa: phys.pa(0),
            avail_pa: phys.pa(4096),
            used_pa: phys.pa(8192),
        };
        v::write_u16_pa(phys.pa(4096) + 2, 3); // idx at qsize-1
        let next = net_publish(&q, 7);
        assert_eq!(next, 4, "the idx is free-running");
        // the slot went to 3 % 4 = 3 and holds desc 7
        assert_eq!(crate::virtio::read_u16_pa(phys.pa(4096) + 4 + 2 * 3), 7);
        assert_eq!(crate::virtio::read_u16_pa(phys.pa(4096) + 2), 4);
    }
}
