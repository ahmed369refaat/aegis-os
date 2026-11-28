//! P1-1: the TCP/IP stack LIVE at ring 3 — `netstack` (the policy
//! core's own, host-tested stack) running as a real CPL=3 ELF service
//! domain, with its clients, over the brokered NIC.
//!
//! The shape (the vnetdom discipline, service edition):
//!
//! 1. **Re-claim the virtio-net** — the ring-0 proof (`net_step`) and
//!    the ring-3 driver domain (`vnetdom_step`) are long done; this
//!    step resets the device and brings it up AGAIN on fresh rings
//!    (reset → negotiate → both queues → DRIVER_OK), every frame
//!    broker-mapped under this step's own IOMMU session.
//! 2. **Arm the syscall session** (`netdata::arm`) so the service's
//!    ONLY egress (`SYS_NET_SEND`) and ONLY ingress (`SYS_NET_RECV`)
//!    ride the kernel's policy gate (Device cap + the token bucket)
//!    and those broker-mapped rings. Nothing in the service touches a
//!    virtio ring, a device register, or a DMA buffer — its profile
//!    answers every other door with -EPERM.
//! 3. **Spawn the service** — a linked no_alloc ELF (`tcpip/`, the
//!    `NETSVC` contract) through `mm::user::spawn_user_elf`: plan →
//!    cage → quota gates, then the exec loader's own table build. The
//!    kernel patches the shared config page (channels, MAC, address,
//!    ports, seed) before the first instruction runs.
//! 4. **Spawn the client** — a gcc freestanding static ELF (the
//!    userland-netcat example) under the CANONICAL contract with the
//!    net-client profile: it has NO network syscall at all and probes
//!    that live (both answer -EPERM, denied by policy) before its
//!    first request.
//! 5. **Wire the two byte channels** through a never-running uid-0
//!    supervisor (the pipe proof's discipline): the service owns the
//!    request pipe, the client owns the reply pipe, each holds WRITE
//!    on the other's — the lockstep marshaller of `aegis_os::netsock`.
//! 6. **Run both domains** (service stashed, client flat-launched),
//!    collect every exit WITHOUT destroying anything (a destroy
//!    scrubs the frames — the reports must be read while the pages
//!    are still live), verify BOTH report blocks through physical
//!    addresses captured before the launch, print the markers, and
//!    tear the whole grant down in order: domains (now), channels,
//!    supervisor, session (the broker revokes the mappings), frames +
//!    identities.
//!
//! The verification is two-sided by construction: the client's report
//! proves the round trip as the PEER saw it (socket → connect → send
//! → the host's echo → recv → close, TCP and UDP), the service's
//! report proves it as the STACK saw it (bytes in both directions,
//! polls, frames, the bucket's EAGAIN and its refill — the kernel
//! clock's stamp working), and the two must agree.

// Host-test builds compile this module without its boot-only step.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;
use crate::virtio as v;

/// The service domain's id (distinct from every frame-owner tag and
/// every ring-3 demo domain: vnetdom 70/71, e1kdom 72/73, netd 66,
/// the kmain lanes 42-44/70-73, tls 77).
pub(crate) const TCPIP_DOMAIN: u32 = 84;
/// The client domain's id.
pub(crate) const NETCAT_DOMAIN: u32 = 85;
/// The never-running uid-0 supervisor that owns the channel grants.
pub(crate) const NET_SUPER_DOMAIN: u32 = 86;

/// The service image, built with the kernel like every ring-3 blob
/// (boot.sh step [0f/4]: cargo → check-tcpip-image.py → strip).
#[cfg(not(test))]
static TCPIP_ELF: &[u8] = include_bytes!("../../blob/tcpipd.bin");
/// The client image (boot.sh step [0g/4]: gcc freestanding, stripped).
#[cfg(not(test))]
static NETCAT_ELF: &[u8] = include_bytes!("../../blob/netcatd.bin");

/// The service's shared config page: the field offsets of
/// `tcpip/src/lib.rs`'s `#[repr(C)] Config` (0x420000, the NETSVC
/// data segment's pinned first page). Both sides pin this order.
///
/// The pinned field offsets — the contract BOTH sides build against
/// (some are read only on the LOUD path; the pin is the point).
#[cfg(not(test))]
#[allow(dead_code)]
mod svc_cfg {
    pub const PAGE: u64 = 0x420_000;
    pub const MAGIC: u64 = 0; // u32 "TCP1"
    pub const CLIENT_COUNT: u64 = 4;
    pub const REQ_CH: u64 = 8; // u64[4]
    pub const REP_CH: u64 = 40; // u64[4]
    pub const MAC: u64 = 72; // u8[6]
    pub const IP: u64 = 80;
    pub const NETMASK: u64 = 84;
    pub const GATEWAY: u64 = 88;
    pub const PEER_IP: u64 = 92;
    pub const TCP_PORT: u64 = 96; // u16
    pub const UDP_PORT: u64 = 98; // u16
    pub const SEED: u64 = 104; // u64
    pub const IDLE_MS: u64 = 112;
    pub const DRAIN_MS: u64 = 120;
    pub const MAGIC_VALUE: u32 = 0x5443_5031;
}

/// The service's report block (0x420400 — the same page's second
/// block; `tcpip/src/lib.rs`'s `#[repr(C)] Report`).
#[cfg(not(test))]
#[allow(dead_code)]
mod svc_rep {
    pub const PAGE: u64 = 0x420_400;
    pub const MAGIC: u64 = 0; // u32 "REP1"
    pub const FLAGS: u64 = 4;
    pub const EXIT: u64 = 8; // i32
    pub const REQUESTS: u64 = 12;
    pub const REPLIES: u64 = 16;
    pub const MALFORMED: u64 = 20;
    pub const TIMEOUTS: u64 = 24;
    pub const CANCELLED: u64 = 28;
    pub const TCP_SENT: u64 = 32;
    pub const TCP_RECVD: u64 = 36;
    pub const UDP_SENT: u64 = 40;
    pub const UDP_RECVD: u64 = 44;
    pub const EMSGSIZE: u64 = 48; // i32 (expect -90)
    pub const THROTTLE_SEEN: u64 = 52;
    pub const REFILL_OK: u64 = 56;
    pub const POLLS: u64 = 60;
    pub const RECVS: u64 = 64;
    pub const FRAMES_IN: u64 = 68;
    pub const FRAMES_OUT: u64 = 72;
    pub const LIVE_SOCKS: u64 = 76;
    pub const MAGIC_VALUE: u32 = 0x5245_5031;
    // The flag bits (Report::F_*).
    pub const F_TCP: u32 = 1;
    pub const F_UDP: u32 = 2;
    pub const F_REFILL: u32 = 4;
    pub const F_EMSGSIZE: u32 = 8;
}

/// The client's config block (0x403800, the CANONICAL data page's
/// pinned block; `examples/userland-netcat/netcat.c`).
#[cfg(not(test))]
#[allow(dead_code)]
mod cli_cfg {
    pub const BASE: u64 = 0x403_800;
    pub const MAGIC: u64 = 0; // u32 "NC01"
    pub const REQ_CH: u64 = 8; // u64
    pub const REP_CH: u64 = 16; // u64
    pub const PEER_IP: u64 = 24; // u8[4]
    pub const TCP_PORT: u64 = 28; // u16
    pub const UDP_PORT: u64 = 30; // u16
    pub const MAGIC_VALUE: u32 = 0x4E43_3031;
}

/// The client's report block (0x403C00).
#[cfg(not(test))]
#[allow(dead_code)]
mod cli_rep {
    pub const BASE: u64 = 0x403_C00;
    pub const MAGIC: u64 = 0; // u32 "NCR1"
    pub const STEP: u64 = 4; // u32 (0 = clean)
    pub const PROBE_SEND: u64 = 8; // i64 (expect -1 EPERM: the mask refuses)
    pub const PROBE_RECV: u64 = 16; // i64 (expect -1 EPERM: the mask refuses)
    pub const OPS: u64 = 24;
    pub const TCP_OK: u64 = 28;
    pub const UDP_OK: u64 = 32;
    pub const BYTES_OUT: u64 = 36;
    pub const BYTES_IN: u64 = 40;
    pub const MAGIC_VALUE: u32 = 0x4E43_5231;
}

/// The queue geometry this step drives (vnet's NetQueue, local: the
/// struct is private to vnet.rs and this step owns its own rings).
#[cfg(not(test))]
struct Queue {
    qsize: u16,
    avail_pa: u64,
}

/// Publish head descriptor 0 on a queue's avail ring (the
/// net_publish shape).
#[cfg(not(test))]
fn publish(q: &Queue) {
    let idx = v::read_u16_pa(q.avail_pa + 2);
    v::write_u16_pa(v::avail_slot_addr(q.avail_pa, idx % q.qsize), 0);
    v::write_u16_pa(q.avail_pa + 2, idx.wrapping_add(1));
}

/// P1-1: run the ring-3 TCP/IP service and its gcc client over the
/// brokered NIC, verify both report blocks, print the live-stack
/// markers, then tear the whole grant down. Refuses closed (loud
/// markers, full cleanup) at every step.
#[cfg(not(test))]
pub(crate) fn tcpip_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::memops;

    // ── the claim (fail-closed: no device or no broker, no step) ──
    let Some(dev) = inv
        .find_by(0x1AF4, 0x02)
        .filter(|d| crate::pci::has_virtio_cap(d))
    else {
        line(
            out,
            &["[NET] no virtio-net on this machine — the tcpip step skips"],
        );
        return;
    };
    if matches!(broker.verdict(), aegis_os::dma::DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[NET] broker verdict absent — refusing to run the service (fail closed)"],
        );
        return;
    }
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(dev, off)) else {
        line(out, &["[NET] vendor caps incomplete — refusing"]);
        return;
    };
    crate::pci::enable_mem(dev);
    let resolved = match caps.resolve(dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[NET] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);

    // ── the spawn half FIRST (the domains exist before the session
    // borrows k/pool; every refusal below cleans only what it made) ──
    let svc = match crate::mm::user::spawn_user_elf(
        k,
        pool,
        TCPIP_DOMAIN,
        aegis_os::profile::tcpip_profile(),
        1084,
        100,
        TCPIP_ELF,
        &crate::mm::user_layout::NETSVC,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[NET] service spawn refused — refusing closed"]);
            return;
        }
    };
    let cli = match crate::mm::user::spawn_user_elf(
        k,
        pool,
        NETCAT_DOMAIN,
        aegis_os::profile::net_client_profile(),
        1085,
        100,
        NETCAT_ELF,
        &crate::mm::user_layout::CANONICAL,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[NET] client spawn refused — refusing closed"]);
            pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
            let _ = k.destroy_domain(TCPIP_DOMAIN);
            return;
        }
    };

    // ── the supervisor + the two byte channels (the pipe proof's
    // discipline: uid 0, never runs, owns every grant) ──
    if k.create_domain_with(
        NET_SUPER_DOMAIN,
        aegis_os::profile::service_profile(),
        0,
        0,
        0,
    )
    .is_err()
    {
        line(out, &["[NET] supervisor spawn refused — refusing closed"]);
        pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
        let _ = k.destroy_domain(TCPIP_DOMAIN);
        pool.free_all_owned(&mut k.frames, NETCAT_DOMAIN);
        let _ = k.destroy_domain(NETCAT_DOMAIN);
        return;
    }
    let chan = k.ipc_channel_create(NET_SUPER_DOMAIN, TCPIP_DOMAIN);
    let rep = k.ipc_channel_create(NET_SUPER_DOMAIN, NETCAT_DOMAIN);
    let (req_id, rep_id) = match (chan, rep) {
        (Ok((r, _)), Ok((p, _))) => (r, p),
        _ => {
            line(out, &["[NET] channel create refused — refusing closed"]);
            let _ = k.destroy_domain(NET_SUPER_DOMAIN);
            pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
            let _ = k.destroy_domain(TCPIP_DOMAIN);
            pool.free_all_owned(&mut k.frames, NETCAT_DOMAIN);
            let _ = k.destroy_domain(NETCAT_DOMAIN);
            return;
        }
    };
    // The client may WRITE requests; the service may WRITE replies.
    if k.ipc_endpoint_grant(
        NET_SUPER_DOMAIN,
        req_id,
        NETCAT_DOMAIN,
        aegis_os::capability::Rights::WRITE,
    )
    .is_err()
        || k.ipc_endpoint_grant(
            NET_SUPER_DOMAIN,
            rep_id,
            TCPIP_DOMAIN,
            aegis_os::capability::Rights::WRITE,
        )
        .is_err()
    {
        line(out, &["[NET] channel grant refused — refusing closed"]);
        let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, req_id);
        let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, rep_id);
        let _ = k.destroy_domain(NET_SUPER_DOMAIN);
        pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
        let _ = k.destroy_domain(TCPIP_DOMAIN);
        pool.free_all_owned(&mut k.frames, NETCAT_DOMAIN);
        let _ = k.destroy_domain(NETCAT_DOMAIN);
        return;
    }
    let _ = k.sched.unregister(NET_SUPER_DOMAIN);
    // The service's brokered socket (the policy half: the Device cap
    // rides the profile's base rights, the token bucket the kernel's).
    if k.net_open(TCPIP_DOMAIN).is_err() {
        line(out, &["[NET] socket open refused — refusing closed"]);
        let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, req_id);
        let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, rep_id);
        let _ = k.destroy_domain(NET_SUPER_DOMAIN);
        pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
        let _ = k.destroy_domain(TCPIP_DOMAIN);
        pool.free_all_owned(&mut k.frames, NETCAT_DOMAIN);
        let _ = k.destroy_domain(NETCAT_DOMAIN);
        return;
    }

    // ── patch the config pages (through the spawn's own tables, via
    // the direct map — before the first instruction of either) ──
    // NOTE: `translate` answers the FRAME of the containing page — a
    // block at a non-page-aligned VA needs its in-page offset added
    // (found live: every read landed one block off, reading the
    // config where the report was meant).
    let cfg_pa = match svc.run.tables.translate(svc_cfg::PAGE) {
        Some(pa) => pa,
        None => {
            line(
                out,
                &["[NET] service config page unresolved — refusing closed"],
            );
            cleanup(k, pool, out, req_id, rep_id);
            return;
        }
    };
    let cli_cfg_pa = match cli.run.tables.translate(cli_cfg::BASE & !0xFFF) {
        Some(pa) => pa + (cli_cfg::BASE & 0xFFF),
        None => {
            line(
                out,
                &["[NET] client config page unresolved — refusing closed"],
            );
            cleanup(k, pool, out, req_id, rep_id);
            return;
        }
    };
    // The device's own MAC (byte reads: the config offset is 4-aligned
    // but not guaranteed 8).
    let cfg = mmio.device_cfg_pa();
    let mac = [
        v::read_u8_pa(cfg),
        v::read_u8_pa(cfg + 1),
        v::read_u8_pa(cfg + 2),
        v::read_u8_pa(cfg + 3),
        v::read_u8_pa(cfg + 4),
        v::read_u8_pa(cfg + 5),
    ];
    const IP: [u8; 4] = [10, 0, 2, 15]; // slirp's guest address
    const NETMASK: [u8; 4] = [255, 255, 255, 0];
    const GATEWAY: [u8; 4] = [10, 0, 2, 2]; // slirp's gateway = the host
    const PEER: [u8; 4] = [10, 0, 2, 2]; // the host's echo servers
    const TCP_PORT: u16 = 18080;
    const UDP_PORT: u16 = 18081;
    const IDLE_MS: u64 = 60_000;
    const DRAIN_MS: u64 = 2_000;
    // The service's config block (the field order is pinned by
    // tcpip/src/lib.rs's Config).
    memops::write_u32(cfg_pa + svc_cfg::MAGIC, svc_cfg::MAGIC_VALUE);
    memops::write_u32(cfg_pa + svc_cfg::CLIENT_COUNT, 1);
    memops::write_u64(cfg_pa + svc_cfg::REQ_CH, u64::from(req_id));
    memops::write_u64(cfg_pa + svc_cfg::REP_CH, u64::from(rep_id));
    for (i, m) in mac.iter().enumerate() {
        v::write_u8_pa(cfg_pa + svc_cfg::MAC + i as u64, *m);
    }
    for (i, (ip_b, (nm_b, (gw_b, peer_b)))) in IP
        .iter()
        .zip(NETMASK.iter().zip(GATEWAY.iter().zip(PEER.iter())))
        .enumerate()
    {
        v::write_u8_pa(cfg_pa + svc_cfg::IP + i as u64, *ip_b);
        v::write_u8_pa(cfg_pa + svc_cfg::NETMASK + i as u64, *nm_b);
        v::write_u8_pa(cfg_pa + svc_cfg::GATEWAY + i as u64, *gw_b);
        v::write_u8_pa(cfg_pa + svc_cfg::PEER_IP + i as u64, *peer_b);
    }
    memops::write_u16(cfg_pa + svc_cfg::TCP_PORT, TCP_PORT);
    memops::write_u16(cfg_pa + svc_cfg::UDP_PORT, UDP_PORT);
    memops::write_u64(
        cfg_pa + svc_cfg::SEED,
        0x5EED_CAFE_00C0_FFEE, // deterministic per boot
    );
    memops::write_u64(cfg_pa + svc_cfg::IDLE_MS, IDLE_MS);
    memops::write_u64(cfg_pa + svc_cfg::DRAIN_MS, DRAIN_MS);
    // The client's config block.
    memops::write_u32(cli_cfg_pa + cli_cfg::MAGIC, cli_cfg::MAGIC_VALUE);
    memops::write_u64(cli_cfg_pa + cli_cfg::REQ_CH, u64::from(req_id));
    memops::write_u64(cli_cfg_pa + cli_cfg::REP_CH, u64::from(rep_id));
    for (i, peer_b) in PEER.iter().enumerate() {
        v::write_u8_pa(cli_cfg_pa + cli_cfg::PEER_IP + i as u64, *peer_b);
    }
    memops::write_u16(cli_cfg_pa + cli_cfg::TCP_PORT, TCP_PORT);
    memops::write_u16(cli_cfg_pa + cli_cfg::UDP_PORT, UDP_PORT);

    // The report blocks' physical addresses (captured now; the reads
    // happen while the frames are still owned — the destroys come
    // after, scrubbing as they go).
    let svc_rep_pa = svc
        .run
        .tables
        .translate(svc_rep::PAGE & !0xFFF)
        .map(|pa| pa + 0x400);
    let cli_rep_pa = cli
        .run
        .tables
        .translate(cli_rep::BASE & !0xFFF)
        .map(|pa| pa + (cli_rep::BASE & 0xFFF));

    // ── the session scope: rings up, the session armed, both domains
    // run, reports verified — the session's borrows end before the
    // domains' frames + identities are reclaimed ──
    let mut proved = false;
    'scope: {
        // The modern handshake (identical discipline to net_step).
        mmio.set_status(0);
        let feat_low = mmio.device_features(0);
        let feat_high = mmio.device_features(1);
        mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
        let negotiated = match v::negotiate_features(feat_low, feat_high) {
            Ok(n) => n,
            Err(why) => {
                line(
                    out,
                    &["[NET] feature negotiation refused: ", why, " — refusing"],
                );
                break 'scope;
            }
        };
        mmio.set_driver_features(0, negotiated.low);
        mmio.set_driver_features(1, negotiated.high);
        mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
        if mmio.status() & v::STATUS_FEATURES_OK == 0 {
            line(out, &["[NET] FEATURES_OK not accepted — refusing"]);
            break 'scope;
        }
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
                &["[NET] queue size out of the supported band — refusing"],
            );
            break 'scope;
        }

        let mut session = crate::session::DriverSession::new(
            k,
            pool,
            broker,
            Some(dev),
            TCPIP_DOMAIN,
            dev.dom,
            false,
            "[NET] teardown",
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
                            "[NET] pool exhausted at frame ",
                            strutil::dec(i as u64, &mut b),
                            " — refusing",
                        ],
                    );
                    session.close(out);
                    break 'scope;
                }
            }
        }
        let [rx_desc, rx_avail, rx_used, tx_desc, tx_avail, tx_used, rx_buf, tx_buf] = frames;
        for &pa in frames.iter() {
            if session.map(pa).is_none() {
                line(
                    out,
                    &["[NET] broker refused a frame — refusing (the device gets no addresses)"],
                );
                session.close(out);
                break 'scope;
            }
        }
        crate::pci::enable_bus_master(dev);

        mmio.select_queue(0);
        mmio.setup_queue(rx_desc, rx_avail, rx_used);
        mmio.select_queue(1);
        mmio.setup_queue(tx_desc, tx_avail, tx_used);
        mmio.set_status(
            v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK | v::STATUS_DRIVER_OK,
        );
        if mmio.status() & v::STATUS_DRIVER_OK == 0 {
            line(out, &["[NET] DRIVER_OK not accepted — refusing"]);
            session.close(out);
            break 'scope;
        }

        // Arm RX: one max-size writable buffer behind the header.
        v::write_net_header(rx_buf);
        v::write_desc(rx_desc, rx_buf, v::NET_HDR_LEN + 1514, v::DESC_F_WRITE, 0);
        let rxq = Queue {
            qsize: qs0,
            avail_pa: rx_avail,
        };
        publish(&rxq);
        if !mmio.notify(0, n0) {
            line(
                out,
                &["[NET] notify slot outside the notify region — refusing (F5)"],
            );
            session.close(out);
            break 'scope;
        }

        // Arm the syscall session: the service's only wire.
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

        // ── the run (the kmain two-domain pattern): the service
        // stashed (it answers; the client's first request wakes it),
        // the client flat-launched; `launch` returns when nothing is
        // runnable, the exits drain from the completed mailbox. ──
        //
        // P1-1: PAUSE THE PREEMPT TICK around the run — the
        // ADR-0019 delivery-window discipline, scaled to this step's
        // window. The preemption demo (kmain section 12) arms the
        // timer BEFORE the driver stack, and SYSCALL enters CPL0 with
        // IF=1 (this QEMU does not apply FMASK.IF — the entry's own
        // documented cli-after-swapgs leaves a 2-instruction seam):
        // a tick through that seam is a CPL0 timer frame, the guard's
        // loud halt. This step is the first SYSCALL-HEAVY long run
        // under the live timer (tens of thousands of polls over
        // ~60 s — found live, rip=syscall_entry+2), so it takes the
        // same discipline every delivery window takes. Nothing in
        // the run needs tick timing: the service is a POLLER (its
        // fairness is SCHED_YIELD, its clock is CLOCK_GETTIME), and
        // the client's wake is the reply's pipe write, not a tick.
        // Masked, any seam delivery is the carve-out's stale-IRR
        // drop — exactly the modeled shape.
        crate::sched::preempt::pause_ticks();
        let kernel_cr3 = crate::hw::read_cr3();
        crate::sched::context::stash_parked(
            svc.run,
            crate::sched::context::ParkedContext::from_user_context(&svc.ctx),
        );
        {
            cli.run.tables.activate();
            crate::sched::context::begin(cli.run);
            crate::sched::context::launch(&cli.ctx);
            crate::hw::write_cr3(kernel_cr3);
        }
        let mut svc_exit: Option<u64> = None;
        let mut cli_exit: Option<u64> = None;
        // Collect every exit WITHOUT destroying: the report pages must
        // still be live when the verification reads them below — a
        // destroy scrubs the frames (the pool's discipline), and the
        // reports would read as zeros (found live, exactly that way).
        let mut drained: [(u32, u64); 8] = [(0, u64::MAX); 8];
        let mut n_drained = 0usize;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            let code = match exit {
                crate::sched::context::ExitKind::Exited(c) => c,
                crate::sched::context::ExitKind::Fault {
                    vector, rip, cr2, ..
                } => {
                    let mut hv = [0u8; 20];
                    let mut hr = [0u8; 18];
                    let mut hc = [0u8; 18];
                    line(
                        out,
                        &[
                            "[NET] fault: dom=",
                            strutil::dec(u64::from(dom), &mut hv),
                            " vector=",
                            strutil::dec(u64::from(vector), &mut [0u8; 20]),
                            " rip=",
                            strutil::hex(rip, &mut hr),
                            " cr2=",
                            strutil::hex(cr2, &mut hc),
                        ],
                    );
                    u64::MAX
                }
                crate::sched::context::ExitKind::Running => u64::MAX,
            };
            if dom == TCPIP_DOMAIN {
                svc_exit = Some(code);
            } else if dom == NETCAT_DOMAIN {
                cli_exit = Some(code);
            }
            if n_drained < drained.len() {
                drained[n_drained] = (dom, code);
                n_drained += 1;
            }
        }
        for &(dom, code) in drained.iter().take(n_drained) {
            let mut b = [0u8; 20];
            let mut c = [0u8; 20];
            line(
                out,
                &[
                    "[NET] exited: dom=",
                    strutil::dec(u64::from(dom), &mut b),
                    " code=",
                    strutil::dec(code, &mut c),
                ],
            );
        }

        // The run slot: whoever the scheduler dispatched LAST (a
        // flat-launched domain's exit can land HERE, not in the
        // mailbox — the vnetdom discipline). Taken, named, kept: the
        // destroy happens after the verification's reads.
        let mut slot = crate::sched::context::try_take();
        if let Some(run) = slot.as_ref() {
            let mut b = [0u8; 20];
            let mut nv = [0u8; 20];
            let mut kind = "parked/running";
            let mut code = 0u64;
            match run.exit {
                crate::sched::context::ExitKind::Exited(c) => {
                    kind = "exited";
                    code = c;
                    if run.domain == TCPIP_DOMAIN {
                        svc_exit = Some(c);
                    } else if run.domain == NETCAT_DOMAIN {
                        cli_exit = Some(c);
                    }
                }
                crate::sched::context::ExitKind::Fault {
                    vector, rip, cr2, ..
                } => {
                    let mut hr = [0u8; 18];
                    let mut hc = [0u8; 18];
                    line(
                        out,
                        &[
                            "[NET] fault: dom=",
                            strutil::dec(u64::from(run.domain), &mut [0u8; 20]),
                            " vector=",
                            strutil::dec(u64::from(vector), &mut [0u8; 20]),
                            " rip=",
                            strutil::hex(rip, &mut hr),
                            " cr2=",
                            strutil::hex(cr2, &mut hc),
                        ],
                    );
                    kind = "FAULTED";
                    code = u64::from(vector);
                }
                crate::sched::context::ExitKind::Running => {}
            }
            line(
                out,
                &[
                    "[NET] post-run slot: dom=",
                    strutil::dec(u64::from(run.domain), &mut b),
                    " ",
                    kind,
                    " code/vector=",
                    strutil::dec(code, &mut nv),
                ],
            );
        }

        // ── the verification: both reports, through the PAs (the
        // frames are still owned — the destroys come after) ──
        let (Some(sr), Some(cr)) = (svc_rep_pa, cli_rep_pa) else {
            line(out, &["[NET] report page unresolved — refusing closed"]);
            crate::drvstack::netdata::disarm();
            session.close(out);
            break 'scope;
        };
        let read_u32 = |off: u64| memops::read_u32(sr + off);
        let s_magic = read_u32(svc_rep::MAGIC);
        let s_flags = read_u32(svc_rep::FLAGS);
        let s_exit = read_u32(svc_rep::EXIT);
        let s_tcp_sent = read_u32(svc_rep::TCP_SENT);
        let s_tcp_recvd = read_u32(svc_rep::TCP_RECVD);
        let s_udp_sent = read_u32(svc_rep::UDP_SENT);
        let s_udp_recvd = read_u32(svc_rep::UDP_RECVD);
        let s_malformed = read_u32(svc_rep::MALFORMED);
        let s_emsgsize = memops::read_u32(sr + svc_rep::EMSGSIZE) as i32;
        let s_refill = read_u32(svc_rep::REFILL_OK);
        let s_throttle = read_u32(svc_rep::THROTTLE_SEEN);
        let s_polls = read_u32(svc_rep::POLLS);
        let s_recvs = read_u32(svc_rep::RECVS);
        let s_frames_in = read_u32(svc_rep::FRAMES_IN);
        let s_frames_out = read_u32(svc_rep::FRAMES_OUT);
        let c_magic = memops::read_u32(cr + cli_rep::MAGIC);
        let c_step = memops::read_u32(cr + cli_rep::STEP);
        let c_tcp_ok = memops::read_u32(cr + cli_rep::TCP_OK);
        let c_udp_ok = memops::read_u32(cr + cli_rep::UDP_OK);
        let c_out = memops::read_u32(cr + cli_rep::BYTES_OUT);
        let c_in = memops::read_u32(cr + cli_rep::BYTES_IN);
        let c_probe_send = memops::read_u64(cr + cli_rep::PROBE_SEND) as i64;
        let c_probe_recv = memops::read_u64(cr + cli_rep::PROBE_RECV) as i64;

        let svc_ok = svc_exit == Some(0)
            && s_magic == svc_rep::MAGIC_VALUE
            && s_flags & (svc_rep::F_TCP | svc_rep::F_UDP | svc_rep::F_EMSGSIZE)
                == (svc_rep::F_TCP | svc_rep::F_UDP | svc_rep::F_EMSGSIZE)
            && s_malformed == 0
            && s_emsgsize == -90
            && s_frames_out > 0;
        let cli_ok = cli_exit == Some(0)
            && c_magic == cli_rep::MAGIC_VALUE
            && c_step == 0
            && c_tcp_ok == 1
            && c_udp_ok == 1
            && c_probe_send == -1
            && c_probe_recv == -1;
        // The two-sided agreement: what the client pushed (BOTH
        // protocols) must be what the stack sent; what the stack
        // received must be what the client saw back (the echo's
        // symmetry). The service splits its counters by protocol —
        // sum them before comparing (the first cut compared TCP-only
        // against the client's combined count: 16 ≠ 26, a red lane
        // over a green round trip, found live).
        let agree = s_tcp_sent + s_udp_sent == c_out && s_tcp_recvd + s_udp_recvd == c_in;

        if svc_ok && cli_ok && agree {
            proved = true;
            line(out, &["[NET] stack=live tcp=1 udp=1 broker=1"]);
            line(
                out,
                &[
                    "[NET] client_roundtrip=ok tcp_bytes=",
                    strutil::dec(u64::from(c_out), &mut [0u8; 20]),
                    " udp_bytes=",
                    strutil::dec(u64::from(s_udp_sent), &mut [0u8; 20]),
                    " (gcc static ELF → channels → ring-3 stack → SYS_NET_SEND → broker → slirp → the host's echo → back)",
                ],
            );
            line(
                out,
                &[
                    "[NET] svc probes: net_send(1515)=-90 malformed=0 polls=",
                    strutil::dec(u64::from(s_polls), &mut [0u8; 20]),
                    " recvs=",
                    strutil::dec(u64::from(s_recvs), &mut [0u8; 20]),
                    " frames_in=",
                    strutil::dec(u64::from(s_frames_in), &mut [0u8; 20]),
                    " frames_out=",
                    strutil::dec(u64::from(s_frames_out), &mut [0u8; 20]),
                ],
            );
            if s_throttle == 1 && s_refill == 1 {
                line(
                    out,
                    &["[NET] svc bucket: EAGAIN observed and REFILLED (the kernel clock's stamp works — 1514 B/window still enforced)"],
                );
            }
            line(
                out,
                &[
                    "[NET] client probes: net_send=-EPERM net_recv=-EPERM (denied by policy) — a client cannot bypass the broker",
                ],
            );
        } else {
            let mut b = [0u8; 20];
            line(
                out,
                &[
                    "[NET] LOUD: the round trip did not verify (svc_exit=",
                    strutil::dec(svc_exit.unwrap_or(u64::MAX), &mut b),
                    " svc_report_exit=",
                    strutil::dec(u64::from(s_exit), &mut [0u8; 20]),
                    " flags=",
                    strutil::hex(u64::from(s_flags), &mut [0u8; 18]),
                    " probes(snd,recv)=(",
                    strutil::dec(c_probe_send as u64, &mut [0u8; 20]),
                    ",",
                    strutil::dec(c_probe_recv as u64, &mut [0u8; 20]),
                    ") c_magic=",
                    strutil::hex(u64::from(c_magic), &mut [0u8; 18]),
                    " cli_exit=",
                    strutil::dec(cli_exit.unwrap_or(u64::MAX), &mut [0u8; 20]),
                    " step=",
                    strutil::dec(u64::from(c_step), &mut [0u8; 20]),
                    ") — no live-stack marker is claimed",
                ],
            );
        }

        crate::drvstack::netdata::disarm();

        // The run's window is over: the tick resumes (reloaded,
        // unmasked — the ADR-0019 resume discipline).
        crate::sched::preempt::resume_ticks();

        // ── NOW the domains go: every report has been read (the
        // destroy scrubs the frames — the reads above are the whole
        // reason this happens last). The drained ids first, then the
        // run-slot domain, then anything still parked. ──
        for &(dom, _) in drained.iter().take(n_drained) {
            if let (Some(gk), Some(gpool)) = (
                crate::sched::context::kernel_mut(),
                crate::sched::context::pool_mut(),
            ) {
                crate::mm::user::destroy_user(gk, gpool, dom);
                let _ = crate::sched::preempt::on_exit(&mut gk.sched, dom);
            }
        }
        if let Some(run) = slot.take() {
            if let (Some(gk), Some(gpool)) = (
                crate::sched::context::kernel_mut(),
                crate::sched::context::pool_mut(),
            ) {
                crate::mm::user::destroy_user(gk, gpool, run.domain);
                let _ = crate::sched::preempt::on_exit(&mut gk.sched, run.domain);
            }
        }
        while let Some(run) = crate::sched::context::try_take() {
            let mut b = [0u8; 20];
            line(
                out,
                &[
                    "[NET] LOUD: dom ",
                    strutil::dec(u64::from(run.domain), &mut b),
                    " never exited — torn down parked",
                ],
            );
            if let (Some(gk), Some(gpool)) = (
                crate::sched::context::kernel_mut(),
                crate::sched::context::pool_mut(),
            ) {
                crate::mm::user::destroy_user(gk, gpool, run.domain);
                let _ = crate::sched::preempt::on_exit(&mut gk.sched, run.domain);
            }
        }
        session.close(out);
    } // the session (and its k/pool/broker borrows) end here

    // ── the teardown's channel + supervisor halves, then the domains'
    // leftovers (the run destroyed them; a refused path may not have) ──
    let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, req_id);
    let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, rep_id);
    let _ = k.destroy_domain(NET_SUPER_DOMAIN);
    pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
    let _ = k.destroy_domain(TCPIP_DOMAIN);
    pool.free_all_owned(&mut k.frames, NETCAT_DOMAIN);
    let _ = k.destroy_domain(NETCAT_DOMAIN);
    if proved {
        line(
            out,
            &["[NET] service torn down: channels, supervisor, session, frames, identities"],
        );
    } else {
        line(
            out,
            &["[NET] torn down after an incomplete proof: channels, supervisor, session, frames, identities"],
        );
    }
}

/// The pre-run refusal cleanup (the run path destroys the domains
/// itself after the reads; this is the spawn-side half).
#[cfg(not(test))]
fn cleanup<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    req_id: u32,
    rep_id: u32,
) {
    let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, req_id);
    let _ = k.ipc_endpoint_destroy(NET_SUPER_DOMAIN, rep_id);
    let _ = k.destroy_domain(NET_SUPER_DOMAIN);
    pool.free_all_owned(&mut k.frames, TCPIP_DOMAIN);
    let _ = k.destroy_domain(TCPIP_DOMAIN);
    pool.free_all_owned(&mut k.frames, NETCAT_DOMAIN);
    let _ = k.destroy_domain(NETCAT_DOMAIN);
    line(out, &["[NET] refused closed — every grant is torn down"]);
}
