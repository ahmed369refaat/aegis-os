//! K20 (P0-4): virtio-net as the SECOND ring-3 DRIVER DOMAIN
//! (ADR-0017's second migration — virtio-blk was the first).
//!
//! The kernel keeps the minimal ring-0 half: the claim, the four
//! registered device-core windows (the `SYS_DEVREG` routing: every
//! register access is a message, window-checked by
//! [`crate::ipc_mmio`]), the broker mapping of the domain's own page
//! into the device's IOMMU domain, the DHCP frame seed (a MESSAGE —
//! the payload, never device control; the ring-0 proof builds its
//! own frame the same way), the run, and the teardown. Everything
//! that USED to be driver logic — the reset, the feature
//! negotiation, the MAC read, BOTH queue setups, DRIVER_OK, the RX
//! buffer post, the TX publish + kick, both completion polls — runs
//! at CPL=3 in `examples/ring3-vnetd` (a flat blob spawned with the
//! driver profile: DEVREG+EXIT, nothing else).
//!
//! **The proof shape (the vblkdom discipline, doubled):** the domain
//! reports its own handshake status, both completions, the OFFER's
//! op byte and yiaddr, and the MAC it read THROUGH the devreg
//! channel; the kernel verifies the MAC against its own direct read
//! of the same config — two independent paths through the same
//! device must agree. This domain RESETS the device and brings it up
//! on ITS OWN rings (the ring-0 proof's session is long since torn
//! down), so the exchange itself — 290-byte DISCOVER out, 590-byte
//! OFFER back into the domain's posted buffer — is the ownership
//! proof: no kernel code touches a queue between the reset and the
//! teardown.
//!
//! **Both ring sets live in the domain's ONE data page** (qsize 8:
//! two descriptor tables, both avail and used rings, the DHCP-sized
//! TX frame and the 1526-byte posted RX buffer all fit in 4 KiB) —
//! the same page the spawn maps user-side and the broker maps
//! device-side. A confused-deputy domain can only corrupt its own
//! queues.

// Host-test builds compile this module without its boot-only step.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The driver domain's id (distinct from every frame-owner tag and
/// every ring-3 demo domain: vnet frames 44, vblkdom 61 + rogue 62,
/// the netd 66, the userland caller 68).
pub(crate) const VNETD_DOMAIN: u32 = 70;

/// The rogue domain id (the quarantine proof).
pub(crate) const VNETD_ROGUE_DOMAIN: u32 = 71;

/// The domain image, built with the kernel like every ring-3 blob.
#[cfg(not(test))]
static VNETD_DOM_BLOB: &[u8] = include_bytes!("../../blob/ring3-vnetd.bin");

/// The rogue domain image (shared with the virtio-blk quarantine —
/// the hostile-offset hammering is device-generic).
#[cfg(not(test))]
static VNETD_ROGUE_BLOB: &[u8] = include_bytes!("../../blob/ring3-rogue-drv.bin");

/// The report block the kernel verifies (the blob's data-page
/// offsets; the layout is documented in the blob's module doc).
#[cfg(not(test))]
mod report {
    pub(crate) const HANDSHAKE: u64 = 0x20;
    pub(crate) const TX_USED_LEN: u64 = 0x28;
    pub(crate) const RX_USED_LEN: u64 = 0x30;
    pub(crate) const RX_OP: u64 = 0x38;
    pub(crate) const RX_YIADDR: u64 = 0x40;
    pub(crate) const MAC_LO: u64 = 0x48;
    pub(crate) const MAC_HI: u64 = 0x50;
    pub(crate) const PROGRESS: u64 = 0x58;
}

/// K20 (P0-4): run the virtio-net bring-up + a DHCP round trip as a
/// ring-3 driver domain on the domain's OWN rings, verify the
/// reports (the MAC against the kernel's own read), then tear the
/// whole grant down — channel first (unregister), broker mapping
/// second (session close), domain last (frames + identity). Refuses
/// closed (loud markers, full cleanup) at every step. Then the
/// quarantine proof: a rogue domain hammers out-of-window offsets
/// and loses its device.
#[cfg(not(test))]
pub(crate) fn vnetdom_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::ipc_mmio;
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv
        .find_by(0x1AF4, 0x02)
        .filter(|d| crate::pci::has_virtio_cap(d))
    else {
        line(
            out,
            &["[VNETD] no virtio-net on this machine — the domain path skips"],
        );
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[VNETD] broker verdict absent — refusing to run the domain"],
        );
        return;
    }
    let Some(caps) = crate::virtio::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(dev, off))
    else {
        line(out, &["[VNETD] vendor caps incomplete — refusing"]);
        return;
    };
    crate::pci::enable_mem(dev);
    let resolved = match caps.resolve(dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[VNETD] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    // The kernel's own MAC read (device-config bytes 0..6, byte
    // reads — the offset is 4-aligned but not guaranteed 8) — both
    // the seed's source and the verification target for the domain's
    // devreg-mediated read.
    let cfg = resolved.device_cfg_pa;
    let mac = [
        crate::virtio::read_u8_pa(cfg),
        crate::virtio::read_u8_pa(cfg + 1),
        crate::virtio::read_u8_pa(cfg + 2),
        crate::virtio::read_u8_pa(cfg + 3),
        crate::virtio::read_u8_pa(cfg + 4),
        crate::virtio::read_u8_pa(cfg + 5),
    ];
    let mac_lo = u32::from(mac[0])
        | (u32::from(mac[1]) << 8)
        | (u32::from(mac[2]) << 16)
        | (u32::from(mac[3]) << 24);
    let mac_hi = u16::from(mac[4]) | (u16::from(mac[5]) << 8);

    // ── the spawn ──
    let boot: [u8; 64] = [0; 64];
    let spawn = match crate::mm::user::spawn_user_blob(
        k,
        pool,
        VNETD_DOMAIN,
        aegis_os::profile::driver_profile(),
        VNETD_DOM_BLOB,
        &boot,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[VNETD] domain spawn refused — refusing closed"]);
            return;
        }
    };
    // Patch the boot info: the data page's own physical address and
    // the notify multiplier for the kick slots.
    let Some(data_pa) = spawn
        .run
        .tables
        .translate(crate::mm::user_layout::DATA_BASE)
    else {
        line(out, &["[VNETD] data page unresolved — refusing closed"]);
        pool.free_all_owned(&mut k.frames, VNETD_DOMAIN);
        let _ = k.destroy_domain(VNETD_DOMAIN);
        return;
    };
    crate::memops::write_u64(data_pa, data_pa);
    crate::memops::write_u64(data_pa + 8, u64::from(resolved.notify_multiplier));
    // The seed: the DISCOVER frame the domain will publish — a
    // message, not device control (the ring-0 proof builds its own
    // the same way). The vnet TX header (12 bytes, all zero for this
    // legacy-compatible path) + the 290-byte frame at +12.
    crate::drvstack::netutil::build_dhcp_discover_at(data_pa + 0x200 + 12, mac);

    // ── the session + the cores + the run, scoped so the session's
    // borrows END before the domain's frames + identity are
    // reclaimed; every refusal breaks out of the scope, the
    // session's Drop still revokes. ──
    let mut proved = false;
    let mut refused = false;
    'scope: {
        let mut session = crate::session::DriverSession::new(
            k,
            pool,
            broker,
            Some(dev),
            VNETD_DOMAIN,
            dev.dom,
            false,
            "[VNETD] teardown",
            "",
        );
        if session.map(data_pa).is_none() {
            line(
                out,
                &["[VNETD] broker refused the ring page — refusing closed"],
            );
            refused = true;
            break 'scope;
        }
        crate::pci::enable_bus_master(dev);

        // ── the cores: the four region windows, registered for THIS
        // domain — the SYS_DEVREG routing table. Region 0 = common,
        // 1 = notify, 2 = isr, 3 = device-config. ──
        let regions: [(u8, u64, u64); 4] = [
            (0, resolved.common_pa, u64::from(caps.common.length)),
            (1, resolved.notify_base_pa, u64::from(resolved.notify_len)),
            (2, resolved.isr_pa, u64::from(caps.isr.length)),
            (3, resolved.device_cfg_pa, u64::from(caps.device.length)),
        ];
        for &(region, base, len) in &regions {
            if !ipc_mmio::register_core(VNETD_DOMAIN, region, base, len) {
                line(
                    out,
                    &["[VNETD] core registration refused (region/full) — refusing closed"],
                );
                ipc_mmio::unregister_domain(VNETD_DOMAIN);
                refused = true;
                break 'scope;
            }
        }

        // ── the run (the kmain ring-3 pattern, verbatim) ──
        let kernel_cr3 = crate::hw::read_cr3();
        spawn.run.tables.activate();
        crate::sched::context::begin(spawn.run);
        crate::sched::context::launch(&spawn.ctx);
        let run = crate::sched::context::take();
        crate::hw::write_cr3(kernel_cr3);

        // ── the verification ──
        let (served, refused_cnt) = ipc_mmio::core_counters(VNETD_DOMAIN);
        let handshake = crate::memops::read_u64(data_pa + report::HANDSHAKE);
        let tx_len = crate::memops::read_u64(data_pa + report::TX_USED_LEN);
        let rx_len = crate::memops::read_u64(data_pa + report::RX_USED_LEN);
        let rx_op = crate::memops::read_u64(data_pa + report::RX_OP);
        let yiaddr = crate::memops::read_u64(data_pa + report::RX_YIADDR);
        let dom_mac_lo = crate::memops::read_u64(data_pa + report::MAC_LO);
        let dom_mac_hi = crate::memops::read_u64(data_pa + report::MAC_HI);
        let mut ns = [0u8; 20];
        let mut ns2 = [0u8; 20];
        let mut nr = [0u8; 20];
        let mut yi = [0u8; 18];
        let mac_agrees = dom_mac_lo == u64::from(mac_lo) && dom_mac_hi == u64::from(mac_hi);
        // The blob read the wire's 4 yiaddr bytes as one little-endian
        // u32; the wire address is big-endian, so swap back before
        // comparing against 10.0.2.x.
        let yiaddr_be = u64::from((yiaddr as u32).swap_bytes());
        // The TX completion's len is QEMU's virtio-net convention: 0
        // (the device consumed the frame but reports no write-back
        // length, unlike the read direction's data-bearing 513). The
        // REAL TX proof is causal: the blob only reaches progress 10
        // after the TX used.idx advanced past its publish, and the
        // OFFER answering the DISCOVER proves the frame traversed the
        // domain's own ring + kick.
        let offer_ok = rx_op == 2 && (yiaddr_be & 0xFF00_0000) == 0x0A00_0000;
        match run.exit {
            crate::sched::context::ExitKind::Exited(0)
                if handshake == 15 && rx_len >= 12 + 590 && offer_ok && mac_agrees =>
            {
                line(
                    out,
                    &[
                        "[VNETD] driver-domains=2: the ring-3 domain brought the NIC up on its OWN rings through the devreg channel (",
                        strutil::dec(served, &mut ns),
                        " ops served, ",
                        strutil::dec(refused_cnt, &mut nr),
                        " refused) — reset, features, both queues, DRIVER_OK, all at CPL=3",
                    ],
                );
                line(
                    out,
                    &[
                        "[VNETD] DHCP at CPL=3 through the domain's OWN rings: 290-byte DISCOVER out, 590-byte OFFER back (op=BOOTREPLY, yiaddr=",
                        strutil::hex(yiaddr, &mut yi),
                        "), the domain's devreg MAC read matches the kernel's — the second migrated driver",
                    ],
                );
                proved = true;
            }
            crate::sched::context::ExitKind::Exited(0) => {
                line(
                    out,
                    &[
                        "[VNETD] domain exited 0 but the verification mismatched (progress ",
                        strutil::dec(
                            crate::memops::read_u64(data_pa + report::PROGRESS),
                            &mut ns2,
                        ),
                        "): handshake=",
                        strutil::hex(handshake, &mut [0u8; 18]),
                        " tx_len=",
                        strutil::dec(tx_len, &mut ns),
                        " rx_len=",
                        strutil::dec(rx_len, &mut nr),
                        " op=",
                        strutil::hex(rx_op, &mut [0u8; 18]),
                        " yiaddr=",
                        strutil::hex(yiaddr, &mut yi),
                        " mac_ok=",
                        if mac_agrees { "yes" } else { "NO" },
                        " — LOUD",
                    ],
                );
            }
            crate::sched::context::ExitKind::Exited(code) => {
                line(
                    out,
                    &[
                        "[VNETD] domain exited ",
                        strutil::dec(code, &mut ns),
                        " (progress ",
                        strutil::dec(
                            crate::memops::read_u64(data_pa + report::PROGRESS),
                            &mut ns2,
                        ),
                        ") — LOUD: the migrated driver did not complete its proof",
                    ],
                );
            }
            crate::sched::context::ExitKind::Fault { vector, .. } => {
                let mut nv = [0u8; 20];
                line(
                    out,
                    &[
                        "[VNETD] domain faulted (vector ",
                        strutil::dec(u64::from(vector), &mut nv),
                        ", progress ",
                        strutil::dec(
                            crate::memops::read_u64(data_pa + report::PROGRESS),
                            &mut ns2,
                        ),
                        ") — LOUD: the migrated driver crashed, the boot continues",
                    ],
                );
            }
            crate::sched::context::ExitKind::Running => {
                line(
                    out,
                    &["[VNETD] domain still marked Running after the launch returned — LOUD kernel bug"],
                );
            }
        }

        // ── the teardown's channel + mapping halves, in order ──
        ipc_mmio::unregister_domain(VNETD_DOMAIN);
        session.close(out);
    } // the session (and its k/pool/broker borrows) end here

    // The domain's frames + identity, LAST.
    pool.free_all_owned(&mut k.frames, VNETD_DOMAIN);
    let _ = k.destroy_domain(VNETD_DOMAIN);
    if refused {
        line(
            out,
            &["[VNETD] refused closed — the domain is fully torn down"],
        );
        return;
    }
    if proved {
        line(
            out,
            &["[VNETD] domain torn down: channel, mapping, identity"],
        );
    } else {
        line(
            out,
            &["[VNETD] domain torn down after an incomplete proof: channel, mapping, identity"],
        );
    }

    // ── the QUARANTINE proof: the same rogue discipline as
    // virtio-blk — a second domain registered over the (read-only)
    // device-config window hammers out-of-window offsets; the core
    // refuses every one (COUNTED), the ladder closes the channel,
    // and the rogue's report proves a LEGAL offset refuses too. ──
    let boot2: [u8; 64] = [0; 64];
    let Ok(spawn2) = crate::mm::user::spawn_user_blob(
        k,
        pool,
        VNETD_ROGUE_DOMAIN,
        aegis_os::profile::driver_profile(),
        VNETD_ROGUE_BLOB,
        &boot2,
    ) else {
        line(
            out,
            &["[VNETD] rogue spawn refused — the quarantine proof cannot run"],
        );
        return;
    };
    if !ipc_mmio::register_core(
        VNETD_ROGUE_DOMAIN,
        3,
        resolved.device_cfg_pa,
        u64::from(caps.device.length),
    ) {
        line(out, &["[VNETD] rogue core registration refused"]);
        pool.free_all_owned(&mut k.frames, VNETD_ROGUE_DOMAIN);
        let _ = k.destroy_domain(VNETD_ROGUE_DOMAIN);
        return;
    }
    let rogue_pa = spawn2
        .run
        .tables
        .translate(crate::mm::user_layout::DATA_BASE)
        .unwrap_or(0);
    let kernel_cr3 = crate::hw::read_cr3();
    spawn2.run.tables.activate();
    crate::sched::context::begin(spawn2.run);
    crate::sched::context::launch(&spawn2.ctx);
    let run2 = crate::sched::context::take();
    crate::hw::write_cr3(kernel_cr3);
    let (_served2, refused2) = ipc_mmio::core_counters(VNETD_ROGUE_DOMAIN);
    let rogue_report = crate::memops::read_u64(rogue_pa);
    let rogue_exit_ok = matches!(run2.exit, crate::sched::context::ExitKind::Exited(0));
    ipc_mmio::unregister_domain(VNETD_ROGUE_DOMAIN);
    pool.free_all_owned(&mut k.frames, VNETD_ROGUE_DOMAIN);
    let _ = k.destroy_domain(VNETD_ROGUE_DOMAIN);
    let mut b = [0u8; 20];
    if rogue_exit_ok && rogue_report == 5 && refused2 == 5 {
        line(
            out,
            &[
                "[VNETD] rogue driver domain contained: ",
                strutil::dec(refused2, &mut b),
                " out-of-window messages refused and COUNTED, the ladder CLOSED the channel (a legal read refuses too) — a bad NIC driver loses its device, the boot continues",
            ],
        );
    } else {
        line(
            out,
            &[
                "[VNETD] rogue containment NOT proven (report=",
                strutil::hex(rogue_report, &mut [0u8; 18]),
                ", refused=",
                strutil::dec(refused2, &mut b),
                ") — LOUD",
            ],
        );
    }
}
