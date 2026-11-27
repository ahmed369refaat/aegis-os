//! K26: the e1000 as the THIRD ring-3 DRIVER DOMAIN (ADR-0017's
//! third migration — virtio-blk was the first, virtio-net the
//! second).
//!
//! The kernel keeps the minimal ring-0 half: the claim, the ONE
//! registered device-core window (the whole BAR0 — every register
//! this legacy driver touches, window-checked by
//! [`crate::ipc_mmio`] on every `SYS_DEVREG` message), the broker
//! mapping of the domain's own page into the NIC's IOMMU domain, the
//! DHCP frame seed (a MESSAGE — the payload, never device control;
//! the ring-0 proof builds its own frame the same way), the run, and
//! the teardown. Everything that USED to be driver logic — the
//! quiesce, the MAC/link read, BOTH legacy ring programs (RDBAL +
//! RDBAH + RDLEN + RDT + RCTL, TDBAL + TDLEN + TCTL), the RX buffer
//! post, the TX descriptor build + the tail kick, both completion
//! polls — runs at CPL=3 in `examples/ring3-e1kdom` (a flat blob
//! spawned with the driver profile: DEVREG+EXIT, nothing else).
//!
//! **The proof shape (the vnetdom discipline, legacy-descriptor
//! edition):** the domain reports its own progress, the TX write-back
//! DD, the RX length, the OFFER's op byte and yiaddr, and the MAC it
//! read THROUGH the devreg channel; the kernel verifies the MAC
//! against its own direct read of the same RAL/RAH registers — two
//! independent paths through the same device must agree. This domain
//! repoints the NIC onto ITS OWN rings (the ring-0 proof's session is
//! long since torn down), so the exchange itself — 290-byte DISCOVER
//! out, OFFER back into the domain's posted buffer — is the ownership
//! proof: no kernel code touches a register between the spawn and the
//! teardown.
//!
//! **Both legacy descriptor rings + both frame buffers live in the
//! domain's ONE data page** (16-entry 16-byte-desc rings, the
//! DHCP-sized TX frame, the 1514-byte posted RX buffer — all inside
//! 4 KiB) — the same page the spawn maps user-side and the broker
//! maps device-side. A confused-deputy domain can only corrupt its
//! own queues.

// Host-test builds compile this module without its boot-only step.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::mmio::MmioBus;
use crate::strutil;
use crate::strutil::line;

/// The driver domain's id (distinct from every frame-owner tag and
/// every ring-3 demo domain: vnet frames 44, e1k frames 45, vblkdom
/// 61 + rogue 62, the netd 66, vnetd 70 + rogue 71).
pub(crate) const E1KD_DOMAIN: u32 = 72;

/// The rogue domain id (the quarantine proof).
pub(crate) const E1KD_ROGUE_DOMAIN: u32 = 73;

/// The domain image, built with the kernel like every ring-3 blob.
#[cfg(not(test))]
static E1KD_DOM_BLOB: &[u8] = include_bytes!("../../blob/ring3-e1kdom.bin");

/// The rogue domain image (shared with the virtio driver domains —
/// the hostile-offset hammering is device-generic).
#[cfg(not(test))]
static E1KD_ROGUE_BLOB: &[u8] = include_bytes!("../../blob/ring3-rogue-drv.bin");

/// The report block the kernel verifies (the blob's data-page
/// offsets; the layout is documented in the blob's module doc and
/// pinned by the host test below).
pub(crate) mod report {
    pub(crate) const PROGRESS: u64 = 0x20;
    pub(crate) const TX_DONE: u64 = 0x28;
    pub(crate) const RX_LEN: u64 = 0x30;
    pub(crate) const RX_OP: u64 = 0x38;
    pub(crate) const RX_YIADDR: u64 = 0x40;
    pub(crate) const MAC_LO: u64 = 0x48;
    pub(crate) const MAC_HI: u64 = 0x50;
    pub(crate) const STATUS_WORD: u64 = 0x58;
    /// The TX frame's seed offset (the kernel-seeded DISCOVER).
    pub(crate) const TX_FRAME: u64 = 0x280;
}

/// K26: run the e1000 bring-up + a DHCP round trip as a ring-3
/// driver domain on the domain's OWN legacy rings, verify the
/// reports (the MAC against the kernel's own read), then tear the
/// whole grant down — channel first (unregister), broker mapping
/// second (session close), domain last (frames + identity). Refuses
/// closed (loud markers, full cleanup) at every step. Then the
/// quarantine proof: a rogue domain hammers out-of-window offsets
/// and loses its device.
#[cfg(not(test))]
pub(crate) fn e1kdom_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::ipc_mmio;
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x8086, 0x02) else {
        line(
            out,
            &["[E1KD] no e1000 on this machine — the domain path skips"],
        );
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[E1KD] broker verdict absent — refusing to run the domain"],
        );
        return;
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[E1KD] BAR0 unresolved — refusing"]);
        return;
    };
    // The registered window is the WHOLE BAR (this legacy driver
    // touches registers from 0x0008 to 0x5404; the window check at
    // every message is the containment, the per-register offsets are
    // the driver's own business at CPL=3).
    let Some(bus) = crate::mmio::BarMmio::new(bar.base, bar.size) else {
        line(
            out,
            &["[E1KD] BAR0 window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    if bus.window().len() < 0x5408 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[E1KD] BAR0 window too small for the register set (len=",
                strutil::hex(bus.window().len(), &mut lb),
                " < 0x5408) — refusing",
            ],
        );
        return;
    }
    // The kernel's own MAC read (RAL/RAH, the identity registers) —
    // both the seed's source and the verification target for the
    // domain's devreg-mediated read.
    let (Some(ral), Some(rah), Some(status)) =
        (bus.read32(0x5400), bus.read32(0x5404), bus.read32(0x0008))
    else {
        line(
            out,
            &["[E1KD] register window refused a MAC/status read — refusing"],
        );
        return;
    };
    let mac_lo = ral;
    let mac_hi = rah & 0xFFFF; // RAH's upper half is AV + reserved
    let mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ];
    let link_up = status & 0x2 != 0;
    if !link_up {
        line(out, &["[E1KD] link reads DOWN before the run — refusing"]);
        return;
    }

    // ── the spawn ──
    let boot: [u8; 64] = [0; 64];
    let spawn = match crate::mm::user::spawn_user_blob(
        k,
        pool,
        E1KD_DOMAIN,
        aegis_os::profile::driver_profile(),
        E1KD_DOM_BLOB,
        &boot,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[E1KD] domain spawn refused — refusing closed"]);
            return;
        }
    };
    // Patch the boot info: the data page's own physical address (the
    // one address the driver holds — its own page, kernel-brokered).
    let Some(data_pa) = spawn
        .run
        .tables
        .translate(crate::mm::user_layout::DATA_BASE)
    else {
        line(out, &["[E1KD] data page unresolved — refusing closed"]);
        pool.free_all_owned(&mut k.frames, E1KD_DOMAIN);
        let _ = k.destroy_domain(E1KD_DOMAIN);
        return;
    };
    crate::memops::write_u64(data_pa, data_pa);
    // The seed: the DISCOVER frame the domain will TX — a message,
    // not device control (the ring-0 proof builds its own the same
    // way). 290 bytes at the page's TX-frame slot.
    crate::drvstack::netutil::build_dhcp_discover_at(data_pa + report::TX_FRAME, mac);

    // ── the session + the core + the run, scoped so the session's
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
            E1KD_DOMAIN,
            dev.dom,
            false,
            "[E1KD] teardown",
            "",
        );
        if session.map(data_pa).is_none() {
            line(
                out,
                &["[E1KD] broker refused the ring page — refusing closed"],
            );
            refused = true;
            break 'scope;
        }
        // The core: ONE window — the whole BAR0, region 0. Every
        // register access the domain makes is a message checked
        // against this window at serve time.
        if !ipc_mmio::register_core(E1KD_DOMAIN, 0, bar.base, bar.size) {
            line(
                out,
                &["[E1KD] core registration refused (region/full) — refusing closed"],
            );
            ipc_mmio::unregister_domain(E1KD_DOMAIN);
            refused = true;
            break 'scope;
        }
        // F9e: the page is broker-mapped — now the device may DMA.
        crate::pci::enable_bus_master(dev);

        // ── the run (the kmain ring-3 pattern, verbatim) ──
        let kernel_cr3 = crate::hw::read_cr3();
        spawn.run.tables.activate();
        crate::sched::context::begin(spawn.run);
        crate::sched::context::launch(&spawn.ctx);
        let run = crate::sched::context::take();
        crate::hw::write_cr3(kernel_cr3);

        // ── the verification ──
        let (served, refused_cnt) = ipc_mmio::core_counters(E1KD_DOMAIN);
        let progress = crate::memops::read_u64(data_pa + report::PROGRESS);
        let tx_done = crate::memops::read_u64(data_pa + report::TX_DONE);
        let rx_len = crate::memops::read_u64(data_pa + report::RX_LEN);
        let rx_op = crate::memops::read_u64(data_pa + report::RX_OP);
        let yiaddr = crate::memops::read_u64(data_pa + report::RX_YIADDR);
        let dom_mac_lo = crate::memops::read_u64(data_pa + report::MAC_LO);
        let dom_mac_hi = crate::memops::read_u64(data_pa + report::MAC_HI);
        let dom_status = crate::memops::read_u64(data_pa + report::STATUS_WORD);
        let mut ns = [0u8; 20];
        let mut ns2 = [0u8; 20];
        let mut nr = [0u8; 20];
        let mut nl = [0u8; 20];
        let mut yi = [0u8; 18];
        let mac_agrees = dom_mac_lo == u64::from(mac_lo) && dom_mac_hi == u64::from(mac_hi);
        // The blob read the wire's 4 yiaddr bytes as one little-endian
        // u32; the wire address is big-endian, so swap back before
        // comparing against 10.0.2.x.
        let yiaddr_be = u64::from((yiaddr as u32).swap_bytes());
        let offer_ok = rx_op == 2 && (yiaddr_be & 0xFF00_0000) == 0x0A00_0000;
        match run.exit {
            crate::sched::context::ExitKind::Exited(0)
                if progress == 7
                    && dom_status & 0x2 != 0 // the domain saw link UP too
                    && tx_done == 1
                    && rx_len >= 300
                    && offer_ok
                    && mac_agrees
                    && refused_cnt == 0 =>
            {
                line(
                    out,
                    &[
                        "[E1KD] driver-domains=3: the ring-3 domain brought the e1000 up on its OWN rings through the devreg channel (",
                        strutil::dec(served, &mut ns),
                        " ops served, ",
                        strutil::dec(refused_cnt, &mut nr),
                        " refused) — quiesce, MAC, both legacy ring programs, all at CPL=3",
                    ],
                );
                line(
                    out,
                    &[
                        "[E1KD] DHCP at CPL=3 through the domain's OWN legacy rings: 290-byte DISCOVER out, ",
                        strutil::dec(rx_len, &mut nl),
                        "-byte OFFER back (op=BOOTREPLY, yiaddr=",
                        strutil::hex(yiaddr, &mut yi),
                        "), the domain's devreg MAC read matches the kernel's — the third migrated driver",
                    ],
                );
                proved = true;
            }
            crate::sched::context::ExitKind::Exited(0) => {
                line(
                    out,
                    &[
                        "[E1KD] domain exited 0 but the verification mismatched (progress ",
                        strutil::dec(progress, &mut ns2),
                        "): tx_done=",
                        strutil::dec(tx_done, &mut ns),
                        " rx_len=",
                        strutil::dec(rx_len, &mut nr),
                        " op=",
                        strutil::hex(rx_op, &mut [0u8; 18]),
                        " yiaddr=",
                        strutil::hex(yiaddr, &mut yi),
                        " mac_ok=",
                        if mac_agrees { "yes" } else { "NO" },
                        " refused=",
                        strutil::dec(refused_cnt, &mut nl),
                        " — LOUD",
                    ],
                );
            }
            crate::sched::context::ExitKind::Exited(code) => {
                line(
                    out,
                    &[
                        "[E1KD] domain exited ",
                        strutil::dec(code, &mut ns),
                        " (progress ",
                        strutil::dec(progress, &mut ns2),
                        ") — LOUD: the migrated driver did not complete its proof",
                    ],
                );
            }
            crate::sched::context::ExitKind::Fault { vector, .. } => {
                let mut nv = [0u8; 20];
                line(
                    out,
                    &[
                        "[E1KD] domain faulted (vector ",
                        strutil::dec(u64::from(vector), &mut nv),
                        ", progress ",
                        strutil::dec(progress, &mut ns2),
                        ") — LOUD: the migrated driver crashed, the boot continues",
                    ],
                );
            }
            crate::sched::context::ExitKind::Running => {
                line(
                    out,
                    &["[E1KD] domain still marked Running after the launch returned — LOUD kernel bug"],
                );
            }
        }

        // ── the teardown's channel + mapping halves, in order ──
        ipc_mmio::unregister_domain(E1KD_DOMAIN);
        session.close(out);
    } // the session (and its k/pool/broker borrows) end here

    // The domain's frames + identity, LAST.
    pool.free_all_owned(&mut k.frames, E1KD_DOMAIN);
    let _ = k.destroy_domain(E1KD_DOMAIN);
    if refused {
        line(
            out,
            &["[E1KD] refused closed — the domain is fully torn down"],
        );
        return;
    }
    if proved {
        line(
            out,
            &["[E1KD] domain torn down: channel, mapping, identity"],
        );
    } else {
        line(
            out,
            &["[E1KD] domain torn down after an incomplete proof: channel, mapping, identity"],
        );
    }

    // ── the QUARANTINE proof: the same rogue discipline as the
    // virtio driver domains — a second domain registered over a
    // small read-only-ish slice of the BAR hammers out-of-window
    // offsets; the core refuses every one (COUNTED), the ladder
    // closes the channel, and the rogue's report proves a LEGAL
    // offset refuses too. ──
    let boot2: [u8; 64] = [0; 64];
    let Ok(spawn2) = crate::mm::user::spawn_user_blob(
        k,
        pool,
        E1KD_ROGUE_DOMAIN,
        aegis_os::profile::driver_profile(),
        E1KD_ROGUE_BLOB,
        &boot2,
    ) else {
        line(
            out,
            &["[E1KD] rogue spawn refused — the quarantine proof cannot run"],
        );
        return;
    };
    // A 256-byte window: the rogue's 0x10000 offsets are far outside
    // it, and the closure check runs before the window check anyway.
    if !ipc_mmio::register_core(E1KD_ROGUE_DOMAIN, 3, bar.base, 0x100) {
        line(out, &["[E1KD] rogue core registration refused"]);
        pool.free_all_owned(&mut k.frames, E1KD_ROGUE_DOMAIN);
        let _ = k.destroy_domain(E1KD_ROGUE_DOMAIN);
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
    let (_served2, refused2) = ipc_mmio::core_counters(E1KD_ROGUE_DOMAIN);
    let rogue_report = crate::memops::read_u64(rogue_pa);
    let rogue_exit_ok = matches!(run2.exit, crate::sched::context::ExitKind::Exited(0));
    ipc_mmio::unregister_domain(E1KD_ROGUE_DOMAIN);
    pool.free_all_owned(&mut k.frames, E1KD_ROGUE_DOMAIN);
    let _ = k.destroy_domain(E1KD_ROGUE_DOMAIN);
    let mut b = [0u8; 20];
    if rogue_exit_ok && rogue_report == 5 && refused2 == 5 {
        line(
            out,
            &[
                "[E1KD] rogue driver domain contained: ",
                strutil::dec(refused2, &mut b),
                " out-of-window messages refused and COUNTED, the ladder CLOSED the channel (a legal read refuses too) — a bad e1000 driver loses its device, the boot continues",
            ],
        );
    } else {
        line(
            out,
            &[
                "[E1KD] rogue containment NOT proven (report=",
                strutil::hex(rogue_report, &mut [0u8; 18]),
                ", refused=",
                strutil::dec(refused2, &mut b),
                ") — LOUD",
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::report;

    /// K25's lesson, made a TEST: the data-page layout's every offset
    /// — the report block, both descriptor rings, both frame slots —
    /// must stay inside the 4 KiB page and never overlap. The
    /// hex/decimal offset confusion that faked the five-round
    /// "page rewritten post-recv" anomaly lived exactly here, in
    /// unchecked literals; this pins them.
    #[test]
    fn the_e1kdom_data_page_layout_is_pinned() {
        // The blob's own literals, restated as the one truth table.
        let page: u64 = 0x403000;
        let page_pa_slot = 0x000u64;
        let report = [
            report::PROGRESS,
            report::TX_DONE,
            report::RX_LEN,
            report::RX_OP,
            report::RX_YIADDR,
            report::MAC_LO,
            report::MAC_HI,
            report::STATUS_WORD,
        ];
        let rx_ring = 0x080u64; // 16 × 16 B descriptors
        let tx_ring = 0x180u64;
        let tx_frame = report::TX_FRAME; // 290 B
        let rx_buffer = 0x400u64; // 1514 B max

        // every slot inside the page
        for &off in report.iter() {
            assert!(off < 0x1000, "report slot {off:#x} escapes the page");
        }
        assert!(rx_ring + 256 <= 0x1000);
        assert!(tx_ring + 256 <= 0x1000);
        assert!(tx_frame + 290 <= 0x1000);
        assert!(rx_buffer + 1514 <= 0x1000, "the RX buffer must fit");

        // the frame slots clear the rings
        assert!(tx_frame >= tx_ring + 256, "TX frame overlaps the TX ring");
        assert!(
            rx_buffer >= tx_frame + 290,
            "RX buffer overlaps the TX frame"
        );

        // the report block clears the page-pa slot and the rings
        for &off in report.iter() {
            assert!(
                off >= page_pa_slot + 8,
                "report slot {off:#x} hits the boot info"
            );
            assert!(off < rx_ring, "report slot {off:#x} reaches the RX ring");
        }

        // THE K25 pin: the OFFER's op byte is frame+42 DECIMAL and
        // yiaddr frame+58 — the blob reads them at 0x42A/0x438 past
        // the RX buffer's base. State the derivation, never a bare
        // literal that could be "42" in the other base.
        let op_off = rx_buffer + 42; // eth(14)+ip(20)+udp(8) — DECIMAL
        let yiaddr_off = rx_buffer + 58; // op+16 in the BOOTP header
        assert_eq!(op_off, 0x42A, "frame+42 decimal is 0x42A, not 0x842");
        assert_eq!(yiaddr_off, 0x43A, "frame+58 decimal is 0x43A, not 0x858");
        assert_eq!(page + op_off, 0x40342A);
        assert_eq!(page + yiaddr_off, 0x40343A);
    }
}
