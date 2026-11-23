//! virtio-blk: the modern virtio handshake + queue rings through the broker.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for virtio-blk frames (rings, control page,
/// data page) — distinct from the VT-d table budget so the M1
/// zero-leak accounting can name every holder.
pub const VBLK_OWNER: u32 = 43;

/// One virtqueue ring set + the request control page, all mapped
/// through the broker BEFORE the device sees any address.
///
/// `notify_off` and `cookies` are the per-queue bookkeeping the
/// per-region teardown + used-ring validation rework (driver-stack
/// phases 3/4) consumes; today's teardown goes through revoke_all,
/// which does not read them.
#[allow(dead_code)]
pub(crate) struct VblkQueue {
    pub(crate) qsize: u16,
    pub(crate) notify_off: u16,
    pub(crate) desc_pa: u64,
    pub(crate) avail_pa: u64,
    pub(crate) used_pa: u64,
    pub(crate) ctrl_pa: u64,
    pub(crate) cookies: [u64; 4],
}

/// The shared submission path: build the 3-descriptor chain, publish
/// it in the avail ring, kick the queue. `data` points at the page
/// the device reads (OUT) or writes (IN). The queue travels as an
/// argument — no statics, no unsafe (the Phase-1 driver-domain model
/// owns per-domain state when multiple devices exist).
pub(crate) fn submit(q: &VblkQueue, data_pa: u64, sector: u64, req_type: u32) -> u16 {
    use crate::virtio as v;
    v::write_blk_header(q.ctrl_pa, req_type, sector);
    // desc 0: the 16-byte header, device reads.
    v::write_desc(q.desc_pa, q.ctrl_pa, 16, v::DESC_F_NEXT, 1);
    // desc 1: the 512-byte sector, device writes for IN.
    let data_flags = if req_type == v::BLK_T_IN {
        v::DESC_F_NEXT | v::DESC_F_WRITE
    } else {
        v::DESC_F_NEXT
    };
    v::write_desc(q.desc_pa + 16, data_pa, 512, data_flags, 2);
    // desc 2: the status byte, device writes.
    v::write_desc(q.desc_pa + 32, q.ctrl_pa + 512, 1, v::DESC_F_WRITE, 0);
    let avail_idx = v::read_u16_pa(q.avail_pa + 2);
    v::write_u16_pa(v::avail_slot_addr(q.avail_pa, avail_idx % q.qsize), 0);
    v::write_u16_pa(q.avail_pa + 2, avail_idx.wrapping_add(1));
    avail_idx.wrapping_add(1)
}

/// Bounded poll for the used ring to reach `want` (the avail index we
/// published). None on timeout — the caller decides what that means
/// (the enforcement probe WANTS the timeout or the error completion).
/// F7 (review round 4): the used ring is device-written memory. Every
/// completion is validated against the submission — the index may
/// never run past what was submitted nor jump by more than the queue
/// depth, and the completion's id/length must match the request.
#[cfg(not(test))]
pub(crate) enum UsedOutcome {
    Completed,
    Timeout,
    Poisoned(&'static str),
}

#[cfg(not(test))]
pub(crate) fn poll_used(q: &VblkQueue, want: u16) -> UsedOutcome {
    use crate::virtio as v;
    let budget = 20_000_000u64; // bounded: ADR-0013's no-infinite-spin rule
    let mut spins = 0u64;
    let entry_used = v::used_idx(q.used_pa); // F7: advance since entry
    loop {
        let used = v::used_idx(q.used_pa);
        if used.wrapping_sub(entry_used) > q.qsize {
            return UsedOutcome::Poisoned("used.idx advanced beyond the queue size");
        }
        if used > want {
            return UsedOutcome::Poisoned("used.idx ran past the submission");
        }
        if used == want {
            let slot = want.wrapping_sub(1) % q.qsize;
            return match v::validate_used(q.used_pa, slot, q.qsize, 0, 529) {
                Ok(_) => UsedOutcome::Completed,
                Err(why) => UsedOutcome::Poisoned(why),
            };
        }
        if spins >= budget {
            return UsedOutcome::Timeout;
        }
        spins += 1;
    }
}

/// Phase 2: drive the claimed virtio-blk — handshake, queue setup
/// (all ring frames mapped through the broker first: the device never
/// sees an unmapped address), a sector read, a write+read-back
/// round trip, then the **enforcement probe**: the data page is
/// unmapped through the broker and a request targeting it must fault
/// (VT-d FSTS.PPF) — ADR-0013's end-to-end security proof. Teardown
/// proves the revoke path with a real device attached.
#[cfg(not(test))]
pub(crate) fn virtio_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::virtio as v;
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv
        .find_by(0x1AF4, 0x01)
        .filter(|d| crate::pci::has_virtio_cap(d))
    else {
        line(out, &["[VBLK] no virtio-blk to drive on this machine"]);
        return;
    };
    // The claim gate ran in pci_step; the verdict must still be live.
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[VBLK] broker verdict flipped absent — refusing to drive"],
        );
        return;
    }
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(dev, off)) else {
        line(out, &["[VBLK] vendor caps incomplete — refusing"]);
        return;
    };
    // F9e claim order: MEMORY-SPACE now (the registers must be
    // reachable for bring-up); BUS-MASTER only AFTER the broker has
    // mapped the rings — a device that can DMA before its mappings
    // exist is exactly what the IOMMU must prevent.
    crate::pci::enable_mem(dev);
    // F5: every device-supplied number is checked before it becomes
    // an address the kernel touches.
    let resolved = match caps.resolve(dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[VBLK] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);

    // ── the modern handshake ──
    mmio.set_status(0);
    let feat_low = mmio.device_features(0);
    let feat_high = mmio.device_features(1);
    // Spec order: ACK|DRIVER first — QEMU errors on feature writes
    // before DRIVER — then negotiate, then FEATURES_OK.
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
    // F6: negotiate device & wanted — refuse devices without
    // VERSION_1 (the layout this driver speaks) or ACCESS_PLATFORM
    // (the IOMMU path the broker design assumes).
    let negotiated = match v::negotiate_features(feat_low, feat_high) {
        Ok(n) => n,
        Err(why) => {
            line(
                out,
                &["[VBLK] feature negotiation refused: ", why, " — refusing"],
            );
            return;
        }
    };
    mmio.set_driver_features(0, negotiated.low);
    mmio.set_driver_features(1, negotiated.high);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
    if mmio.status() & v::STATUS_FEATURES_OK == 0 {
        line(out, &["[VBLK] FEATURES_OK not accepted — refusing"]);
        return;
    }
    let (qsize_raw, notify_off) = mmio.select_queue(0);
    // One frame per ring serves 256 descriptors: shrink if needed.
    let qsize = if qsize_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qsize_raw
    };
    if qsize == 0 || qsize > 2048 {
        let mut nq = [0u8; 20];
        let mut no = [0u8; 20];
        line(
            out,
            &[
                "[VBLK] queue size out of the supported band (size=",
                strutil::dec(u64::from(qsize), &mut nq),
                " notify_off=",
                strutil::dec(u64::from(notify_off), &mut no),
                ") — refusing",
            ],
        );
        return;
    }

    // ── ring frames: pool + broker FIRST, device second ──
    // ADR-0016/F10: the session owns every acquisition from here on —
    // a mid-flight refusal (pool OR broker) still closes on return;
    // the stranded-frame/region class is gone by construction.
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        VBLK_OWNER,
        dev.dom,
        false,
        "[VBLK] teardown",
        "",
    );
    let mut frames = [0u64; 5];
    for (i, slot) in frames.iter_mut().enumerate() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                let mut b = [0u8; 20];
                line(
                    out,
                    &[
                        "[VBLK] pool exhausted at frame ",
                        strutil::dec(i as u64, &mut b),
                        " — refusing",
                    ],
                );
                return;
            }
        }
    }
    let [desc_pa, avail_pa, used_pa, ctrl_pa, data_pa] = frames;
    let mut cookies = [0u64; 5];
    for (i, &pa) in frames.iter().enumerate() {
        match session.map(pa) {
            Some(cookie) => cookies[i] = cookie,
            None => {
                let mut b = [0u8; 20];
                line(
                    out,
                    &[
                        "[VBLK] broker refused ring frame ",
                        strutil::dec(i as u64, &mut b),
                        " — refusing (the device gets no addresses)",
                    ],
                );
                return;
            }
        }
    }
    let mut n = [0u8; 20];
    line(
        out,
        &[
            "[VBLK] queue rings mapped via broker (desc/avail/used/ctrl/data: ",
            strutil::dec(5, &mut n),
            " regions, IOMMU-enforced)",
        ],
    );
    // F9e: rings mapped through the broker — NOW the device may DMA.
    crate::pci::enable_bus_master(dev);
    mmio.setup_queue(desc_pa, avail_pa, used_pa);
    mmio.set_status(v::live_status());
    let status = mmio.status();
    if status != v::live_status() {
        line(out, &["[VBLK] DRIVER_OK path failed — refusing"]);
        return;
    }
    let capacity = mmio.capacity_sectors();
    let mut nc = [0u8; 20];
    line(
        out,
        &[
            "[VBLK] alive: status=0x0f qsize=",
            strutil::dec(u64::from(qsize), &mut n),
            " capacity=",
            strutil::dec(capacity, &mut nc),
            " sectors",
        ],
    );
    let _ = (feat_low, feat_high);

    // The live queue for the submit/poll helpers (plain data — no
    // statics anywhere in this driver).
    let queue = VblkQueue {
        qsize,
        notify_off,
        desc_pa,
        avail_pa,
        used_pa,
        ctrl_pa,
        cookies: [cookies[0], cookies[1], cookies[2], cookies[3]],
    };

    // ── read sector 0 (device WRITES the data page through the IOMMU) ──
    let want = submit(&queue, data_pa, 0, v::BLK_T_IN);
    if !mmio.notify(0, notify_off) {
        line(
            out,
            &["[VBLK] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    match poll_used(&queue, want) {
        UsedOutcome::Timeout => {
            line(
                out,
                &["[VBLK] read sector 0: DID NOT COMPLETE — refusing to continue"],
            );
            return;
        }
        UsedOutcome::Poisoned(why) => {
            line(out, &["[VBLK] used-ring POISON: ", why, " — refusing"]);
            return;
        }
        UsedOutcome::Completed => {}
    }
    let st = v::read_u8_pa(ctrl_pa + 512);
    let data0 = crate::memops::read_u64(data_pa);
    let mut h = [0u8; 18];
    line(
        out,
        &[
            "[VBLK] read sector 0: complete, status=OK, data[0..8]=",
            strutil::hex(data0, &mut h),
            " (DMA landed through the IOMMU)",
        ],
    );
    if st != v::BLK_S_OK {
        line(
            out,
            &["[VBLK] status byte is not OK — refusing to continue"],
        );
        return;
    }

    // ── write + read-back round trip (device READS the data page too) ──
    crate::memops::write_u64(data_pa, 0x0BAD_C0DE_0BAD_C0DE);
    let want = submit(&queue, data_pa, 0, v::BLK_T_OUT);
    if !mmio.notify(0, notify_off) {
        line(
            out,
            &["[VBLK] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    match poll_used(&queue, want) {
        UsedOutcome::Timeout => {
            line(
                out,
                &["[VBLK] write: DID NOT COMPLETE — refusing to continue"],
            );
            return;
        }
        UsedOutcome::Poisoned(why) => {
            line(out, &["[VBLK] used-ring POISON: ", why, " — refusing"]);
            return;
        }
        UsedOutcome::Completed => {}
    }
    // Scrub the page (the broker discipline: the device's copy dies
    // with the region), then read the sector back fresh.
    crate::memops::scrub_frame(data_pa);
    let want = submit(&queue, data_pa, 0, v::BLK_T_IN);
    if !mmio.notify(0, notify_off) {
        line(
            out,
            &["[VBLK] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    match poll_used(&queue, want) {
        UsedOutcome::Timeout => {
            line(
                out,
                &["[VBLK] read-back: DID NOT COMPLETE — refusing to continue"],
            );
            return;
        }
        UsedOutcome::Poisoned(why) => {
            line(out, &["[VBLK] used-ring POISON: ", why, " — refusing"]);
            return;
        }
        UsedOutcome::Completed => {}
    }
    let back = crate::memops::read_u64(data_pa);
    if back == 0x0BAD_C0DE_0BAD_C0DE {
        line(
            out,
            &["[VBLK] write+read-back: pattern survived the round trip (device read+write through the IOMMU)"],
        );
    } else {
        let mut h2 = [0u8; 18];
        line(
            out,
            &[
                "[VBLK] write+read-back MISMATCH: wrote 0x0badc0de0badc0de, read ",
                strutil::hex(back, &mut h2),
            ],
        );
        return;
    }

    // ── THE ENFORCEMENT PROBE (ADR-0013's payoff; ADR-0014 makes it
    // honest — under the old TT=0b10 this request COMPLETED with
    // status=0 and PPF never set, because the device was in
    // pass-through and never walked the tables) ──
    // Complete the data region and unmap it through the broker (the
    // full abort handshake — the honest path), return the frame, then
    // ask the device to DMA into the now-unmapped page. Proof = the
    // SLPTE reads back absent (P=0) AND FSTS.PPF sets: the IOMMU
    // faulted the access to a page the broker unmapped.
    session
        .complete_unmap(cookies[4])
        .expect("data region live + abort handshake done");
    session.hand_back(data_pa);
    // The tables' own verdict, read back from the walk the device must
    // now take: the SLPTE for the dead page must be absent (P=0).
    let slpt_root = session.with_prot(|p| p.dom_slpt(0));
    let pte_absent = match slpt_root {
        Some(root) => session.with_prot(|p| p.slpte_of(root, data_pa).is_none()),
        None => false, // no SLPT root: the proof cannot even be attempted
    };
    let want = submit(&queue, data_pa, 0, v::BLK_T_IN); // the dead page
    if !mmio.notify(0, notify_off) {
        // No request reached the device — the probe can claim
        // nothing (the IOMMU was never asked).
        line(
            out,
            &["[VBLK] enforcement: notify refused (outside the notify region) — INVESTIGATE (F5)"],
        );
        return;
    }
    let completed = poll_used(&queue, want);
    let fsts = session.with_prot(|p| p.fsts());
    let ppf = fsts & crate::arch::vtd::FSTS_PPF != 0;
    let mut hf = [0u8; 18];
    line(
        out,
        &[
            "[VBLK] enforcement: slpte ",
            if slpt_root.is_none() {
                "NO SLPT ROOT — INVESTIGATE"
            } else if pte_absent {
                "P=0 after unmap (the table no longer names the page)"
            } else {
                "STILL PRESENT after unmap — INVESTIGATE"
            },
            ", fsts=",
            strutil::hex(u64::from(fsts), &mut hf),
        ],
    );
    match (completed, ppf) {
        (UsedOutcome::Timeout, true) => {
            line(
                out,
                &["[VBLK] enforcement: PPF=yes — the request to the unmapped page did NOT complete; the IOMMU faulted the access (ADR-0013 D1/D6 proven)"],
            );
        }
        (UsedOutcome::Completed, true) => {
            let st = v::read_u8_pa(ctrl_pa + 512);
            let mut ns = [0u8; 20];
            line(
                out,
                &[
                    "[VBLK] enforcement: PPF=yes — the IOMMU faulted the access (request completed with device-side error status=",
                    strutil::dec(u64::from(st), &mut ns),
                    ")",
                ],
            );
        }
        (UsedOutcome::Poisoned(why), _) => {
            // The device wrote a hostile completion against an
            // unmapped page: report the poison, the PPF line above
            // still carries the IOMMU's own verdict.
            line(out, &["[VBLK] enforcement: used-ring POISON: ", why]);
        }
        (_, false) => {
            // The device reached (or stalled on) a page the broker
            // unmapped with no recorded IOMMU fault: the isolation
            // property is ABSENT on this boot. Say so loudly.
            line(
                out,
                &["[VBLK] enforcement: ENFORCEMENT FAILURE — PPF=no (no IOMMU fault for the unmapped page; see ADR-0014)"],
            );
        }
    }

    // ── teardown: revoke the rest with the device still attached ──
    session.close(out);
}

// ── Phase 2: the virtio-net driver — same transport, two queues,
// and a real DHCP round trip through slirp ──

#[cfg(test)]
mod tests {
    use super::*;

    /// The 3-descriptor request chain, pinned: header (device reads),
    /// data (device writes for IN), status (device writes) — plus the
    /// avail-ring publish and its modulo advance.
    #[test]
    fn submit_builds_the_three_descriptor_chain() {
        use crate::virtio as v;
        let phys = crate::drvstack::testharness::FakePhys::new(5);
        let desc = phys.pa(0);
        let avail = phys.pa(4096);
        let ctrl = phys.pa(8192);
        let data = phys.pa(12288);
        let q = VblkQueue {
            qsize: 8,
            notify_off: 0,
            desc_pa: desc,
            avail_pa: avail,
            used_pa: phys.pa(16384),
            ctrl_pa: ctrl,
            cookies: [0; 4],
        };
        let wrote = submit(&q, data, 4, v::BLK_T_IN);
        // desc 0: the 16-byte header, NEXT, next=1
        assert_eq!(crate::memops::read_u64(desc), ctrl);
        assert_eq!(crate::virtio::read_u16_pa(desc + 8), 16);
        assert_eq!(
            u16::from(crate::virtio::read_u8_pa(desc + 12)),
            u16::from(v::DESC_F_NEXT)
        );
        assert_eq!(crate::virtio::read_u8_pa(desc + 14), 1);
        // desc 1: the 512-byte data page, NEXT|WRITE for IN, next=2
        assert_eq!(crate::memops::read_u64(desc + 16), data);
        assert_eq!(crate::virtio::read_u16_pa(desc + 16 + 8), 512);
        assert_eq!(
            u16::from(crate::virtio::read_u8_pa(desc + 16 + 12)),
            u16::from(v::DESC_F_NEXT) | u16::from(v::DESC_F_WRITE)
        );
        assert_eq!(crate::virtio::read_u8_pa(desc + 16 + 14), 2);
        // desc 2: the status byte, WRITE, last
        assert_eq!(crate::memops::read_u64(desc + 32), ctrl + 512);
        assert_eq!(crate::virtio::read_u16_pa(desc + 32 + 8), 1);
        assert_eq!(
            u16::from(crate::virtio::read_u8_pa(desc + 32 + 12)),
            u16::from(v::DESC_F_WRITE)
        );
        assert_eq!(crate::virtio::read_u8_pa(desc + 32 + 14), 0);
        // the avail ring: slot 0 holds desc 0, idx advanced
        assert_eq!(crate::virtio::read_u16_pa(avail + 4), 0);
        assert_eq!(crate::virtio::read_u16_pa(avail + 2), wrote);
        // OUT flips the data descriptor's WRITE bit off
        let _ = submit(&q, data, 4, 1 /* OUT */);
        assert_eq!(
            u16::from(crate::virtio::read_u8_pa(desc + 16 + 12)),
            u16::from(v::DESC_F_NEXT),
            "OUT: the device reads the data page"
        );
    }

    /// The avail index wraps modulo the queue size.
    #[test]
    fn submit_wraps_the_avail_index() {
        use crate::virtio as v;
        let phys = crate::drvstack::testharness::FakePhys::new(5);
        let q = VblkQueue {
            qsize: 2,
            notify_off: 0,
            desc_pa: phys.pa(0),
            avail_pa: phys.pa(4096),
            used_pa: phys.pa(8192),
            ctrl_pa: phys.pa(12288),
            cookies: [0; 4],
        };
        // idx at qsize-1: the SLOT index wraps modulo qsize (the
        // avail idx itself is free-running per the spec)
        v::write_u16_pa(phys.pa(4096) + 2, 1);
        let idx = submit(&q, phys.pa(16384), 0, v::BLK_T_IN);
        assert_eq!(idx, 2, "the avail idx is free-running (1 + 1)");
        // the slot write went to slot 1 % 2 = 1: avail[1] holds desc 0
        assert_eq!(crate::virtio::read_u16_pa(phys.pa(4096) + 4 + 2 * 1), 0);
    }
}
