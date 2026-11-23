//! virtio-balloon (the virtio row's memory device): a REAL one-page
//! inflate/deflate cycle through the broker — a frame the pool owns
//! is offered to the device by its PFN (the host drops its backing,
//! the completion lands on the used ring), the driver then writes
//! the config's `actual` count (the guest's own report of the
//! balloon size), and the SAME page is deflated back and returned to
//! the pool. Device ids: modern 0x1045, legacy 0x1005.
//!
//! Config layout (virtio-balloon spec — and QEMU 10's own
//! `virtio_balloon_set_config`, read off the wire in the K13
//! forensics): num_pages u32 LE at +0 (the guest's TARGET — host
//! tools set it via QMP; no QEMU device path reads the guest's
//! copy), actual u32 LE at +4 (the balloon size — QEMU READS this
//! field on every config write, meaning it is THE GUEST'S to keep
//! current; no device path ever advances it). The queues: 0 =
//! inflate, 1 = deflate (the stats vq is not negotiated in this
//! slice). Both queues carry device-READABLE pages: the guest offers
//! a PFN LIST (u32 LE each — one 4-byte entry per ballooned page),
//! the host manipulates those pages' backing.
//!
//! The safety rule that makes this CI-safe: exactly ONE page, freshly
//! allocated from the frame pool (scrubbed, unowned by anything
//! else), deflated and freed before the step returns. A balloon that
//! forgets to deflate leaks one frame to the M1 zero-leak accounting
//! — which is exactly the loud accounting this kernel runs.

// Host-test builds compile this module without its boot-only step
// (it needs `hw`); the device-id table and the config math are the
// pure parts.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for virtio-balloon frames (two ring sets + the
/// offered page).
pub const VBAL_OWNER: u32 = 80;

/// The virtio balloon's PCI device ids: modern 0x1045 (0x1040 + 5),
/// legacy 0x1005.
pub const VIRTIO_BALLOON_MODERN: u16 = 0x1045;
pub const VIRTIO_BALLOON_LEGACY: u16 = 0x1005;

/// Config offset: num_pages (u32 LE) — the guest's target.
pub const CFG_NUM_PAGES: u64 = 0;
/// Config offset: actual (u32 LE) — the guest's own report of the
/// balloon size. QEMU's set_config READS this field (the K13
/// forensics: `virtio_balloon_set_config actual: 0 oldactual: 0` on
/// every config write); no device path ever writes it — keeping
/// `actual` current is the DRIVER's job, one write per completion.
pub const CFG_ACTUAL: u64 = 4;

/// Does this device id name the virtio balloon?
#[must_use]
pub const fn is_virtio_balloon(device_id: u16) -> bool {
    device_id == VIRTIO_BALLOON_MODERN || device_id == VIRTIO_BALLOON_LEGACY
}

/// The new num_pages target for a one-page inflate of `actual`:
/// checked (a target that overflows u32 refuses — the config write
/// would wrap and the device would see nonsense).
#[must_use]
pub fn inflate_target(actual: u32, pages: u32) -> Option<u32> {
    actual.checked_add(pages)
}

/// The deflate target: the original count.
#[must_use]
pub fn deflate_target(actual_before_inflate: u32) -> u32 {
    actual_before_inflate
}

/// The balloon step: handshake, queues, read the config, inflate ONE
/// freshly-allocated page, watch `actual` advance, deflate it back,
/// free the page. Every refusal is a marker; the session's close
/// returns everything the step acquired.
#[cfg(not(test))]
pub(crate) fn balloon_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::virtio as v;
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.devices[..inv.count]
        .iter()
        .find(|d| d.vendor == 0x1AF4 && is_virtio_balloon(d.device))
        .copied()
    else {
        line(out, &["[VBAL] no virtio-balloon on this machine — skipped"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[VBAL] broker verdict absent — refusing to drive"]);
        return;
    }
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(&dev, off)) else {
        line(out, &["[VBAL] vendor caps incomplete — refusing"]);
        return;
    };
    crate::pci::enable_mem(&dev);
    let resolved = match caps.resolve(&dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[VBAL] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);

    // Handshake — WITHOUT any stats-vq feature: this slice drives the
    // two page queues only.
    mmio.set_status(0);
    let feat_low = mmio.device_features(0);
    let feat_high = mmio.device_features(1);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
    let negotiated = match v::negotiate_features(feat_low, feat_high) {
        Ok(n) => n,
        Err(why) => {
            line(
                out,
                &["[VBAL] feature negotiation refused: ", why, " — refusing"],
            );
            return;
        }
    };
    mmio.set_driver_features(0, negotiated.low);
    mmio.set_driver_features(1, negotiated.high);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
    if mmio.status() & v::STATUS_FEATURES_OK == 0 {
        line(out, &["[VBAL] FEATURES_OK not accepted — refusing"]);
        return;
    }

    // Frames: the inflate rings, the deflate rings, and the offered
    // page itself.
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(&dev),
        VBAL_OWNER,
        dev.dom,
        false,
        "[VBAL] teardown",
        "",
    );
    let mut frames = [0u64; 7];
    for (i, slot) in frames.iter_mut().enumerate() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                let mut fb = [0u8; 20];
                line(
                    out,
                    &[
                        "[VBAL] pool exhausted at frame ",
                        strutil::dec(i as u64, &mut fb),
                        " — refusing",
                    ],
                );
                return;
            }
        }
    }
    let [i_desc, i_avail, i_used, d_desc, d_avail, d_used, page] = frames;
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(
                out,
                &["[VBAL] broker refused a ring frame — refusing (the device gets no addresses)"],
            );
            return;
        }
    }
    crate::pci::enable_bus_master(&dev);

    // Queue 0 (inflate), then queue 1 (deflate) — setup_queue binds
    // the addresses to the QUEUE_SEL-selected queue, so select first.
    let (qs_raw, i_notify) = mmio.select_queue(0);
    let i_qsize = if qs_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qs_raw
    };
    if i_qsize == 0 || i_qsize > 2048 {
        line(out, &["[VBAL] inflate queue size out of band — refusing"]);
        return;
    }
    mmio.setup_queue(i_desc, i_avail, i_used);
    let (qs_raw2, d_notify) = mmio.select_queue(1);
    let d_qsize = if qs_raw2 > 256 {
        mmio.set_queue_size(256)
    } else {
        qs_raw2
    };
    if d_qsize == 0 || d_qsize > 2048 {
        line(out, &["[VBAL] deflate queue size out of band — refusing"]);
        return;
    }
    mmio.setup_queue(d_desc, d_avail, d_used);
    mmio.set_status(v::live_status());
    if mmio.status() != v::live_status() {
        line(out, &["[VBAL] DRIVER_OK path failed — refusing"]);
        return;
    }

    // The config: num_pages/actual before any ballooning — the
    // DEVICE-specific region (memops on the resolved device-config
    // base, the same access pattern as vblk's capacity read).
    let dcfg = mmio.device_cfg_pa();
    let num_pages = crate::memops::read_u32(dcfg + CFG_NUM_PAGES);
    let actual0 = crate::memops::read_u32(dcfg + CFG_ACTUAL);
    let mut a = [0u8; 20];
    let mut b = [0u8; 20];
    line(
        out,
        &[
            "[VBAL] virtio-balloon alive: config num_pages=",
            strutil::dec(u64::from(num_pages), &mut a),
            " actual=",
            strutil::dec(u64::from(actual0), &mut b),
            " (4 KiB pages)",
        ],
    );

    // ── the one-page inflate ──
    // The offered page: a fresh pool frame, mapped for the device,
    // device-READABLE (the host takes its backing away — the guest
    // must not touch it until deflated). The buffer is a PFN LIST:
    // ONE u32 LE entry — the page's own PFN — and the descriptor's
    // length is 4, the list's byte size. (The K13 forensics caught
    // this frame's first draft: a 4096-byte descriptor over the
    // scrubbed frame offered 1024 ZERO PFNs — QEMU's handle_output
    // dutifully processed the zeros while the trace showed the real
    // gpa's backing gone and `actual` never moving.)
    crate::memops::write_u32(page, (page >> 12) as u32);
    v::write_desc(i_desc, page, 4, 0, 0);
    let avail_idx = v::read_u16_pa(i_avail + 2);
    v::write_u16_pa(v::avail_slot_addr(i_avail, avail_idx % i_qsize), 0);
    v::write_u16_pa(i_avail + 2, avail_idx.wrapping_add(1));
    if !mmio.notify(0, i_notify) {
        line(
            out,
            &["[VBAL] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    // The new target: actual + 1 page (checked). num_pages is the
    // guest's TARGET field — written for the config's honesty, and
    // read by host-side tooling (QMP); no QEMU device path reads the
    // guest's copy.
    let Some(target) = inflate_target(actual0, 1) else {
        line(
            out,
            &["[VBAL] the +1-page target would overflow — refusing"],
        );
        return;
    };
    crate::memops::write_u32(dcfg + CFG_NUM_PAGES, target);
    // Bounded wait: the COMPLETION on the inflate queue's used ring.
    // `actual` is not part of the wait — the device never advances it
    // (QEMU's set_config only READS the field); the DRIVER writes it
    // below, once the completion lands.
    let want = avail_idx.wrapping_add(1);
    let budget = 20_000_000u64;
    let mut spins = 0u64;
    while v::used_idx(i_used) != want && spins < budget {
        spins += 1;
    }
    let inflated = v::used_idx(i_used) == want;
    if inflated {
        crate::memops::write_u32(dcfg + CFG_ACTUAL, target);
    }

    // ── the deflate: the SAME page on queue 1, the target back to
    // the original count — the host restores the page's backing and
    // the completion lands on the deflate queue's used ring; the
    // driver then writes `actual` home.
    v::write_desc(d_desc, page, 4, 0, 0);
    let d_idx = v::read_u16_pa(d_avail + 2);
    v::write_u16_pa(v::avail_slot_addr(d_avail, d_idx % d_qsize), 0);
    v::write_u16_pa(d_avail + 2, d_idx.wrapping_add(1));
    if !mmio.notify(1, d_notify) {
        line(
            out,
            &["[VBAL] deflate notify refused — the page returns via the session close"],
        );
        return;
    }
    crate::memops::write_u32(dcfg + CFG_NUM_PAGES, deflate_target(actual0));
    let d_want = d_idx.wrapping_add(1);
    let mut spins2 = 0u64;
    while v::used_idx(d_used) != d_want && spins2 < budget {
        spins2 += 1;
    }
    let deflated = v::used_idx(d_used) == d_want;
    if deflated {
        crate::memops::write_u32(dcfg + CFG_ACTUAL, actual0);
    }

    let mut c1 = [0u8; 20];
    let mut c2 = [0u8; 20];
    line(
        out,
        &[
            "[VBAL] cycle done: inflated=",
            if inflated { "yes" } else { "NO (budget)" },
            " deflated=",
            if deflated { "yes" } else { "NO (budget)" },
            " actual=",
            strutil::dec(
                u64::from(crate::memops::read_u32(dcfg + CFG_ACTUAL)),
                &mut c1,
            ),
            " (started ",
            strutil::dec(u64::from(actual0), &mut c2),
            ") — the page returns to the pool",
        ],
    );
    session.close(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_balloon_device_ids_are_pinned() {
        assert_eq!(VIRTIO_BALLOON_MODERN, 0x1045);
        assert_eq!(VIRTIO_BALLOON_LEGACY, 0x1005);
        assert!(is_virtio_balloon(VIRTIO_BALLOON_MODERN));
        assert!(is_virtio_balloon(VIRTIO_BALLOON_LEGACY));
        // The neighbors are NOT it.
        assert!(!is_virtio_balloon(0x1043));
        assert!(!is_virtio_balloon(0x1044));
        assert!(!is_virtio_balloon(0x1004));
        // Config offsets.
        assert_eq!(CFG_NUM_PAGES, 0);
        assert_eq!(CFG_ACTUAL, 4);
    }

    #[test]
    fn the_target_math_is_checked() {
        assert_eq!(inflate_target(0, 1), Some(1));
        assert_eq!(inflate_target(32768, 1), Some(32769));
        // A u32 overflow refuses instead of wrapping.
        assert_eq!(inflate_target(u32::MAX, 1), None);
        assert_eq!(inflate_target(u32::MAX - 1, 2), None);
        // The deflate target is the remembered original.
        assert_eq!(deflate_target(32768), 32768);
    }
}
