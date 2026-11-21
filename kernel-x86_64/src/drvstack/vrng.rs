//! virtio-rng (ADR-free platform slice, the entropy source's device
//! half): the same modern handshake vblk speaks, one WRITE
//! descriptor, the device fills it with entropy, the pool eats it.
//! The CPU half (RDRAND/RDSEED probes) runs first — machine
//! sources before bus sources, and the machine half needs no device
//! at all.

// Host-test builds compile this module without its boot-only step
// (it needs `hw`); the device-id table is the pure part.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for virtio-rng frames (desc/avail/used rings +
/// the entropy page).
pub const VRNG_OWNER: u32 = 78;

/// The virtio entropy source's PCI device ids: modern 0x1044
/// (0x1040 + virtio device id 4), legacy 0x1004.
pub const VIRTIO_RNG_MODERN: u16 = 0x1044;
pub const VIRTIO_RNG_LEGACY: u16 = 0x1004;

/// Does this device id name the virtio entropy source?
#[must_use]
pub const fn is_virtio_rng(device_id: u16) -> bool {
    device_id == VIRTIO_RNG_MODERN || device_id == VIRTIO_RNG_LEGACY
}

/// The entropy step: CPU sources first (RDRAND/RDSEED, CPUID-gated,
/// bounded retries — a refusing instruction is counted, not trusted),
/// then the device source through the broker. Markers report what
/// each half actually did; nothing is claimed that did not happen.
#[cfg(not(test))]
pub(crate) fn rng_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::rng;
    use crate::virtio as v;
    use aegis_os::dma::DmaVerdict;

    // ── the CPU half ──
    let ecx = crate::hw::cpuid1_ecx();
    let has_rdrand = crate::arch::features::has_rdrand(ecx);
    let mut ok = 0u64;
    if has_rdrand {
        // Ten bounded attempts: the instruction CAN refuse
        // (undersubscribed entropy is a documented state); refusals
        // are counted, samples are mixed.
        for _ in 0..10 {
            if let Some(sample) = crate::hw::rdrand64() {
                rng::BOOT_POOL.mix(sample);
                ok += 1;
            }
        }
    }
    let mut b = [0u8; 20];
    line(
        out,
        &[
            "[RNG ] rdrand: ",
            if has_rdrand {
                ""
            } else {
                "absent (CPUID.01H:ECX bit 30 clear)"
            },
            if has_rdrand {
                strutil::dec(ok, &mut b)
            } else {
                ""
            },
            if has_rdrand { "/10 samples mixed" } else { "" },
        ],
    );
    // RDSEED (leaf 7): preferred when present, one attempt each of a
    // bounded pair.
    let has_rdseed = crate::arch::features::has_rdseed(crate::hw::cpuid7_ebx());
    if has_rdseed {
        let mut seed_ok = 0u64;
        for _ in 0..2 {
            if let Some(sample) = crate::hw::rdseed64() {
                rng::BOOT_POOL.mix(sample);
                seed_ok += 1;
            }
        }
        let mut sb = [0u8; 20];
        line(
            out,
            &[
                "[RNG ] rdseed: ",
                strutil::dec(seed_ok, &mut sb),
                "/2 samples mixed",
            ],
        );
    } else {
        line(out, &["[RNG ] rdseed: absent (CPUID.07H:EBX bit 18 clear)"]);
    }

    // ── the device half ──
    let Some(dev) = inv.devices[..inv.count]
        .iter()
        .find(|d| d.vendor == 0x1AF4 && is_virtio_rng(d.device))
        .copied()
    else {
        line(
            out,
            &["[RNG ] virtio-rng: absent on this machine (CPU sources stand)"],
        );
        rng_summary(out);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[RNG ] broker verdict absent — refusing to drive the device"],
        );
        rng_summary(out);
        return;
    }
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(&dev, off)) else {
        line(out, &["[RNG ] vendor caps incomplete — refusing"]);
        rng_summary(out);
        return;
    };
    crate::pci::enable_mem(&dev);
    let resolved = match caps.resolve(&dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[RNG ] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            rng_summary(out);
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);

    // The same modern handshake vblk speaks.
    mmio.set_status(0);
    let feat_low = mmio.device_features(0);
    let feat_high = mmio.device_features(1);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
    let negotiated = match v::negotiate_features(feat_low, feat_high) {
        Ok(n) => n,
        Err(why) => {
            line(
                out,
                &["[RNG ] feature negotiation refused: ", why, " — refusing"],
            );
            rng_summary(out);
            return;
        }
    };
    mmio.set_driver_features(0, negotiated.low);
    mmio.set_driver_features(1, negotiated.high);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
    if mmio.status() & v::STATUS_FEATURES_OK == 0 {
        line(out, &["[RNG ] FEATURES_OK not accepted — refusing"]);
        rng_summary(out);
        return;
    }
    let (qsize_raw, notify_off) = mmio.select_queue(0);
    let qsize = if qsize_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qsize_raw
    };
    if qsize == 0 || qsize > 2048 {
        line(
            out,
            &["[RNG ] queue size out of the supported band — refusing"],
        );
        rng_summary(out);
        return;
    }

    // Rings + the entropy page through the session (F10: a mid-flight
    // refusal still closes on return).
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(&dev),
        VRNG_OWNER,
        dev.dom,
        false,
        "[RNG ] teardown",
        "",
    );
    let mut frames = [0u64; 4];
    for (i, slot) in frames.iter_mut().enumerate() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                let mut fb = [0u8; 20];
                line(
                    out,
                    &[
                        "[RNG ] pool exhausted at frame ",
                        strutil::dec(i as u64, &mut fb),
                        " — refusing",
                    ],
                );
                return;
            }
        }
    }
    let [desc_pa, avail_pa, used_pa, data_pa] = frames;
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(
                out,
                &["[RNG ] broker refused a ring frame — refusing (the device gets no addresses)"],
            );
            return;
        }
    }
    crate::pci::enable_bus_master(&dev);
    mmio.setup_queue(desc_pa, avail_pa, used_pa);
    mmio.set_status(v::live_status());
    if mmio.status() != v::live_status() {
        line(out, &["[RNG ] DRIVER_OK path failed — refusing"]);
        return;
    }
    let mut qb = [0u8; 20];
    line(
        out,
        &[
            "[RNG ] virtio-rng alive: qsize=",
            strutil::dec(u64::from(qsize), &mut qb),
        ],
    );

    // One WRITE descriptor: the device fills 16 bytes of the entropy
    // page (the whole point of the device).
    v::write_desc(desc_pa, data_pa, 16, v::DESC_F_WRITE, 0);
    let avail_idx = v::read_u16_pa(avail_pa + 2);
    v::write_u16_pa(v::avail_slot_addr(avail_pa, avail_idx % qsize), 0);
    v::write_u16_pa(avail_pa + 2, avail_idx.wrapping_add(1));
    if !mmio.notify(0, notify_off) {
        line(
            out,
            &["[RNG ] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    // Bounded poll (ADR-0013's no-infinite-spin rule).
    let want = avail_idx.wrapping_add(1);
    let budget = 20_000_000u64;
    let mut spins = 0u64;
    let entry_used = v::used_idx(used_pa);
    loop {
        let used = v::used_idx(used_pa);
        if used.wrapping_sub(entry_used) > qsize || used > want {
            line(out, &["[RNG ] used-ring POISON — refusing"]);
            return;
        }
        if used == want {
            break;
        }
        if spins >= budget {
            line(
                out,
                &["[RNG ] entropy request DID NOT COMPLETE (budget) — CPU sources stand"],
            );
            rng_summary(out);
            return;
        }
        spins += 1;
    }
    // F7: validate the completion against the submission.
    let slot = want.wrapping_sub(1) % qsize;
    if let Err(why) = v::validate_used(used_pa, slot, qsize, 0, 16) {
        line(
            out,
            &["[RNG ] used-ring validation refused: ", why, " — refusing"],
        );
        return;
    }
    // Harvest: two words into the pool.
    let w0 = crate::memops::read_u64(data_pa);
    let w1 = crate::memops::read_u64(data_pa + 8);
    rng::BOOT_POOL.mix(w0);
    rng::BOOT_POOL.mix(w1);
    let mut h0 = [0u8; 18];
    let mut h1 = [0u8; 18];
    line(
        out,
        &[
            "[RNG ] virtio-rng: 16 bytes harvested (0x",
            strutil::hex(w0, &mut h0),
            " 0x",
            strutil::hex(w1, &mut h1),
            ") → pool",
        ],
    );

    // Teardown + the summary line (the pool's own counters — the
    // honest health feed).
    session.close(out);
    rng_summary(out);
}

/// The pool summary: mixes, draws, and two live draws printed (the
/// "not constants" proof — a draw of 0 or a repeated draw is a
/// marker-visible fact, not a silent one).
#[cfg(not(test))]
fn rng_summary(out: &mut dyn FnMut(&str)) {
    use crate::rng;
    let d0 = rng::BOOT_POOL.next_u64();
    let d1 = rng::BOOT_POOL.next_u64();
    let (mixes, draws, _) = rng::BOOT_POOL.counters();
    let mut m = [0u8; 20];
    let mut dr = [0u8; 20];
    let mut s0 = [0u8; 18];
    let mut s1 = [0u8; 18];
    line(
        out,
        &[
            "[RNG ] pool: mixes=",
            strutil::dec(mixes, &mut m),
            " draws=",
            strutil::dec(draws, &mut dr),
            " sample=0x",
            strutil::hex(d0, &mut s0),
            " 0x",
            strutil::hex(d1, &mut s1),
            " (mixer: splitmix64 — CSPRNG is the next slice)",
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rng_device_ids_are_pinned() {
        // Modern: 0x1040 + virtio device id 4.
        assert_eq!(VIRTIO_RNG_MODERN, 0x1044);
        // Legacy: 0x1000 + 4.
        assert_eq!(VIRTIO_RNG_LEGACY, 0x1004);
        assert!(is_virtio_rng(VIRTIO_RNG_MODERN));
        assert!(is_virtio_rng(VIRTIO_RNG_LEGACY));
        // The neighbors are NOT it (net 0x1041, blk 0x1042, console
        // 0x1043, balloon 0x1045).
        assert!(!is_virtio_rng(0x1041));
        assert!(!is_virtio_rng(0x1042));
        assert!(!is_virtio_rng(0x1043));
        assert!(!is_virtio_rng(0x1045));
        assert!(!is_virtio_rng(0x1005));
        assert!(!is_virtio_rng(0));
    }
}
