//! virtio-console (the virtio row's next device): port 0's transmit
//! queue driven end to end — the guest's bytes land in the HOST's
//! chardev file, and the lane greps BOTH sides (the guest marker and
//! the host file). Device ids: modern 0x1043, legacy 0x1003.
//!
//! The wire format (virtio-serial spec): every guest→host buffer is
//! [4-byte port id (LE)][payload]; port 0 is the console. The proof
//! string rides a two-descriptor chain (header + data), published on
//! the port's TRANSMIT queue (queue index 1), kicked, and its
//! completion validated against the submission (F7).

// Host-test builds compile this module without its boot-only step
// (it needs `hw`); the device-id table is the pure part.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for virtio-console frames (two ring sets + the
/// header/data page).
pub const VCON_OWNER: u32 = 79;

/// The virtio console's PCI device ids: modern 0x1043 (0x1040 + 3),
/// legacy 0x1003.
pub const VIRTIO_CONSOLE_MODERN: u16 = 0x1043;
pub const VIRTIO_CONSOLE_LEGACY: u16 = 0x1003;

/// Does this device id name the virtio console?
#[must_use]
pub const fn is_virtio_console(device_id: u16) -> bool {
    device_id == VIRTIO_CONSOLE_MODERN || device_id == VIRTIO_CONSOLE_LEGACY
}

/// The proof string the lane greps in the HOST file.
pub const PROOF: &[u8] = b"AEGIS-VIRTIO-CONSOLE-ROUNDTRIP\n";

/// The console step: negotiate, set up port 0's transmit queue, send
/// the proof string, validate the completion. The host-side grep of
/// the chardev file is the lane's job (boot.sh) — the guest's marker
/// is only half the round trip, stated as such.
#[cfg(not(test))]
pub(crate) fn console_step<const N: usize>(
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
        .find(|d| d.vendor == 0x1AF4 && is_virtio_console(d.device))
        .copied()
    else {
        line(out, &["[VCON] no virtio-console on this machine — skipped"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[VCON] broker verdict absent — refusing to drive"]);
        return;
    }
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(&dev, off)) else {
        line(out, &["[VCON] vendor caps incomplete — refusing"]);
        return;
    };
    crate::pci::enable_mem(&dev);
    let resolved = match caps.resolve(&dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[VCON] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);

    // The modern handshake (the same one every virtio driver here
    // speaks).
    mmio.set_status(0);
    let feat_low = mmio.device_features(0);
    let feat_high = mmio.device_features(1);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
    let negotiated = match v::negotiate_features(feat_low, feat_high) {
        Ok(n) => n,
        Err(why) => {
            line(
                out,
                &["[VCON] feature negotiation refused: ", why, " — refusing"],
            );
            return;
        }
    };
    mmio.set_driver_features(0, negotiated.low);
    mmio.set_driver_features(1, negotiated.high);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
    if mmio.status() & v::STATUS_FEATURES_OK == 0 {
        line(out, &["[VCON] FEATURES_OK not accepted — refusing"]);
        return;
    }
    // Port 0's queues: index 0 = receive (host→guest), index 1 =
    // transmit (guest→host). This slice drives ONLY the transmit side
    // — the receive side is the input-domain slice.
    let (qs_raw, notify_off) = mmio.select_queue(1);
    let qsize = if qs_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qs_raw
    };
    if qsize == 0 || qsize > 2048 {
        line(
            out,
            &["[VCON] queue size out of the supported band — refusing"],
        );
        return;
    }

    // Frames: the tx rings + the header/data page, through the
    // session (F10: a mid-flight refusal still closes on return).
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(&dev),
        VCON_OWNER,
        dev.dom,
        false,
        "[VCON] teardown",
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
                        "[VCON] pool exhausted at frame ",
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
                &["[VCON] broker refused a ring frame — refusing (the device gets no addresses)"],
            );
            return;
        }
    }
    crate::pci::enable_bus_master(&dev);
    mmio.setup_queue(desc_pa, avail_pa, used_pa);
    mmio.set_status(v::live_status());
    if mmio.status() != v::live_status() {
        line(out, &["[VCON] DRIVER_OK path failed — refusing"]);
        return;
    }
    let mut qb = [0u8; 20];
    line(
        out,
        &[
            "[VCON] virtio-console alive: tx qsize=",
            strutil::dec(u64::from(qsize), &mut qb),
            " (port 0)",
        ],
    );

    // The transmit buffer: [port id 0 (4 bytes)][proof string] as a
    // two-descriptor chain — header first, payload second, both
    // device-readable (no DESC_F_WRITE: the device READS guest
    // memory on transmit).
    v::write_u32_pa(data_pa, 0); // the port-id header
    for (i, &b) in PROOF.iter().enumerate() {
        crate::virtio::write_u8_pa(data_pa + 4 + i as u64, b);
    }
    // Round I: the header descriptor needs DESC_F_NEXT — without the
    // flag the next-index field is ignored, the device treats the
    // 4-byte header as the whole request, and the host file received
    // exactly those 4 bytes (the observed failure: console.out held
    // the header alone, the payload never left the machine).
    v::write_desc(desc_pa, data_pa, 4, v::DESC_F_NEXT, 1); // header, chained
    v::write_desc(desc_pa + 16, data_pa + 4, PROOF.len() as u32, 0, 0); // payload, last
    let avail_idx = v::read_u16_pa(avail_pa + 2);
    v::write_u16_pa(v::avail_slot_addr(avail_pa, avail_idx % qsize), 0);
    v::write_u16_pa(avail_pa + 2, avail_idx.wrapping_add(1));
    if !mmio.notify(1, notify_off) {
        line(
            out,
            &["[VCON] notify slot outside the notify region — refusing (F5)"],
        );
        return;
    }
    // Bounded poll + F7 validation: the completion's length must be
    // the whole chain (the device consumed header + payload).
    let want = avail_idx.wrapping_add(1);
    let budget = 20_000_000u64;
    let mut spins = 0u64;
    let entry_used = v::used_idx(used_pa);
    loop {
        let used = v::used_idx(used_pa);
        if used.wrapping_sub(entry_used) > qsize || used > want {
            line(out, &["[VCON] used-ring POISON — refusing"]);
            return;
        }
        if used == want {
            break;
        }
        if spins >= budget {
            line(
                out,
                &["[VCON] transmit DID NOT COMPLETE (budget) — refusing"],
            );
            return;
        }
        spins += 1;
    }
    let slot = want.wrapping_sub(1) % qsize;
    let chain_len = 4 + PROOF.len() as u32;
    if let Err(why) = v::validate_used(used_pa, slot, qsize, 0, chain_len) {
        line(
            out,
            &["[VCON] used-ring validation refused: ", why, " — refusing"],
        );
        return;
    }
    let mut nb = [0u8; 20];
    line(
        out,
        &[
            "[VCON] TX complete: ",
            strutil::dec(u64::from(chain_len), &mut nb),
            " bytes (header+payload) — the HOST file holds the other half of the round trip",
        ],
    );

    session.close(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_device_ids_are_pinned() {
        // Modern: 0x1040 + virtio device id 3.
        assert_eq!(VIRTIO_CONSOLE_MODERN, 0x1043);
        assert_eq!(VIRTIO_CONSOLE_LEGACY, 0x1003);
        assert!(is_virtio_console(VIRTIO_CONSOLE_MODERN));
        assert!(is_virtio_console(VIRTIO_CONSOLE_LEGACY));
        // The neighbors are NOT it (net 0x1041, blk 0x1042, rng
        // 0x1044, balloon 0x1045).
        assert!(!is_virtio_console(0x1041));
        assert!(!is_virtio_console(0x1042));
        assert!(!is_virtio_console(0x1044));
        assert!(!is_virtio_console(0x1045));
    }

    #[test]
    fn the_proof_string_is_the_lane_contract() {
        // The lane greps this exact string in the HOST-side chardev
        // file — changing it is a two-sided change (here + boot.sh).
        assert_eq!(PROOF, b"AEGIS-VIRTIO-CONSOLE-ROUNDTRIP\n");
        assert_eq!(PROOF.len(), 31);
    }
}
