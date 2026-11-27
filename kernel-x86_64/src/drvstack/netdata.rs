//! K20 (P0-2): the live virtio-net session the ring-3 NET_SEND /
//! NET_RECV syscall arms drive.
//!
//! The boot's CPL0 proof (`vnet::net_step`) owns the rings while it
//! runs; the syscall arms run later, in interrupt context on the
//! guarded syscall stack, and can only reach state that lives in a
//! `static`. This module IS that state: the ring addresses, the
//! notify lane and the last-seen used indices, published once by
//! `net_step` (atomics, the `ipc_mmio::REGISTRY` discipline: written
//! once at arm time before the domain can run, read with Acquire on
//! every serve — single CPU, the syscall path cannot interleave with
//! the driver phase) and consumed by `send`/`recv`.
//!
//! The data path is deliberately THIN: the desc arrays, avail rings
//! and frame pages stay exactly where the CPL0 proof broker-mapped
//! them (the IOMMU translations never change). A send rewrites desc
//! 0's length, publishes, kicks the queue's notify slot (the same
//! 2-byte store `MmioVirtio::notify` makes) and waits for the used
//! index to advance; a receive polls the RX used ring, copies out of
//! the proof's RX frame page and re-arms the buffer. No broker calls
//! from the syscall path — the mappings the proof bought are the
//! mappings the data path uses (ADR-0017's cookie-only rule).

use crate::memops;
use crate::virtio as v;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Everything the syscall arms need to drive the live NIC: both
/// rings' physical addresses, the frame pages, the notify lane, and
/// the used-index cursors (u32 halves of the u16 device counters —
/// monotonic, never wrapped in one boot).
struct NetSession {
    /// 0 = absent (arms answer ENODEV), 1 = armed.
    live: AtomicU8,
    // TX (virtqueue 1): desc 0 = the frame chain, one buffer.
    tx_desc: AtomicU64,
    tx_avail: AtomicU64,
    tx_used: AtomicU64,
    tx_buf: AtomicU64,
    tx_qsize: AtomicU32,
    tx_last_used: AtomicU32,
    // RX (virtqueue 0): desc 0 = the receive buffer.
    rx_desc: AtomicU64,
    rx_avail: AtomicU64,
    rx_used: AtomicU64,
    rx_buf: AtomicU64,
    rx_qsize: AtomicU32,
    rx_last_used: AtomicU32,
    // The notify lane: base + off × multiplier, the value written is
    // the queue index (virtio 1.x §4.1.5.2, exactly Linux's kick).
    notify_base: AtomicU64,
    notify_mult: AtomicU64,
    notify_off_rx: AtomicU32,
    notify_off_tx: AtomicU32,
}

static SESSION: NetSession = const {
    NetSession {
        live: AtomicU8::new(0),
        tx_desc: AtomicU64::new(0),
        tx_avail: AtomicU64::new(0),
        tx_used: AtomicU64::new(0),
        tx_buf: AtomicU64::new(0),
        tx_qsize: AtomicU32::new(0),
        tx_last_used: AtomicU32::new(0),
        rx_desc: AtomicU64::new(0),
        rx_avail: AtomicU64::new(0),
        rx_used: AtomicU64::new(0),
        rx_buf: AtomicU64::new(0),
        rx_qsize: AtomicU32::new(0),
        rx_last_used: AtomicU32::new(0),
        notify_base: AtomicU64::new(0),
        notify_mult: AtomicU64::new(0),
        notify_off_rx: AtomicU32::new(0),
        notify_off_tx: AtomicU32::new(0),
    }
};

/// Is a live session armed? (The syscall arms' ENODEV check.)
pub(crate) fn armed() -> bool {
    SESSION.live.load(Ordering::Acquire) == 1
}

/// K20 debug + verification: the first bytes of the LAST received
/// frame, snapshotted by the syscall arm at copy time (the arm-time
/// truth — if the user-page copy later reads differently, the writer
/// is AFTER the copy, not the copy itself). 64 bytes cover the DHCP
/// op (frame+42) and yiaddr (frame+58..62).
static SNAP: [AtomicU8; 64] = [const { AtomicU8::new(0) }; 64];
static SNAP_LEN: AtomicU32 = AtomicU32::new(0);
/// K20 debug: the PA the recv arm's copy actually targeted, and the
/// byte it read back at frame+42 right after the copy.
static SNAP_PA: AtomicU64 = AtomicU64::new(0);
static SNAP_READBACK: AtomicU8 = AtomicU8::new(0);

/// Record the copy target + the post-copy read-back (K20 debug,
/// exonerated in K25: the va read-back and the PA read-back agree —
/// the old "zeroer" was the test's own hex/decimal offset bug).
pub(crate) fn snapshot_target(pa: u64, readback: u8, va_readback: u8) {
    SNAP_PA.store(pa, Ordering::Relaxed);
    SNAP_READBACK.store(readback, Ordering::Relaxed);
    SNAP_VA_READBACK.store(va_readback, Ordering::Relaxed);
}

static SNAP_VA_READBACK: AtomicU8 = AtomicU8::new(0);
pub(crate) fn snap_va_readback() -> u8 {
    SNAP_VA_READBACK.load(Ordering::Relaxed)
}

/// The PA the last copy targeted.
#[cfg(not(test))]
pub(crate) fn snap_pa() -> u64 {
    SNAP_PA.load(Ordering::Relaxed)
}

/// The post-copy read-back of frame+42.
#[cfg(not(test))]
pub(crate) fn snap_readback() -> u8 {
    SNAP_READBACK.load(Ordering::Relaxed)
}

/// Record the arm-time view of a received frame (first 64 bytes).
pub(crate) fn snapshot(frame: &[u8]) {
    let n = frame.len().min(64);
    for (i, b) in frame.iter().take(n).enumerate() {
        SNAP[i].store(*b, Ordering::Relaxed);
    }
    SNAP_LEN.store(n as u32, Ordering::Relaxed);
}

/// The snapshot byte at `off` (None past the snapshotted length).
#[cfg(not(test))]
pub(crate) fn snap_byte(off: usize) -> Option<u8> {
    if off < SNAP_LEN.load(Ordering::Relaxed) as usize {
        Some(SNAP[off].load(Ordering::Relaxed))
    } else {
        None
    }
}

/// Arm the session from `net_step`'s live rings. `last_tx_used` /
/// `last_rx_used` are the used-index cursors AFTER the CPL0 proof
/// completed (its completions are not ours to re-wait for). The
/// virtio-net TX header is written once here — every frame reuses
/// the same header slot (all zeros, no offloads negotiated).
#[allow(clippy::too_many_arguments)]
pub(crate) fn arm(
    tx_desc: u64,
    tx_avail: u64,
    tx_used: u64,
    tx_buf: u64,
    tx_qsize: u16,
    last_tx_used: u16,
    rx_desc: u64,
    rx_avail: u64,
    rx_used: u64,
    rx_buf: u64,
    rx_qsize: u16,
    last_rx_used: u16,
    notify_base: u64,
    notify_mult: u32,
    notify_off_rx: u16,
    notify_off_tx: u16,
) {
    v::write_net_header(tx_buf);
    SESSION.tx_desc.store(tx_desc, Ordering::Relaxed);
    SESSION.tx_avail.store(tx_avail, Ordering::Relaxed);
    SESSION.tx_used.store(tx_used, Ordering::Relaxed);
    SESSION.tx_buf.store(tx_buf, Ordering::Relaxed);
    SESSION
        .tx_qsize
        .store(u32::from(tx_qsize), Ordering::Relaxed);
    SESSION
        .tx_last_used
        .store(u32::from(last_tx_used), Ordering::Relaxed);
    SESSION.rx_desc.store(rx_desc, Ordering::Relaxed);
    SESSION.rx_avail.store(rx_avail, Ordering::Relaxed);
    SESSION.rx_used.store(rx_used, Ordering::Relaxed);
    SESSION.rx_buf.store(rx_buf, Ordering::Relaxed);
    SESSION
        .rx_qsize
        .store(u32::from(rx_qsize), Ordering::Relaxed);
    SESSION
        .rx_last_used
        .store(u32::from(last_rx_used), Ordering::Relaxed);
    SESSION.notify_base.store(notify_base, Ordering::Relaxed);
    SESSION
        .notify_mult
        .store(u64::from(notify_mult), Ordering::Relaxed);
    SESSION
        .notify_off_rx
        .store(u32::from(notify_off_rx), Ordering::Relaxed);
    SESSION
        .notify_off_tx
        .store(u32::from(notify_off_tx), Ordering::Relaxed);
    // The fences around `live` make every field above visible to the
    // syscall path before the arms can observe the session at all.
    SESSION.live.store(1, Ordering::Release);
}

/// Disarm (the teardown half — `net_step` calls this after the ring-3
/// exchange, before the broker session revokes the mappings).
pub(crate) fn disarm() {
    SESSION.live.store(0, Ordering::Release);
}

/// The queue kick: a 2-byte store of the queue INDEX at the queue's
/// own notify slot (base + off × multiplier). EXACTLY what
/// `MmioVirtio::notify` does — the F5 bounds check happened at arm
/// time (`net_step` already used the same lane for the CPL0 proof).
fn kick(queue_index: u16, off: u32) {
    let base = SESSION.notify_base.load(Ordering::Relaxed);
    let mult = SESSION.notify_mult.load(Ordering::Relaxed);
    memops::write_u16(base + u64::from(off) * mult, queue_index);
}

/// Publish head descriptor 0 on a queue's avail ring (the net_publish
/// shape, against the session's own addresses).
fn publish(avail_pa: u64, qsize: u32) {
    let idx = v::read_u16_pa(avail_pa + 2);
    v::write_u16_pa(v::avail_slot_addr(avail_pa, idx % qsize as u16), 0);
    v::write_u16_pa(avail_pa + 2, idx.wrapping_add(1));
}

/// Send one frame (the syscall arm already copied it in and the
/// policy gate already charged the tokens). Publishes desc 0 with
/// the frame's length, kicks, and waits (bounded) for the completion.
/// Returns the byte count accepted, or None when the completion never
/// landed (the honest loud stall — the caller answers EIO).
pub(crate) fn send(frame: &[u8]) -> Option<usize> {
    if !armed() {
        return None;
    }
    let tx_buf = SESSION.tx_buf.load(Ordering::Relaxed);
    let tx_desc = SESSION.tx_desc.load(Ordering::Relaxed);
    // The frame rides BEHIND the 12-byte virtio-net header; the header
    // itself was written once at arm time.
    let p = tx_buf + u64::from(v::NET_HDR_LEN);
    for (i, &b) in frame.iter().enumerate() {
        v::write_u8_pa(p + i as u64, b);
    }
    v::write_desc(tx_desc, tx_buf, v::NET_HDR_LEN + frame.len() as u32, 0, 0);
    publish(
        SESSION.tx_avail.load(Ordering::Relaxed),
        SESSION.tx_qsize.load(Ordering::Relaxed),
    );
    kick(1, SESSION.notify_off_tx.load(Ordering::Relaxed));
    // Bounded completion wait (the CPL0 proof's discipline: two kicks
    // already exist upstream; here ONE wait, and a stall is a loud
    // None, never a hang).
    let tx_used = SESSION.tx_used.load(Ordering::Relaxed);
    let mut last = SESSION.tx_last_used.load(Ordering::Relaxed);
    let want = last.wrapping_add(1);
    let mut spins = 0u64;
    while u32::from(v::used_idx(tx_used)) != want && spins < 200_000_000 {
        spins += 1;
    }
    if u32::from(v::used_idx(tx_used)) != want {
        return None;
    }
    last = want;
    SESSION.tx_last_used.store(last, Ordering::Relaxed);
    Some(frame.len())
}

/// Receive into `out`: polls (bounded) for the NEXT RX completion,
/// copies min(frame, out.len()) bytes out of the proof's RX frame
/// page, then re-arms the buffer for the next packet. Returns the
/// copied count, or None when nothing completed in the budget (the
/// caller answers EAGAIN — the module's non-blocking flavor).
pub(crate) fn recv(out: &mut [u8]) -> Option<usize> {
    if !armed() {
        return None;
    }
    let rx_used = SESSION.rx_used.load(Ordering::Relaxed);
    let rx_qsize = SESSION.rx_qsize.load(Ordering::Relaxed);
    let last = SESSION.rx_last_used.load(Ordering::Relaxed);
    let mut spins = 0u64;
    while u32::from(v::used_idx(rx_used)) == last && spins < 200_000_000 {
        spins += 1;
    }
    let now = u32::from(v::used_idx(rx_used));
    if now == last {
        return None; // budget exhausted: EAGAIN, the honest empty
    }
    // The completing entry is (used.idx - 1) mod qsize; its len covers
    // the 12-byte header + the frame.
    let entry = now.wrapping_sub(1) % rx_qsize;
    let total = v::used_entry_len(rx_used, entry as u16);
    let frame_len = (total as usize).saturating_sub(v::NET_HDR_LEN as usize);
    let n = frame_len.min(out.len());
    let rx_buf = SESSION.rx_buf.load(Ordering::Relaxed);
    let p = rx_buf + u64::from(v::NET_HDR_LEN);
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = v::read_u8_pa(p + i as u64);
    }
    SESSION.rx_last_used.store(now, Ordering::Relaxed);
    // Re-arm the buffer for the NEXT packet (the proof's RX geometry:
    // one max-size writable buffer behind the header).
    let rx_desc = SESSION.rx_desc.load(Ordering::Relaxed);
    v::write_desc(rx_desc, rx_buf, v::NET_HDR_LEN + 1514, v::DESC_F_WRITE, 0);
    publish(SESSION.rx_avail.load(Ordering::Relaxed), rx_qsize);
    kick(0, SESSION.notify_off_rx.load(Ordering::Relaxed));
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_starts_disarmed() {
        assert!(!armed());
    }

    #[test]
    fn send_and_recv_refuse_when_disarmed() {
        assert!(send(&[1, 2, 3]).is_none());
        let mut out = [0u8; 16];
        assert!(recv(&mut out).is_none());
    }
}
