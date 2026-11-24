//! The TTY (Phase 7): serial RX into a ring the console read drains.
//!
//! The 16550 at 0x3F8 (COM1 — QEMU's `-serial stdio` wires it to the
//! process's stdio, so a scripted stdin IS a typed session). The
//! driver-init half is interrupt-driven where the machine allows it:
//! ISA IRQ 4 through the MADT override table into a broker vector
//! (the keyboard's proven chain, ADR-0019), and the IRQ-time bottom
//! half (`drain_uart`) moves bytes from the UART's FIFO into the
//! ring inside `irq::deliver` — EOI first, then the mailbox, then
//! the device drain. The read path ALSO drains opportunistically:
//! on a machine without the armed vector (the no-DMAR branch, a
//! bare `pc` box) the TTY still works — polling at SERVICE time,
//! documented as such, never silently.
//!
//! Every byte carries its SOURCE: serial (the UART's RX) or keyboard
//! (the 8042 bottom half, the PS/2 proof's own path). The tag rides a
//! parallel bit-ring (`TAGS`, one bit per byte, set on `push_ps2`,
//! cleared on `push`), so the PS/2 capture waits for and takes ONLY
//! keyboard bytes and never consumes a serial byte — the shell
//! session's scripted stdin shares this ring, and the old capture
//! drained whatever sat at the head, ate the session's first byte,
//! and printed a false round-trip marker with it (found live, the
//! K17 shell lane's `? cho`).
//!
//! The ring itself is single-producer/single-consumer and — because
//! there is exactly one CPU and syscalls run at IF=0 — the two
//! sides can never actually interleave: the IRQ either happens
//! before the syscall or after it. The atomics exist for the memory
//! model and the ordering documentation (Release publishes a
//! producer's bytes, Acquire makes the consumer see them), and the
//! byte-in-qword packing keeps the whole thing `static` without a
//! single line of unsafe — this module lives outside the allowlist.

// Host-test builds compile this module without its target-only
// halves; its imports stay (used by the target build).
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The frames-ledger owner tag for the TTY's broker vector (the IRQ
/// broker's slot table, not the frame pool — same discipline: every
/// vector names its holder).
pub const TTY_OWNER: u32 = 81;

/// ISA IRQ 4 = COM1 (the MADT's override table may remap it — the
/// arm step resolves the GSI through `gsi_of_isa_irq`).
pub const TTY_ISA_IRQ: u8 = 4;

/// The ring: 32 qword slots × 8 bytes = 256 bytes of line buffer —
/// a command line and the next one, comfortably.
const SLOTS: usize = 32;
const CAP: usize = SLOTS * 8;

static RING: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// The consumer's byte index (the next byte `drain` reads).
static HEAD: AtomicUsize = AtomicUsize::new(0);
/// The producer's byte index (the next byte `push` writes).
static TAIL: AtomicUsize = AtomicUsize::new(0);
/// Bytes dropped because the ring was full (the overrun honesty
/// counter — the marker prints it).
static DROPPED: AtomicUsize = AtomicUsize::new(0);
/// The per-byte source tags, one bit per ring byte (1 = keyboard, 0 =
/// serial): bit `(i % 8)` of `TAGS[(i / 8) % SLOTS]` names the
/// producer of ring byte `i`. Every push writes its byte's bit, so
/// the bit at HEAD is always the CURRENT head byte's tag — no stale
/// tag can survive a lap of the ring.
static TAGS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

/// Push one byte from the SERIAL source. False = the ring is full
/// (the byte is dropped and counted, never a silent loss).
pub fn push(b: u8) -> bool {
    push_tagged(b, false)
}

/// Push one byte from the KEYBOARD source (the 8042 bottom half's
/// decoded byte — the PS/2 round trip's own path). Same contract.
pub fn push_ps2(b: u8) -> bool {
    push_tagged(b, true)
}

/// The shared write half: one byte plus its source tag.
fn push_tagged(b: u8, from_keyboard: bool) -> bool {
    let head = HEAD.load(Ordering::Acquire);
    let tail = TAIL.load(Ordering::Relaxed);
    if tail.wrapping_sub(head) >= CAP {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let slot = (tail / 8) % SLOTS;
    let shift = ((tail % 8) * 8) as u32;
    // Patch one byte of the packed slot. No true concurrency exists
    // (single CPU, IF=0 on the consumer side), so the load-patch-
    // store cannot lose a byte; the store publishes with Release.
    let mut q = RING[slot].load(Ordering::Relaxed);
    q = (q & !(0xFFu64 << shift)) | (u64::from(b) << shift);
    RING[slot].store(q, Ordering::Release);
    // The same slot's tag byte: set or clear THIS byte's bit — the
    // load-patch-store argument is the ring's, verbatim.
    let bit = 1u64 << ((tail % 8) as u32);
    let mut t = TAGS[slot].load(Ordering::Relaxed);
    t = (t & !bit) | if from_keyboard { bit } else { 0 };
    TAGS[slot].store(t, Ordering::Release);
    TAIL.store(tail.wrapping_add(1), Ordering::Release);
    true
}

/// Drain up to `out.len()` bytes (the OLDEST first). Returns the
/// count moved.
pub fn drain(out: &mut [u8]) -> usize {
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    let avail = tail.wrapping_sub(head);
    let n = avail.min(out.len());
    for (i, o) in out.iter_mut().enumerate().take(n) {
        let idx = head.wrapping_add(i);
        let q = RING[(idx / 8) % SLOTS].load(Ordering::Acquire);
        let shift = ((idx % 8) * 8) as u32;
        *o = ((q >> shift) & 0xFF) as u8;
    }
    HEAD.store(head.wrapping_add(n), Ordering::Release);
    n
}

/// Bytes buffered but not yet drained.
pub fn buffered() -> usize {
    TAIL.load(Ordering::Acquire)
        .wrapping_sub(HEAD.load(Ordering::Acquire))
}

/// Keyboard-sourced bytes currently buffered (the PS/2 capture's wait
/// condition — serial bytes never count).
pub fn ps2_pushed() -> usize {
    let head = HEAD.load(Ordering::Acquire);
    let tail = TAIL.load(Ordering::Acquire);
    let mut n = 0usize;
    for i in 0..tail.wrapping_sub(head) {
        let idx = head.wrapping_add(i);
        let t = TAGS[(idx / 8) % SLOTS].load(Ordering::Acquire);
        if t & (1u64 << ((idx % 8) as u32)) != 0 {
            n += 1;
        }
    }
    n
}

/// Take the head byte ONLY if it is keyboard-sourced: the PS/2
/// capture consumes exactly its own byte and leaves every serial byte
/// where it sits. None = the head is serial, or the ring is empty.
pub fn take_head_ps2() -> Option<u8> {
    let head = HEAD.load(Ordering::Acquire);
    let tail = TAIL.load(Ordering::Acquire);
    if tail.wrapping_sub(head) == 0 {
        return None;
    }
    let t = TAGS[(head / 8) % SLOTS].load(Ordering::Acquire);
    if t & (1u64 << ((head % 8) as u32)) == 0 {
        return None;
    }
    let q = RING[(head / 8) % SLOTS].load(Ordering::Acquire);
    let shift = ((head % 8) * 8) as u32;
    let b = ((q >> shift) & 0xFF) as u8;
    HEAD.store(head.wrapping_add(1), Ordering::Release);
    Some(b)
}

/// Bytes dropped to a full ring since boot.
pub fn dropped() -> usize {
    DROPPED.load(Ordering::Relaxed)
}

// ── the 16550 half (target-only: port I/O) ──────────────────────────

const COM1: u16 = 0x3F8;
/// The interrupt-enable register (DLAB=0): bit 0 = data-available.
const IER: u16 = COM1 + 1;
/// The FIFO control register: enable + clear both FIFOs (14-byte
/// receive threshold).
const FCR: u16 = COM1 + 2;
/// The line control register: 8N1, DLAB=0.
const LCR: u16 = COM1 + 3;
/// The line status register: bit 0 = receiver data ready.
const LSR: u16 = COM1 + 5;

/// Bring the UART up: 8N1, FIFOs on and cleared, the RX interrupt
/// enabled. Bytes the host queued BEFORE the arm move into the ring
/// (not the void — found live: the shell lane's scripted session lost
/// its first 15 bytes here, and the shell's first command arrived as
/// the line's tail). The FIFO still ends empty, so the first
/// interrupt edge is honest either way. (Target-only: the host has no
/// ports.)
#[cfg(not(test))]
pub fn uart_init() {
    // DRAIN FIRST, register games after (found live: the FCR
    // enable-transition can drop a byte sitting in the receiver —
    // the scripted session's very first byte died exactly there).
    let mut spins = 0u64;
    while crate::hw::inb(LSR) & 1 != 0 && spins < 1024 {
        let b = crate::hw::inb(COM1);
        push(b);
        spins += 1;
    }
    port_init();
}

/// The register writes, split out so the doc can name what the
/// target half does (the host has no ports). FCR is 0x01 — FIFO
/// ENABLE ONLY: bits 1..=2 are the CLEAR commands, and clearing the
/// receiver DISCARDS whatever the host queued before the arm (found
/// live: the shell lane's first 15 scripted bytes died exactly here).
#[cfg(not(test))]
fn port_init() {
    crate::hw::outb(LCR, 0x03); // 8N1, DLAB=0
    crate::hw::outb(FCR, 0x01); // FIFO enable, NO clears
    crate::hw::outb(IER, 0x01); // RX data-available interrupt
}

/// The bottom half: drain the UART's FIFO into the ring. Called from
/// the IRQ delivery path (after the EOI) AND opportunistically from
/// the console read — on a machine without the armed vector, this
/// service-time drain IS the whole driver (documented polling). The
/// loop is bounded by the FIFO's 16-byte depth plus slack.
#[cfg(not(test))]
pub fn drain_uart() -> usize {
    let mut n = 0usize;
    let mut spins = 0u64;
    while crate::hw::inb(LSR) & 1 != 0 && spins < 64 {
        let b = crate::hw::inb(COM1);
        push(b);
        n += 1;
        spins += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring's whole contract, driven from the test side: FIFO
    /// order, the wraparound across slot and qword boundaries, the
    /// bounded drain, and the honest drop counter at capacity.
    #[test]
    fn ring_is_fifo_across_the_wrap_and_drops_honestly() {
        // 300 bytes: wraps the 256-byte ring.
        for i in 0..300u32 {
            let ok = push((i % 251) as u8);
            if (i as usize) < CAP {
                assert!(ok, "byte {i} must fit");
            } else {
                assert!(!ok, "byte {i} must drop (ring full)");
            }
        }
        assert_eq!(dropped(), 300 - CAP);
        assert_eq!(buffered(), CAP);
        // Drain in odd-sized chunks: FIFO order throughout.
        let mut out = [0u8; 7];
        let mut next = 0usize;
        while buffered() > 0 {
            let n = drain(&mut out);
            assert!(n > 0);
            for i in 0..n {
                let want = ((next + i) % 251) as u8;
                assert_eq!(out[i], want, "byte {} of the stream", next + i);
            }
            next += n;
        }
        assert_eq!(next, CAP);
        // Empty drain answers 0; buffered back to 0.
        assert_eq!(drain(&mut out), 0);
        assert_eq!(buffered(), 0);
        // The ring is reusable: push through the wrapped indices
        // again (HEAD/TAIL stay monotonically wrapping).
        assert!(push(0xAA));
        assert!(push(0xBB));
        let mut two = [0u8; 2];
        assert_eq!(drain(&mut two), 2);
        assert_eq!(&two, &[0xAA, 0xBB]);
        // The source tags: a keyboard byte is takeable exactly once,
        // a serial byte is never consumed by the keyboard path — the
        // shell-session contract (found live: the old capture drained
        // the head and ate the session's first byte).
        assert_eq!(ps2_pushed(), 0);
        assert!(push(b'e')); // serial
        assert_eq!(ps2_pushed(), 0);
        assert_eq!(take_head_ps2(), None, "a serial head is not the keyboard's");
        assert_eq!(buffered(), 1, "the serial byte stays put");
        assert!(push_ps2(b'a')); // keyboard, behind the serial byte
        assert_eq!(ps2_pushed(), 1);
        assert_eq!(take_head_ps2(), None, "only a keyboard HEAD is takeable");
        // The console read drains FIFO, tags aside — the shell gets
        // every byte in order, whatever its source.
        let mut one = [0u8; 1];
        assert_eq!(drain(&mut one), 1);
        assert_eq!(one[0], b'e');
        // Now the head is the keyboard's: take it — exactly it.
        assert_eq!(take_head_ps2(), Some(b'a'));
        assert_eq!(take_head_ps2(), None);
        assert_eq!(ps2_pushed(), 0);
        assert!(push_ps2(b'h'));
        assert!(push_ps2(b'i'));
        assert_eq!(take_head_ps2(), Some(b'h'));
        assert_eq!(take_head_ps2(), Some(b'i'));
        assert_eq!(take_head_ps2(), None);
    }
}
