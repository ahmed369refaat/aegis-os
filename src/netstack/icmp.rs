//! ICMP: echo (ping) and Destination Unreachable (K24).
//!
//! ## What this module owns
//!
//! - [`IcmpPacket::parse`] with full-length and checksum validation
//!   for the message shapes the stack acts on (echo request/reply,
//!   destination unreachable); anything else is parsed-but-ignored
//!   (counted, never answered).
//! - Pure emit functions for the three messages we generate: echo
//!   reply, echo request (the `ping` API), and destination
//!   unreachable.
//! - [`IcmpLimiter`]: the error-generation token bucket
//!   (THREAT_MODEL.md §Malformed / amplification).
//!
//! ## Threat model (THREAT_MODEL.md §Malformed, §Amplification)
//!
//! - **No reply to unknown types**, and never a reply TO an error:
//!   unreachable messages are generated only from the UDP/TCP
//!   dispatch (a closed port), never from ICMP input — the classic
//!   ICMP-error ping-pong loop is closed by construction.
//! - **Rate-limited error generation**: every emitted destination
//!   unreachable consumes a token from a fixed bucket (refilled by
//!   wall time, bounded burst). A port-scanner sweeping 65,535
//!   closed ports gets at most a handful of replies, not 65,535 —
//!   the stack refuses to be an amplifier.
//! - **We do NOT tear down TCP on received ICMP errors.** A spoofed
//!   "host/network unreachable" that names a live connection is a
//!   classic blind-reset shape; this stack treats received
//!   unreachables as DIAGNOSTICS ONLY (a counter). The connection
//!   dies by retransmission exhaustion, or not at all.
//! - **Echo request payloads are bounded** (≤ 1472 B, the MTU minus
//!   IPv4+ICMP headers) and the REPLY carries exactly the request's
//!   bytes: a 64-byte request never answers with more than 64 bytes
//!   (no bloat amplification).
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use super::error::{Error, Result};

/// ICMP header length (type, code, checksum, 4 message bytes).
pub const ICMP_HDR_LEN: usize = 8;
/// The largest echo payload the stack will echo: 1500 MTU − 20 IPv4
/// header − 8 ICMP header.
pub const MAX_ICMP_PAYLOAD: usize = 1472;

// ── message types and codes we speak ───────────────────────────────
pub const TYPE_ECHO_REPLY: u8 = 0;
pub const TYPE_ECHO_REQUEST: u8 = 8;
pub const TYPE_DEST_UNREACHABLE: u8 = 3;

pub const CODE_UNREACH_NET: u8 = 0;
pub const CODE_UNREACH_HOST: u8 = 1;
pub const CODE_UNREACH_PORT: u8 = 3;

/// A parsed ICMP message. `payload` views into the caller's buffer,
/// bounded by the real IPv4 payload length (already validated by the
/// IP layer) and re-validated here against the ICMP minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpPacket<'a> {
    pub icmp_type: u8,
    pub code: u8,
    /// Echo identifier / unreachable first message word.
    pub word0: u16,
    /// Echo sequence / unreachable second message word.
    pub word1: u16,
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    /// Parse and validate: length ≥ 8, then the CHECKSUM over the
    /// whole message (header + payload). A bad checksum is a drop,
    /// never a reply. Unknown types PARSE (they are well-formed) but
    /// the stack counts and ignores them — see [`IcmpPacket::kind`].
    pub fn parse(buf: &'a [u8]) -> Result<IcmpPacket<'a>> {
        if buf.len() < ICMP_HDR_LEN {
            return Err(Error::Truncated {
                need: ICMP_HDR_LEN,
                have: buf.len(),
            });
        }
        if !super::ipv4::checksum_ok(buf) {
            return Err(Error::BadTransportChecksum);
        }
        Ok(IcmpPacket {
            icmp_type: buf[0],
            code: buf[1],
            word0: ((buf[4] as u16) << 8) | buf[5] as u16,
            word1: ((buf[6] as u16) << 8) | buf[7] as u16,
            payload: &buf[ICMP_HDR_LEN..],
        })
    }

    /// The shapes the stack acts on; everything else is ignored.
    pub const fn kind(&self) -> IcmpKind {
        match self.icmp_type {
            TYPE_ECHO_REPLY => IcmpKind::EchoReply,
            TYPE_ECHO_REQUEST => IcmpKind::EchoRequest,
            TYPE_DEST_UNREACHABLE => IcmpKind::Unreachable,
            _ => IcmpKind::Ignored,
        }
    }
}

/// The ICMP message kinds the stack distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpKind {
    EchoRequest,
    EchoReply,
    Unreachable,
    /// Well-formed but unhandled (timestamp, redirect, …). Counted,
    /// never answered. Redirects in particular are IGNORED — this
    /// stack's routing table is operator-configured, not
    /// wire-configurable (THREAT_MODEL.md §ICMP redirect).
    Ignored,
}

/// Emit an echo request or reply (identical shape, one type byte
/// apart). Bounds-checked: `out` must hold 8 + payload bytes and the
/// payload must respect [`MAX_ICMP_PAYLOAD`]. The checksum is
/// computed over the whole message.
fn emit_echo(out: &mut [u8], is_request: bool, id: u16, seq: u16, payload: &[u8]) -> Result<usize> {
    if payload.len() > MAX_ICMP_PAYLOAD {
        return Err(Error::DatagramTooLarge {
            len: payload.len(),
            max: MAX_ICMP_PAYLOAD,
        });
    }
    let need = ICMP_HDR_LEN
        .checked_add(payload.len())
        .ok_or(Error::DatagramTooLarge {
            len: usize::MAX,
            max: MAX_ICMP_PAYLOAD,
        })?;
    if out.len() < need {
        return Err(Error::Truncated {
            need,
            have: out.len(),
        });
    }
    out[0] = if is_request {
        TYPE_ECHO_REQUEST
    } else {
        TYPE_ECHO_REPLY
    };
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = (id >> 8) as u8;
    out[5] = id as u8;
    out[6] = (seq >> 8) as u8;
    out[7] = seq as u8;
    out[ICMP_HDR_LEN..need].copy_from_slice(payload);
    let ck = super::ipv4::checksum16(&out[..need]);
    out[2] = (ck >> 8) as u8;
    out[3] = ck as u8;
    Ok(need)
}

/// Emit an echo REQUEST (the ping API's egress half).
pub fn emit_echo_request(out: &mut [u8], id: u16, seq: u16, payload: &[u8]) -> Result<usize> {
    emit_echo(out, true, id, seq, payload)
}

/// Emit an echo REPLY carrying exactly the request's id/seq/payload.
pub fn emit_echo_reply(out: &mut [u8], id: u16, seq: u16, payload: &[u8]) -> Result<usize> {
    emit_echo(out, false, id, seq, payload)
}

/// Emit a Destination Unreachable. `embedded` is the original
/// datagram's IPv4 header + first 8 payload bytes (≤ 28 B, per RFC
/// 792/1122) — the caller copies it from the offending packet.
pub fn emit_unreachable(out: &mut [u8], code: u8, embedded: &[u8]) -> Result<usize> {
    let need = ICMP_HDR_LEN
        .checked_add(embedded.len())
        .ok_or(Error::DatagramTooLarge {
            len: usize::MAX,
            max: ICMP_HDR_LEN + 28,
        })?;
    if out.len() < need {
        return Err(Error::Truncated {
            need,
            have: out.len(),
        });
    }
    out[0] = TYPE_DEST_UNREACHABLE;
    out[1] = code;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;
    out[ICMP_HDR_LEN..need].copy_from_slice(embedded);
    let ck = super::ipv4::checksum16(&out[..need]);
    out[2] = (ck >> 8) as u8;
    out[3] = ck as u8;
    Ok(need)
}

/// A fixed-capacity, time-refilled token bucket for MESSAGE
/// GENERATION (errors and echo replies). This is the anti-amplifier:
/// a scanner or a spoofed-source flood gets at most `burst` messages
/// per refill window, then silence.
///
/// Deliberately integer and deterministic (same discipline as the
/// kernel broker's `TokenBucket`): refill is credited for fully
/// elapsed windows only.
#[derive(Debug, Clone, Copy)]
pub struct IcmpLimiter {
    tokens: u8,
    max: u8,
    per_window: u8,
    window_ms: u64,
    last_window: u64,
}

impl IcmpLimiter {
    /// An error-generation bucket: 5 messages at once, one more per
    /// second (a compliant host's answer to a full closed-port scan
    /// is a trickle, not a mirror).
    pub const fn for_errors() -> IcmpLimiter {
        IcmpLimiter {
            tokens: 5,
            max: 5,
            per_window: 1,
            window_ms: 1000,
            last_window: 0,
        }
    }

    /// An echo-reply bucket: generous (ping is a legitimate
    /// diagnostic) but still bounded: 10 at once, 2 per second.
    pub const fn for_echo() -> IcmpLimiter {
        IcmpLimiter {
            tokens: 10,
            max: 10,
            per_window: 2,
            window_ms: 1000,
            last_window: 0,
        }
    }

    /// Refill for elapsed full windows; call on every use.
    pub fn refill(&mut self, now: u64) {
        if self.window_ms == 0 {
            return;
        }
        let cur = now / self.window_ms;
        if cur > self.last_window {
            let elapsed = (cur - self.last_window).min(u32::MAX as u64);
            let credit = (elapsed as u32) as u8 * self.per_window;
            // Saturating: the bucket never exceeds `max`.
            self.tokens = self.tokens.saturating_add(credit).min(self.max);
            self.last_window = cur;
        }
    }

    /// Consume one token; false when the bucket is empty (the
    /// message is NOT generated — the honest refusal, no queueing).
    pub fn try_consume(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Current tokens (diagnostics/tests).
    pub fn tokens(&self) -> u8 {
        self.tokens
    }
}

/// The ICMP layer: two limiters + counters. PURE decision logic —
/// it never emits; it returns the action and the stack's egress path
/// (one funneled broker path for every frame) builds and sends.
#[derive(Debug)]
pub struct IcmpLayer {
    pub err_limiter: IcmpLimiter,
    pub echo_limiter: IcmpLimiter,
    // Counters surfaced to the stack stats / tests.
    pub echo_requests_received: u64,
    pub echo_replies_sent: u64,
    pub echo_replies_received: u64,
    pub unreachables_sent: u64,
    pub unreachables_received: u64,
    pub ignored_types: u64,
}

impl Default for IcmpLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpLayer {
    pub const fn new() -> IcmpLayer {
        IcmpLayer {
            err_limiter: IcmpLimiter::for_errors(),
            echo_limiter: IcmpLimiter::for_echo(),
            echo_requests_received: 0,
            echo_replies_sent: 0,
            echo_replies_received: 0,
            unreachables_sent: 0,
            unreachables_received: 0,
            ignored_types: 0,
        }
    }

    /// Input path for an echo REQUEST: rate-limited, returns whether
    /// a reply should be sent (the caller echoes id/seq/payload
    /// back to the source — exactly the request's bytes, no more).
    pub fn on_echo_request(&mut self, now: u64) -> bool {
        self.echo_requests_received += 1;
        if self.echo_limiter.try_consume(now) {
            self.echo_replies_sent += 1;
            true
        } else {
            false
        }
    }

    /// Input path for an echo REPLY: counted; the stack's ping API
    /// matches it against its outstanding request elsewhere.
    pub fn on_echo_reply(&mut self) {
        self.echo_replies_received += 1;
    }

    /// Input path for a received UNREACHABLE: counted ONLY — no
    /// connection state is touched (see the module docs: spoofed
    /// unreachable blind-resets are deliberately inert here).
    pub fn on_unreachable(&mut self) {
        self.unreachables_received += 1;
    }

    /// Input path for an unhandled type: counted, never answered.
    pub fn on_ignored(&mut self) {
        self.ignored_types += 1;
    }

    /// May we generate a destination unreachable? Rate-limited;
    /// false means silent drop of the offending datagram (the
    /// sending side learns by its own retransmissions).
    pub fn may_send_unreachable(&mut self, now: u64) -> bool {
        if self.err_limiter.try_consume(now) {
            self.unreachables_sent += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_round_trip_with_checksum() {
        let mut req = [0u8; 8 + 16]; // 16-byte payload: "ping-payload-16!"
        assert_eq!(
            emit_echo_request(&mut req, 0x1234, 7, b"ping-payload-16!").unwrap(),
            24
        );
        let p = IcmpPacket::parse(&req).unwrap();
        assert_eq!(p.kind(), IcmpKind::EchoRequest);
        assert_eq!(p.word0, 0x1234);
        assert_eq!(p.word1, 7);
        assert_eq!(p.payload, b"ping-payload-16!".as_slice());
        // The reply mirrors it exactly.
        let mut rep = [0u8; 24];
        emit_echo_reply(&mut rep, p.word0, p.word1, p.payload).unwrap();
        let r = IcmpPacket::parse(&rep).unwrap();
        assert_eq!(r.kind(), IcmpKind::EchoReply);
        assert_eq!(r.payload, p.payload);
    }

    #[test]
    fn truncated_icmp_refused() {
        assert_eq!(
            IcmpPacket::parse(&[0u8; 7]),
            Err(Error::Truncated { need: 8, have: 7 })
        );
    }

    #[test]
    fn corrupted_icmp_checksum_refused() {
        let mut req = [0u8; 8 + 4];
        emit_echo_request(&mut req, 1, 1, b"abcd").unwrap();
        req[8] ^= 0x80; // payload flip changes the message checksum
        assert_eq!(IcmpPacket::parse(&req), Err(Error::BadTransportChecksum));
    }

    #[test]
    fn oversized_echo_payload_refused() {
        let mut out = [0u8; ICMP_HDR_LEN + MAX_ICMP_PAYLOAD + 1];
        let big = [0u8; MAX_ICMP_PAYLOAD + 1];
        assert!(matches!(
            emit_echo_request(&mut out, 1, 1, &big),
            Err(Error::DatagramTooLarge { .. })
        ));
    }

    #[test]
    fn unreachable_emit_and_parse() {
        let embedded = [0u8; 28]; // a zeroed "original header + 8"
        let mut out = [0u8; 8 + 28];
        assert_eq!(
            emit_unreachable(&mut out, CODE_UNREACH_PORT, &embedded).unwrap(),
            36
        );
        let p = IcmpPacket::parse(&out).unwrap();
        assert_eq!(p.kind(), IcmpKind::Unreachable);
        assert_eq!(p.code, CODE_UNREACH_PORT);
        assert_eq!(p.payload.len(), 28);
    }

    #[test]
    fn error_bucket_bounds_amplification() {
        let mut l = IcmpLimiter::for_errors();
        let mut allowed = 0;
        for _ in 0..10 {
            if l.try_consume(0) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5); // burst only
                                // One refill window passes: exactly one more.
        assert!(l.try_consume(1000));
        assert!(!l.try_consume(1000));
        // A long idle period refills to max, never beyond.
        assert!(l.try_consume(10_000));
        assert_eq!(l.tokens(), (5 - 1)); // consumed one of the refilled
    }

    #[test]
    fn layer_counts_and_ignores() {
        let mut l = IcmpLayer::new();
        assert!(l.on_echo_request(0));
        l.on_echo_reply();
        l.on_unreachable();
        l.on_ignored();
        assert_eq!(l.echo_requests_received, 1);
        assert_eq!(l.echo_replies_received, 1);
        assert_eq!(l.unreachables_received, 1);
        assert_eq!(l.ignored_types, 1);
        assert!(l.may_send_unreachable(0));
    }
}
