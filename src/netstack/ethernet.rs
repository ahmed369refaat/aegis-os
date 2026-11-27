//! Ethernet II framing (K24).
//!
//! The stack's own independent, testable framing — deliberately NOT
//! shared with the netd driver's wire code. The driver owns the
//! virtio rings; this module owns what the bytes MEAN. The two meet
//! only at the [`FrameSink`](crate::netstack::FrameSink) boundary,
//! which is the broker's.
//!
//! ## Threat model (THREAT_MODEL.md §Malformed)
//!
//! Ethernet headers are 14 untrusted bytes and the payload behind
//! them is untrusted up to the frame length the caller reports:
//!
//! - [`EthFrame::parse`] never returns a payload slice longer than
//!   the input: `payload_len = frame.len() - 14`, computed with a
//!   checked subtraction after the minimum-length gate.
//! - No EtherType dispatches into a parser blindly: unknown types
//!   are counted and dropped ([`Error::BadEtherType`]), never
//!   answered — an unknown-protocol reply would be an amplifier.
//! - Construction ([`EthFrame::emit`]) bounds-checks the OUTPUT
//!   buffer before writing a single byte, so a caller passing a
//!   short buffer gets an error, not a truncated frame on the wire.
//!
//! `no_std`, `no_alloc`, no `unsafe` in this module.

use super::error::{Error, Result};

/// Minimum frame the parser will consider: 14 header bytes + the
/// smallest legal payload (46 B for real Ethernet; the stack accepts
/// 14 alone because virtio pads are the driver's business, not the
/// parser's — length honesty is enforced at the IP layer, which
/// carries its own total-length field).
pub const ETH_HDR_LEN: usize = 14;
/// One standard Ethernet frame: 1500 B MTU + 14 B header. Egress
/// beyond this is refused before the broker is touched (matching
/// `net::MAX_NET_FRAME_BYTES`, one source of truth per side).
pub const ETH_FRAME_MAX: usize = 1514;

/// A 48-bit EUI-48 media access control address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The broadcast address (all ones). Frames TO this address are
    /// accepted for ARP processing; frames FROM it are not legal
    /// unicast sources but the stack only logs, never trusts.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    /// The all-zero address: unspecified/empty.
    pub const ZERO: MacAddr = MacAddr([0x00; 6]);

    /// True when this is the broadcast address.
    pub const fn is_broadcast(&self) -> bool {
        let [a, b, c, d, e, f] = self.0;
        a == 0xff && b == 0xff && c == 0xff && d == 0xff && e == 0xff && f == 0xff
    }

    /// True for a unicast (non-broadcast, locally significant bit
    /// not set by US — we do not police the I/G bit of SOURCE
    /// addresses; only destination filtering is a correctness
    /// matter).
    pub const fn is_unicast(&self) -> bool {
        !self.is_broadcast()
    }

    /// The lowest bit of the first octet: 1 means group/multicast.
    /// Used only for accounting; multicast is not forwarded by this
    /// stack.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Big-endian octets as `[u8; 6]` (wire order).
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// The EtherTypes this stack speaks. Everything else is refused with
/// the raw number intact so counters can name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Arp,
    Ipv4,
    /// Any other EtherType; the payload is never parsed.
    Unknown(u16),
}

impl EtherType {
    /// Wire value (big-endian field, host-order value here).
    pub const fn be_bytes(&self) -> [u8; 2] {
        let v: u16 = match self {
            EtherType::Arp => 0x0806,
            EtherType::Ipv4 => 0x0800,
            EtherType::Unknown(v) => *v,
        };
        [(v >> 8) as u8, (v & 0xff) as u8]
    }

    /// Parse the 16-bit field (host order after a big-endian read).
    pub const fn from_u16(v: u16) -> EtherType {
        match v {
            0x0806 => EtherType::Arp,
            0x0800 => EtherType::Ipv4,
            other => EtherType::Unknown(other),
        }
    }
}

/// A parsed Ethernet II header. Owns nothing; the payload is a view
/// into the caller's frame computed by [`EthFrame::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthFrame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: EtherType,
    /// The payload AFTER the 14-byte header, bounded by the input's
    /// real length — never longer than what the caller supplied.
    pub payload: &'a [u8],
}

impl<'a> EthFrame<'a> {
    /// Parse a frame. Fails with [`Error::Truncated`] under 14
    /// bytes, [`Error::FrameTooLong`] beyond the MTU the stack will
    /// ever process locally. No checksum exists at this layer, so
    /// length sanity is the whole gate — and it is checked BEFORE
    /// any field is trusted.
    pub fn parse(frame: &'a [u8]) -> Result<EthFrame<'a>> {
        if frame.len() < ETH_HDR_LEN {
            return Err(Error::Truncated {
                need: ETH_HDR_LEN,
                have: frame.len(),
            });
        }
        if frame.len() > ETH_FRAME_MAX {
            // Over-MTU frames can only arrive if a caller misused
            // the driver; count and refuse rather than trust.
            return Err(Error::FrameTooLong {
                len: frame.len(),
                max: ETH_FRAME_MAX,
            });
        }
        let dst = MacAddr([frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]]);
        let src = MacAddr([frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]]);
        let t = ((frame[12] as u16) << 8) | frame[13] as u16;
        let payload = &frame[ETH_HDR_LEN..];
        Ok(EthFrame {
            dst,
            src,
            ethertype: EtherType::from_u16(t),
            payload,
        })
    }

    /// Should this frame be ACCEPTED for local processing? Destination
    /// must be our unicast MAC or broadcast. Multicast is refused
    /// (this stack does not join groups) — a quiet drop, because
    /// replying would confirm membership we never declared.
    pub fn addressed_to(&self, our_mac: &MacAddr) -> bool {
        self.dst == *our_mac || self.dst.is_broadcast()
    }
}

/// Emit an Ethernet II frame into `out`: 14-byte header + `payload`.
///
/// Bounds-checked BEFORE any write: `out` must hold 14 + payload
/// bytes. Returns the total frame length written. The caller (the
/// stack's egress path) is responsible for delivering the frame to
/// the broker — this function never touches a device.
pub fn emit(
    out: &mut [u8],
    dst: &MacAddr,
    src: &MacAddr,
    ethertype: EtherType,
    payload: &[u8],
) -> Result<usize> {
    let need = ETH_HDR_LEN
        .checked_add(payload.len())
        .ok_or(Error::FrameTooLong {
            len: usize::MAX,
            max: ETH_FRAME_MAX,
        })?;
    if need > ETH_FRAME_MAX {
        return Err(Error::FrameTooLong {
            len: need,
            max: ETH_FRAME_MAX,
        });
    }
    if out.len() < need {
        return Err(Error::Truncated {
            need,
            have: out.len(),
        });
    }
    out[0..6].copy_from_slice(&dst.0);
    out[6..12].copy_from_slice(&src.0);
    let t = ethertype.be_bytes();
    out[12] = t[0];
    out[13] = t[1];
    out[ETH_HDR_LEN..need].copy_from_slice(payload);
    Ok(need)
}

/// Write ONLY the 14-byte Ethernet header into `out` (the payload
/// is expected to follow in the same buffer — the split-borrow form
/// of [`emit`] for builders that assemble header and payload in one
/// array).
pub fn emit_header_only(
    out: &mut [u8],
    dst: &MacAddr,
    src: &MacAddr,
    ethertype: EtherType,
) -> Result<()> {
    if out.len() < ETH_HDR_LEN {
        return Err(Error::Truncated {
            need: ETH_HDR_LEN,
            have: out.len(),
        });
    }
    out[0..6].copy_from_slice(&dst.0);
    out[6..12].copy_from_slice(&src.0);
    let t = ethertype.be_bytes();
    out[12] = t[0];
    out[13] = t[1];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, n])
    }

    #[test]
    fn parse_and_emit_round_trip() {
        let mut buf = [0u8; 64];
        let payload = b"0123456789abcdef";
        let n = emit(&mut buf, &mac(1), &mac(2), EtherType::Ipv4, payload).unwrap();
        assert_eq!(n, 14 + payload.len());
        let f = EthFrame::parse(&buf[..n]).unwrap();
        assert_eq!(f.dst, mac(1));
        assert_eq!(f.src, mac(2));
        assert_eq!(f.ethertype, EtherType::Ipv4);
        assert_eq!(f.payload, payload.as_slice());
    }

    #[test]
    fn truncated_frame_is_refused_before_any_field_is_trusted() {
        let short = [0u8; 13];
        assert_eq!(
            EthFrame::parse(&short),
            Err(Error::Truncated { need: 14, have: 13 })
        );
    }

    #[test]
    fn over_mtu_frame_is_refused() {
        let big = [0u8; ETH_FRAME_MAX + 1];
        assert!(matches!(
            EthFrame::parse(&big),
            Err(Error::FrameTooLong { .. })
        ));
    }

    #[test]
    fn emit_bounds_checks_the_output_buffer_first() {
        let mut small = [0u8; 20];
        // 14 header + 16 payload = 30 > 20: refused, buffer untouched.
        assert_eq!(
            emit(
                &mut small,
                &mac(1),
                &mac(2),
                EtherType::Arp,
                b"0123456789abcdef"
            ),
            Err(Error::Truncated { need: 30, have: 20 })
        );
        assert!(small.iter().all(|&b| b == 0));
    }

    #[test]
    fn unknown_ethertype_is_named_not_parsed() {
        let mut buf = [0u8; 16];
        emit(
            &mut buf,
            &mac(1),
            &mac(2),
            EtherType::Unknown(0x88cc),
            b"xx",
        )
        .unwrap();
        let f = EthFrame::parse(&buf).unwrap();
        assert_eq!(f.ethertype, EtherType::Unknown(0x88cc));
    }

    #[test]
    fn destination_filter_accepts_unicast_and_broadcast_only() {
        let mut buf = [0u8; 16];
        emit(&mut buf, &mac(1), &mac(2), EtherType::Ipv4, b"xx").unwrap();
        let f = EthFrame::parse(&buf).unwrap();
        assert!(f.addressed_to(&mac(1)));
        assert!(!f.addressed_to(&mac(9)));
        // A frame SENT TO the broadcast address is accepted as ours
        // (addressed_to asks "should WE process it", taking OUR mac).
        let mut bbuf = [0u8; 16];
        emit(
            &mut bbuf,
            &MacAddr::BROADCAST,
            &mac(2),
            EtherType::Ipv4,
            b"xx",
        )
        .unwrap();
        let bf = EthFrame::parse(&bbuf).unwrap();
        assert!(bf.addressed_to(&mac(1)));
        // Multicast destination: refused (we join no groups).
        let mut m = [0u8; 16];
        emit(
            &mut m,
            &MacAddr([0x01, 0, 0, 0, 0, 5]),
            &mac(2),
            EtherType::Ipv4,
            b"xx",
        )
        .unwrap();
        let fm = EthFrame::parse(&m).unwrap();
        assert!(!fm.addressed_to(&mac(1)));
    }
}
