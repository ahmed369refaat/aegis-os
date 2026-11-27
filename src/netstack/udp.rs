//! UDP: datagram parse/emit and the bounded receive queue (K24).
//!
//! ## What this module owns
//!
//! - [`UdpDatagram::parse`] with the length-field honesty check and
//!   optional-but-verified checksum (IPv4 rules: 0x0000 means "no
//!   checksum", anything else MUST verify over the pseudo-header).
//! - [`emit`] building header + payload with a computed checksum
//!   (the stack always SENDS checksums — the cheap integrity win).
//! - [`UdpSocketQueue`]: the fixed, per-socket receive queue —
//!   datagram boundaries are PRESERVED (this is UDP, not a byte
//!   stream), the depth is [`UDP_QUEUE_DEPTH`] and the datagram cap
//!   is [`MAX_DGRAM_LEN`], both compile-time constants.
//!
//! ## Threat model (THREAT_MODEL.md §Malformed, §Resource Exhaustion)
//!
//! - The `length` field is validated BOTH ways: ≥ 8 (header alone)
//!   and ≤ the actual IP payload the caller measured. A lying
//!   length never extends the data slice.
//! - The queue is a FIXED array; a flood arriving faster than the
//!   domain drains it drops NEW arrivals (POSIX shape: the queue
//!   keeps what it had) and counts them. Memory is O(1) in attacker
//!   effort.
//! - Oversized datagrams (> [`MAX_DGRAM_LEN`]) are counted and
//!   dropped at the queue boundary, never truncated mid-record —
//!   partial delivery would corrupt datagram semantics.
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use super::error::{Error, Result};
use super::ipv4;

/// UDP header length: src port, dst port, length, checksum.
pub const UDP_HDR_LEN: usize = 8;
/// The largest datagram PAYLOAD a socket queue will hold. Larger
/// (still-legal) datagrams parse and checksum-verify, but are not
/// queued — the stack is honest about its capacity instead of
/// truncating.
pub const MAX_DGRAM_LEN: usize = 512;
/// Datagrams buffered per bound socket.
pub const UDP_QUEUE_DEPTH: usize = 4;

/// A parsed UDP datagram. `data` views into the caller's buffer,
/// bounded by the MINIMUM of the real IP payload and the header's
/// length field (which must be ≥ 8 to parse at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    /// The checksum AS RECEIVED (0 = none, IPv4).
    pub checksum: u16,
    pub data: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Parse one UDP datagram from the IP payload `buf`.
    ///
    /// `verify_checksum` uses the IPv4 pseudo-header with the
    /// packet's addresses — the caller passes them in because the
    /// pseudo-header is IP's, not UDP's.
    pub fn parse(buf: &'a [u8], src: &[u8; 4], dst: &[u8; 4]) -> Result<UdpDatagram<'a>> {
        if buf.len() < UDP_HDR_LEN {
            return Err(Error::Truncated {
                need: UDP_HDR_LEN,
                have: buf.len(),
            });
        }
        let src_port = ((buf[0] as u16) << 8) | buf[1] as u16;
        let dst_port = ((buf[2] as u16) << 8) | buf[3] as u16;
        let length = ((buf[4] as u16) << 8) | buf[5] as u16;
        let checksum = ((buf[6] as u16) << 8) | buf[7] as u16;
        if length < UDP_HDR_LEN as u16 {
            return Err(Error::Malformed("udp: length < header"));
        }
        // The length field covers header + data and MUST NOT claim
        // more than the IP payload actually carries. (Claiming less
        // — IP padding — is legal; the data slice follows the
        // smaller, honest bound.)
        let data_len = (length as usize)
            .checked_sub(UDP_HDR_LEN)
            .ok_or(Error::Malformed("udp: length underflow"))?;
        if UDP_HDR_LEN + data_len > buf.len() {
            return Err(Error::Malformed("udp: length > ip payload"));
        }
        let data = &buf[UDP_HDR_LEN..UDP_HDR_LEN + data_len];
        let dgram = UdpDatagram {
            src_port,
            dst_port,
            length,
            checksum,
            data,
        };
        if checksum != 0 {
            // Verify: pseudo-header + header(with embedded checksum)
            // + data must fold to 0xFFFF (ones'-complement zero).
            let whole = &buf[..UDP_HDR_LEN + data_len];
            if !checksum_folds_zero(src, dst, length, whole) {
                return Err(Error::BadTransportChecksum);
            }
        }
        Ok(dgram)
    }
}

/// The verification form of the pseudo-header sum: fold the
/// pseudo-header + message (with embedded checksum) and require the
/// complement to be zero — i.e. the sum folds to 0xFFFF.
fn checksum_folds_zero(src: &[u8; 4], dst: &[u8; 4], length: u16, whole: &[u8]) -> bool {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(src);
    ph[4..8].copy_from_slice(dst);
    ph[8] = 0;
    ph[9] = ipv4::PROTO_UDP;
    ph[10] = (length >> 8) as u8;
    ph[11] = length as u8;
    let mut sum: u32 = 0;
    for chunk in ph.as_chunks::<2>().0 {
        sum += ((chunk[0] as u32) << 8) | chunk[1] as u32;
    }
    let mut i = 0;
    while i + 1 < whole.len() {
        sum += ((whole[i] as u32) << 8) | whole[i + 1] as u32;
        i += 2;
    }
    if i < whole.len() {
        sum += (whole[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

/// Emit a UDP datagram into `out` (header + data, checksum
/// computed and stored — the stack never sends UDP without one).
/// `src`/`dst` are the IP addresses (pseudo-header inputs). Returns
/// the total datagram length (8 + data).
pub fn emit(
    out: &mut [u8],
    src: &[u8; 4],
    src_port: u16,
    dst: &[u8; 4],
    dst_port: u16,
    data: &[u8],
) -> Result<usize> {
    let total = UDP_HDR_LEN
        .checked_add(data.len())
        .and_then(|t| u16::try_from(t).ok())
        .ok_or(Error::DatagramTooLarge {
            len: UDP_HDR_LEN + data.len(),
            max: u16::MAX as usize,
        })?;
    if out.len() < total as usize {
        return Err(Error::Truncated {
            need: total as usize,
            have: out.len(),
        });
    }
    out[0] = (src_port >> 8) as u8;
    out[1] = src_port as u8;
    out[2] = (dst_port >> 8) as u8;
    out[3] = dst_port as u8;
    out[4] = (total >> 8) as u8;
    out[5] = total as u8;
    out[6] = 0;
    out[7] = 0;
    out[UDP_HDR_LEN..total as usize].copy_from_slice(data);
    let mut ck =
        ipv4::pseudo_header_checksum(src, dst, ipv4::PROTO_UDP, total, &out[..total as usize]);
    // RFC 768: a computed 0x0000 is transmitted as 0xffff (0 means
    // "no checksum" on IPv4 — we never mean that).
    if ck == 0 {
        ck = 0xffff;
    }
    out[6] = (ck >> 8) as u8;
    out[7] = ck as u8;
    Ok(total as usize)
}

/// One queued datagram: its origin and bytes (fixed inline storage —
/// the queue is an array of these, no allocation anywhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DgramSlot {
    pub from_ip: [u8; 4],
    pub from_port: u16,
    pub len: usize,
    pub data: [u8; MAX_DGRAM_LEN],
}

/// The bounded, boundary-preserving receive queue for one UDP
/// socket. Fixed depth; full-queue policy is DROP-NEW (the queue
/// keeps its older datagrams — the POSIX receive-buffer shape, and
/// the one a flood cannot weaponize: attacker effort does not evict
/// earlier, legitimate traffic).
#[derive(Debug, Clone, Copy)]
pub struct UdpSocketQueue {
    slots: [Option<DgramSlot>; UDP_QUEUE_DEPTH],
    head: usize,
    count: usize,
    pub dropped_full: u64,
    pub dropped_oversize: u64,
}

impl Default for UdpSocketQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpSocketQueue {
    pub const fn new() -> UdpSocketQueue {
        UdpSocketQueue {
            slots: [None; UDP_QUEUE_DEPTH],
            head: 0,
            count: 0,
            dropped_full: 0,
            dropped_oversize: 0,
        }
    }

    /// Queue one received datagram. Oversize and full are counted
    /// drops; a successful push never overwrites an unread one.
    pub fn push(&mut self, from_ip: &[u8; 4], from_port: u16, data: &[u8]) -> Result<()> {
        if data.len() > MAX_DGRAM_LEN {
            self.dropped_oversize += 1;
            return Err(Error::DatagramTooLarge {
                len: data.len(),
                max: MAX_DGRAM_LEN,
            });
        }
        if self.count == UDP_QUEUE_DEPTH {
            self.dropped_full += 1;
            return Err(Error::Again);
        }
        let idx = (self.head + self.count) % UDP_QUEUE_DEPTH;
        let mut slot = DgramSlot {
            from_ip: *from_ip,
            from_port,
            len: data.len(),
            data: [0; MAX_DGRAM_LEN],
        };
        slot.data[..data.len()].copy_from_slice(data);
        self.slots[idx] = Some(slot);
        self.count += 1;
        Ok(())
    }

    /// Pop the OLDEST queued datagram into `out` (datagram
    /// boundaries preserved). `Err(Again)` when empty.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<([u8; 4], u16, usize)> {
        if self.count == 0 {
            return Err(Error::Again);
        }
        let slot = self.slots[self.head].take().ok_or(Error::Again)?;
        self.head = (self.head + 1) % UDP_QUEUE_DEPTH;
        self.count -= 1;
        if out.len() < slot.len {
            // The caller's buffer is too small for THIS datagram;
            // the datagram is already consumed (POSIX semantics:
            // truncated-or-dropped, never kept). Report the honest
            // size need.
            return Err(Error::Truncated {
                need: slot.len,
                have: out.len(),
            });
        }
        out[..slot.len].copy_from_slice(&slot.data[..slot.len]);
        Ok((slot.from_ip, slot.from_port, slot.len))
    }

    /// Datagrams currently queued.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when no datagram is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    #[test]
    fn emit_parse_round_trip_with_checksum() {
        let mut buf = [0u8; 8 + 11];
        let n = emit(&mut buf, &SRC, 5353, &DST, 53, b"hello-udp-!").unwrap();
        assert_eq!(n, 19);
        let d = UdpDatagram::parse(&buf[..n], &SRC, &DST).unwrap();
        assert_eq!(d.src_port, 5353);
        assert_eq!(d.dst_port, 53);
        assert_eq!(d.length, 19);
        assert_eq!(d.data, b"hello-udp-!".as_slice());
        assert_ne!(d.checksum, 0);
    }

    #[test]
    fn zero_checksum_is_accepted_ipv4() {
        let mut buf = [0u8; 8 + 4];
        emit(&mut buf, &SRC, 1, &DST, 2, b"abcd").unwrap();
        buf[6] = 0;
        buf[7] = 0; // "no checksum" — legal on IPv4
        let d = UdpDatagram::parse(&buf, &SRC, &DST).unwrap();
        assert_eq!(d.checksum, 0);
        assert_eq!(d.data, b"abcd".as_slice());
    }

    #[test]
    fn corrupted_checksum_refused() {
        let mut buf = [0u8; 8 + 4];
        emit(&mut buf, &SRC, 1, &DST, 2, b"abcd").unwrap();
        buf[8] ^= 0xff; // data flip
        assert_eq!(
            UdpDatagram::parse(&buf, &SRC, &DST),
            Err(Error::BadTransportChecksum)
        );
    }

    #[test]
    fn length_field_lies_refused_both_ways() {
        // Claims less than the header.
        let mut buf = [0u8; 12];
        emit(&mut buf, &SRC, 1, &DST, 2, b"abcd").unwrap();
        buf[4] = 0;
        buf[5] = 7;
        assert_eq!(
            UdpDatagram::parse(&buf, &SRC, &DST),
            Err(Error::Malformed("udp: length < header"))
        );
        // Claims more than the IP payload.
        let mut buf2 = [0u8; 12];
        emit(&mut buf2, &SRC, 1, &DST, 2, b"abcd").unwrap();
        buf2[5] = 99;
        // The checksum no longer matches either — the length check
        // fires first (order is the contract).
        assert!(matches!(
            UdpDatagram::parse(&buf2, &SRC, &DST),
            Err(Error::Malformed("udp: length > ip payload"))
        ));
    }

    #[test]
    fn queue_preserves_boundaries_and_fifo_order() {
        let mut q = UdpSocketQueue::new();
        q.push(&SRC, 1000, b"first").unwrap();
        q.push(&SRC, 1001, b"second-2").unwrap();
        let mut out = [0u8; 64];
        let (ip, port, n) = q.pop(&mut out).unwrap();
        assert_eq!((&out[..n], port, ip), (b"first".as_slice(), 1000, SRC));
        let (_, p2, n2) = q.pop(&mut out).unwrap();
        assert_eq!((&out[..n2], p2), (b"second-2".as_slice(), 1001));
        assert_eq!(q.pop(&mut out), Err(Error::Again));
    }

    #[test]
    fn queue_full_drops_new_and_counts() {
        let mut q = UdpSocketQueue::new();
        for i in 0..UDP_QUEUE_DEPTH {
            q.push(&SRC, i as u16, b"x").unwrap();
        }
        assert_eq!(q.push(&SRC, 99, b"y"), Err(Error::Again));
        assert_eq!(q.dropped_full, 1);
        // The OLD datagrams survive: FIFO pops in order.
        let mut out = [0u8; 16];
        let (_, p, _) = q.pop(&mut out).unwrap();
        assert_eq!(p, 0);
    }

    #[test]
    fn oversize_datagram_counted_and_dropped() {
        let mut q = UdpSocketQueue::new();
        let big = [0u8; MAX_DGRAM_LEN + 1];
        assert!(matches!(
            q.push(&SRC, 1, &big),
            Err(Error::DatagramTooLarge { .. })
        ));
        assert_eq!(q.dropped_oversize, 1);
        assert!(q.is_empty());
    }
}
