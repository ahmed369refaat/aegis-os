//! IPv4: header parse/emit, checksum, fragmentation & reassembly (K24).
//!
//! ## Threat model (THREAT_MODEL.md §IP Fragmentation, §Malformed)
//!
//! - **Every length field is validated against the buffer before it
//!   is trusted**: `ihl` (≥ 20, ≤ 60, and the header must actually be
//!   present), `total_length` (≥ header, ≤ the frame the caller
//!   supplied — the classic overread is a total_length larger than
//!   the carrying frame), and for fragments, `offset*8 + len` in
//!   checked arithmetic against the fixed slot cap.
//! - **Overlapping fragments are refused, whole-datagram**: the
//!   teardrop shape (fragments whose ranges intersect, engineered to
//!   make naive copy loops write out of bounds) never reaches a copy
//!   loop here — the slot is dropped and counted. We do not "handle"
//!   overlap by believing any byte ordering; we treat it as attack
//!   traffic (RFC 1858's insight, applied unconditionally).
//! - **Bounded reassembly**: [`MAX_REASM_SLOTS`] datagrams at a time,
//!   each capped at [`MAX_REASM_DATAGRAM`] bytes, each with an
//!   absolute lifetime of [`REASM_TIMEOUT_MS`]. The "ping of death"
//!   (a reassembly that claims > 65535 B) cannot exceed the slot cap;
//!   incomplete floods occupy at most 4 slots and then the fifth
//!   datagram is dropped — memory is O(1), never O(attacker).
//! - **No forwarding**: TTL is checked for expiry reporting only;
//!   this stack never re-emits a transit packet (one amplifier
//!   surface closed by construction).
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use super::error::{Error, Result};

/// Minimum IPv4 header (no options).
pub const IPV4_MIN_HDR: usize = 20;
/// Minimum total length field (header alone).
pub const MIN_TOTAL_LEN: u16 = IPV4_MIN_HDR as u16;

/// Protocol numbers the stack dispatches.
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// The 16-bit ones'-complement checksum shared by IP, ICMP, UDP and
/// TCP. Pure function over a byte slice; even lengths sum as u16
/// pairs, a trailing odd byte is padded (zero) per RFC 1071. The
/// final value is the one's COMPLEMENT of the accumulated sum.
pub fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        // Odd trailing byte: high half only, low half zero-padded.
        sum += (data[i] as u32) << 8;
    }
    // Fold the 32-bit accumulator into 16 bits (ones'-complement
    // arithmetic carries), then complement. Double-fold is enough
    // for any input length we accept (≤ 65535 B).
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// True when the ones'-complement checksum of `data` is zero (the
/// verification form: the sender sums header + checksum to 0xFFFF,
/// so the checksum of the whole is 0).
pub fn checksum_ok(data: &[u8]) -> bool {
    // Re-sum with the embedded checksum: folding the embedded value
    // in must yield 0 after complement.
    checksum16(data) == 0
}

/// A parsed IPv4 header. `payload` is a view into the caller's
/// packet, bounded by the MINIMUM of the real buffer and the
/// header's total_length field — never past either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub id: u16,
    /// Flags + fragment offset field (raw, big-endian value; use
    /// [`Ipv4Packet::frag_offset`] / [`Ipv4Packet::more_fragments`]
    /// / [`Ipv4Packet::df_bit`]).
    pub flags_frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parse and validate one IPv4 packet. The order of the gates is
    /// the security contract:
    ///
    /// 1. length ≥ 20 (before ANY field read),
    /// 2. version == 4 and ihl ≥ 5 (ihl*4 is the real header end and
    ///    must be within the buffer),
    /// 3. total_len ≥ ihl*4 and total_len ≤ buf.len() (the classic
    ///    overread),
    /// 4. header checksum over exactly ihl*4 bytes.
    ///
    /// Only then are `src`/`dst`/`payload` trusted. A failed
    /// checksum is reported but the CALLER decides drop-vs-count; the
    /// stack's dispatcher drops.
    pub fn parse(buf: &'a [u8]) -> Result<Ipv4Packet<'a>> {
        if buf.len() < IPV4_MIN_HDR {
            return Err(Error::Truncated {
                need: IPV4_MIN_HDR,
                have: buf.len(),
            });
        }
        let version = buf[0] >> 4;
        let ihl = (buf[0] & 0x0f) as usize;
        if version != 4 {
            return Err(Error::BadIpVersion(version));
        }
        if ihl < 5 {
            return Err(Error::Malformed("ipv4: ihl < 5"));
        }
        let hdr_len = ihl
            .checked_mul(4)
            .ok_or(Error::Malformed("ipv4: ihl overflow"))?;
        if hdr_len > 60 {
            return Err(Error::Malformed("ipv4: ihl > 15"));
        }
        if buf.len() < hdr_len {
            return Err(Error::Truncated {
                need: hdr_len,
                have: buf.len(),
            });
        }
        let total_len = ((buf[2] as u16) << 8) | buf[3] as u16;
        if total_len < hdr_len as u16 {
            return Err(Error::Malformed("ipv4: total_len < header"));
        }
        if total_len as usize > buf.len() {
            // The packet CLAIMS more than it carries: the classic
            // overread. Trust the smaller (real) bound — but refuse,
            // because a correct sender never lies about this.
            return Err(Error::Malformed("ipv4: total_len > frame"));
        }
        let hdr = &buf[..hdr_len];
        if !checksum_ok(hdr) {
            return Err(Error::BadIpChecksum);
        }
        let payload_len = total_len as usize - hdr_len;
        Ok(Ipv4Packet {
            version_ihl: buf[0],
            dscp_ecn: buf[1],
            total_len,
            id: ((buf[4] as u16) << 8) | buf[5] as u16,
            flags_frag: ((buf[6] as u16) << 8) | buf[7] as u16,
            ttl: buf[8],
            protocol: buf[9],
            header_checksum: ((buf[10] as u16) << 8) | buf[11] as u16,
            src: [buf[12], buf[13], buf[14], buf[15]],
            dst: [buf[16], buf[17], buf[18], buf[19]],
            payload: &buf[hdr_len..hdr_len + payload_len],
        })
    }

    /// Fragment offset in 8-byte units.
    pub const fn frag_offset(&self) -> u16 {
        self.flags_frag & 0x1fff
    }
    /// More-fragments flag.
    pub const fn more_fragments(&self) -> bool {
        self.flags_frag & 0x2000 != 0
    }
    /// Don't-fragment flag.
    pub const fn df_bit(&self) -> bool {
        self.flags_frag & 0x4000 != 0
    }
    /// Fragment offset in BYTES (checked arithmetic on the wire field).
    pub fn frag_offset_bytes(&self) -> Result<usize> {
        (self.frag_offset() as usize)
            .checked_mul(8)
            .ok_or(Error::Malformed("ipv4: offset*8 overflow"))
    }
    /// True when this packet IS a fragment (offset != 0 or MF set).
    pub const fn is_fragment(&self) -> bool {
        self.frag_offset() != 0 || self.more_fragments()
    }
}

/// Emit an IPv4 header into `out` (exactly `ihl=5`, 20 bytes, no
/// options — the stack never sends options). `payload_len` must fit
/// `total_len ≤ u16::MAX`; the checksum is computed over the header
/// with the checksum field zeroed, per RFC 791. Returns the header
/// length (20).
///
/// `id` rotation and TTL are the CALLER's policy (the stack keeps a
/// monotonically wrapping id counter and a fixed TTL 64).
/// (clippy::too_many_arguments is deliberate: the parameters ARE
/// the wire format's fields.)
#[allow(clippy::too_many_arguments)]
pub fn emit_header(
    out: &mut [u8],
    total_len: u16,
    id: u16,
    flags_frag: u16,
    ttl: u8,
    protocol: u8,
    src: &[u8; 4],
    dst: &[u8; 4],
) -> Result<usize> {
    if out.len() < IPV4_MIN_HDR {
        return Err(Error::Truncated {
            need: IPV4_MIN_HDR,
            have: out.len(),
        });
    }
    out[0] = 0x45; // version 4, ihl 5
    out[1] = 0; // DSCP/ECN: default
    out[2] = (total_len >> 8) as u8;
    out[3] = total_len as u8;
    out[4] = (id >> 8) as u8;
    out[5] = id as u8;
    out[6] = (flags_frag >> 8) as u8;
    out[7] = flags_frag as u8;
    out[8] = ttl;
    out[9] = protocol;
    out[10] = 0;
    out[11] = 0; // checksum computed below
    out[12..16].copy_from_slice(src);
    out[16..20].copy_from_slice(dst);
    let ck = checksum16(&out[..IPV4_MIN_HDR]);
    out[10] = (ck >> 8) as u8;
    out[11] = ck as u8;
    Ok(IPV4_MIN_HDR)
}

/// The pseudo-header for transport (TCP/UDP/ICMP-in-IPv4-tunneling)
/// checksums: src, dst, zero, protocol, tcp_length (RFC 768/793).
pub fn pseudo_header_checksum(
    src: &[u8; 4],
    dst: &[u8; 4],
    protocol: u8,
    length: u16,
    transport: &[u8],
) -> u16 {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(src);
    ph[4..8].copy_from_slice(dst);
    ph[8] = 0;
    ph[9] = protocol;
    ph[10] = (length >> 8) as u8;
    ph[11] = length as u8;
    let mut acc = pseudo_sum(&ph);
    acc = fold_add(acc, sum_bytes(transport));
    !(fold(acc) as u16)
}

// ── checksum internals shared with the pseudo-header path ─────────
fn sum_bytes(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn pseudo_sum(ph: &[u8; 12]) -> u32 {
    sum_bytes(ph)
}

fn fold_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

fn fold(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

// ── fragmentation / reassembly ─────────────────────────────────────

/// Reassembly slot capacity: one full-MTU datagram (1500 − 20 IP
/// header = 1480 payload bytes). Anything that would reassemble
/// larger is refused — the ping-of-death cap.
pub const MAX_REASM_DATAGRAM: usize = 1480;
/// Concurrent datagrams under reassembly. Four: a link this small
/// legitimately carries at most a couple of concurrent big-UDP
/// senders; a flood caps at four slots of state, then drops.
pub const MAX_REASM_SLOTS: usize = 4;
/// Incomplete datagrams die at this age — bounded state, always.
pub const REASM_TIMEOUT_MS: u64 = 10_000;
/// Distinct (non-overlapping) fragment ranges tracked per datagram.
/// The honest bound on legitimate senders (MTU-sized fragments of a
/// 1480-B datagram: 2). Attack shapes exceed it and are dropped.
pub const MAX_FRAG_HOLES: usize = 8;

/// One tracked byte-range of a datagram under reassembly
/// (start inclusive, end exclusive; both byte offsets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragRange {
    start: usize,
    end: usize,
}

/// One reassembly slot. The datagram's received fragments are kept
/// as disjoint SORTED ranges plus the bytes copied into `data`.
#[derive(Debug, Clone, Copy)]
pub struct ReasmSlot {
    src: [u8; 4],
    dst: [u8; 4],
    id: u16,
    protocol: u8,
    /// Received bytes (fragment payloads copied at their offsets).
    data: [u8; MAX_REASM_DATAGRAM],
    /// Sorted disjoint ranges received so far.
    ranges: [Option<FragRange>; MAX_FRAG_HOLES],
    /// The end offset of the fragment that carried MF=0 (the FINAL
    /// one). Completion requires BOTH contiguous coverage from 0 AND
    /// this value equal to the covered total — a single range
    /// starting at 0 is NOT a complete datagram (the old bug: any
    /// first fragment "completed").
    final_end: Option<usize>,
    started_at: u64,
    /// Counters surfaced to the stack's stats.
    pub fragments: u16,
}

impl ReasmSlot {
    fn reset(&mut self) {
        self.src = [0; 4];
        self.dst = [0; 4];
        self.id = 0;
        self.protocol = 0;
        self.ranges = [None; MAX_FRAG_HOLES];
        self.final_end = None;
        self.started_at = 0;
        self.fragments = 0;
        // `data` need not be zeroed: completion only exposes
        // [0, total) which is fully covered by definition.
    }

    /// Feed one fragment's payload range. Returns:
    /// - `Ok(None)` — accepted, datagram still incomplete.
    /// - `Ok(Some(len))` — accepted and COMPLETE; `len` is the
    ///   reassembled length; the caller reads `slot.data[..len]`.
    /// - `Err` — this slot is INVALID (overlap, cap, hole count):
    ///   the WHOLE datagram is dropped (the caller frees the slot).
    ///
    /// Overlap policy (THREAT_MODEL.md): ANY intersection with a
    /// previously received range refuses the datagram. No byte of an
    /// overlapping datagram is ever believed.
    fn feed(&mut self, pkt: &Ipv4Packet<'_>) -> Result<Option<usize>> {
        let offset = pkt.frag_offset_bytes()?;
        let len = pkt.payload.len();
        if len == 0 {
            return Err(Error::Malformed("ipv4: zero-length fragment"));
        }
        // Byte range of THIS fragment, checked arithmetic, capped.
        let start = offset;
        let end = offset
            .checked_add(len)
            .ok_or(Error::Malformed("ipv4: fragment end overflow"))?;
        if end > MAX_REASM_DATAGRAM {
            return Err(Error::DatagramTooLarge {
                len: end,
                max: MAX_REASM_DATAGRAM,
            });
        }
        // 8-byte alignment: only the LAST fragment may carry a
        // non-multiple-of-8 length; earlier fragments with a tail
        // break the 8-byte grid and are malformed (RFC 791).
        if pkt.more_fragments() && !len.is_multiple_of(8) {
            return Err(Error::Malformed("ipv4: non-final fragment not 8-aligned"));
        }
        // Overlap detection against every tracked range.
        for r in self.ranges.iter().flatten() {
            if start < r.end && r.start < end {
                // Intersection: attack traffic (teardrop/bonk shapes
                // and duplicate retransmissions alike — an honest
                // duplicate retransmission also lands here and is
                // dropped with the datagram; the peer's transport
                // re-sends the whole set if it cares).
                return Err(Error::FragmentOverlap);
            }
        }
        // The FINAL fragment (MF clear) publishes the datagram's
        // total end — remember it (an MF-clear fragment at ANY
        // offset is the honest total-length oracle).
        if !pkt.more_fragments() {
            self.final_end = Some(end);
        }
        // Copy the bytes (bounds proven above).
        self.data[start..end].copy_from_slice(pkt.payload);
        // Insert keeping the ranges sorted + disjoint.
        let mut inserted = None;
        for (i, r) in self.ranges.iter().enumerate() {
            match r {
                Some(cur) if cur.start < start => continue,
                Some(_) | None => {
                    // Free tail slot?
                    if self.ranges[MAX_FRAG_HOLES - 1].is_some() {
                        return Err(Error::FragmentHoleCount);
                    }
                    // Shift right from position i.
                    let mut j = MAX_FRAG_HOLES - 1;
                    while j > i {
                        self.ranges[j] = self.ranges[j - 1];
                        j -= 1;
                    }
                    self.ranges[i] = Some(FragRange { start, end });
                    inserted = Some(i);
                    break;
                }
            }
        }
        if inserted.is_none() {
            // The insertion loop walked past every entry without
            // breaking: all present entries start before ours, so
            // this range appends at the packed tail. (The invariant
            // is packed order — a free tail slot is the ONLY legal
            // landing spot; anything else is a hole-count error.)
            match self.ranges.iter_mut().find(|r| r.is_none()) {
                Some(slot) => *slot = Some(FragRange { start, end }),
                None => return Err(Error::FragmentHoleCount),
            }
        }
        self.fragments = self.fragments.saturating_add(1);
        // Completion: the packed, sorted ranges must cover [0, total)
        // contiguously AND the final fragment's published end must
        // equal that total (the MF=0 oracle — without it, any first
        // fragment would look "complete"). Indexed walk (not
        // `flatten`): the first None ends the set by the
        // packed-insert invariant, and `take_completed` re-verifies
        // independently.
        let mut covered = 0usize;
        let mut contiguous = true;
        for r in self.ranges.iter() {
            match r {
                Some(fr) => {
                    if fr.start != covered {
                        contiguous = false;
                        break;
                    }
                    covered = fr.end;
                }
                None => break,
            }
        }
        let complete = contiguous && covered > 0 && self.final_end == Some(covered);
        if complete {
            Ok(Some(covered))
        } else {
            Ok(None)
        }
    }
}

/// The fixed reassembly pool. One `feed` per received fragment; the
/// stack frees slots on completion, invalidation, or timeout.
#[derive(Debug)]
pub struct ReassemblyPool {
    slots: [ReasmSlot; MAX_REASM_SLOTS],
    /// Stats for THREAT_MODEL.md counters.
    pub datagrams_completed: u64,
    pub datagrams_dropped_overlap: u64,
    pub datagrams_dropped_timeout: u64,
    pub datagrams_dropped_full: u64,
}

impl Default for ReassemblyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyPool {
    pub const fn new() -> ReassemblyPool {
        ReassemblyPool {
            slots: [ReasmSlot {
                src: [0; 4],
                dst: [0; 4],
                id: 0,
                protocol: 0,
                data: [0; MAX_REASM_DATAGRAM],
                ranges: [None; MAX_FRAG_HOLES],
                final_end: None,
                started_at: 0,
                fragments: 0,
            }; MAX_REASM_SLOTS],
            datagrams_completed: 0,
            datagrams_dropped_overlap: 0,
            datagrams_dropped_timeout: 0,
            datagrams_dropped_full: 0,
        }
    }

    /// Feed a fragment. On completion returns the fully assembled
    /// transport payload COPY end — the caller reads it via
    /// [`ReassemblyPool::take_completed`] to keep borrows short.
    /// `Err` results drop the whole datagram and free its slot.
    pub fn feed(&mut self, now: u64, pkt: &Ipv4Packet<'_>) -> Result<Option<usize>> {
        // Find this datagram's slot (matching 4-tuple + id + proto),
        // else take a free one (reset first), else drop the fragment.
        let mut slot_idx = None;
        for (i, s) in self.slots.iter().enumerate() {
            if s.id == pkt.id && s.protocol == pkt.protocol && s.src == pkt.src && s.dst == pkt.dst
            {
                slot_idx = Some(i);
                break;
            }
        }
        if slot_idx.is_none() {
            for (i, s) in self.slots.iter_mut().enumerate() {
                if s.fragments == 0 {
                    s.reset();
                    s.src = pkt.src;
                    s.dst = pkt.dst;
                    s.id = pkt.id;
                    s.protocol = pkt.protocol;
                    s.started_at = now;
                    slot_idx = Some(i);
                    break;
                }
            }
        }
        let Some(i) = slot_idx else {
            self.datagrams_dropped_full += 1;
            return Err(Error::ReassemblyFull);
        };
        match self.slots[i].feed(pkt) {
            Ok(Some(len)) => {
                self.datagrams_completed += 1;
                Ok(Some(len))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                if e == Error::FragmentOverlap {
                    self.datagrams_dropped_overlap += 1;
                }
                self.slots[i].reset();
                Err(e)
            }
        }
    }

    /// Copy out a completed datagram (call right after a completing
    /// `feed` returned `Some(len)`). Copies into `out` (bounds
    /// checked), then frees the slot. The walk re-verifies the
    /// contiguity invariant independently of `feed`.
    pub fn take_completed(
        &mut self,
        src: &[u8; 4],
        id: u16,
        protocol: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        for s in self.slots.iter_mut() {
            if s.fragments > 0 && s.id == id && s.protocol == protocol && s.src == *src {
                let mut total = 0usize;
                let mut exp = 0usize;
                for r in s.ranges.iter() {
                    match r {
                        Some(fr) => {
                            if fr.start != exp {
                                return Err(Error::Malformed("reasm: take on incomplete"));
                            }
                            exp = fr.end;
                            total = exp;
                        }
                        None => break,
                    }
                }
                if total == 0 || s.final_end != Some(total) {
                    return Err(Error::Malformed("reasm: take on incomplete"));
                }
                if out.len() < total {
                    return Err(Error::Truncated {
                        need: total,
                        have: out.len(),
                    });
                }
                out[..total].copy_from_slice(&s.data[..total]);
                s.reset();
                return Ok(total);
            }
        }
        Err(Error::Malformed("reasm: no such datagram"))
    }

    /// Age out incomplete datagrams. Returns how many timed out.
    pub fn tick(&mut self, now: u64) -> usize {
        let mut timed_out = 0;
        for s in self.slots.iter_mut() {
            if s.fragments > 0 && now.saturating_sub(s.started_at) >= REASM_TIMEOUT_MS {
                s.reset();
                timed_out += 1;
            }
        }
        self.datagrams_dropped_timeout += timed_out as u64;
        timed_out
    }

    /// Slots currently holding fragments (diagnostics).
    pub fn active(&self) -> usize {
        self.slots.iter().filter(|s| s.fragments > 0).count()
    }
}

/// Build one fragment's IPv4 packet for a payload the stack is
/// SPLITTING at the egress MTU (used when a transport payload
/// exceeds the MTU and DF is clear). Writes header + this
/// fragment's payload slice into `out`; returns bytes written.
///
/// Fragmentation math is checked end-to-end: offsets are 8-aligned,
/// the last fragment carries the tail, and the id is shared across
/// the fragment set.
/// (clippy::too_many_arguments is deliberate: the parameters ARE
/// the wire format's fields.)
#[allow(clippy::too_many_arguments)]
pub fn emit_fragment(
    out: &mut [u8],
    id: u16,
    frag_offset_bytes_val: usize,
    more: bool,
    ttl: u8,
    protocol: u8,
    src: &[u8; 4],
    dst: &[u8; 4],
    payload: &[u8],
) -> Result<usize> {
    if !frag_offset_bytes_val.is_multiple_of(8) {
        return Err(Error::InvalidArgument(
            "ipv4: fragment offset must be 8-aligned",
        ));
    }
    let total_len = IPV4_MIN_HDR
        .checked_add(payload.len())
        .and_then(|t| u16::try_from(t).ok())
        .ok_or(Error::DatagramTooLarge {
            len: usize::MAX,
            max: MAX_REASM_DATAGRAM,
        })?;
    // Offset units must fit the 13-bit field.
    let off_units = frag_offset_bytes_val / 8;
    if off_units > 0x1fff {
        return Err(Error::InvalidArgument("ipv4: fragment offset > 13 bits"));
    }
    let flags_frag = (off_units as u16) | if more { 0x2000 } else { 0 };
    let n = emit_header(out, total_len, id, flags_frag, ttl, protocol, src, dst)?;
    if out.len() < n + payload.len() {
        return Err(Error::Truncated {
            need: n + payload.len(),
            have: out.len(),
        });
    }
    out[n..n + payload.len()].copy_from_slice(payload);
    Ok(n + payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkpkt(buf: &mut [u8], total: u16, id: u16, flags_frag: u16, payload: &[u8]) {
        emit_header(
            buf,
            total,
            id,
            flags_frag,
            64,
            PROTO_UDP,
            &[1, 1, 1, 1],
            &[2, 2, 2, 2],
        )
        .unwrap();
        buf[20..20 + payload.len()].copy_from_slice(payload);
    }

    #[test]
    fn checksum_known_vector() {
        // RFC 1071's worked example: 0x0001f203f4f5f6f7 → 0x220e
        // (sum 0xddf2, complement 0x220d — recomputed honestly here:
        // 0x0001+0xf203+0xf4f5+0xf6f7 = 0x2ddf0 → fold 0xddf2 →
        // !0xddf2 = 0x220d).
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum16(&data), 0x220d);
    }

    #[test]
    fn header_round_trip_and_checksum() {
        let mut buf = [0u8; 20 + 8];
        mkpkt(&mut buf, 28, 7, 0, b"abcdefgh");
        let p = Ipv4Packet::parse(&buf).unwrap();
        assert_eq!(p.total_len, 28);
        assert_eq!(p.id, 7);
        assert_eq!(p.protocol, PROTO_UDP);
        assert_eq!(p.payload, b"abcdefgh".as_slice());
        assert!(!p.is_fragment());
    }

    #[test]
    fn tampered_checksum_refused() {
        let mut buf = [0u8; 20 + 8];
        mkpkt(&mut buf, 28, 7, 0, b"abcdefgh");
        buf[20] ^= 0xff; // payload flip: header cksum still valid,
                         // this test targets the HEADER:
        let mut hdr_only = [0u8; 28];
        hdr_only.copy_from_slice(&buf);
        // Flip a header byte.
        let mut bad = hdr_only;
        bad[9] ^= 0x01;
        assert_eq!(Ipv4Packet::parse(&bad), Err(Error::BadIpChecksum));
    }

    #[test]
    fn total_len_lies_are_refused() {
        let mut buf = [0u8; 20 + 4];
        mkpkt(&mut buf, 24, 1, 0, b"abcd");
        // Claim 60 bytes while carrying 24.
        buf[2] = 0;
        buf[3] = 60;
        // Fix the checksum for the new total_len so the ONLY lie is
        // the length (the classic overread probe).
        let ck = checksum16(&buf[..20]);
        buf[10] = (ck >> 8) as u8;
        buf[11] = ck as u8;
        assert_eq!(
            Ipv4Packet::parse(&buf),
            Err(Error::Malformed("ipv4: total_len > frame"))
        );
    }

    #[test]
    fn truncated_and_bad_version_refused() {
        assert_eq!(
            Ipv4Packet::parse(&[0u8; 19]),
            Err(Error::Truncated { need: 20, have: 19 })
        );
        let mut buf = [0u8; 28];
        mkpkt(&mut buf, 28, 1, 0, b"abcdefgh");
        buf[0] = 0x55; // version 5
        assert_eq!(Ipv4Packet::parse(&buf), Err(Error::BadIpVersion(5)));
    }

    #[test]
    fn reassembly_two_fragments_complete() {
        let mut pool = ReassemblyPool::new();
        // 1000-byte datagram: fragment 0 = 992 B at offset 0 (124
        // units, MF), fragment 1 = 8 B at offset 992 (124 units,
        // final). Both ends within the 1480-B slot cap.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut f0 = [0u8; 20 + 992];
        mkpkt(&mut f0, 1012, 42, 0x2000, &payload[..992]);
        let p0 = Ipv4Packet::parse(&f0).unwrap();
        assert_eq!(pool.feed(0, &p0).unwrap(), None);
        let mut f1 = [0u8; 20 + 8];
        mkpkt(&mut f1, 28, 42, 124, &payload[992..]);
        let p1 = Ipv4Packet::parse(&f1).unwrap();
        assert_eq!(pool.feed(1, &p1).unwrap(), Some(1000));
        let mut out = [0u8; 1000];
        let n = pool
            .take_completed(&[1, 1, 1, 1], 42, PROTO_UDP, &mut out)
            .unwrap();
        assert_eq!(n, 1000);
        assert_eq!(&out[..1000], payload.as_slice());
        assert_eq!(pool.active(), 0);
    }

    #[test]
    fn overlapping_fragment_refuses_whole_datagram() {
        let mut pool = ReassemblyPool::new();
        let payload: Vec<u8> = (0..16u32).map(|i| i as u8).collect();
        // Fragment A: offset 0, 16 bytes, MF.
        let mut fa = [0u8; 20 + 16];
        mkpkt(&mut fa, 36, 5, 0x2000, &payload);
        let pa = Ipv4Packet::parse(&fa).unwrap();
        assert_eq!(pool.feed(0, &pa).unwrap(), None);
        // Fragment B: offset 8 (OVERLAPS A's [0,16)), 8 bytes.
        let mut fb = [0u8; 20 + 8];
        mkpkt(&mut fb, 28, 5, 1, &payload[8..16]);
        let pb = Ipv4Packet::parse(&fb).unwrap();
        assert_eq!(pool.feed(1, &pb), Err(Error::FragmentOverlap));
        // The whole datagram is gone: the slot was freed.
        assert_eq!(pool.active(), 0);
        assert_eq!(pool.datagrams_dropped_overlap, 1);
        // A completion attempt now fails: no such datagram.
        let mut out = [0u8; 64];
        assert!(pool
            .take_completed(&[1, 1, 1, 1], 5, PROTO_UDP, &mut out)
            .is_err());
    }

    #[test]
    fn reassembly_timeout_frees_slot() {
        let mut pool = ReassemblyPool::new();
        let mut fa = [0u8; 20 + 16];
        mkpkt(&mut fa, 36, 6, 0x2000, b"0123456789abcdef");
        let pa = Ipv4Packet::parse(&fa).unwrap();
        pool.feed(0, &pa).unwrap();
        assert_eq!(pool.active(), 1);
        // Before the timeout: still active.
        assert_eq!(pool.tick(REASM_TIMEOUT_MS - 1), 0);
        // At/after: swept.
        assert_eq!(pool.tick(REASM_TIMEOUT_MS), 1);
        assert_eq!(pool.active(), 0);
        // And the freed slot is reusable for the same id.
        assert_eq!(pool.feed(REASM_TIMEOUT_MS, &pa).unwrap(), None);
        assert_eq!(pool.active(), 1);
    }

    #[test]
    fn oversized_reassembly_refused() {
        let mut pool = ReassemblyPool::new();
        // A fragment that would end beyond the 1480-B cap.
        let mut fa = [0u8; 20 + 8];
        mkpkt(&mut fa, 28, 8, 0x2000, b"ABCDEFGH");
        let pa = Ipv4Packet::parse(&fa).unwrap();
        pool.feed(0, &pa).unwrap();
        // Second fragment at offset 1472, len 16 → end 1488 > 1480.
        let mut fb = [0u8; 20 + 16];
        mkpkt(&mut fb, 36, 8, 184, b"0123456789abcdef"); // 184*8=1472
        let pb = Ipv4Packet::parse(&fb).unwrap();
        assert_eq!(
            pool.feed(1, &pb),
            Err(Error::DatagramTooLarge {
                len: 1488,
                max: MAX_REASM_DATAGRAM
            })
        );
    }

    #[test]
    fn nonfinal_fragment_must_be_8_aligned() {
        let mut pool = ReassemblyPool::new();
        let mut fa = [0u8; 20 + 9]; // 9 bytes with MF set: malformed
        mkpkt(&mut fa, 29, 9, 0x2000, b"123456789");
        let pa = Ipv4Packet::parse(&fa).unwrap();
        assert_eq!(
            pool.feed(0, &pa),
            Err(Error::Malformed("ipv4: non-final fragment not 8-aligned"))
        );
    }

    #[test]
    fn emit_fragment_shape() {
        let mut out = [0u8; 20 + 8];
        let n = emit_fragment(
            &mut out,
            3,
            0,
            true,
            64,
            PROTO_UDP,
            &[9, 9, 9, 9],
            &[1, 1, 1, 1],
            &[8, 8, 8, 8, 8, 8, 8, 8],
        )
        .unwrap();
        assert_eq!(n, 28);
        let p = Ipv4Packet::parse(&out).unwrap();
        assert!(p.more_fragments());
        assert_eq!(p.frag_offset(), 0);
        assert_eq!(p.payload.len(), 8);
        // Offset must be 8-aligned: 12 is refused.
        assert_eq!(
            emit_fragment(
                &mut out,
                3,
                12,
                true,
                64,
                PROTO_UDP,
                &[9, 9, 9, 9],
                &[1, 1, 1, 1],
                &[0u8; 8]
            ),
            Err(Error::InvalidArgument(
                "ipv4: fragment offset must be 8-aligned"
            ))
        );
    }
}
