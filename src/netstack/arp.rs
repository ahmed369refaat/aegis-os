//! ARP: address resolution for IPv4 over Ethernet (K24).
//!
//! ## What this module owns
//!
//! - [`ArpPacket`] parse/emit for request/reply (hardware = Ethernet,
//!   protocol = IPv4 — the only pairing the stack speaks; anything
//!   else is refused with the fields named, never guessed).
//! - [`ArpCache`]: a fixed [`MAX_ARP_ENTRIES`] table with absolute
//!   expiry (every entry dies at `now + ENTRY_TTL_MS`; nothing lives
//!   forever — THREAT_MODEL.md §Resource Exhaustion).
//! - [`ArpLayer`]: the resolver the stack's egress path drives —
//!   cache hit, or an in-flight request with a bounded retry budget,
//!   and the input path that answers requests for OUR address and
//!   caches gratuitous announcements.
//!
//! ## Threat model (THREAT_MODEL.md §Malformed, §Resource Exhaustion)
//!
//! - The 28-byte packet is validated in full (length, htype/ptype,
//!   hlen/plen) before any address is trusted.
//! - The cache is a FIXED array. A remote attacker spraying 10,000
//!   spoofed ARP replies can at most rotate [`MAX_ARP_ENTRIES`]
//!   entries; there is no allocation to exhaust.
//! - Expiry bounds the damage of a POISONED entry: a spoofed mapping
//!   ages out in [`ENTRY_TTL_MS`], and the stack re-asks.
//! - Unrequested replies (gratuitous ARP) update the cache ONLY for
//!   an address that already has an entry OR overwrite the oldest
//!   slot — they cannot grow the table beyond its bound, and they
//!   never bypass the expiry clock.
//! - Reply emission (answering a request) is bounded by the caller's
//!   frame sink (the broker): this module never emits on its own.
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use super::error::{Error, Result};
use super::ethernet::{emit as eth_emit, EthFrame, EtherType, MacAddr};
use super::FrameSink;

/// One ARP packet for Ethernet/IPv4: 28 bytes on the wire.
pub const ARP_PKT_LEN: usize = 28;
/// Hardware type: Ethernet.
pub const HTYPE_ETHERNET: u16 = 1;
/// Protocol type: IPv4 (same numbering as EtherType).
pub const PTYPE_IPV4: u16 = 0x0800;

/// A parsed ARP packet. All fields big-endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    /// Sender hardware (MAC) address.
    pub sha: MacAddr,
    /// Sender protocol (IPv4) address.
    pub spa: [u8; 4],
    /// Target hardware address (meaningful in replies).
    pub tha: MacAddr,
    /// Target protocol address.
    pub tpa: [u8; 4],
}

/// The two operations the stack acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
}

impl ArpPacket {
    /// Parse and validate a 28-byte ARP packet. Every field is
    /// checked BEFORE the packet is acted on: a wrong htype/ptype or
    /// hlen/plen is [`Error::Malformed`] — the stack must not resolve
    /// addresses for protocols it does not speak.
    pub fn parse(buf: &[u8]) -> Result<ArpPacket> {
        if buf.len() < ARP_PKT_LEN {
            return Err(Error::Truncated {
                need: ARP_PKT_LEN,
                have: buf.len(),
            });
        }
        let htype = ((buf[0] as u16) << 8) | buf[1] as u16;
        let ptype = ((buf[2] as u16) << 8) | buf[3] as u16;
        let hlen = buf[4];
        let plen = buf[5];
        if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 {
            return Err(Error::Malformed("arp: htype/ptype/hlen/plen mismatch"));
        }
        let op = match ((buf[6] as u16) << 8) | buf[7] as u16 {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            _ => return Err(Error::Malformed("arp: op")),
        };
        Ok(ArpPacket {
            op,
            sha: MacAddr([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13]]),
            spa: [buf[14], buf[15], buf[16], buf[17]],
            tha: MacAddr([buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]),
            tpa: [buf[24], buf[25], buf[26], buf[27]],
        })
    }

    /// Emit into `out` (28 bytes). Bounds-checked before any write.
    pub fn emit(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < ARP_PKT_LEN {
            return Err(Error::Truncated {
                need: ARP_PKT_LEN,
                have: out.len(),
            });
        }
        out[0] = (HTYPE_ETHERNET >> 8) as u8;
        out[1] = HTYPE_ETHERNET as u8;
        out[2] = (PTYPE_IPV4 >> 8) as u8;
        out[3] = PTYPE_IPV4 as u8;
        out[4] = 6;
        out[5] = 4;
        out[6] = 0;
        out[7] = match self.op {
            ArpOp::Request => 1,
            ArpOp::Reply => 2,
        };
        out[8..14].copy_from_slice(&self.sha.0);
        out[14..18].copy_from_slice(&self.spa);
        out[18..24].copy_from_slice(&self.tha.0);
        out[24..28].copy_from_slice(&self.tpa);
        Ok(ARP_PKT_LEN)
    }
}

/// One cache entry: a resolved mapping with an absolute expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: [u8; 4],
    pub mac: MacAddr,
    /// Absolute `now` (ms ticks) at which this entry dies.
    pub expires_at: u64,
}

/// The fixed-size ARP cache. [`MAX_ARP_ENTRIES`] slots; lookups of
/// expired entries return `None` AND clear the slot (lazy expiry),
/// [`ArpCache::tick`] sweeps them all.
#[derive(Debug)]
pub struct ArpCache {
    entries: [Option<ArpEntry>; MAX_ARP_ENTRIES],
}

/// Cache capacity. Small by design: one per host on the local link
/// we actually talk to (gateway + a few peers). Attackers cannot
/// grow it.
pub const MAX_ARP_ENTRIES: usize = 16;
/// Entry lifetime. Bounded: a poisoned entry self-heals within this
/// window even if nobody notices.
pub const ENTRY_TTL_MS: u64 = 60_000;

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpCache {
    pub const fn new() -> ArpCache {
        ArpCache {
            entries: [None; MAX_ARP_ENTRIES],
        }
    }

    /// Look up `ip` at time `now`. Expired entries return `None` and
    /// free their slot immediately (the memory is reclaimed, not
    /// just ignored).
    pub fn lookup(&mut self, ip: &[u8; 4], now: u64) -> Option<MacAddr> {
        for slot in self.entries.iter_mut() {
            if let Some(e) = *slot {
                if &e.ip == ip {
                    if now < e.expires_at {
                        return Some(e.mac);
                    }
                    // Expired: reclaim now, fail the lookup.
                    *slot = None;
                    return None;
                }
            }
        }
        None
    }

    /// Insert or refresh `ip -> mac` expiring at `now + ttl`.
    /// Policy (THREAT_MODEL.md §Malformed): an update from the WIRE
    /// (gratuitous/unrequested reply) may only refresh an EXISTING
    /// entry or take a FREE slot or evict the entry with the SOONEST
    /// expiry — it can never allocate beyond the fixed bound, and it
    /// can never extend an entry's remaining lifetime past one TTL
    /// from `now`.
    pub fn upsert(&mut self, ip: &[u8; 4], mac: &MacAddr, now: u64) {
        let expiry = now.saturating_add(ENTRY_TTL_MS);
        // Refresh in place if present.
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot.as_mut() {
                if &e.ip == ip {
                    e.mac = *mac;
                    e.expires_at = expiry;
                    return;
                }
            }
        }
        // Free slot?
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(ArpEntry {
                    ip: *ip,
                    mac: *mac,
                    expires_at: expiry,
                });
                return;
            }
        }
        // Evict the soonest-to-die entry — bounded table, honest
        // victim selection (the least valuable mapping by time left).
        let mut victim = 0usize;
        let mut soonest = u64::MAX;
        for (i, slot) in self.entries.iter().enumerate() {
            if let Some(e) = slot {
                if e.expires_at < soonest {
                    soonest = e.expires_at;
                    victim = i;
                }
            }
        }
        self.entries[victim] = Some(ArpEntry {
            ip: *ip,
            mac: *mac,
            expires_at: expiry,
        });
    }

    /// Sweep expired entries (called from the stack's poll loop).
    pub fn tick(&mut self, now: u64) -> usize {
        let mut swept = 0;
        for slot in self.entries.iter_mut() {
            if let Some(e) = *slot {
                if now >= e.expires_at {
                    *slot = None;
                    swept += 1;
                }
            }
        }
        swept
    }

    /// Number of live entries (diagnostics/tests).
    pub fn live(&self) -> usize {
        self.entries.iter().filter(|s| s.is_some()).count()
    }
}

/// The input/output event the resolver reports to the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEvent {
    /// A reply resolved an address the stack had asked about (the
    /// egress path flushes its pending frame).
    Resolved([u8; 4]),
    /// A request for OUR address was answered (a reply was emitted
    /// through the sink).
    Answered,
    /// A gratuitous announcement was cached.
    Announced,
    /// Nothing the stack must act on.
    None,
}

/// The resolver: cache + ONE in-flight request with a bounded retry
/// budget. Single outstanding request is deliberate
/// (THREAT_MODEL.md §Resource Exhaustion): the stack serializes
/// resolution attempts so a link full of unresolvable destinations
/// costs one request's worth of state, not one per destination.
#[derive(Debug)]
pub struct ArpLayer {
    our_mac: MacAddr,
    our_ip: [u8; 4],
    cache: ArpCache,
    in_flight: Option<InFlight>,
    /// Requests answered (gratuitous included) — for counters.
    pub requests_answerered: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    target: [u8; 4],
    /// Absolute deadline of the NEXT retry.
    next_retry_at: u64,
    /// Retries already sent (bounded by `MAX_ARP_RETRIES`).
    tries: u8,
}

/// Resolution attempts per address before the stack gives up and
/// reports [`Error::TimedOut`] to the pending egress.
pub const MAX_ARP_RETRIES: u8 = 3;
/// Delay between ARP retries.
pub const RETRY_MS: u64 = 1_000;

impl ArpLayer {
    pub const fn new(our_mac: MacAddr, our_ip: [u8; 4]) -> ArpLayer {
        ArpLayer {
            our_mac,
            our_ip,
            cache: ArpCache::new(),
            in_flight: None,
            requests_answerered: 0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Resolve `ip`: cache hit, else start/continue a request. The
    /// caller's `sink` carries the request frame (the broker — this
    /// layer has no device access). On a miss the caller should
    /// treat egress as [`Error::ArpPending`] and retry after a poll
    /// cycle; the request itself is (re)sent here.
    pub fn resolve(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        ip: &[u8; 4],
    ) -> Result<Option<MacAddr>> {
        if let Some(mac) = self.cache.lookup(ip, now) {
            self.cache_hits += 1;
            self.in_flight = None; // resolved; cancel any request
            return Ok(Some(mac));
        }
        self.cache_misses += 1;
        // Same address already in flight? Retransmit only past the
        // retry deadline.
        if let Some(f) = &mut self.in_flight {
            if &f.target == ip {
                if now >= f.next_retry_at {
                    if f.tries >= MAX_ARP_RETRIES {
                        // Give up: report timeout, clear the slot.
                        self.in_flight = None;
                        return Err(Error::TimedOut);
                    }
                    f.tries += 1;
                    f.next_retry_at = now.saturating_add(RETRY_MS);
                    self.send_request(now, sink, ip)?;
                }
                return Ok(None);
            }
            // A DIFFERENT address: replace the in-flight request
            // (serialized resolution — the old target's pending
            // frame was already reported as ArpPending to its
            // caller, which retries; TCP retransmits, UDP callers
            // re-send).
            self.in_flight = None;
        }
        self.in_flight = Some(InFlight {
            target: *ip,
            next_retry_at: now.saturating_add(RETRY_MS),
            tries: 1,
        });
        self.send_request(now, sink, ip)?;
        Ok(None)
    }

    /// Direct cache probe without side effects (tests/diagnostics).
    pub fn probe(&mut self, ip: &[u8; 4], now: u64) -> Option<MacAddr> {
        self.cache.lookup(ip, now)
    }

    /// The input path: one ARP packet from the wire. May emit a
    /// REPLY (through the caller's sink) when the request targets our
    /// address; caches sender mappings for requests AND replies.
    pub fn on_packet(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        pkt: &ArpPacket,
    ) -> Result<ArpEvent> {
        // THREAT_MODEL.md §Malformed: the sender pair (sha, spa) is
        // cached from BOTH request and reply — a request's sender
        // fields are as spoofable as a reply's, but the cache bound
        // and TTL make either a bounded, self-healing event.
        // Ethernet source 0.0.0.0 style probes (spa = 0) are ignored:
        // they carry no mapping worth keeping.
        if pkt.spa != [0, 0, 0, 0] {
            self.cache.upsert(&pkt.spa, &pkt.sha, now);
        }
        match pkt.op {
            ArpOp::Request => {
                if pkt.tpa == self.our_ip {
                    self.requests_answerered += 1;
                    let reply = ArpPacket {
                        op: ArpOp::Reply,
                        sha: self.our_mac,
                        spa: self.our_ip,
                        tha: pkt.sha,
                        tpa: pkt.spa,
                    };
                    self.transmit(now, sink, &reply, &pkt.sha)?;
                    Ok(ArpEvent::Answered)
                } else {
                    Ok(ArpEvent::None)
                }
            }
            ArpOp::Reply => {
                // Gratuitous (spa == tpa) or an answer to our request.
                if let Some(f) = self.in_flight {
                    if f.target == pkt.spa {
                        self.in_flight = None;
                        return Ok(ArpEvent::Resolved(pkt.spa));
                    }
                }
                if pkt.spa == pkt.tpa {
                    Ok(ArpEvent::Announced)
                } else {
                    Ok(ArpEvent::None)
                }
            }
        }
    }

    /// Sweep expired cache entries (the stack's poll loop).
    pub fn sweep(&mut self, now: u64) -> usize {
        self.cache.tick(now)
    }

    /// Drive retry deadlines. Returns the address given up on, if any.
    pub fn poll(&mut self, now: u64, sink: &mut dyn FrameSink) -> Result<Option<[u8; 4]>> {
        let Some(f) = self.in_flight else {
            return Ok(None);
        };
        if now >= f.next_retry_at {
            if f.tries >= MAX_ARP_RETRIES {
                let target = f.target;
                self.in_flight = None;
                return Ok(Some(target));
            }
            let target = f.target;
            let tries = f.tries + 1;
            self.in_flight = Some(InFlight {
                target,
                next_retry_at: now.saturating_add(RETRY_MS),
                tries,
            });
            self.send_request(now, sink, &target)?;
        }
        Ok(None)
    }

    fn send_request(&mut self, now: u64, sink: &mut dyn FrameSink, ip: &[u8; 4]) -> Result<()> {
        let req = ArpPacket {
            op: ArpOp::Request,
            sha: self.our_mac,
            spa: self.our_ip,
            tha: MacAddr::ZERO,
            tpa: *ip,
        };
        self.transmit(now, sink, &req, &MacAddr::BROADCAST)
    }

    /// Build and send one ARP frame through the sink. Every egress
    /// path in this module funnels here — there is exactly one way
    /// out, and it is the broker's.
    fn transmit(
        &mut self,
        _now: u64,
        sink: &mut dyn FrameSink,
        pkt: &ArpPacket,
        dst_mac: &MacAddr,
    ) -> Result<()> {
        let mut arpbuf = [0u8; ARP_PKT_LEN];
        let arp_len = pkt.emit(&mut arpbuf)?;
        let mut frame = [0u8; super::ethernet::ETH_HDR_LEN + ARP_PKT_LEN];
        let n = eth_emit(
            &mut frame,
            dst_mac,
            &self.our_mac,
            EtherType::Arp,
            &arpbuf[..arp_len],
        )?;
        sink.send_frame(&frame[..n])
    }
}

/// Convenience: parse a raw Ethernet frame's payload as ARP when the
/// EtherType already says so (the stack's dispatch calls this).
pub fn parse_from_eth(eth: &EthFrame<'_>) -> Result<ArpPacket> {
    ArpPacket::parse(eth.payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CollectSink {
        pub frames: Vec<Vec<u8>>,
    }

    impl FrameSink for CollectSink {
        fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
            self.frames.push(frame.to_vec());
            Ok(())
        }
    }

    fn mac(n: u8) -> MacAddr {
        MacAddr([0x02, 0, 0, 0, 0, n])
    }
    fn ip(n: u8) -> [u8; 4] {
        [10, 0, 0, n]
    }

    #[test]
    fn parse_emit_round_trip() {
        let p = ArpPacket {
            op: ArpOp::Request,
            sha: mac(1),
            spa: ip(1),
            tha: MacAddr::ZERO,
            tpa: ip(2),
        };
        let mut buf = [0u8; ARP_PKT_LEN];
        assert_eq!(p.emit(&mut buf).unwrap(), ARP_PKT_LEN);
        assert_eq!(ArpPacket::parse(&buf).unwrap(), p);
    }

    #[test]
    fn truncated_and_malformed_arp_refused() {
        assert_eq!(
            ArpPacket::parse(&[0u8; 27]),
            Err(Error::Truncated { need: 28, have: 27 })
        );
        // Wrong ptype (IPv6): refused, fields named.
        let mut buf = [0u8; 28];
        buf[2] = 0x86;
        buf[3] = 0xdd;
        assert_eq!(
            ArpPacket::parse(&buf),
            Err(Error::Malformed("arp: htype/ptype/hlen/plen mismatch"))
        );
        // Unknown op — with VALID htype/ptype/hlen/plen so the op
        // check is the one that fires.
        let mut buf = [0u8; 28];
        buf[0] = 0;
        buf[1] = 1; // htype 1 (Ethernet)
        buf[2] = 0x08;
        buf[3] = 0x00; // ptype IPv4
        buf[4] = 6;
        buf[5] = 4;
        buf[6] = 0;
        buf[7] = 9;
        assert_eq!(ArpPacket::parse(&buf), Err(Error::Malformed("arp: op")));
    }

    #[test]
    fn cache_insert_lookup_expire() {
        let mut c = ArpCache::new();
        c.upsert(&ip(7), &mac(7), 0);
        assert_eq!(c.lookup(&ip(7), 1000), Some(mac(7)));
        assert_eq!(c.lookup(&ip(8), 1000), None);
        // Past TTL: gone AND the slot is free.
        assert_eq!(c.lookup(&ip(7), ENTRY_TTL_MS + 1), None);
        assert_eq!(c.live(), 0);
    }

    #[test]
    fn cache_bounded_evicts_soonest_expiry() {
        let mut c = ArpCache::new();
        for i in 0..MAX_ARP_ENTRIES as u8 {
            c.upsert(&ip(i), &mac(i), 0);
        }
        // Insert one more: evicts entry 0 (all expire together, victim
        // = first soonest). Table stays at MAX.
        c.upsert(&ip(99), &mac(99), 5000);
        assert_eq!(c.live(), MAX_ARP_ENTRIES);
        assert_eq!(c.lookup(&ip(99), 6000), Some(mac(99)));
        assert_eq!(c.lookup(&ip(0), 6000), None);
    }

    #[test]
    fn layer_answers_request_and_caches_sender() {
        let mut sink = CollectSink { frames: Vec::new() };
        let mut layer = ArpLayer::new(mac(1), ip(1));
        let req = ArpPacket {
            op: ArpOp::Request,
            sha: mac(2),
            spa: ip(2),
            tha: MacAddr::BROADCAST,
            tpa: ip(1),
        };
        let ev = layer.on_packet(100, &mut sink, &req).unwrap();
        assert_eq!(ev, ArpEvent::Answered);
        // One reply emitted, unicast to the requester, carrying OUR pair.
        assert_eq!(sink.frames.len(), 1);
        let f = EthFrame::parse(&sink.frames[0]).unwrap();
        assert_eq!(f.ethertype, EtherType::Arp);
        assert_eq!(f.dst, mac(2));
        let reply = ArpPacket::parse(f.payload).unwrap();
        assert_eq!(reply.op, ArpOp::Reply);
        assert_eq!(reply.sha, mac(1));
        assert_eq!(reply.spa, ip(1));
        // The requester's mapping was cached from the REQUEST.
        assert_eq!(layer.probe(&ip(2), 200), Some(mac(2)));
    }

    #[test]
    fn layer_resolve_request_then_reply_flushes() {
        let mut sink = CollectSink { frames: Vec::new() };
        let mut layer = ArpLayer::new(mac(1), ip(1));
        // Miss → request broadcast emitted, in flight.
        assert_eq!(layer.resolve(0, &mut sink, &ip(2)).unwrap(), None);
        assert_eq!(sink.frames.len(), 1);
        assert_eq!(
            EthFrame::parse(&sink.frames[0]).unwrap().dst,
            MacAddr::BROADCAST
        );
        // The reply resolves.
        let reply = ArpPacket {
            op: ArpOp::Reply,
            sha: mac(2),
            spa: ip(2),
            tha: mac(1),
            tpa: ip(1),
        };
        let ev = layer.on_packet(10, &mut sink, &reply).unwrap();
        assert_eq!(ev, ArpEvent::Resolved(ip(2)));
        // Next resolve is a cache hit with no new frame.
        assert_eq!(layer.resolve(20, &mut sink, &ip(2)).unwrap(), Some(mac(2)));
        assert_eq!(sink.frames.len(), 1);
        assert_eq!(layer.cache_hits, 1);
    }

    #[test]
    fn gratuitous_announcement_is_cached_and_bounded() {
        let mut sink = CollectSink { frames: Vec::new() };
        let mut layer = ArpLayer::new(mac(1), ip(1));
        let g = ArpPacket {
            op: ArpOp::Reply,
            sha: mac(9),
            spa: ip(9),
            tha: MacAddr::BROADCAST,
            tpa: ip(9),
        };
        let ev = layer.on_packet(50, &mut sink, &g).unwrap();
        assert_eq!(ev, ArpEvent::Announced);
        assert_eq!(layer.probe(&ip(9), 60), Some(mac(9)));
        // And it expires like everything else.
        assert_eq!(layer.probe(&ip(9), ENTRY_TTL_MS + 51), None);
    }

    #[test]
    fn resolve_retries_then_times_out() {
        let mut sink = CollectSink { frames: Vec::new() };
        let mut layer = ArpLayer::new(mac(1), ip(1));
        assert_eq!(layer.resolve(0, &mut sink, &ip(2)).unwrap(), None); // attempt 1
                                                                        // Retries at 1s and 2s (tries 2 and 3 = MAX_ARP_RETRIES);
                                                                        // the 3s poll sees tries == MAX and gives up WITHOUT a frame.
        assert!(layer.poll(1000, &mut sink).unwrap().is_none());
        assert!(layer.poll(2000, &mut sink).unwrap().is_none());
        let gave_up = layer.poll(3000, &mut sink).unwrap();
        assert_eq!(gave_up, Some(ip(2)));
        // 3 frames: initial + 2 retransmissions — the give-up is
        // silent, not a fourth probe.
        assert_eq!(sink.frames.len(), 3);
    }
}
