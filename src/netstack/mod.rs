//! The AegisOS TCP/IP stack (K24).
//!
//! A complete, `no_std`/`no_alloc`, zero-dependency TCP/IP stack for
//! the netd (or dedicated `tcpip`) domain. Pure Rust, no `unsafe`,
//! every packet untrusted, every buffer fixed.
//!
//! ## The shape
//!
//! ```text
//!        ring-3 user domains
//!            │  (sockets API → syscalls, capability-checked)
//!            ▼
//!   ┌─────────────────────────┐
//!   │  NetStack (this module) │  ethernet → arp → ipv4
//!   │  fixed pools, no alloc  │  → icmp / udp / tcp → sockets
//!   └───────────┬─────────────┘
//!               │ FrameSink (the ONLY egress)
//!               ▼
//!      the Broker (token bucket, per-domain accounting)
//!               │
//!               ▼
//!        virtio-net (netd driver domain)
//! ```
//!
//! The stack NEVER touches a device: every frame it emits goes
//! through the caller-supplied [`FrameSink`] — in the real domain
//! that sink wraps `SYS_NET_SEND`, so the kernel broker's token
//! bucket and per-domain accounting sit under every byte
//! (THREAT_MODEL.md §Broker Bypass).
//!
//! ## Driving the stack (the domain's event loop)
//!
//! 1. Frames from the driver → [`NetStack::on_frame`] (with the
//!    current tick clock and the sink).
//! 2. Timer ticks → [`NetStack::poll`] (retransmissions, delayed
//!    ACKs, ARP retries, reassembly timeouts, TIME_WAIT expiry).
//! 3. User syscalls → [`NetStack::socket`]/`bind`/`listen`/…
//!    (all non-blocking; EAGAIN is the only "later").
//!
//! ## Time
//!
//! The stack has NO internal clock: every entry point takes `now`
//! (milliseconds, monotonically non-decreasing from the caller's
//! time source). Deterministic tests fall out (THREAT_MODEL.md
//! §Testing): the tests drive the clock by hand and every timer is
//! an absolute deadline, so late ticks are late, never lost.
//!
//! ## Randomness
//!
//! [`Entropy`] supplies the per-boot secret folded into ISNs and
//! SYN cookies. The trait is tiny (one `next_u32`) so the domain can
//! back it with whatever the platform offers; the tests back it
//! with a deterministic xorshift to pin exact sequences.

pub mod arp;
pub mod error;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod socket;
pub mod tcp;
#[cfg(test)]
pub mod tests;
pub mod udp;

pub use error::{errno, Error, Result};
pub use ethernet::{EthFrame, EtherType, MacAddr, ETH_FRAME_MAX};
pub use socket::{
    SocketKind, SocketStatus, SocketTable, AF_INET, MAX_STACK_SOCKETS, SOCK_DGRAM, SOCK_STREAM,
};

use arp::{ArpEvent, ArpLayer};
use icmp::IcmpLayer;
use ipv4::{Ipv4Packet, ReassemblyPool, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use tcp::{TcpEvent, TcpIfCfg, TcpLayer, TcpState};

/// The one egress interface: a byte-sink the stack hands COMPLETE
/// Ethernet frames to. In the netd domain this wraps the broker
/// syscall; in tests it is an in-memory collector or a token-bucket
/// simulator. There is no other way out of the stack — by
/// construction, not by convention.
pub trait FrameSink {
    /// Deliver one complete Ethernet frame. Errors surface to the
    /// caller ([`Error::RateLimited`] / EAGAIN is the throttle
    /// shape; the stack never retries egress itself, its timers
    /// re-drive transmission at the transport layer).
    fn send_frame(&mut self, frame: &[u8]) -> Result<()>;
}

/// The per-boot entropy source (ISN/cookie secret). One method, so
/// any backend fits.
pub trait Entropy {
    /// One 32-bit random value.
    fn next_u32(&mut self) -> u32;
}

/// The interface configuration: who we are on the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfCfg {
    pub mac: MacAddr,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    /// 0.0.0.0 = no gateway (on-link peers only).
    pub gateway: [u8; 4],
}

impl IfCfg {
    /// The next-hop IP for a destination (on-link → the destination;
    /// else the gateway; no gateway + off-link → NoRoute).
    pub fn next_hop(&self, dst: &[u8; 4]) -> Result<[u8; 4]> {
        let on_link = (self.ip[0] & self.netmask[0]) == (dst[0] & self.netmask[0])
            && (self.ip[1] & self.netmask[1]) == (dst[1] & self.netmask[1])
            && (self.ip[2] & self.netmask[2]) == (dst[2] & self.netmask[2])
            && (self.ip[3] & self.netmask[3]) == (dst[3] & self.netmask[3]);
        if on_link {
            Ok(*dst)
        } else if self.gateway != [0, 0, 0, 0] {
            Ok(self.gateway)
        } else {
            Err(Error::NoRoute)
        }
    }
    /// Is a packet addressed to one of OUR addresses?
    fn is_ours(&self, dst: &[u8; 4], broadcast: &[u8; 4]) -> bool {
        *dst == self.ip || *dst == *broadcast
    }
}

/// Per-stack counters (one line of honesty each; THREAT_MODEL.md
/// §Testing reads these in the tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StackStats {
    pub frames_in: u64,
    pub frames_out: u64,
    pub arp_packets: u64,
    pub ip_packets: u64,
    pub ip_checksum_drops: u64,
    pub not_for_us: u64,
    pub fragments_reassembled: u64,
    pub icmp_messages: u64,
    pub udp_datagrams: u64,
    pub tcp_segments: u64,
    pub unknown_protocol: u64,
    /// Egress refused by the sink (broker throttle): the honest
    /// back-pressure counter.
    pub egress_refused: u64,
}

/// ONE parked egress datagram awaiting ARP resolution (the
/// documented single-slot bound — THREAT_MODEL.md §Resource
/// Exhaustion: the stack never queues unboundedly; a second datagram
/// racing the same resolution is refused with
/// [`Error::ArpQueueFull`] and the caller re-sends. TCP never uses
/// this slot: its retransmission timer re-drives egress).
#[derive(Debug, Clone)]
struct PendingTx {
    dst_ip: [u8; 4],
    protocol: u8,
    data: [u8; 1500],
    len: usize,
}

/// The stack: fixed pools, one of everything, no allocation at any
/// point in its life. Sized once at construction.
#[derive(Debug)]
pub struct NetStack<E: Entropy> {
    pub cfg: IfCfg,
    arp: ArpLayer,
    reasm: ReassemblyPool,
    icmp: IcmpLayer,
    pub tcp: TcpLayer,
    pub sockets: SocketTable,
    entropy: E,
    ip_id: u16,
    pub stats: StackStats,
    /// The broadcast address implied by ip/netmask.
    broadcast: [u8; 4],
    /// The pending echo (the `ping` API): (dst, id, seq, sent_at).
    echo_pending: Option<([u8; 4], u16, u16, u64)>,
    /// Last completed echo (dst, id, seq, rtt_ms) — one slot: a
    /// second concurrent ping overwrites; the API is one-at-a-time
    /// by design.
    pub echo_last: Option<([u8; 4], u16, u16, u64)>,
    /// The parked egress datagram (see [`PendingTx`]).
    pending_tx: Option<PendingTx>,
}

impl<E: Entropy> NetStack<E> {
    /// Construct with interface config and the entropy source. The
    /// per-boot secret is folded ONCE (four draws mixed) — every
    /// ISN and cookie derives from it.
    pub fn new(cfg: IfCfg, mut entropy: E) -> NetStack<E> {
        let mut secret = entropy.next_u32();
        for _ in 0..3 {
            secret ^= entropy.next_u32().rotate_left(11);
            secret = secret.wrapping_mul(0x9e37_79b1);
        }
        let broadcast = [
            cfg.ip[0] | !cfg.netmask[0],
            cfg.ip[1] | !cfg.netmask[1],
            cfg.ip[2] | !cfg.netmask[2],
            cfg.ip[3] | !cfg.netmask[3],
        ];
        NetStack {
            arp: ArpLayer::new(cfg.mac, cfg.ip),
            reasm: ReassemblyPool::new(),
            icmp: IcmpLayer::new(),
            tcp: TcpLayer::new(secret),
            sockets: SocketTable::new(),
            entropy,
            ip_id: 0,
            stats: StackStats::default(),
            broadcast,
            echo_pending: None,
            echo_last: None,
            pending_tx: None,
            cfg,
        }
    }

    fn tcp_cfg(&self) -> TcpIfCfg {
        TcpIfCfg {
            our_ip: self.cfg.ip,
            our_mac: self.cfg.mac,
            netmask: self.cfg.netmask,
            gateway: self.cfg.gateway,
        }
    }

    // ── input path ────────────────────────────────────────────────

    /// One Ethernet frame from the driver. Untrusted from the first
    /// byte; every refusal is a counted drop, never a reply unless
    /// the protocol demands one (ARP requests for us, ICMP echo,
    /// TCP RSTs — all rate-bounded).
    pub fn on_frame(&mut self, now: u64, sink: &mut dyn FrameSink, frame: &[u8]) -> Result<()> {
        self.stats.frames_in += 1;
        let eth = match EthFrame::parse(frame) {
            Ok(f) => f,
            Err(_) => {
                // Counted ingress attempt: truncated/oversized frames
                // die here (the counter counts ATTEMPTS — the honest
                // load number).
                return Ok(());
            }
        };
        if !eth.addressed_to(&self.cfg.mac) {
            self.stats.not_for_us += 1;
            return Ok(());
        }
        match eth.ethertype {
            EtherType::Arp => {
                self.stats.arp_packets += 1;
                let pkt = match arp::ArpPacket::parse(eth.payload) {
                    Ok(p) => p,
                    Err(_) => return Ok(()), // counted in the layer's stats
                };
                let ev = self.arp.on_packet(now, sink, &pkt)?;
                if let ArpEvent::Resolved(_) = ev {
                    // The neighbor is real: flush the ONE parked
                    // datagram, if any (a refused flush — broker
                    // throttle — counts and drops; the sender's own
                    // retry policy owns re-delivery).
                    self.flush_pending_tx(now, sink);
                }
                Ok(())
            }
            EtherType::Ipv4 => self.on_ipv4(now, sink, eth.payload),
            EtherType::Unknown(_) => Ok(()), // counted by the parser
        }
    }

    fn on_ipv4(&mut self, now: u64, sink: &mut dyn FrameSink, buf: &[u8]) -> Result<()> {
        let pkt = match Ipv4Packet::parse(buf) {
            Ok(p) => p,
            Err(Error::BadIpChecksum) => {
                self.stats.ip_checksum_drops += 1;
                return Ok(());
            }
            Err(_) => return Ok(()), // malformed: counted drop
        };
        self.stats.ip_packets += 1;
        if !self.cfg.is_ours(&pkt.dst, &self.broadcast) {
            self.stats.not_for_us += 1;
            return Ok(());
        }
        // Fragmented? Reassemble (bounded pool, overlap refusal).
        if pkt.is_fragment() {
            match self.reasm.feed(now, &pkt) {
                Ok(Some(_len)) => {
                    // Complete: copy out and process the datagram.
                    self.stats.fragments_reassembled += 1;
                    let mut out = [0u8; ipv4::MAX_REASM_DATAGRAM];
                    let src = pkt.src;
                    let dst = pkt.dst;
                    let id = pkt.id;
                    let proto = pkt.protocol;
                    match self.reasm.take_completed(&src, id, proto, &mut out) {
                        Ok(n) => self.on_transport(now, sink, &src, &dst, proto, &out[..n]),
                        Err(_) => Ok(()),
                    }
                }
                Ok(None) => Ok(()), // waiting for more fragments
                Err(_) => Ok(()),   // overlap/full/oversize: dropped
            }
        } else {
            self.on_transport(now, sink, &pkt.src, &pkt.dst, pkt.protocol, pkt.payload)
        }
    }

    fn on_transport(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        src: &[u8; 4],
        dst: &[u8; 4],
        protocol: u8,
        payload: &[u8],
    ) -> Result<()> {
        match protocol {
            PROTO_ICMP => {
                self.stats.icmp_messages += 1;
                let msg = match icmp::IcmpPacket::parse(payload) {
                    Ok(m) => m,
                    Err(_) => return Ok(()), // bad checksum: counted drop
                };
                match msg.kind() {
                    icmp::IcmpKind::EchoRequest => {
                        if self.icmp.on_echo_request(now) {
                            // Reply with EXACTLY the request's bytes,
                            // to the request's source (never a
                            // broadcast — THREAT_MODEL.md §Amplification).
                            let mut out = [0u8; ethernet::ETH_HDR_LEN
                                + 20
                                + icmp::ICMP_HDR_LEN
                                + icmp::MAX_ICMP_PAYLOAD];
                            let n = icmp::emit_echo_reply(
                                &mut out[ethernet::ETH_HDR_LEN + 20..],
                                msg.word0,
                                msg.word1,
                                msg.payload,
                            )?;
                            self.transmit_ipv4(
                                now,
                                sink,
                                src,
                                PROTO_ICMP,
                                &out[ethernet::ETH_HDR_LEN + 20..ethernet::ETH_HDR_LEN + 20 + n],
                            )
                        } else {
                            Ok(()) // rate limited: silent
                        }
                    }
                    icmp::IcmpKind::EchoReply => {
                        self.icmp.on_echo_reply();
                        // Match the outstanding ping: (dst, id, seq).
                        if let Some((pend_dst, id, seq, sent_at)) = self.echo_pending {
                            if pend_dst == *src && id == msg.word0 && seq == msg.word1 {
                                self.echo_pending = None;
                                self.echo_last = Some((*src, id, seq, now.saturating_sub(sent_at)));
                            }
                        }
                        Ok(())
                    }
                    icmp::IcmpKind::Unreachable => {
                        self.icmp.on_unreachable();
                        Ok(()) // diagnostics only (module doc: no
                               // connection teardown on ICMP errors)
                    }
                    icmp::IcmpKind::Ignored => {
                        self.icmp.on_ignored();
                        Ok(())
                    }
                }
            }
            PROTO_UDP => {
                self.stats.udp_datagrams += 1;
                let dgram = match udp::UdpDatagram::parse(payload, src, dst) {
                    Ok(d) => d,
                    Err(_) => return Ok(()), // checksum/length: drop
                };
                // Find the bound socket for the destination port
                // (index first: the delivery push needs a mutable
                // queue, and the scan needs a shared view — one
                // borrow at a time).
                let mut target: Option<usize> = None;
                for i in 0..MAX_STACK_SOCKETS {
                    if let Some(entry) = self.sockets.entries_view(i) {
                        if let socket::SocketKind::Dgram {
                            bound_port: Some(p),
                            ..
                        } = &entry.kind
                        {
                            if *p == dgram.dst_port {
                                target = Some(i);
                                break;
                            }
                        }
                    }
                }
                let mut delivered = false;
                if let Some(i) = target {
                    if let Some(q) = self.sockets.entry_dgram_queue(i) {
                        delivered = q.push(src, dgram.src_port, dgram.data).is_ok();
                    }
                }
                if !delivered {
                    // Closed port → rate-limited ICMP unreachable
                    // (the classic shape; the limiter keeps us from
                    // mirroring a port scan).
                    if self.icmp.may_send_unreachable(now) {
                        let mut emb = [0u8; 28];
                        let take = (payload.len() + 20).min(28);
                        // Rebuild the original IP header + first 8
                        // bytes: the header was validated at parse;
                        // embed what we have.
                        if take >= 20 {
                            // The IP header bytes are at
                            // payload-20.. but we only kept the
                            // transport slice — re-emit a honest
                            // minimal header instead (RFC 1122 allows
                            // the best-effort embed).
                            let _ = ipv4::emit_header(
                                &mut emb[..20],
                                (payload.len() + 20).min(u16::MAX as usize) as u16,
                                0,
                                0,
                                64,
                                PROTO_UDP,
                                dst,
                                src,
                            );
                            let n8 = (payload.len()).min(8);
                            emb[20..20 + n8].copy_from_slice(&payload[..n8]);
                        }
                        let mut out = [0u8; ethernet::ETH_HDR_LEN + 20 + icmp::ICMP_HDR_LEN + 28];
                        let n = icmp::emit_unreachable(
                            &mut out[ethernet::ETH_HDR_LEN + 20..],
                            icmp::CODE_UNREACH_PORT,
                            &emb[..take],
                        )?;
                        return self.transmit_ipv4(
                            now,
                            sink,
                            src,
                            PROTO_ICMP,
                            &out[ethernet::ETH_HDR_LEN + 20..ethernet::ETH_HDR_LEN + 20 + n],
                        );
                    }
                }
                Ok(())
            }
            PROTO_TCP => {
                self.stats.tcp_segments += 1;
                let tcpcfg = self.tcp_cfg();
                let r = self
                    .tcp
                    .on_segment(now, &tcpcfg, &mut self.arp, sink, src, dst, payload);
                self.drain_tcp_events();
                r
            }
            p => {
                self.stats.unknown_protocol += 1;
                let _ = p;
                Ok(())
            }
        }
    }

    /// Translate TCP events into socket statuses (the fd the
    /// user holds learns the handshake's outcome).
    fn drain_tcp_events(&mut self) {
        while let Some(ev) = self.tcp.events.pop() {
            match ev {
                TcpEvent::Connected { tcb } | TcpEvent::AcceptReady { tcb, .. } => {
                    self.mark_stream_status(tcb, SocketStatus::Live);
                }
                TcpEvent::RecvReady { .. } | TcpEvent::PeerClosed { .. } => {}
                TcpEvent::Closed { tcb, reason } => {
                    let status = SocketTable::status_for_reason(reason);
                    self.mark_stream_status(tcb, status);
                }
            }
        }
    }

    fn mark_stream_status(&mut self, tcb: usize, status: SocketStatus) {
        // Find the fd holding this TCB (index scan; the mut borrow
        // happens only after the shared scan ends).
        let mut found: Option<u32> = None;
        for i in 0..MAX_STACK_SOCKETS {
            if let Some(entry) = self.sockets.entries_view(i) {
                if let socket::SocketKind::Stream { tcb: t } = entry.kind {
                    if t == tcb {
                        found = Some(i as u32);
                        break;
                    }
                }
            }
        }
        if let Some(fd) = found {
            let _ = self.sockets.set_status(fd, status);
        }
    }

    // ── egress path (the ONE funnel — always via the sink) ─────────

    /// Transmit one IPv4 payload to `dst_ip` (L3 → ARP → Ethernet →
    /// the sink). MTU-bound: callers keep payloads ≤ 1480 B (TCP
    /// segments are MSS-bound by construction; UDP datagrams are
    /// capped by the socket queue; ICMP by its payload cap). Larger
    /// payloads are fragmented by the UDP path (the only legal
    /// fragmentation the stack emits, DF-clear).
    fn transmit_ipv4(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        dst_ip: &[u8; 4],
        protocol: u8,
        payload: &[u8],
    ) -> Result<()> {
        let next_hop = self.cfg.next_hop(dst_ip)?;
        let Some(dst_mac) = self.arp.resolve(now, sink, &next_hop)? else {
            // Resolution in flight: park the datagram (ONE slot —
            // the documented bound) and report success to the
            // caller; the ARP reply flushes it. A busy slot refuses.
            if self.pending_tx.is_none() && payload.len() <= 1480 {
                let mut data = [0u8; 1500];
                data[..payload.len()].copy_from_slice(payload);
                self.pending_tx = Some(PendingTx {
                    dst_ip: *dst_ip,
                    protocol,
                    data,
                    len: payload.len(),
                });
                return Ok(());
            }
            return Err(Error::ArpQueueFull);
        };
        // Build the IPv4 packet into a LOCAL part buffer first —
        // the frame and its payload cannot alias one array.
        let mut part = [0u8; 20 + 1480];
        let total_len = 20u16
            .checked_add(
                u16::try_from(payload.len()).map_err(|_| Error::DatagramTooLarge {
                    len: payload.len(),
                    max: 1480,
                })?,
            )
            .ok_or(Error::DatagramTooLarge {
                len: payload.len(),
                max: 1480,
            })?;
        if total_len as usize > part.len() {
            return Err(Error::DatagramTooLarge {
                len: payload.len(),
                max: 1480,
            });
        }
        self.ip_id = self.ip_id.wrapping_add(1);
        let ttl = 64;
        ipv4::emit_header(
            &mut part,
            total_len,
            self.ip_id,
            if protocol == PROTO_TCP { 0x4000 } else { 0 },
            ttl,
            protocol,
            &self.cfg.ip,
            dst_ip,
        )?;
        part[20..total_len as usize].copy_from_slice(payload);
        let mut frame = [0u8; ethernet::ETH_HDR_LEN + 20 + 1480];
        let n = ethernet::emit(
            &mut frame,
            &dst_mac,
            &self.cfg.mac,
            EtherType::Ipv4,
            &part[..total_len as usize],
        )?;
        self.stats.frames_out += 1;
        match sink.send_frame(&frame[..n]) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stats.egress_refused += 1;
                Err(e)
            }
        }
    }

    /// Flush the parked datagram now that ARP resolved. Errors are
    /// counted (egress_refused) and the datagram is dropped — the
    /// single slot is freed either way (bounded, no growth).
    fn flush_pending_tx(&mut self, now: u64, sink: &mut dyn FrameSink) {
        if let Some(p) = self.pending_tx.take() {
            let r = self.transmit_ipv4(now, sink, &p.dst_ip, p.protocol, &p.data[..p.len]);
            if r.is_err() {
                self.stats.egress_refused += 1;
            }
        }
    }

    fn send_echo_inner(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        dst: [u8; 4],
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Result<()> {
        let mut out =
            [0u8; ethernet::ETH_HDR_LEN + 20 + icmp::ICMP_HDR_LEN + icmp::MAX_ICMP_PAYLOAD];
        let n = icmp::emit_echo_request(&mut out[ethernet::ETH_HDR_LEN + 20..], id, seq, payload)?;
        self.transmit_ipv4(
            now,
            sink,
            &dst,
            PROTO_ICMP,
            &out[ethernet::ETH_HDR_LEN + 20..ethernet::ETH_HDR_LEN + 20 + n],
        )
    }

    // ── timer path ─────────────────────────────────────────────────

    /// Drive every bounded lifetime in the stack: TCP timers
    /// (retransmission with exponential backoff, delayed ACKs,
    /// persist probes, TIME_WAIT), ARP retries and cache expiry,
    /// reassembly timeouts, ICMP bucket refills.
    pub fn poll(&mut self, now: u64, sink: &mut dyn FrameSink) -> Result<()> {
        let tcpcfg = self.tcp_cfg();
        let r = self.tcp.poll(now, &tcpcfg, &mut self.arp, sink);
        self.drain_tcp_events();
        r?;
        // ARP: retries + expiry sweep.
        let gave_up = self.arp.poll(now, sink)?;
        let _ = gave_up;
        let _ = self.arp.sweep(now);
        // Reassembly timeouts.
        let _ = self.reasm.tick(now);
        Ok(())
    }

    // ── the sockets API (capability-gated, non-blocking) ───────────

    /// `socket(domain, AF_INET, SOCK_STREAM|SOCK_DGRAM)`.
    pub fn socket(&mut self, domain: u32, kind: i32) -> Result<u32> {
        let k = match kind {
            SOCK_STREAM => socket::SocketKind::Stream { tcb: usize::MAX },
            SOCK_DGRAM => socket::SocketKind::Dgram {
                bound_port: None,
                remote: None,
                queue: udp::UdpSocketQueue::new(),
            },
            _ => return Err(Error::InvalidArgument("socket: kind")),
        };
        self.sockets.open(domain, k)
    }

    /// `bind(fd, port)` — UDP ports bind here; stream sockets take
    /// their port at connect/listen time (a pre-bound stream port is
    /// refused: one shape per kind, POSIX-compatible).
    pub fn bind(&mut self, domain: u32, fd: u32, port: u16) -> Result<()> {
        // Port-in-use check across datagram sockets AND listeners.
        for i in 0..MAX_STACK_SOCKETS {
            if let Some(e) = self.sockets.entries_view(i) {
                match &e.kind {
                    socket::SocketKind::Dgram {
                        bound_port: Some(p),
                        ..
                    } if *p == port => {
                        return Err(Error::AddrInUse);
                    }
                    socket::SocketKind::Listen { listener }
                        if self.tcp.listener_port(*listener) == port =>
                    {
                        return Err(Error::AddrInUse);
                    }
                    _ => {}
                }
            }
        }
        let e = self.sockets.get_mut(domain, fd)?;
        match &mut e.kind {
            socket::SocketKind::Dgram { bound_port, .. } => {
                *bound_port = Some(port);
                Ok(())
            }
            _ => Err(Error::WrongKind("bind: not a datagram socket")),
        }
    }

    /// `listen(fd, backlog)` — stream socket → listener. The backlog
    /// is clamped to the fixed [`tcp::LISTEN_BACKLOG`] (honesty about
    /// capacity: asking for 128 gets 4, and that is what it has).
    pub fn listen(&mut self, domain: u32, fd: u32, port: u16) -> Result<()> {
        for i in 0..MAX_STACK_SOCKETS {
            if let Some(e) = self.sockets.entries_view(i) {
                match &e.kind {
                    socket::SocketKind::Dgram {
                        bound_port: Some(p),
                        ..
                    } if *p == port => {
                        return Err(Error::AddrInUse);
                    }
                    socket::SocketKind::Listen { listener }
                        if self.tcp.listener_port(*listener) == port =>
                    {
                        return Err(Error::AddrInUse);
                    }
                    _ => {}
                }
            }
        }
        let l = self.tcp.listen(port)?;
        let e = self.sockets.get_mut(domain, fd)?;
        match &mut e.kind {
            socket::SocketKind::Stream { .. } => {
                e.kind = socket::SocketKind::Listen { listener: l };
                Ok(())
            }
            _ => Err(Error::WrongKind("listen: not a stream socket")),
        }
    }

    /// `connect(fd, ip, port)` — non-blocking: EINPROGRESS now, the
    /// handshake completing on later polls (the event flips the
    /// socket to Live; a REFUSED flips it to Failed and the NEXT
    /// call answers ECONNREFUSED).
    pub fn connect(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        domain: u32,
        fd: u32,
        ip: &[u8; 4],
        port: u16,
    ) -> Result<()> {
        // Datagram sockets: connect sets the DEFAULT remote (the
        // POSIX connected-UDP shape — send() needs no per-call peer
        // and recv() accepts from anyone, the queue records the
        // sender) AND, when no local port is bound yet, binds an
        // ephemeral one — POSIX semantics: an unbound UDP socket that
        // connects gets a source port, so send() has a sender (found
        // LIVE: the gcc netcat client connects without binding and
        // the stack answered NotBound for a send the host suite only
        // ever tried after an explicit bind — the gap stayed
        // invisible for exactly that reason).
        {
            let local_port = self.ephemeral_port(fd, now);
            let e = self.sockets.get_mut(domain, fd)?;
            if let socket::SocketKind::Dgram {
                remote, bound_port, ..
            } = &mut e.kind
            {
                *remote = Some((*ip, port));
                if bound_port.is_none() {
                    *bound_port = Some(local_port);
                }
                return Ok(());
            }
        }
        // Stream: kind check FIRST (a TCB is never allocated for an
        // ineligible fd).
        {
            let e = self.sockets.get(domain, fd)?;
            match &e.kind {
                socket::SocketKind::Stream { tcb } => {
                    if *tcb != usize::MAX && self.tcp.state_of(*tcb) != TcpState::Closed {
                        return Err(Error::WrongKind("connect: already connecting/connected"));
                    }
                }
                _ => return Err(Error::WrongKind("connect: not a stream socket")),
            }
        }
        // Ephemeral local port: a fixed rotation over the dynamic
        // range, spread by the entropy source (a collision with a
        // live 4-tuple is the pool's to refuse).
        let local_port = self.ephemeral_port(fd, now);
        let tcpcfg = self.tcp_cfg();
        let idx = self
            .tcp
            .connect(now, &tcpcfg, &mut self.arp, sink, local_port, ip, port)?;
        let e = self.sockets.get_mut(domain, fd)?;
        if let socket::SocketKind::Stream { tcb } = &mut e.kind {
            *tcb = idx;
            e.status = SocketStatus::Connecting;
        }
        Err(Error::InProgress)
    }

    fn ephemeral_port(&mut self, fd: u32, now: u64) -> u16 {
        // Deterministic spread over the dynamic range; retries after
        // a refusal land elsewhere (the tick term).
        let h = self
            .entropy
            .next_u32()
            .wrapping_mul(0x9e37_79b1)
            .wrapping_add(fd << 16)
            .wrapping_add(now as u32);
        49152 + (h % 16384) as u16
    }

    /// `accept(fd)` — non-blocking: the next ESTABLISHED connection
    /// off the listener, as a NEW fd owned by the SAME domain; EAGAIN
    /// when nothing is ready.
    pub fn accept(&mut self, domain: u32, fd: u32) -> Result<u32> {
        let listener = {
            let e = self.sockets.get(domain, fd)?;
            match &e.kind {
                socket::SocketKind::Listen { listener } => *listener,
                _ => return Err(Error::WrongKind("accept: not a listener")),
            }
        };
        let tcb = self.tcp.accept(listener)?;
        self.sockets
            .open(domain, socket::SocketKind::Stream { tcb })
    }

    /// `send(fd, buf)` — stream: returns the accepted byte count
    /// (bounded by the fixed send ring AND the peer's window —
    /// EAGAIN when both are full). Datagram: one datagram per call,
    /// capped by the queue's datagram bound (EMSGSIZE when larger).
    pub fn send(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        domain: u32,
        fd: u32,
        buf: &[u8],
    ) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::InvalidArgument("send: empty buffer"));
        }
        let (kind, status) = {
            let e = self.sockets.get(domain, fd)?;
            (e.kind, e.status)
        };
        match kind {
            socket::SocketKind::Stream { tcb } => {
                if tcb == usize::MAX {
                    return Err(Error::NotBound);
                }
                match status {
                    SocketStatus::Live => {}
                    SocketStatus::Connecting => return Err(Error::InProgress),
                    SocketStatus::Failed(e) => return Err(e),
                    SocketStatus::Closed => return Err(Error::NotOpen(fd)),
                }
                let tcpcfg = self.tcp_cfg();
                self.tcp.send(now, &tcpcfg, &mut self.arp, sink, tcb, buf)
            }
            socket::SocketKind::Listen { .. } => Err(Error::WrongKind("send: on a listener")),
            socket::SocketKind::Dgram {
                bound_port, remote, ..
            } => {
                let (dst_ip, dst_port) = remote.ok_or(Error::NotBound)?;
                let src_port = bound_port.ok_or(Error::NotBound)?;
                if buf.len() > udp::MAX_DGRAM_LEN {
                    return Err(Error::DatagramTooLarge {
                        len: buf.len(),
                        max: udp::MAX_DGRAM_LEN,
                    });
                }
                let mut dg = [0u8; udp::UDP_HDR_LEN + udp::MAX_DGRAM_LEN];
                let n = udp::emit(&mut dg, &self.cfg.ip, src_port, &dst_ip, dst_port, buf)?;
                self.transmit_ipv4(now, sink, &dst_ip, PROTO_UDP, &dg[..n])?;
                Ok(buf.len())
            }
        }
    }

    /// `recv(fd, buf)` — non-blocking. Stream: bytes copied, 0 = EOF
    /// (peer closed and drained), EAGAIN when empty. Datagram: ONE
    /// datagram per call, boundaries preserved; a too-small buffer
    /// loses the datagram (POSIX semantics) and reports the need.
    pub fn recv(&mut self, domain: u32, fd: u32, buf: &mut [u8]) -> Result<usize> {
        let (kind, status) = {
            let e = self.sockets.get(domain, fd)?;
            (e.kind, e.status)
        };
        match kind {
            socket::SocketKind::Stream { tcb } => {
                if tcb == usize::MAX {
                    return Err(Error::NotBound);
                }
                match status {
                    SocketStatus::Live | SocketStatus::Connecting => {}
                    SocketStatus::Failed(e) => return Err(e),
                    SocketStatus::Closed => return Ok(0), // EOF shape
                }
                self.tcp.recv(tcb, buf)
            }
            socket::SocketKind::Listen { .. } => Err(Error::WrongKind("recv: on a listener")),
            socket::SocketKind::Dgram { .. } => {
                let e = self.sockets.get_mut(domain, fd)?;
                match &mut e.kind {
                    socket::SocketKind::Dgram { queue, .. } => {
                        let (_from_ip, _from_port, n) = queue.pop(buf)?;
                        Ok(n)
                    }
                    _ => Err(Error::WrongKind("recv: not a datagram socket")),
                }
            }
        }
    }

    /// `close(fd)` — stream: FIN when established (after queued data
    /// drains), RST when half-open; the fd is freed immediately (the
    /// teardown completes by event; the TCB rides TIME_WAIT on the
    /// pool, not on the fd). Listener: the slot frees and its
    /// half-open queue is reset.
    pub fn close(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        domain: u32,
        fd: u32,
    ) -> Result<()> {
        let entry = self.sockets.close(domain, fd)?;
        match entry.kind {
            socket::SocketKind::Stream { tcb } => {
                if tcb != usize::MAX && self.tcp.state_of(tcb) != TcpState::Closed {
                    let tcpcfg = self.tcp_cfg();
                    self.tcp.close(now, &tcpcfg, &mut self.arp, sink, tcb)?;
                }
                Ok(())
            }
            socket::SocketKind::Listen { listener } => {
                let tcpcfg = self.tcp_cfg();
                self.tcp
                    .free_listener(now, &tcpcfg, &mut self.arp, sink, listener);
                Ok(())
            }
            socket::SocketKind::Dgram { .. } => Ok(()),
        }
    }

    /// The ping API: send one echo request (bounded payload). The
    /// reply lands in [`NetStack::echo_last`] after a later
    /// `on_frame`/`poll`.
    pub fn ping(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        dst: &[u8; 4],
        payload: &[u8],
    ) -> Result<()> {
        let id = self.entropy.next_u32() as u16;
        let seq = self
            .echo_pending
            .as_ref()
            .map_or(0, |p| p.2)
            .wrapping_add(1);
        self.send_echo_inner(now, sink, *dst, id, seq, payload)?;
        self.echo_pending = Some((*dst, id, seq, now));
        Ok(())
    }

    /// Pending echo (diagnostics / tests).
    pub fn echo_pending(&self) -> Option<([u8; 4], u16, u16, u64)> {
        self.echo_pending
    }
}
