//! The netstack integration suite (K24).
//!
//! Every category from the round contract, driven through the REAL
//! [`NetStack`] over a fake wire: two stacks (client/server) whose
//! sinks feed each other's `on_frame`, with a hand-driven clock —
//! deterministic by construction (no sleeps, no real time, no real
//! randomness: the entropy source is a seeded xorshift).
//!
//! ## The harness
//!
//! - [`TestSink`]: collects every frame; an optional token BUDGET
//!   simulates the broker refusing egress (the §Broker test).
//! - [`pump`]: delivers both stacks' outputs to each other until
//!   quiescent, advancing the clock.
//! - [`Xorshift`]: a deterministic [`Entropy`](super::Entropy).
//!
//! ## Categories
//!
//! 1. Happy paths: ARP resolution, ICMP echo (ping), UDP
//!    send/recv, TCP handshake/data/teardown.
//! 2. Malformed rejection: truncated/corrupted headers at every
//!    layer, wrong protocol numbers.
//! 3. Fragmentation: wire-level reassembly, out-of-order delivery,
//!    overlap refusal, incomplete-reassembly timeout.
//! 4. TCP robustness: SYN flood (rate window + cookies), cookie
//!    completion into a real connection, RTO backoff to timeout,
//!    window-full stall and drain.
//! 5. Socket API errno surface: EAGAIN, ECONNREFUSED, EADDRINUSE,
//!    EINPROGRESS, EMFILE, EMSGSIZE, EOPNOTSUPP, EINVAL paths.
//! 6. Broker: egress exhaustion surfaces, nothing bypasses the sink.
//! 7. Resource limits: socket table, per-domain quota, TCB pool.
//! 8. Sequence space: wraparound arithmetic and the byte ring's
//!    own wrap.

use super::*;

// ── the harness ────────────────────────────────────────────────────

/// A seeded xorshift: deterministic entropy for exact assertions.
pub struct Xorshift(u32);

impl Xorshift {
    pub fn new(seed: u32) -> Xorshift {
        Xorshift(seed | 1)
    }
}

impl Entropy for Xorshift {
    fn next_u32(&mut self) -> u32 {
        // xorshift32: zero is excluded by construction (seed | 1).
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

/// The frame collector / fake broker. With `budget = Some(n)` it
/// refuses every frame past n TOTAL bytes (the token-bucket
/// exhaustion shape: [`Error::RateLimited`]).
pub struct TestSink {
    pub frames: Vec<Vec<u8>>,
    pub budget: Option<u32>,
    pub spent: u32,
}

impl TestSink {
    pub fn new() -> TestSink {
        TestSink {
            frames: Vec::new(),
            budget: None,
            spent: 0,
        }
    }
    pub fn with_budget(bytes: u32) -> TestSink {
        TestSink {
            frames: Vec::new(),
            budget: Some(bytes),
            spent: 0,
        }
    }
    /// Drain the collected frames (the wire takes them).
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.frames)
    }
}

impl Default for TestSink {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSink for TestSink {
    fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        let len = frame.len() as u32;
        if let Some(b) = self.budget {
            if self.spent.saturating_add(len) > b {
                return Err(Error::RateLimited {
                    requested: len,
                    available: b.saturating_sub(self.spent),
                });
            }
            self.spent += len;
        }
        self.frames.push(frame.to_vec());
        Ok(())
    }
}

fn cfg(ip: [u8; 4], mac_last: u8) -> IfCfg {
    IfCfg {
        mac: ethernet::MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, mac_last]),
        ip,
        netmask: [255, 255, 255, 0],
        gateway: [0, 0, 0, 0],
    }
}

fn stack(ip: [u8; 4], mac_last: u8, seed: u32) -> (NetStack<Xorshift>, TestSink) {
    (
        NetStack::new(cfg(ip, mac_last), Xorshift::new(seed)),
        TestSink::new(),
    )
}

const A_IP: [u8; 4] = [10, 0, 0, 1];
const B_IP: [u8; 4] = [10, 0, 0, 2];
const A_MAC: u8 = 1;
const B_MAC: u8 = 2;

/// Deliver every frame each stack produced to the other, repeat
/// until quiescent. `now` advances by `step` per round (drives
/// delayed ACKs and the FIN drains).
fn pump(
    a: &mut NetStack<Xorshift>,
    sa: &mut TestSink,
    b: &mut NetStack<Xorshift>,
    sb: &mut TestSink,
    now: &mut u64,
    step: u64,
) {
    for _ in 0..24 {
        let mut moved = 0;
        for f in sa.take() {
            let _ = b.on_frame(*now, sb, &f);
            moved += 1;
        }
        for f in sb.take() {
            let _ = a.on_frame(*now, sa, &f);
            moved += 1;
        }
        let _ = a.poll(*now, sa);
        let _ = b.poll(*now, sb);
        *now += step;
        if moved == 0 && sa.frames.is_empty() && sb.frames.is_empty() {
            break;
        }
    }
}

// ── 1. happy paths ─────────────────────────────────────────────────

#[test]
fn arp_resolves_over_the_wire() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    // A resolves B: one broadcast request, B answers, both caches
    // filled.
    let mac = a.arp.resolve(now, &mut sa, &B_IP);
    assert_eq!(mac, Ok(None)); // first call: request in flight
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    // The reply went out on the wire; A's NEXT resolve hits cache.
    assert_eq!(
        a.arp.resolve(now, &mut sa, &B_IP).unwrap(),
        Some(ethernet::MacAddr([0x02, 0, 0, 0, 0, B_MAC]))
    );
    // And B cached A from the request itself.
    assert_eq!(
        b.arp.probe(&A_IP, now),
        Some(ethernet::MacAddr([0x02, 0, 0, 0, 0, A_MAC]))
    );
    // No new frames for the cached hit.
    let before = sa.frames.len();
    assert!(a.arp.resolve(now, &mut sa, &B_IP).unwrap().is_some());
    assert_eq!(sa.frames.len(), before);
}

#[test]
fn ping_end_to_end() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    // First egress triggers ARP; the pending echo re-fires on the
    // reply (the ArpEvent::Resolved flush path).
    a.ping(now, &mut sa, &B_IP, b"pingping").unwrap();
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    // The echo request reached B and B answered.
    assert_eq!(b.icmp.echo_requests_received, 1);
    assert_eq!(b.icmp.echo_replies_sent, 1);
    // A matched the reply (echo_last set, pending cleared).
    assert!(a.echo_pending().is_none());
    let (dst, _id, _seq, rtt) = a.echo_last.unwrap();
    assert_eq!(dst, B_IP);
    assert!(rtt < 10); // the wire is free; only pump steps elapse
}

#[test]
fn udp_wire_send_recv() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    seed_arp_side(&mut a, &B_IP, B_MAC, now);
    seed_arp_side(&mut b, &A_IP, A_MAC, now);
    // B binds a datagram socket on 5353.
    let bfd = b.socket(7, SOCK_DGRAM).unwrap();
    b.bind(7, bfd, 5353).unwrap();
    // A binds + connects its datagram socket to B.
    let afd = a.socket(8, SOCK_DGRAM).unwrap();
    a.bind(8, afd, 4242).unwrap();
    a.connect(now, &mut TestSink::new(), 8, afd, &B_IP, 5353)
        .unwrap();
    // Send two datagrams (boundaries must survive).
    let n = a.send(now, &mut sa, 8, afd, b"first-dgram").unwrap();
    assert_eq!(n, b"first-dgram".len());
    a.send(now, &mut sa, 8, afd, b"second").unwrap();
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    // B receives BOTH, in order, with boundaries intact.
    let mut buf = [0u8; 64];
    let n1 = b.recv(7, bfd, &mut buf).unwrap();
    assert_eq!(&buf[..n1], b"first-dgram".as_slice());
    let n2 = b.recv(7, bfd, &mut buf).unwrap();
    assert_eq!(&buf[..n2], b"second".as_slice());
    // Empty now: EAGAIN.
    assert_eq!(b.recv(7, bfd, &mut buf), Err(Error::Again));
    // Unconnected UDP send is refused (NotBound → EINVAL).
    let cfd = a.socket(8, SOCK_DGRAM).unwrap();
    assert!(matches!(
        a.send(now, &mut sa, 8, cfd, b"x"),
        Err(Error::NotBound)
    ));
}

#[test]
fn tcp_handshake_data_teardown() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    seed_arp_side(&mut a, &B_IP, B_MAC, now);
    seed_arp_side(&mut b, &A_IP, A_MAC, now);
    // B listens on 80.
    let lfd = b.socket(7, SOCK_STREAM).unwrap();
    b.listen(7, lfd, 80).unwrap();
    // A connects — EINPROGRESS (non-blocking connect).
    let afd = a.socket(8, SOCK_STREAM).unwrap();
    assert_eq!(
        a.connect(now, &mut sa, 8, afd, &B_IP, 80)
            .err()
            .map(|e| e.errno()),
        Some(error::errno::EINPROGRESS)
    );
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    // Both sides established; B accepts.
    let bfd = b.accept(7, lfd).unwrap();
    assert_eq!(
        b.sockets.stream_state(&b.tcp, bfd).unwrap(),
        tcp::TcpState::Established
    );
    // Data A → B.
    let sent = a.send(now, &mut sa, 8, afd, b"hello-tcp").unwrap();
    assert_eq!(sent, 9);
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 50);
    let mut buf = [0u8; 64];
    let n = b.recv(7, bfd, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello-tcp".as_slice());
    // Data B → A (the other direction).
    b.send(now, &mut sb, 7, bfd, b"pong").unwrap();
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 50);
    let n2 = a.recv(8, afd, &mut buf).unwrap();
    assert_eq!(&buf[..n2], b"pong".as_slice());
    // Teardown: A closes (FIN), B drains to EOF, B closes, A's TCB
    // rides TIME_WAIT and the 2MSL expiry frees the pool slot.
    a.close(now, &mut sa, 8, afd).unwrap();
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 50);
    assert_eq!(b.recv(7, bfd, &mut buf), Ok(0)); // EOF: FIN drained
    b.close(now, &mut sb, 7, bfd).unwrap();
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 50);
    // A's socket reports Closed (EOF on the last recv attempt).
    if let Ok(e) = a.sockets.get(8, afd) {
        assert!(matches!(e.status, socket::SocketStatus::Closed))
    }
    // TIME_WAIT expiry (2*MSL) frees the TCB.
    a.poll(now + 2 * tcp::MSL_MS + 1, &mut sa).unwrap();
    b.poll(now + 2 * tcp::MSL_MS + 1, &mut sb).unwrap();
    let live: usize = a
        .tcp
        .tcbs
        .iter()
        .chain(b.tcp.tcbs.iter())
        .filter(|t| t.state != tcp::TcpState::Closed)
        .count();
    assert_eq!(live, 0);
}

// ── 2. malformed rejection ─────────────────────────────────────────

#[test]
fn malformed_frames_never_panic_never_reply() {
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let now = 100u64;
    let before_out = b.stats.frames_out;
    // Truncated ethernet (7 bytes).
    let _ = b.on_frame(now, &mut sb, &[0u8; 7]);
    // Ethernet frame with an unknown EtherType.
    let mut junk = vec![0xffu8; 6]; // dst = broadcast
    junk.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src
    junk.extend_from_slice(&[0x99, 0x99]); // unknown EtherType
    junk.extend_from_slice(&[0u8; 4]);
    let _ = b.on_frame(now, &mut sb, &junk);
    // IPv4 with a corrupted header checksum: valid frame, then one
    // flipped header byte.
    let mut ip_frame = vec![0xffu8; 6];
    ip_frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    ip_frame.extend_from_slice(&[0x08, 0x00]);
    let mut pkt = [0u8; 28];
    ipv4::emit_header(&mut pkt, 28, 1, 0, 64, ipv4::PROTO_UDP, &A_IP, &B_IP).unwrap();
    pkt[20..24].copy_from_slice(b"junk");
    ip_frame.extend_from_slice(&pkt);
    let mut corrupt = ip_frame.clone();
    // Flip the PROTOCOL byte (inside the checksum, outside the
    // structural fields): a pure checksum violation.
    corrupt[14 + 9] ^= 0x55;
    let _ = b.on_frame(now, &mut sb, &corrupt);
    // Truncated TCP (well-formed IP, 4 bytes of "TCP").
    let mut tcp_short = vec![0xffu8; 6];
    tcp_short.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    tcp_short.extend_from_slice(&[0x08, 0x00]);
    let mut iph = [0u8; 24];
    ipv4::emit_header(&mut iph, 24, 2, 0x4000, 64, ipv4::PROTO_TCP, &A_IP, &B_IP).unwrap();
    iph[20..24].copy_from_slice(&[0, 0, 0, 0]); // 4 "TCP" bytes
    tcp_short.extend_from_slice(&iph);
    let _ = b.on_frame(now, &mut sb, &tcp_short);
    // IP protocol 99 (no handler).
    let mut proto99 = vec![0xffu8; 6];
    proto99.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    proto99.extend_from_slice(&[0x08, 0x00]);
    let mut iph2 = [0u8; 24];
    ipv4::emit_header(&mut iph2, 24, 3, 0, 64, 99, &A_IP, &B_IP).unwrap();
    proto99.extend_from_slice(&iph2);
    let _ = b.on_frame(now, &mut sb, &proto99);
    // Nothing crashed; nothing was answered; drops were counted.
    assert_eq!(b.stats.frames_out, before_out);
    assert_eq!(b.stats.unknown_protocol, 1);
    assert_eq!(b.stats.ip_checksum_drops, 1);
    assert!(b.stats.frames_in >= 5);
}

// ── 3. fragmentation over the wire ─────────────────────────────────

#[test]
fn fragmented_udp_reassembles_and_delivers() {
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let now = 100u64;
    let bfd = b.socket(7, SOCK_DGRAM).unwrap();
    b.bind(7, bfd, 5353).unwrap();
    // One 100-byte UDP datagram, hand-fragmented into two IP
    // fragments (the UDP header rides fragment 0). Fragments fed
    // OUT OF ORDER — the slot accepts either order.
    let payload: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
    let mut dg = [0u8; udp::UDP_HDR_LEN + 512];
    let dlen = udp::emit(&mut dg, &A_IP, 1111, &B_IP, 5353, &payload).unwrap();
    assert_eq!(dlen, 8 + 100);
    let wrap = |ip_pkt: &[u8]| -> Vec<u8> {
        let mut f = vec![0xffu8; 6];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(ip_pkt);
        f
    };
    let mut frag0 = vec![0u8; 20 + 96];
    ipv4::emit_fragment(
        &mut frag0,
        77,
        0,
        true,
        64,
        ipv4::PROTO_UDP,
        &A_IP,
        &B_IP,
        &dg[..96],
    )
    .unwrap();
    let mut frag1 = vec![0u8; 20 + 12];
    ipv4::emit_fragment(
        &mut frag1,
        77,
        96,
        false,
        64,
        ipv4::PROTO_UDP,
        &A_IP,
        &B_IP,
        &dg[96..108],
    )
    .unwrap();
    let _ = b.on_frame(now, &mut sb, &wrap(&frag1)); // final first
    let _ = b.on_frame(now, &mut sb, &wrap(&frag0));
    // The datagram reassembled and delivered to the socket.
    assert_eq!(b.stats.fragments_reassembled, 1);
    let mut buf = [0u8; 128];
    let n = b.recv(7, bfd, &mut buf).unwrap();
    assert_eq!(n, 100);
    assert_eq!(&buf[..100], payload.as_slice());
}

#[test]
fn overlapping_fragments_kill_the_datagram_over_the_wire() {
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let now = 100u64;
    let bfd = b.socket(7, SOCK_DGRAM).unwrap();
    b.bind(7, bfd, 5353).unwrap();
    let payload: Vec<u8> = (0..16u32).map(|i| i as u8).collect();
    let mut dg = [0u8; 8 + 512];
    udp::emit(&mut dg, &A_IP, 2222, &B_IP, 5353, &payload).unwrap();
    let wrap = |ip_pkt: &[u8]| -> Vec<u8> {
        let mut f = vec![0xffu8; 6];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(ip_pkt);
        f
    };
    let mut frag_a = vec![0u8; 20 + 24];
    ipv4::emit_fragment(
        &mut frag_a,
        78,
        0,
        true,
        64,
        ipv4::PROTO_UDP,
        &A_IP,
        &B_IP,
        &dg[..24],
    )
    .unwrap();
    // Fragment B overlaps A: offset 8 covers [8..16) inside A's
    // [0..24).
    let mut frag_b = vec![0u8; 20 + 8];
    ipv4::emit_fragment(
        &mut frag_b,
        78,
        8,
        false,
        64,
        ipv4::PROTO_UDP,
        &A_IP,
        &B_IP,
        &dg[8..16],
    )
    .unwrap();
    let _ = b.on_frame(now, &mut sb, &wrap(&frag_a));
    let _ = b.on_frame(now, &mut sb, &wrap(&frag_b));
    // The whole datagram is gone: nothing delivered.
    assert_eq!(b.stats.fragments_reassembled, 0);
    let mut buf = [0u8; 64];
    assert_eq!(b.recv(7, bfd, &mut buf), Err(Error::Again));
}

#[test]
fn incomplete_fragment_times_out_over_the_wire() {
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 100u64;
    // One MF-set fragment, never completed.
    let mut dg = [0u8; 8 + 512];
    udp::emit(&mut dg, &A_IP, 3333, &B_IP, 5353, b"12345678").unwrap();
    let mut frag = vec![0u8; 20 + 16];
    ipv4::emit_fragment(
        &mut frag,
        79,
        0,
        true,
        64,
        ipv4::PROTO_UDP,
        &A_IP,
        &B_IP,
        &dg[..16],
    )
    .unwrap();
    let mut f = vec![0xffu8; 6];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&frag);
    let _ = b.on_frame(now, &mut sb, &f);
    assert_eq!(b.stats.fragments_reassembled, 0);
    // Within the lifetime: still held (no delivery).
    b.poll(now + ipv4::REASM_TIMEOUT_MS - 1, &mut sb).unwrap();
    // Past it: swept (bounded state — the slot is reusable).
    now += ipv4::REASM_TIMEOUT_MS;
    b.poll(now, &mut sb).unwrap();
    let _ = b.on_frame(now, &mut sb, &f); // re-starts a fresh slot
    b.poll(now + ipv4::REASM_TIMEOUT_MS, &mut sb).unwrap();
    assert_eq!(b.stats.fragments_reassembled, 0);
}

// ── 4. TCP robustness ──────────────────────────────────────────────

#[test]
fn syn_flood_layers_rate_window_and_cookies() {
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let now = 0u64;
    let lfd = b.socket(7, SOCK_STREAM).unwrap();
    b.listen(7, lfd, 80).unwrap();
    seed_arp_side(&mut b, &A_IP, A_MAC, now); // SYN-ACKs go straight out
                                              // The flood: raw SYNs from one source, hand-built (each with a
                                              // distinct sequence so they are distinct attempts). The rate
                                              // window admits SYN_RATE_MAX per 500 ms; the rest drop.
    let mut syns_answered = 0;
    for i in 0..12u32 {
        let seg = build_tcp_segment(
            A_IP,
            4000 + i as u16,
            80,
            i * 1000,
            0,
            tcp::SYN_BIT,
            4096,
            &[],
        );
        let _ = b.on_frame(now, &mut sb, &seg);
        if !sb.frames.is_empty() {
            syns_answered += 1;
        }
        sb.take();
    }
    // The first SYN_RATE_MAX got SYN-ACKs; the rest were dropped by
    // the per-source window (silent).
    assert_eq!(syns_answered, tcp::SYN_RATE_MAX as u32);
    assert!(b.tcp.syn_rate_dropped >= 8);

    // A NEW rate window (past 500 ms) with the half-open budget
    // spent: the queue is full, so further SYNs get COOKIES (a
    // SYN-ACK with NO TCB spent).
    let now2 = now + tcp::SYN_RATE_WINDOW_MS + 1;
    let seg = build_tcp_segment(A_IP, 5000, 80, 99_000, 0, tcp::SYN_BIT, 4096, &[]);
    let _ = b.on_frame(now2, &mut sb, &seg);
    assert_eq!(sb.frames.len(), 1); // a cookie SYN-ACK went out
    assert_eq!(b.tcp.syn_cookies_issued, 1);
    // The TCB pool spent exactly 4 (the rate-admitted half-opens),
    // not one per SYN.
    let live: usize = b
        .tcp
        .tcbs
        .iter()
        .filter(|t| t.state != tcp::TcpState::Closed)
        .count();
    assert_eq!(live, 4);
}

#[test]
fn syn_cookie_completes_a_connection() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    let lfd = b.socket(7, SOCK_STREAM).unwrap();
    b.listen(7, lfd, 80).unwrap();
    seed_arp_side(&mut a, &B_IP, B_MAC, now); // A's SYN goes straight out
    seed_arp_side(&mut b, &A_IP, A_MAC, now); // the cookie path needs a MAC
                                              // Spend the half-open budget: four raw SYNs from a DIFFERENT
                                              // source (the attacker), answered with real SYN-ACKs.
    for i in 0..4u32 {
        let seg = build_tcp_segment(
            [192, 168, 9, 9],
            6000 + i as u16,
            80,
            50_000 + i * 100,
            0,
            tcp::SYN_BIT,
            4096,
            &[],
        );
        let _ = b.on_frame(now, &mut sb, &seg);
        sb.take();
    }
    // Now A (the honest client) connects — the budget is spent, so
    // B answers with a cookie. A's stack completes the handshake
    // against the cookie, and B MATERIALIZES the TCB on A's ACK.
    let afd = a.socket(8, SOCK_STREAM).unwrap();
    let _ = a.connect(now, &mut sa, 8, afd, &B_IP, 80);
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    assert_eq!(b.tcp.syn_cookies_issued, 1);
    assert_eq!(b.tcp.syn_cookies_completed, 1);
    // The connection is REAL: accept + data flows.
    let bfd = b.accept(7, lfd).unwrap();
    let n = a.send(now, &mut sa, 8, afd, b"cookie-data").unwrap();
    assert_eq!(n, 11);
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 50);
    let mut buf = [0u8; 64];
    let m = b.recv(7, bfd, &mut buf).unwrap();
    assert_eq!(&buf[..m], b"cookie-data".as_slice());
}

#[test]
fn rto_backoff_and_timeout() {
    // A connects into the VOID (a sink that records but never
    // answers): the SYN retransmits with exponential backoff until
    // MAX_RETRANSMITS, then the socket fails ETIMEDOUT.
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let now = 0u64;
    let afd = a.socket(8, SOCK_STREAM).unwrap();
    // Pre-seed A's ARP cache for the destination so the only
    // pending event is the handshake itself.
    seed_arp_side(&mut a, &[10, 0, 0, 9], 9, now);
    let _ = a.connect(now, &mut sa, 8, afd, &[10, 0, 0, 9], 80);
    assert_eq!(sa.frames.len(), 1);
    // Backoff schedule: RTO doubles from 1s. Drive the clock in 1s
    // steps until the retransmission budget is spent.
    let mut t = now;
    let mut retrans = 0u32;
    while t < 500_000 {
        t += 1000;
        let before = a.tcp.segments_sent;
        a.poll(t, &mut sa).unwrap();
        a.drain_tcp_events();
        if a.tcp.segments_sent > before {
            retrans += 1;
        }
        if matches!(
            a.sockets.get(8, afd).map(|e| e.status),
            Ok(socket::SocketStatus::Failed(_))
        ) {
            break;
        }
    }
    assert!(retrans >= 1, "the SYN must retransmit at least once");
    // The failure is ETIMEDOUT (never a panic, never a hang).
    match a.sockets.get(8, afd) {
        Ok(e) => match e.status {
            socket::SocketStatus::Failed(err) => assert_eq!(err.errno(), error::errno::ETIMEDOUT),
            other => panic!("expected Failed, got {other:?}"),
        },
        Err(e) => panic!("socket vanished: {e:?}"),
    }
}

#[test]
fn window_full_stalls_then_drains() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    seed_arp_side(&mut a, &B_IP, B_MAC, now);
    seed_arp_side(&mut b, &A_IP, A_MAC, now);
    let lfd = b.socket(7, SOCK_STREAM).unwrap();
    b.listen(7, lfd, 80).unwrap();
    let afd = a.socket(8, SOCK_STREAM).unwrap();
    let _ = a.connect(now, &mut sa, 8, afd, &B_IP, 80);
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    let bfd = b.accept(7, lfd).unwrap();
    // Fill: keep sending 600-byte chunks until the ring AND window
    // close (EAGAIN). Flow control does the bounding. Each chunk's
    // pattern is anchored at its ABSOLUTE stream position so the
    // drain can verify byte-exactness across chunk boundaries.
    let mut total = 0usize;
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 32, "the stall never came");
        let chunk: Vec<u8> = (0..600u32)
            .map(|i| ((total as u32 + i) % 256) as u8)
            .collect();
        match a.send(now, &mut sa, 8, afd, &chunk) {
            Ok(n) => total += n,
            Err(e) => {
                assert_eq!(e.errno(), error::errno::EAGAIN);
                break; // the honest would-block
            }
        }
        pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 60);
    }
    // The stall bound is real: at least the 1024-B ring plus some
    // in-flight window was accepted before refusing.
    assert!(total >= 1024);
    // Drain: B receives EXACTLY total bytes, byte-exact by pattern.
    let mut got = 0usize;
    let mut buf = [0u8; 1024];
    let mut idle = 0;
    while got < total {
        // 250-ms steps: the drain must reach across the persist
        // interval if it ever comes to that.
        pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 250);
        match b.recv(7, bfd, &mut buf) {
            Ok(n) => {
                for (i, byte) in buf[..n].iter().enumerate() {
                    assert_eq!(
                        *byte,
                        ((got + i) % 256) as u8,
                        "byte {} of {}",
                        got + i,
                        total
                    );
                }
                got += n;
                idle = 0;
            }
            Err(Error::Again) => {
                idle += 1;
                if idle == 39 {
                    let t = &a.tcp.tcbs[0];
                    let bt = &b.tcp.tcbs[0];
                    eprintln!(
                        "[stall] A: state={} una={} nxt={} wnd={}",
                        t.state, t.snd_una, t.snd_nxt, t.snd_wnd
                    );
                    eprintln!("[stall] B: state={} rcv_nxt={}", bt.state, bt.rcv_nxt);
                }
                assert!(idle < 40, "drain stalled with {got}/{total}");
            }
            Err(e) => panic!("unexpected recv error: {e:?}"),
        }
    }
    assert_eq!(got, total);
}

// ── 5. socket API errno surface ────────────────────────────────────

#[test]
fn socket_api_error_paths() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let (mut b, mut sb) = stack(B_IP, B_MAC, 0x2222);
    let mut now = 0u64;
    seed_arp_side(&mut a, &B_IP, B_MAC, now);
    seed_arp_side(&mut b, &A_IP, A_MAC, now);
    // ECONNREFUSED: connect to a port nobody listens on; B answers
    // RST; A's socket flips to Failed(ECONNREFUSED).
    let afd = a.socket(8, SOCK_STREAM).unwrap();
    let _ = a.connect(now, &mut sa, 8, afd, &B_IP, 9999);
    pump(&mut a, &mut sa, &mut b, &mut sb, &mut now, 1);
    match a.sockets.get(8, afd) {
        Ok(e) => match e.status {
            socket::SocketStatus::Failed(err) => {
                assert_eq!(err.errno(), error::errno::ECONNREFUSED)
            }
            other => panic!("expected Failed, got {other:?}"),
        },
        Err(e) => panic!("socket vanished: {e:?}"),
    }
    // EAGAIN: recv on an empty UDP socket.
    let ufd = a.socket(8, SOCK_DGRAM).unwrap();
    a.bind(8, ufd, 5353).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(
        a.recv(8, ufd, &mut buf).err().map(|e| e.errno()),
        Some(error::errno::EAGAIN)
    );
    // EAGAIN: accept with nothing completed.
    let lfd = b.socket(7, SOCK_STREAM).unwrap();
    b.listen(7, lfd, 80).unwrap();
    assert_eq!(
        b.accept(7, lfd).err().map(|e| e.errno()),
        Some(error::errno::EAGAIN)
    );
    // EADDRINUSE: two sockets on one port.
    let ufd2 = a.socket(8, SOCK_DGRAM).unwrap();
    assert_eq!(
        a.bind(8, ufd2, 5353).err().map(|e| e.errno()),
        Some(error::errno::EADDRINUSE)
    );
    // EOPNOTSUPP: listen on a datagram socket.
    let ufd3 = b.socket(7, SOCK_DGRAM).unwrap();
    assert_eq!(
        b.listen(7, ufd3, 81).err().map(|e| e.errno()),
        Some(error::errno::EOPNOTSUPP)
    );
    // EINVAL: unknown fd; wrong-domain fd.
    assert_eq!(
        a.recv(8, 99, &mut buf).err().map(|e| e.errno()),
        Some(error::errno::EINVAL)
    );
    assert_eq!(
        b.recv(6, ufd3, &mut buf).err().map(|e| e.errno()),
        Some(error::errno::EINVAL)
    );
    // EMSGSIZE: a UDP datagram over the queue's cap.
    a.connect(now, &mut TestSink::new(), 8, ufd, &B_IP, 5353)
        .unwrap();
    let huge = [0u8; udp::MAX_DGRAM_LEN + 1];
    assert_eq!(
        a.send(now, &mut sa, 8, ufd, &huge).err().map(|e| e.errno()),
        Some(error::errno::EMSGSIZE)
    );
    let _ = sb;
}

// ── 6. broker integration ──────────────────────────────────────────

#[test]
fn broker_exhaustion_surfaces_and_nothing_bypasses_the_sink() {
    let (mut a, _sa) = stack(A_IP, A_MAC, 0x1111);
    let now = 0u64;
    // A's sink has a 60-byte budget: the ARP request (42 B) fits;
    // the echo request behind it is refused — the honest broker
    // refusal surfaces, and the stack never invents a bypass.
    let mut thrifty = TestSink::with_budget(60);
    let r = a.ping(now, &mut thrifty, &B_IP, b"pingpingping");
    match r {
        Err(Error::RateLimited { .. }) => {
            // Even the ARP request was refused: honest too.
        }
        Ok(()) => {
            // The ARP request fit; the echo REQUEST then hit the
            // empty bucket: the ping stays pending (back-pressure,
            // not loss of accounting).
            assert!(a.echo_pending().is_some());
        }
        Err(e) => panic!("unexpected error: {e:?}"),
    }
    // The ARP request went OUT through the sink (the only egress
    // path); the echo request is parked pending resolution — both
    // facts are visible without any private counter: the sink SAW
    // the request, and the ping is still pending.
    assert!(!thrifty.frames.is_empty());
    assert!(thrifty.spent <= 60);
    // A zero-budget sink: the FIRST frame is refused inside the ARP
    // resolve — RateLimited verbatim, no silent drop. (The stack and
    // its sink are built separately here: the budget is the point.)
    let mut b = NetStack::new(cfg(B_IP, B_MAC), Xorshift::new(0x2222));
    let mut broke = TestSink::with_budget(0);
    let r2 = b.arp.resolve(now, &mut broke, &A_IP);
    assert!(matches!(r2, Err(Error::RateLimited { .. })));
    assert!(broke.frames.is_empty());
}

// ── 7. resource limits ─────────────────────────────────────────────

#[test]
fn socket_table_and_domain_quota_exhaust() {
    let (mut a, _sa) = stack(A_IP, A_MAC, 0x1111);
    // The PER-DOMAIN quota: 6 sockets for domain 8.
    for _ in 0..socket::MAX_SOCKETS_PER_DOMAIN {
        a.socket(8, SOCK_DGRAM).unwrap();
    }
    assert_eq!(
        a.socket(8, SOCK_DGRAM).err().map(|e| e.errno()),
        Some(error::errno::EMFILE)
    );
    // A DIFFERENT domain still gets its own quota (capability
    // isolation: one domain's flood does not starve the others).
    a.socket(9, SOCK_DGRAM).unwrap();
    // ... until the QUOTA SYSTEM's tracked-domain cap (8 domains)
    // fires: the 9th DISTINCT domain is refused even though the
    // table has room — the accounting table is fixed too.
    let mut domain = 10u32;
    loop {
        match a.socket(domain, SOCK_DGRAM) {
            Ok(_) => domain += 1,
            Err(e) => {
                assert_eq!(e.errno(), error::errno::EMFILE);
                break;
            }
        }
    }
    // 6 (domain 8) + 1 (domain 9) + 6 more distinct domains = 13
    // sockets; domains 8..15 fill the 8 tracked slots.
    assert_eq!(a.sockets.len(), 13);
    assert_eq!(domain, 16);
}

#[test]
fn tcb_pool_exhausts_cleanly() {
    let (mut a, mut sa) = stack(A_IP, A_MAC, 0x1111);
    let now = 0u64;
    // Pre-seed the ARP cache so connects do not spend on resolution.
    seed_arp_side(&mut a, &[10, 0, 0, 9], 9, now);
    // 8 TCBs: the pool fills. The per-domain socket quota is 6, so
    // the connections span two domains (the honest multi-domain
    // shape).
    let mut fds = Vec::new();
    for i in 0..tcp::MAX_TCBS as u32 {
        let dom = if i < 6 { 8 } else { 9 };
        let fd = a.socket(dom, SOCK_STREAM).unwrap();
        let _ = a.connect(now, &mut sa, dom, fd, &[10, 0, 0, 9], 1000 + i as u16);
        fds.push((dom, fd));
    }
    // The ninth: EMFILE, cleanly refused, no panic.
    let fd9 = a.socket(9, SOCK_STREAM).unwrap();
    assert_eq!(
        a.connect(now, &mut sa, 9, fd9, &[10, 0, 0, 9], 2000)
            .err()
            .map(|e| e.errno()),
        Some(error::errno::EMFILE)
    );
    assert_eq!(fds.len(), tcp::MAX_TCBS);
}

// ── 8. sequence space and the ring ─────────────────────────────────

#[test]
fn sequence_arithmetic_wraps_correctly() {
    use super::tcp::{seq_le, seq_lt};
    // RFC 793 comparison semantics across the 2^32 seam.
    let max = u32::MAX;
    assert!(seq_lt(max, 0)); // wraps: MAX < 0 in seq space
    assert!(seq_lt(max, 1));
    assert!(seq_lt(max - 2, max));
    assert!(seq_le(max, max));
    assert!(!seq_lt(0, max));
    assert!(seq_lt(5, 6));
    // A window straddling the seam: [max-1, max+3) contains 0.
    let rcv_nxt = max - 1;
    let win = 4u32;
    assert_eq!(rcv_nxt.wrapping_add(win), 2);
    assert!(seq_le(rcv_nxt, 0) && seq_lt(0, rcv_nxt.wrapping_add(win)));
}

#[test]
fn byte_ring_wraps_without_loss() {
    use super::tcp::Ring;
    let mut r = Ring::new();
    // Three quarter-fills: each crosses the 1024 boundary.
    let chunk: Vec<u8> = (0..768u32).map(|i| (i % 256) as u8).collect();
    for round in 0..3u32 {
        let n = r.push(&chunk);
        assert_eq!(n, 768);
        let mut out = [0u8; 768];
        let got = r.pop(&mut out);
        assert_eq!(got, 768);
        for (i, b) in out.iter().enumerate() {
            assert_eq!(
                *b,
                ((i as u32 + round * 768) % 256) as u8,
                "byte {i} round {round}"
            );
        }
        assert!(r.is_empty());
    }
    // Peek (the retransmission read) across the wrap: pop 700, push
    // 400 more — the stored bytes straddle the 1024 seam.
    r.push(&chunk); // len 768
    let mut drain = [0u8; 700];
    assert_eq!(r.pop(&mut drain), 700); // head 700, len 68
    let tail: Vec<u8> = (0..400u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(r.push(&tail), 400); // len 468, wraps the seam
    let mut probe = [0u8; 4];
    assert_eq!(r.peek(0, 4, &mut probe), 4);
    // The surviving FIRST-chunk bytes (700..704 of 768) are at the
    // head: (700 % 256, 701 % 256, ...) = (188, 189, 190, 191).
    assert_eq!(probe, [188u8, 189, 190, 191]);
    assert_eq!(r.peek(464, 4, &mut probe), 4);
    // The last four of the 400-byte tail: (i % 251) for i=396..399.
    assert_eq!(
        probe,
        [
            (396u32 % 251) as u8,
            (397 % 251) as u8,
            (398 % 251) as u8,
            (399 % 251) as u8
        ]
    );
}

// ── raw segment builder (the attacker's hands) ─────────────────────

/// Build a complete Ethernet+IPv4+TCP frame with CORRECT checksums
/// (the suite plays a well-formed-but-hostile peer). Addressed to
/// B (broadcast dst is accepted for processing).
#[allow(clippy::too_many_arguments)] // the wire builder's shape
fn build_tcp_segment(
    src_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = tcp::TCP_HDR_LEN + payload.len();
    let mut seg = vec![0u8; tcp_len];
    seg[0] = (src_port >> 8) as u8;
    seg[1] = src_port as u8;
    seg[2] = (dst_port >> 8) as u8;
    seg[3] = dst_port as u8;
    seg[4..8].copy_from_slice(&seq.to_be_bytes());
    seg[8..12].copy_from_slice(&ack.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = flags;
    seg[14] = (window >> 8) as u8;
    seg[15] = window as u8;
    seg[tcp::TCP_HDR_LEN..tcp_len].copy_from_slice(payload);
    let ck = ipv4::pseudo_header_checksum(&src_ip, &B_IP, ipv4::PROTO_TCP, tcp_len as u16, &seg);
    seg[16] = (ck >> 8) as u8;
    seg[17] = ck as u8;
    let mut ip = vec![0u8; 20 + tcp_len];
    ipv4::emit_header(
        &mut ip,
        (20 + tcp_len) as u16,
        9,
        0x4000,
        64,
        ipv4::PROTO_TCP,
        &src_ip,
        &B_IP,
    )
    .unwrap();
    ip[20..].copy_from_slice(&seg);
    let mut frame = vec![0xffu8; 6]; // to B (broadcast)
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 9]); // the attacker's MAC
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&ip);
    frame
}

// ── test-only hooks on the real types (cfg(test)) ──────────────────

/// Seed an ARP cache entry on stack `s` for `ip` (skips the
/// resolution round-trip when a test isolates protocol behavior).
fn seed_arp_side(s: &mut NetStack<Xorshift>, ip: &[u8; 4], mac_last: u8, now: u64) {
    let mut dead = TestSink::new();
    // A REPLY seeds the cache silently (a REQUEST for our address
    // would be answered — not the side effect we want here).
    let _ = s.arp.on_packet(
        now,
        &mut dead,
        &arp::ArpPacket {
            op: arp::ArpOp::Reply,
            sha: ethernet::MacAddr([0x02, 0, 0, 0, 0, mac_last]),
            spa: *ip,
            tha: s.cfg.mac,
            tpa: s.cfg.ip,
        },
    );
    assert!(dead.frames.is_empty());
    assert_eq!(
        s.arp.probe(ip, now),
        Some(ethernet::MacAddr([0x02, 0, 0, 0, 0, mac_last]))
    );
}
