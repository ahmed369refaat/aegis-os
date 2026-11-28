//! The socket relay's host suite (P1-1).
//!
//! The codec is fuzzed (random buffers and mutated valid frames) and
//! the [`Relay`] runs the REAL [`NetStack`] against a scripted peer
//! stack over a fake broker — the same two-stacks-one-wire harness
//! the netstack suite uses, with the relay's request/reply surface
//! in front of one side.
//!
//! Categories:
//!
//! 1. Codec: documented offsets, every structural violation → one
//!    `-EINVAL`, fuzz without panic and without a second reply.
//! 2. Stage: oversize refused by arithmetic, dead fragments expire,
//!    glued requests never read as one frame.
//! 3. Broker queue: throttle absorbed in order, bounded, refusals
//!    mapped, nothing bypasses the wire.
//! 4. Relay: TCP connect/send/recv/close, DONTWAIT shapes, the
//!    pending deadline, ECONNREFUSED, UDP, listen/accept, DONE,
//!    lockstep displacement, cross-client isolation and quotas.

use super::*;
use crate::netstack::arp::{ArpOp, ArpPacket};
use crate::netstack::socket::MAX_SOCKETS_PER_DOMAIN;
use crate::netstack::tests::TestSink;
use crate::netstack::tests::Xorshift;
use crate::netstack::{IfCfg, MacAddr};

// ── the harness: a scripted peer over a fake broker ────────────────

const A_IP: [u8; 4] = [10, 0, 0, 1];
const B_IP: [u8; 4] = [10, 0, 0, 2];

fn cfg(ip: [u8; 4], mac_last: u8) -> IfCfg {
    IfCfg {
        mac: MacAddr([0x02, 0, 0, 0, 0, mac_last]),
        ip,
        netmask: [255, 255, 255, 0],
        gateway: [0, 0, 0, 0],
    }
}

/// The fake broker: an optional byte BUDGET throttles past it
/// (`-EAGAIN`), a refusing mode answers every frame `-ENODEV`, an
/// MTU answers over-long frames `-EMSGSIZE`, and a drop mode is a
/// black-hole wire.
#[derive(Debug, Default)]
struct FakeWire {
    frames: Vec<Vec<u8>>,
    budget: Option<u32>,
    spent: u32,
    refuse: bool,
    mtu: usize,
    drop: bool,
}

impl Wire for FakeWire {
    fn transmit(&mut self, frame: &[u8]) -> core::result::Result<(), WireErr> {
        if self.mtu != 0 && frame.len() > self.mtu {
            return Err(WireErr::TooLong);
        }
        if self.refuse {
            return Err(WireErr::Refused);
        }
        if self.drop {
            return Ok(());
        }
        if let Some(b) = self.budget {
            if self.spent.saturating_add(frame.len() as u32) > b {
                return Err(WireErr::Throttled);
            }
            self.spent += frame.len() as u32;
        }
        self.frames.push(frame.to_vec());
        Ok(())
    }
}

type Client = BrokerQueue<FakeWire>;

fn client_relay() -> (Relay<Xorshift>, Client) {
    (
        Relay::new(NetStack::new(cfg(A_IP, 1), Xorshift::new(0x1111))),
        BrokerQueue::new(FakeWire::default()),
    )
}

fn peer() -> (NetStack<Xorshift>, TestSink) {
    (
        NetStack::new(cfg(B_IP, 2), Xorshift::new(0x2222)),
        TestSink::new(),
    )
}

fn seed_arp<E: Entropy>(s: &mut NetStack<E>, ip: &[u8; 4], mac_last: u8, now: u64) {
    // A real REPLY on the wire, through the public input path: the
    // peer's MAC is cached exactly as the live stack would cache it.
    let peer_mac = MacAddr([0x02, 0, 0, 0, 0, mac_last]);
    let mut pkt = [0u8; 28];
    let n = ArpPacket {
        op: ArpOp::Reply,
        sha: peer_mac,
        spa: *ip,
        tha: s.cfg.mac,
        tpa: s.cfg.ip,
    }
    .emit(&mut pkt)
    .unwrap();
    let mut f = [0u8; 60];
    let n = crate::netstack::ethernet::emit(
        &mut f,
        &s.cfg.mac,
        &peer_mac,
        crate::netstack::ethernet::EtherType::Arp,
        &pkt[..n],
    )
    .unwrap();
    let mut dead = TestSink::new();
    let _ = s.on_frame(now, &mut dead, &f[..n]);
    assert!(dead.frames.is_empty());
}

/// Deliver both sides' output to the other until quiescent, then
/// poll both timers; `now` advances by `step` per round.
#[allow(clippy::too_many_arguments)]
fn pump(
    relay: &mut Relay<Xorshift>,
    sink: &mut Client,
    peer: &mut NetStack<Xorshift>,
    psink: &mut TestSink,
    now: &mut u64,
    step: u64,
) {
    for _ in 0..32 {
        sink.flush();
        let mut moved = 0;
        for f in sink.wire.frames.drain(..) {
            let _ = peer.on_frame(*now, psink, &f);
            moved += 1;
        }
        for f in psink.take() {
            let _ = relay.stack.on_frame(*now, sink, &f);
            moved += 1;
        }
        let _ = relay.stack.poll(*now, sink);
        let _ = peer.poll(*now, psink);
        sink.flush();
        *now += step;
        if moved == 0 && sink.wire.frames.is_empty() && psink.frames.is_empty() {
            break;
        }
    }
}

/// The service's "one iteration": poll, then collect every reply
/// that became ready.
fn tick(
    relay: &mut Relay<Xorshift>,
    sink: &mut Client,
    peer: &mut NetStack<Xorshift>,
    psink: &mut TestSink,
    now: &mut u64,
    step: u64,
) -> Vec<(usize, Rep)> {
    pump(relay, sink, peer, psink, now, step);
    let mut out = Vec::new();
    while let Some(r) = relay.recheck(*now, sink) {
        out.push(r);
    }
    out
}

impl Step {
    fn now(self) -> Rep {
        match self {
            Step::Now(r) => r,
            Step::Pending => panic!("expected an immediate reply"),
        }
    }
}

fn frame(r: &Req, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_REQ_LEN];
    let n = r.encode(payload, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn send_frame(payload: &[u8]) -> Vec<u8> {
    let mut s = Req::new(OP_SEND);
    s.fd = 1;
    frame(&s, payload)
}

/// A bare 16-byte header with every other field zero (the shape of
/// a frame the encoder itself would never produce).
fn header(op: u8) -> Vec<u8> {
    let mut h = vec![0u8; REQ_HDR_LEN];
    h[0] = op;
    h
}

fn dgram_socket(relay: &mut Relay<Xorshift>, sink: &mut Client, client: usize, now: u64) -> u32 {
    let mut sk = Req::new(OP_SOCKET);
    sk.kind = SOCK_DGRAM as u8;
    relay.submit(now, sink, client, &sk, &[]).now().result as u32
}

fn stream_socket(relay: &mut Relay<Xorshift>, sink: &mut Client, client: usize, now: u64) -> u32 {
    let mut sk = Req::new(OP_SOCKET);
    sk.kind = SOCK_STREAM as u8;
    relay.submit(now, sink, client, &sk, &[]).now().result as u32
}

/// The peer listens on 8080, client 0 connects (the blocking shape)
/// and the handshake runs to establishment; `(fd, peer listener)`.
fn connect_tcp(
    relay: &mut Relay<Xorshift>,
    sink: &mut Client,
    peer: &mut NetStack<Xorshift>,
    psink: &mut TestSink,
    now: &mut u64,
) -> (u32, u32) {
    seed_arp(&mut relay.stack, &B_IP, 2, *now);
    seed_arp(peer, &A_IP, 1, *now);
    let lfd = peer.socket(7, SOCK_STREAM).unwrap();
    peer.listen(7, lfd, 8080).unwrap();
    let fd = stream_socket(relay, sink, 0, *now);
    assert_eq!(fd, 0, "the stack's first descriptor");
    let mut c = Req::new(OP_CONNECT);
    c.fd = fd;
    c.ip = B_IP;
    c.port = 8080;
    assert_eq!(relay.submit(*now, sink, 0, &c, &[]), Step::Pending);
    assert!(relay.client_pending(0));
    assert_eq!(
        tick(relay, sink, peer, psink, now, 1),
        vec![(0, Rep::result(OP_CONNECT, 0))]
    );
    assert!(!relay.client_pending(0));
    // A repeated connect on the established socket answers 0 now.
    assert_eq!(
        relay.submit(*now, sink, 0, &c, &[]),
        Step::Now(Rep::result(OP_CONNECT, 0))
    );
    (fd, lfd)
}

// ── 1. the codec ──────────────────────────────────────────────────

#[test]
fn codec_round_trips_every_op_at_the_documented_offsets() {
    let payload: Vec<u8> = (0..MAX_PAYLOAD as u16).map(|i| i as u8).collect();
    for op in OP_SOCKET..=OP_DONE {
        let mut r = Req::new(op);
        r.flags = FLAG_DONTWAIT;
        r.fd = 0x0102_0304;
        r.ip = [10, 0, 2, 15];
        r.port = 0xBEEF;
        r.kind = u8::from(op == OP_SOCKET) * SOCK_DGRAM as u8;
        // Only a send has a body; a recv's `len` is its capacity.
        let (p, hdr_len): (&[u8], u16) = match op {
            OP_SEND => (&payload, MAX_PAYLOAD as u16),
            OP_RECV => (&[], 4096),
            _ => (&[], 0),
        };
        r.len = hdr_len;
        let mut buf = [0xAAu8; MAX_REQ_LEN];
        let n = r.encode(p, &mut buf).unwrap();
        assert_eq!(n, REQ_HDR_LEN + p.len());
        // The offsets, byte by byte (the C header mirrors them).
        assert_eq!(&buf[0..4], &[op, FLAG_DONTWAIT, r.kind, 0]);
        assert_eq!(&buf[4..8], &0x0102_0304i32.to_le_bytes());
        assert_eq!(&buf[8..12], &[10, 0, 2, 15]);
        assert_eq!(&buf[12..14], &0xBEEFu16.to_le_bytes());
        assert_eq!(&buf[14..16], &hdr_len.to_le_bytes());
        // A send's length comes from its payload, whatever `len` said.
        assert_eq!(Req::frame_len(&buf), Some(n));
        match Req::decode(&buf[..n]) {
            Ok((got, pl)) => {
                assert_eq!(got, r);
                assert_eq!(pl, p);
            }
            Err(rep) => panic!("op {op}: rejected {rep:?}"),
        }
    }
    // A small send: the header's length IS the payload's.
    let small = send_frame(b"abcd");
    assert_eq!(small.len(), REQ_HDR_LEN + 4);
    assert_eq!(&small[14..16], &4u16.to_le_bytes());
    // The reply side: result + payload, and the result-only shape.
    let rep = Rep::with_payload(OP_RECV, 77, &[7u8; 100]);
    let mut out = [0u8; MAX_REP_LEN];
    let n = rep.encode(&mut out);
    assert_eq!(n, REP_HDR_LEN + 100);
    assert_eq!(&out[0..4], &[OP_RECV, 0, 0, 0]);
    assert_eq!(&out[4..8], &77i32.to_le_bytes());
    assert_eq!(&out[8..12], &100u32.to_le_bytes());
    assert_eq!(Rep::decode(&out[..n]), Some((OP_RECV, 77, &[7u8; 100][..])));
    let n = Rep::error(OP_CONNECT, errno::ECONNREFUSED).encode(&mut out);
    assert_eq!(Rep::decode(&out[..n]), Some((OP_CONNECT, -111, &[][..])));
    // A too-small output buffer never yields a partial frame.
    assert_eq!(rep.encode(&mut out[..REP_HDR_LEN + 99]), 0);
    // The reply decoder refuses what the codec can never produce.
    let n = rep.encode(&mut out);
    assert_eq!(Rep::decode(&out[..REP_HDR_LEN - 1]), None);
    assert_eq!(Rep::decode(&out[..n + 1]), None, "trailing byte");
    out[8..12].copy_from_slice(&513u32.to_le_bytes());
    assert_eq!(Rep::decode(&out[..n]), None, "length over the cap");
    out[8..12].copy_from_slice(&0u32.to_le_bytes());
    out[2] = 1;
    assert_eq!(Rep::decode(&out[..REP_HDR_LEN]), None, "reserved byte");
    // An over-cap payload is clipped to exactly the cap, by count.
    let big = Rep::with_payload(OP_RECV, 600, &vec![9u8; 600]);
    assert_eq!(big.len as usize, MAX_PAYLOAD);
    assert_eq!(big.result, 600);
}

#[test]
fn codec_rejects_every_structural_violation_with_one_einval() {
    let send = send_frame(b"abcd");
    assert_eq!(Req::decode(&send).unwrap().0.fd, 1);
    let check = |name: &str, bytes: &[u8]| match Req::decode(bytes) {
        Err(rep) => {
            assert_eq!(rep.result, -errno::EINVAL, "{name}");
            assert_eq!(rep.len, 0, "{name}: one result-only reply");
        }
        Ok(_) => panic!("{name}: accepted"),
    };
    // No header at all / a short header.
    check("empty", &[]);
    check("short", &send[..REQ_HDR_LEN - 1]);
    // Single-byte mutations of a valid frame, each of which must fail.
    let mut b = send.clone();
    b[0] = 0;
    check("op 0", &b);
    b[0] = OP_DONE + 1;
    check("op past DONE", &b);
    b = send.clone();
    b[1] = 0x02;
    check("unknown flag", &b);
    b = send.clone();
    b[2] = SOCK_STREAM as u8;
    check("kind on a send", &b);
    b = send.clone();
    b[3] = 1;
    check("reserved byte", &b);
    b = send.clone();
    b[7] = 0x80;
    check("negative fd", &b);
    b = send.clone();
    b[14] = 3;
    check("len shorter than the frame", &b);
    check("trailing byte", &[send.as_slice(), &[0]].concat());
    check("missing payload byte", &send[..send.len() - 1]);
    // Payload on an op that carries none; port zero where one is
    // required; an unknown kind; empty send / recv; a recv that
    // smuggles a body; a header-only op naming a length. (The
    // encoder refuses to produce any of these, so they are built by
    // hand — the decoder must not depend on the encoder.)
    let mut m = header(OP_CLOSE);
    m.extend_from_slice(b"x");
    check("payload on close", &m);
    let mut m = header(OP_CLOSE);
    m[14..16].copy_from_slice(&1u16.to_le_bytes());
    check("len on close", &m);
    for op in [OP_BIND, OP_LISTEN, OP_CONNECT] {
        check("port 0", &header(op));
    }
    let mut m = header(OP_SOCKET);
    m[2] = 3;
    check("kind 3", &m);
    check("empty send", &header(OP_SEND));
    check("empty recv", &header(OP_RECV));
    {
        // A send frame relabelled RECV: a capacity of 4 with 4 bytes
        // of body is not a recv.
        let mut m = send_frame(b"abcd");
        m[0] = OP_RECV;
        check("recv carrying a body", &m);
    }
    // The encoder refuses the shapes the decoder would reject.
    assert!(Req::new(OP_SEND)
        .encode(&[], &mut [0u8; MAX_REQ_LEN])
        .is_err());
    assert!(Req::new(OP_RECV)
        .encode(b"x", &mut [0u8; MAX_REQ_LEN])
        .is_err());
    let mut s = Req::new(OP_CLOSE);
    s.len = 3;
    assert!(s.encode(&[], &mut [0u8; MAX_REQ_LEN]).is_err());
    // The failure reply carries the op byte the client wrote.
    assert_eq!(
        Req::decode(&send[..REQ_HDR_LEN]).unwrap_err(),
        Rep::error(OP_SEND, errno::EINVAL)
    );
    // The in-range extremes still pass (the stack answers them).
    let mut s = Req::new(OP_CLOSE);
    s.fd = i32::MAX as u32;
    assert!(Req::decode(&frame(&s, &[])).is_ok());
    let mut s = Req::new(OP_SOCKET);
    s.kind = SOCK_STREAM as u8;
    assert!(Req::decode(&frame(&s, &[])).is_ok());
    let mut s = Req::new(OP_RECV);
    s.len = u16::MAX; // a capacity: clamped by the relay, not refused
    s.fd = 0;
    assert!(Req::decode(&frame(&s, &[])).is_ok());
    // The encode refuses an oversize payload instead of clipping it.
    let s = Req::new(OP_SEND);
    assert!(s
        .encode(&[0u8; MAX_PAYLOAD + 1], &mut [0u8; MAX_REQ_LEN + 16])
        .is_err());
    let mut s = Req::new(OP_SEND);
    s.fd = 1;
    assert_eq!(
        s.encode(&[7u8; MAX_PAYLOAD], &mut [0u8; MAX_REQ_LEN])
            .unwrap(),
        MAX_REQ_LEN
    );
}

#[test]
fn codec_and_stage_survive_fuzz_without_ever_answering_two_replies() {
    // A deterministic xorshift (no external rng).
    let mut x: u32 = 0x1234_5678;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    // 1. Fully random buffers: never a panic, never a payload
    //    longer than the frame, and an accepted frame is whole.
    let mut random_ok = 0u32;
    for _ in 0..40_000 {
        let len = (next() as usize) % (MAX_REQ_LEN + 8);
        let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        match Req::decode(&bytes) {
            Ok((r, p)) => {
                assert_eq!(bytes.len(), REQ_HDR_LEN + r.len as usize);
                assert_eq!(p.len(), r.len as usize);
                assert!((OP_SOCKET..=OP_LAST).contains(&r.op));
                random_ok += 1;
            }
            Err(rep) => {
                assert_eq!(rep.result, -errno::EINVAL);
                assert_eq!(rep.op, bytes.first().copied().unwrap_or(0));
                assert_eq!(rep.len, 0);
            }
        }
    }
    // 2. Valid frames with 1-3 mutated bytes, fed to the stage in a
    //    random cut: the stage and the codec always agree, and a
    //    frame that decodes is reassembled byte-exact.
    let mut accepted = 0u32;
    let mut overflow = 0u32;
    for round in 0..40_000u32 {
        let op = OP_FIRST + (next() % (OP_LAST - OP_FIRST + 1) as u32) as u8;
        // A send's body is never empty (the encoder refuses that).
        let plen = (next() as usize) % 40 + usize::from(op == OP_SEND);
        let payload: Vec<u8> = (0..plen).map(|_| next() as u8).collect();
        let mut s = Req::new(op);
        s.kind = u8::from(op == OP_SOCKET) * SOCK_DGRAM as u8;
        s.fd = next() % 8;
        s.ip = [10, 0, 0, 2];
        s.port = 8080;
        // A recv's capacity is sometimes zero (a built-in violation).
        s.len = (next() % 4) as u16 * u16::from(op == OP_RECV);
        let mut bytes = frame(&s, if op == OP_SEND { &payload } else { &[] });
        // (a frame whose op carries no payload with plen > 0 is a
        // built-in structural violation — the mutation set widens it)
        for _ in 0..(round % 3) + 1 {
            let at = (next() as usize) % bytes.len();
            bytes[at] ^= 1u8 << (next() % 8);
        }
        let verdict = Req::decode(&bytes);
        let mut st = Stage::new();
        let cut = (next() as usize) % (bytes.len() + 1);
        let a = st.push(0, &bytes[..cut]);
        let b = st.push(0, &bytes[cut..]);
        if a.is_err() || b.is_err() {
            // A refusal resets the stage. When the FIRST push was the
            // one refused, the second push's bytes are a brand-new
            // fragment (and may be refused on their own).
            assert!(verdict.is_err(), "an over-long frame was accepted");
            if b.is_err() || cut == bytes.len() {
                assert!(!st.active());
            } else {
                assert!(a.is_err());
            }
            overflow += 1;
            continue;
        }
        assert_eq!(
            st.ready(),
            Req::frame_len(&bytes).is_some_and(|n| n <= bytes.len()),
            "round {round}"
        );
        if st.ready() {
            let mut pl = [0u8; MAX_PAYLOAD];
            match (verdict, st.take(&mut pl)) {
                (Ok((want, wpayload)), Ok((got, n))) => {
                    assert_eq!(got, want);
                    assert_eq!(&pl[..n], wpayload);
                    accepted += 1;
                }
                (Err(_), Err(rep)) => assert_eq!(rep.result, -errno::EINVAL),
                (v, t) => panic!("stage and codec disagree: {v:?} vs {t:?}"),
            }
            assert!(!st.active());
        }
    }
    assert!(
        accepted > 5_000,
        "the mutation fuzzer never exercises the accept path"
    );
    assert!(
        overflow > 0,
        "the mutation fuzzer never exercises the overflow path"
    );
    let _ = random_ok;
}

// ── 2. the stage ──────────────────────────────────────────────────

#[test]
fn stage_refuses_oversize_by_arithmetic_and_expires_dead_fragments() {
    // A 513-byte send: the header alone is harmless, the payload is
    // refused the moment it cannot fit — before any copy.
    let mut bytes = vec![0u8; REQ_HDR_LEN];
    bytes[0] = OP_SEND;
    bytes[4..8].copy_from_slice(&1i32.to_le_bytes());
    bytes[14..16].copy_from_slice(&513u16.to_le_bytes());
    let mut st = Stage::new();
    // Refused the moment the header names a length that can never
    // fit — before any payload byte is copied.
    assert_eq!(st.push(0, &bytes[..REQ_HDR_LEN]), Err(OP_SEND));
    assert!(!st.active(), "the stage reset after the refusal");
    // The same frame in one write (no fragment): refused the same way.
    assert_eq!(Stage::new().push(0, &bytes), Err(OP_SEND));
    // A maximum-size frame fits; a byte glued behind it does not.
    let full = send_frame(&[0u8; MAX_PAYLOAD]);
    let mut st = Stage::new();
    st.push(0, &full).unwrap();
    assert!(st.ready());
    assert_eq!(st.push(0, &[0]), Err(OP_SEND));
    assert!(!st.active());
    // A recv names a capacity, never a body: its frame is the bare
    // header whatever the capacity says (the relay clamps it).
    let mut r = header(OP_RECV);
    r[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut st = Stage::new();
    st.push(0, &r).unwrap();
    assert!(st.ready());
    let mut pl = [0u8; MAX_PAYLOAD];
    assert_eq!(st.take(&mut pl).unwrap().0.len, u16::MAX);
    // A fragment that never completes expires, and only then.
    let one = send_frame(b"ab");
    let mut st = Stage::new();
    st.push(10, &one[..9]).unwrap();
    assert!(st.active() && !st.ready());
    assert!(!st.expire(10 + OP_TIMEOUT_MS - 1));
    assert!(st.active());
    assert!(st.expire(10 + OP_TIMEOUT_MS));
    assert!(!st.active());
    // Two requests glued back-to-back (a lockstep violation) are
    // never read as one frame: the whole buffer answers -EINVAL.
    let mut st = Stage::new();
    st.push(0, &one).unwrap();
    assert!(st.ready());
    st.push(0, &send_frame(b"cd")).unwrap();
    assert!(st.ready(), "complete, with trailing bytes");
    let mut pl = [0u8; MAX_PAYLOAD];
    assert_eq!(
        st.take(&mut pl).unwrap_err(),
        Rep::error(OP_SEND, errno::EINVAL)
    );
    assert!(!st.active());
    // And a clean fragmented frame reassembles byte-exact.
    let two = send_frame(b"split-payload");
    let mut st = Stage::new();
    st.push(0, &two[..7]).unwrap();
    assert!(!st.ready());
    st.push(0, &two[7..19]).unwrap();
    assert!(!st.ready());
    st.push(0, &two[19..]).unwrap();
    assert!(st.ready());
    let (req, n) = st.take(&mut pl).unwrap();
    assert_eq!((req.op, req.fd, n), (OP_SEND, 1, 13));
    assert_eq!(&pl[..n], b"split-payload");
    // take() on an empty stage is the codec's EINVAL, not a panic.
    assert_eq!(st.take(&mut pl).unwrap_err().result, -errno::EINVAL);
}

// ── 3. the broker queue ───────────────────────────────────────────

#[test]
fn broker_queue_absorbs_throttle_in_order_and_never_bypasses_the_wire() {
    let mut q = BrokerQueue::new(FakeWire {
        budget: Some(100),
        ..FakeWire::default()
    });
    // Two 60-byte frames: the second does not fit the budget.
    q.send_frame(&[1u8; 60]).unwrap();
    assert_eq!(q.queued(), 0);
    q.send_frame(&[2u8; 60]).unwrap();
    assert_eq!(q.queued(), 1, "throttled, not failed");
    assert_eq!(q.stats.deferred, 1);
    // The wire saw exactly one frame — nothing bypassed it.
    assert_eq!(q.wire.frames.len(), 1);
    // A third frame waits BEHIND the second (FIFO).
    q.send_frame(&[3u8; 60]).unwrap();
    assert_eq!(q.queued(), 2);
    assert_eq!(q.wire.frames.len(), 1, "still throttled: nothing new left");
    // The budget returns: the parked frames leave oldest first.
    q.wire.budget = Some(1000);
    assert_eq!(q.flush(), 2);
    let order: Vec<u8> = q.wire.frames.iter().map(|f| f[0]).collect();
    assert_eq!(order, vec![1, 2, 3]);
    assert_eq!(q.queued(), 0);
    assert_eq!(q.stats.sent, 3);
    assert_eq!(q.stats.refused, 0);
    assert_eq!(q.stats.backpressured, 0);
    // A later frame goes straight out (the queue is empty again).
    q.send_frame(&[4u8; 60]).unwrap();
    assert_eq!(q.wire.frames.len(), 4);
    assert_eq!(q.queued(), 0);
}

#[test]
fn broker_queue_is_bounded_and_tells_the_stack_when_full() {
    let mut q = BrokerQueue::new(FakeWire {
        budget: Some(0),
        ..FakeWire::default()
    });
    for i in 0..QUEUE_LEN {
        q.send_frame(&[i as u8 + 1; 60]).unwrap();
    }
    assert_eq!(q.queued(), QUEUE_LEN);
    // The fifth has no room: the stack hears the throttle.
    let e = q.send_frame(&[9u8; 60]).unwrap_err();
    assert_eq!(e.errno(), errno::EAGAIN);
    assert_eq!(q.stats.backpressured, 1);
    assert_eq!(q.queued(), QUEUE_LEN, "nothing was dropped or replaced");
    assert!(q.wire.frames.is_empty());
}

#[test]
fn broker_queue_maps_the_wire_refusals_and_drops_undeliverable_frames() {
    // Oversize: refused before the wire, EMSGSIZE.
    let mut q = BrokerQueue::new(FakeWire::default());
    let e = q.send_frame(&[0u8; ETH_FRAME_MAX + 1]).unwrap_err();
    assert_eq!(e.errno(), errno::EMSGSIZE);
    assert_eq!(q.wire.frames.len(), 0);
    // The wire itself answering -EMSGSIZE (a tighter MTU).
    let mut m = BrokerQueue::new(FakeWire {
        mtu: 100,
        ..FakeWire::default()
    });
    assert_eq!(
        m.send_frame(&[0u8; 120]).unwrap_err().errno(),
        errno::EMSGSIZE
    );
    assert_eq!(m.queued(), 0, "never parked");
    // A refusing wire (the session is gone): ENETUNREACH, not parked.
    let mut g = BrokerQueue::new(FakeWire {
        refuse: true,
        ..FakeWire::default()
    });
    assert_eq!(
        g.send_frame(&[0u8; 60]).unwrap_err().errno(),
        errno::ENETUNREACH
    );
    assert_eq!(g.queued(), 0);
    // Parked frames whose session dies before they leave are
    // dropped — never resent forever — and the counters say so.
    let mut t = BrokerQueue::new(FakeWire {
        budget: Some(0),
        ..FakeWire::default()
    });
    t.send_frame(&[1u8; 60]).unwrap();
    t.send_frame(&[2u8; 60]).unwrap();
    assert_eq!(t.queued(), 2);
    t.wire.refuse = true;
    assert_eq!(t.flush(), 0);
    assert_eq!(t.queued(), 0);
    assert_eq!(t.stats.refused, 2);
    assert_eq!(t.stats.sent, 0);
}

#[test]
fn a_parked_handshake_segment_leaves_in_order_once_the_broker_refills() {
    // The broker admits the SYN (54 bytes) but not the final ACK:
    // the ACK is parked, the client side reports ESTABLISHED (it saw
    // the SYN-ACK) while the peer still waits for the ACK — and the
    // peer's accept succeeds only after the refill, from the SAME
    // parked frame (no retransmission ahead of its original).
    let mut sink = BrokerQueue::new(FakeWire {
        budget: Some(60),
        ..FakeWire::default()
    });
    let (mut relay, _discarded) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    seed_arp(&mut relay.stack, &B_IP, 2, now);
    seed_arp(&mut peer, &A_IP, 1, now);
    let lfd = peer.socket(7, SOCK_STREAM).unwrap();
    peer.listen(7, lfd, 8080).unwrap();
    let mut c = Req::new(OP_CONNECT);
    c.fd = stream_socket(&mut relay, &mut sink, 0, now);
    c.ip = B_IP;
    c.port = 8080;
    assert_eq!(relay.submit(now, &mut sink, 0, &c, &[]), Step::Pending);
    let replies = tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1);
    assert_eq!(replies, vec![(0, Rep::result(OP_CONNECT, 0))]);
    assert_eq!(
        sink.queued(),
        1,
        "the final ACK is parked behind the throttle"
    );
    assert_eq!(sink.stats.deferred, 1);
    assert_eq!(sink.stats.sent, 1, "only the SYN left");
    assert_eq!(peer.accept(7, lfd).unwrap_err().errno(), errno::EAGAIN);
    // The broker refills: the parked ACK leaves, the peer accepts.
    sink.wire.budget = Some(10_000);
    pump(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1);
    assert_eq!(sink.queued(), 0);
    peer.accept(7, lfd).unwrap();
    assert_eq!(
        sink.stats.sent, 2,
        "SYN, then the one parked ACK — nothing re-sent"
    );
}

// ── 4. the relay over a real peer ─────────────────────────────────

#[test]
fn relay_tcp_connect_send_recv_close_against_a_real_peer() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    let (fd, lfd) = connect_tcp(&mut relay, &mut sink, &mut peer, &mut psink, &mut now);

    // DONTWAIT recv before any data: -EAGAIN, nothing pending.
    let mut r = Req::new(OP_RECV);
    r.fd = fd;
    r.len = 64;
    r.flags = FLAG_DONTWAIT;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &r, &[]),
        Step::Now(Rep::error(OP_RECV, errno::EAGAIN))
    );
    assert!(!relay.client_pending(0));

    // A send of 16 bytes: accepted whole, counted as stream bytes.
    let mut s = Req::new(OP_SEND);
    s.fd = fd;
    let payload = b"0123456789ABCDEF";
    assert_eq!(
        relay.submit(now, &mut sink, 0, &s, payload),
        Step::Now(Rep::result(OP_SEND, 16))
    );
    assert_eq!(relay.stats.stream_sent, 16);

    // The blocking recv (capacity 8): pending until the peer's echo
    // returns, then a short read of exactly the capacity.
    let mut rr = Req::new(OP_RECV);
    rr.fd = fd;
    rr.len = 8;
    assert_eq!(relay.submit(now, &mut sink, 0, &rr, &[]), Step::Pending);
    assert!(tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1).is_empty());
    let afd = peer.accept(7, lfd).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(peer.recv(7, afd, &mut buf).unwrap(), 16);
    assert_eq!(&buf[..16], payload);
    peer.send(now, &mut psink, 7, afd, b"0123456789").unwrap();
    assert_eq!(
        tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1),
        vec![(0, Rep::with_payload(OP_RECV, 8, b"01234567"))]
    );
    assert_eq!(relay.stats.stream_recvd, 8);
    // The remaining two bytes come back on the next ask — the
    // short-read shape POSIX callers loop on.
    assert_eq!(
        relay.submit(now, &mut sink, 0, &rr, &[]),
        Step::Now(Rep::with_payload(OP_RECV, 2, b"89"))
    );
    assert_eq!(relay.stats.stream_recvd, 10);

    // Close: clean, nothing left owned, nothing pending.
    let mut c = Req::new(OP_CLOSE);
    c.fd = fd;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &c, &[]),
        Step::Now(Rep::result(OP_CLOSE, 0))
    );
    assert_eq!(relay.live_sockets(), 0);
    // Closing twice is the stack's EINVAL, not a success.
    assert_eq!(
        relay.submit(now, &mut sink, 0, &c, &[]),
        Step::Now(Rep::error(OP_CLOSE, errno::EINVAL))
    );
    // DONE: the client is finished and every later op is refused.
    assert_eq!(
        relay.submit(now, &mut sink, 0, &Req::new(OP_DONE), &[]),
        Step::Now(Rep::result(OP_DONE, 0))
    );
    assert!(relay.client_finished(0));
    assert!(!relay.all_finished(), "the other client slots are not done");
    assert_eq!(
        relay.submit(now, &mut sink, 0, &Req::new(OP_SOCKET), &[]),
        Step::Now(Rep::error(OP_SOCKET, errno::EINVAL))
    );
    assert_eq!(relay.stats.requests[OP_DONE as usize], 1);
    assert_eq!(relay.stats.timeouts, 0);
    assert_eq!(relay.stats.cancelled, 0);
}

#[test]
fn relay_dontwait_connect_reports_in_progress_then_a_blocking_connect_waits() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    seed_arp(&mut relay.stack, &B_IP, 2, now);
    seed_arp(&mut peer, &A_IP, 1, now);
    let lfd = peer.socket(7, SOCK_STREAM).unwrap();
    peer.listen(7, lfd, 8080).unwrap();
    let mut c = Req::new(OP_CONNECT);
    c.fd = stream_socket(&mut relay, &mut sink, 0, now);
    c.ip = B_IP;
    c.port = 8080;
    // The non-blocking shape: -EINPROGRESS now, nothing pending.
    c.flags = FLAG_DONTWAIT;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &c, &[]),
        Step::Now(Rep::error(OP_CONNECT, errno::EINPROGRESS))
    );
    assert!(!relay.client_pending(0));
    // A send meanwhile is the stack's own InProgress.
    let mut s = Req::new(OP_SEND);
    s.fd = c.fd;
    s.flags = FLAG_DONTWAIT;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &s, b"early"),
        Step::Now(Rep::error(OP_SEND, errno::EINPROGRESS))
    );
    // The status poll: still handshaking (the SYN has not moved).
    assert_eq!(
        relay.submit(now, &mut sink, 0, &c, &[]),
        Step::Now(Rep::error(OP_CONNECT, errno::EINPROGRESS))
    );
    // The blocking shape waits for the handshake.
    c.flags = 0;
    assert_eq!(relay.submit(now, &mut sink, 0, &c, &[]), Step::Pending);
    assert_eq!(
        tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1),
        vec![(0, Rep::result(OP_CONNECT, 0))]
    );
}

#[test]
fn relay_pending_operations_time_out_to_etimedout() {
    // A black-hole wire: frames leave, nothing ever answers.
    let mut sink = BrokerQueue::new(FakeWire {
        drop: true,
        ..FakeWire::default()
    });
    let (mut relay, _discarded) = client_relay();
    let now = 0u64;
    seed_arp(&mut relay.stack, &B_IP, 2, now);
    let mut c = Req::new(OP_CONNECT);
    c.fd = stream_socket(&mut relay, &mut sink, 0, now);
    c.ip = B_IP;
    c.port = 8080;
    assert_eq!(relay.submit(now, &mut sink, 0, &c, &[]), Step::Pending);
    // One tick before the deadline it is still pending.
    assert_eq!(relay.recheck(now + OP_TIMEOUT_MS - 1, &mut sink), None);
    assert!(relay.client_pending(0));
    assert_eq!(
        relay.recheck(now + OP_TIMEOUT_MS, &mut sink),
        Some((0, Rep::error(OP_CONNECT, errno::ETIMEDOUT)))
    );
    assert!(!relay.client_pending(0));
    assert_eq!(relay.stats.timeouts, 1);
    assert_eq!(relay.recheck(now + 10 * OP_TIMEOUT_MS, &mut sink), None);
    // A pending datagram recv times out the same way.
    let fd = dgram_socket(&mut relay, &mut sink, 0, now);
    let mut r = Req::new(OP_RECV);
    r.fd = fd;
    r.len = 16;
    assert_eq!(relay.submit(now, &mut sink, 0, &r, &[]), Step::Pending);
    assert_eq!(
        relay.recheck(now + OP_TIMEOUT_MS, &mut sink),
        Some((0, Rep::error(OP_RECV, errno::ETIMEDOUT)))
    );
    assert_eq!(relay.stats.timeouts, 2);
}

#[test]
fn relay_refused_connect_flows_as_econnrefused() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    seed_arp(&mut relay.stack, &B_IP, 2, now);
    seed_arp(&mut peer, &A_IP, 1, now);
    let mut c = Req::new(OP_CONNECT);
    c.fd = stream_socket(&mut relay, &mut sink, 0, now);
    c.ip = B_IP;
    c.port = 9; // no listener there: the peer answers RST
    assert_eq!(relay.submit(now, &mut sink, 0, &c, &[]), Step::Pending);
    assert_eq!(
        tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1),
        vec![(0, Rep::error(OP_CONNECT, errno::ECONNREFUSED))]
    );
    // The status query repeats the outcome: the socket is dead.
    assert_eq!(
        relay.submit(now, &mut sink, 0, &c, &[]),
        Step::Now(Rep::error(OP_CONNECT, errno::ECONNREFUSED))
    );
}

#[test]
fn relay_udp_round_trip_and_the_stack_errnos_pass_through() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    seed_arp(&mut relay.stack, &B_IP, 2, now);
    seed_arp(&mut peer, &A_IP, 1, now);
    let pfd = peer.socket(7, SOCK_DGRAM).unwrap();
    peer.bind(7, pfd, 5353).unwrap();
    peer.connect(now, &mut TestSink::new(), 7, pfd, &A_IP, 4000)
        .unwrap();

    let fd = dgram_socket(&mut relay, &mut sink, 0, now);
    let mut b = Req::new(OP_BIND);
    b.fd = fd;
    b.port = 4000;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &b, &[]),
        Step::Now(Rep::result(OP_BIND, 0))
    );
    // A second socket on the same port: the stack's EADDRINUSE,
    // verbatim.
    let mut b2 = Req::new(OP_BIND);
    b2.fd = dgram_socket(&mut relay, &mut sink, 0, now);
    b2.port = 4000;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &b2, &[]),
        Step::Now(Rep::error(OP_BIND, errno::EADDRINUSE))
    );
    // A datagram connect is immediate; an unconnected send is
    // NotBound → EINVAL; a stream op on a datagram socket is
    // EOPNOTSUPP.
    let mut c = Req::new(OP_CONNECT);
    c.fd = fd;
    c.ip = B_IP;
    c.port = 5353;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &c, &[]),
        Step::Now(Rep::result(OP_CONNECT, 0))
    );
    let mut s2 = Req::new(OP_SEND);
    s2.fd = b2.fd;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &s2, b"x"),
        Step::Now(Rep::error(OP_SEND, errno::EINVAL))
    );
    let mut l = Req::new(OP_LISTEN);
    l.fd = fd;
    l.port = 8081;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &l, &[]),
        Step::Now(Rep::error(OP_LISTEN, errno::EOPNOTSUPP))
    );
    // Send 9 bytes: the datagram count, verbatim.
    let mut s = Req::new(OP_SEND);
    s.fd = fd;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &s, b"hello-udp"),
        Step::Now(Rep::result(OP_SEND, 9))
    );
    assert_eq!(relay.stats.dgram_sent, 9);
    assert_eq!(relay.stats.stream_sent, 0);
    // DONTWAIT recv: nothing yet → EAGAIN.
    let mut r = Req::new(OP_RECV);
    r.fd = fd;
    r.len = 64;
    r.flags = FLAG_DONTWAIT;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &r, &[]),
        Step::Now(Rep::error(OP_RECV, errno::EAGAIN))
    );
    // The datagram reaches the peer with its boundary intact.
    pump(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1);
    let mut buf = [0u8; 64];
    assert_eq!(peer.recv(7, pfd, &mut buf).unwrap(), 9);
    assert_eq!(&buf[..9], b"hello-udp");
    // The peer answers; a blocking recv is pending until it arrives.
    let mut rr = Req::new(OP_RECV);
    rr.fd = fd;
    rr.len = 64;
    assert_eq!(relay.submit(now, &mut sink, 0, &rr, &[]), Step::Pending);
    peer.send(now, &mut psink, 7, pfd, b"udp-pong").unwrap();
    assert_eq!(
        tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1),
        vec![(0, Rep::with_payload(OP_RECV, 8, b"udp-pong"))]
    );
    assert_eq!(relay.stats.dgram_recvd, 8);
    assert_eq!(relay.stats.stream_recvd, 0);
}

#[test]
fn relay_listen_accept_hands_the_client_an_inbound_connection() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    seed_arp(&mut relay.stack, &B_IP, 2, now);
    seed_arp(&mut peer, &A_IP, 1, now);
    let fd = stream_socket(&mut relay, &mut sink, 0, now);
    let mut l = Req::new(OP_LISTEN);
    l.fd = fd;
    l.port = 8080;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &l, &[]),
        Step::Now(Rep::result(OP_LISTEN, 0))
    );
    // DONTWAIT accept: nothing queued → EAGAIN, nothing pending.
    let mut a = Req::new(OP_ACCEPT);
    a.fd = fd;
    a.flags = FLAG_DONTWAIT;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &a, &[]),
        Step::Now(Rep::error(OP_ACCEPT, errno::EAGAIN))
    );
    assert!(!relay.client_pending(0));
    // The blocking accept waits; the peer connects.
    a.flags = 0;
    assert_eq!(relay.submit(now, &mut sink, 0, &a, &[]), Step::Pending);
    let pfd = peer.socket(7, SOCK_STREAM).unwrap();
    assert_eq!(
        peer.connect(now, &mut psink, 7, pfd, &A_IP, 8080)
            .err()
            .map(|e| e.errno()),
        Some(errno::EINPROGRESS)
    );
    let replies = tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1);
    assert_eq!(replies.len(), 1);
    let (client, rep) = replies[0];
    assert_eq!((client, rep.op), (0, OP_ACCEPT));
    // The accepted descriptor is a NEW fd owned by the same client.
    let cfd = rep.result as u32;
    assert_eq!(cfd, 1);
    assert_eq!(relay.live_sockets(), 2, "the listener AND the connection");
    // Bidirectional data on the accepted socket.
    peer.send(now, &mut psink, 7, pfd, b"inbound").unwrap();
    let mut r = Req::new(OP_RECV);
    r.fd = cfd;
    r.len = 64;
    assert_eq!(relay.submit(now, &mut sink, 0, &r, &[]), Step::Pending);
    assert_eq!(
        tick(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1),
        vec![(0, Rep::with_payload(OP_RECV, 7, b"inbound"))]
    );
    let answer = b"accepted-by-aegis";
    let mut s = Req::new(OP_SEND);
    s.fd = cfd;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &s, answer),
        Step::Now(Rep::result(OP_SEND, answer.len() as i32))
    );
    pump(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1);
    let mut buf = [0u8; 64];
    assert_eq!(peer.recv(7, pfd, &mut buf).unwrap(), answer.len());
    assert_eq!(&buf[..answer.len()], answer);
    // DONE closes the listener AND the connection.
    assert_eq!(
        relay.submit(now, &mut sink, 0, &Req::new(OP_DONE), &[]),
        Step::Now(Rep::result(OP_DONE, 0))
    );
    assert_eq!(relay.live_sockets(), 0);
}

#[test]
fn relay_done_closes_every_socket_the_client_owns_and_only_its_own() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    let (fd, lfd) = connect_tcp(&mut relay, &mut sink, &mut peer, &mut psink, &mut now);
    let afd = peer.accept(7, lfd).unwrap();
    let dfd = dgram_socket(&mut relay, &mut sink, 0, now);
    let other = dgram_socket(&mut relay, &mut sink, 1, now);
    assert_eq!(relay.live_sockets(), 3);
    assert_eq!(
        relay.submit(now, &mut sink, 0, &Req::new(OP_DONE), &[]),
        Step::Now(Rep::result(OP_DONE, 0))
    );
    assert_eq!(
        relay.live_sockets(),
        1,
        "only the other client's socket survives"
    );
    assert!(relay.client_finished(0) && !relay.client_finished(1));
    assert!(!relay.client_pending(0));
    // The stream got its FIN: the peer drains to EOF.
    pump(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 5);
    let mut buf = [0u8; 8];
    assert_eq!(peer.recv(7, afd, &mut buf), Ok(0));
    let _ = (fd, dfd, other);
    // The other client is untouched and can still finish on its own.
    assert_eq!(
        relay.submit(now, &mut sink, 1, &Req::new(OP_DONE), &[]),
        Step::Now(Rep::result(OP_DONE, 0))
    );
    assert_eq!(relay.live_sockets(), 0);
    assert!(!relay.all_finished(), "slots 2 and 3 were never used");
}

#[test]
fn relay_a_request_that_breaks_lockstep_displaces_the_pending_one() {
    let (mut relay, mut sink) = client_relay();
    let (mut peer, mut psink) = peer();
    let mut now = 0u64;
    let (fd, lfd) = connect_tcp(&mut relay, &mut sink, &mut peer, &mut psink, &mut now);
    let afd = peer.accept(7, lfd).unwrap();
    let mut rr = Req::new(OP_RECV);
    rr.fd = fd;
    rr.len = 64;
    assert_eq!(relay.submit(now, &mut sink, 0, &rr, &[]), Step::Pending);
    // A second request while the first is pending: answered on its
    // own, and the stale recv is dropped (never delivered out of
    // turn), counted.
    assert_eq!(
        relay.submit(now, &mut sink, 0, &Req::new(OP_SOCKET), &[]),
        Step::Now(Rep::error(OP_SOCKET, errno::EINVAL))
    );
    assert_eq!(relay.stats.cancelled, 1);
    assert!(!relay.client_pending(0));
    // Even when the data the stale recv waited for arrives.
    peer.send(now, &mut psink, 7, afd, b"late").unwrap();
    pump(&mut relay, &mut sink, &mut peer, &mut psink, &mut now, 1);
    assert_eq!(relay.recheck(now, &mut sink), None);
    // The client's next recv does see the data (nothing was lost).
    let mut r2 = Req::new(OP_RECV);
    r2.fd = fd;
    r2.len = 64;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &r2, &[]),
        Step::Now(Rep::with_payload(OP_RECV, 4, b"late"))
    );
}

#[test]
fn relay_clients_are_isolated_by_the_stack_owner_check_and_quota() {
    let (mut relay, mut sink) = client_relay();
    let now = 0u64;
    let fd0 = dgram_socket(&mut relay, &mut sink, 0, now);
    assert_eq!(fd0, 0);
    // Client 1 cannot recv / send / close client 0's descriptor.
    let mut r = Req::new(OP_RECV);
    r.fd = fd0;
    r.len = 8;
    assert_eq!(
        relay.submit(now, &mut sink, 1, &r, &[]),
        Step::Now(Rep::error(OP_RECV, errno::EINVAL))
    );
    let mut s = Req::new(OP_SEND);
    s.fd = fd0;
    assert_eq!(
        relay.submit(now, &mut sink, 1, &s, b"x"),
        Step::Now(Rep::error(OP_SEND, errno::EINVAL))
    );
    let mut c = Req::new(OP_CLOSE);
    c.fd = fd0;
    assert_eq!(
        relay.submit(now, &mut sink, 1, &c, &[]),
        Step::Now(Rep::error(OP_CLOSE, errno::EINVAL))
    );
    assert_eq!(relay.live_sockets(), 1, "still owned by client 0");
    // Client 1 gets its OWN descriptor and its own quota.
    let fd1 = dgram_socket(&mut relay, &mut sink, 1, now);
    assert_eq!(fd1, 1);
    for _ in 1..MAX_SOCKETS_PER_DOMAIN {
        dgram_socket(&mut relay, &mut sink, 0, now);
    }
    assert_eq!(
        relay.submit(now, &mut sink, 0, &Req::new(OP_SOCKET), &[]),
        Step::Now(Rep::error(OP_SOCKET, errno::EINVAL))
    );
    // ...the 7th for client 0 is EMFILE (the per-domain quota)...
    let mut sk = Req::new(OP_SOCKET);
    sk.kind = SOCK_DGRAM as u8;
    assert_eq!(
        relay.submit(now, &mut sink, 0, &sk, &[]),
        Step::Now(Rep::error(OP_SOCKET, errno::EMFILE))
    );
    // ...while client 1 is unaffected: the next slot is its own count.
    assert_eq!(dgram_socket(&mut relay, &mut sink, 1, now), 7);
    // A client index past the table is refused, never indexed.
    assert_eq!(
        relay.submit(now, &mut sink, MAX_CLIENTS, &sk, &[]),
        Step::Now(Rep::error(OP_SOCKET, errno::EINVAL))
    );
    // An op number past the table never indexes the counters.
    let bogus = Req::new(200);
    assert_eq!(
        relay.submit(now, &mut sink, 0, &bogus, &[]),
        Step::Now(Rep::error(200, errno::EINVAL))
    );
    assert_eq!(relay.stats.requests[OP_SOCKET as usize], 6 + 2 + 2);
    relay.note_malformed();
    assert_eq!(relay.stats.malformed, 1);
    // A recv capacity past the cap is clamped, never indexed out.
    let mut huge = Req::new(OP_RECV);
    huge.fd = fd1;
    huge.len = u16::MAX;
    huge.flags = FLAG_DONTWAIT;
    assert_eq!(
        relay.submit(now, &mut sink, 1, &huge, &[]),
        Step::Now(Rep::error(OP_RECV, errno::EAGAIN))
    );
}
