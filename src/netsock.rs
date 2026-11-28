//! The socket relay (P1-1): the wire protocol between a ring-3 socket
//! client and the ring-3 TCP/IP service, and the per-client state
//! machine that turns request/reply into non-blocking
//! [`NetStack`] calls.
//!
//! ## What this module owns
//!
//! - The codec: a fixed 16-byte request header and a 12-byte reply
//!   header, little-endian, explicit offsets, decoded without any
//!   cast or padding assumption (the C client mirrors these offsets
//!   in `examples/userland-netcat/aegis_net.h`).
//! - [`Relay`]: one pending operation per client (strict lockstep is
//!   the framing), with the blocking shapes built from the stack's
//!   non-blocking API: a blocking `recv` is "asked, `EAGAIN`, ask
//!   again after the next poll", bounded by [`OP_TIMEOUT_MS`].
//! - [`BrokerQueue`]: the ONE egress the stack sees. It hands
//!   complete frames to a [`Wire`] (the service's `SYS_NET_SEND`
//!   wrapper) and absorbs the broker's `EAGAIN` for a bounded number
//!   of frames, in order, so a throttle never desynchronises the TCP
//!   send state. There is no other way out.
//!
//! ## Threat model (THREAT_MODEL.md §Malformed, §Resource Exhaustion)
//!
//! - Every byte a client writes is untrusted. A malformed request
//!   answers exactly ONE `-EINVAL` reply — the client is parked on
//!   its reply channel, so silence would be a hang, and two replies
//!   would desynchronise it.
//! - All buffers are fixed arrays: a client cannot make the service
//!   allocate, and a request larger than [`MAX_PAYLOAD`] is refused
//!   by arithmetic on the header BEFORE anything is copied.
//! - A client is a stack "domain": the stack's per-domain socket
//!   quota (6) and its owner checks apply unchanged — one client
//!   cannot touch another client's descriptors.
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use crate::netstack::errno;
use crate::netstack::tcp::TcpState;
use crate::netstack::{
    Entropy, Error, FrameSink, NetStack, Result, SocketKind, SocketStatus, ETH_FRAME_MAX,
    MAX_STACK_SOCKETS, SOCK_DGRAM, SOCK_STREAM,
};

// ── the wire protocol ──────────────────────────────────────────────

/// Request header: `op, flags, kind, _rsv, fd:i32, ip:[u8;4], port:u16,
/// len:u16` — all little-endian at fixed offsets.
pub const REQ_HDR_LEN: usize = 16;
/// Reply header: `op, _rsv:[u8;3], result:i32, len:u32`.
pub const REP_HDR_LEN: usize = 12;
/// The largest payload one request or reply carries. `16 + 512` and
/// `12 + 512` both fit the kernel's 1024-byte channel ring in ONE
/// write, which is what makes the framing atomic.
pub const MAX_PAYLOAD: usize = 512;
/// The largest request frame (header + payload).
pub const MAX_REQ_LEN: usize = REQ_HDR_LEN + MAX_PAYLOAD;
/// The largest reply frame (header + payload).
pub const MAX_REP_LEN: usize = REP_HDR_LEN + MAX_PAYLOAD;
/// Clients the relay serves at once (each is one stack "domain").
pub const MAX_CLIENTS: usize = 4;
/// A pending (blocking-shaped) operation that has not completed by
/// then answers `-ETIMEDOUT`. Long enough for the broker's one-second
/// refill and several RTO rounds; short enough to be a bound.
pub const OP_TIMEOUT_MS: u64 = 20_000;

pub const OP_SOCKET: u8 = 1;
pub const OP_BIND: u8 = 2;
pub const OP_LISTEN: u8 = 3;
pub const OP_CONNECT: u8 = 4;
pub const OP_ACCEPT: u8 = 5;
pub const OP_SEND: u8 = 6;
pub const OP_RECV: u8 = 7;
pub const OP_CLOSE: u8 = 8;
/// The client is done: every socket it still owns is closed and the
/// client is marked finished (any later request answers `-EINVAL`).
pub const OP_DONE: u8 = 9;

/// `MSG_DONTWAIT`: a would-block answers `-EAGAIN` now instead of
/// staying pending.
pub const FLAG_DONTWAIT: u8 = 1;

const OP_FIRST: u8 = OP_SOCKET;
const OP_LAST: u8 = OP_DONE;
const OP_COUNT: usize = OP_LAST as usize + 1;

/// One decoded request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Req {
    pub op: u8,
    pub flags: u8,
    /// The socket kind for `OP_SOCKET` (`SOCK_STREAM` / `SOCK_DGRAM`);
    /// zero for every other op.
    pub kind: u8,
    pub fd: u32,
    pub ip: [u8; 4],
    pub port: u16,
    /// Payload length (`OP_SEND`), buffer capacity (`OP_RECV`), else 0.
    pub len: u16,
}

impl Req {
    /// A header with the fields the op needs; everything else zero.
    pub const fn new(op: u8) -> Req {
        Req {
            op,
            flags: 0,
            kind: 0,
            fd: 0,
            ip: [0; 4],
            port: 0,
            len: 0,
        }
    }

    /// The total frame length the header at the head of `buf`
    /// announces, or `None` while fewer than [`REQ_HDR_LEN`] bytes
    /// are present. Only `OP_SEND` has a body (its payload); every
    /// other frame is the bare header — a recv's `len` is a buffer
    /// capacity, not a byte count. The announced length is NOT
    /// trusted: the caller bounds it against [`MAX_REQ_LEN`] before
    /// copying anything.
    pub fn frame_len(buf: &[u8]) -> Option<usize> {
        if buf.len() < REQ_HDR_LEN {
            return None;
        }
        Some(match buf[0] {
            OP_SEND => REQ_HDR_LEN + u16::from_le_bytes([buf[14], buf[15]]) as usize,
            _ => REQ_HDR_LEN,
        })
    }

    /// Encode header (+ payload for `OP_SEND`) into `out`; returns
    /// the bytes written. Only a send carries a payload, and it MUST
    /// be non-empty and ≤ [`MAX_PAYLOAD`] (anything else is refused
    /// as `Err` — never a silent truncation); a recv's buffer
    /// capacity is `self.len`.
    pub fn encode(&self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let body: &[u8] = match self.op {
            OP_SEND => {
                if payload.is_empty() {
                    return Err(Error::InvalidArgument("req: empty send"));
                }
                payload
            }
            OP_RECV => {
                if !payload.is_empty() {
                    return Err(Error::InvalidArgument("req: recv carries no payload"));
                }
                &[]
            }
            _ => {
                if !payload.is_empty() || self.len != 0 {
                    return Err(Error::InvalidArgument("req: op carries no payload"));
                }
                &[]
            }
        };
        if body.len() > MAX_PAYLOAD || out.len() < REQ_HDR_LEN + body.len() {
            return Err(Error::InvalidArgument("req: encode"));
        }
        out[0] = self.op;
        out[1] = self.flags;
        out[2] = self.kind;
        out[3] = 0;
        out[4..8].copy_from_slice(&(self.fd as i32).to_le_bytes());
        out[8..12].copy_from_slice(&self.ip);
        out[12..14].copy_from_slice(&self.port.to_le_bytes());
        let len = if self.op == OP_SEND {
            body.len() as u16
        } else {
            self.len
        };
        out[14..16].copy_from_slice(&len.to_le_bytes());
        out[REQ_HDR_LEN..REQ_HDR_LEN + body.len()].copy_from_slice(body);
        Ok(REQ_HDR_LEN + body.len())
    }

    /// Decode ONE complete frame. Every structural violation answers
    /// a single `-EINVAL` reply carrying the op byte the client wrote
    /// (zero when even the header is missing), so the lockstep
    /// invariant "one request, one reply" holds for hostile input too.
    // (clippy::result_large_err is deliberate: the Err IS the reply
    // the service must send — a fixed 524-byte frame on the caller's
    // stack, where a no_std service has nothing to Box it into.)
    #[allow(clippy::result_large_err)]
    pub fn decode(frame: &[u8]) -> core::result::Result<(Req, &[u8]), Rep> {
        let op = frame.first().copied().unwrap_or(0);
        #[allow(clippy::result_large_err)]
        let bad = || Err(Rep::error(op, errno::EINVAL));
        if frame.len() < REQ_HDR_LEN {
            return bad();
        }
        let fd = i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let req = Req {
            op,
            flags: frame[1],
            kind: frame[2],
            fd: fd as u32,
            ip: [frame[8], frame[9], frame[10], frame[11]],
            port: u16::from_le_bytes([frame[12], frame[13]]),
            len: u16::from_le_bytes([frame[14], frame[15]]),
        };
        // Framing: a send is header + exactly `len` payload bytes
        // (1..=MAX_PAYLOAD); everything else is the bare header, and
        // only a recv may name a non-zero `len` there (its capacity).
        let framed = match op {
            OP_SEND => {
                (1..=MAX_PAYLOAD as u16).contains(&req.len)
                    && frame.len() == REQ_HDR_LEN + req.len as usize
            }
            OP_RECV => req.len != 0 && frame.len() == REQ_HDR_LEN,
            OP_FIRST..=OP_LAST => req.len == 0 && frame.len() == REQ_HDR_LEN,
            _ => false, // unknown op
        };
        if !framed
            || frame[3] != 0                                // reserved byte
            || req.flags & !FLAG_DONTWAIT != 0              // unknown flags
            || fd < 0
        // negative descriptor
        {
            return bad();
        }
        let payload = &frame[REQ_HDR_LEN..];
        let needs_port = matches!(op, OP_BIND | OP_LISTEN | OP_CONNECT);
        if needs_port && req.port == 0 {
            return bad();
        }
        match op {
            OP_SOCKET => {
                if req.kind != SOCK_STREAM as u8 && req.kind != SOCK_DGRAM as u8 {
                    return bad();
                }
            }
            OP_SEND | OP_RECV => {
                if req.kind != 0 {
                    return bad();
                }
            }
            _ => {
                if req.kind != 0 {
                    return bad();
                }
            }
        }
        Ok((req, payload))
    }
}

/// One reply: the op it answers, the raw result (a non-negative
/// count/descriptor, or `-errno`), and at most [`MAX_PAYLOAD`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rep {
    pub op: u8,
    pub result: i32,
    pub payload: [u8; MAX_PAYLOAD],
    pub len: u32,
}

impl Rep {
    /// A result-only reply (no payload): a count, a descriptor, zero.
    pub const fn result(op: u8, result: i32) -> Rep {
        Rep {
            op,
            result,
            payload: [0; MAX_PAYLOAD],
            len: 0,
        }
    }

    /// A failure reply: `-errno` (the errno is passed POSITIVE, the
    /// negation happens in exactly one place).
    pub const fn error(op: u8, errno: i32) -> Rep {
        Rep::result(op, -errno)
    }

    /// A reply carrying `payload` (≤ [`MAX_PAYLOAD`]; a longer slice
    /// is truncated to exactly that bound — the byte count is the
    /// honest truncation, POSIX `recv` semantics).
    pub fn with_payload(op: u8, result: i32, payload: &[u8]) -> Rep {
        let n = payload.len().min(MAX_PAYLOAD);
        let mut r = Rep::result(op, result);
        r.payload[..n].copy_from_slice(&payload[..n]);
        r.len = n as u32;
        r
    }

    /// Encode header + payload into `out`; returns the bytes written
    /// (zero when `out` is too short — never a partial frame).
    pub fn encode(&self, out: &mut [u8]) -> usize {
        let n = (self.len as usize).min(MAX_PAYLOAD);
        let total = REP_HDR_LEN + n;
        if out.len() < total {
            return 0;
        }
        out[0] = self.op;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.result.to_le_bytes());
        out[8..12].copy_from_slice(&(n as u32).to_le_bytes());
        out[REP_HDR_LEN..total].copy_from_slice(&self.payload[..n]);
        total
    }

    /// Decode a complete reply frame: `(op, result, payload)`.
    /// `None` for anything structurally impossible (short header, a
    /// length that does not match the frame, a length over the cap).
    pub fn decode(frame: &[u8]) -> Option<(u8, i32, &[u8])> {
        if frame.len() < REP_HDR_LEN {
            return None;
        }
        let result = i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let len = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
        if frame[1] != 0 || frame[2] != 0 || frame[3] != 0 || len > MAX_PAYLOAD {
            return None;
        }
        if frame.len() != REP_HDR_LEN + len {
            return None;
        }
        Some((frame[0], result, &frame[REP_HDR_LEN..]))
    }
}

/// Reassembles one client's request stream: a `pipe_read` may return
/// a fragment, so bytes accumulate until [`Req::frame_len`] is
/// satisfied. A fragment that never completes expires after
/// [`OP_TIMEOUT_MS`] (a client that died mid-write must not pin the
/// slot), and a frame announced longer than [`MAX_REQ_LEN`] is
/// refused by arithmetic before any copy.
#[derive(Debug)]
pub struct Stage {
    buf: [u8; MAX_REQ_LEN],
    len: usize,
    since: Option<u64>,
}

impl Stage {
    pub const fn new() -> Stage {
        Stage {
            buf: [0; MAX_REQ_LEN],
            len: 0,
            since: None,
        }
    }

    /// Is a byte sequence being accumulated?
    pub fn active(&self) -> bool {
        self.len > 0
    }

    /// Append `bytes`. `Err(op)` when the announced frame can never
    /// fit: the stage is reset and the caller answers that op with
    /// `-EMSGSIZE` for a send (the caller asked for more than the
    /// relay carries) or `-EINVAL` otherwise.
    pub fn push(&mut self, now: u64, bytes: &[u8]) -> core::result::Result<(), u8> {
        if self.len == 0 {
            self.since = Some(now);
        }
        let room = MAX_REQ_LEN - self.len;
        let take = bytes.len().min(room);
        self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
        self.len += take;
        let over = bytes.len() > take
            || Req::frame_len(&self.buf[..self.len]).is_some_and(|n| n > MAX_REQ_LEN);
        if over {
            let op = self.buf[0];
            self.reset();
            return Err(op);
        }
        Ok(())
    }

    /// A complete frame is buffered — including the hostile shape
    /// "a frame plus trailing bytes", which [`take`](Self::take)
    /// then refuses whole rather than silently clipping.
    pub fn ready(&self) -> bool {
        matches!(Req::frame_len(&self.buf[..self.len]), Some(n) if n <= self.len)
    }

    /// Drop an expired fragment; true when something was dropped.
    pub fn expire(&mut self, now: u64) -> bool {
        if self.len > 0
            && self
                .since
                .is_some_and(|t| now.saturating_sub(t) >= OP_TIMEOUT_MS)
        {
            self.reset();
            return true;
        }
        false
    }

    /// Decode the buffered frame, copying its payload to `payload`
    /// (its length comes back in the tuple). Always resets the stage.
    /// The WHOLE buffered content goes to the decoder: trailing
    /// bytes are a protocol violation and answer `-EINVAL`, never a
    /// silently clipped frame.
    #[allow(clippy::result_large_err)]
    pub fn take(
        &mut self,
        payload: &mut [u8; MAX_PAYLOAD],
    ) -> core::result::Result<(Req, usize), Rep> {
        let frame = self.buf;
        let buffered = self.len;
        self.reset();
        Req::decode(&frame[..buffered]).map(|(req, p)| {
            payload[..p.len()].copy_from_slice(p);
            (req, p.len())
        })
    }

    fn reset(&mut self) {
        self.len = 0;
        self.since = None;
    }
}

impl Default for Stage {
    fn default() -> Self {
        Stage::new()
    }
}

// ── the ONE egress: the broker queue ───────────────────────────────

/// Why a [`Wire`] refused a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireErr {
    /// The broker's bucket is empty (`-EAGAIN`): retry on a later
    /// iteration — the frame is still deliverable.
    Throttled,
    /// `-EMSGSIZE`: no window will ever admit this frame.
    TooLong,
    /// Any other refusal (`-ENODEV`, `-EPERM`): the session is gone
    /// or the right was lost; not retryable.
    Refused,
}

/// The environment's frame exit — in the service, the `SYS_NET_SEND`
/// wrapper and nothing else.
pub trait Wire {
    fn transmit(&mut self, frame: &[u8]) -> core::result::Result<(), WireErr>;
}

/// Deferred frames the queue holds before the stack itself is told
/// the broker is throttling. Four frames is the longest burst a
/// handshake plus a data segment produces between two polls.
pub const QUEUE_LEN: usize = 4;

/// Counters, one line of honesty each.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueStats {
    /// Frames the wire accepted.
    pub sent: usize,
    /// Frames parked here after an `EAGAIN` (all later sent, or
    /// dropped by a refusal — counted below).
    pub deferred: usize,
    /// Frames the wire refused for good.
    pub refused: usize,
    /// Times the stack was answered `RateLimited` because the queue
    /// itself was full (the throttle reached the stack, honestly).
    pub backpressured: usize,
}

/// The stack's [`FrameSink`]: every frame goes out through the
/// [`Wire`], in order, or the stack is told it did not.
///
/// A throttled frame is NOT an error to the stack: the stack already
/// advanced its sequence space for it, so reporting a failure would
/// make the caller re-queue bytes that are in fact queued. The frame
/// is parked here instead and leaves at the next successful
/// [`flush`](Self::flush), before anything newer — FIFO, so the peer
/// never sees a retransmission ahead of its original.
#[derive(Debug)]
pub struct BrokerQueue<W: Wire> {
    wire: W,
    frames: [[u8; ETH_FRAME_MAX]; QUEUE_LEN],
    lens: [u16; QUEUE_LEN],
    head: usize,
    count: usize,
    pub stats: QueueStats,
}

impl<W: Wire> BrokerQueue<W> {
    pub fn new(wire: W) -> Self {
        BrokerQueue {
            wire,
            frames: [[0; ETH_FRAME_MAX]; QUEUE_LEN],
            lens: [0; QUEUE_LEN],
            head: 0,
            count: 0,
            stats: QueueStats::default(),
        }
    }

    /// Try to send the deferred frames, oldest first. Returns how
    /// many left; stops at the first throttle so order is kept.
    pub fn flush(&mut self) -> usize {
        let mut sent = 0;
        while self.count > 0 {
            let frame = &self.frames[self.head][..self.lens[self.head] as usize];
            match self.wire.transmit(frame) {
                Ok(()) => {
                    self.stats.sent += 1;
                    sent += 1;
                }
                Err(WireErr::Throttled) => break,
                Err(WireErr::TooLong | WireErr::Refused) => {
                    // Undeliverable for good: drop it, keep order.
                    self.stats.refused += 1;
                }
            }
            self.lens[self.head] = 0;
            self.head = (self.head + 1) % QUEUE_LEN;
            self.count -= 1;
        }
        sent
    }

    /// Frames parked, waiting for the broker.
    pub fn queued(&self) -> usize {
        self.count
    }

    fn push(&mut self, frame: &[u8]) -> bool {
        if self.count == QUEUE_LEN || frame.len() > ETH_FRAME_MAX {
            return false;
        }
        let slot = (self.head + self.count) % QUEUE_LEN;
        self.frames[slot][..frame.len()].copy_from_slice(frame);
        self.lens[slot] = frame.len() as u16;
        self.count += 1;
        true
    }
}

impl<W: Wire> FrameSink for BrokerQueue<W> {
    fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > ETH_FRAME_MAX {
            self.stats.refused += 1;
            return Err(Error::TooLong {
                requested: frame.len() as u32,
                max: ETH_FRAME_MAX as u32,
            });
        }
        self.flush();
        // Still backlogged: the new frame waits its turn behind the
        // older ones (or the stack is told the truth if that wait
        // has no room).
        if self.count > 0 {
            if self.push(frame) {
                self.stats.deferred += 1;
                return Ok(());
            }
            self.stats.backpressured += 1;
            return Err(Error::RateLimited {
                requested: frame.len() as u32,
                available: 0,
            });
        }
        match self.wire.transmit(frame) {
            Ok(()) => {
                self.stats.sent += 1;
                Ok(())
            }
            Err(WireErr::Throttled) => {
                // The broker said "not now" and the frame is
                // deliverable: park it rather than fail the stack's
                // already-committed accounting.
                self.stats.deferred += 1;
                self.push(frame);
                Ok(())
            }
            Err(WireErr::TooLong) => {
                self.stats.refused += 1;
                Err(Error::TooLong {
                    requested: frame.len() as u32,
                    max: ETH_FRAME_MAX as u32,
                })
            }
            Err(WireErr::Refused) => {
                self.stats.refused += 1;
                Err(Error::NoRoute)
            }
        }
    }
}

// ── the relay ──────────────────────────────────────────────────────

/// What the service does with a request.
// (clippy::large_enum_variant is deliberate: `Now` embeds the reply
// frame by value — the service has no allocator to Box it into, and
// one 528-byte temporary per request is the whole cost.)
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Answer the client now.
    Now(Rep),
    /// Accepted; the reply comes from [`Relay::recheck`] after a
    /// later poll (or the operation's deadline).
    Pending,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    op: u8,
    fd: u32,
    /// The caller's buffer capacity for `OP_RECV`.
    cap: u16,
    len: u16,
    started: u64,
    payload: [u8; MAX_PAYLOAD],
}

/// Counters the service reports to the kernel (the boot markers are
/// printed from these).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    /// Requests per op (indexed by op number; slot 0 unused).
    pub requests: [u32; OP_COUNT],
    /// Requests that failed the codec.
    pub malformed: u32,
    /// Pending operations that hit [`OP_TIMEOUT_MS`].
    pub timeouts: u32,
    /// Pending operations displaced by a request that broke lockstep.
    pub cancelled: u32,
    /// Stream bytes accepted from clients / delivered to clients.
    pub stream_sent: u32,
    pub stream_recvd: u32,
    /// Datagram bytes accepted from clients / delivered to clients.
    pub dgram_sent: u32,
    pub dgram_recvd: u32,
}

/// Where a stream descriptor's handshake stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// Never connected (or not a stream socket at all — the stack
    /// answers that with its own errno).
    Fresh,
    Handshaking,
    Established,
    /// Dead: the errno the caller hears (positive).
    Dead(i32),
}

fn stream_state<E: Entropy>(stack: &NetStack<E>, dom: u32, fd: u32) -> Result<StreamState> {
    let e = stack.sockets.get(dom, fd)?;
    match &e.kind {
        SocketKind::Stream { tcb } if *tcb != usize::MAX => Ok(match e.status {
            SocketStatus::Connecting => StreamState::Handshaking,
            SocketStatus::Live if stack.tcp.state_of(*tcb) != TcpState::Closed => {
                StreamState::Established
            }
            SocketStatus::Live => StreamState::Dead(errno::ENOTCONN),
            SocketStatus::Failed(err) => StreamState::Dead(err.errno()),
            SocketStatus::Closed => StreamState::Dead(errno::ENOTCONN),
        }),
        _ => Ok(StreamState::Fresh),
    }
}

/// The per-client state machine over the stack.
///
/// The client index IS the stack's domain id: every stack call names
/// it, so the stack's own ownership check is the capability check
/// between clients.
#[derive(Debug)]
pub struct Relay<E: Entropy> {
    pub stack: NetStack<E>,
    pending: [Option<Pending>; MAX_CLIENTS],
    finished: [bool; MAX_CLIENTS],
    pub stats: RelayStats,
}

impl<E: Entropy> Relay<E> {
    pub fn new(stack: NetStack<E>) -> Self {
        Relay {
            stack,
            pending: [None; MAX_CLIENTS],
            finished: [false; MAX_CLIENTS],
            stats: RelayStats::default(),
        }
    }

    /// The stack domain id a client index maps to.
    pub const fn domain(client: usize) -> u32 {
        client as u32
    }

    /// Did this client send `OP_DONE`?
    pub fn client_finished(&self, client: usize) -> bool {
        self.finished.get(client).copied().unwrap_or(true)
    }

    /// Did every client slot finish?
    pub fn all_finished(&self) -> bool {
        self.finished.iter().all(|f| *f)
    }

    /// Sockets still open across all clients (the service drains
    /// until this is zero before it exits).
    pub fn live_sockets(&self) -> usize {
        self.stack.sockets.len()
    }

    /// Is an operation pending for this client?
    pub fn client_pending(&self, client: usize) -> bool {
        self.pending.get(client).is_some_and(|p| p.is_some())
    }

    fn pend(&mut self, client: usize, req: &Req, now: u64, payload: &[u8]) -> Step {
        let mut p = Pending {
            op: req.op,
            fd: req.fd,
            cap: req.len,
            len: 0,
            started: now,
            payload: [0; MAX_PAYLOAD],
        };
        let n = payload.len().min(MAX_PAYLOAD);
        p.payload[..n].copy_from_slice(&payload[..n]);
        p.len = n as u16;
        self.pending[client] = Some(p);
        Step::Pending
    }

    fn bump_sent(&mut self, dgram: bool, n: usize) {
        let n = n.min(u32::MAX as usize) as u32;
        if dgram {
            self.stats.dgram_sent = self.stats.dgram_sent.saturating_add(n);
        } else {
            self.stats.stream_sent = self.stats.stream_sent.saturating_add(n);
        }
    }

    fn bump_recvd(&mut self, dgram: bool, n: usize) {
        let n = n.min(u32::MAX as usize) as u32;
        if dgram {
            self.stats.dgram_recvd = self.stats.dgram_recvd.saturating_add(n);
        } else {
            self.stats.stream_recvd = self.stats.stream_recvd.saturating_add(n);
        }
    }

    /// Apply one decoded request. `payload` is the request's payload
    /// (`OP_SEND`) and empty otherwise.
    pub fn submit(
        &mut self,
        now: u64,
        sink: &mut dyn FrameSink,
        client: usize,
        req: &Req,
        payload: &[u8],
    ) -> Step {
        if client >= MAX_CLIENTS || !(OP_FIRST..=OP_LAST).contains(&req.op) {
            return Step::Now(Rep::error(req.op, errno::EINVAL));
        }
        // Lockstep is the framing: a new request while one is pending
        // means the client stopped waiting for the old one. Its reply
        // would be read as this request's answer, so it is dropped —
        // counted, never delivered out of turn.
        if self.pending[client].take().is_some() {
            self.stats.cancelled += 1;
        }
        if self.finished[client] {
            return Step::Now(Rep::error(req.op, errno::EINVAL));
        }
        self.stats.requests[req.op as usize] += 1;
        let dom = Self::domain(client);
        let op = req.op;
        let now_ = |r: i32| Step::Now(Rep::result(op, r));
        let fail = |e: Error| Step::Now(Rep::error(op, e.errno()));
        let dontwait = req.flags & FLAG_DONTWAIT != 0;
        match op {
            OP_SOCKET => match self.stack.socket(dom, req.kind as i32) {
                Ok(fd) => now_(fd as i32),
                Err(e) => fail(e),
            },
            OP_BIND => match self.stack.bind(dom, req.fd, req.port) {
                Ok(()) => now_(0),
                Err(e) => fail(e),
            },
            OP_LISTEN => match self.stack.listen(dom, req.fd, req.port) {
                Ok(()) => now_(0),
                Err(e) => fail(e),
            },
            OP_CONNECT => {
                // A repeated connect is the handshake's status query:
                // the first call starts it, later ones report it.
                let state = match stream_state(&self.stack, dom, req.fd) {
                    Ok(s) => s,
                    Err(e) => return fail(e),
                };
                match state {
                    StreamState::Established => now_(0),
                    StreamState::Dead(code) => now_(-code),
                    StreamState::Handshaking if dontwait => now_(-errno::EINPROGRESS),
                    StreamState::Handshaking => self.pend(client, req, now, &[]),
                    StreamState::Fresh => {
                        match self
                            .stack
                            .connect(now, sink, dom, req.fd, &req.ip, req.port)
                        {
                            // A datagram connect is immediate; a stream
                            // connect is in flight (the handshake
                            // completes on polls) — the non-blocking
                            // caller hears that as EINPROGRESS now.
                            Ok(()) => now_(0),
                            Err(Error::InProgress) if dontwait => now_(-errno::EINPROGRESS),
                            Err(Error::InProgress) => self.pend(client, req, now, &[]),
                            Err(e) => fail(e),
                        }
                    }
                }
            }
            OP_ACCEPT => match self.stack.accept(dom, req.fd) {
                Ok(fd) => now_(fd as i32),
                Err(Error::Again) if !dontwait => self.pend(client, req, now, &[]),
                Err(e) => fail(e),
            },
            OP_SEND => match self.stack.send(now, sink, dom, req.fd, payload) {
                Ok(n) => {
                    let dgram = is_dgram(&self.stack, dom, req.fd);
                    self.bump_sent(dgram, n);
                    now_(n as i32)
                }
                Err(e) if retry_later(&e) && !dontwait => self.pend(client, req, now, payload),
                Err(e) => fail(e),
            },
            OP_RECV => {
                let cap = (req.len as usize).min(MAX_PAYLOAD);
                let mut buf = [0u8; MAX_PAYLOAD];
                match self.stack.recv(dom, req.fd, &mut buf[..cap]) {
                    Ok(0) => now_(0),
                    Ok(n) => {
                        let dgram = is_dgram(&self.stack, dom, req.fd);
                        self.bump_recvd(dgram, n);
                        Step::Now(Rep::with_payload(op, n as i32, &buf[..n]))
                    }
                    Err(e) if retry_later(&e) && !dontwait => self.pend(client, req, now, &[]),
                    Err(e) => fail(e),
                }
            }
            OP_CLOSE => match self.stack.close(now, sink, dom, req.fd) {
                Ok(()) => now_(0),
                Err(e) => fail(e),
            },
            OP_DONE => {
                // Every descriptor the client still owns is closed
                // (FIN/RST on the wire for live streams) BEFORE the
                // ack, so the client's exit never strands a TCB.
                for fd in self.owned_fds(client) {
                    let _ = self.stack.close(now, sink, dom, fd);
                }
                self.finished[client] = true;
                now_(0)
            }
            _ => now_(-errno::EINVAL),
        }
    }

    /// Record a reply the service produced WITHOUT the relay (a
    /// malformed request): keeps the counters honest.
    pub fn note_malformed(&mut self) {
        self.stats.malformed += 1;
    }

    /// Advance every pending operation once. Returns the first one
    /// that completed (or timed out) as `(client, reply)`; the
    /// caller loops until `None`.
    pub fn recheck(&mut self, now: u64, sink: &mut dyn FrameSink) -> Option<(usize, Rep)> {
        for client in 0..MAX_CLIENTS {
            let Some(p) = self.pending[client] else {
                continue;
            };
            if now.saturating_sub(p.started) >= OP_TIMEOUT_MS {
                self.pending[client] = None;
                self.stats.timeouts += 1;
                return Some((client, Rep::error(p.op, errno::ETIMEDOUT)));
            }
            let dom = Self::domain(client);
            let reply = match p.op {
                OP_CONNECT => match stream_state(&self.stack, dom, p.fd) {
                    Ok(StreamState::Established) => Some(Rep::result(p.op, 0)),
                    Ok(StreamState::Handshaking) | Ok(StreamState::Fresh) => None,
                    Ok(StreamState::Dead(code)) => Some(Rep::error(p.op, code)),
                    Err(e) => Some(Rep::error(p.op, e.errno())),
                },
                OP_ACCEPT => match self.stack.accept(dom, p.fd) {
                    Ok(fd) => Some(Rep::result(p.op, fd as i32)),
                    Err(Error::Again) => None,
                    Err(e) => Some(Rep::error(p.op, e.errno())),
                },
                OP_SEND => {
                    match self
                        .stack
                        .send(now, sink, dom, p.fd, &p.payload[..p.len as usize])
                    {
                        Ok(n) => {
                            let dgram = is_dgram(&self.stack, dom, p.fd);
                            self.bump_sent(dgram, n);
                            Some(Rep::result(p.op, n as i32))
                        }
                        Err(e) if retry_later(&e) => None,
                        Err(e) => Some(Rep::error(p.op, e.errno())),
                    }
                }
                OP_RECV => {
                    let mut buf = [0u8; MAX_PAYLOAD];
                    match self.stack.recv(dom, p.fd, &mut buf[..p.cap as usize]) {
                        Ok(0) => Some(Rep::result(p.op, 0)),
                        Ok(n) => {
                            let dgram = is_dgram(&self.stack, dom, p.fd);
                            self.bump_recvd(dgram, n);
                            Some(Rep::with_payload(p.op, n as i32, &buf[..n]))
                        }
                        Err(e) if retry_later(&e) => None,
                        Err(e) => Some(Rep::error(p.op, e.errno())),
                    }
                }
                _ => Some(Rep::error(p.op, errno::EINVAL)),
            };
            if let Some(rep) = reply {
                self.pending[client] = None;
                return Some((client, rep));
            }
        }
        None
    }

    /// The stack descriptors (by index) this client still owns;
    /// `u32::MAX` marks an unused slot.
    fn owned_fds(&self, client: usize) -> [u32; MAX_STACK_SOCKETS] {
        let mut fds = [u32::MAX; MAX_STACK_SOCKETS];
        let dom = Self::domain(client);
        for (i, slot) in fds.iter_mut().enumerate() {
            if self
                .stack
                .sockets
                .entries_view(i)
                .is_some_and(|e| e.domain == dom)
            {
                *slot = i as u32;
            }
        }
        fds
    }
}

/// The stack's "try again after a poll" family, plus the two
/// in-flight shapes a blocking caller simply waits out.
fn retry_later(e: &Error) -> bool {
    e.is_retryable() || matches!(e, Error::InProgress | Error::ArpPending)
}

fn is_dgram<E: Entropy>(stack: &NetStack<E>, dom: u32, fd: u32) -> bool {
    stack
        .sockets
        .get(dom, fd)
        .is_ok_and(|e| matches!(e.kind, SocketKind::Dgram { .. }))
}

#[cfg(test)]
mod tests;
