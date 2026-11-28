//! TCP: the state machine, TCB pool, windows, timers (K24).
//!
//! This is the stack's largest module, and the one a CVE would live
//! in. The design rules, stated once and enforced everywhere:
//!
//! 1. **Sequence arithmetic is wrapping** (RFC 793 §3.3): every
//!    comparison goes through [`seq_lt`]/[`seq_le`] — a raw `<` on
//!    sequence numbers is a bug by construction. The 32-bit space
//!    wraps; tests drive it across the wrap.
//! 2. **Every length from the wire is bounds-checked before use**:
//!    data_offset*4 ≤ segment length, payload slices are views into
//!    the IP payload the caller already measured, and the receive
//!    window the peer violates lands in the acceptance test, not in
//!    a copy loop.
//! 3. **All state is bounded**: [`MAX_TCBS`] blocks, [`MAX_LISTENERS`]
//!    listeners, a [`LISTEN_BACKLOG`] deep accept queue, a
//!    [`MAX_HALF_OPEN`] budget, per-source SYN rate windows, and
//!    every timer has a deadline. Nothing grows with attacker
//!    effort.
//! 4. **SYN flood**: three layers — per-source rate window, a
//!    half-open budget, and SYN COOKIES when the budget is spent
//!    (the cookie is a per-boot-secret keyed mix over the 4-tuple
//!    and a 64-second time bucket; a TCB is only materialized when
//!    the returning ACK proves possession of the cookie). See
//!    THREAT_MODEL.md §SYN Flood for why cookies and not SYN caches.
//! 5. **ISN generation** mixes the per-boot secret, a coarse clock,
//!    a per-boot counter and the remote 4-tuple (§TCP Sequence
//!    Number Prediction): consecutive connections to the same peer
//!    get unrelated ISNs.
//! 6. **Go-Back-N retransmission** (deliberate, documented): we keep
//!    ONE retransmission timer per TCB and re-send from `snd_una`;
//!    out-of-order receive segments are dropped with a duplicate ACK
//!    (triggering the peer's fast retransmit). No out-of-order
//!    queue exists to poison — bounded memory, and the cost is
//!    throughput, not correctness.
//! 7. **Delayed ACKs** (40 ms) with the two classic immediate-ACK
//!    exceptions: a second in-order segment while one is pending,
//!    and a FIN.
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use super::arp::ArpLayer;
use super::error::{Error, Result};
use super::ethernet::{EtherType, MacAddr};
use super::ipv4::{emit_header, pseudo_header_checksum, PROTO_TCP};
use super::FrameSink;

/// (internal) the Ethernet header length alias used by the
/// split-borrow egress paths.
mod eth_hdr {
    pub const LEN: usize = super::super::ethernet::ETH_HDR_LEN;
}

// ── wire constants ─────────────────────────────────────────────────

pub const TCP_HDR_LEN: usize = 20;
pub const FIN_BIT: u8 = 0x01;
pub const SYN_BIT: u8 = 0x02;
pub const RST_BIT: u8 = 0x04;
pub const PSH_BIT: u8 = 0x08;
pub const ACK_BIT: u8 = 0x10;

// ── pool/timer/budget constants (all attack-surface bounds) ───────

/// Transmission control blocks. Eight concurrent connections is the
/// honest budget for a stack this size; the ninth `connect` answers
/// [`Error::TcbPoolFull`] (EMFILE) — never an allocation.
pub const MAX_TCBS: usize = 8;
/// Listening sockets.
pub const MAX_LISTENERS: usize = 4;
/// Connections per accept queue (completed or half-open).
pub const LISTEN_BACKLOG: usize = 4;
/// Half-open (SYN_RECEIVED) TCBs, stack-wide, before cookie mode.
pub const MAX_HALF_OPEN: usize = 4;
/// Per-source SYN rate window.
pub const SYN_RATE_WINDOW_MS: u64 = 500;
/// SYNs accepted per source per window.
pub const SYN_RATE_MAX: u8 = 4;
/// Tracked SYN-rate sources (fixed).
pub const SYN_RATE_SLOTS: usize = 8;

/// Per-TCB send buffer (unacked + unsent bytes).
pub const SEND_BUF: usize = 1024;
/// Per-TCB receive buffer (delivered-but-unread bytes).
pub const RECV_BUF: usize = 1024;
/// The MSS we offer and use absent peer options (RFC 879's safe
/// default for any path).
pub const DEFAULT_MSS: u16 = 536;
/// Largest MSS we will honor from a peer option (MTU 1500 − 40).
pub const MAX_MSS: u16 = 1460;
/// Initial retransmission timeout; doubles per retransmission to
/// [`MAX_RTO_MS`] (exponential backoff, RFC 6298's shape with a
/// fixed RTO — no RTT estimator, documented honestly).
pub const INITIAL_RTO_MS: u64 = 1000;
pub const MAX_RTO_MS: u64 = 60_000;
/// Retransmissions before the connection is declared dead.
pub const MAX_RETRANSMITS: u8 = 6;
/// Delayed-ACK delay.
pub const DELAYED_ACK_MS: u64 = 40;
/// Zero-window persist probe interval.
pub const PERSIST_MS: u64 = 5_000;
/// MSL for TIME_WAIT = 2×MSL bounded lifetime.
pub const MSL_MS: u64 = 60_000;
/// SYN cookie time bucket (the cookie's validity window, ±1
/// bucket on validation).
pub const COOKIE_BUCKET_MS: u64 = 64_000;
/// RST generation budget (anti-amplification, like ICMP's).
pub const RST_RATE_MAX: u8 = 5;
pub const RST_RATE_WINDOW_MS: u64 = 1000;

// ── sequence-number arithmetic (RFC 793 §3.3) ──────────────────────

/// a < b in the wrapping 32-bit sequence space.
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
/// a ≤ b in the wrapping sequence space.
pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}
/// a > b in the wrapping sequence space.
pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}
/// a ≥ b in the wrapping sequence space.
pub fn seq_ge(a: u32, b: u32) -> bool {
    a == b || seq_gt(a, b)
}

// ── the cookie and ISN mixers ─────────────────────────────────────

/// The SYN cookie: a keyed mix of the per-boot secret, the remote
/// 4-tuple and the coarse time bucket. Not a PRF — a per-boot
/// unpredictable mixing function (the secret is folded from the
/// domain's entropy source at stack construction). Attackers
/// without the secret cannot mint cookies for OUR stack, and cannot
/// predict another connection's cookie from a known one.
pub fn syn_cookie(
    secret: u32,
    remote_ip: &[u8; 4],
    remote_port: u16,
    local_port: u16,
    t_bucket: u64,
) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let fold = |x: u32, h: &mut u32| {
        *h ^= x;
        *h = h.wrapping_mul(0x0100_0193);
    };
    for b in remote_ip.iter() {
        fold(*b as u32, &mut h);
    }
    fold(remote_port as u32, &mut h);
    fold(local_port as u32, &mut h);
    fold((t_bucket & 0xffff_ffff) as u32, &mut h);
    fold((t_bucket >> 32) as u32, &mut h);
    h ^= secret;
    // Two rounds of multiply-xorshift mixing.
    h = h.wrapping_mul(0x9e37_79b1);
    h ^= h >> 15;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h
}

// ── segment parsing ────────────────────────────────────────────────

/// A parsed TCP segment. `payload` is a view into the caller's IP
/// payload, bounded by data_offset*4 (validated) and the real
/// buffer length; `opts` is the header's option space (bytes 20 ..
/// data_offset*4), the ONLY place option parsing ever looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// Raw flag bits (FIN/SYN/RST/PSH/ACK).
    pub flags: u8,
    /// The peer's advertised receive window.
    pub window: u16,
    pub data_offset: usize,
    pub opts: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// Parse and verify one segment. Gates, in order: length ≥ 20,
    /// data_offset ≥ 5, data_offset*4 ≤ buffer (the overread gate),
    /// then the checksum over the pseudo-header + whole segment.
    /// The SYN flag's options are parsed separately (only the MSS
    /// kind, only on SYN).
    pub fn parse(buf: &'a [u8], src: &[u8; 4], dst: &[u8; 4]) -> Result<TcpSegment<'a>> {
        if buf.len() < TCP_HDR_LEN {
            return Err(Error::Truncated {
                need: TCP_HDR_LEN,
                have: buf.len(),
            });
        }
        let src_port = ((buf[0] as u16) << 8) | buf[1] as u16;
        let dst_port = ((buf[2] as u16) << 8) | buf[3] as u16;
        let seq = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data_offset = (buf[12] >> 4) as usize;
        let flags = buf[13];
        let window = ((buf[14] as u16) << 8) | buf[15] as u16;
        let checksum = ((buf[16] as u16) << 8) | buf[17] as u16;
        if data_offset < 5 {
            return Err(Error::Malformed("tcp: data offset < 5"));
        }
        let hdr_len = data_offset
            .checked_mul(4)
            .ok_or(Error::Malformed("tcp: data offset overflow"))?;
        if hdr_len > buf.len() {
            return Err(Error::Malformed("tcp: data offset > segment"));
        }
        let opts = &buf[TCP_HDR_LEN..hdr_len];
        let payload = &buf[hdr_len..];
        // Checksum: pseudo-header + segment (with embedded checksum)
        // must fold to ones'-complement zero.
        let seg_len = u16::try_from(buf.len()).map_err(|_| Error::DatagramTooLarge {
            len: buf.len(),
            max: u16::MAX as usize,
        })?;
        if checksum != 0 && !folds_zero(src, dst, seg_len, buf) {
            return Err(Error::BadTransportChecksum);
        }
        Ok(TcpSegment {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            data_offset,
            opts,
            payload,
        })
    }

    pub const fn has_syn(&self) -> bool {
        self.flags & SYN_BIT != 0
    }
    pub const fn has_ack(&self) -> bool {
        self.flags & ACK_BIT != 0
    }
    pub const fn has_fin(&self) -> bool {
        self.flags & FIN_BIT != 0
    }
    pub const fn has_rst(&self) -> bool {
        self.flags & RST_BIT != 0
    }
    /// Sequence-space length: payload + 1 for SYN + 1 for FIN.
    pub fn seg_len(&self) -> u32 {
        let mut n = self.payload.len() as u32;
        if self.has_syn() {
            n = n.saturating_add(1);
        }
        if self.has_fin() {
            n = n.saturating_add(1);
        }
        n
    }
}

/// The verification fold for a whole segment (pseudo-header +
/// header-with-checksum + payload).
fn folds_zero(src: &[u8; 4], dst: &[u8; 4], seg_len: u16, whole: &[u8]) -> bool {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(src);
    ph[4..8].copy_from_slice(dst);
    ph[8] = 0;
    ph[9] = PROTO_TCP;
    ph[10] = (seg_len >> 8) as u8;
    ph[11] = seg_len as u8;
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

/// Pull the MSS option out of a SYN's option space. Anything
/// malformed in the options is IGNORED (options are advisory) —
/// bounded scan, never a parse failure.
fn mss_from_options(hdr_and_opts: &[u8]) -> Option<u16> {
    let mut i = TCP_HDR_LEN;
    while i + 1 < hdr_and_opts.len() {
        let kind = hdr_and_opts[i];
        let len = hdr_and_opts[i + 1] as usize;
        if kind == 0 {
            break; // EOL
        }
        if kind == 1 {
            i += 1; // NOP
            continue;
        }
        if len < 2 || i + len > hdr_and_opts.len() {
            break; // malformed advisory option: stop scanning
        }
        if kind == 2 && len == 4 {
            let m = ((hdr_and_opts[i + 2] as u16) << 8) | hdr_and_opts[i + 3] as u16;
            return Some(m);
        }
        i += len;
    }
    None
}

// ── states, events ─────────────────────────────────────────────────

/// The eleven RFC 793 states (CLOSED is the free-slot state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl core::fmt::Display for TcpState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
        };
        f.write_str(s)
    }
}

/// Why a TCB died — surfaced to the socket layer so `recv`/`connect`
/// answer the RIGHT errno (ETIMEDOUT vs ECONNREFUSED vs 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Normal,
    Refused,
    Reset,
    TimedOut,
}

/// Events the TCP layer reports to the stack (fixed queue, drained
/// by the owner after every input/poll — no callbacks, no dynamic
/// dispatch, no re-entrancy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpEvent {
    /// A client-side handshake completed (SYN_SENT → ESTABLISHED).
    Connected { tcb: usize },
    /// A server-side connection completed and sits in the listener's
    /// accept queue.
    AcceptReady { listener: usize, tcb: usize },
    /// In-order data was delivered to a TCB's receive buffer.
    RecvReady { tcb: usize },
    /// The peer half-closed (FIN received).
    PeerClosed { tcb: usize },
    /// The TCB is gone and its pool slot is free.
    Closed { tcb: usize, reason: CloseReason },
}

/// Fixed-size event queue (the stack drains it every cycle).
#[derive(Debug)]
pub struct EventQueue {
    slots: [Option<TcpEvent>; 16],
    head: usize,
    count: usize,
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EventQueue {
    pub const fn new() -> EventQueue {
        EventQueue {
            slots: [None; 16],
            head: 0,
            count: 0,
        }
    }
    pub fn push(&mut self, ev: TcpEvent) {
        if self.count == 16 {
            return; // bounded: a lost event is a missed wakeup, the
                    // next poll re-derives from state (timers and
                    // recv() both re-check).
        }
        let idx = (self.head + self.count) % 16;
        self.slots[idx] = Some(ev);
        self.count += 1;
    }
    pub fn pop(&mut self) -> Option<TcpEvent> {
        if self.count == 0 {
            return None;
        }
        let ev = self.slots[self.head].take();
        self.head = (self.head + 1) % 16;
        self.count -= 1;
        ev
    }
    pub fn clear(&mut self) {
        self.slots = [None; 16];
        self.head = 0;
        self.count = 0;
    }
}

// ── the byte rings ─────────────────────────────────────────────────

/// A fixed byte ring used as the send buffer (unacked + unsent) and
/// the receive buffer (delivered, unread). All indices wrap by
/// masking because the capacities are powers of two — no modulo
/// division, and the capacity invariant is checked at construction
/// sites by the type system (const generic power of two).
#[derive(Debug, Clone, Copy)]
pub struct Ring {
    data: [u8; 1024],
    head: usize,
    len: usize,
}

impl Default for Ring {
    fn default() -> Self {
        Self::new()
    }
}

impl Ring {
    pub const fn new() -> Ring {
        Ring {
            data: [0; 1024],
            head: 0,
            len: 0,
        }
    }
    /// Append up to `bytes.len()` bytes (bounded by free space);
    /// returns how many were stored.
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        let free = self.data.len() - self.len;
        let n = bytes.len().min(free);
        for (k, &b) in bytes.iter().enumerate().take(n) {
            let idx = (self.head + self.len + k) % self.data.len();
            self.data[idx] = b;
        }
        self.len += n;
        n
    }
    /// Pop into `out`; returns bytes copied.
    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(out.len());
        for k in 0..n {
            out[k] = self.data[(self.head + k) % self.data.len()];
        }
        self.head = (self.head + n) % self.data.len();
        self.len -= n;
        n
    }
    /// Read `n` bytes starting at offset `off` from the head WITHOUT
    /// consuming (retransmission reads). Returns the bytes actually
    /// readable (bounded by len − off).
    pub fn peek(&self, off: usize, n: usize, out: &mut [u8]) -> usize {
        if off >= self.len {
            return 0;
        }
        let avail = self.len - off;
        let n = n.min(avail).min(out.len());
        for k in 0..n {
            out[k] = self.data[(self.head + off + k) % self.data.len()];
        }
        n
    }
    /// Drop `n` bytes from the head (an ACK advancing snd_una).
    pub fn consume(&mut self, n: usize) -> usize {
        let n = n.min(self.len);
        self.head = (self.head + n) % self.data.len();
        self.len -= n;
        n
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn free(&self) -> usize {
        self.data.len() - self.len
    }
}

// ── the TCB ────────────────────────────────────────────────────────

/// One transmission control block. Fixed cost, no allocation, all
/// timers absolute deadlines (ms ticks from the caller's clock).
#[derive(Debug, Clone, Copy)]
pub struct Tcb {
    pub state: TcpState,
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    /// Our initial sequence number.
    pub iss: u32,
    /// Peer's initial sequence number (rcv_nxt at handshake end).
    pub irs: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    /// Peer's advertised receive window (u32 to survive a 0-window
    /// probe without sign games).
    pub snd_wnd: u32,
    pub rcv_nxt: u32,
    send: Ring,
    recv: Ring,
    fin_queued: bool,
    fin_sent: bool,
    /// Sequence number one past our FIN (i.e. snd_nxt after FIN).
    fin_end: Option<u32>,
    fin_rcvd: bool,
    pub mss: u16,
    rto_ms: u64,
    rto_at: Option<u64>,
    retransmits: u8,
    delayed_ack_at: Option<u64>,
    timewait_until: Option<u64>,
    // congestion window (bytes) + threshold + dupack counter
    cwnd: u32,
    ssthresh: u32,
    dup_acks: u8,
    // zero-window persist timer
    persist_at: Option<u64>,
    /// The peer saw a zero window and we just drained receive
    /// bytes: send a WINDOW-UPDATE ack on the next poll (the
    /// "window opened" notification — without it a drained peer
    /// waits for its persist probe to learn the window moved).
    window_update_pending: bool,
    /// Which listener's accept queue holds this TCB (server side).
    pub listener: Option<usize>,
}

impl Default for Tcb {
    fn default() -> Self {
        Self::fresh()
    }
}

impl Tcb {
    const fn fresh() -> Tcb {
        Tcb {
            state: TcpState::Closed,
            local_ip: [0; 4],
            local_port: 0,
            remote_ip: [0; 4],
            remote_port: 0,
            iss: 0,
            irs: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            rcv_nxt: 0,
            send: Ring::new(),
            recv: Ring::new(),
            fin_queued: false,
            fin_sent: false,
            fin_end: None,
            fin_rcvd: false,
            mss: DEFAULT_MSS,
            rto_ms: INITIAL_RTO_MS,
            rto_at: None,
            retransmits: 0,
            delayed_ack_at: None,
            timewait_until: None,
            cwnd: 0,
            ssthresh: 0,
            dup_acks: 0,
            persist_at: None,
            window_update_pending: false,
            listener: None,
        }
    }

    /// Bytes in flight (sent, unacked).
    fn inflight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }
    /// The window we advertise: free receive space, clamped to u16.
    fn advertised_window(&self) -> u16 {
        self.recv.free() as u16
    }
    /// The peer-permitted send budget: min(cwnd, advertised).
    fn effective_window(&self) -> u32 {
        self.cwnd.min(self.snd_wnd)
    }
}

/// One listener: bound port + accept queue (TCB indices).
#[derive(Debug, Clone, Copy)]
pub struct Listener {
    pub port: u16,
    queue: [Option<usize>; LISTEN_BACKLOG],
    head: usize,
    count: usize,
}

impl Default for Listener {
    fn default() -> Self {
        Self::fresh()
    }
}

impl Listener {
    const fn fresh() -> Listener {
        Listener {
            port: 0,
            queue: [None; LISTEN_BACKLOG],
            head: 0,
            count: 0,
        }
    }
    fn push(&mut self, tcb: usize) -> bool {
        if self.count == LISTEN_BACKLOG {
            return false;
        }
        let idx = (self.head + self.count) % LISTEN_BACKLOG;
        self.queue[idx] = Some(tcb);
        self.count += 1;
        true
    }
    /// Queue a cookie-MATERIALIZED connection: a completed handshake
    /// outranks a pending one — when the queue is full, the OLDEST
    /// half-open entry is evicted (its TCB reset, never an event: no
    /// fd ever referenced it). False only when every slot holds an
    /// ESTABLISHED connection (a genuinely full service).
    fn push_for_cookie(&mut self, tcbs: &mut [Tcb; MAX_TCBS], t: usize) -> bool {
        if self.count < LISTEN_BACKLOG {
            self.push(t);
            return true;
        }
        for k in 0..self.count {
            let idx = (self.head + k) % LISTEN_BACKLOG;
            if let Some(q) = self.queue[idx] {
                if tcbs[q].state == TcpState::SynReceived {
                    self.drop_dead(q);
                    tcbs[q] = Tcb::fresh();
                    return self.push(t);
                }
            }
        }
        false
    }

    /// Pop the next COMPLETED (ESTABLISHED) connection; half-open
    /// entries are skipped (they stay queued until complete or dead).
    fn pop_established(&mut self, tcbs: &[Tcb; MAX_TCBS]) -> Option<usize> {
        for k in 0..self.count {
            let idx = (self.head + k) % LISTEN_BACKLOG;
            if let Some(t) = self.queue[idx] {
                if tcbs[t].state == TcpState::Established {
                    self.queue[idx] = None;
                    // Compact: shift everything after k one left.
                    for j in k..self.count - 1 {
                        let a = (self.head + j + 1) % LISTEN_BACKLOG;
                        let b = (self.head + j) % LISTEN_BACKLOG;
                        self.queue[b] = self.queue[a];
                    }
                    self.queue[(self.head + self.count - 1) % LISTEN_BACKLOG] = None;
                    self.count -= 1;
                    return Some(t);
                }
            }
        }
        None
    }
    /// Drop a dead TCB from the queue (compaction as above).
    fn drop_dead(&mut self, tcb: usize) {
        for k in 0..self.count {
            let idx = (self.head + k) % LISTEN_BACKLOG;
            if self.queue[idx] == Some(tcb) {
                for j in k..self.count.saturating_sub(1) {
                    let a = (self.head + j + 1) % LISTEN_BACKLOG;
                    let b = (self.head + j) % LISTEN_BACKLOG;
                    self.queue[b] = self.queue[a];
                }
                self.queue[(self.head + self.count - 1) % LISTEN_BACKLOG] = None;
                self.count -= 1;
                return;
            }
        }
    }
}

/// Per-source SYN rate window.
#[derive(Debug, Clone, Copy)]
struct SynWindow {
    ip: [u8; 4],
    window_start: u64,
    count: u8,
}

/// The stack's idea of "us" for the TCP layer (a value copy of the
/// interface config the layer needs on every send).
#[derive(Debug, Clone, Copy)]
pub struct TcpIfCfg {
    pub our_ip: [u8; 4],
    pub our_mac: MacAddr,
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
}

impl TcpIfCfg {
    /// The next hop for a destination: on-link peers directly, the
    /// gateway otherwise. Zero gateway + off-link → NoRoute.
    fn next_hop(&self, dst: &[u8; 4]) -> Result<[u8; 4]> {
        let on_link = (self.our_ip[0] & self.netmask[0]) == (dst[0] & self.netmask[0])
            && (self.our_ip[1] & self.netmask[1]) == (dst[1] & self.netmask[1])
            && (self.our_ip[2] & self.netmask[2]) == (dst[2] & self.netmask[2])
            && (self.our_ip[3] & self.netmask[3]) == (dst[3] & self.netmask[3]);
        if on_link {
            Ok(*dst)
        } else if self.gateway != [0, 0, 0, 0] {
            Ok(self.gateway)
        } else {
            Err(Error::NoRoute)
        }
    }
}

/// The TCP layer: pools + the segment builder + the input state
/// machine + the timer engine.
#[derive(Debug)]
pub struct TcpLayer {
    pub tcbs: [Tcb; MAX_TCBS],
    pub listeners: [Listener; MAX_LISTENERS],
    syn_rate: [SynWindow; SYN_RATE_SLOTS],
    pub events: EventQueue,
    /// Per-boot secret (folded from the domain's entropy source by
    /// the stack owner) — ISNs and cookies derive from it.
    pub secret: u32,
    isn_counter: u32,
    ip_id: u16,
    rst_window: (u64, u8),
    // statistics
    pub segments_sent: u64,
    pub segments_received: u64,
    pub retransmissions: u64,
    pub syn_cookies_issued: u64,
    pub syn_cookies_completed: u64,
    pub syn_rate_dropped: u64,
    pub rst_sent: u64,
    pub rst_received: u64,
    pub checksum_drops: u64,
    pub out_of_window_drops: u64,
    tx: [u8; 1514],
}

impl Default for TcpLayer {
    fn default() -> Self {
        Self::new(0)
    }
}

impl TcpLayer {
    pub const fn new(secret: u32) -> TcpLayer {
        TcpLayer {
            tcbs: [Tcb::fresh(); MAX_TCBS],
            listeners: [Listener::fresh(); MAX_LISTENERS],
            syn_rate: [SynWindow {
                ip: [0; 4],
                window_start: 0,
                count: 0,
            }; SYN_RATE_SLOTS],
            events: EventQueue::new(),
            secret,
            isn_counter: 0,
            ip_id: 0,
            rst_window: (0, 0),
            segments_sent: 0,
            segments_received: 0,
            retransmissions: 0,
            syn_cookies_issued: 0,
            syn_cookies_completed: 0,
            syn_rate_dropped: 0,
            rst_sent: 0,
            rst_received: 0,
            checksum_drops: 0,
            out_of_window_drops: 0,
            tx: [0; 1514],
        }
    }

    // ── public queries used by the socket layer ───────────────────

    pub fn state_of(&self, idx: usize) -> TcpState {
        self.tcbs[idx].state
    }

    pub fn recv_len(&self, idx: usize) -> usize {
        self.tcbs[idx].recv.len()
    }

    /// Read received bytes (socket `recv`).
    pub fn recv(&mut self, idx: usize, out: &mut [u8]) -> Result<usize> {
        let tcb = &mut self.tcbs[idx];
        if matches!(tcb.state, TcpState::Closed) {
            return Err(Error::InvalidSocket(idx as u32));
        }
        let was_full = tcb.recv.free() == 0;
        let n = tcb.recv.pop(out);
        if n == 0 {
            if tcb.fin_rcvd {
                // Peer closed and the buffer is drained: EOF (0).
                return Ok(0);
            }
            return Err(Error::Again);
        }
        // The peer's zero window just opened (the ring was full,
        // the user drained): the next poll sends a WINDOW-UPDATE
        // ack so the peer learns without waiting for its persist
        // probe (the classic deadlock — found live in the window
        // test).
        if was_full && tcb.recv.free() > 0 {
            tcb.window_update_pending = true;
        }
        Ok(n)
    }

    /// Queue outgoing bytes; transmits what the window allows.
    /// Returns bytes accepted (0 → EAGAIN/stalled).
    pub fn send(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        data: &[u8],
    ) -> Result<usize> {
        let (state, remote_ok) = {
            let tcb = &self.tcbs[idx];
            (
                tcb.state,
                matches!(tcb.state, TcpState::Established | TcpState::CloseWait),
            )
        };
        if !remote_ok {
            return Err(match state {
                TcpState::Closed => Error::InvalidSocket(idx as u32),
                TcpState::CloseWait => Error::NotOpen(idx as u32),
                _ => Error::WrongKind("tcp: send on non-established"),
            });
        }
        let accepted = {
            let tcb = &mut self.tcbs[idx];
            let free = tcb.send.free().min(data.len());
            tcb.send.push(&data[..free])
        };
        if accepted == 0 {
            return Err(Error::SendStalled);
        }
        self.push_pending(now, cfg, arp, sink, idx)?;
        Ok(accepted)
    }

    /// Active open: SYN_SENT, SYN emitted. `connect` semantics:
    /// Err(InProgress) to the caller, completion by event.
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        local_port: u16,
        remote_ip: &[u8; 4],
        remote_port: u16,
    ) -> Result<usize> {
        let idx = self.alloc_tcb().ok_or(Error::TcbPoolFull)?;
        let isn = self.next_isn(now, remote_ip, remote_port);
        {
            let tcb = &mut self.tcbs[idx];
            tcb.state = TcpState::SynSent;
            tcb.local_ip = cfg.our_ip;
            tcb.local_port = local_port;
            tcb.remote_ip = *remote_ip;
            tcb.remote_port = remote_port;
            tcb.iss = isn;
            tcb.snd_una = isn;
            tcb.snd_nxt = isn.wrapping_add(1);
            tcb.rcv_nxt = 0;
            tcb.rto_ms = INITIAL_RTO_MS;
            tcb.rto_at = Some(now.saturating_add(INITIAL_RTO_MS));
            tcb.retransmits = 0;
            tcb.cwnd = 2 * DEFAULT_MSS as u32;
            tcb.ssthresh = 8 * DEFAULT_MSS as u32;
        }
        // The SYN's FIRST emission may pend on ARP resolution (or be
        // refused by the broker's bucket) — either way the TCB is
        // live, the frame rides the ARP queue, and the RTO machinery
        // re-drives it from poll(). connect() must return the idx so
        // the SOCKET layer can bind its fd; propagating ArpPending
        // here orphaned the TCB: the SYN left, the handshake even
        // completed on the wire, but the fd never learned its tcb —
        // send() answered NotBound forever. Caught live by the K27
        // TLS lane (SYN+SYN-ACK+ACK on the pcap, zero data).
        let _ = self.send_control(now, cfg, arp, sink, idx, SYN_BIT, None);
        Ok(idx)
    }

    /// Passive open on a port.
    pub fn listen(&mut self, port: u16) -> Result<usize> {
        for (i, l) in self.listeners.iter_mut().enumerate() {
            if l.count == 0 && l.port == 0 {
                l.port = port;
                l.head = 0;
                l.queue = [None; LISTEN_BACKLOG];
                return Ok(i);
            }
        }
        Err(Error::TcbPoolFull) // no listener slots: the honest EMFILE shape
    }

    /// Pop one established connection off a listener's queue.
    pub fn accept(&mut self, listener: usize) -> Result<usize> {
        let l = &mut self.listeners[listener];
        match l.pop_established(&self.tcbs) {
            Some(t) => {
                self.tcbs[t].listener = None;
                Ok(t)
            }
            None => Err(Error::Again),
        }
    }

    /// Close: FIN when established (after queued data drains — the
    /// fin_queued flag rides the ring), RST for half-open states.
    pub fn close(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
    ) -> Result<()> {
        let state = self.tcbs[idx].state;
        match state {
            TcpState::Established | TcpState::CloseWait | TcpState::FinWait2 => {
                let send_empty = self.tcbs[idx].send.is_empty();
                if send_empty {
                    self.send_fin(now, cfg, arp, sink, idx)?;
                } else {
                    self.tcbs[idx].fin_queued = true;
                }
                Ok(())
            }
            TcpState::SynSent | TcpState::SynReceived => {
                // Half-open: abort with RST (RFC 1122 4.2.2.13).
                self.abort_with_rst(now, cfg, arp, sink, idx);
                self.free_tcb(idx, CloseReason::Normal);
                Ok(())
            }
            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                // Teardown already in flight: idempotent.
                Ok(())
            }
            TcpState::Closed | TcpState::Listen => Ok(()),
        }
    }

    // ── input path ────────────────────────────────────────────────

    /// One segment from the wire. Every branch ends in an explicit
    /// drop or a state transition — no silent fallthrough.
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    pub fn on_segment(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        src: &[u8; 4],
        dst: &[u8; 4],
        raw: &[u8],
    ) -> Result<()> {
        let seg = match TcpSegment::parse(raw, src, dst) {
            Ok(s) => s,
            Err(Error::BadTransportChecksum) => {
                self.checksum_drops += 1;
                return Ok(()); // counted drop, never a reply
            }
            Err(e) => return Err(e),
        };
        self.segments_received += 1;

        // RST rate-limit window bookkeeping (for OUR RST sends).
        let _ = self.rst_window;

        // 1) an existing TCB for this 4-tuple?
        if let Some(idx) = self.find_tcb(src, seg.src_port, seg.dst_port) {
            return self.on_segment_for_tcb(now, cfg, arp, sink, idx, &seg);
        }

        // 2) no TCB: SYN to a listener? (or cookie completion)
        if seg.has_syn() && !seg.has_ack() {
            let listener = self.find_listener(seg.dst_port);
            if let Some(l) = listener {
                return self.on_syn(now, cfg, arp, sink, l, src, &seg);
            }
            // No listener on this port: RST|ACK acknowledging their
            // SYN (rate-limited) — the ECONNREFUSED half of the
            // contract.
            self.maybe_send_rst(
                now,
                cfg,
                arp,
                sink,
                src,
                seg.src_port,
                seg.dst_port,
                RST_BIT | ACK_BIT,
                0,
                seg.seq.wrapping_add(seg.seg_len()),
            );
            return Ok(());
        }

        // 3) an ACK naming no TCB: the SYN-cookie completion path
        //    (our SYN-ACK answered when no TCB was spent), or a
        //    stale/blind ACK → rate-limited RST.
        if seg.has_ack() {
            if let Some(l) = self.find_listener(seg.dst_port) {
                if self.try_cookie_completion(now, cfg, arp, sink, l, src, &seg) {
                    return Ok(());
                }
            }
            // A blind ACK: bare RST carrying their ack as our seq.
            self.maybe_send_rst(
                now,
                cfg,
                arp,
                sink,
                src,
                seg.src_port,
                seg.dst_port,
                RST_BIT,
                seg.ack,
                0,
            );
            return Ok(());
        }

        // FIN/anything else for nobody: quiet drop (RST only for
        // ACK-bearing segments above — FIN-with-no-ACK to no TCB is
        // already answered by the ACK branch's RST when it carries
        // one; a bare FIN needs no reply).
        Ok(())
    }

    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn on_syn(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        listener: usize,
        src: &[u8; 4],
        seg: &TcpSegment<'_>,
    ) -> Result<()> {
        // Layer 1: per-source rate window (THREAT_MODEL.md §SYN
        // Flood). Over-budget SYNs drop silently.
        if !self.syn_rate_admit(now, src) {
            self.syn_rate_dropped += 1;
            return Ok(());
        }
        // Layer 2: half-open budget + accept queue room → a real
        // TCB in SYN_RECEIVED.
        let half_open = self
            .tcbs
            .iter()
            .filter(|t| t.state == TcpState::SynReceived)
            .count();
        let queue_room = self.listeners[listener].count < LISTEN_BACKLOG;
        if half_open < MAX_HALF_OPEN && queue_room {
            if let Some(idx) = self.alloc_tcb() {
                let isn = self.next_isn(now, src, seg.src_port);
                {
                    let tcb = &mut self.tcbs[idx];
                    tcb.state = TcpState::SynReceived;
                    tcb.local_ip = cfg.our_ip;
                    tcb.local_port = seg.dst_port;
                    tcb.remote_ip = *src;
                    tcb.remote_port = seg.src_port;
                    tcb.iss = isn;
                    tcb.snd_una = isn;
                    tcb.snd_nxt = isn.wrapping_add(1);
                    tcb.rcv_nxt = seg.seq.wrapping_add(1); // SYN consumed
                    tcb.irs = seg.seq;
                    tcb.snd_wnd = seg.window as u32;
                    tcb.mss = mss_from_options(seg.opts).map_or(DEFAULT_MSS, |m| m.min(MAX_MSS));
                    tcb.rto_ms = INITIAL_RTO_MS;
                    tcb.rto_at = Some(now.saturating_add(INITIAL_RTO_MS));
                    tcb.retransmits = 0;
                    tcb.cwnd = 2 * tcb.mss as u32;
                    tcb.ssthresh = 8 * tcb.mss as u32;
                    tcb.listener = Some(listener);
                }
                // A dup SYN for an entry already queued? find_tcb
                // above would have matched it — reaching here means
                // fresh.
                self.listeners[listener].push(idx);
                let offered_mss = self.tcbs[idx].mss;
                self.send_control(
                    now,
                    cfg,
                    arp,
                    sink,
                    idx,
                    SYN_BIT | ACK_BIT,
                    Some(offered_mss),
                )?;
                return Ok(());
            }
        }
        // Layer 3: budget spent (or no TCB/queue room) → SYN COOKIE
        // (no TCB, no queue slot): the SYN-ACK's ISN IS the cookie.
        // A returning ACK proving cookie+1 materializes the
        // connection (§SYN Flood).
        let cookie = syn_cookie(
            self.secret,
            src,
            seg.src_port,
            seg.dst_port,
            now / COOKIE_BUCKET_MS,
        );
        self.syn_cookies_issued += 1;
        // The cookie SYN-ACK is fire-and-forget: an egress refusal
        // (ARP pending, broker throttle) costs nothing — a real
        // client re-SYNs, a flood gets silence.
        let _ = self.send_synack_cookie(
            now,
            cfg,
            arp,
            sink,
            *src,
            seg.src_port,
            seg.dst_port,
            cookie,
            seg.seq.wrapping_add(1),
        );
        Ok(())
    }

    /// The cookie completion: an ACK for no TCB whose ack-1 equals
    /// the cookie we would have minted for this 4-tuple in the
    /// current (or previous) time bucket.
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn try_cookie_completion(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        listener: usize,
        src: &[u8; 4],
        seg: &TcpSegment<'_>,
    ) -> bool {
        let bucket = now / COOKIE_BUCKET_MS;
        let claimed = seg.ack.wrapping_sub(1);
        let want_now = syn_cookie(self.secret, src, seg.src_port, seg.dst_port, bucket);
        let ok_now = claimed == want_now;
        let ok_prev = if bucket > 0 {
            claimed == syn_cookie(self.secret, src, seg.src_port, seg.dst_port, bucket - 1)
        } else {
            false
        };
        if !ok_now && !ok_prev {
            return false;
        }
        let Some(idx) = self.alloc_tcb() else {
            return false;
        };
        let cookie = claimed;
        {
            let tcb = &mut self.tcbs[idx];
            tcb.state = TcpState::Established;
            tcb.local_ip = cfg.our_ip;
            tcb.local_port = seg.dst_port;
            tcb.remote_ip = *src;
            tcb.remote_port = seg.src_port;
            tcb.iss = cookie;
            tcb.irs = seg.seq.wrapping_sub(1);
            tcb.snd_una = seg.ack; // acked the cookie SYN-ACK
            tcb.snd_nxt = cookie.wrapping_add(1);
            tcb.rcv_nxt = seg.seq;
            tcb.snd_wnd = seg.window as u32;
            tcb.mss = DEFAULT_MSS;
            tcb.cwnd = 2 * DEFAULT_MSS as u32;
            tcb.ssthresh = 8 * DEFAULT_MSS as u32;
            tcb.listener = Some(listener);
        }
        self.syn_cookies_completed += 1;
        // The ACK may carry the first data segment: deliver it.
        if !seg.payload.is_empty() {
            let n = self.tcbs[idx].recv.push(seg.payload);
            self.tcbs[idx].rcv_nxt = self.tcbs[idx].rcv_nxt.wrapping_add(n as u32);
        }
        if seg.has_fin() {
            self.on_fin_input(
                now,
                cfg,
                arp,
                sink,
                idx,
                seg.seq
                    .wrapping_add(seg.payload.len() as u32)
                    .wrapping_add(1),
            );
        }
        let pushed = self.listeners[listener].push_for_cookie(&mut self.tcbs, idx);
        if pushed {
            self.events
                .push(TcpEvent::AcceptReady { listener, tcb: idx });
        } else {
            // A service whose queue holds only ESTABLISHED
            // connections and still got flooded: the completion is
            // dropped with the TCB (bounded; loud in the stats).
            self.tcbs[idx] = Tcb::fresh();
        }
        // Acknowledge the completion ACK (and any data).
        self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None)
            .ok();
        true
    }

    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn on_segment_for_tcb(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        seg: &TcpSegment<'_>,
    ) -> Result<()> {
        let state = self.tcbs[idx].state;
        if state == TcpState::Closed {
            return Ok(()); // raced with a free: drop
        }
        // RST first (RFC 793: the reset wins over processing).
        if seg.has_rst() {
            // Sequence-value check: an in-window RST only (a blind
            // RST with a bogus seq must not kill a live connection —
            // THREAT_MODEL.md §TCP Sequence Number Prediction). In
            // SYN_SENT the ONLY acceptable reset is one that
            // acknowledges OUR SYN (ack == snd_nxt): the refused-
            // connection shape.
            let acceptable = if state == TcpState::SynSent {
                seg.has_ack() && seg.ack == self.tcbs[idx].snd_nxt
            } else if seg.has_ack() {
                seq_le(self.tcbs[idx].snd_una, seg.seq) && seq_lt(seg.seq, self.tcbs[idx].snd_nxt)
            } else {
                seq_le(self.tcbs[idx].rcv_nxt, seg.seq)
                    && seq_lt(
                        seg.seq,
                        self.tcbs[idx]
                            .rcv_nxt
                            .wrapping_add(self.tcbs[idx].advertised_window() as u32),
                    )
            };
            if acceptable {
                self.rst_received += 1;
                let reason = if state == TcpState::SynSent {
                    CloseReason::Refused
                } else {
                    CloseReason::Reset
                };
                self.free_tcb(idx, reason);
            }
            return Ok(());
        }

        match state {
            TcpState::Listen | TcpState::Closed => Ok(()),
            TcpState::SynSent => {
                if seg.has_syn() && seg.has_ack() && seg.ack == self.tcbs[idx].snd_nxt {
                    // Handshake done: ESTABLISHED.
                    {
                        let tcb = &mut self.tcbs[idx];
                        tcb.snd_una = seg.ack;
                        tcb.rcv_nxt = seg.seq.wrapping_add(1);
                        tcb.irs = seg.seq;
                        tcb.snd_wnd = seg.window as u32;
                        tcb.mss =
                            mss_from_options(seg.opts).map_or(DEFAULT_MSS, |m| m.min(MAX_MSS));
                        tcb.state = TcpState::Established;
                        tcb.rto_at = None;
                        tcb.retransmits = 0;
                    }
                    // Data riding the SYN-ACK: deliver.
                    if !seg.payload.is_empty() {
                        let n = self.tcbs[idx].recv.push(seg.payload);
                        self.tcbs[idx].rcv_nxt = self.tcbs[idx].rcv_nxt.wrapping_add(n as u32);
                    }
                    self.events.push(TcpEvent::Connected { tcb: idx });
                    self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None)?;
                    Ok(())
                } else if seg.has_syn() {
                    // Simultaneous open: answer with SYN-ACK, become
                    // SYN_RECEIVED (rare, but the honest state).
                    {
                        let tcb = &mut self.tcbs[idx];
                        tcb.rcv_nxt = seg.seq.wrapping_add(1);
                        tcb.irs = seg.seq;
                        tcb.snd_wnd = seg.window as u32;
                        tcb.state = TcpState::SynReceived;
                    }
                    self.send_control(now, cfg, arp, sink, idx, SYN_BIT | ACK_BIT, None)
                } else {
                    Ok(()) // non-SYN in SYN_SENT: drop
                }
            }
            TcpState::SynReceived => {
                if seg.has_syn() && !seg.has_ack() {
                    // Retransmitted SYN: refresh the SYN-ACK.
                    return self.send_control(now, cfg, arp, sink, idx, SYN_BIT | ACK_BIT, None);
                }
                if seg.has_ack() && seg.ack == self.tcbs[idx].snd_nxt {
                    {
                        let tcb = &mut self.tcbs[idx];
                        tcb.snd_una = seg.ack;
                        tcb.state = TcpState::Established;
                        tcb.rto_at = None;
                        tcb.retransmits = 0;
                    }
                    if let Some(l) = self.tcbs[idx].listener {
                        self.events.push(TcpEvent::AcceptReady {
                            listener: l,
                            tcb: idx,
                        });
                    } else {
                        self.events.push(TcpEvent::Connected { tcb: idx });
                    }
                    // Fall through to normal segment processing for
                    // data/FIN riding the completing ACK.
                    self.on_established_segment(now, cfg, arp, sink, idx, seg)
                } else {
                    // A wrong ACK in SYN_RECEIVED: challenge.
                    self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None)
                }
            }
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => self.on_established_segment(now, cfg, arp, sink, idx, seg),
        }
    }

    /// The ESTABLISHED-family state machine: acceptance test, data
    /// delivery, ACK processing, FIN handling.
    fn on_established_segment(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        seg: &TcpSegment<'_>,
    ) -> Result<()> {
        let (state, rcv_nxt, win) = {
            let t = &self.tcbs[idx];
            (t.state, t.rcv_nxt, t.advertised_window() as u32)
        };
        // ── acceptance test (RFC 793) ─────────────────────────────
        // Zero-window: only the exact-next segment is acceptable
        // (the persist probe's ACK case).
        let seg_end = seg.seq.wrapping_add(seg.seg_len());
        let acceptable = if win == 0 {
            seg.seq == rcv_nxt
        } else {
            seq_le(rcv_nxt, seg.seq) && seq_lt(seg.seq, rcv_nxt.wrapping_add(win))
        };
        let old_dup = seq_lt(seg_end, rcv_nxt) && !seg.has_syn();
        if old_dup {
            // Fully already-acked duplicate: re-ACK (the peer's
            // fast-recover path), never re-deliver.
            return self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None);
        }
        if !acceptable {
            self.out_of_window_drops += 1;
            // Out-of-order within the window: duplicate ACK now
            // (triggers the peer's fast retransmit; we keep no
            // out-of-order queue — module rule 6).
            return self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None);
        }

        // ── window tracking (before everything else): an acceptable
        // segment carries the peer's CURRENT advertised window —
        // snd_wnd follows it. (Found live: the cookie SYN-ACK
        // advertised 0 and the client NEVER learned the window had
        // opened — window updates must ride every segment, not just
        // handshakes.)
        self.tcbs[idx].snd_wnd = seg.window as u32;

        // ── ACK processing (before delivery, per the SND.UNA rule) ─
        let mut fin_now = false;
        if seg.has_ack() {
            let (una, nxt, fin_end) = {
                let t = &self.tcbs[idx];
                (t.snd_una, t.snd_nxt, t.fin_end)
            };
            if seq_gt(seg.ack, una) && seq_le(seg.ack, nxt) {
                // Advance in SEQUENCE space by the full acked range:
                // the FIN consumes one sequence number without a
                // ring byte (found live: a FIN's ACK on a drained
                // ring never advanced snd_una, wedging both
                // teardowns). The ring drops only the bytes it
                // actually holds.
                let advance = seg.ack.wrapping_sub(una);
                let _ring_dropped = self.tcbs[idx].send.consume(advance as usize);
                let mut fin_acked = false;
                {
                    let t = &mut self.tcbs[idx];
                    t.snd_una = t.snd_una.wrapping_add(advance);
                    if t.snd_una == t.snd_nxt && t.send.is_empty() {
                        // Everything acked: stop the retransmission timer.
                        t.rto_at = None;
                        t.retransmits = 0;
                    } else {
                        // Restart the timer for what remains (RFC 6298's
                        // retransmit-on-new-ACK).
                        t.rto_ms = INITIAL_RTO_MS;
                        t.rto_at = Some(now.saturating_add(t.rto_ms));
                    }
                    // Congestion control: a NEW ack.
                    let mss = t.mss as u32;
                    if t.cwnd < t.ssthresh {
                        t.cwnd = (t.cwnd + mss).min(64 * 1024);
                    } else {
                        let add = (mss * mss / t.cwnd.max(1)).max(1);
                        t.cwnd = (t.cwnd + add).min(64 * 1024);
                    }
                    t.dup_acks = 0;
                    // FIN acked?
                    if let Some(fe) = fin_end {
                        if t.snd_una == fe {
                            fin_acked = true;
                            match t.state {
                                TcpState::FinWait1 => {
                                    t.state = TcpState::FinWait2;
                                    t.rto_at = None;
                                }
                                TcpState::Closing => {
                                    t.state = TcpState::TimeWait;
                                    t.timewait_until = Some(now.saturating_add(2 * MSL_MS));
                                }
                                TcpState::LastAck => {
                                    t.state = TcpState::Closed;
                                }
                                _ => {}
                            }
                        }
                    }
                    // A queued FIN whose data just drained: send it
                    // after this block (borrow discipline).
                    if t.fin_queued && t.send.is_empty() && t.fin_end.is_none() {
                        fin_now = true;
                        t.fin_queued = false;
                    }
                }
                if fin_acked && self.tcbs[idx].state == TcpState::Closed {
                    // LAST_ACK's FIN acked: the connection is done.
                    return self.finish_tcb(idx, CloseReason::Normal);
                }
                if fin_now {
                    return self.send_fin(now, cfg, arp, sink, idx);
                }
                // The window may have moved (peer acked +
                // re-advertised): flush what the new window admits.
                self.push_pending(now, cfg, arp, sink, idx)?;
            } else if seg.ack == una && !seg.has_fin() && seg.payload.is_empty() && !seg.has_syn() {
                // Duplicate ACK (the peer is missing something).
                let t = &mut self.tcbs[idx];
                if t.snd_wnd == seg.window as u32 {
                    t.dup_acks = t.dup_acks.saturating_add(1);
                    if t.dup_acks == 3 && t.snd_nxt != t.snd_una {
                        // Fast retransmit: halve, retransmit once.
                        let inflight = t.inflight();
                        t.ssthresh = (inflight / 2).max(2 * t.mss as u32);
                        t.cwnd = t.ssthresh;
                        t.dup_acks = 0;
                        return self.retransmit(now, cfg, arp, sink, idx);
                    }
                }
            }
        }

        // ── data delivery (in-order only; module rule 6) ──────────
        if !seg.payload.is_empty() && seg.seq == self.tcbs[idx].rcv_nxt {
            let n = self.tcbs[idx].recv.push(seg.payload);
            let t = &mut self.tcbs[idx];
            t.rcv_nxt = t.rcv_nxt.wrapping_add(n as u32);
            if n < seg.payload.len() {
                // The peer sent past our advertised window (or we
                // shrank it): the tail is dropped; our ACK will
                // re-advertise the true window. Counted, no panic.
                self.out_of_window_drops += 1;
            }
            if n > 0 {
                self.events.push(TcpEvent::RecvReady { tcb: idx });
            }
            // Delayed ACK (module rule 7): immediate if one is
            // already pending (second in-order segment), else arm.
            let t = &mut self.tcbs[idx];
            if t.delayed_ack_at.is_some() {
                t.delayed_ack_at = Some(now); // fire now
            } else {
                t.delayed_ack_at = Some(now.saturating_add(DELAYED_ACK_MS));
            }
        }

        // ── FIN ───────────────────────────────────────────────────
        if seg.has_fin() {
            // Valid FIN: its sequence must land exactly on rcv_nxt
            // after the data we just took (seg_end == rcv_nxt).
            let expected = self.tcbs[idx].rcv_nxt;
            if seg.seq.wrapping_add(seg.payload.len() as u32) == expected {
                self.on_fin_input(now, cfg, arp, sink, idx, seg_end);
            } else {
                // FIN at a future sequence: the data gap will be
                // retransmitted; FIN is handled then.
                self.out_of_window_drops += 1;
            }
        }
        let _ = state;
        Ok(())
    }

    /// FIN received at the exact next sequence: advance rcv_nxt over
    /// it, transition, ACK (delayed-arm: FIN deserves a prompt ACK).
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn on_fin_input(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        fin_end_seq: u32,
    ) {
        let t = &mut self.tcbs[idx];
        if t.fin_rcvd {
            // Duplicate FIN: re-ACK below.
        } else {
            t.fin_rcvd = true;
            t.rcv_nxt = fin_end_seq;
            match t.state {
                TcpState::Established => t.state = TcpState::CloseWait,
                TcpState::FinWait1 => t.state = TcpState::Closing,
                TcpState::FinWait2 => {
                    t.state = TcpState::TimeWait;
                    t.timewait_until = Some(now.saturating_add(2 * MSL_MS));
                }
                TcpState::TimeWait => {
                    t.timewait_until = Some(now.saturating_add(2 * MSL_MS));
                }
                _ => {}
            }
            self.events.push(TcpEvent::PeerClosed { tcb: idx });
        }
        // The ACK for a FIN is immediate (module rule 7's second
        // exception).
        let _ = self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None);
    }

    // ── timers ────────────────────────────────────────────────────

    /// Drive every TCB's timers. One call per stack poll; every
    /// deadline is absolute, so missed ticks are late, not lost.
    pub fn poll(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
    ) -> Result<()> {
        for idx in 0..MAX_TCBS {
            let state = self.tcbs[idx].state;
            if state == TcpState::Closed {
                continue;
            }
            // TIME_WAIT expiry: the bounded 2MSL.
            if state == TcpState::TimeWait {
                if let Some(until) = self.tcbs[idx].timewait_until {
                    if now >= until {
                        self.finish_tcb(idx, CloseReason::Normal)?;
                    }
                }
                continue;
            }
            // Retransmission timer.
            if let Some(at) = self.tcbs[idx].rto_at {
                if now >= at {
                    let retrans = self.tcbs[idx].retransmits;
                    if retrans >= MAX_RETRANSMITS {
                        // A SYN that exhausted its retransmissions
                        // is a TIMEOUT (ETIMEDOUT); REFUSED is
                        // reserved for an explicit RST from the peer.
                        self.finish_tcb(idx, CloseReason::TimedOut)?;
                        continue;
                    }
                    // A retransmit that cannot egress RIGHT NOW (ARP
                    // in flight, broker throttle) is not a poll
                    // failure: the timer re-drives it. Counted drops
                    // live in the layer's stats.
                    let _ = self.retransmit(now, cfg, arp, sink, idx);
                    let t = &mut self.tcbs[idx];
                    t.retransmits = t.retransmits.saturating_add(1);
                    t.rto_ms = (t.rto_ms * 2).min(MAX_RTO_MS);
                    t.rto_at = Some(now.saturating_add(t.rto_ms));
                    // Backoff collapses the window (RFC 6298 §5):
                    let inflight = t.inflight();
                    t.ssthresh = (inflight / 2).max(2 * t.mss as u32);
                    t.cwnd = t.mss as u32;
                    // Abandon a stuck zero-window probe.
                    t.persist_at = None;
                }
            }
            // Delayed ACK.
            if let Some(at) = self.tcbs[idx].delayed_ack_at {
                if now >= at {
                    self.tcbs[idx].delayed_ack_at = None;
                    let _ = self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None);
                }
            }
            // Transmit: unsent ring bytes with window room go out
            // EVERY poll — waiting for a peer ACK deadlocks when the
            // peer is idle (found live: 1024 unsent bytes, window
            // wide open, no trigger).
            if matches!(
                self.tcbs[idx].state,
                TcpState::Established | TcpState::CloseWait
            ) {
                let _ = self.push_pending(now, cfg, arp, sink, idx);
            }
            // Window-update ack: the ring drained after the peer saw
            // a zero window — tell it the window moved.
            if self.tcbs[idx].window_update_pending
                && matches!(
                    self.tcbs[idx].state,
                    TcpState::Established | TcpState::CloseWait
                )
            {
                self.tcbs[idx].window_update_pending = false;
                let _ = self.send_control(now, cfg, arp, sink, idx, ACK_BIT, None);
            }
            // Zero-window persist probe: ONE DATA byte (RFC 793's
            // persist shape — data forces the peer to ACK, and the
            // ACK carries the window we need; a payload-less probe
            // is ignored by a quiescent peer and never opens the
            // window).
            let (wnd, has_pending, inflight) = {
                let t = &self.tcbs[idx];
                (
                    t.snd_wnd,
                    t.snd_nxt != t.snd_una || !t.send.is_empty(),
                    t.snd_nxt.wrapping_sub(t.snd_una),
                )
            };
            if wnd == 0 && has_pending {
                let deadline = self.tcbs[idx]
                    .persist_at
                    .unwrap_or(now.saturating_add(PERSIST_MS));
                if now >= deadline {
                    let mut probe = [0u8; 1];
                    let n = self.tcbs[idx].send.peek(inflight as usize, 1, &mut probe);
                    if n == 1 {
                        let seq = self.tcbs[idx].snd_nxt;
                        if self
                            .send_segment(now, cfg, arp, sink, idx, PSH_BIT | ACK_BIT, seq, &probe)
                            .is_ok()
                        {
                            let t = &mut self.tcbs[idx];
                            t.snd_nxt = t.snd_nxt.wrapping_add(1);
                            if t.rto_at.is_none() {
                                t.rto_ms = INITIAL_RTO_MS;
                                t.rto_at = Some(now.saturating_add(t.rto_ms));
                            }
                        }
                    } else {
                        // Nothing peekable (inflight == stored): probe
                        // the first unacked byte instead.
                        let mut probe2 = [0u8; 1];
                        let n2 = self.tcbs[idx].send.peek(0, 1, &mut probe2);
                        if n2 == 1 {
                            let seq = self.tcbs[idx].snd_una;
                            let _ = self.send_segment(
                                now,
                                cfg,
                                arp,
                                sink,
                                idx,
                                PSH_BIT | ACK_BIT,
                                seq,
                                &probe2,
                            );
                        }
                    }
                    let t = &mut self.tcbs[idx];
                    t.persist_at = Some(now.saturating_add(PERSIST_MS));
                } else {
                    self.tcbs[idx].persist_at = Some(deadline);
                }
            }
        }
        // Drop half-open TCBs whose handshake never completed within
        // the retransmission budget — SynReceived includes its own
        // rto_at, handled above.
        Ok(())
    }

    /// Re-send the oldest unacked chunk (SYN re-send in SYN_SENT,
    /// SYN-ACK in SYN_RECEIVED, data/FIN otherwise). Go-Back-N:
    /// one timer, one chunk per expiry.
    fn retransmit(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
    ) -> Result<()> {
        self.retransmissions += 1;
        let state = self.tcbs[idx].state;
        match state {
            TcpState::SynSent => self.send_control(now, cfg, arp, sink, idx, SYN_BIT, None),
            TcpState::SynReceived => {
                self.send_control(now, cfg, arp, sink, idx, SYN_BIT | ACK_BIT, None)
            }
            _ => {
                // Data (and FIN flag when the ring is drained). ONLY
                // the in-flight range [snd_una, snd_nxt): a
                // retransmission of bytes never sent desyncs the
                // receiver past our snd_nxt and their acks become
                // unacceptable forever (found live in the window
                // test).
                let mut payload = [0u8; 1460];
                let (n, base) = {
                    let t = &self.tcbs[idx];
                    let inflight = t.snd_nxt.wrapping_sub(t.snd_una) as usize;
                    let want = (t.mss as usize).min(inflight);
                    let n = t.send.peek(0, want, &mut payload);
                    (n, t.snd_una)
                };
                let mut flags = PSH_BIT | ACK_BIT;
                let add_fin = self.tcbs[idx].fin_end.is_some()
                    && self.tcbs[idx].send.is_empty()
                    && self.tcbs[idx].state != TcpState::CloseWait;
                let add_fin_wait =
                    self.tcbs[idx].fin_end.is_some() && self.tcbs[idx].send.is_empty();
                let _ = add_fin_wait;
                if add_fin {
                    flags |= FIN_BIT;
                }
                self.send_segment(now, cfg, arp, sink, idx, flags, base, &payload[..n])
            }
        }
    }

    // ── emission (the ONE egress path — all through the sink) ─────

    /// Send a control segment (no payload, optional MSS on SYN*).
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn send_control(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        flags: u8,
        mss: Option<u16>,
    ) -> Result<()> {
        let (seq, ack, win) = {
            let t = &self.tcbs[idx];
            let seq = if flags & SYN_BIT != 0 {
                t.iss
            } else {
                t.snd_nxt
            };
            (
                seq,
                if flags & ACK_BIT != 0 { t.rcv_nxt } else { 0 },
                t.advertised_window(),
            )
        };
        self.build_and_send(now, cfg, arp, sink, idx, flags, seq, ack, win, &[], mss)
    }

    /// Send a data segment at `seq` (retransmission or fresh push).
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn send_segment(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        flags: u8,
        seq: u32,
        payload: &[u8],
    ) -> Result<()> {
        #[cfg(test)]
        if std::env::var("NETSTACK_DEBUG").is_ok() && !payload.is_empty() {
            eprintln!(
                "[tcp] data segment seq={seq} len={} first={:?}",
                payload.len(),
                &payload[..8.min(payload.len())]
            );
        }
        let win = self.tcbs[idx].advertised_window();
        self.build_and_send(
            now,
            cfg,
            arp,
            sink,
            idx,
            flags,
            seq,
            self.tcbs[idx].rcv_nxt,
            win,
            payload,
            None,
        )
    }

    /// Transmit new data while the effective window allows (called
    /// after `send` enqueues and from FIN-drain paths).
    fn push_pending(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
    ) -> Result<()> {
        loop {
            let (inflight, stored, win, mss, fin_end, fin_queued, state) = {
                let t = &self.tcbs[idx];
                (
                    t.inflight(),
                    t.send.len() as u32,
                    t.effective_window(),
                    t.mss,
                    t.fin_end,
                    t.fin_queued,
                    t.state,
                )
            };
            let _ = state;
            let allowed = (win.saturating_sub(inflight)).min(mss as u32);
            if allowed == 0 {
                return Ok(());
            }
            let unsent = stored.saturating_sub(inflight);
            if unsent == 0 {
                // Nothing new to send — but a queued FIN may be ripe.
                if fin_queued && fin_end.is_none() && stored == inflight && inflight == 0 {
                    self.tcbs[idx].fin_queued = false;
                    return self.send_fin(now, cfg, arp, sink, idx);
                }
                return Ok(());
            }
            let take = allowed.min(unsent).min(1460);
            let mut payload = [0u8; 1460];
            let n = {
                let t = &self.tcbs[idx];
                t.send.peek(inflight as usize, take as usize, &mut payload)
            };
            if n == 0 {
                return Ok(());
            }
            let seq = self.tcbs[idx].snd_nxt;
            let r = self.send_segment(
                now,
                cfg,
                arp,
                sink,
                idx,
                PSH_BIT | ACK_BIT,
                seq,
                &payload[..n],
            );
            r?;
            let t = &mut self.tcbs[idx];
            t.snd_nxt = t.snd_nxt.wrapping_add(n as u32);
            if t.rto_at.is_none() {
                t.rto_ms = INITIAL_RTO_MS;
                t.rto_at = Some(now.saturating_add(t.rto_ms));
                t.retransmits = 0;
            }
        }
    }

    /// Send the FIN (after the send ring is empty). Sets fin_end and
    /// transitions.
    fn send_fin(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
    ) -> Result<()> {
        {
            let t = &mut self.tcbs[idx];
            if t.fin_end.is_some() {
                return Ok(()); // already sent
            }
            let fin_at = t.snd_nxt;
            t.fin_end = Some(fin_at.wrapping_add(1));
            t.snd_nxt = fin_at.wrapping_add(1);
            t.fin_sent = true;
            match t.state {
                TcpState::Established | TcpState::SynReceived => t.state = TcpState::FinWait1,
                TcpState::CloseWait => t.state = TcpState::LastAck,
                TcpState::FinWait2 => {}
                _ => {}
            }
            if t.rto_at.is_none() {
                t.rto_ms = INITIAL_RTO_MS;
                t.rto_at = Some(now.saturating_add(t.rto_ms));
                t.retransmits = 0;
            }
        }
        let seq = self.tcbs[idx]
            .fin_end
            .map(|e| e.wrapping_sub(1))
            .unwrap_or(0);
        self.send_control_with_seq(now, cfg, arp, sink, idx, FIN_BIT | ACK_BIT, seq)
    }

    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn send_control_with_seq(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        flags: u8,
        seq: u32,
    ) -> Result<()> {
        let win = self.tcbs[idx].advertised_window();
        self.build_and_send(
            now,
            cfg,
            arp,
            sink,
            idx,
            flags,
            seq,
            self.tcbs[idx].rcv_nxt,
            win,
            &[],
            None,
        )
    }

    /// The ONE frame builder: eth + IP + TCP(+options) + payload in
    /// `self.tx`, delivered to the sink. MAC resolution through the
    /// ARP layer (a miss → the frame waits for the reply; the RTO
    /// re-drives). `self.tx` and TCB fields are sequenced, never
    /// aliased.
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn build_and_send(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
        flags: u8,
        seq: u32,
        ack: u32,
        window: u16,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Result<()> {
        let (lip, lport, rip, rport) = {
            let t = &self.tcbs[idx];
            (t.local_ip, t.local_port, t.remote_ip, t.remote_port)
        };
        // Resolve the next hop FIRST (it may emit an ARP request and
        // fail with pending — before we touch the scratch).
        let next_hop = cfg.next_hop(&rip)?;
        let Some(dst_mac) = arp.resolve(now, sink, &next_hop)? else {
            // ARP in flight: the RTO re-drives this send. The bytes
            // stay accounted (snd_nxt already advanced for fresh
            // pushes; control segments are idempotent).
            return Err(Error::ArpPending);
        };
        // TCP header (20 + optional 4-byte MSS on SYN).
        let opt_len = if mss.is_some() { 4 } else { 0 };
        let tcp_len = TCP_HDR_LEN + opt_len + payload.len();
        let ip_total = (20 + tcp_len) as u16;
        // Bounds: the scratch is 1514; eth 14 + ip 20 + tcp_len.
        let total = 14 + 20 + tcp_len;
        if total > self.tx.len() {
            return Err(Error::DatagramTooLarge {
                len: total,
                max: self.tx.len(),
            });
        }
        // TCP header into tx[14+20 ..].
        let t = &mut self.tx;
        let tcp_at = 14 + 20;
        t[tcp_at] = (lport >> 8) as u8;
        t[tcp_at + 1] = lport as u8;
        t[tcp_at + 2] = (rport >> 8) as u8;
        t[tcp_at + 3] = rport as u8;
        t[tcp_at + 4..tcp_at + 8].copy_from_slice(&seq.to_be_bytes());
        t[tcp_at + 8..tcp_at + 12].copy_from_slice(&ack.to_be_bytes());
        t[tcp_at + 12] = (((TCP_HDR_LEN + opt_len) / 4) as u8) << 4;
        t[tcp_at + 13] = flags;
        t[tcp_at + 14] = (window >> 8) as u8;
        t[tcp_at + 15] = window as u8;
        t[tcp_at + 16] = 0;
        t[tcp_at + 17] = 0; // checksum, below
        t[tcp_at + 18] = 0;
        t[tcp_at + 19] = 0; // urgent pointer (never)
        if opt_len == 4 {
            t[tcp_at + 20] = 2; // MSS
            t[tcp_at + 21] = 4;
            let m = mss.unwrap_or(DEFAULT_MSS);
            t[tcp_at + 22] = (m >> 8) as u8;
            t[tcp_at + 23] = m as u8;
        }
        t[tcp_at + TCP_HDR_LEN + opt_len..tcp_at + tcp_len].copy_from_slice(payload);
        // Checksum over pseudo-header + segment.
        let seg_len16 = u16::try_from(tcp_len).map_err(|_| Error::DatagramTooLarge {
            len: tcp_len,
            max: u16::MAX as usize,
        })?;
        let ck = pseudo_header_checksum(
            &lip,
            &rip,
            PROTO_TCP,
            seg_len16,
            &self.tx[tcp_at..tcp_at + tcp_len],
        );
        self.tx[tcp_at + 16] = (ck >> 8) as u8;
        self.tx[tcp_at + 17] = ck as u8;
        // IPv4 header at tx[14..34].
        self.ip_id = self.ip_id.wrapping_add(1);
        emit_header(
            &mut self.tx[14..],
            ip_total,
            self.ip_id,
            0x4000, // DF set: the stack does not fragment TCP
            64,
            PROTO_TCP,
            &lip,
            &rip,
        )?;
        // Ethernet header.
        // Split-borrow: the header goes into the first 14 bytes,
        // the already-built packet rides behind it in the same
        // array — one array, no aliasing.
        {
            let (head, _) = self.tx.split_at_mut(eth_hdr::LEN);
            super::ethernet::emit_header_only(head, &dst_mac, &cfg.our_mac, EtherType::Ipv4)?;
        }
        self.segments_sent += 1;
        sink.send_frame(&self.tx[..14 + 20 + tcp_len])
    }

    /// A cookie SYN-ACK with no TCB: raw emission for the SYN-flood
    /// path (layer 3).
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn send_synack_cookie(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
        cookie: u32,
        ack: u32,
    ) -> Result<()> {
        let next_hop = cfg.next_hop(&remote_ip)?;
        let Some(dst_mac) = arp.resolve(now, sink, &next_hop)? else {
            return Err(Error::ArpPending);
        };
        let tcp_len = TCP_HDR_LEN + 4;
        let total = 14 + 20 + tcp_len;
        if total > self.tx.len() {
            return Err(Error::DatagramTooLarge {
                len: total,
                max: self.tx.len(),
            });
        }
        let tcp_at = 34;
        let t = &mut self.tx;
        t[tcp_at] = (local_port >> 8) as u8;
        t[tcp_at + 1] = local_port as u8;
        t[tcp_at + 2] = (remote_port >> 8) as u8;
        t[tcp_at + 3] = remote_port as u8;
        t[tcp_at + 4..tcp_at + 8].copy_from_slice(&cookie.to_be_bytes());
        t[tcp_at + 8..tcp_at + 12].copy_from_slice(&ack.to_be_bytes());
        // data_offset 6: the 24-byte header INCLUDES the 4-byte MSS
        // option below — a 5 here would make the peer parse the
        // option bytes as payload (found live by the cookie test).
        t[tcp_at + 12] = 6 << 4;
        t[tcp_at + 13] = SYN_BIT | ACK_BIT;
        // Advertise the receive capacity a MATERIALIZED connection
        // actually gets: the client's window tracking updates from
        // our later ACKs, but the first data burst should not need
        // to wait for one.
        let adv = SEND_BUF as u16;
        t[tcp_at + 14] = (adv >> 8) as u8;
        t[tcp_at + 15] = adv as u8;
        t[tcp_at + 16] = 0;
        t[tcp_at + 17] = 0;
        t[tcp_at + 18] = 0;
        t[tcp_at + 19] = 0;
        t[tcp_at + 20] = 2;
        t[tcp_at + 21] = 4;
        t[tcp_at + 22] = (DEFAULT_MSS >> 8) as u8;
        t[tcp_at + 23] = DEFAULT_MSS as u8;
        let ck = pseudo_header_checksum(
            &cfg.our_ip,
            &remote_ip,
            PROTO_TCP,
            tcp_len as u16,
            &self.tx[tcp_at..tcp_at + tcp_len],
        );
        self.tx[tcp_at + 16] = (ck >> 8) as u8;
        self.tx[tcp_at + 17] = ck as u8;
        self.ip_id = self.ip_id.wrapping_add(1);
        emit_header(
            &mut self.tx[14..],
            (20 + tcp_len) as u16,
            self.ip_id,
            0x4000,
            64,
            PROTO_TCP,
            &cfg.our_ip,
            &remote_ip,
        )?;
        {
            let (head, _) = self.tx.split_at_mut(eth_hdr::LEN);
            super::ethernet::emit_header_only(head, &dst_mac, &cfg.our_mac, EtherType::Ipv4)?;
        }
        self.segments_sent += 1;
        sink.send_frame(&self.tx[..14 + 20 + tcp_len])
    }

    /// Rate-limited RST emission with an EXPLICIT shape:
    /// - refusing a SYN: RST|ACK, seq=0, ack=the SYN's sequence end
    ///   (the peer's SYN_SENT acceptance test matches exactly this);
    /// - answering a blind ACK: bare RST, seq=their ack (RFC 793);
    /// - aborting a half-open TCB: RST|ACK, seq=our snd_nxt,
    ///   ack=our rcv_nxt (the unambiguous teardown).
    // (clippy::too_many_arguments is deliberate: the wire
    // builders' parameters ARE the protocol's fields, and the
    // no_alloc context (now/cfg/arp/sink) threads explicitly —
    // there is no allocation to bundle it into.)
    #[allow(clippy::too_many_arguments)]
    fn maybe_send_rst(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        remote_ip: &[u8; 4],
        remote_port: u16,
        local_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) {
        // Rate window.
        let (w, c) = self.rst_window;
        if now / RST_RATE_WINDOW_MS == w && c >= RST_RATE_MAX {
            return; // silently: an RST flood answers nothing
        }
        if now / RST_RATE_WINDOW_MS != w {
            self.rst_window = (now / RST_RATE_WINDOW_MS, 1);
        } else {
            self.rst_window = (w, c + 1);
        }
        self.rst_sent += 1;
        // Build + emit the RST with the caller's shape.
        let Ok(next_hop) = cfg.next_hop(remote_ip) else {
            return;
        };
        let Ok(Some(dst_mac)) = arp.resolve(now, sink, &next_hop) else {
            return;
        };
        let tcp_len = TCP_HDR_LEN;
        let total = 14 + 20 + tcp_len;
        if total > self.tx.len() {
            return;
        }
        let seq_v = seq;
        let ack_v = ack;
        let tcp_at = 34;
        let t = &mut self.tx;
        t[tcp_at] = (local_port >> 8) as u8;
        t[tcp_at + 1] = local_port as u8;
        t[tcp_at + 2] = (remote_port >> 8) as u8;
        t[tcp_at + 3] = remote_port as u8;
        t[tcp_at + 4..tcp_at + 8].copy_from_slice(&seq_v.to_be_bytes());
        t[tcp_at + 8..tcp_at + 12].copy_from_slice(&ack_v.to_be_bytes());
        t[tcp_at + 12] = 5 << 4;
        t[tcp_at + 13] = flags;
        t[tcp_at + 14] = 0;
        t[tcp_at + 15] = 0;
        t[tcp_at + 16] = 0;
        t[tcp_at + 17] = 0;
        t[tcp_at + 18] = 0;
        t[tcp_at + 19] = 0;
        let ck = pseudo_header_checksum(
            &cfg.our_ip,
            remote_ip,
            PROTO_TCP,
            tcp_len as u16,
            &self.tx[tcp_at..tcp_at + tcp_len],
        );
        self.tx[tcp_at + 16] = (ck >> 8) as u8;
        self.tx[tcp_at + 17] = ck as u8;
        self.ip_id = self.ip_id.wrapping_add(1);
        if emit_header(
            &mut self.tx[14..],
            (20 + tcp_len) as u16,
            self.ip_id,
            0x4000,
            64,
            PROTO_TCP,
            &cfg.our_ip,
            remote_ip,
        )
        .is_err()
        {
            return;
        }
        if super::ethernet::emit_header_only(
            &mut self.tx[..14],
            &dst_mac,
            &cfg.our_mac,
            EtherType::Ipv4,
        )
        .is_ok()
        {
            self.segments_sent += 1;
            let _ = sink.send_frame(&self.tx[..14 + 20 + tcp_len]);
        }
    }

    fn abort_with_rst(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        idx: usize,
    ) {
        let (rip, rport, lport, nxt, rcv) = {
            let t = &self.tcbs[idx];
            (
                t.remote_ip,
                t.remote_port,
                t.local_port,
                t.snd_nxt,
                t.rcv_nxt,
            )
        };
        // RST|ACK: our seq covers everything sent, our ack pins their
        // side — the unambiguous abort.
        self.maybe_send_rst(
            now,
            cfg,
            arp,
            sink,
            &rip,
            rport,
            lport,
            RST_BIT | ACK_BIT,
            nxt,
            rcv,
        );
    }

    // ── pool + bookkeeping helpers ────────────────────────────────

    /// Owner-facing TCB free (the socket layer unwinding a
    /// wrong-kind connect: the TCB was allocated, the fd was not
    /// eligible — free it loudly).
    pub fn free_tcb_public(&mut self, idx: usize, reason: CloseReason) {
        self.free_tcb(idx, reason);
    }

    /// The port a listener slot is bound to (port-in-use checks).
    pub fn listener_port(&self, listener: usize) -> u16 {
        self.listeners[listener].port
    }

    /// Free a listener slot (the owner closed its listener fd).
    /// Half-open TCBs in the queue are dropped with RSTs first —
    /// closing a listener never leaks half-open state.
    pub fn free_listener(
        &mut self,
        now: u64,
        cfg: &TcpIfCfg,
        arp: &mut ArpLayer,
        sink: &mut dyn FrameSink,
        listener: usize,
    ) {
        let queued: [Option<usize>; LISTEN_BACKLOG] = self.listeners[listener].queue;
        for t in queued.iter().flatten() {
            self.abort_with_rst(now, cfg, arp, sink, *t);
            self.free_tcb(*t, CloseReason::Normal);
        }
        self.listeners[listener] = Listener::fresh();
    }

    fn alloc_tcb(&self) -> Option<usize> {
        self.tcbs.iter().position(|t| t.state == TcpState::Closed)
    }

    fn find_tcb(&self, remote_ip: &[u8; 4], remote_port: u16, local_port: u16) -> Option<usize> {
        self.tcbs.iter().position(|t| {
            t.state != TcpState::Closed
                && t.remote_ip == *remote_ip
                && t.remote_port == remote_port
                && t.local_port == local_port
        })
    }

    fn find_listener(&self, port: u16) -> Option<usize> {
        // A listener exists for a PORT regardless of queue depth
        // (depth 0 still listens — cookies answer when the queue
        // fills).
        if port == 0 {
            return None;
        }
        self.listeners.iter().position(|l| l.port == port)
    }

    /// Free a TCB (and its listener queue slot) with a reason event.
    fn free_tcb(&mut self, idx: usize, reason: CloseReason) {
        let listener = self.tcbs[idx].listener;
        self.tcbs[idx] = Tcb::fresh();
        if let Some(l) = listener {
            self.listeners[l].drop_dead(idx);
        }
        self.events.push(TcpEvent::Closed { tcb: idx, reason });
    }

    fn finish_tcb(&mut self, idx: usize, reason: CloseReason) -> Result<()> {
        self.free_tcb(idx, reason);
        Ok(())
    }

    fn next_isn(&mut self, now: u64, remote_ip: &[u8; 4], remote_port: u16) -> u32 {
        self.isn_counter = self.isn_counter.wrapping_add(0x9e37_79b1);
        let mut h = self.secret ^ (now / 1024) as u32 ^ self.isn_counter;
        for b in remote_ip.iter() {
            h = h.wrapping_mul(0x0100_0193) ^ (*b as u32);
        }
        h ^= remote_port as u32;
        h = h.wrapping_mul(0x85eb_ca6b);
        h ^= h >> 13;
        h
    }

    fn syn_rate_admit(&mut self, now: u64, src: &[u8; 4]) -> bool {
        let window = now / SYN_RATE_WINDOW_MS;
        for w in self.syn_rate.iter_mut() {
            if w.ip == *src && w.count > 0 {
                if w.window_start == window {
                    if w.count >= SYN_RATE_MAX {
                        return false;
                    }
                    w.count += 1;
                    return true;
                }
                // New window for this source: reset.
                w.window_start = window;
                w.count = 1;
                return true;
            }
        }
        // Untracked source: take a free slot (or the oldest window).
        let mut victim = 0;
        let mut oldest = u64::MAX;
        for (i, w) in self.syn_rate.iter().enumerate() {
            if w.count == 0 {
                victim = i;
                break;
            }
            if w.window_start < oldest {
                oldest = w.window_start;
                victim = i;
            }
        }
        self.syn_rate[victim] = SynWindow {
            ip: *src,
            window_start: window,
            count: 1,
        };
        true
    }
}
