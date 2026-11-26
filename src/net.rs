//! Brokered sockets with per-domain token-bucket rate limiting.
//!
//! Design (matches the AegisOS broker model): no domain talks to the NIC
//! directly. The single network broker domain does, and every other domain
//! sends through it. The kernel enforces two things per sending domain:
//!
//! 1. **Socket lifecycle** — send on a closed/unknown socket fails.
//! 2. **Rate limit** — a token bucket: `burst` tokens max, refilled by
//!    `rate` tokens per `RATE_WINDOW_TICKS`. Sending `n` bytes consumes `n`
//!    tokens; an empty bucket throttles (EAGAIN-style) instead of queueing.
//!
//! All arithmetic is integer and deterministic: `try_consume` is a pure
//! function of (bucket state, current tick).

pub const RATE_WINDOW_TICKS: u64 = 100;
/// K20 (P0-2): the largest frame `NetSend` will ever admit — one
/// standard Ethernet frame (1500 MTU + 14 header). A longer request
/// is refused `TooLong` before any token is touched: it can never fit
/// any window and must not masquerade as a throttle.
pub const MAX_NET_FRAME_BYTES: u32 = 1514;
/// K20 (P0-2): the defaults now speak Ethernet: a full standard frame
/// per window. The old 64-byte burst could never pass a real frame —
/// the DHCP DISCOVER the boot itself sends is 290 bytes — so the rate
/// limit was a paper gate.
pub const DEFAULT_RATE_BYTES_PER_WINDOW: u32 = MAX_NET_FRAME_BYTES;
pub const DEFAULT_BURST_BYTES: u32 = MAX_NET_FRAME_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No free socket slot.
    TableFull,
    /// Unknown socket id (never opened, or already closed).
    InvalidSocket(u32),
    /// Socket exists but is closed.
    NotOpen(u32),
    /// Bucket empty: throttled (non-blocking flavor).
    RateLimited { requested: u32, available: u32 },
    /// K20 (P0-2): the send is longer than `MAX_NET_FRAME_BYTES` —
    /// refused before any capability or token work (it can never fit
    /// the bucket; EMSGSIZE, not EAGAIN).
    TooLong(u32),
}

/// Integer token bucket. `last_window` is the last window index at which a
/// refill happened; refills are credited for fully elapsed windows only,
/// which keeps the math exact and deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucket {
    pub rate: u32,
    pub burst: u32,
    tokens: u32,
    last_window: u64,
}

impl TokenBucket {
    pub const fn new(rate: u32, burst: u32) -> Self {
        // A fresh bucket starts full (traffic may burst immediately).
        TokenBucket {
            rate,
            burst,
            tokens: burst,
            last_window: 0,
        }
    }

    /// Refill for elapsed whole windows and try to consume `n` tokens.
    pub fn try_consume(&mut self, now_ticks: u64, n: u32) -> Result<u32, (u32, u32)> {
        let window = now_ticks / RATE_WINDOW_TICKS;
        let elapsed = window.saturating_sub(self.last_window);
        if elapsed > 0 {
            // Add rate × elapsed windows, capped at burst (no infinite
            // accumulation while idle).
            let credit = (self.rate as u64)
                .saturating_mul(elapsed)
                .min(u32::MAX as u64) as u32;
            self.tokens = self.tokens.saturating_add(credit).min(self.burst);
            self.last_window = window;
        }
        if self.tokens >= n {
            self.tokens -= n;
            Ok(self.tokens)
        } else {
            Err((n, self.tokens))
        }
    }

    #[must_use]
    pub fn tokens(&self) -> u32 {
        self.tokens
    }

    /// Refill only (no consumption) — used for introspection/tests.
    pub fn refill_to(&mut self, now_ticks: u64) {
        let _ = self.try_consume(now_ticks, 0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socket {
    pub domain_id: u32,
    pub state: SocketState,
    pub bytes_sent: u64,
    /// K20 (P0-2): bytes accounted RECEIVED on this socket (the
    /// policy half — data movement is the kernel executor's business).
    pub bytes_recvd: u64,
}

/// K20 (P0-1): 4 -> 16 — one listening socket per service domain in a
/// 64-domain system, still a fixed table with fail-loud `TableFull`.
/// Measured cost: 24 B per slot; the whole table is bytes.
pub const MAX_SOCKETS: usize = 16;

#[derive(Default)]
pub struct SocketTable {
    sockets: [Option<Socket>; MAX_SOCKETS],
}

impl SocketTable {
    pub const fn new() -> Self {
        SocketTable {
            sockets: [None; MAX_SOCKETS],
        }
    }

    /// Open a socket owned by `domain_id`; returns the socket id.
    pub fn open(&mut self, domain_id: u32) -> Result<u32, NetError> {
        for (i, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Socket {
                    domain_id,
                    state: SocketState::Open,
                    bytes_sent: 0,
                    bytes_recvd: 0,
                });
                return Ok(i as u32);
            }
        }
        Err(NetError::TableFull)
    }

    fn get(&mut self, id: u32) -> Result<&mut Socket, NetError> {
        match self.sockets.get_mut(id as usize) {
            Some(Some(s)) => Ok(s),
            _ => Err(NetError::InvalidSocket(id)),
        }
    }

    /// Close a socket; the slot is reclaimed and the id becomes invalid.
    pub fn close(&mut self, id: u32) -> Result<Socket, NetError> {
        let s = self.get(id)?;
        if s.state != SocketState::Open {
            return Err(NetError::NotOpen(id));
        }
        let closed = *s;
        self.sockets[id as usize] = None;
        Ok(closed)
    }

    /// Send `len` bytes through socket `id`, throttled by `bucket`.
    /// Returns the remaining token count on success.
    pub fn send(
        &mut self,
        id: u32,
        len: u32,
        bucket: &mut TokenBucket,
        now_ticks: u64,
    ) -> Result<u32, NetError> {
        let socket = self.get(id)?;
        if socket.state != SocketState::Open {
            return Err(NetError::NotOpen(id));
        }
        match bucket.try_consume(now_ticks, len) {
            Ok(remaining) => {
                let s = self.get(id)?;
                s.bytes_sent = s.bytes_sent.saturating_add(len as u64);
                Ok(remaining)
            }
            Err((requested, available)) => Err(NetError::RateLimited {
                requested,
                available,
            }),
        }
    }

    #[must_use]
    pub fn bytes_sent(&self, id: u32) -> Option<u64> {
        match self.sockets.get(id as usize) {
            Some(Some(s)) => Some(s.bytes_sent),
            _ => None,
        }
    }

    /// K20 (P0-2): the received-byte total of an open socket.
    #[must_use]
    pub fn bytes_recvd(&self, id: u32) -> Option<u64> {
        match self.sockets.get(id as usize) {
            Some(Some(s)) => Some(s.bytes_recvd),
            _ => None,
        }
    }

    /// K20 (P0-2): account a successful receive of `len` bytes — the
    /// policy half of `NetRecv` (the kernel executor moved the data
    /// and already re-validated everything; this keeps the socket's
    /// counters honest for telemetry). Refuses closed/unknown
    /// sockets with the same identities as `send`.
    pub fn recv(&mut self, id: u32, len: u32) -> Result<(), NetError> {
        let s = self.get(id)?;
        if s.state != SocketState::Open {
            return Err(NetError::NotOpen(id));
        }
        s.bytes_recvd = s.bytes_recvd.saturating_add(len as u64);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sockets.iter().flatten().count()
    }

    /// Find the open socket owned by `domain_id`, if any.
    #[must_use]
    pub fn open_socket_of(&self, domain_id: u32) -> Option<u32> {
        self.sockets
            .iter()
            .position(|s| matches!(s, Some(sock) if sock.domain_id == domain_id && sock.state == SocketState::Open))
            .map(|i| i as u32)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket() -> TokenBucket {
        TokenBucket::new(32, 64) // 32 bytes/window, burst 64
    }

    #[test]
    fn fresh_bucket_starts_full_and_burst_passes() {
        let mut b = bucket();
        assert_eq!(b.tokens(), 64);
        assert_eq!(b.try_consume(0, 64).unwrap(), 0);
        assert_eq!(b.tokens(), 0);
    }

    #[test]
    fn empty_bucket_throttles_with_details() {
        let mut b = bucket();
        b.try_consume(0, 64).unwrap();
        assert_eq!(
            b.try_consume(0, 1),
            Err((1, 0)),
            "same tick: no refill, no credit"
        );
    }

    #[test]
    fn refill_happens_only_for_whole_elapsed_windows() {
        let mut b = bucket();
        b.try_consume(0, 64).unwrap(); // empty
                                       // 99 ticks later: still inside window 0 — no refill.
        assert_eq!(b.try_consume(99, 1), Err((1, 0)));
        // Tick 100 = window 1: 32 tokens credited.
        assert_eq!(b.try_consume(100, 1).unwrap(), 31);
    }

    #[test]
    fn multi_window_refill_capped_at_burst() {
        let mut b = bucket();
        b.try_consume(0, 64).unwrap();
        // 10 windows × 32 tokens = 320 credited, but capped at burst 64.
        assert_eq!(b.try_consume(10 * RATE_WINDOW_TICKS, 64).unwrap(), 0);
        assert_eq!(b.tokens(), 0);
    }

    #[test]
    fn exact_boundary_consume_all_available() {
        let mut b = TokenBucket::new(10, 10);
        // Drain everything at t=0.
        b.try_consume(0, 10).unwrap();
        // One window later: exactly 10 again.
        assert_eq!(b.try_consume(RATE_WINDOW_TICKS, 10).unwrap(), 0);
        assert_eq!(b.try_consume(RATE_WINDOW_TICKS, 1), Err((1, 0)));
    }

    #[test]
    fn oversized_request_reports_available() {
        let mut b = TokenBucket::new(10, 10);
        let e = b.try_consume(0, 11).unwrap_err();
        assert_eq!(e, (11, 10));
        // Tokens untouched on failure.
        assert_eq!(b.tokens(), 10);
    }

    #[test]
    fn socket_lifecycle_send_and_accounting() {
        let mut t = SocketTable::new();
        let id = t.open(7).unwrap();
        let mut b = bucket();
        assert_eq!(t.send(id, 20, &mut b, 0).unwrap(), 44);
        assert_eq!(t.send(id, 30, &mut b, 0).unwrap(), 14);
        assert_eq!(t.bytes_sent(id), Some(50));
        // Bucket has 14 left: 15 bytes throttled.
        assert_eq!(
            t.send(id, 15, &mut b, 0),
            Err(NetError::RateLimited {
                requested: 15,
                available: 14
            })
        );
        // Throttled send did not count.
        assert_eq!(t.bytes_sent(id), Some(50));
    }

    #[test]
    fn closed_and_invalid_sockets_rejected() {
        let mut t = SocketTable::new();
        let id = t.open(1).unwrap();
        let closed = t.close(id).unwrap();
        assert_eq!(closed.domain_id, 1);
        let mut b = bucket();
        assert_eq!(t.send(id, 1, &mut b, 0), Err(NetError::InvalidSocket(id)));
        assert_eq!(t.close(id), Err(NetError::InvalidSocket(id)));
        assert_eq!(t.send(99, 1, &mut b, 0), Err(NetError::InvalidSocket(99)));
        assert_eq!(t.bytes_sent(99), None);
    }

    #[test]
    fn table_fills_and_reuses_slots() {
        let mut t = SocketTable::new();
        for i in 0..MAX_SOCKETS {
            assert_eq!(t.open(i as u32).unwrap(), i as u32);
        }
        assert_eq!(t.open(9), Err(NetError::TableFull));
        t.close(2).unwrap();
        assert_eq!(t.open(9).unwrap(), 2);
        assert_eq!(t.len(), MAX_SOCKETS);
    }

    #[test]
    fn per_domain_buckets_are_independent() {
        // Two domains, separate buckets, same clock.
        let mut b1 = TokenBucket::new(10, 10);
        let mut b2 = TokenBucket::new(10, 10);
        b1.try_consume(0, 10).unwrap(); // domain 1 empty
                                        // Domain 2 unaffected.
        assert_eq!(b2.try_consume(0, 10).unwrap(), 0);
        assert_eq!(b1.try_consume(0, 1), Err((1, 0)));
    }

    #[test]
    fn refill_to_helper_advances_without_consuming() {
        let mut b = bucket();
        b.try_consume(0, 64).unwrap();
        b.refill_to(RATE_WINDOW_TICKS * 2);
        // 2 windows × 32 = 64, capped at burst.
        assert_eq!(b.tokens(), 64);
    }
}
