//! Capability-endpoint IPC — ADR-0004, async half (lib layer).
//!
//! Design (ADR-0004 §2): every message flows through an **endpoint**
//! owned by exactly one domain; senders need a capability on that
//! endpoint. Rights mapping onto the existing bitset (ADR-0004 §4):
//!
//! - `SEND`  == `Rights::WRITE`
//! - `RECV`  == `Rights::READ`
//! - `GRANT` == `Rights::GRANT` (derivation stays subset-only)
//!
//! Invariants, all test-proven:
//! - **No ambient authority**: no send without a live capability on the
//!   endpoint; revoked caps and dead endpoint ids fail closed.
//! - **Ids are never reused**: endpoint ids are monotonic; destroying an
//!   endpoint frees its slot but no future `create` hands that id out
//!   again, so a stale capability can never reach a reincarnated queue
//!   (no ABA).
//! - **Bounded, non-blocking**: each queue has a fixed depth; a full
//!   queue refuses with `QueueFull` (EAGAIN-style), never drops
//!   silently, never blocks (the lib has no scheduler involvement here
//!   by design — sync call/reply is the kernel-side fast-path slice).
//! - **Fixed message size**: `IPC_MAX_MSG_BYTES` (64) per ADR-0004 §1;
//!   the lib layer carries `(sender, len)` records — payload bytes ride
//!   the kernel-side copy path.
//! - **Zero allocation**: every structure is a fixed-size array.

use crate::pipe::PipeError;

/// Endpoint slots in the kernel (fail-loud exhaustion, F14 discipline).
pub const MAX_ENDPOINTS: usize = 8;
/// ADR-0004 §1: messages are fixed-size, at most 64 bytes.
pub const IPC_MAX_MSG_BYTES: u32 = 64;
/// Per-endpoint queue depth (bounded, EAGAIN-style overflow).
pub const IPC_QUEUE_DEPTH: usize = 4;
/// ADR-0029: a byte-channel endpoint's ring — the queue-depth ×
/// max-message scale (4 × 64). The pipe engine (`pipe::Pipe`) rides
/// inside the endpoint at this capacity.
pub const CHANNEL_CAPACITY: usize = 4 * IPC_MAX_MSG_BYTES as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Unknown, destroyed, or never-issued endpoint id (fail closed).
    InvalidHandle,
    /// Queue exhausted — the EAGAIN-style bounded refusal.
    QueueFull,
    /// Nothing to receive.
    QueueEmpty,
    /// Message length above `IPC_MAX_MSG_BYTES`.
    TooLong(u32),
    /// RECV on an endpoint the caller does not own (queues are
    /// per-domain; delegating queue ownership is a later slice).
    NotOwner(u32),
    /// The endpoint table is exhausted.
    TableFull,
    /// A supervisor-only API was called by a non-privileged domain.
    NotAuthorized(u32),
    /// Requested rights exceed the conferable set (READ|WRITE|GRANT):
    /// the endpoint-grant derivation stays subset-only.
    Escalation,
    /// The target domain does not exist.
    UnknownDomain(u32),
    /// ADR-0029: a MESSAGE operation (send/recv/call/reply) aimed at
    /// a byte-channel endpoint — the type-discipline refusal. The two
    /// kinds share the id space but never the operations.
    WrongKind,
}

/// ADR-0026: what a sync-IPC-blocked domain is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcWaitKind {
    /// Blocked in ipc_call on `endpoint`: the owner's reply is the
    /// wake value (the reply's len).
    AwaitingReply { endpoint: u32 },
    /// Blocked in ipc_recv_wait on `endpoint` (the owner): the next
    /// push's rendezvous delivers the message len.
    AwaitingMsg { endpoint: u32 },
}

/// One registered waiter: the waiting domain + the kind + the FIFO
/// sequence (replies answer the OLDEST caller first). Slots are
/// insertion-ordered, like the sleepers' — the domain rides IN the
/// entry, never in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcWait {
    pub domain: u32,
    pub kind: IpcWaitKind,
    pub seq: u64,
}

/// One queued message record (payload length + authenticated sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub sender: u32,
    pub len: u32,
}

/// A live endpoint: owner + a bounded FIFO ring of message records.
/// ADR-0029: `pipe` set = a BYTE CHANNEL (the pipe engine's ring at
/// `CHANNEL_CAPACITY`); `pipe` clear = a MESSAGE endpoint (the
/// ADR-0004 queue). One id space, monotonic, never reused — the kind
/// is fixed at creation and every operation checks it.
#[derive(Clone, Copy)]
struct Endpoint {
    id: u32,
    owner: u32,
    ring: [Option<Message>; IPC_QUEUE_DEPTH],
    head: usize,
    count: usize,
    pipe: Option<crate::pipe::Pipe<CHANNEL_CAPACITY>>,
}

impl Endpoint {
    const fn empty() -> Self {
        Endpoint {
            id: 0,
            owner: 0,
            ring: [None; IPC_QUEUE_DEPTH],
            head: 0,
            count: 0,
            pipe: None,
        }
    }
}

/// Kernel-owned endpoint table. Slot reuse is safe because ids are
/// monotonic: a freed slot's old id is dead forever.
pub struct EndpointTable {
    slots: [Option<Endpoint>; MAX_ENDPOINTS],
    next_id: u32,
}

impl EndpointTable {
    pub fn new() -> Self {
        EndpointTable {
            slots: [None; MAX_ENDPOINTS],
            next_id: 1, // id 0 is never issued ("no endpoint" reads clearly)
        }
    }

    fn find(&self, id: u32) -> Option<&Endpoint> {
        self.slots.iter().flatten().find(|e| e.id == id)
    }

    fn find_mut(&mut self, id: u32) -> Option<&mut Endpoint> {
        self.slots.iter_mut().flatten().find(|e| e.id == id)
    }

    /// Create an endpoint owned by `owner`. Returns its fresh,
    /// never-before-used id.
    pub fn create(&mut self, owner: u32) -> Result<u32, IpcError> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(IpcError::TableFull)?;
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(IpcError::TableFull)?;
        self.slots[slot] = Some(Endpoint {
            id,
            owner,
            ..Endpoint::empty()
        });
        Ok(id)
    }

    /// Destroy an endpoint: its queue is dropped with it and the id is
    /// dead forever. Caller checks authority (uid-0 supervisor).
    pub fn destroy(&mut self, id: u32) -> Result<(), IpcError> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|e| e.id == id))
            .ok_or(IpcError::InvalidHandle)?;
        self.slots[slot] = None;
        Ok(())
    }

    /// The owning domain of a live endpoint (None = dead id).
    pub fn owner_of(&self, id: u32) -> Option<u32> {
        self.find(id).map(|e| e.owner)
    }

    /// Enqueue a message record. FIFO, bounded, EAGAIN-style overflow.
    /// ADR-0029: message endpoints only — a channel id refuses
    /// `WrongKind` (bytes and messages never share an operation).
    pub fn push(&mut self, id: u32, sender: u32, len: u32) -> Result<usize, IpcError> {
        if len > IPC_MAX_MSG_BYTES {
            return Err(IpcError::TooLong(len));
        }
        let e = self.find_mut(id).ok_or(IpcError::InvalidHandle)?;
        if e.pipe.is_some() {
            return Err(IpcError::WrongKind);
        }
        if e.count == IPC_QUEUE_DEPTH {
            return Err(IpcError::QueueFull);
        }
        let tail = (e.head + e.count) % IPC_QUEUE_DEPTH;
        e.ring[tail] = Some(Message { sender, len });
        e.count += 1;
        // Free slots remaining after the push (useful, cheap telemetry).
        Ok(IPC_QUEUE_DEPTH - e.count)
    }

    /// Dequeue the oldest message record (FIFO). Message endpoints
    /// only (ADR-0029 type discipline).
    pub fn pop(&mut self, id: u32) -> Result<Message, IpcError> {
        let e = self.find_mut(id).ok_or(IpcError::InvalidHandle)?;
        if e.pipe.is_some() {
            return Err(IpcError::WrongKind);
        }
        if e.count == 0 {
            return Err(IpcError::QueueEmpty);
        }
        let m = e.ring[e.head].take().expect("count > 0 implies a record");
        e.head = (e.head + 1) % IPC_QUEUE_DEPTH;
        e.count -= 1;
        Ok(m)
    }

    /// Queue depth of a live endpoint (tests + telemetry).
    pub fn depth_of(&self, id: u32) -> Option<usize> {
        self.find(id).map(|e| e.count)
    }

    /// Live endpoint count (capacity reporting).
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ── ADR-0029: byte-channel endpoints ──────────────────────────

    /// Create a byte-channel endpoint owned by `owner`: the pipe
    /// engine's ring at `CHANNEL_CAPACITY`, the same monotonic id
    /// space as message endpoints. The channel lives until an
    /// explicit `destroy` UNLESS fd references take it over (see
    /// `channel_release_read`/`write`: both ends' refs at zero
    /// reclaim the slot — the Unix pipe lifetime).
    pub fn create_channel(&mut self, owner: u32) -> Result<u32, IpcError> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(IpcError::TableFull)?;
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(IpcError::TableFull)?;
        let mut e = Endpoint {
            id,
            owner,
            ..Endpoint::empty()
        };
        e.pipe = Some(crate::pipe::Pipe::new());
        self.slots[slot] = Some(e);
        Ok(id)
    }

    /// ADR-0029: is this live id a byte channel? (False for dead ids
    /// and message endpoints — callers that need the distinction
    /// check liveness through the operation's own error first.)
    #[must_use]
    pub fn is_channel(&self, id: u32) -> bool {
        self.find(id).is_some_and(|e| e.pipe.is_some())
    }

    /// The live endpoint ids, in creation order (supervisor hygiene
    /// sweeps; ADR-0029 D4).
    pub fn live_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots.iter().flatten().map(|e| e.id)
    }

    fn channel(&mut self, id: u32) -> Result<&mut crate::pipe::Pipe<CHANNEL_CAPACITY>, PipeError> {
        let e = self.find_mut(id).ok_or(PipeError::InvalidPipe(id))?;
        e.pipe.as_mut().ok_or(PipeError::NotAChannel(id))
    }

    /// Write up to `bytes.len()` into the channel; returns bytes
    /// accepted (short write at the free space). `WouldBlock` when
    /// full, `BrokenPipe` once the read end has closed — the pipe
    /// semantics, capability-mediated by the caller.
    pub fn channel_write(&mut self, id: u32, bytes: &[u8]) -> Result<usize, PipeError> {
        self.channel(id)?.write(bytes)
    }

    /// Read up to `buf.len()` bytes out of the channel (short read);
    /// `Ok(0)` at EOF (write end closed and drained), `WouldBlock`
    /// when empty with the write end open.
    pub fn channel_read(&mut self, id: u32, buf: &mut [u8]) -> Result<usize, PipeError> {
        self.channel(id)?.read(buf)
    }

    /// Open read-end descriptors on the channel (dup introspection;
    /// tests and telemetry). None on dead ids and message endpoints.
    #[must_use]
    pub fn channel_read_refs(&self, id: u32) -> Option<u8> {
        let e = self.find(id)?;
        e.pipe.as_ref().map(|p| p.read_refs())
    }

    /// Open write-end descriptors on the channel (dup introspection).
    #[must_use]
    pub fn channel_write_refs(&self, id: u32) -> Option<u8> {
        let e = self.find(id)?;
        e.pipe.as_ref().map(|p| p.write_refs())
    }

    /// ADR-0029 D7: is the channel's write end still open? None for
    /// dead ids and message endpoints.
    #[must_use]
    pub fn channel_write_open(&self, id: u32) -> Option<bool> {
        let e = self.find(id)?;
        e.pipe.as_ref().map(|p| p.write_open())
    }

    /// ADR-0029 D7: force the write end closed (the last WRITE
    /// capability died, not a descriptor). Reclaims the slot when the
    /// read end is already closed too.
    pub fn channel_mark_write_closed(&mut self, id: u32) -> Result<(), PipeError> {
        let reclaim = self.channel(id)?.mark_write_closed();
        if reclaim {
            self.slots[self
                .slots
                .iter()
                .position(|s| s.as_ref().is_some_and(|e| e.id == id))
                .expect("a live channel just answered")] = None;
        }
        Ok(())
    }

    /// Bytes waiting in the channel (the `recv_wait` fast path and
    /// probes). `NotAChannel` on message endpoints, `InvalidPipe` on
    /// dead ids.
    pub fn channel_avail(&self, id: u32) -> Result<usize, PipeError> {
        let e = self.find(id).ok_or(PipeError::InvalidPipe(id))?;
        e.pipe.as_ref().ok_or(PipeError::NotAChannel(id))?;
        Ok(e.pipe.as_ref().map_or(0, |p| p.count()))
    }

    /// Register one more descriptor referencing the read end (fd
    /// alloc/dup).
    pub fn channel_acquire_read(&mut self, id: u32) -> Result<(), PipeError> {
        self.channel(id)?.acquire_read();
        Ok(())
    }

    /// Register one more descriptor referencing the write end.
    pub fn channel_acquire_write(&mut self, id: u32) -> Result<(), PipeError> {
        self.channel(id)?.acquire_write();
        Ok(())
    }

    /// Drop one read-end reference. The last one closes the end; if
    /// the write end is already closed too, the SLOT RECLAIMS ITSELF
    /// (the fd-scoped lifetime — Unix pipe semantics; the id stays
    /// dead forever, the no-ABA rule). A channel that never saw an
    /// acquire (the supervisor bootstrap shape) never reclaims here.
    pub fn channel_release_read(&mut self, id: u32) -> Result<(), PipeError> {
        let reclaim = self.channel(id)?.release_read();
        if reclaim {
            self.slots[self
                .slots
                .iter()
                .position(|s| s.as_ref().is_some_and(|e| e.id == id))
                .expect("a live channel just answered")] = None;
        }
        Ok(())
    }

    /// Drop one write-end reference (dup-aware; the read side sees
    /// EOF once the last one goes, and a both-ends-closed channel
    /// reclaims its slot).
    pub fn channel_release_write(&mut self, id: u32) -> Result<(), PipeError> {
        let reclaim = self.channel(id)?.release_write();
        if reclaim {
            self.slots[self
                .slots
                .iter()
                .position(|s| s.as_ref().is_some_and(|e| e.id == id))
                .expect("a live channel just answered")] = None;
        }
        Ok(())
    }
}

impl Default for EndpointTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_push_pop_roundtrip_fifo() {
        let mut t = EndpointTable::new();
        let ep = t.create(7).unwrap();
        assert_eq!(t.owner_of(ep), Some(7));
        for len in [1u32, 2, 3] {
            assert_eq!(t.push(ep, 9, len), Ok(IPC_QUEUE_DEPTH - len as usize));
        }
        assert_eq!(t.depth_of(ep), Some(3));
        for len in [1u32, 2, 3] {
            assert_eq!(t.pop(ep), Ok(Message { sender: 9, len }));
        }
        assert_eq!(t.pop(ep), Err(IpcError::QueueEmpty));
    }

    #[test]
    fn bounded_queue_refuses_with_eagain_style() {
        let mut t = EndpointTable::new();
        let ep = t.create(1).unwrap();
        for i in 0..IPC_QUEUE_DEPTH {
            t.push(ep, 1, (i + 1) as u32).unwrap();
        }
        assert_eq!(t.push(ep, 1, 8), Err(IpcError::QueueFull));
        // Pop one: exactly one slot frees (no silent drops anywhere).
        t.pop(ep).unwrap();
        assert!(t.push(ep, 1, 8).is_ok());
    }

    #[test]
    fn oversize_messages_refused_before_queue_work() {
        let mut t = EndpointTable::new();
        let ep = t.create(1).unwrap();
        assert_eq!(t.push(ep, 1, IPC_MAX_MSG_BYTES), Ok(IPC_QUEUE_DEPTH - 1));
        assert_eq!(
            t.push(ep, 1, IPC_MAX_MSG_BYTES + 1),
            Err(IpcError::TooLong(65))
        );
    }

    #[test]
    fn ids_are_never_reused_no_aba() {
        let mut t = EndpointTable::new();
        let first = t.create(1).unwrap();
        t.push(first, 1, 8).unwrap();
        t.destroy(first).unwrap();
        // The queue died with the endpoint.
        assert_eq!(t.owner_of(first), None);
        assert_eq!(t.pop(first), Err(IpcError::InvalidHandle));
        // A new create reuses the SLOT but never the ID.
        let second = t.create(2).unwrap();
        assert_ne!(first, second);
        assert_eq!(t.owner_of(first), None, "the old id stays dead");
        assert_eq!(t.owner_of(second), Some(2));
        // Double destroy of the same id fails closed.
        assert_eq!(t.destroy(first), Err(IpcError::InvalidHandle));
    }

    #[test]
    fn table_exhaustion_is_surfaced_not_silent() {
        let mut t = EndpointTable::new();
        for i in 0..MAX_ENDPOINTS {
            assert!(t.create(i as u32).is_ok());
        }
        assert_eq!(t.len(), MAX_ENDPOINTS);
        assert_eq!(t.create(99), Err(IpcError::TableFull));
        // Destroy frees a slot: the next create succeeds.
        t.destroy(1).unwrap();
        assert!(t.create(99).is_ok());
    }

    #[test]
    fn ring_wraps_correctly_across_boundaries() {
        let mut t = EndpointTable::new();
        let ep = t.create(1).unwrap();
        // Wrap the ring multiple times with interleaved push/pop.
        for round in 0..6u32 {
            for i in 0..IPC_QUEUE_DEPTH as u32 {
                t.push(ep, round, i).unwrap();
            }
            for i in 0..IPC_QUEUE_DEPTH as u32 {
                assert_eq!(
                    t.pop(ep),
                    Ok(Message {
                        sender: round,
                        len: i
                    })
                );
            }
        }
    }

    // ── ADR-0029: byte-channel endpoints ──────────────────────────

    #[test]
    fn channel_roundtrip_short_write_and_read() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(5).unwrap();
        assert_eq!(t.owner_of(ep), Some(5));
        assert!(t.is_channel(ep));
        // A write larger than the ring is SHORT (the free space), and
        // a full ring refuses WouldBlock — the bounded truth.
        let n = t.channel_write(ep, &[7u8; CHANNEL_CAPACITY + 44]).unwrap();
        assert_eq!(n, CHANNEL_CAPACITY);
        assert_eq!(t.channel_write(ep, b"!"), Err(PipeError::WouldBlock));
        // Short read: only what was asked, exact bytes back.
        let mut out = [0u8; 100];
        assert_eq!(t.channel_read(ep, &mut out).unwrap(), 100);
        assert_eq!(&out, &[7u8; 100]);
        let mut rest = [0u8; CHANNEL_CAPACITY];
        assert_eq!(
            t.channel_read(ep, &mut rest).unwrap(),
            CHANNEL_CAPACITY - 100
        );
        assert_eq!(
            &rest[..CHANNEL_CAPACITY - 100],
            &[7u8; CHANNEL_CAPACITY - 100]
        );
        // Drained, write end open: WouldBlock (non-blocking flavor).
        assert_eq!(t.channel_read(ep, &mut out), Err(PipeError::WouldBlock));
    }

    #[test]
    fn channel_ring_wraps_across_boundaries() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(1).unwrap();
        // 40-byte chunks crossing the 256-byte boundary repeatedly.
        let mut seq = 0u8;
        for _ in 0..20 {
            let mut chunk = [0u8; 40];
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = seq.wrapping_add(i as u8);
            }
            assert_eq!(t.channel_write(ep, &chunk).unwrap(), 40);
            let mut out = [0u8; 40];
            assert_eq!(t.channel_read(ep, &mut out).unwrap(), 40);
            assert_eq!(&out, &chunk);
            seq = seq.wrapping_add(40);
        }
    }

    #[test]
    fn channel_eof_after_write_end_closed() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(1).unwrap();
        t.channel_acquire_write(ep).unwrap();
        t.channel_acquire_read(ep).unwrap();
        t.channel_write(ep, b"xyz").unwrap();
        t.channel_release_write(ep).unwrap(); // last write ref: end closes
        let mut out = [0u8; 8];
        assert_eq!(t.channel_read(ep, &mut out).unwrap(), 3); // buffered
        assert_eq!(&out[..3], b"xyz");
        assert_eq!(t.channel_read(ep, &mut out).unwrap(), 0); // EOF
    }

    #[test]
    fn channel_epipe_after_read_end_closed() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(1).unwrap();
        t.channel_acquire_read(ep).unwrap();
        t.channel_release_read(ep).unwrap();
        assert_eq!(t.channel_write(ep, b"dead"), Err(PipeError::BrokenPipe));
    }

    #[test]
    fn channel_fd_scoped_reclaim_when_both_released() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(2).unwrap();
        t.channel_acquire_read(ep).unwrap();
        t.channel_acquire_write(ep).unwrap();
        t.channel_acquire_write(ep).unwrap(); // dup
                                              // First write release: one ref left, the end stays open.
        t.channel_release_write(ep).unwrap();
        assert!(t.channel_write(ep, b"alive").is_ok());
        // Last write release + the read release: the slot reclaims
        // ITSELF (the Unix pipe lifetime; no supervisor involved).
        t.channel_release_write(ep).unwrap();
        t.channel_release_read(ep).unwrap();
        assert_eq!(t.channel_write(ep, b"x"), Err(PipeError::InvalidPipe(ep)));
        assert_eq!(t.owner_of(ep), None);
        assert_eq!(t.live_ids().count(), 0);
        // The id is dead forever even though the SLOT may be reused.
        let next = t.create_channel(3).unwrap();
        assert_ne!(next, ep);
    }

    #[test]
    fn supervisor_channel_without_refs_never_self_reclaims() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(9).unwrap();
        // No acquire ever happened (the kmain bootstrap shape): the
        // endpoint lives until an explicit destroy.
        assert_eq!(t.live_ids().count(), 1);
        let mut out = [0u8; 4];
        assert_eq!(t.channel_read(ep, &mut out), Err(PipeError::WouldBlock));
        assert_eq!(t.owner_of(ep), Some(9));
    }

    #[test]
    fn channel_wrong_kind_refusals_both_directions() {
        let mut t = EndpointTable::new();
        let msg = t.create(1).unwrap();
        let ch = t.create_channel(1).unwrap();
        // Message ops on a channel: WrongKind.
        assert_eq!(t.push(ch, 1, 8), Err(IpcError::WrongKind));
        assert_eq!(t.pop(ch), Err(IpcError::WrongKind));
        // Channel ops on a message endpoint: NotAChannel.
        assert_eq!(t.channel_write(msg, b"x"), Err(PipeError::NotAChannel(msg)));
        let mut out = [0u8; 4];
        assert_eq!(
            t.channel_read(msg, &mut out),
            Err(PipeError::NotAChannel(msg))
        );
        assert_eq!(t.channel_avail(msg), Err(PipeError::NotAChannel(msg)));
    }

    #[test]
    fn channel_avail_counts_waiting_bytes() {
        let mut t = EndpointTable::new();
        let ep = t.create_channel(1).unwrap();
        assert_eq!(t.channel_avail(ep).unwrap(), 0);
        t.channel_write(ep, &[1u8; 24]).unwrap();
        assert_eq!(t.channel_avail(ep).unwrap(), 24);
        let mut out = [0u8; 10];
        t.channel_read(ep, &mut out).unwrap();
        assert_eq!(t.channel_avail(ep).unwrap(), 14);
    }

    #[test]
    fn channel_ids_share_the_monotonic_space() {
        let mut t = EndpointTable::new();
        let m1 = t.create(1).unwrap();
        let c1 = t.create_channel(1).unwrap();
        let m2 = t.create(1).unwrap();
        let c2 = t.create_channel(1).unwrap();
        // One id space, strictly monotonic, kinds interleaved freely.
        assert!(m1 < c1 && c1 < m2 && m2 < c2);
        assert_eq!(t.live_ids().count(), 4);
        // Destroy a message endpoint; the channel ids are unaffected.
        t.destroy(m1).unwrap();
        assert_eq!(t.live_ids().count(), 3);
    }
}
