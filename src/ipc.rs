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

/// Endpoint slots in the kernel (fail-loud exhaustion, F14 discipline).
pub const MAX_ENDPOINTS: usize = 8;
/// ADR-0004 §1: messages are fixed-size, at most 64 bytes.
pub const IPC_MAX_MSG_BYTES: u32 = 64;
/// Per-endpoint queue depth (bounded, EAGAIN-style overflow).
pub const IPC_QUEUE_DEPTH: usize = 4;

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
}

/// One queued message record (payload length + authenticated sender).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub sender: u32,
    pub len: u32,
}

/// A live endpoint: owner + a bounded FIFO ring of message records.
#[derive(Clone, Copy)]
struct Endpoint {
    id: u32,
    owner: u32,
    ring: [Option<Message>; IPC_QUEUE_DEPTH],
    head: usize,
    count: usize,
}

impl Endpoint {
    const fn empty() -> Self {
        Endpoint {
            id: 0,
            owner: 0,
            ring: [None; IPC_QUEUE_DEPTH],
            head: 0,
            count: 0,
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
    pub fn push(&mut self, id: u32, sender: u32, len: u32) -> Result<usize, IpcError> {
        if len > IPC_MAX_MSG_BYTES {
            return Err(IpcError::TooLong(len));
        }
        let e = self.find_mut(id).ok_or(IpcError::InvalidHandle)?;
        if e.count == IPC_QUEUE_DEPTH {
            return Err(IpcError::QueueFull);
        }
        let tail = (e.head + e.count) % IPC_QUEUE_DEPTH;
        e.ring[tail] = Some(Message { sender, len });
        e.count += 1;
        // Free slots remaining after the push (useful, cheap telemetry).
        Ok(IPC_QUEUE_DEPTH - e.count)
    }

    /// Dequeue the oldest message record (FIFO).
    pub fn pop(&mut self, id: u32) -> Result<Message, IpcError> {
        let e = self.find_mut(id).ok_or(IpcError::InvalidHandle)?;
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
}
