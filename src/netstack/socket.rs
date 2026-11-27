//! The sockets API: capability-gated fd surface over the stack (K24).
//!
//! ## What this module owns
//!
//! - [`SocketTable`]: a FIXED [`MAX_STACK_SOCKETS`] descriptor table
//!   with **per-domain quotas** — one domain cannot monopolize the
//!   stack ([`MAX_SOCKETS_PER_DOMAIN`], tracked in a fixed array of
//!   [`MAX_TRACKED_DOMAINS`] owners; an untracked 9th domain is
//!   refused, never silently unlimited).
//! - The fd lifecycle: `socket`/`bind`/`listen`/`connect`/`accept`/
//!   `send`/`recv`/`close` — POSIX-shaped semantics on top of the
//!   TCP/UDP layers, non-blocking everywhere ([`Error::Again`] /
//!   EAGAIN is the only "wait" answer; `connect` answers
//!   EINPROGRESS and completes by event).
//! - errno mapping is NOT invented here: every refusal goes through
//!   the ONE map in [`Error::errno`](super::error::Error::errno).
//!
//! ## Threat model (THREAT_MODEL.md §Resource Exhaustion, §Malformed)
//!
//! - The table is a fixed array: fd exhaustion is a bounded, counted
//!   refusal (EMFILE), never an allocation.
//! - Ownership is CAPABILITY-shaped: every operation names the
//!   calling domain, and a domain may only operate on ITS OWN
//!   descriptors — the fd number space is not shared secrets, the
//!   domain id is the capability check.
//! - Buffer sizes are fixed constants (send ring 1 KiB, UDP queue
//!   4×512 B): a caller asking to send "the world" gets a partial
//!   write bounded by what the TCB can hold, and the return value
//!   tells the truth.
//!
//! `no_std`, `no_alloc`, no `unsafe`.

use super::error::{Error, Result};
use super::tcp::TcpState;
use super::udp::UdpSocketQueue;

/// Socket descriptors in the stack's table.
pub const MAX_STACK_SOCKETS: usize = 16;
/// Per-domain cap.
pub const MAX_SOCKETS_PER_DOMAIN: usize = 6;
/// Domains whose quotas are tracked.
pub const MAX_TRACKED_DOMAINS: usize = 8;

/// The address family the stack speaks (the only one).
pub const AF_INET: i32 = 2;
/// Stream (TCP) sockets.
pub const SOCK_STREAM: i32 = 1;
/// Datagram (UDP) sockets.
pub const SOCK_DGRAM: i32 = 2;

/// The per-fd state. Stream sockets reference the TCP layer's TCB
/// pool or a listener slot BY INDEX — indices are private to the
/// stack, never a raw pointer.
// (clippy::large_enum_variant is deliberate: `Dgram` embeds the
// 2 KiB receive queue by VALUE — there is no allocator to Box it
// into, and the fixed 16-entry table bounds the total cost at
// ~36 KiB either way.)
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum SocketKind {
    /// A TCP client/connection socket bound to one TCB.
    Stream { tcb: usize },
    /// A TCP listener bound to one listener slot.
    Listen { listener: usize },
    /// A UDP socket with its bounded datagram queue.
    Dgram {
        bound_port: Option<u16>,
        remote: Option<([u8; 4], u16)>,
        queue: UdpSocketQueue,
    },
}

/// Why a stream socket is dead — carried to the user as the recv()
/// answer's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketStatus {
    Live,
    /// Handshake in flight (connect answered EINPROGRESS).
    Connecting,
    /// Peer refused / reset / timed out — the errno shape is on the
    /// error itself.
    Failed(Error),
    /// Torn down cleanly: recv() answers 0 (EOF), send() ENOTCONN.
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub struct SocketEntry {
    pub domain: u32,
    pub kind: SocketKind,
    pub status: SocketStatus,
}

/// The fixed descriptor table + per-domain accounting.
#[derive(Debug)]
pub struct SocketTable {
    entries: [Option<SocketEntry>; MAX_STACK_SOCKETS],
    domain_counts: [(u32, u16); MAX_TRACKED_DOMAINS],
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketTable {
    pub const fn new() -> SocketTable {
        SocketTable {
            entries: [None; MAX_STACK_SOCKETS],
            domain_counts: [(0, 0); MAX_TRACKED_DOMAINS],
        }
    }

    fn domain_slot(&mut self, domain: u32) -> Result<usize> {
        for (i, (d, _)) in self.domain_counts.iter().enumerate() {
            if *d == domain {
                return Ok(i);
            }
        }
        // Untracked: take a zero-count slot (a fresh domain's first
        // socket), else refuse — never silently unlimited.
        for (i, (d, c)) in self.domain_counts.iter_mut().enumerate() {
            if *c == 0 {
                *d = domain;
                return Ok(i);
            }
        }
        Err(Error::DomainQuota {
            domain,
            max: MAX_SOCKETS_PER_DOMAIN,
        })
    }

    /// Allocate the next fd. Quota + capacity are checked BEFORE the
    /// slot is touched.
    pub fn open(&mut self, domain: u32, kind: SocketKind) -> Result<u32> {
        let slot = self.domain_slot(domain)?;
        let (_, count) = self.domain_counts[slot];
        if count as usize >= MAX_SOCKETS_PER_DOMAIN {
            return Err(Error::DomainQuota {
                domain,
                max: MAX_SOCKETS_PER_DOMAIN,
            });
        }
        let fd = self
            .entries
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::SocketTableFull)? as u32;
        self.entries[fd as usize] = Some(SocketEntry {
            domain,
            kind,
            status: SocketStatus::Live,
        });
        self.domain_counts[slot].1 += 1;
        Ok(fd)
    }

    /// Close by fd — only the OWNER domain may (the capability
    /// check). Frees the quota accounting.
    pub fn close(&mut self, domain: u32, fd: u32) -> Result<SocketEntry> {
        let entry = self
            .entries
            .get_mut(fd as usize)
            .ok_or(Error::InvalidSocket(fd))?
            .take()
            .ok_or(Error::InvalidSocket(fd))?;
        if entry.domain != domain {
            // Not the owner: restore and refuse (a closed entry
            // would leak the quota — restore first).
            self.entries[fd as usize] = Some(entry);
            return Err(Error::InvalidSocket(fd));
        }
        for (d, c) in self.domain_counts.iter_mut() {
            if *d == domain && *c > 0 {
                *c -= 1;
                break;
            }
        }
        Ok(entry)
    }

    /// Shared view of one fd (owner-checked).
    pub fn get(&self, domain: u32, fd: u32) -> Result<&SocketEntry> {
        let e = self
            .entries
            .get(fd as usize)
            .ok_or(Error::InvalidSocket(fd))?
            .as_ref()
            .ok_or(Error::InvalidSocket(fd))?;
        if e.domain != domain {
            return Err(Error::InvalidSocket(fd));
        }
        Ok(e)
    }

    /// Raw entry view by INDEX (the stack's input path — the stack
    /// is the trusted owner; domain checks apply to the API, not to
    /// packet delivery).
    pub fn entries_view(&self, i: usize) -> Option<&SocketEntry> {
        self.entries.get(i).and_then(|e| e.as_ref())
    }

    /// Mutable datagram-queue access by index (the UDP input path).
    /// `None` when the index is not a bound datagram socket.
    pub fn entry_dgram_queue(&mut self, i: usize) -> Option<&mut UdpSocketQueue> {
        match self.entries.get_mut(i).and_then(|e| e.as_mut()) {
            Some(entry) => match &mut entry.kind {
                SocketKind::Dgram { queue, .. } => Some(queue),
                _ => None,
            },
            None => None,
        }
    }

    /// Mutable view of one fd (owner-checked).
    pub fn get_mut(&mut self, domain: u32, fd: u32) -> Result<&mut SocketEntry> {
        let e = self
            .entries
            .get_mut(fd as usize)
            .ok_or(Error::InvalidSocket(fd))?
            .as_mut()
            .ok_or(Error::InvalidSocket(fd))?;
        if e.domain != domain {
            return Err(Error::InvalidSocket(fd));
        }
        Ok(e)
    }

    /// Mark a stream fd's status (event-driven from the TCP layer).
    pub fn set_status(&mut self, fd: u32, status: SocketStatus) -> Result<()> {
        let e = self
            .entries
            .get_mut(fd as usize)
            .ok_or(Error::InvalidSocket(fd))?
            .as_mut()
            .ok_or(Error::InvalidSocket(fd))?;
        e.status = status;
        Ok(())
    }

    /// The errno for a failed socket op (kept as a helper so the
    /// syscall layer never formats its own codes).
    pub fn failure_errno(err: &Error) -> i32 {
        err.errno()
    }

    /// Descriptor count (diagnostics).
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Map a TCP close reason onto the socket status users see.
    pub fn status_for_reason(reason: super::tcp::CloseReason) -> SocketStatus {
        match reason {
            super::tcp::CloseReason::Normal => SocketStatus::Closed,
            super::tcp::CloseReason::Refused => SocketStatus::Failed(Error::ConnectionRefused),
            super::tcp::CloseReason::Reset => SocketStatus::Failed(Error::ConnectionReset),
            super::tcp::CloseReason::TimedOut => SocketStatus::Failed(Error::TimedOut),
        }
    }

    /// The public state of a stream fd, for poll-style users.
    pub fn stream_state(&self, tcp: &super::tcp::TcpLayer, fd: u32) -> Result<TcpState> {
        let e = self
            .entries
            .get(fd as usize)
            .ok_or(Error::InvalidSocket(fd))?
            .as_ref()
            .ok_or(Error::InvalidSocket(fd))?;
        match &e.kind {
            SocketKind::Stream { tcb } => Ok(tcp.state_of(*tcb)),
            SocketKind::Listen { .. } => Ok(TcpState::Listen),
            SocketKind::Dgram { .. } => Err(Error::WrongKind("socket: not a stream socket")),
        }
    }
}

/// The POSIX errno constants re-exported (one import surface for the
/// syscall boundary's callers).
pub use super::error::errno;
