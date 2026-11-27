//! The netstack's error surface (K24).
//!
//! One enum for the whole stack, three consumers:
//!
//! 1. **Library callers** — every fallible path returns
//!    [`Result<T>`](crate::netstack::Result); nothing panics on
//!    untrusted input, ever.
//! 2. **Ring-3 programs** — [`Error::errno`] maps each variant onto
//!    the POSIX errno numbers the sockets API answers with
//!    (EAGAIN, ECONNREFUSED, …), so the syscall boundary is a
//!    faithful translation, not a re-invention.
//! 3. **Diagnostics** — [`core::fmt::Display`] renders every variant
//!    with its numbers, so a dropped frame can be logged in one
//!    line without a formatter.
//!
//! Threat model (THREAT_MODEL.md §Malformed): the distinction between
//! [`Error::Truncated`], [`Error::Malformed`] and the checksum family
//! is deliberate — a *length* bug and a *checksum* bug are different
//! incidents with different blast radii, and the stack's counters
//! keep them apart.
//!
//! `no_std`, `no_alloc`: no formatting allocation, no `String`, no
//! backtrace capture. The `'static` str payloads name the refusing
//! site (compile-time constants only).

use core::fmt;

/// The netstack's universal result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Linux errno numbers the sockets layer answers with. Kept as a
/// `pub` const block so the netd domain (and its tests) can assert
/// the exact wire-visible codes without magic numbers drifting.
pub mod errno {
    pub const EAGAIN: i32 = 11;
    pub const EINPROGRESS: i32 = 115;
    pub const ENOMEM: i32 = 12;
    pub const EINVAL: i32 = 22;
    pub const EMFILE: i32 = 24;
    pub const EMSGSIZE: i32 = 90;
    pub const ENETUNREACH: i32 = 101;
    pub const ECONNRESET: i32 = 104;
    pub const ENOBUFS: i32 = 105;
    pub const EISCONN: i32 = 106;
    pub const ENOTCONN: i32 = 107;
    pub const EADDRINUSE: i32 = 98;
    pub const ECONNREFUSED: i32 = 111;
    pub const ETIMEDOUT: i32 = 110;
    pub const EOPNOTSUPP: i32 = 95;
}

/// Every way the netstack can refuse. Grouped by origin layer; the
/// group order matches the module order the stack is built in
/// (ethernet → arp → ipv4 → icmp → udp → tcp → socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    // ── framing: ethernet.rs ──────────────────────────────────────
    /// A header claims more bytes than the buffer holds. `need` is
    /// the minimum the field requires, `have` the bytes actually
    /// present. Untrusted input NEVER extends a slice past this.
    Truncated { need: usize, have: usize },
    /// The frame/packet is structurally nonsensical (bad version,
    /// bad header length, data offset < 5, …) with the refusing
    /// site named.
    Malformed(&'static str),
    /// An EtherType we do not speak. Counted and dropped, never an
    /// error reply (replying to unknown protocols is an amplifier).
    BadEtherType(u16),
    /// The frame exceeds the Ethernet MTU the stack will ever emit
    /// or admit for local processing.
    FrameTooLong { len: usize, max: usize },

    // ── link: arp.rs ──────────────────────────────────────────────
    /// The ARP cache holds no entry for the destination yet — the
    /// request went out; retry after the resolver's deadline.
    ArpPending,
    /// The ARP cache table is full (all [`MAX_ARP_ENTRIES`] live and
    /// unexpired). The lookup failed without allocating.
    ArpTableFull,
    /// The single MAC-layer pending-transmit slot is occupied; the
    /// caller retries. Bounded by design (THREAT_MODEL.md §Resource
    /// Exhaustion): the stack never queues unboundedly.
    ArpQueueFull,

    // ── network: ipv4.rs ──────────────────────────────────────────
    /// Not an IPv4 packet (version != 4).
    BadIpVersion(u8),
    /// The IPv4 header checksum does not match the header bytes.
    BadIpChecksum,
    /// A transport checksum (TCP/UDP+pseudo-header) mismatch.
    BadTransportChecksum,
    /// The packet is addressed to an IP that is not ours (and not a
    /// broadcast we accept). Silently counted, never answered.
    NotForUs,
    /// An IPv4 protocol number with no handler (not ICMP/UDP/TCP).
    UnsupportedProtocol(u8),
    /// Two fragments of one datagram overlap. The ENTIRE datagram is
    /// dropped (THREAT_MODEL.md §IP Fragmentation: overlap is the
    /// teardrop shape, and we refuse it rather than believe any
    /// byte order).
    FragmentOverlap,
    /// More distinct fragments than the reassembly slot tracks.
    FragmentHoleCount,
    /// The reassembly pool has no free slot. The datagram is dropped,
    /// never partially processed.
    ReassemblyFull,
    /// An incomplete datagram aged out (bounded reassembly lifetime).
    ReassemblyTimeout,
    /// The datagram's reassembled size exceeds the fixed slot cap.
    DatagramTooLarge { len: usize, max: usize },

    // ── icmp.rs ───────────────────────────────────────────────────
    /// The ICMP error-generation token bucket is empty — the stack
    /// refuses to become an amplifier (THREAT_MODEL.md §Malformed).
    IcmpRateLimited,

    // ── tcp.rs ────────────────────────────────────────────────────
    /// The fixed TCB pool is exhausted.
    TcbPoolFull,
    /// The per-listener accept queue is full; the SYN was answered
    /// with a SYN-cookie (no TCB spent) or dropped, never queued
    /// unboundedly.
    AcceptQueueFull,
    /// The per-source SYN rate window tripped (THREAT_MODEL.md
    /// §SYN Flood). The SYN is dropped silently.
    SynDropped,
    /// A connection was refused by the peer (RST to our SYN, or no
    /// listener on the port). errno: ECONNREFUSED.
    ConnectionRefused,
    /// Retransmission exhaustion — the peer is unreachable at this
    /// hop; the TCB is destroyed. errno: ETIMEDOUT.
    TimedOut,
    /// The connection reset by the peer mid-stream (RST).
    ConnectionReset,
    /// The peer sent a segment that fails the RFC 793 acceptance
    /// test for the current state (e.g. a FIN at a sequence we
    /// never reached). Counted and dropped.
    SegmentUnacceptable,
    /// connect() on a socket whose handshake is still in flight.
    /// errno: EINPROGRESS (the sockets API's only "try again later
    /// with a different meaning" code).
    InProgress,
    /// A stream socket send would exceed the peer's advertised
    /// window and the send buffer simultaneously. errno: EAGAIN.
    SendStalled,
    /// The remote peer's SYN cookie did not validate (the ACK's
    /// acknowledgement number is not the cookie we minted for this
    /// time bucket). The ACK is dropped; no TCB is created.
    BadSynCookie,

    // ── sockets: socket.rs / the broker boundary ──────────────────
    /// The fixed socket table is exhausted. errno: EMFILE (the
    /// caller's file/table limit, the closest POSIX shape).
    SocketTableFull,
    /// The per-domain socket quota is exhausted — one domain may not
    /// monopolize the stack. errno: EMFILE with the domain named in
    /// the caller's diagnostics.
    DomainQuota { domain: u32, max: usize },
    /// Unknown socket descriptor.
    InvalidSocket(u32),
    /// The socket exists but is not open for this operation.
    NotOpen(u32),
    /// The address/port pair is already bound. errno: EADDRINUSE.
    AddrInUse,
    /// The operation does not match the socket's kind (send-stream
    /// on a datagram socket, listen on a connected socket, …).
    /// errno: EOPNOTSUPP or EINVAL by call site.
    WrongKind(&'static str),
    /// The socket is not bound/connected where the operation
    /// requires it. errno: EINVAL or ENOTCONN by call site.
    NotBound,
    /// A would-block: the operation can succeed later. errno: EAGAIN.
    Again,
    /// The broker's token bucket denied the egress (the stack never
    /// bypasses it — THREAT_MODEL.md §Broker Bypass). errno: EAGAIN.
    RateLimited { requested: u32, available: u32 },
    /// The egress exceeds the broker's hard frame cap before any
    /// token is touched. errno: EMSGSIZE.
    TooLong { requested: u32, max: u32 },
    /// A caller-supplied buffer is too small / a user copy would
    /// overflow. errno: EMSGSIZE or EINVAL by call site.
    InvalidArgument(&'static str),
    /// Destination is off-link and no gateway is configured. The
    /// stack does not forward; egress is refused.
    NoRoute,
}

impl Error {
    /// The POSIX errno this error answers with at the sockets
    /// boundary. One mapping, written down once: the syscall layer
    /// translates, it never invents codes.
    pub const fn errno(&self) -> i32 {
        match self {
            // Would-block family: recv empty, window stalled, broker
            // throttle — all "try again", none fatal.
            Error::Again | Error::SendStalled | Error::ArpQueueFull | Error::RateLimited { .. } => {
                errno::EAGAIN
            }
            Error::ArpPending | Error::InProgress => errno::EINPROGRESS,
            Error::ArpTableFull | Error::TcbPoolFull | Error::SocketTableFull => errno::EMFILE,
            Error::DomainQuota { .. } => errno::EMFILE,
            Error::ConnectionRefused => errno::ECONNREFUSED,
            Error::TimedOut => errno::ETIMEDOUT,
            Error::ConnectionReset => errno::ECONNRESET,
            Error::AddrInUse => errno::EADDRINUSE,
            Error::FrameTooLong { .. } | Error::DatagramTooLarge { .. } => errno::EMSGSIZE,
            Error::TooLong { .. } => errno::EMSGSIZE,
            Error::ReassemblyFull | Error::ReassemblyTimeout | Error::FragmentHoleCount => {
                errno::ENOBUFS
            }
            Error::WrongKind(_) => errno::EOPNOTSUPP,
            Error::NotBound => errno::EINVAL,
            Error::InvalidArgument(_) => errno::EINVAL,
            Error::SegmentUnacceptable | Error::BadSynCookie => errno::EINVAL,
            // Input-side refusals of untrusted packets are NOT
            // syscall errors: they surface as drops + counters. If
            // one ever escapes to the boundary anyway, EINVAL is the
            // honest "the peer sent garbage" answer, never success.
            Error::Truncated { .. }
            | Error::Malformed(_)
            | Error::BadEtherType(_)
            | Error::BadIpVersion(_)
            | Error::BadIpChecksum
            | Error::BadTransportChecksum
            | Error::NotForUs
            | Error::UnsupportedProtocol(_)
            | Error::FragmentOverlap
            | Error::IcmpRateLimited
            | Error::SynDropped
            | Error::AcceptQueueFull
            | Error::InvalidSocket(_)
            | Error::NotOpen(_) => errno::EINVAL,
            Error::NoRoute => errno::ENETUNREACH,
        }
    }

    /// True when the error is a would-block shape the caller may
    /// retry immediately after a poll cycle. Used by the sockets
    /// layer to decide between failing an fd and just yielding.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Again | Error::SendStalled | Error::RateLimited { .. } | Error::ArpQueueFull
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { need, have } => {
                write!(f, "truncated: need {need} bytes, have {have}")
            }
            Error::Malformed(site) => write!(f, "malformed at {site}"),
            Error::BadEtherType(t) => write!(f, "unsupported EtherType 0x{t:04x}"),
            Error::FrameTooLong { len, max } => write!(f, "frame {len} B exceeds {max} B"),
            Error::ArpPending => write!(f, "ARP resolution in flight"),
            Error::ArpTableFull => write!(f, "ARP cache full"),
            Error::ArpQueueFull => write!(f, "pending-TX slot busy"),
            Error::BadIpVersion(v) => write!(f, "IP version {v}, expected 4"),
            Error::BadIpChecksum => write!(f, "IPv4 header checksum mismatch"),
            Error::BadTransportChecksum => write!(f, "transport checksum mismatch"),
            Error::NotForUs => write!(f, "packet not addressed to us"),
            Error::UnsupportedProtocol(p) => write!(f, "IP protocol {p} unsupported"),
            Error::FragmentOverlap => write!(f, "fragment overlap: datagram dropped"),
            Error::FragmentHoleCount => write!(f, "too many fragment holes"),
            Error::ReassemblyFull => write!(f, "reassembly pool full"),
            Error::ReassemblyTimeout => write!(f, "reassembly timed out"),
            Error::DatagramTooLarge { len, max } => {
                write!(f, "reassembled {len} B exceeds {max} B cap")
            }
            Error::IcmpRateLimited => write!(f, "ICMP error bucket empty"),
            Error::TcbPoolFull => write!(f, "TCB pool exhausted"),
            Error::AcceptQueueFull => write!(f, "accept queue full"),
            Error::SynDropped => write!(f, "SYN dropped by per-source rate window"),
            Error::ConnectionRefused => write!(f, "connection refused"),
            Error::TimedOut => write!(f, "retransmission exhausted"),
            Error::ConnectionReset => write!(f, "connection reset by peer"),
            Error::SegmentUnacceptable => write!(f, "segment fails the acceptance test"),
            Error::InProgress => write!(f, "connection attempt in progress"),
            Error::SendStalled => write!(f, "send window and buffer full"),
            Error::BadSynCookie => write!(f, "SYN cookie did not validate"),
            Error::SocketTableFull => write!(f, "socket table exhausted"),
            Error::DomainQuota { domain, max } => {
                write!(f, "domain {domain} at its {max}-socket quota")
            }
            Error::InvalidSocket(fd) => write!(f, "invalid socket {fd}"),
            Error::NotOpen(fd) => write!(f, "socket {fd} not open"),
            Error::AddrInUse => write!(f, "address already in use"),
            Error::WrongKind(site) => write!(f, "wrong socket kind at {site}"),
            Error::NotBound => write!(f, "socket not bound"),
            Error::Again => write!(f, "would block"),
            Error::RateLimited {
                requested,
                available,
            } => {
                write!(f, "broker throttle: need {requested}, have {available}")
            }
            Error::TooLong { requested, max } => {
                write!(f, "send {requested} B over broker cap {max} B")
            }
            Error::InvalidArgument(site) => write!(f, "invalid argument at {site}"),
            Error::NoRoute => write!(f, "no route (off-link, no gateway)"),
        }
    }
}
