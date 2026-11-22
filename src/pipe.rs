//! Bounded anonymous pipes (POSIX `pipe(2)` semantics in miniature).
//!
//! - Fixed byte ring per pipe (`CAP`, const-generic since ADR-0029:
//!   the ambient table used 64, the endpoint byte channel uses 256);
//!   ids are table indices.
//! - Writes are short: at most the free space is accepted. A completely
//!   full pipe returns `WouldBlock` (non-blocking flavor, deterministic).
//! - Reads are short: up to `buf.len()` or the available bytes.
//!   An empty pipe with the write end open returns `WouldBlock`;
//!   with the write end closed it returns `Ok(0)` — EOF.
//! - Writing to a pipe whose read end is closed returns `BrokenPipe` (EPIPE).
//! - The slot is reclaimed when both ends are closed.
//!
//! ADR-0029: `Pipe` is the RING ENGINE — the semantics this module's
//! tests pin. The ambient `PipeTable` that used to own these rings is
//! gone (the capability-mediated `EndpointTable` hosts them now); the
//! engine survives inside byte-channel endpoints unchanged.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// No free pipe slot.
    TableFull,
    /// Unknown pipe id (never created, or both ends already closed).
    /// ADR-0029: also the byte-channel refusal for a dead or
    /// non-channel endpoint id (the caller asked for a channel, the
    /// id is not one).
    InvalidPipe(u32),
    /// Pipe is full (non-blocking flavor).
    WouldBlock,
    /// Read end closed; no reader left (EPIPE).
    BrokenPipe,
    /// ADR-0029: the id names a live MESSAGE endpoint, not a byte
    /// channel — the type-discipline refusal.
    NotAChannel(u32),
}

/// The ring engine. ADR-0029: pub(crate) — the endpoint byte channel
/// hosts it directly; the methods below are the OWNERSHIP half (dup
/// refs, end closes, the both-ends-closed reclaim signal) so every
/// host of the engine gets identical semantics.
#[derive(Clone, Copy)]
pub(crate) struct Pipe<const CAP: usize> {
    buf: [u8; CAP],
    head: usize,
    count: usize,
    write_open: bool,
    read_open: bool,
    /// How many open descriptors reference the read end (dup-aware).
    read_refs: u8,
    /// How many open descriptors reference the write end (dup-aware).
    write_refs: u8,
}

impl<const CAP: usize> Pipe<CAP> {
    pub(crate) const fn new() -> Self {
        Pipe {
            buf: [0; CAP],
            head: 0,
            count: 0,
            write_open: true,
            read_open: true,
            read_refs: 0,
            write_refs: 0,
        }
    }

    fn free(&self) -> usize {
        CAP - self.count
    }

    /// Bytes currently buffered (ADR-0029: the channel's `avail`).
    pub(crate) fn count(&self) -> usize {
        self.count
    }

    /// Open read-end descriptors (dup introspection; tests).
    pub(crate) fn read_refs(&self) -> u8 {
        self.read_refs
    }

    /// Open write-end descriptors (dup introspection; tests).
    pub(crate) fn write_refs(&self) -> u8 {
        self.write_refs
    }

    /// Is the write end still open? (ADR-0029 D7's EOF-wake
    /// transition detector.)
    pub(crate) fn write_open(&self) -> bool {
        self.write_open
    }

    /// Force the write end closed with no fd accounting (ADR-0029
    /// D7: the last WRITE *capability* died, not a descriptor).
    /// Returns true when the SLOT should reclaim (the read end was
    /// already closed too).
    pub(crate) fn mark_write_closed(&mut self) -> bool {
        self.write_open = false;
        !self.read_open
    }

    /// Register one more read-end descriptor (fd alloc/dup).
    pub(crate) fn acquire_read(&mut self) {
        self.read_refs = self.read_refs.saturating_add(1);
    }

    /// Register one more write-end descriptor.
    pub(crate) fn acquire_write(&mut self) {
        self.write_refs = self.write_refs.saturating_add(1);
    }

    /// Drop one read-end reference. Returns true when the SLOT should
    /// reclaim (this close took the last read ref AND the write end is
    /// already closed) — the caller owns the table.
    pub(crate) fn release_read(&mut self) -> bool {
        if self.read_refs > 1 {
            self.read_refs -= 1;
            return false;
        }
        self.read_refs = 0;
        self.read_open = false;
        !self.write_open
    }

    /// Drop one write-end reference (dup-aware). Returns true when
    /// the slot should reclaim.
    pub(crate) fn release_write(&mut self) -> bool {
        if self.write_refs > 1 {
            self.write_refs -= 1;
            return false;
        }
        self.write_refs = 0;
        self.write_open = false;
        !self.read_open
    }

    /// Write up to `bytes.len()` bytes; returns bytes accepted (short write).
    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<usize, PipeError> {
        if !self.read_open {
            return Err(PipeError::BrokenPipe);
        }
        if self.free() == 0 {
            return Err(PipeError::WouldBlock);
        }
        let n = bytes.len().min(self.free());
        for &b in &bytes[..n] {
            self.buf[(self.head + self.count) % CAP] = b;
            self.count += 1;
        }
        Ok(n)
    }

    /// Read up to `buf.len()` bytes; returns bytes read (short read),
    /// or 0 at EOF (write end closed and buffer drained).
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize, PipeError> {
        if self.count == 0 {
            if !self.write_open {
                return Ok(0); // EOF
            }
            return Err(PipeError::WouldBlock);
        }
        let n = buf.len().min(self.count);
        for slot in buf.iter_mut().take(n) {
            *slot = self.buf[self.head];
            self.head = (self.head + 1) % CAP;
            self.count -= 1;
        }
        Ok(n)
    }
}
