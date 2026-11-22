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

pub const MAX_PIPES: usize = 8;
pub const PIPE_CAPACITY: usize = 64;

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

#[derive(Default)]
pub struct PipeTable {
    pipes: [Option<Pipe<PIPE_CAPACITY>>; MAX_PIPES],
}

impl PipeTable {
    pub const fn new() -> Self {
        PipeTable {
            pipes: [None; MAX_PIPES],
        }
    }

    /// Create a pipe; the returned id addresses both ends.
    pub fn create(&mut self) -> Result<u32, PipeError> {
        for (i, slot) in self.pipes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Pipe::new());
                return Ok(i as u32);
            }
        }
        Err(PipeError::TableFull)
    }

    fn get(&mut self, id: u32) -> Result<&mut Pipe<PIPE_CAPACITY>, PipeError> {
        match self.pipes.get_mut(id as usize) {
            Some(Some(p)) => Ok(p),
            _ => Err(PipeError::InvalidPipe(id)),
        }
    }

    pub fn write(&mut self, id: u32, bytes: &[u8]) -> Result<usize, PipeError> {
        self.get(id)?.write(bytes)
    }

    pub fn read(&mut self, id: u32, buf: &mut [u8]) -> Result<usize, PipeError> {
        self.get(id)?.read(buf)
    }

    /// Close the read end. If the write end is already closed too, the
    /// slot is reclaimed.
    pub fn close_read(&mut self, id: u32) -> Result<(), PipeError> {
        let reclaim = {
            let p = self.get(id)?;
            p.read_open = false;
            !p.write_open
        };
        if reclaim {
            self.pipes[id as usize] = None;
        }
        Ok(())
    }

    /// Close the write end (readers will see EOF once drained).
    pub fn close_write(&mut self, id: u32) -> Result<(), PipeError> {
        let reclaim = {
            let p = self.get(id)?;
            p.write_open = false;
            !p.read_open
        };
        if reclaim {
            self.pipes[id as usize] = None;
        }
        Ok(())
    }

    /// Register a new descriptor referencing the read end (fd alloc/dup).
    pub fn acquire_read(&mut self, id: u32) -> Result<(), PipeError> {
        let p = self.get(id)?;
        p.read_refs = p.read_refs.saturating_add(1);
        Ok(())
    }

    /// Register a new descriptor referencing the write end (fd alloc/dup).
    pub fn acquire_write(&mut self, id: u32) -> Result<(), PipeError> {
        let p = self.get(id)?;
        p.write_refs = p.write_refs.saturating_add(1);
        Ok(())
    }

    /// Drop one descriptor reference to the read end. The end is actually
    /// closed (and the slot possibly reclaimed) only when the last
    /// reference goes away — dup semantics.
    pub fn release_read(&mut self, id: u32) -> Result<(), PipeError> {
        let p = self.get(id)?;
        if p.read_refs > 1 {
            p.read_refs -= 1;
            return Ok(());
        }
        p.read_refs = 0;
        self.close_read(id)
    }

    /// Drop one descriptor reference to the write end (dup-aware).
    pub fn release_write(&mut self, id: u32) -> Result<(), PipeError> {
        let p = self.get(id)?;
        if p.write_refs > 1 {
            p.write_refs -= 1;
            return Ok(());
        }
        p.write_refs = 0;
        self.close_write(id)
    }

    #[must_use]
    pub fn read_refs(&self, id: u32) -> Option<u8> {
        match self.pipes.get(id as usize) {
            Some(Some(p)) => Some(p.read_refs),
            _ => None,
        }
    }

    #[must_use]
    pub fn write_refs(&self, id: u32) -> Option<u8> {
        match self.pipes.get(id as usize) {
            Some(Some(p)) => Some(p.write_refs),
            _ => None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pipes.iter().flatten().count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_write_read_roundtrip_fifo() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        let payload: &[u8] = b"hello, aegis";
        let n = t.write(id, payload).unwrap();
        assert_eq!(n, payload.len());
        let mut out = [0u8; 32];
        let m = t.read(id, &mut out).unwrap();
        assert_eq!(m, payload.len());
        assert_eq!(&out[..m], payload);
        // Drained: empty pipe with writer still open.
        assert_eq!(t.read(id, &mut out), Err(PipeError::WouldBlock));
    }

    #[test]
    fn short_write_when_only_part_fits() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        let first = t.write(id, &[7u8; 60]).unwrap();
        assert_eq!(first, 60);
        // Only 4 bytes of space left.
        let second = t.write(id, &[9u8; 20]).unwrap();
        assert_eq!(second, 4, "short write accepts only the free space");
        // Now completely full.
        assert_eq!(t.write(id, b"!"), Err(PipeError::WouldBlock));
        let mut out = [0u8; 64];
        assert_eq!(t.read(id, &mut out).unwrap(), 64);
        assert_eq!(&out[..60], &[7u8; 60]);
        assert_eq!(&out[60..], &[9u8; 4]);
    }

    #[test]
    fn short_read_returns_only_available() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.write(id, b"abc").unwrap();
        let mut small = [0u8; 8];
        assert_eq!(t.read(id, &mut small).unwrap(), 3);
        assert_eq!(&small[..3], b"abc");
    }

    #[test]
    fn zero_length_read_and_write_edges() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        // Zero-length write on a non-full pipe is Ok(0) (POSIX allows it).
        assert_eq!(t.write(id, b"").unwrap(), 0);
        let mut out = [0u8; 4];
        // Empty + writer open: WouldBlock even for a zero-length buffer? No:
        // POSIX read of 0 returns 0; mirror that deterministically.
        // We keep the strict non-blocking flavor: WouldBlock.
        assert_eq!(t.read(id, &mut out), Err(PipeError::WouldBlock));
    }

    #[test]
    fn eof_after_close_write() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.write(id, b"xyz").unwrap();
        t.close_write(id).unwrap();
        // Buffered data still readable.
        let mut out = [0u8; 8];
        assert_eq!(t.read(id, &mut out).unwrap(), 3);
        assert_eq!(&out[..3], b"xyz");
        // Drained + writer gone: EOF.
        assert_eq!(t.read(id, &mut out).unwrap(), 0);
        assert_eq!(t.read(id, &mut out).unwrap(), 0);
    }

    #[test]
    fn broken_pipe_after_close_read() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.close_read(id).unwrap();
        assert_eq!(t.write(id, b"dead"), Err(PipeError::BrokenPipe));
    }

    #[test]
    fn slot_reclaimed_only_when_both_ends_closed() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.close_write(id).unwrap();
        // Read end still open: slot alive (EOF readable).
        let mut out = [0u8; 4];
        assert_eq!(t.read(id, &mut out).unwrap(), 0);
        t.close_read(id).unwrap();
        // Both closed: id is invalid now.
        assert_eq!(t.read(id, &mut out), Err(PipeError::InvalidPipe(id)));
        assert_eq!(t.write(id, b"x"), Err(PipeError::InvalidPipe(id)));
        assert_eq!(t.close_read(id), Err(PipeError::InvalidPipe(id)));
        assert!(t.is_empty());
        // The same slot is reusable.
        let id2 = t.create().unwrap();
        assert_eq!(id2, id);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn wraparound_preserves_order_over_many_cycles() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        let mut seq = 0u8;
        // Write 10, read 10, repeatedly: crosses the 64-byte ring many times.
        for _ in 0..30 {
            let chunk = [
                seq,
                seq.wrapping_add(1),
                seq.wrapping_add(2),
                seq.wrapping_add(3),
                seq.wrapping_add(4),
                seq.wrapping_add(5),
                seq.wrapping_add(6),
                seq.wrapping_add(7),
                seq.wrapping_add(8),
                seq.wrapping_add(9),
            ];
            assert_eq!(t.write(id, &chunk).unwrap(), 10);
            let mut out = [0u8; 10];
            assert_eq!(t.read(id, &mut out).unwrap(), 10);
            assert_eq!(&out, &chunk);
            seq = seq.wrapping_add(10);
        }
    }

    #[test]
    fn table_fills_and_reuses_slots() {
        let mut t = PipeTable::new();
        let mut ids = Vec::new();
        for i in 0..MAX_PIPES {
            let id = t.create().unwrap();
            assert_eq!(id, i as u32);
            ids.push(id);
        }
        assert_eq!(t.create(), Err(PipeError::TableFull));
        // Free two scattered slots; they are reused in index order.
        t.close_read(ids[3]).unwrap();
        t.close_write(ids[3]).unwrap();
        assert_eq!(t.create().unwrap(), 3);
        assert_eq!(t.len(), MAX_PIPES);
    }

    #[test]
    fn dup_aware_release_keeps_end_open_until_last_ref() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.acquire_write(id).unwrap();
        t.acquire_write(id).unwrap(); // dup
        assert_eq!(t.write_refs(id), Some(2));
        // First release: still one descriptor left, end stays open.
        t.release_write(id).unwrap();
        assert!(t.write(id, b"still alive").is_ok());
        // Last release: the end closes -> readers see EOF, slot drains.
        t.release_write(id).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(t.read(id, &mut out).unwrap(), 11);
        assert_eq!(&out[..11], b"still alive");
        assert_eq!(t.read(id, &mut out).unwrap(), 0);
    }

    #[test]
    fn release_without_acquire_closes_immediately() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.release_write(id).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(t.read(id, &mut out).unwrap(), 0, "EOF immediately");
        t.release_read(id).unwrap();
        assert_eq!(t.read(id, &mut out), Err(PipeError::InvalidPipe(id)));
    }

    #[test]
    fn invalid_pipe_ids_rejected() {
        let mut t = PipeTable::new();
        let mut out = [0u8; 4];
        assert_eq!(t.read(0, &mut out), Err(PipeError::InvalidPipe(0)));
        assert_eq!(t.write(99, b"x"), Err(PipeError::InvalidPipe(99)));
        assert_eq!(
            t.close_read(u32::MAX),
            Err(PipeError::InvalidPipe(u32::MAX))
        );
    }

    #[test]
    fn double_close_of_one_end_is_rejected_after_reclaim_only() {
        let mut t = PipeTable::new();
        let id = t.create().unwrap();
        t.close_read(id).unwrap();
        // Closing the same end again: pipe still exists (write end open),
        // so the close is idempotent-safe: we reject via state? The read end
        // is already closed; closing again succeeds as a no-op (POSIX close
        // on an fd is once, but our table tracks ends, not fds).
        t.close_read(id).unwrap();
        t.close_write(id).unwrap();
        assert_eq!(t.close_write(id), Err(PipeError::InvalidPipe(id)));
    }
}
