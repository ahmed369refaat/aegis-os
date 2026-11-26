//! The AKP1 package container: framing, streaming LZ4 block
//! decoder with decompression-bomb guards, and the
//! verify-before-extract pipeline.
//!
//! ## Container layout
//!
//! ```text
//! "AKP1"                          magic
//! u32 LE  manifest_len            (≤ MAX_MANIFEST)
//! [manifest_len bytes]            canonical manifest (AMFT)
//! [64 bytes]                      Ed25519 signature over
//!                                 "AKP1" || manifest_len || manifest
//! per file, in manifest order:
//!   u8 mode                       0 = store, 1 = lz4-blocks
//!   mode 0: raw bytes until the manifest's declared size is reached
//!   mode 1: blocks until declared size:
//!     u16 comp_len  u16 raw_len(≤ LZ4_BLOCK)  [comp_len bytes]
//! ```
//!
//! The payload is **positional**: paths, permissions and sizes live
//! only in the signed manifest; the payload section is pure data in
//! manifest order. There is nothing meaningful to forge in the
//! payload framing that the per-file hash check does not catch, and
//! nothing in the payload influences *where* bytes land.
//!
//! ## THREAT: malicious package contents
//!
//! * **Path traversal `../../`**: rejected twice — `Manifest::parse`
//!   validates every file path structurally, and the transaction
//!   re-validates against the live filesystem before staging.
//! * **Symlink attacks**: extraction writes only to freshly created
//!   staging files (`O_CREAT|O_EXCL`) inside the manager's own
//!   staging root; the install step moves them into place only
//!   after every destination parent is `stat`-verified as a real
//!   directory (see `transaction.rs`).
//! * **Hardlink to sensitive files**: the same `stat` walk refuses
//!   non-regular destination nodes; a hardlink at a destination
//!   would have the target's content hash, failing the pre-install
//!   check, and `rename` replaces rather than follows.
//! * **Zip-bomb-style payloads**: [`HashingSink`] enforces the
//!   signed declared size exactly, plus a global expansion-ratio
//!   cap (`BOMB_RATIO_CAP × compressed bytes + slack`); either guard
//!   firing aborts the whole transaction with
//!   [`ErrorKind::Bomb`].
//! * **TOCTOU on file extraction**: after writing a staged file it
//!   is re-read through a *fresh open* and re-hashed before the
//!   commit renames anything (the write handle is closed first) —
//!   a racing writer between write and verify is detected.
//!
//! ## THREAT: disk-full during install
//!
//! Every write flows through [`HashingSink`]; a
//! [`ErrorKind::NoSpace`] from the sink propagates immediately and
//! the transaction rolls back — a partially written staging file
//! never reaches the destination tree.

use crate::crypto::ct_eq;
use crate::crypto::ed25519;
use crate::crypto::sha256::Sha256;
use crate::error::{Error, ErrorKind, Result};
use crate::limits;
use crate::manifest::Manifest;
use crate::rd_u32;

/// A data source for package bytes (a file through [`crate::Fs`],
/// or an in-memory slice in tests/builders).
pub trait DataSource {
    /// Read up to `buf.len()` bytes; 0 = end of stream.
    ///
    /// # Errors
    /// Whatever the backing store reports, wrapped as
    /// [`ErrorKind::Io`].
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// A [`DataSource`] reading from an open [`crate::Fs`] handle.
pub struct FsSource<'a> {
    fs: &'a mut dyn crate::Fs,
    fd: u32,
}

impl<'a> FsSource<'a> {
    /// Wrap a handle.
    #[must_use]
    pub fn new(fs: &'a mut dyn crate::Fs, fd: u32) -> Self {
        FsSource { fs, fd }
    }
}

impl DataSource for FsSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.fs.read(self.fd, buf)
    }
}

/// A [`DataSource`] over an in-memory slice (tests, repo builder).
pub struct SliceSource<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SliceSource<'a> {
    /// Wrap the slice.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        SliceSource { buf, pos: 0 }
    }
}

impl DataSource for SliceSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.buf.len().saturating_sub(self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Buffered reader over a [`DataSource`]: every parse step is
/// bounds-checked against what is actually buffered — a truncated
/// package is an [`ErrorKind::InvalidFormat`], never a panic.
pub struct ByteReader<'a> {
    src: &'a mut dyn DataSource,
    buf: [u8; limits::IO_CHUNK],
    pos: usize,
    len: usize,
    total_in: u64,
    exhausted: bool,
}

impl<'a> ByteReader<'a> {
    /// Wrap a source.
    #[must_use]
    pub fn new(src: &'a mut dyn DataSource) -> Self {
        ByteReader {
            src,
            buf: [0; limits::IO_CHUNK],
            pos: 0,
            len: 0,
            total_in: 0,
            exhausted: false,
        }
    }

    /// Total bytes consumed from the source so far (for the ratio
    /// guard).
    #[must_use]
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// Ensure at least `n` bytes are buffered (n ≤ IO_CHUNK).
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] on truncation.
    fn need(&mut self, n: usize) -> Result<()> {
        debug_assert!(n <= limits::IO_CHUNK);
        if self.len - self.pos >= n {
            return Ok(());
        }
        // compact and top up
        let have = self.len - self.pos;
        self.buf.copy_within(self.pos..self.len, 0);
        self.pos = 0;
        self.len = have;
        while self.len < n && !self.exhausted {
            let got = self.src.read(&mut self.buf[self.len..])?;
            self.total_in = self.total_in.saturating_add(got as u64);
            if got == 0 {
                self.exhausted = true;
            } else {
                self.len += got;
            }
        }
        if self.len < n {
            return Err(Error::new(ErrorKind::InvalidFormat, "package truncated"));
        }
        Ok(())
    }

    /// Take `n` buffered bytes (n ≤ IO_CHUNK).
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < out.len() {
            let want = (out.len() - done).min(limits::IO_CHUNK);
            self.need(want)?;
            out[done..done + want].copy_from_slice(&self.buf[self.pos..self.pos + want]);
            self.pos += want;
            done += want;
        }
        Ok(())
    }
}

/// The extraction I/O pair: pull package bytes, push staged bytes.
///
/// Both operations are methods on ONE object so a single `&mut`
/// suffices — extraction alternates reads and writes, and the
/// borrow must pass through per call (this is what makes the
/// transaction able to drive extraction with its single `Fs`
/// reference while also opening staging files between files).
pub trait ExtractIo {
    /// Read up to `buf.len()` bytes of package input (0 = EOF).
    ///
    /// # Errors
    /// Io errors from the backing store.
    fn pull(&mut self, buf: &mut [u8]) -> Result<usize>;
    /// Write the whole chunk to the staged output.
    ///
    /// # Errors
    /// Io errors — including [`ErrorKind::NoSpace`] (disk full).
    fn push(&mut self, data: &[u8]) -> Result<()>;
}

/// Per-call-borrow input buffer: the extraction state machine owns
/// only data, never a borrow of the I/O.
pub struct InBuf {
    buf: [u8; limits::IO_CHUNK],
    pos: usize,
    len: usize,
    total_in: u64,
}

impl InBuf {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        InBuf {
            buf: [0; limits::IO_CHUNK],
            pos: 0,
            len: 0,
            total_in: 0,
        }
    }

    fn need(&mut self, io: &mut dyn ExtractIo, n: usize) -> Result<()> {
        debug_assert!(n <= limits::IO_CHUNK);
        if self.len - self.pos >= n {
            return Ok(());
        }
        let have = self.len - self.pos;
        self.buf.copy_within(self.pos..self.len, 0);
        self.pos = 0;
        self.len = have;
        while self.len < n {
            let got = io.pull(&mut self.buf[self.len..])?;
            if got == 0 {
                return Err(Error::new(ErrorKind::InvalidFormat, "package truncated"));
            }
            self.total_in = self.total_in.saturating_add(got as u64);
            self.len += got;
        }
        Ok(())
    }

    /// Take `n` buffered bytes (refilling through `io` as needed).
    fn take(&mut self, io: &mut dyn ExtractIo, n: usize) -> Result<&[u8]> {
        self.need(io, n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_exact(&mut self, io: &mut dyn ExtractIo, out: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < out.len() {
            let want = (out.len() - done).min(limits::IO_CHUNK);
            // `out` never aliases self.buf (distinct locals), so a
            // direct copy from the borrowed slice is safe
            let chunk = self.take(io, want)?;
            out[done..done + want].copy_from_slice(chunk);
            done += want;
        }
        Ok(())
    }
}

impl Default for InBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed, signature-checkable package header.
pub struct PackageHeader {
    /// The parsed (and structurally validated) manifest.
    pub manifest: Manifest,
    /// The raw canonical manifest bytes (the exact signed bytes).
    pub manifest_bytes: [u8; limits::MAX_MANIFEST],
    /// Their length.
    pub manifest_len: usize,
    /// The Ed25519 signature.
    pub signature: ed25519::Signature,
}

impl PackageHeader {
    /// Verify the package signature under `key`.
    ///
    /// **This must succeed before any payload byte is staged** — the
    /// pipeline is ordered verify → extract → hash-check → install.
    ///
    /// # Errors
    /// [`ErrorKind::BadSignature`] when the signature does not
    /// verify.
    pub fn verify_signature(&self, key: &ed25519::PublicKey) -> Result<()> {
        let mut msg = [0u8; 8 + limits::MAX_MANIFEST];
        msg[..4].copy_from_slice(b"AKP1");
        msg[4..8].copy_from_slice(&(self.manifest_len as u32).to_le_bytes());
        msg[8..8 + self.manifest_len].copy_from_slice(&self.manifest_bytes[..self.manifest_len]);
        if ed25519::verify(key, &msg[..8 + self.manifest_len], &self.signature) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::BadSignature,
                "package signature rejected",
            ))
        }
    }
}

/// Read and parse a package header from `src` (the manifest is fully
/// canonical-checked; the caller still owes the signature check
/// before extraction).
///
/// # Errors
/// [`ErrorKind::InvalidFormat`] / [`ErrorKind::TooLarge`] for
/// malformed framing; everything `Manifest::parse` can raise.
pub fn read_header(src: &mut dyn DataSource) -> Result<PackageHeader> {
    let mut br = ByteReader::new(src);
    read_header_br(&mut br)
}

/// [`read_header`] over an existing [`ByteReader`] — the stream
/// position advances past the signature, so extraction can continue
/// with the same reader (no buffered bytes are lost).
///
/// # Errors
/// As [`read_header`].
pub fn read_header_br(br: &mut ByteReader<'_>) -> Result<PackageHeader> {
    let magic = br
        .take(4)
        .map_err(|_| Error::new(ErrorKind::InvalidFormat, "short magic"))?;
    if magic != b"AKP1" {
        return Err(Error::new(ErrorKind::InvalidFormat, "bad package magic"));
    }
    let len_bytes = br
        .take(4)
        .map_err(|_| Error::new(ErrorKind::InvalidFormat, "short length"))?;
    let mlen = rd_u32(len_bytes)
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "bad length"))? as usize;
    if !(8..=limits::MAX_MANIFEST).contains(&mlen) {
        return Err(Error::new(
            ErrorKind::TooLarge,
            "manifest length out of band",
        ));
    }
    let mut mbytes = [0u8; limits::MAX_MANIFEST];
    br.read_exact(&mut mbytes[..mlen])?;
    let manifest = Manifest::parse(&mbytes[..mlen])?;
    let mut sig = [0u8; 64];
    br.read_exact(&mut sig)?;
    Ok(PackageHeader {
        manifest,
        manifest_bytes: mbytes,
        manifest_len: mlen,
        signature: sig,
    })
}

/// Read a package's header AND prepare an [`InBuf`] positioned just
/// past the signature, using one scoped fs borrow: the caller then
/// loops [`extract_file`] with its own I/O object.
///
/// # Errors
/// As [`read_header`].
pub fn open_header_stream(io: &mut dyn ExtractIo, ib: &mut InBuf) -> Result<PackageHeader> {
    // magic
    let magic = ib
        .take(io, 4)
        .map_err(|_| Error::new(ErrorKind::InvalidFormat, "short magic"))?;
    let mut magic_copy = [0u8; 4];
    magic_copy.copy_from_slice(magic);
    if &magic_copy != b"AKP1" {
        return Err(Error::new(ErrorKind::InvalidFormat, "bad package magic"));
    }
    let len_bytes = ib
        .take(io, 4)
        .map_err(|_| Error::new(ErrorKind::InvalidFormat, "short length"))?;
    let mut len_copy = [0u8; 4];
    len_copy.copy_from_slice(len_bytes);
    let mlen = rd_u32(&len_copy)
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "bad length"))? as usize;
    if !(8..=limits::MAX_MANIFEST).contains(&mlen) {
        return Err(Error::new(
            ErrorKind::TooLarge,
            "manifest length out of band",
        ));
    }
    let mut mbytes = [0u8; limits::MAX_MANIFEST];
    ib.read_exact(io, &mut mbytes[..mlen])?;
    let manifest = Manifest::parse(&mbytes[..mlen])?;
    let mut sig = [0u8; 64];
    ib.read_exact(io, &mut sig)?;
    Ok(PackageHeader {
        manifest,
        manifest_bytes: mbytes,
        manifest_len: mlen,
        signature: sig,
    })
}

/// Output accounting for extraction: hashes, enforces the declared
/// size and the expansion-ratio bomb guard; the caller pushes the
/// same bytes to the staged file right after.
pub struct HashingSink {
    hash: Sha256,
    written: u64,
    declared: u64,
    input_note: u64,
}

impl HashingSink {
    /// Create the sink for a file whose *signed* declared size is
    /// `declared`.
    #[must_use]
    pub fn new(declared: u64) -> Self {
        HashingSink {
            hash: Sha256::new(),
            written: 0,
            declared,
            input_note: 0,
        }
    }

    /// Record `n` compressed bytes consumed (ratio-guard input).
    pub fn note_input(&mut self, n: u64) {
        self.input_note = self.input_note.saturating_add(n);
    }

    fn guard(&self) -> Result<()> {
        if self.written > self.declared {
            return Err(Error::new(ErrorKind::Bomb, "payload exceeds declared size"));
        }
        let allowed = self
            .input_note
            .saturating_mul(limits::BOMB_RATIO_CAP)
            .saturating_add(limits::BOMB_RATIO_SLACK);
        if self.written > allowed {
            return Err(Error::new(ErrorKind::Bomb, "expansion ratio cap exceeded"));
        }
        Ok(())
    }

    /// Account one chunk: hash it and run the bomb guards. The
    /// caller pushes the same bytes to the staged file right after.
    ///
    /// # Errors
    /// [`ErrorKind::Bomb`] when a guard fires.
    pub fn emit(&mut self, data: &[u8]) -> Result<()> {
        self.written = self.written.saturating_add(data.len() as u64);
        self.guard()?;
        self.hash.update(data);
        Ok(())
    }

    /// Finish: size must match the declared size exactly; returns
    /// the SHA-256 of everything emitted.
    ///
    /// # Errors
    /// [`ErrorKind::Bomb`] (size mismatch), or the pending guard.
    pub fn finish(self) -> Result<[u8; 32]> {
        if self.written != self.declared {
            return Err(Error::new(
                ErrorKind::Bomb,
                "payload short of declared size",
            ));
        }
        self.guard()?;
        let mut d = [0u8; 32];
        self.hash.finish(&mut d);
        Ok(d)
    }
}

/// Streaming LZ4-block decoder over the ring history buffer.
///
/// The ring holds the last [`limits::LZ4_WINDOW`] emitted bytes —
/// match references never reach further back, so bytes older than
/// one window behind the write cursor are flushed to the sink while
/// decoding continues. Fixed memory: ring + block slack, regardless
/// of file size.
///
/// # Errors
/// [`ErrorKind::Bomb`] / [`ErrorKind::InvalidFormat`] on
/// malformed blocks (bad offsets, lengths).
pub struct Lz4Decoder {
    ring: [u8; limits::LZ4_WINDOW + limits::LZ4_BLOCK + 16],
    flushed: u64,
    written: u64,
}

impl Lz4Decoder {
    /// Fresh decoder (empty history).
    #[must_use]
    pub fn new() -> Self {
        Lz4Decoder {
            ring: [0; limits::LZ4_WINDOW + limits::LZ4_BLOCK + 16],
            flushed: 0,
            written: 0,
        }
    }

    fn cap(&self) -> u64 {
        self.ring.len() as u64
    }

    fn rpos(&self, abs: u64) -> usize {
        (abs % self.cap()) as usize
    }

    /// Decode one whole LZ4 block (`comp` bytes) into the sink.
    ///
    /// # Errors
    /// As the struct docs; plus sink errors (NoSpace etc.).
    pub fn decode_block(
        &mut self,
        comp: &[u8],
        sink: &mut HashingSink,
        io: &mut dyn ExtractIo,
    ) -> Result<()> {
        sink.note_input(comp.len() as u64);
        let mut i = 0usize;
        while i < comp.len() {
            let token = comp[i];
            i += 1;
            // literal length
            let mut lit = token as usize >> 4;
            if lit == 15 {
                loop {
                    let Some(&b) = comp.get(i) else {
                        return Err(Error::new(
                            ErrorKind::InvalidFormat,
                            "lz4 literal length truncated",
                        ));
                    };
                    i += 1;
                    lit = lit
                        .checked_add(b as usize)
                        .filter(|&l| l <= limits::LZ4_BLOCK)
                        .ok_or_else(|| {
                            Error::new(ErrorKind::Bomb, "lz4 literal length out of band")
                        })?;
                    if b != 255 {
                        break;
                    }
                }
            }
            // literals
            if i + lit > comp.len() {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "lz4 literals truncated",
                ));
            }
            self.write_literals(&comp[i..i + lit], sink, io)?;
            i += lit;
            if i >= comp.len() {
                break; // last sequence: literals only
            }
            // match offset
            if i + 2 > comp.len() {
                return Err(Error::new(ErrorKind::InvalidFormat, "lz4 offset truncated"));
            }
            let off = u16::from(comp[i]) | (u16::from(comp[i + 1]) << 8);
            i += 2;
            if off == 0 || u64::from(off) > self.written {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "lz4 offset out of history",
                ));
            }
            if u64::from(off) > limits::LZ4_WINDOW as u64 {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "lz4 offset beyond window",
                ));
            }
            // match length
            let mut mlen = (token & 0x0F) as usize + 4;
            if (token & 0x0F) == 15 {
                loop {
                    let Some(&b) = comp.get(i) else {
                        return Err(Error::new(
                            ErrorKind::InvalidFormat,
                            "lz4 match length truncated",
                        ));
                    };
                    i += 1;
                    mlen = mlen
                        .checked_add(b as usize)
                        .filter(|&l| l <= limits::LZ4_BLOCK)
                        .ok_or_else(|| {
                            Error::new(ErrorKind::Bomb, "lz4 match length out of band")
                        })?;
                    if b != 255 {
                        break;
                    }
                }
            }
            self.copy_match(off, mlen, sink, io)?;
        }
        Ok(())
    }

    fn write_literals(
        &mut self,
        data: &[u8],
        sink: &mut HashingSink,
        io: &mut dyn ExtractIo,
    ) -> Result<()> {
        if data.len() > limits::LZ4_BLOCK {
            return Err(Error::new(ErrorKind::Bomb, "literal run exceeds block cap"));
        }
        let start = self.written;
        for (off, &b) in data.iter().enumerate() {
            self.ring[self.rpos(start + off as u64)] = b;
        }
        self.written = self.written.saturating_add(data.len() as u64);
        self.flush_aged(sink, io, false)?;
        Ok(())
    }

    fn copy_match(
        &mut self,
        off: u16,
        len: usize,
        sink: &mut HashingSink,
        io: &mut dyn ExtractIo,
    ) -> Result<()> {
        if len > limits::LZ4_BLOCK {
            return Err(Error::new(ErrorKind::Bomb, "match run exceeds block cap"));
        }
        let mut remaining = len;
        while remaining > 0 {
            let step = remaining.min(limits::LZ4_BLOCK);
            for _ in 0..step {
                let src_abs = self.written - u64::from(off);
                let b = self.ring[self.rpos(src_abs)];
                self.ring[self.rpos(self.written)] = b;
                self.written += 1;
            }
            remaining -= step;
            self.flush_aged(sink, io, false)?;
        }
        Ok(())
    }

    /// Emit bytes that are more than one window behind the cursor
    /// (no match can reach them anymore). `all` flushes everything
    /// (end of file).
    fn flush_aged(
        &mut self,
        sink: &mut HashingSink,
        io: &mut dyn ExtractIo,
        all: bool,
    ) -> Result<()> {
        let keep = if all { 0 } else { limits::LZ4_WINDOW as u64 };
        loop {
            let available = self.written.saturating_sub(self.flushed);
            let releasable = available.saturating_sub(keep);
            if releasable == 0 {
                return Ok(());
            }
            let n = releasable.min(limits::IO_CHUNK as u64) as usize;
            let start = self.flushed;
            let mut tmp = [0u8; limits::IO_CHUNK];
            for k in 0..n {
                tmp[k] = self.ring[self.rpos(start + k as u64)];
            }
            sink.emit(&tmp[..n])?;
            io.push(&tmp[..n])?;
            self.flushed += n as u64;
        }
    }

    /// Flush everything remaining (call after the file's declared
    /// size is reached).
    ///
    /// # Errors
    /// Sink errors.
    pub fn finish(&mut self, sink: &mut HashingSink, io: &mut dyn ExtractIo) -> Result<()> {
        self.flush_aged(sink, io, true)
    }
}

impl Default for Lz4Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract one file (manifest entry `idx` of the ALREADY-PARSED
/// header `hdr`) from the reader position into `io`.
///
/// The caller must have called [`read_header`] / [`open_header_stream`]
/// on the same stream first: extraction continues exactly after the
/// signature.
///
/// # Errors
/// [`ErrorKind::InvalidFormat`] on framing/truncation,
/// [`ErrorKind::Bomb`] on guard trips, [`ErrorKind::HashMismatch`]
/// when the extracted digest differs from the signed manifest
/// entry, and all sink errors.
pub fn extract_file(
    hdr: &PackageHeader,
    idx: usize,
    ib: &mut InBuf,
    io: &mut dyn ExtractIo,
) -> Result<()> {
    if idx >= hdr.manifest.files_len as usize {
        return Err(Error::new(
            ErrorKind::InvalidFormat,
            "file index out of range",
        ));
    }
    let entry = &hdr.manifest.files[idx];
    let mut sink = HashingSink::new(entry.size);
    let mode = *ib
        .take(io, 1)
        .map_err(|_| Error::new(ErrorKind::InvalidFormat, "mode byte truncated"))?
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "empty mode"))?;
    match mode {
        0 => {
            // store: raw bytes until the declared size
            let mut left = entry.size;
            while left > 0 {
                let want = left.min(limits::IO_CHUNK as u64) as usize;
                let chunk = ib.take(io, want)?;
                sink.note_input(chunk.len() as u64);
                sink.emit(chunk)?;
                io.push(chunk)?;
                left -= want as u64;
            }
        }
        1 => {
            let mut dec = Lz4Decoder::new();
            let mut out_total = 0u64;
            while out_total < entry.size {
                let bh = ib.take(io, 4)?;
                let comp_len = u16::from(bh[0]) | (u16::from(bh[1]) << 8);
                let raw_len = u16::from(bh[2]) | (u16::from(bh[3]) << 8);
                if raw_len == 0 || raw_len as usize > limits::LZ4_BLOCK {
                    return Err(Error::new(
                        ErrorKind::InvalidFormat,
                        "raw length out of band",
                    ));
                }
                if comp_len == 0 || comp_len as usize > limits::LZ4_BLOCK + 16 {
                    return Err(Error::new(
                        ErrorKind::InvalidFormat,
                        "comp length out of band",
                    ));
                }
                if out_total
                    .checked_add(raw_len as u64)
                    .ok_or_else(|| Error::new(ErrorKind::Bomb, "size arithmetic overflow"))?
                    > entry.size
                {
                    return Err(Error::new(ErrorKind::Bomb, "blocks exceed declared size"));
                }
                let mut comp = [0u8; limits::LZ4_BLOCK + 16];
                ib.read_exact(io, &mut comp[..comp_len as usize])?;
                dec.decode_block(&comp[..comp_len as usize], &mut sink, io)?;
                out_total += raw_len as u64;
            }
            dec.finish(&mut sink, io)?;
        }
        _ => {
            return Err(Error::new(ErrorKind::InvalidFormat, "unknown payload mode"));
        }
    }
    let digest = sink.finish()?;
    if !ct_eq(&digest, &entry.sha256) {
        return Err(Error::with(ErrorKind::HashMismatch, entry.path.as_bytes())
            .context("extracted file hash mismatch"));
    }
    Ok(())
}

/// Byte buffer shared by the (test/builder) package writer below.
pub type PkgBuf = [u8; 512 * 1024];

/// Build a store-mode package in memory (repo builder + tests).
/// `contents` must be in manifest order.
///
/// Only available when signing is compiled in (tests / the
/// `signer` feature): deployed managers verify, they never create.
///
/// # Errors
/// [`ErrorKind::TooLarge`] when the buffer overflows;
/// [`ErrorKind::InvalidFormat`] on count/size mismatches.
#[cfg(any(test, feature = "signer"))]
pub fn build_package(
    manifest: &Manifest,
    contents: &[&[u8]],
    key: &ed25519::SecretKey,
    out: &mut PkgBuf,
) -> Result<usize> {
    use crate::{wr_bytes, wr_u32};
    if contents.len() != manifest.files_len as usize {
        return Err(Error::new(
            ErrorKind::InvalidFormat,
            "contents count mismatch",
        ));
    }
    let mut mbuf = [0u8; limits::MAX_MANIFEST];
    let mlen = manifest.serialize(&mut mbuf)?;
    let mut msg = [0u8; 8 + limits::MAX_MANIFEST];
    msg[..4].copy_from_slice(b"AKP1");
    msg[4..8].copy_from_slice(&(mlen as u32).to_le_bytes());
    msg[8..8 + mlen].copy_from_slice(&mbuf[..mlen]);
    let sig = ed25519::sign(key, &msg[..8 + mlen]);
    let mut pos = 0usize;
    wr_bytes(out, &mut pos, b"AKP1")?;
    wr_u32(out, &mut pos, mlen as u32)?;
    wr_bytes(out, &mut pos, &mbuf[..mlen])?;
    wr_bytes(out, &mut pos, &sig)?;
    for (i, data) in contents.iter().enumerate() {
        let entry = &manifest.files[i];
        if data.len() as u64 != entry.size {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "size mismatch vs manifest",
            ));
        }
        wr_bytes(out, &mut pos, &[0])?;
        for chunk in data.chunks(limits::IO_CHUNK) {
            wr_bytes(out, &mut pos, chunk)?;
        }
    }
    Ok(pos)
}

/// Build an LZ4-mode file payload for one entry (tests: exercises
/// the ring decoder with a literals + overlapping-match block).
///
/// The single block encodes `seed` literals followed by one
/// overlapping match (`offset 1`, `len 20`) — the output is the
/// seed then 20 repetitions of its last byte.
///
/// # Errors
/// [`ErrorKind::TooLarge`] on buffer overflow.
#[cfg(any(test, feature = "signer"))]
pub fn build_lz4_payload(seed: &[u8], out: &mut [u8]) -> Result<usize> {
    use crate::wr_bytes;
    let mut pos = 0usize;
    // literal length token: the high nibble carries the literal
    // count when < 15, else 15 plus extension bytes; the low nibble
    // carries (match_len - 4) when < 15, else 15 plus extension
    // bytes. Our match is 20 bytes: 15 + one extension byte (5).
    let lit = seed.len().min(15);
    let mut comp = [0u8; limits::LZ4_BLOCK + 32];
    let mut cpos = 0usize;
    comp[cpos] = ((lit as u8) << 4) | 0x0F;
    cpos += 1;
    if seed.len() >= 15 {
        let mut rem = seed.len() - 15;
        while rem >= 255 {
            comp[cpos] = 255;
            cpos += 1;
            rem -= 255;
        }
        comp[cpos] = rem as u8;
        cpos += 1;
    }
    wr_bytes(&mut comp, &mut cpos, seed)?;
    // match: offset 1, extension 16 → mlen = 4 + 15 + ... wait:
    // mlen = (token&0xF) + 4 + extension; token low nibble is 15 so
    // mlen = 19 + ext; ext 1 gives the intended 20
    wr_bytes(&mut comp, &mut cpos, &[1u8, 0, 1])?;
    let comp_len = cpos;
    wr_bytes(out, &mut pos, &[1])?; // mode = lz4
    let mut bh = [0u8; 4];
    bh[0] = comp_len as u8;
    bh[1] = (comp_len >> 8) as u8;
    bh[2] = (seed.len() + 20) as u8;
    bh[3] = ((seed.len() + 20) >> 8) as u8;
    wr_bytes(out, &mut pos, &bh)?;
    wr_bytes(out, &mut pos, &comp[..comp_len])?;
    Ok(pos)
}
