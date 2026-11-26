//! # aegis-pkg — the AegisOS package manager
//!
//! Pure Rust, `no_std`, **no allocator, zero external crates**. Every
//! buffer is fixed-size and declared in [`limits`]; every untrusted
//! length is bounds-checked before it is used; every arithmetic
//! operation that can overflow uses `checked_*`.
//!
//! ## Security architecture (one paragraph, the rest is per-module)
//!
//! Packages are **file-only**: the format has no script field and any
//! package carrying a hook path is rejected (module [`package`]), so
//! there is no code execution at install time beyond the manager
//! itself. Every package is Ed25519-verified over its canonical
//! manifest bytes **before** a single file is staged
//! ([`crypto`], [`package`]), and every extracted file is re-hashed
//! through a *fresh open* after the write (TOCTOU discipline in
//! [`transaction`]). Installs are atomic — staged, journal-planned,
//! committed by renames, recoverable on the next open after power
//! loss ([`transaction`]). The manager talks to the world only
//! through the [`Fs`] trait, whose surface is exactly the
//! least-privilege syscall mask the domain is granted
//! ([`BUILD.md`] in this crate's directory), plus the rate-limited
//! network broker behind [`repository::NetTransport`].
//!
//! ## Single-threaded by design
//!
//! There is no global mutable state and no `static mut` anywhere: all
//! mutable state lives in stack-allocated structs owned by the
//! caller. Concurrency between two `pkg` invocations is handled at
//! the filesystem level with an `O_EXCL` lock file
//! ([`transaction`]), not with threads.

#![cfg_attr(not(test), no_std)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(missing_docs)]

pub mod cli;
pub mod crypto;
pub mod database;
pub mod error;
pub mod manifest;
pub mod package;
pub mod repository;
pub mod solver;
#[cfg(test)]
mod tests;
pub mod transaction;

pub use error::{Error, ErrorKind, Result};
pub use manifest::{Dependency, FileEntry, Manifest, SemVer};

/// Fixed resource limits. A package manager for a research OS must
/// refuse gracefully, not `oom`: every collection below is a
/// fixed-size array with a runtime count, and every count from
/// untrusted input is checked against these before it is stored.
pub mod limits {
    /// Longest package/repository name component set (bytes).
    pub const MAX_NAME: usize = 64;
    /// Longest maintainer field (bytes).
    pub const MAX_MAINTAINER: usize = 64;
    /// Longest description field (bytes).
    pub const MAX_DESCRIPTION: usize = 192;
    /// Longest installable file path (bytes), NUL excluded.
    pub const MAX_PATH: usize = 256;
    /// Longest single path component (bytes).
    pub const MAX_COMPONENT: usize = 64;
    /// Most files one package may install.
    pub const MAX_FILES: usize = 128;
    /// Most dependencies one package may declare.
    pub const MAX_DEPS: usize = 16;
    /// Most conflict/provide/replace entries each.
    pub const MAX_RELATIONS: usize = 8;
    /// Most packages one repository index may list.
    pub const MAX_REPO_PACKAGES: usize = 256;
    /// Most packages the local database may track.
    pub const MAX_INSTALLED: usize = 128;
    /// Solver/plan width: candidates and plan steps per resolution.
    pub const MAX_PACKAGES: usize = 128;
    /// Solver recursion depth cap (also the cycle-diagnostic chain
    /// length). Cycles are *detected*, never recursed into.
    pub const MAX_SOLVER_DEPTH: usize = 48;
    /// Solver total step budget: bounds backtracking against
    /// adversarial dependency graphs (a malicious repository cannot
    /// burn unbounded CPU).
    pub const MAX_SOLVER_STEPS: u32 = 200_000;
    /// Longest canonical manifest the parser will accept.
    pub const MAX_MANIFEST: usize = 4096;
    /// Largest single file a package may install (policy cap; the
    /// decompressor streams, so this is a denial-of-service bound,
    /// not a memory bound).
    pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
    /// Maximum tolerated compression expansion: total decompressed
    /// bytes must not exceed `RATIO_CAP × compressed bytes + BLOCK`.
    /// A payload claiming more is a decompression bomb and refused.
    pub const BOMB_RATIO_CAP: u64 = 100;
    /// Slack added to the ratio cap so tiny stored blocks pass.
    pub const BOMB_RATIO_SLACK: u64 = 4096;
    /// LZ4 history window (bytes) — the ring buffer is sized from
    /// this; matches may reference at most this far back.
    pub const LZ4_WINDOW: usize = 65536;
    /// Raw size of one self-contained LZ4 block in the package
    /// container (blocks are independent; matches may cross blocks
    /// through the ring).
    pub const LZ4_BLOCK: usize = 4096;
    /// Streaming chunk for store-mode payloads and all file I/O.
    pub const IO_CHUNK: usize = 8192;
    /// Largest index/repo metadata file accepted.
    pub const MAX_INDEX: usize = 96 * 1024;
    /// Largest package file accepted before streaming starts (the
    /// header is size-checked; payload is streamed, so this bounds
    /// the *compressed* container only for cache accounting).
    pub const MAX_PACKAGE: u64 = 256 * 1024 * 1024;
}

/// A validated absolute file path, fixed 256-byte storage.
///
/// Validation ([`Path::from_bytes`]) is the *first* line of defense
/// against path traversal: components must be non-empty, at most
/// [`limits::MAX_COMPONENT`] bytes, contain no NUL, no `.` and no
/// `..`, and the whole path must be absolute. Symlink components are
/// rejected separately at use time by [`transaction`] (via `stat`),
/// because that check must happen against the live filesystem.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Path {
    bytes: [u8; limits::MAX_PATH],
    len: u16,
}

impl Path {
    /// The root path `/` — a valid, non-empty path.
    #[must_use]
    pub const fn root() -> Self {
        let mut p = Path {
            bytes: [0; limits::MAX_PATH],
            len: 1,
        };
        p.bytes[0] = b'/';
        p
    }

    /// The empty (invalid) path — only a constructor default.
    fn empty() -> Self {
        Path {
            bytes: [0; limits::MAX_PATH],
            len: 0,
        }
    }

    /// Validate and adopt `p`. Trailing slashes are normalized away
    /// for a single root slash. Rejects: non-absolute, empty
    /// components (double slashes), `.`/`..`, NUL bytes, over-long
    /// paths or components.
    ///
    /// # Errors
    /// [`ErrorKind::PathEscape`] for any traversal-shaped input,
    /// [`ErrorKind::TooLarge`] when a length cap is exceeded,
    /// [`ErrorKind::InvalidFormat`] for NUL or a non-absolute path.
    pub fn from_bytes(p: &[u8]) -> Result<Self> {
        if p.is_empty() || p[0] != b'/' {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "path must be absolute",
            ));
        }
        if p.len() > limits::MAX_PATH {
            return Err(Error::new(ErrorKind::TooLarge, "path exceeds MAX_PATH"));
        }
        let mut i = 0usize;
        let mut comp_start = 0usize;
        while i < p.len() {
            let c = p[i];
            if c == 0 {
                return Err(Error::new(ErrorKind::InvalidFormat, "NUL in path"));
            }
            if c == b'/' {
                let comp = &p[comp_start..i];
                if comp.is_empty() {
                    // Only the leading "/" may be followed by content;
                    // "//" and trailing "/" are rejected as malformed.
                    if i != 0 && i != p.len() - 1 {
                        return Err(Error::new(ErrorKind::InvalidFormat, "empty component"));
                    }
                } else if comp == b"." || comp == b".." {
                    return Err(Error::new(ErrorKind::PathEscape, "dot component in path"));
                } else if comp.len() > limits::MAX_COMPONENT {
                    return Err(Error::new(ErrorKind::TooLarge, "component exceeds cap"));
                }
                comp_start = i + 1;
            }
            i += 1;
        }
        let tail = &p[comp_start..];
        if !tail.is_empty() {
            if tail == b"." || tail == b".." {
                return Err(Error::new(ErrorKind::PathEscape, "dot component in path"));
            }
            if tail.len() > limits::MAX_COMPONENT {
                return Err(Error::new(ErrorKind::TooLarge, "component exceeds cap"));
            }
        }
        // Normalize one trailing slash away ("/bin/" == "/bin"); the
        // root "/" keeps its single slash.
        let mut len = p.len();
        if len > 1 && p[len - 1] == b'/' {
            len -= 1;
        }
        let mut out = Path::empty();
        out.bytes[..len].copy_from_slice(&p[..len]);
        out.len = len as u16;
        Ok(out)
    }

    /// The path bytes as stored (no NUL terminator).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Append one validated component; errors mirror
    /// [`Path::from_bytes`].
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] if the result would exceed
    /// [`limits::MAX_PATH`] or [`limits::MAX_COMPONENT`];
    /// [`ErrorKind::PathEscape`] for `.`/`..`/empty components.
    pub fn push(&mut self, comp: &[u8]) -> Result<()> {
        if comp.is_empty() || comp == b"." || comp == b".." {
            return Err(Error::new(ErrorKind::PathEscape, "bad component"));
        }
        if comp.len() > limits::MAX_COMPONENT {
            return Err(Error::new(ErrorKind::TooLarge, "component exceeds cap"));
        }
        let extra = if self.len == 1 { 0 } else { 1 };
        let need = self.len as usize + extra + comp.len();
        if need > limits::MAX_PATH {
            return Err(Error::new(ErrorKind::TooLarge, "path exceeds MAX_PATH"));
        }
        if extra == 1 {
            self.bytes[self.len as usize] = b'/';
            self.len += 1;
        }
        self.bytes[self.len as usize..need].copy_from_slice(comp);
        self.len = need as u16;
        Ok(())
    }

    /// Remove the last component; returns `false` (and changes
    /// nothing) if called on `/`.
    #[must_use]
    pub fn pop(&mut self) -> bool {
        if self.len <= 1 {
            return false;
        }
        let mut i = self.len as usize;
        while i > 1 && self.bytes[i - 1] != b'/' {
            i -= 1;
        }
        // keep the parent's trailing slash only if it is the root
        if i > 1 {
            i -= 1;
        }
        self.len = i as u16;
        true
    }

    /// The last component, or `b"/"` for the root.
    #[must_use]
    pub fn last_component(&self) -> &[u8] {
        if self.len <= 1 {
            return b"/";
        }
        let s = self.as_bytes();
        let mut i = s.len();
        while i > 1 && s[i - 1] != b'/' {
            i -= 1;
        }
        &s[i..]
    }

    /// Copy into a caller-owned NUL-terminated buffer (for syscall
    /// adapters). Returns the byte length without NUL.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] if `out` is shorter than the path.
    pub fn to_cstr(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < self.len as usize + 1 {
            return Err(Error::new(ErrorKind::TooLarge, "cstr buffer small"));
        }
        out[..self.len as usize].copy_from_slice(self.as_bytes());
        out[self.len as usize] = 0;
        Ok(self.len as usize)
    }

    /// True when `self` equals `base` extended by exactly one more
    /// component (used to detect file/dir shadowing in manifests).
    #[must_use]
    pub fn is_direct_child_of(&self, base: &Path) -> bool {
        if self.len <= base.len {
            return false;
        }
        let s = self.as_bytes();
        let b = base.as_bytes();
        if !s.starts_with(b) {
            return false;
        }
        let tail = &s[b.len()..];
        if b != b"/" {
            if tail.first() != Some(&b'/') {
                return false;
            }
            tail.len() > 1 && !tail[1..].contains(&b'/')
        } else {
            tail.len() > 1 && !tail[1..].contains(&b'/')
        }
    }
}

impl core::fmt::Debug for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Path(")?;
        for &b in self.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        f.write_str(")")?;
        Ok(())
    }
}

/// File kind reported by [`Fs::stat`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link — always refused wherever the manager walks.
    Symlink,
    /// Anything else (device, socket, ...): refused.
    Other,
}

/// Result of [`Fs::stat`].
#[derive(Clone, Copy, Debug)]
pub struct Stat {
    /// Kind of the node.
    pub kind: FileKind,
    /// Size in bytes (0 for non-files).
    pub size: u64,
    /// Permission bits (0o644 style; setuid/gid never expected —
    /// checked by callers).
    pub perm: u16,
}

/// Open flags accepted by [`Fs::open`]. Deliberately minimal: no
/// `O_EXEC`, no `O_NOFOLLOW` (symlink checks are done with `stat`
/// walks — see THREAT_MODEL.md), no async.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Open for reading only.
    pub const RDONLY: OpenFlags = OpenFlags(0);
    /// Open for writing; truncate on open.
    pub const WRONLY: OpenFlags = OpenFlags(1);
    /// Create the file if missing (combined with WRONLY).
    pub const CREATE: OpenFlags = OpenFlags(2);
    /// Fail with [`ErrorKind::Exists`] if the file already exists
    /// (combined with CREATE). This is the lock primitive.
    pub const EXCL: OpenFlags = OpenFlags(4);
    /// Open a directory itself for `getdents`.
    pub const DIRECTORY: OpenFlags = OpenFlags(8);

    /// Bit-set test.
    #[must_use]
    pub fn has(&self, o: OpenFlags) -> bool {
        self.0 & o.0 == o.0
    }
}

impl core::ops::BitOr for OpenFlags {
    type Output = OpenFlags;
    fn bitor(self, rhs: OpenFlags) -> OpenFlags {
        OpenFlags(self.0 | rhs.0)
    }
}

/// The complete filesystem surface the package manager needs.
///
/// This trait **is** the least-privilege claim: the domain's syscall
/// mask admits exactly these operations (plus `exit` and the broker
/// net arms — see BUILD.md). Every implementation must:
///
/// * Treat paths as validated [`Path`] values (no client-side path
///   interpretation happens beyond this trait).
/// * Return an error, never panic, on any failure — including
///   "disk full" as [`ErrorKind::NoSpace`] so the transaction layer
///   can roll back.
/// * Implement `rename` atomically w.r.t. crashes of *this* process
///   (a rename either happened or did not); cross-process power-loss
///   atomicity is what the journal handles.
///
/// `sync` is fsync: the AegisOS adapter notes that the current
/// kernel VFS writes synchronously and implements it as a no-op
/// success; the contract stays so a cached VFS later becomes correct
/// without touching this crate.
pub trait Fs {
    /// Open `path`, returning a handle.
    ///
    /// # Errors
    /// [`ErrorKind::NotFound`], [`ErrorKind::Exists`] (O_EXCL race —
    /// the concurrent-invocation lockout), [`ErrorKind::Access`],
    /// [`ErrorKind::NoSpace`], [`ErrorKind::IsDir`] / [`ErrorKind::NotDir`]
    /// as applicable.
    fn open(&mut self, path: &Path, flags: OpenFlags) -> Result<u32>;
    /// Read up to `buf.len()` bytes; returns bytes read (0 = EOF).
    fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize>;
    /// Write the whole buffer or fail (short writes are retried by
    /// the caller; implementations should loop internally).
    fn write(&mut self, fd: u32, buf: &[u8]) -> Result<usize>;
    /// Close a handle. Idempotent per handle value.
    fn close(&mut self, fd: u32) -> Result<()>;
    /// Flush the file's data to stable storage.
    fn sync(&mut self, fd: u32) -> Result<()>;
    /// Stat a path. A symlink is reported as [`FileKind::Symlink`]
    /// (never followed — the manager refuses symlinks itself).
    fn stat(&mut self, path: &Path) -> Result<Stat>;
    /// Create a directory (not recursive).
    fn mkdir(&mut self, path: &Path) -> Result<()>;
    /// Remove a file (or empty directory).
    fn unlink(&mut self, path: &Path) -> Result<()>;
    /// Atomically rename/move `from` to `to`, replacing `to` if it is
    /// a file (POSIX semantics).
    fn rename(&mut self, from: &Path, to: &Path) -> Result<()>;
    /// Read directory entries of a directory opened with
    /// `DIRECTORY`; returns NUL-separated names in `out`, the number
    /// of bytes written (0 = end).
    fn getdents(&mut self, fd: u32, out: &mut [u8]) -> Result<usize>;
}

/// Read a little-endian u16, returning `None` on truncation.
#[must_use]
pub fn rd_u16(b: &[u8]) -> Option<u16> {
    if b.len() < 2 {
        return None;
    }
    Some(u16::from(b[0]) | (u16::from(b[1]) << 8))
}

/// Read a little-endian u32, returning `None` on truncation.
#[must_use]
pub fn rd_u32(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    Some(
        u32::from(b[0])
            | (u32::from(b[1]) << 8)
            | (u32::from(b[2]) << 16)
            | (u32::from(b[3]) << 24),
    )
}

/// Read a little-endian u64, returning `None` on truncation.
#[must_use]
pub fn rd_u64(b: &[u8]) -> Option<u64> {
    if b.len() < 8 {
        return None;
    }
    let lo = u64::from(rd_u32(b).unwrap_or(0));
    let hi = u64::from(rd_u32(&b[4..]).unwrap_or(0));
    Some(lo | (hi << 32))
}

/// Write a little-endian u16 into `out`, advancing by 2.
///
/// # Errors
/// [`ErrorKind::TooLarge`] when the buffer is exhausted (the fixed
/// serializer's only failure mode).
pub fn wr_u16(out: &mut [u8], pos: &mut usize, v: u16) -> Result<()> {
    if out.len() < *pos + 2 {
        return Err(Error::new(ErrorKind::TooLarge, "serialize overflow"));
    }
    out[*pos] = v as u8;
    out[*pos + 1] = (v >> 8) as u8;
    *pos += 2;
    Ok(())
}

/// Write a little-endian u32 into `out`, advancing by 4. Errors as
/// [`wr_u16`].
pub fn wr_u32(out: &mut [u8], pos: &mut usize, v: u32) -> Result<()> {
    if out.len() < *pos + 4 {
        return Err(Error::new(ErrorKind::TooLarge, "serialize overflow"));
    }
    out[*pos] = v as u8;
    out[*pos + 1] = (v >> 8) as u8;
    out[*pos + 2] = (v >> 16) as u8;
    out[*pos + 3] = (v >> 24) as u8;
    *pos += 4;
    Ok(())
}

/// Write a little-endian u64 into `out`, advancing by 8. Errors as
/// [`wr_u16`].
pub fn wr_u64(out: &mut [u8], pos: &mut usize, v: u64) -> Result<()> {
    if out.len() < *pos + 8 {
        return Err(Error::new(ErrorKind::TooLarge, "serialize overflow"));
    }
    let lo = v as u32;
    let hi = (v >> 32) as u32;
    wr_u32(out, pos, lo)?;
    wr_u32(out, pos, hi)?;
    Ok(())
}

/// Write raw bytes into `out`, advancing. Errors as [`wr_u16`].
pub fn wr_bytes(out: &mut [u8], pos: &mut usize, b: &[u8]) -> Result<()> {
    if out.len() < *pos + b.len() {
        return Err(Error::new(ErrorKind::TooLarge, "serialize overflow"));
    }
    out[*pos..*pos + b.len()].copy_from_slice(b);
    *pos += b.len();
    Ok(())
}

/// A bounded byte-cursor reader for untrusted input. Every read
/// returns `None` past the end — parse code turns that into
/// [`ErrorKind::InvalidFormat`] at the call site, so no panic and no
/// index arithmetic on untrusted lengths.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Adopt `buf` at position 0.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current offset.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Take up to `n` bytes (fewer at the end).
    #[must_use]
    pub fn take(&mut self, n: usize) -> &'a [u8] {
        let end = self.pos.saturating_add(n).min(self.buf.len());
        let s = &self.buf[self.pos..end];
        self.pos = end;
        s
    }

    /// Read a length-prefixed field: `u8 len` then that many bytes.
    #[must_use]
    pub fn take_l8(&mut self) -> &'a [u8] {
        let Some(&n) = self.buf.get(self.pos) else {
            return &[];
        };
        self.pos += 1;
        self.take(n as usize)
    }

    /// Read a `u16 len`-prefixed field.
    #[must_use]
    pub fn take_l16(&mut self) -> &'a [u8] {
        let Some(n) = rd_u16(self.buf.get(self.pos..).unwrap_or(&[])) else {
            return &[];
        };
        self.pos += 2;
        self.take(n as usize)
    }

    /// Read one u16.
    #[must_use]
    pub fn u16(&mut self) -> Option<u16> {
        let v = rd_u16(self.buf.get(self.pos..).unwrap_or(&[]))?;
        self.pos += 2;
        Some(v)
    }

    /// Read one u32.
    #[must_use]
    pub fn u32(&mut self) -> Option<u32> {
        let v = rd_u32(self.buf.get(self.pos..).unwrap_or(&[]))?;
        self.pos += 4;
        Some(v)
    }

    /// Read one u64.
    #[must_use]
    pub fn u64(&mut self) -> Option<u64> {
        let v = rd_u64(self.buf.get(self.pos..).unwrap_or(&[]))?;
        self.pos += 8;
        Some(v)
    }

    /// Read one byte.
    #[must_use]
    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    /// Read 32 raw bytes (a hash).
    #[must_use]
    pub fn hash32(&mut self) -> Option<[u8; 32]> {
        if self.remaining() < 32 {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.buf[self.pos..self.pos + 32]);
        self.pos += 32;
        Some(h)
    }

    /// Read 64 raw bytes (a signature).
    #[must_use]
    pub fn hash64(&mut self) -> Option<[u8; 64]> {
        if self.remaining() < 64 {
            return None;
        }
        let mut h = [0u8; 64];
        h.copy_from_slice(&self.buf[self.pos..self.pos + 64]);
        self.pos += 64;
        Some(h)
    }
}

/// Format a byte slice as lowercase hex into `out` (must be ≥ 2n
/// bytes); returns bytes written. Never fails: callers size buffers.
#[must_use]
pub fn hex_encode(data: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = out.len() / 2;
    let n = n.min(data.len());
    for i in 0..n {
        out[i * 2] = HEX[(data[i] >> 4) as usize];
        out[i * 2 + 1] = HEX[(data[i] & 0xF) as usize];
    }
    n * 2
}
