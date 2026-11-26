//! The package manager's error type.
//!
//! Design constraints that shaped it:
//!
//! * **`no_alloc`**: no `String` in errors. The detail is a
//!   fixed 96-byte buffer, filled by [`Error::with`] and friends —
//!   small enough to be cheap, large enough for a path or a
//!   diagnostic token.
//! * **No panics**: every fallible path returns [`Result`]; the
//!   only `unwrap`s in this crate are in `#[cfg(test)]` code.
//! * **Actionable**: [`ErrorKind`] mirrors the failure taxonomy of
//!   THREAT_MODEL.md, so the CLI can phrase each refusal in terms of
//!   the attack it just stopped ("downgrade blocked", "signature
//!   rejected", "package is a decompression bomb", ...).
//!
//! THREAT: partial installs surface as [`ErrorKind::NoSpace`] /
//! [`ErrorKind::Io`]; the transaction layer treats both as
//! roll-back-now signals (see `transaction.rs` — disk-full is
//! recoverable *by design*, never a half-installed tree).

use core::fmt;

/// The failure taxonomy. Order is roughly "where in the pipeline".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Filesystem I/O failure with an errno-like detail.
    Io(Errno),
    /// Malformed input: bad magic, truncated field, bad charset.
    InvalidFormat,
    /// Well-formed but unsupported (future format version).
    Unsupported,
    /// A length or count exceeded a fixed cap (malicious-size
    /// defense — manifests with huge fields land here, not in an
    /// allocation).
    TooLarge,
    /// Path validation rejected traversal / dot / NUL components.
    PathEscape,
    /// A symlink appeared where a real file or directory was
    /// required (extraction and DB walks).
    SymlinkEscape,
    /// Ed25519 signature invalid, or public key malformed.
    BadSignature,
    /// File hash mismatch after extraction (TOCTOU/tamper).
    HashMismatch,
    /// No trust anchor / repository key accepted the artifact.
    MissingTrust,
    /// Repository index epoch regression or same-epoch content
    /// change — replay or rollback of metadata.
    Replay,
    /// Install would move to a version ≤ the installed one without
    /// the explicit root `--force-downgrade`.
    DowngradeBlocked,
    /// Solver: constraints unsatisfiable.
    ConstraintUnsat,
    /// Solver: dependency cycle detected (chain in the detail).
    Cycle,
    /// Solver: recursion or step budget exhausted (adversarial
    /// graph — bounded by design).
    DepthLimit,
    /// Another package (selected or installed) conflicts.
    Conflicts,
    /// The package lock is held by another invocation.
    Locked,
    /// Named package is not installed.
    NotInstalled,
    /// Named package is already installed at the same or newer
    /// version.
    AlreadyInstalled,
    /// Decompression bomb guard fired (expansion ratio cap).
    Bomb,
    /// A package violates the file-only policy (hook/script path).
    ScriptRefused,
    /// The referenced repository is not configured.
    UnknownRepo,
    /// The current journal/DB state forbids the operation (e.g.
    /// journal replay discovered an unrecoverable inconsistency).
    Corruption,
    /// Invalid command line (bad flags, unknown command).
    CliUsage,
    /// Something not otherwise classified.
    Other,
}

/// Filesystem errno-like codes the [`crate::Fs`] layer reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Errno {
    /// No such file or directory.
    NoEnt,
    /// File exists (O_EXCL, mkdir over existing).
    Exists,
    /// Not a directory.
    NotDir,
    /// Is a directory (write/open misuse).
    IsDir,
    /// Permission denied.
    Access,
    /// No space left on device — triggers rollback.
    NoSpace,
    /// Directory not empty.
    NotEmpty,
    /// Unspecified I/O failure.
    Io,
}

/// A package-manager error: kind plus a bounded detail message.
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    detail: [u8; 96],
    detail_len: u8,
}

impl Error {
    /// New error with a static detail (copied, truncated at 96
    /// bytes — details are diagnostics, never data).
    #[must_use]
    pub fn new(kind: ErrorKind, detail: &str) -> Self {
        let mut e = Error {
            kind,
            detail: [0; 96],
            detail_len: 0,
        };
        e.set_detail(detail.as_bytes());
        e
    }

    /// New error with a byte-slice detail.
    #[must_use]
    pub fn with(kind: ErrorKind, detail: &[u8]) -> Self {
        let mut e = Error {
            kind,
            detail: [0; 96],
            detail_len: 0,
        };
        e.set_detail(detail);
        e
    }

    fn set_detail(&mut self, d: &[u8]) {
        let n = d.len().min(96);
        self.detail[..n].copy_from_slice(&d[..n]);
        self.detail_len = n as u8;
    }

    /// Attach more context: appends `": " + detail` to a copy.
    #[must_use]
    pub fn context(self, detail: &str) -> Self {
        let mut d = [0u8; 96];
        let mut n = self.detail_len as usize;
        d[..n].copy_from_slice(&self.detail[..n]);
        if n < 94 && !detail.is_empty() {
            d[n] = b':';
            d[n + 1] = b' ';
            n += 2;
            let extra = detail.as_bytes();
            let m = extra.len().min(96 - n);
            d[n..n + m].copy_from_slice(&extra[..m]);
            n += m;
        }
        Error {
            kind: self.kind,
            detail: d,
            detail_len: n as u8,
        }
    }

    /// The kind.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The detail bytes.
    #[must_use]
    pub fn detail(&self) -> &[u8] {
        &self.detail[..self.detail_len as usize]
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg: {:?}", self.kind)?;
        if self.detail_len > 0 {
            f.write_str(": ")?;
            // detail is text from our own messages or validated
            // package names; print as lossless bytes.
            for &b in self.detail() {
                if b.is_ascii_graphic() || b == b' ' {
                    write!(f, "{}", b as char)?;
                } else {
                    write!(f, "\\x{:02x}", b)?;
                }
            }
        }
        Ok(())
    }
}

/// The crate-wide result type.
pub type Result<T> = core::result::Result<T, Error>;
