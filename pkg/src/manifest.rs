//! Package manifest: model, strict binary parsing, and canonical
//! serialization.
//!
//! ## The format (binary, versioned, canonical)
//!
//! The manifest is a **binary** format, not TOML: with no allocator,
//! deterministic *canonical bytes* must be reconstructible from the
//! parsed value (the Ed25519 signature covers those exact bytes, and
//! `serialize(parse(bytes)) == bytes` is *enforced* — non-canonical
//! encodings are rejected, which kills signature malleability and
//! parser-differential attacks in one rule).
//!
//! ```text
//! "AMFT" | u16 ver(=1)
//! u8 name_len | name bytes             (ns/name, validated charset)
//! 3×u32 version | u8 pre_len | pre bytes
//! u8 maint_len | maintainer bytes
//! u16 desc_len | description bytes
//! u8 deps_len | per dep: u8 nlen | name | u8 kind | 3×u32 lo | u8 lo_pre_len | lo pre |
//!                                            3×u32 hi | u8 hi_pre_len | hi pre
//! u8 conflicts_len | per: u8 nlen | name
//! u8 provides_len | per: u8 nlen | name
//! u8 replaces_len | per: u8 nlen | name
//! u16 files_len | per file: u16 plen | path | u16 perm | u64 size | 32B sha256
//! u16 flags (=0)
//! ```
//! All integers little-endian.
//!
//! ## THREAT: malicious manifests
//!
//! * **Huge fields**: every length is `u8`/`u16` and the parser
//!   takes *exactly that many bytes from the remaining input* —
//!   oversized claims cannot allocate or copy out of bounds; the
//!   total manifest is capped at [`crate::limits::MAX_MANIFEST`].
//! * **Integer overflow in size fields**: file sizes are parsed via
//!   checked reads and validated against
//!   [`crate::limits::MAX_FILE_SIZE`]; they are never used as array
//!   indices (extraction streams, it does not preallocate).
//! * **Deeply nested deps**: not possible to *nest* in this format
//!   (deps are a flat list), and the solver caps recursion at
//!   [`crate::limits::MAX_SOLVER_DEPTH`] with cycle detection.
//! * **Dependency confusion**: names are mandatory two-part
//!   `repo/name` namespaces (see [`validate_name`]).
//! * **Typosquat pressure**: each name part is ≥ 2 characters of
//!   ASCII lowercase alnum plus `-._`; the CLI always shows the full
//!   namespaced name so a lookalike must fake the namespace too.

use crate::error::{Error, ErrorKind, Result};
use crate::{limits, rd_u16, wr_bytes, wr_u16, wr_u32, wr_u64, Path, Reader};

/// A semantic version (SemVer 2.0.0 subset).
///
/// Build metadata (`+...`) is **rejected** at parse time: SemVer
/// ignores it for precedence, so two different artifacts could share
/// a version — a supply-chain hazard. Prerelease tags are limited to
/// 16 bytes of the restricted identifier charset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SemVer {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch.
    pub patch: u32,
    /// Prerelease tag bytes (empty = release).
    pub pre: [u8; 16],
    /// Prerelease length.
    pub pre_len: u8,
}

impl SemVer {
    /// The `0.0.0` release.
    #[must_use]
    pub const fn zero() -> Self {
        SemVer {
            major: 0,
            minor: 0,
            patch: 0,
            pre: [0; 16],
            pre_len: 0,
        }
    }

    /// Constructor for a plain release version.
    #[must_use]
    pub const fn release(major: u32, minor: u32, patch: u32) -> Self {
        SemVer {
            major,
            minor,
            patch,
            pre: [0; 16],
            pre_len: 0,
        }
    }

    /// Attach a prerelease tag (validated charset).
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] on bad charset; [`ErrorKind::TooLarge`]
    /// when longer than 16 bytes.
    pub fn with_pre(mut self, pre: &[u8]) -> Result<Self> {
        validate_tag_charset(pre, "prerelease")?;
        if pre.len() > 16 {
            return Err(Error::new(ErrorKind::TooLarge, "prerelease > 16 bytes"));
        }
        self.pre[..pre.len()].copy_from_slice(pre);
        self.pre_len = pre.len() as u8;
        Ok(self)
    }

    /// Parse `major.minor.patch[-pre]` from bytes. Strict: exactly
    /// three numeric components, each ≤ `u32` with no leading zeros
    /// (except a lone `0`).
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] on any deviation — version
    /// strings are security-relevant (downgrade logic compares them),
    /// so loose parsing is refused.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mut parts: [[u8; 12]; 3] = [[0; 12]; 3];
        let mut lens = [0usize; 3];
        let mut idx = 0usize;
        let mut i = 0usize;
        while i < b.len() {
            let c = b[i];
            if c == b'.' {
                idx = idx.checked_add(1).filter(|&x| x < 3).ok_or_else(|| {
                    Error::new(ErrorKind::InvalidFormat, "version has > 3 components")
                })?;
                if lens[idx - 1] == 0 {
                    return Err(Error::new(ErrorKind::InvalidFormat, "empty component"));
                }
                i += 1;
                continue;
            }
            if c == b'-' {
                if idx != 2 || lens[2] == 0 {
                    return Err(Error::new(
                        ErrorKind::InvalidFormat,
                        "prerelease misplacement",
                    ));
                }
                if i + 1 >= b.len() {
                    return Err(Error::new(ErrorKind::InvalidFormat, "empty prerelease"));
                }
                let base = Self::from_parts(parts, lens)?;
                return base.with_pre(&b[i + 1..]);
            }
            if !c.is_ascii_digit() {
                return Err(Error::new(ErrorKind::InvalidFormat, "non-digit in version"));
            }
            if lens[idx] == 0 && c == b'0' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "leading zero in version",
                ));
            }
            if lens[idx] >= 12 {
                return Err(Error::new(
                    ErrorKind::TooLarge,
                    "version component too long",
                ));
            }
            parts[idx][lens[idx]] = c;
            lens[idx] += 1;
            i += 1;
        }
        if idx != 2 || lens[2] == 0 {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "version needs 3 components",
            ));
        }
        Self::from_parts(parts, lens)
    }

    fn from_parts(parts: [[u8; 12]; 3], lens: [usize; 3]) -> Result<Self> {
        let mut nums = [0u32; 3];
        for j in 0..3 {
            if lens[j] == 0 {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "empty version component",
                ));
            }
            let mut v: u32 = 0;
            for &d in &parts[j][..lens[j]] {
                v = v
                    .checked_mul(10)
                    .and_then(|x| x.checked_add(u32::from(d - b'0')))
                    .ok_or_else(|| Error::new(ErrorKind::TooLarge, "version component overflow"))?;
            }
            nums[j] = v;
        }
        Ok(SemVer {
            major: nums[0],
            minor: nums[1],
            patch: nums[2],
            pre: [0; 16],
            pre_len: 0,
        })
    }

    /// SemVer precedence. Release > prerelease; prerelease tags
    /// compare identifier-by-identifier (numeric < alphanumeric).
    #[must_use]
    pub fn precedes(&self, other: &SemVer) -> bool {
        if self.major != other.major {
            return self.major < other.major;
        }
        if self.minor != other.minor {
            return self.minor < other.minor;
        }
        if self.patch != other.patch {
            return self.patch < other.patch;
        }
        let a = self.pre_bytes();
        let b = other.pre_bytes();
        match (a.is_empty(), b.is_empty()) {
            (true, true) => false,
            (true, false) => false,
            (false, true) => true,
            (false, false) => cmp_pre(a, b) == core::cmp::Ordering::Less,
        }
    }

    /// The prerelease bytes.
    #[must_use]
    pub fn pre_bytes(&self) -> &[u8] {
        &self.pre[..self.pre_len as usize]
    }

    /// Render `d.d.d[-pre]` into `out`; returns bytes written.
    #[must_use]
    pub fn write_bytes(&self, out: &mut [u8]) -> usize {
        let mut pos = write_u32_dec(out, self.major);
        if pos + 1 > out.len() {
            return pos;
        }
        out[pos] = b'.';
        pos += 1;
        pos += write_u32_dec(&mut out[pos..], self.minor);
        if pos + 1 > out.len() {
            return pos;
        }
        out[pos] = b'.';
        pos += 1;
        pos += write_u32_dec(&mut out[pos..], self.patch);
        if self.pre_len > 0 && pos < out.len() {
            out[pos] = b'-';
            pos += 1;
            let m = (self.pre_len as usize).min(out.len() - pos);
            out[pos..pos + m].copy_from_slice(&self.pre[..m]);
            pos += m;
        }
        pos
    }
}

impl core::fmt::Debug for SemVer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 40];
        let n = self.write_bytes(&mut buf);
        match core::str::from_utf8(&buf[..n]) {
            Ok(s) => f.write_str(s),
            Err(_) => f.write_str("<bad-utf8>"),
        }
    }
}

fn write_u32_dec(out: &mut [u8], v: u32) -> usize {
    let mut tmp = [0u8; 10];
    let mut n = 0usize;
    let mut x = v;
    loop {
        tmp[n] = b'0' + (x % 10) as u8;
        n += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    let m = n.min(out.len());
    for i in 0..m {
        out[i] = tmp[n - 1 - i];
    }
    m
}

/// Compare prerelease identifier lists per SemVer 2.0.0 §11.4.
fn cmp_pre(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let mut ai = 0usize;
    let mut bi = 0usize;
    loop {
        match (ai < a.len(), bi < b.len()) {
            (false, false) => return Ordering::Equal,
            (false, true) => return Ordering::Less,
            (true, false) => return Ordering::Greater,
            (true, true) => {}
        }
        let a_end = ident_end(a, ai);
        let b_end = ident_end(b, bi);
        let ia = &a[ai..a_end];
        let ib = &b[bi..b_end];
        let ord = match (is_numeric(ia), is_numeric(ib)) {
            (true, true) => cmp_numeric(ia, ib),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => ia.cmp(ib),
        };
        if ord != Ordering::Equal {
            return ord;
        }
        ai = a_end + 1;
        bi = b_end + 1;
    }
}

fn ident_end(s: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < s.len() && s[i] != b'.' {
        i += 1;
    }
    i
}

fn is_numeric(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(u8::is_ascii_digit)
}

fn cmp_numeric(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    // strip leading zeros first (canonical numeric identifiers),
    // then compare by length and lexicographically — no u64 parse,
    // so hostile 40-digit identifiers cannot overflow anything.
    let a = strip_zeros(a);
    let b = strip_zeros(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn strip_zeros(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < s.len() && s[i] == b'0' {
        i += 1;
    }
    &s[i..]
}

/// Constraint kinds. Textual renderings (CLI display only):
/// `=1.2.3`, `>=1.2.3`, `<2.0.0`, `>=1.0.0<2.0.0`, `^1.2.3`, `*`,
/// `>1.2.3`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionReqKind {
    /// Exactly this version.
    Exact,
    /// At least this version.
    Min,
    /// Strictly below this version.
    Max,
    /// `>=lo` and `<hi`.
    Range,
    /// `^lo`: compatible-with per npm-style caret semantics.
    Caret,
    /// Any version (downgrade policy still applies globally).
    Any,
    /// Strictly NEWER than `lo` — the upgrade request. The solver's
    /// prefer-keep rule fires only when the installed version
    /// SATISFIES the request, so `any()` can never move an installed
    /// package: `pkg upgrade` asks for `above(installed)` and the
    /// keep shortcut does not fire (found live in K23 — the upgrade
    /// lane's plan was [keep] forever).
    Above,
}

/// A version request: kind plus one or two boundary versions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VersionReq {
    /// The kind.
    pub kind: VersionReqKind,
    /// Lower/exact boundary (ignored for Any/Max).
    pub lo: SemVer,
    /// Upper boundary (used by Range/Max).
    pub hi: SemVer,
}

impl VersionReq {
    /// The unconstrained request.
    #[must_use]
    pub const fn any() -> Self {
        VersionReq {
            kind: VersionReqKind::Any,
            lo: SemVer::zero(),
            hi: SemVer::zero(),
        }
    }

    /// `=ver`.
    #[must_use]
    pub const fn exact(ver: SemVer) -> Self {
        VersionReq {
            kind: VersionReqKind::Exact,
            lo: ver,
            hi: SemVer::zero(),
        }
    }

    /// `>=ver`.
    #[must_use]
    pub const fn min(ver: SemVer) -> Self {
        VersionReq {
            kind: VersionReqKind::Min,
            lo: ver,
            hi: SemVer::zero(),
        }
    }

    /// `<ver`.
    #[must_use]
    pub const fn max(ver: SemVer) -> Self {
        VersionReq {
            kind: VersionReqKind::Max,
            lo: SemVer::zero(),
            hi: ver,
        }
    }

    /// `>=lo <hi`.
    #[must_use]
    pub const fn range(lo: SemVer, hi: SemVer) -> Self {
        VersionReq {
            kind: VersionReqKind::Range,
            lo,
            hi,
        }
    }

    /// `^ver`.
    #[must_use]
    pub const fn caret(ver: SemVer) -> Self {
        VersionReq {
            kind: VersionReqKind::Caret,
            lo: ver,
            hi: SemVer::zero(),
        }
    }

    /// `>ver` — strictly newer than `ver`. The upgrade request (the
    /// solver keeps an installed version only while it SATISFIES the
    /// request; `above(installed)` therefore forces the candidate
    /// walk, where prefer-latest plus the downgrade policy pick the
    /// newest repo version).
    #[must_use]
    pub const fn above(ver: SemVer) -> Self {
        VersionReq {
            kind: VersionReqKind::Above,
            lo: ver,
            hi: SemVer::zero(),
        }
    }

    /// Does `v` satisfy this request?
    #[must_use]
    pub fn satisfied_by(&self, v: &SemVer) -> bool {
        match self.kind {
            VersionReqKind::Any => true,
            VersionReqKind::Exact => v == &self.lo,
            VersionReqKind::Min => !v.precedes(&self.lo),
            VersionReqKind::Max => v.precedes(&self.hi) && v != &self.hi,
            VersionReqKind::Range => !v.precedes(&self.lo) && v.precedes(&self.hi) && v != &self.hi,
            VersionReqKind::Above => self.lo.precedes(v),
            VersionReqKind::Caret => {
                // v >= lo is required
                if v.precedes(&self.lo) && v != &self.lo {
                    return false;
                }
                if self.lo.major > 0 {
                    v.major == self.lo.major
                } else if self.lo.minor > 0 {
                    v.major == 0 && v.minor == self.lo.minor
                } else {
                    v.major == 0 && v.minor == 0 && v.patch == self.lo.patch
                }
            }
        }
    }

    /// Render for CLI display; returns bytes written.
    #[must_use]
    pub fn write_bytes(&self, out: &mut [u8]) -> usize {
        use VersionReqKind::*;
        let (sym, show_lo, show_hi): (&[u8], bool, bool) = match self.kind {
            Exact => (b"=", true, false),
            Min => (b">=", true, false),
            Max => (b"<", false, true),
            Range => (b">=", true, true),
            Caret => (b"^", true, false),
            Above => (b">", true, false),
            Any => (b"*", false, false),
        };
        let mut pos = 0usize;
        let m = sym.len().min(out.len().saturating_sub(pos));
        out[pos..pos + m].copy_from_slice(&sym[..m]);
        pos += m;
        if show_lo && pos < out.len() {
            pos += self.lo.write_bytes(&mut out[pos..]);
        }
        if show_hi && pos < out.len() {
            if pos < out.len() {
                out[pos] = b'<';
                pos += 1;
            }
            if pos < out.len() {
                pos += self.hi.write_bytes(&mut out[pos..]);
            }
        }
        pos
    }
}

impl core::fmt::Debug for VersionReq {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 48];
        let n = self.write_bytes(&mut buf);
        match core::str::from_utf8(&buf[..n]) {
            Ok(s) => f.write_str(s),
            Err(_) => f.write_str("<bad-utf8>"),
        }
    }
}

/// Validate a manifest/repo name part: 2..=MAX_NAME bytes, ASCII
/// lowercase `a-z 0-9 - . _` only, must start and end with alnum.
///
/// This is the typosquat/namespace discipline: no case tricks, no
/// lookalike Unicode (everything is ASCII), no 1-character names.
///
/// # Errors
/// [`ErrorKind::InvalidFormat`] on any deviation.
pub fn validate_name_part(s: &[u8], what: &str) -> Result<()> {
    if s.len() < 2 || s.len() > limits::MAX_NAME {
        return Err(Error::with(ErrorKind::InvalidFormat, s).context("bad name length"));
    }
    let _ = what;
    for &c in s {
        let ok =
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.' || c == b'_';
        if !ok {
            return Err(Error::new(ErrorKind::InvalidFormat, "bad name charset"));
        }
    }
    let first_ok = s[0].is_ascii_lowercase() || s[0].is_ascii_digit();
    let last_ok = s[s.len() - 1].is_ascii_lowercase() || s[s.len() - 1].is_ascii_digit();
    if !first_ok || !last_ok {
        return Err(Error::new(
            ErrorKind::InvalidFormat,
            "name must start/end alnum",
        ));
    }
    Ok(())
}

/// Validate a full namespaced name: exactly one `/` separating two
/// valid parts (`repo/pkg`). This is the dependency-confusion
/// defense: *bare names do not exist*.
///
/// # Errors
/// [`ErrorKind::InvalidFormat`] when not two-part or a part fails
/// [`validate_name_part`].
pub fn validate_name(s: &[u8]) -> Result<()> {
    let slashes = s.iter().filter(|&&c| c == b'/').count();
    if slashes != 1 {
        return Err(Error::new(
            ErrorKind::InvalidFormat,
            "name must be repo/pkg",
        ));
    }
    let cut = s.iter().position(|&c| c == b'/').unwrap_or(0);
    validate_name_part(&s[..cut], "namespace")?;
    validate_name_part(&s[cut + 1..], "package")?;
    Ok(())
}

fn validate_tag_charset(s: &[u8], what: &str) -> Result<()> {
    for &c in s {
        let ok = c.is_ascii_alphanumeric() || c == b'-' || c == b'.';
        if !ok {
            return Err(Error::with(ErrorKind::InvalidFormat, s).context("bad charset in tag"));
        }
    }
    let _ = what;
    if s.contains(&b'.') && s.split(|&c| c == b'.').any(|p| p.is_empty()) {
        return Err(Error::new(ErrorKind::InvalidFormat, "empty tag identifier"));
    }
    Ok(())
}

/// Validate description/maintainer text: printable ASCII (no
/// control bytes — keeps terminal output safe).
///
/// # Errors
/// [`ErrorKind::InvalidFormat`] on control bytes.
pub fn validate_text(s: &[u8]) -> Result<()> {
    for &c in s {
        if !c.is_ascii() || (c < 0x20 && c != b'\0') || c == 0x7f {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "control byte in text field",
            ));
        }
    }
    Ok(())
}

/// Which relation list [`Manifest::push_relation`] appends to.
#[derive(Clone, Copy)]
pub enum Relation {
    /// Add to `conflicts`.
    Conflict,
    /// Add to `provides`.
    Provide,
    /// Add to `replaces`.
    Replace,
}

/// One installable file declared by the manifest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileEntry {
    /// Destination path (validated absolute, prefix-checked at
    /// solve time against the install allow-list).
    pub path: Path,
    /// Permission bits: 0o000..0o777 only — setuid/setgid/sticky are
    /// refused by [`Manifest::validate`].
    pub perm: u16,
    /// Exact decompressed size in bytes (checked after extraction).
    pub size: u64,
    /// SHA-256 of the file contents.
    pub sha256: [u8; 32],
}

/// One declared dependency.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dependency {
    /// Namespaced target name.
    pub name: [u8; limits::MAX_NAME],
    /// Name length.
    pub name_len: u8,
    /// Version constraint.
    pub req: VersionReq,
}

impl Dependency {
    /// The name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Build a dependency (validates the name).
    ///
    /// # Errors
    /// As [`validate_name`].
    pub fn new(name: &[u8], req: VersionReq) -> Result<Self> {
        validate_name(name)?;
        let mut d = Dependency {
            name: [0; limits::MAX_NAME],
            name_len: 0,
            req,
        };
        d.name[..name.len()].copy_from_slice(name);
        d.name_len = name.len() as u8;
        Ok(d)
    }
}

/// The manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Format version (must be 1).
    pub format_version: u16,
    /// Namespaced name (`repo/pkg`).
    pub name: [u8; limits::MAX_NAME],
    /// Name length.
    pub name_len: u8,
    /// Package version.
    pub version: SemVer,
    /// Maintainer (printable ASCII).
    pub maintainer: [u8; limits::MAX_MAINTAINER],
    /// Maintainer length.
    pub maintainer_len: u8,
    /// Description (printable ASCII).
    pub description: [u8; limits::MAX_DESCRIPTION],
    /// Description length.
    pub description_len: u16,
    /// Declared dependencies.
    pub deps: [Dependency; limits::MAX_DEPS],
    /// Dependency count.
    pub deps_len: u8,
    /// Conflict names (namespaced).
    pub conflicts: [Dependency; limits::MAX_RELATIONS],
    /// Conflict count.
    pub conflicts_len: u8,
    /// Provided aliases (namespaced).
    pub provides: [Dependency; limits::MAX_RELATIONS],
    /// Provides count.
    pub provides_len: u8,
    /// Replaced packages (namespaced) — removed on update.
    pub replaces: [Dependency; limits::MAX_RELATIONS],
    /// Replaces count.
    pub replaces_len: u8,
    /// Files.
    pub files: [FileEntry; limits::MAX_FILES],
    /// File count.
    pub files_len: u16,
    /// Reserved flags (must be 0 — unknown flags are refused, not
    /// ignored: forward-compatibility failures must be loud).
    pub flags: u16,
}

impl Manifest {
    /// A fresh empty manifest for the given name (validated).
    ///
    /// # Errors
    /// As [`validate_name`].
    pub fn new(name: &[u8], version: SemVer) -> Result<Self> {
        validate_name(name)?;
        let mut m = Manifest::empty();
        m.name[..name.len()].copy_from_slice(name);
        m.name_len = name.len() as u8;
        m.version = version;
        Ok(m)
    }

    fn empty() -> Self {
        Manifest {
            format_version: 1,
            name: [0; limits::MAX_NAME],
            name_len: 0,
            version: SemVer::zero(),
            maintainer: [0; limits::MAX_MAINTAINER],
            maintainer_len: 0,
            description: [0; limits::MAX_DESCRIPTION],
            description_len: 0,
            deps: [Dependency {
                name: [0; limits::MAX_NAME],
                name_len: 0,
                req: VersionReq::any(),
            }; limits::MAX_DEPS],
            deps_len: 0,
            conflicts: [Dependency {
                name: [0; limits::MAX_NAME],
                name_len: 0,
                req: VersionReq::any(),
            }; limits::MAX_RELATIONS],
            conflicts_len: 0,
            provides: [Dependency {
                name: [0; limits::MAX_NAME],
                name_len: 0,
                req: VersionReq::any(),
            }; limits::MAX_RELATIONS],
            provides_len: 0,
            replaces: [Dependency {
                name: [0; limits::MAX_NAME],
                name_len: 0,
                req: VersionReq::any(),
            }; limits::MAX_RELATIONS],
            replaces_len: 0,
            files: [FileEntry {
                path: Path::root(),
                perm: 0,
                size: 0,
                sha256: [0; 32],
            }; limits::MAX_FILES],
            files_len: 0,
            flags: 0,
        }
    }

    /// The name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// The maintainer bytes.
    #[must_use]
    pub fn maintainer(&self) -> &[u8] {
        &self.maintainer[..self.maintainer_len as usize]
    }

    /// The description bytes.
    #[must_use]
    pub fn description(&self) -> &[u8] {
        &self.description[..self.description_len as usize]
    }

    /// Append a file entry (capacity-checked).
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] when the file table is full.
    pub fn push_file(&mut self, entry: FileEntry) -> Result<()> {
        if self.files_len as usize >= limits::MAX_FILES {
            return Err(Error::new(ErrorKind::TooLarge, "too many files"));
        }
        self.files[self.files_len as usize] = entry;
        self.files_len += 1;
        Ok(())
    }

    /// Append a dependency (capacity- and name-checked).
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] or as [`validate_name`].
    pub fn push_dep(&mut self, dep: Dependency) -> Result<()> {
        if self.deps_len as usize >= limits::MAX_DEPS {
            return Err(Error::new(ErrorKind::TooLarge, "too many deps"));
        }
        self.deps[self.deps_len as usize] = dep;
        self.deps_len += 1;
        Ok(())
    }

    /// Append a relation entry to one of the relation lists.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] when the list is full, or as
    /// [`validate_name`].
    pub fn push_relation(&mut self, which: Relation, name: &[u8]) -> Result<()> {
        let (list, len): (&mut [Dependency; limits::MAX_RELATIONS], &mut u8) = match which {
            Relation::Conflict => (&mut self.conflicts, &mut self.conflicts_len),
            Relation::Provide => (&mut self.provides, &mut self.provides_len),
            Relation::Replace => (&mut self.replaces, &mut self.replaces_len),
        };
        if *len as usize >= limits::MAX_RELATIONS {
            return Err(Error::new(ErrorKind::TooLarge, "relation table full"));
        }
        let d = Dependency::new(name, VersionReq::any())?;
        list[*len as usize] = d;
        *len += 1;
        Ok(())
    }

    /// Cross-field validation. Enforces everything the parser checks
    /// per-field, plus the structural rules:
    ///
    /// * file paths are unique, prefix-free (no file may be a
    ///   directory-prefix of another), no SUID/SGID/sticky bits;
    /// * file sizes within [`limits::MAX_FILE_SIZE`];
    /// * the package must not write into the manager's own state
    ///   (`/pkg`) or the kernel's device namespace — paths must
    ///   start with an allowed prefix;
    /// * no file may live under a hooks directory (file-only
    ///   policy);
    /// * names in all relation lists and deps are namespaced;
    /// * `flags == 0`.
    ///
    /// # Errors
    /// The first violation found, as [`ErrorKind::PathEscape`] /
    /// [`ErrorKind::TooLarge`] / [`ErrorKind::ScriptRefused`] /
    /// [`ErrorKind::InvalidFormat`].
    pub fn validate(&self) -> Result<()> {
        validate_name(self.name())?;
        validate_text(self.maintainer())?;
        validate_text(self.description())?;
        if self.flags != 0 {
            return Err(Error::new(ErrorKind::Unsupported, "unknown manifest flags"));
        }
        if self.format_version != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unknown manifest version",
            ));
        }
        for d in self.deps[..self.deps_len as usize].iter() {
            validate_name(d.name())?;
        }
        for d in self.conflicts[..self.conflicts_len as usize].iter() {
            validate_name(d.name())?;
        }
        for d in self.provides[..self.provides_len as usize].iter() {
            validate_name(d.name())?;
        }
        for d in self.replaces[..self.replaces_len as usize].iter() {
            validate_name(d.name())?;
        }
        for (i, f) in self.files[..self.files_len as usize].iter().enumerate() {
            let p = f.path.as_bytes();
            if p == b"/" {
                return Err(Error::new(ErrorKind::PathEscape, "file at /"));
            }
            if f.perm & !0o777 != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "setuid/setgid/sticky refused",
                ));
            }
            if f.size > limits::MAX_FILE_SIZE {
                return Err(Error::new(
                    ErrorKind::TooLarge,
                    "file size above policy cap",
                ));
            }
            if !is_allowed_install_path(p) {
                return Err(Error::with(ErrorKind::PathEscape, p)
                    .context("install path outside allow-list"));
            }
            if is_hook_path(p) {
                return Err(Error::new(
                    ErrorKind::ScriptRefused,
                    "hook path in file list",
                ));
            }
            // unique + prefix-free
            for prior in self.files[..i].iter() {
                let q = prior.path.as_bytes();
                let (short, long) = if p.len() <= q.len() { (p, q) } else { (q, p) };
                if long.starts_with(short) {
                    if long.len() == short.len() {
                        return Err(Error::new(ErrorKind::InvalidFormat, "duplicate file path"));
                    }
                    if long[short.len()] == b'/' {
                        return Err(Error::new(
                            ErrorKind::InvalidFormat,
                            "file shadows another as directory",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Canonical serialization into `out`; returns total length.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] when the manifest exceeds `out`.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        let mut pos = 0usize;
        wr_bytes(out, &mut pos, b"AMFT")?;
        wr_u16(out, &mut pos, 1)?;
        // name
        let name = self.name();
        if name.len() > 255 {
            return Err(Error::new(ErrorKind::TooLarge, "name too long"));
        }
        wr_bytes(out, &mut pos, &[name.len() as u8])?;
        wr_bytes(out, &mut pos, name)?;
        // version
        wr_u32(out, &mut pos, self.version.major)?;
        wr_u32(out, &mut pos, self.version.minor)?;
        wr_u32(out, &mut pos, self.version.patch)?;
        wr_bytes(out, &mut pos, &[self.version.pre_len])?;
        wr_bytes(out, &mut pos, self.version.pre_bytes())?;
        // maintainer / description
        let maint = self.maintainer();
        if maint.len() > 255 {
            return Err(Error::new(ErrorKind::TooLarge, "maintainer too long"));
        }
        wr_bytes(out, &mut pos, &[maint.len() as u8])?;
        wr_bytes(out, &mut pos, maint)?;
        let desc = self.description();
        wr_u16(out, &mut pos, desc.len() as u16)?;
        wr_bytes(out, &mut pos, desc)?;
        // deps
        wr_bytes(out, &mut pos, &[self.deps_len])?;
        for i in 0..self.deps_len as usize {
            let d = &self.deps[i];
            let n = d.name();
            wr_bytes(out, &mut pos, &[n.len() as u8])?;
            wr_bytes(out, &mut pos, n)?;
            wr_bytes(out, &mut pos, &[kind_to_u8(d.req.kind)])?;
            self.write_ver(out, &mut pos, &d.req.lo)?;
            self.write_ver(out, &mut pos, &d.req.hi)?;
        }
        // relations
        for (list, len) in [
            (&self.conflicts, self.conflicts_len),
            (&self.provides, self.provides_len),
            (&self.replaces, self.replaces_len),
        ] {
            wr_bytes(out, &mut pos, &[len])?;
            for dep in list[..len as usize].iter() {
                let n = dep.name();
                wr_bytes(out, &mut pos, &[n.len() as u8])?;
                wr_bytes(out, &mut pos, n)?;
            }
        }
        // files
        wr_u16(out, &mut pos, self.files_len)?;
        for f in self.files[..self.files_len as usize].iter() {
            let p = f.path.as_bytes();
            if p.len() > u16::MAX as usize {
                return Err(Error::new(ErrorKind::TooLarge, "file path too long"));
            }
            wr_u16(out, &mut pos, p.len() as u16)?;
            wr_bytes(out, &mut pos, p)?;
            wr_u16(out, &mut pos, f.perm)?;
            wr_u64(out, &mut pos, f.size)?;
            wr_bytes(out, &mut pos, &f.sha256)?;
        }
        wr_u16(out, &mut pos, self.flags)?;
        Ok(pos)
    }

    fn write_ver(&self, out: &mut [u8], pos: &mut usize, v: &SemVer) -> Result<()> {
        wr_u32(out, pos, v.major)?;
        wr_u32(out, pos, v.minor)?;
        wr_u32(out, pos, v.patch)?;
        wr_bytes(out, pos, &[v.pre_len])?;
        wr_bytes(out, pos, v.pre_bytes())?;
        Ok(())
    }

    /// Strict parse of canonical bytes. Enforces: magic, version 1,
    /// *exact consumption* of the input, canonical re-serialization
    /// equality, and [`Manifest::validate`].
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] / [`ErrorKind::Unsupported`] /
    /// [`ErrorKind::TooLarge`] and everything [`validate`] can
    /// raise. Non-canonical encodings are [`InvalidFormat`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > limits::MAX_MANIFEST {
            return Err(Error::new(ErrorKind::TooLarge, "manifest above cap"));
        }
        if bytes.len() < 8 || &bytes[..4] != b"AMFT" {
            return Err(Error::new(ErrorKind::InvalidFormat, "bad manifest magic"));
        }
        let ver = rd_u16(&bytes[4..])
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated manifest version"))?;
        if ver != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unknown manifest version",
            ));
        }
        let mut r = Reader::new(&bytes[6..]);
        let mut m = Manifest::empty();
        m.format_version = ver;
        // name
        let name = r.take_l8();
        if name.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "name above cap"));
        }
        m.name[..name.len()].copy_from_slice(name);
        m.name_len = name.len() as u8;
        // version
        let (major, minor, patch) = match (r.u32(), r.u32(), r.u32()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return Err(Error::new(ErrorKind::InvalidFormat, "truncated version")),
        };
        m.version = SemVer {
            major,
            minor,
            patch,
            pre: [0; 16],
            pre_len: 0,
        };
        let pre_len = r.u8().unwrap_or(u8::MAX);
        if pre_len as usize > r.remaining() || pre_len > 16 {
            return Err(Error::new(ErrorKind::InvalidFormat, "truncated prerelease"));
        }
        let pre = r.take(pre_len as usize);
        m.version.pre[..pre.len()].copy_from_slice(pre);
        m.version.pre_len = pre_len;
        // maintainer / description
        let maint = r.take_l8();
        if maint.len() > limits::MAX_MAINTAINER {
            return Err(Error::new(ErrorKind::TooLarge, "maintainer above cap"));
        }
        m.maintainer[..maint.len()].copy_from_slice(maint);
        m.maintainer_len = maint.len() as u8;
        let desc = r.take_l16();
        if desc.len() > limits::MAX_DESCRIPTION {
            return Err(Error::new(ErrorKind::TooLarge, "description above cap"));
        }
        m.description[..desc.len()].copy_from_slice(desc);
        m.description_len = desc.len() as u16;
        // deps
        let deps_len = r
            .u8()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated deps count"))?;
        if deps_len as usize > limits::MAX_DEPS {
            return Err(Error::new(ErrorKind::TooLarge, "deps above cap"));
        }
        m.deps_len = deps_len;
        for slot in m.deps.iter_mut().take(deps_len as usize) {
            let n = r.take_l8();
            if n.len() > limits::MAX_NAME {
                return Err(Error::new(ErrorKind::TooLarge, "dep name above cap"));
            }
            let kind_raw = r
                .u8()
                .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated dep kind"))?;
            let kind = u8_to_kind(kind_raw)
                .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "unknown dep kind"))?;
            let lo = read_ver(&mut r)?;
            let hi = read_ver(&mut r)?;
            *slot = Dependency {
                name: {
                    let mut nm = [0u8; limits::MAX_NAME];
                    nm[..n.len()].copy_from_slice(n);
                    nm
                },
                name_len: n.len() as u8,
                req: VersionReq { kind, lo, hi },
            };
        }
        // relations
        m.conflicts_len = read_relation_list(&mut r, &mut m.conflicts)?;
        m.provides_len = read_relation_list(&mut r, &mut m.provides)?;
        m.replaces_len = read_relation_list(&mut r, &mut m.replaces)?;
        // files
        let files_len = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated files count"))?;
        if files_len as usize > limits::MAX_FILES {
            return Err(Error::new(ErrorKind::TooLarge, "files above cap"));
        }
        m.files_len = files_len;
        for slot in m.files.iter_mut().take(files_len as usize) {
            let p = r.take_l16();
            let path = Path::from_bytes(p)?;
            let perm = r
                .u16()
                .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated file perm"))?;
            let size = r
                .u64()
                .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated file size"))?;
            let sha256 = r
                .hash32()
                .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated file hash"))?;
            *slot = FileEntry {
                path,
                perm,
                size,
                sha256,
            };
        }
        m.flags = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated flags"))?;
        if r.remaining() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "trailing manifest bytes",
            ));
        }
        // canonical roundtrip: the signature covers exactly these bytes
        let mut scratch = [0u8; limits::MAX_MANIFEST];
        let n = m.serialize(&mut scratch)?;
        if n != bytes.len() || scratch[..n] != *bytes {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "non-canonical manifest encoding",
            ));
        }
        m.validate()?;
        Ok(m)
    }
}

fn read_ver(r: &mut Reader<'_>) -> Result<SemVer> {
    let (a, b, c) = match (r.u32(), r.u32(), r.u32()) {
        (Some(x), Some(y), Some(z)) => (x, y, z),
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "truncated dep version",
            ))
        }
    };
    let pre_len = r
        .u8()
        .filter(|&p| p as usize <= 16)
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "truncated dep pre"))?;
    if pre_len as usize > r.remaining() {
        return Err(Error::new(
            ErrorKind::InvalidFormat,
            "truncated dep pre bytes",
        ));
    }
    let pre = r.take(pre_len as usize);
    let mut v = SemVer {
        major: a,
        minor: b,
        patch: c,
        pre: [0; 16],
        pre_len: 0,
    };
    v.pre[..pre.len()].copy_from_slice(pre);
    v.pre_len = pre_len;
    Ok(v)
}

fn read_relation_list(
    r: &mut Reader<'_>,
    out: &mut [Dependency; limits::MAX_RELATIONS],
) -> Result<u8> {
    let len = r
        .u8()
        .filter(|&l| l as usize <= limits::MAX_RELATIONS)
        .ok_or_else(|| Error::new(ErrorKind::TooLarge, "relations above cap"))?;
    for slot in out.iter_mut().take(len as usize) {
        let n = r.take_l8();
        if n.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "relation name above cap"));
        }
        let mut nm = [0u8; limits::MAX_NAME];
        nm[..n.len()].copy_from_slice(n);
        *slot = Dependency {
            name: nm,
            name_len: n.len() as u8,
            req: VersionReq::any(),
        };
    }
    Ok(len)
}

fn u8_to_kind(k: u8) -> Option<VersionReqKind> {
    use VersionReqKind::*;
    match k {
        0 => Some(Exact),
        1 => Some(Min),
        2 => Some(Max),
        3 => Some(Range),
        4 => Some(Caret),
        5 => Some(Any),
        6 => Some(Above),
        _ => None,
    }
}

fn kind_to_u8(k: VersionReqKind) -> u8 {
    use VersionReqKind::*;
    match k {
        Exact => 0,
        Min => 1,
        Max => 2,
        Range => 3,
        Caret => 4,
        Any => 5,
        Above => 6,
    }
}

/// Allowed install roots. Packages may write userland trees only:
/// never `/pkg` (manager state), never `/dev`/`/kernel`/`/proc`.
/// THREAT: a compromised package cannot reach the manager's lock,
/// journal, DB or trust store through its own file list.
#[must_use]
pub fn is_allowed_install_path(p: &[u8]) -> bool {
    const ALLOWED: [&[u8]; 5] = [b"/bin/", b"/lib/", b"/etc/", b"/usr/", b"/share/"];
    if p == b"/bin" || p == b"/lib" || p == b"/etc" || p == b"/usr" || p == b"/share" {
        return true; // directories for directory-owning packages
    }
    ALLOWED.iter().any(|a| p.starts_with(a))
}

fn is_hook_path(p: &[u8]) -> bool {
    // File-only policy: no executable hooks anywhere in the tree.
    // The manifest has no script field; this belt-and-braces check
    // refuses known hook locations should a future format add any.
    if p.ends_with(b".pkg-hook") {
        return true;
    }
    const HOOKS: &[u8] = b"/pkg/hooks/";
    p.len() >= HOOKS.len() && p.windows(HOOKS.len()).any(|w| w == HOOKS)
}
