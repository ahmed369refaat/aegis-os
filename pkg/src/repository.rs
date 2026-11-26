//! Repositories: the signed index (AKI1), the trust-anchor store,
//! local-directory and broker-mediated remote implementations.
//!
//! ## The index format
//!
//! ```text
//! "AKI1"  u16 ver(=1)  u8 slug_len  slug  u64 epoch  u32 count
//! per entry: u8 nlen | name | 3×u32 version | u8 pre_len | pre |
//!            32B sha256 | u64 size
//! [64B repo signature  over everything above]
//! [64B root signature  over everything above, including the repo
//!                      signature — present when the repo is
//!                      chain-anchored]
//! ```
//!
//! ## The trust model (explicit)
//!
//! * **Root anchors** (Ed25519 public keys) live in `/pkg/trust`,
//!   admin-managed; the compiled-in set is empty by default so no
//!   key is silently trusted.
//! * A repository is registered with `pkg repo add <url> <pubkey>`:
//!   that key becomes the repo's verification key, and the record
//!   is marked **admin-pinned**.
//! * Index verification always requires the **repo signature** to
//!   verify under the registered key — a repo cannot swap its key
//!   by shipping a new one in-band; only an explicit, out-of-band
//!   `repo add` changes it.
//! * If the index carries a **root signature**, it must verify under
//!   an anchor: the full chain root → repo → index → packages.
//! * If the index carries no root signature, the repo must be
//!   admin-pinned — deliberate trust-on-first-use, which the CLI
//!   reports loudly. This is the documented residual risk: a
//!   compromised pinned repo key can sign anything the manager will
//!   then install (the per-file hashes still bind content, so the
//!   *installed* bytes are at least the *signed* bytes).
//!
//! ## THREAT: supply-chain compromise
//!
//! * Malicious repo metadata: refused by the signatures above.
//! * Malicious repo key swap: in-band key changes are structurally
//!   impossible (keys live only in the admin-written config).
//! * Malicious maintainer key inside a chain-anchored repo: every
//!   package's SHA-256 is pinned by the signed index; a package
//!   whose hash is not in the (root-signed) index is refused.
//! * Malicious root key: game over by definition — anchors are the
//!   top of the chain; they are never fetched, only provisioned.
//!
//! ## THREAT: signature replay
//!
//! See [`crate::database::RepoEpochs`]: index epochs are monotonic
//! per repository, and same-epoch mutation is refused.

use crate::crypto::ed25519;
use crate::crypto::sha256;
use crate::error::{Error, ErrorKind, Result};
use crate::limits;
use crate::manifest::{validate_name, validate_name_part, SemVer};
use crate::{OpenFlags, Path, Reader};

/// One index entry: a package the repository offers.
#[derive(Clone, Copy)]
pub struct IndexEntry {
    /// Namespaced package name (`repo/pkg`).
    pub name: [u8; limits::MAX_NAME],
    /// Name length.
    pub name_len: u8,
    /// The version this entry points at.
    pub version: SemVer,
    /// SHA-256 of the whole `.akp` package file.
    pub sha256: [u8; 32],
    /// Package file size (compressed container size).
    pub size: u64,
}

impl IndexEntry {
    /// The name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// A verified repository index.
#[derive(Clone)]
pub struct RepoIndex {
    /// The repository slug (namespace of its packages).
    pub slug: [u8; limits::MAX_NAME],
    /// Slug length.
    pub slug_len: u8,
    /// The monotonic index epoch.
    pub epoch: u64,
    /// The entries.
    pub entries: [IndexEntry; limits::MAX_REPO_PACKAGES],
    /// Entry count.
    pub count: u32,
    /// SHA-256 of the raw index bytes (anti-replay identity).
    pub digest: [u8; 32],
}

impl RepoIndex {
    /// The slug bytes.
    #[must_use]
    pub fn slug(&self) -> &[u8] {
        &self.slug[..self.slug_len as usize]
    }

    /// Find the entry for `name`.
    #[must_use]
    pub fn find(&self, name: &[u8]) -> Option<&IndexEntry> {
        (0..self.count as usize)
            .map(|i| &self.entries[i])
            .find(|e| e.name() == name)
    }

    /// All versions offered for `name`, in index order.
    #[must_use]
    pub fn versions_of<'s>(&'s self, name: &'s [u8]) -> Entries<'s> {
        Entries {
            idx: self,
            name,
            pos: 0,
        }
    }
}

/// Fixed-capacity iteration helper (no allocator).
pub struct Entries<'a> {
    /// The index.
    pub idx: &'a RepoIndex,
    /// The sought name.
    pub name: &'a [u8],
    /// Cursor.
    pub pos: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = &'a IndexEntry;
    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.idx.count as usize {
            let e = &self.idx.entries[self.pos];
            self.pos += 1;
            if e.name() == self.name {
                return Some(e);
            }
        }
        None
    }
}

/// Parse an index file's bytes and verify both signature layers.
///
/// # Errors
/// [`ErrorKind::InvalidFormat`] / [`ErrorKind::TooLarge`] on
/// framing; [`ErrorKind::MissingTrust`] when no accepted trust
/// chain covers the index; [`ErrorKind::BadSignature`] when a
/// signature layer fails; [`ErrorKind::Unsupported`] on unknown
/// versions; [`ErrorKind::UnknownRepo`] when the index's slug does
/// not match `expect_slug`.
pub fn parse_index(
    bytes: &[u8],
    expect_slug: &[u8],
    repo_key: &ed25519::PublicKey,
    root_anchor: Option<&ed25519::PublicKey>,
    pinned: bool,
) -> Result<RepoIndex> {
    if bytes.len() < 8 || &bytes[..4] != b"AKI1" {
        return Err(Error::new(ErrorKind::InvalidFormat, "bad index magic"));
    }
    let has_root = root_anchor.is_some();
    let need = 8 + 64 + if has_root { 64 } else { 0 };
    if bytes.len() < need {
        return Err(Error::new(ErrorKind::InvalidFormat, "index too short"));
    }
    let split_repo = bytes.len() - 64;
    let split_root = if has_root {
        split_repo - 64
    } else {
        split_repo
    };
    let body_len = split_root;
    let mut r = Reader::new(&bytes[4..body_len]);
    let ver = r
        .u16()
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "index version truncated"))?;
    if ver != 1 {
        return Err(Error::new(ErrorKind::Unsupported, "unknown index version"));
    }
    let slug = r.take_l8();
    if slug != expect_slug {
        return Err(Error::new(ErrorKind::UnknownRepo, "index slug mismatch"));
    }
    let mut slugb = [0u8; limits::MAX_NAME];
    if slug.len() > limits::MAX_NAME {
        return Err(Error::new(ErrorKind::TooLarge, "slug above cap"));
    }
    slugb[..slug.len()].copy_from_slice(slug);
    let epoch = r
        .u64()
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "index epoch truncated"))?;
    let count = r
        .u32()
        .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "index count truncated"))?;
    if count as usize > limits::MAX_REPO_PACKAGES {
        return Err(Error::new(ErrorKind::TooLarge, "index count above cap"));
    }
    let mut entries = [IndexEntry {
        name: [0; limits::MAX_NAME],
        name_len: 0,
        version: SemVer::zero(),
        sha256: [0; 32],
        size: 0,
    }; limits::MAX_REPO_PACKAGES];
    for e in entries.iter_mut().take(count as usize) {
        let name = r.take_l8();
        validate_name(name)?;
        if name.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "entry name above cap"));
        }
        e.name[..name.len()].copy_from_slice(name);
        e.name_len = name.len() as u8;
        let (a, b, c) = match (r.u32(), r.u32(), r.u32()) {
            (Some(x), Some(y), Some(z)) => (x, y, z),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidFormat,
                    "entry version truncated",
                ))
            }
        };
        let pre_len = r.u8().unwrap_or(u8::MAX);
        if pre_len as usize > 16 || pre_len as usize > r.remaining() {
            return Err(Error::new(ErrorKind::InvalidFormat, "entry pre truncated"));
        }
        let pre = r.take(pre_len as usize);
        e.version = SemVer {
            major: a,
            minor: b,
            patch: c,
            pre: [0; 16],
            pre_len: pre.len() as u8,
        };
        e.version.pre[..pre.len()].copy_from_slice(pre);
        e.sha256 = r
            .hash32()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "entry hash truncated"))?;
        e.size = r
            .u64()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "entry size truncated"))?;
        if e.size > limits::MAX_PACKAGE {
            return Err(Error::new(ErrorKind::TooLarge, "package size above cap"));
        }
    }
    if r.remaining() != 0 {
        return Err(Error::new(ErrorKind::InvalidFormat, "trailing index bytes"));
    }
    // repo signature: covers everything before it
    let repo_sig: ed25519::Signature = {
        let mut s = [0u8; 64];
        s.copy_from_slice(
            bytes
                .get(split_root..split_repo)
                .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "repo sig out of range"))?,
        );
        s
    };
    if !ed25519::verify(repo_key, &bytes[..split_root], &repo_sig) {
        return Err(Error::new(
            ErrorKind::BadSignature,
            "index repo signature rejected",
        ));
    }
    if let Some(anchor) = root_anchor {
        let root_sig: ed25519::Signature =
            {
                let mut s = [0u8; 64];
                s.copy_from_slice(bytes.get(split_repo..).ok_or_else(|| {
                    Error::new(ErrorKind::InvalidFormat, "root sig out of range")
                })?);
                s
            };
        if !ed25519::verify(anchor, &bytes[..split_repo], &root_sig) {
            return Err(Error::new(
                ErrorKind::BadSignature,
                "index root signature rejected",
            ));
        }
    } else if !pinned {
        return Err(Error::new(
            ErrorKind::MissingTrust,
            "index has no root signature and the repo is not admin-pinned",
        ));
    }
    Ok(RepoIndex {
        slug: slugb,
        slug_len: slug.len() as u8,
        epoch,
        entries,
        count,
        digest: sha256::digest(bytes),
    })
}

/// A registered repository's config record (`/pkg/repos/<slug>.repo`).
#[derive(Clone)]
pub struct RepoConfig {
    /// The slug.
    pub slug: [u8; limits::MAX_NAME],
    /// Slug length.
    pub slug_len: u8,
    /// Where to fetch from (a path for local repos, a host/path for
    /// broker repos).
    pub url: [u8; 128],
    /// URL length.
    pub url_len: u8,
    /// The repo's Ed25519 verification key.
    pub key: ed25519::PublicKey,
    /// True when the repo was registered without a root anchor
    /// (admin TOFU — reported loudly).
    pub pinned: bool,
    /// True when this is a local directory repo (no network).
    pub local: bool,
}

impl RepoConfig {
    /// The slug bytes.
    #[must_use]
    pub fn slug(&self) -> &[u8] {
        &self.slug[..self.slug_len as usize]
    }
    /// The URL bytes.
    #[must_use]
    pub fn url(&self) -> &[u8] {
        &self.url[..self.url_len as usize]
    }

    /// Serialize into `out`; returns the length.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on overflow.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        use crate::{wr_bytes, wr_u16};
        let mut pos = 0usize;
        wr_bytes(out, &mut pos, b"ARPS")?;
        wr_u16(out, &mut pos, 1)?;
        wr_bytes(out, &mut pos, &[self.slug_len])?;
        wr_bytes(out, &mut pos, self.slug())?;
        wr_bytes(out, &mut pos, &[self.url_len])?;
        wr_bytes(out, &mut pos, self.url())?;
        wr_bytes(out, &mut pos, &self.key)?;
        wr_bytes(
            out,
            &mut pos,
            &[u8::from(self.pinned), u8::from(self.local)],
        )?;
        Ok(pos)
    }

    /// Parse (strict).
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] / [`ErrorKind::TooLarge`]; also
    /// validates the slug charset.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || &bytes[..4] != b"ARPS" {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "bad repo config magic",
            ));
        }
        let mut r = Reader::new(&bytes[4..]);
        let ver = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "config version truncated"))?;
        if ver != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unknown repo config version",
            ));
        }
        let slug = r.take_l8();
        validate_name_part(slug, "slug")?;
        if slug.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "slug above cap"));
        }
        let url = r.take_l8();
        if url.len() > 128 || url.is_empty() {
            return Err(Error::new(ErrorKind::TooLarge, "url out of band"));
        }
        for &c in url {
            if !c.is_ascii_graphic() {
                return Err(Error::new(ErrorKind::InvalidFormat, "control byte in url"));
            }
        }
        let key = r
            .hash32()
            .ok_or_else(|| Error::new(ErrorKind::InvalidFormat, "config key truncated"))?;
        let flags = r.take(2);
        if flags.len() < 2 {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "config flags truncated",
            ));
        }
        if r.remaining() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidFormat,
                "trailing config bytes",
            ));
        }
        let mut s = [0u8; limits::MAX_NAME];
        s[..slug.len()].copy_from_slice(slug);
        let mut u = [0u8; 128];
        u[..url.len()].copy_from_slice(url);
        Ok(RepoConfig {
            slug: s,
            slug_len: slug.len() as u8,
            url: u,
            url_len: url.len() as u8,
            key,
            pinned: flags[0] == 1,
            local: flags[1] == 1,
        })
    }
}

/// The trust-anchor store (`/pkg/trust`): ATST ver count [32B keys].
#[derive(Clone)]
pub struct TrustAnchors {
    /// Anchor keys.
    pub keys: [ed25519::PublicKey; 8],
    /// Count.
    pub count: u8,
}

impl TrustAnchors {
    /// The empty store.
    #[must_use]
    pub fn empty() -> Self {
        TrustAnchors {
            keys: [[0; 32]; 8],
            count: 0,
        }
    }

    /// Load from the trust file (missing = empty).
    ///
    /// # Errors
    /// [`ErrorKind::Corruption`] on malformed content.
    pub fn load(fs: &mut dyn crate::Fs, path: &Path) -> Result<Self> {
        let fd = match fs.open(path, OpenFlags::RDONLY) {
            Ok(fd) => fd,
            Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => {
                return Ok(Self::empty());
            }
            Err(e) => return Err(e),
        };
        let mut buf = [0u8; 4 + 2 + 1 + 8 * 32];
        let mut n = 0usize;
        loop {
            if n == buf.len() {
                let _ = fs.close(fd);
                return Err(Error::new(ErrorKind::Corruption, "trust file too large"));
            }
            let got = fs.read(fd, &mut buf[n..])?;
            if got == 0 {
                break;
            }
            n += got;
        }
        let _ = fs.close(fd);
        if n == 0 {
            return Ok(Self::empty());
        }
        if n < 7 || &buf[..4] != b"ATST" {
            return Err(Error::new(ErrorKind::Corruption, "bad trust magic"));
        }
        // parse ONLY the file's bytes — the fixed buffer's tail is
        // zero padding, not content
        let mut r = Reader::new(&buf[4..n]);
        let ver = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "trust version truncated"))?;
        if ver != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "unknown trust version"));
        }
        let count = r
            .u8()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "trust count truncated"))?;
        if count as usize > 8 {
            return Err(Error::new(ErrorKind::TooLarge, "trust count above cap"));
        }
        let mut t = TrustAnchors {
            keys: [[0; 32]; 8],
            count,
        };
        for slot in t.keys.iter_mut().take(count as usize) {
            *slot = r
                .hash32()
                .ok_or_else(|| Error::new(ErrorKind::Corruption, "trust key truncated"))?;
        }
        if r.remaining() != 0 {
            return Err(Error::new(ErrorKind::Corruption, "trailing trust bytes"));
        }
        Ok(t)
    }

    /// Serialize into `out`; returns the length.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on overflow.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        use crate::{wr_bytes, wr_u16};
        let mut pos = 0usize;
        wr_bytes(out, &mut pos, b"ATST")?;
        wr_u16(out, &mut pos, 1)?;
        wr_bytes(out, &mut pos, &[self.count])?;
        for key in self.keys[..self.count as usize].iter() {
            wr_bytes(out, &mut pos, key)?;
        }
        Ok(pos)
    }

    /// Does `key` match any anchor (constant-time per key)?
    #[must_use]
    pub fn contains(&self, key: &ed25519::PublicKey) -> bool {
        (0..self.count as usize).any(|i| crate::crypto::ct_eq(&self.keys[i], key))
    }
}

/// Broker-mediated network transport (the ONLY way the manager
/// touches the network — see BUILD.md for the domain's syscall
/// mask: the broker's rate-limited arms, never raw sockets).
pub trait NetTransport {
    /// Fetch `path` (an opaque byte string meaningful to the
    /// transport, e.g. `mirror.example/aegis/index.aki`) and stream
    /// the body to `sink`. The transport enforces size caps.
    ///
    /// # Errors
    /// [`ErrorKind::Io`] on transport failure;
    /// [`ErrorKind::TooLarge`] when the body exceeds the cap.
    fn get(&mut self, path: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;
}

/// A local-directory repository: the index at
/// `<root>/index.aki`, packages at `<root>/<name-slash-dots>.akp`.
pub struct LocalRepository {
    root: Path,
}

impl LocalRepository {
    /// Open the repo rooted at `path` (the URL field of the config).
    ///
    /// # Errors
    /// As [`Path::from_bytes`].
    pub fn new(path: &[u8], _slug: &[u8]) -> Result<Self> {
        let mut p = Path::from_bytes(path)?;
        if p.as_bytes().len() > 1 && p.as_bytes()[p.as_bytes().len() - 1] == b'/' {
            let _ = p.pop();
        }
        Ok(LocalRepository { root: p })
    }

    /// The index file path.
    #[must_use]
    pub fn index_path(&self) -> Path {
        let mut p = self.root;
        let _ = p.push(b"index.aki");
        p
    }

    /// The package file path for an entry.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] for malformed names.
    pub fn package_path(&self, name: &[u8]) -> Result<Path> {
        validate_name(name)?;
        let mut fname = [0u8; limits::MAX_NAME + 8];
        let mut n = 0usize;
        for &b in name {
            fname[n] = if b == b'/' { b'.' } else { b };
            n += 1;
        }
        let mut p = self.root;
        p.push(&fname[..n])?;
        p.push_last(b".akp")?;
        Ok(p)
    }
}

impl Path {
    /// Append a trailing suffix to the last component (used for
    /// file extensions).
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on overflow.
    pub fn push_last(&mut self, suffix: &[u8]) -> Result<()> {
        let base = self.len as usize;
        if base + suffix.len() > limits::MAX_PATH {
            return Err(Error::new(ErrorKind::TooLarge, "path exceeds MAX_PATH"));
        }
        self.bytes[base..base + suffix.len()].copy_from_slice(suffix);
        self.len = (base + suffix.len()) as u16;
        Ok(())
    }
}

/// Read a whole (small) file through the Fs into a fixed buffer.
/// Used for indexes and configs, never for package payloads (those
/// stream).
///
/// # Errors
/// Io errors; [`ErrorKind::TooLarge`] when the file exceeds
/// `buf.len()`.
pub fn read_small_file(fs: &mut dyn crate::Fs, path: &Path, buf: &mut [u8]) -> Result<usize> {
    let fd = fs.open(path, OpenFlags::RDONLY)?;
    let mut n = 0usize;
    let res = loop {
        if n == buf.len() {
            break Err(Error::new(ErrorKind::TooLarge, "file exceeds read buffer"));
        }
        let got = match fs.read(fd, &mut buf[n..]) {
            Ok(g) => g,
            Err(e) => {
                let _ = fs.close(fd);
                return Err(e);
            }
        };
        if got == 0 {
            break Ok(());
        }
        n += got;
    };
    let _ = fs.close(fd);
    res.map(|_| n)
}

/// A broker-mediated remote repository: fetches the index and
/// packages through a [`NetTransport`] into the cache directory.
pub struct BrokerRepository<'a> {
    transport: &'a mut dyn NetTransport,
    cache_dir: Path,
    url: [u8; 128],
    url_len: u8,
}

impl<'a> BrokerRepository<'a> {
    /// Wrap a transport; packages land in `cache_dir`.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on oversized slug/url.
    pub fn new(
        transport: &'a mut dyn NetTransport,
        cache_dir: &Path,
        slug: &[u8],
        url: &[u8],
    ) -> Result<Self> {
        if slug.len() > limits::MAX_NAME || url.len() > 128 || url.is_empty() {
            return Err(Error::new(ErrorKind::TooLarge, "slug/url above cap"));
        }
        let mut u = [0u8; 128];
        u[..url.len()].copy_from_slice(url);
        Ok(BrokerRepository {
            transport,
            cache_dir: *cache_dir,
            url: u,
            url_len: url.len() as u8,
        })
    }

    /// Fetch a remote object, streaming to `sink` as well (so the
    /// index can be verified without a second fetch). Returns the
    /// total size.
    ///
    /// # Errors
    /// Transport errors; [`ErrorKind::TooLarge`] when the object
    /// exceeds [`limits::MAX_PACKAGE`].
    fn fetch_object(
        &mut self,
        name: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        let mut full = [0u8; 160];
        // url + "/" + name
        let url = &self.url[..self.url_len as usize];
        if url.len() + 1 + name.len() > full.len() {
            return Err(Error::new(ErrorKind::TooLarge, "object path too long"));
        }
        full[..url.len()].copy_from_slice(url);
        full[url.len()] = b'/';
        full[url.len() + 1..url.len() + 1 + name.len()].copy_from_slice(name);
        let n = url.len() + 1 + name.len();
        let mut total = 0u64;
        self.transport
            .get(&full[..n], &mut |chunk: &[u8]| -> Result<()> {
                total = total
                    .checked_add(chunk.len() as u64)
                    .filter(|&t| t <= limits::MAX_PACKAGE)
                    .ok_or_else(|| Error::new(ErrorKind::TooLarge, "object exceeds cap"))?;
                sink(chunk)
            })?;
        Ok(total)
    }

    /// Fetch the index: streams into `buf` (bounded by
    /// [`limits::MAX_INDEX`]) and returns the length.
    ///
    /// # Errors
    /// As [`Self::fetch_object`] plus buffer overflow.
    pub fn fetch_index(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut n = 0usize;
        let mut sink = |chunk: &[u8]| -> Result<()> {
            if n + chunk.len() > buf.len().min(limits::MAX_INDEX) {
                return Err(Error::new(ErrorKind::TooLarge, "index exceeds cap"));
            }
            buf[n..n + chunk.len()].copy_from_slice(chunk);
            n += chunk.len();
            Ok(())
        };
        self.fetch_object(b"index.aki", &mut sink)?;
        Ok(n)
    }

    /// Fetch a package into the cache; returns the cache path.
    ///
    /// # Errors
    /// As [`Self::fetch_object`] plus cache-write errors.
    pub fn fetch_package(&mut self, fs: &mut dyn crate::Fs, entry: &IndexEntry) -> Result<Path> {
        // cache name: <name-dots>.akp
        let mut fname = [0u8; limits::MAX_NAME + 8];
        let mut n = 0usize;
        for &b in entry.name() {
            fname[n] = if b == b'/' { b'.' } else { b };
            n += 1;
        }
        let mut cache_path = self.cache_dir;
        cache_path.push(&fname[..n])?;
        cache_path.push_last(b".akp")?;
        let fd = fs.open(&cache_path, OpenFlags::WRONLY | OpenFlags::CREATE)?;
        let sink = &mut |chunk: &[u8]| -> Result<()> {
            let mut off = 0;
            while off < chunk.len() {
                {
                    let w = fs.write(fd, &chunk[off..])?;
                    off += w
                }
            }
            Ok(())
        };
        let res = self.fetch_object(entry.name(), sink);
        let sync_res = fs.sync(fd);
        let close_res = fs.close(fd);
        res?;
        sync_res?;
        close_res?;
        Ok(cache_path)
    }
}
