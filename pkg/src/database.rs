//! The local package database: per-package records, the state file,
//! and the repository-epoch table (signature-replay defense).
//!
//! ## Layout (under `/pkg`)
//!
//! ```text
//! /pkg/db/<name>.rec        one record per installed package
//!                           (name's "/" → ".")
//! /pkg/db/state             epoch + installed-name list
//! /pkg/db/repos             per-repo last-seen (epoch, index hash)
//! /pkg/lock                 transaction lock (O_EXCL)
//! /pkg/stage/<txid>/        staging root
//! /pkg/cache/<hash>.akp     fetched package cache
//! /pkg/trust                root anchors (compiled-in + admin)
//! /pkg/repos/<slug>.repo    registered repositories
//! ```
//!
//! ## Crash consistency
//!
//! Records and state are only ever *written* through the
//! transaction layer (staged + renamed + journaled — see
//! `transaction.rs`), so a reader either sees the old whole file or
//! the new whole file. Reads are defensive anyway: every field is
//! bounds-checked, and a record that does not re-parse canonically
//! is [`ErrorKind::Corruption`] — loudly, never silently skipped.
//!
//! ## THREAT: symlink races during package DB writes
//!
//! The DB directory tree is created by the manager itself; the
//! transaction walks each parent with `stat` and refuses symlinks
//! before every rename, and package manifests cannot install paths
//! under `/pkg` at all (the install-path allow-list in
//! `manifest.rs`), so no package can pre-plant a symlink or
//! hardlink that the manager will later follow.

use crate::error::{Error, ErrorKind, Result};
use crate::limits;
use crate::manifest::{validate_name, Manifest};
use crate::{OpenFlags, Path, Reader};

/// Where everything lives: one root path, all state derived.
#[derive(Clone)]
pub struct PkgPaths {
    root: Path,
}

impl PkgPaths {
    /// State under `root` (typically `/pkg`).
    ///
    /// # Errors
    /// As [`Path::from_bytes`].
    pub fn new(root: &[u8]) -> Result<Self> {
        Ok(PkgPaths {
            root: Path::from_bytes(root)?,
        })
    }

    /// `/pkg`
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// `/pkg/db`
    #[must_use]
    pub fn db_dir(&self) -> Path {
        self.join(b"db")
    }
    /// `/pkg/db/state`
    #[must_use]
    pub fn state_path(&self) -> Path {
        let mut p = self.db_dir();
        let _ = p.push(b"state");
        p
    }
    /// `/pkg/db/repos`
    #[must_use]
    pub fn repo_epochs_path(&self) -> Path {
        let mut p = self.db_dir();
        let _ = p.push(b"repos");
        p
    }
    /// `/pkg/db/<name>.rec` — the `/` in `repo/pkg` becomes `.`.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] for a non-namespaced name.
    pub fn record_path(&self, name: &[u8]) -> Result<Path> {
        validate_name(name)?;
        let mut fname = [0u8; limits::MAX_NAME + 8];
        let mut n = 0usize;
        for &b in name {
            fname[n] = if b == b'/' { b'.' } else { b };
            n += 1;
        }
        let mut p = self.db_dir();
        p.push(&fname[..n])?;
        Ok(p)
    }
    /// `/pkg/lock`
    #[must_use]
    pub fn lock_path(&self) -> Path {
        self.join(b"lock")
    }
    /// `/pkg/stage`
    #[must_use]
    pub fn stage_root(&self) -> Path {
        self.join(b"stage")
    }
    /// `/pkg/cache`
    #[must_use]
    pub fn cache_dir(&self) -> Path {
        self.join(b"cache")
    }
    /// `/pkg/trust`
    #[must_use]
    pub fn trust_path(&self) -> Path {
        self.join(b"trust")
    }
    /// `/pkg/repos`
    #[must_use]
    pub fn repos_dir(&self) -> Path {
        self.join(b"repos")
    }

    fn join(&self, comp: &[u8]) -> Path {
        let mut p = self.root;
        // components here are compile-time constants: cannot fail
        let _ = p.push(comp);
        p
    }
}

/// One installed package's database record.
#[derive(Clone)]
pub struct InstalledPkg {
    /// The package's manifest (files + hashes are the audit source).
    pub manifest: Manifest,
    /// The DB epoch at which the record was written (monotonic).
    pub epoch: u64,
    /// The repository the package came from (its slug).
    pub origin: [u8; limits::MAX_NAME],
    /// Origin length.
    pub origin_len: u8,
    /// SHA-256 of the package file as fetched (cache identity +
    /// audit trail).
    pub pkg_hash: [u8; 32],
}

impl InstalledPkg {
    /// The origin slug bytes.
    #[must_use]
    pub fn origin(&self) -> &[u8] {
        &self.origin[..self.origin_len as usize]
    }

    /// Serialize into `out`; returns the length.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on overflow.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        use crate::{wr_bytes, wr_u16, wr_u32, wr_u64};
        let mut mbuf = [0u8; limits::MAX_MANIFEST];
        let mlen = self.manifest.serialize(&mut mbuf)?;
        let mut pos = 0usize;
        wr_bytes(out, &mut pos, b"AREC")?;
        wr_u16(out, &mut pos, 1)?;
        wr_u64(out, &mut pos, self.epoch)?;
        wr_bytes(out, &mut pos, &[self.origin_len])?;
        wr_bytes(out, &mut pos, self.origin())?;
        wr_bytes(out, &mut pos, &self.pkg_hash)?;
        wr_u32(out, &mut pos, mlen as u32)?;
        wr_bytes(out, &mut pos, &mbuf[..mlen])?;
        Ok(pos)
    }

    /// Parse a record (strict: exact consumption, canonical manifest).
    ///
    /// # Errors
    /// [`ErrorKind::InvalidFormat`] / [`ErrorKind::Corruption`] /
    /// [`ErrorKind::TooLarge`] and everything `Manifest::parse`
    /// raises.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || &bytes[..4] != b"AREC" {
            return Err(Error::new(ErrorKind::Corruption, "bad record magic"));
        }
        let mut r = Reader::new(&bytes[4..]);
        let ver = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "record version truncated"))?;
        if ver != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "unknown record version"));
        }
        let epoch = r
            .u64()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "record epoch truncated"))?;
        let origin_len = r.u8().unwrap_or(u8::MAX);
        if origin_len as usize > limits::MAX_NAME || origin_len as usize > r.remaining() {
            return Err(Error::new(ErrorKind::Corruption, "origin out of band"));
        }
        let origin = r.take(origin_len as usize);
        let mut obuf = [0u8; limits::MAX_NAME];
        obuf[..origin.len()].copy_from_slice(origin);
        let pkg_hash = r
            .hash32()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "record hash truncated"))?;
        let mlen = r
            .u32()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "record manifest length truncated"))?
            as usize;
        if mlen > limits::MAX_MANIFEST || mlen > r.remaining() {
            return Err(Error::new(
                ErrorKind::Corruption,
                "record manifest out of band",
            ));
        }
        let mbytes = r.take(mlen);
        let manifest = Manifest::parse(mbytes)?;
        if r.remaining() != 0 {
            return Err(Error::new(ErrorKind::Corruption, "trailing record bytes"));
        }
        Ok(InstalledPkg {
            manifest,
            epoch,
            origin: obuf,
            origin_len: origin.len() as u8,
            pkg_hash,
        })
    }
}

/// The state file: global epoch + installed names.
#[derive(Clone)]
pub struct DbState {
    /// Monotonic transaction epoch; bumped on every commit.
    pub epoch: u64,
    /// Installed package names.
    pub names: [[u8; limits::MAX_NAME]; limits::MAX_INSTALLED],
    /// Count of names.
    pub count: u16,
}

impl DbState {
    /// The empty state (epoch 0).
    #[must_use]
    pub fn empty() -> Self {
        DbState {
            epoch: 0,
            names: [[0; limits::MAX_NAME]; limits::MAX_INSTALLED],
            count: 0,
        }
    }

    /// Read the state file; a missing file is the empty state (fresh
    /// system), anything malformed is loud.
    ///
    /// # Errors
    /// [`ErrorKind::Corruption`] on malformed content; Io errors
    /// other than NotFound pass through.
    pub fn load(fs: &mut dyn crate::Fs, path: &Path) -> Result<Self> {
        let fd = match fs.open(path, OpenFlags::RDONLY) {
            Ok(fd) => fd,
            Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => {
                return Ok(Self::empty());
            }
            Err(e) => return Err(e),
        };
        let mut buf = [0u8; 8 + limits::MAX_INSTALLED * (limits::MAX_NAME + 1)];
        let mut n = 0usize;
        loop {
            if n == buf.len() {
                let _ = fs.close(fd);
                return Err(Error::new(ErrorKind::Corruption, "state file too large"));
            }
            let got = fs.read(fd, &mut buf[n..])?;
            if got == 0 {
                break;
            }
            n += got;
        }
        let _ = fs.close(fd);
        Self::parse(&buf[..n])
    }

    /// Parse state bytes (strict).
    ///
    /// # Errors
    /// [`ErrorKind::Corruption`] / [`ErrorKind::TooLarge`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::empty());
        }
        if bytes.len() < 8 || &bytes[..4] != b"ASTT" {
            return Err(Error::new(ErrorKind::Corruption, "bad state magic"));
        }
        let mut r = Reader::new(&bytes[4..]);
        let ver = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "state version truncated"))?;
        if ver != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "unknown state version"));
        }
        let epoch = r
            .u64()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "state epoch truncated"))?;
        let count = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "state count truncated"))?;
        if count as usize > limits::MAX_INSTALLED {
            return Err(Error::new(ErrorKind::TooLarge, "state count above cap"));
        }
        let mut st = DbState {
            epoch,
            names: [[0; limits::MAX_NAME]; limits::MAX_INSTALLED],
            count,
        };
        for slot in st.names.iter_mut().take(count as usize) {
            let name = r.take_l8();
            if name.is_empty() || name.len() > limits::MAX_NAME {
                return Err(Error::new(ErrorKind::Corruption, "state name out of band"));
            }
            slot[..name.len()].copy_from_slice(name);
        }
        if r.remaining() != 0 {
            return Err(Error::new(ErrorKind::Corruption, "trailing state bytes"));
        }
        Ok(st)
    }

    /// Serialize into `out`; returns the length.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on overflow.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        use crate::{wr_bytes, wr_u16, wr_u64};
        let mut pos = 0usize;
        wr_bytes(out, &mut pos, b"ASTT")?;
        wr_u16(out, &mut pos, 1)?;
        wr_u64(out, &mut pos, self.epoch)?;
        wr_u16(out, &mut pos, self.count)?;
        for nb in self.names[..self.count as usize].iter() {
            let end = nb.iter().position(|&b| b == 0).unwrap_or(limits::MAX_NAME);
            wr_bytes(out, &mut pos, &[end as u8])?;
            wr_bytes(out, &mut pos, &nb[..end])?;
        }
        Ok(pos)
    }

    /// Does the state track `name`?
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        (0..self.count as usize).any(|i| name_at(&self.names[i]) == name)
    }
}

fn name_at(buf: &[u8; limits::MAX_NAME]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(limits::MAX_NAME);
    &buf[..end]
}

/// Per-repository replay defense: the last-seen (epoch, index
/// digest) pair. A signed index with a LOWER epoch, or the SAME
/// epoch but different bytes, is refused — an attacker replaying an
/// old (validly signed) index cannot roll the metadata back.
#[derive(Clone)]
pub struct RepoEpochs {
    /// Per-repo slugs.
    pub slugs: [[u8; limits::MAX_NAME]; 16],
    /// Slug lengths.
    pub lens: [u8; 16],
    /// Last-seen epoch per repo.
    pub epochs: [u64; 16],
    /// Last-seen index digest per repo.
    pub digests: [[u8; 32]; 16],
    /// Entry count.
    pub count: u8,
}

impl RepoEpochs {
    /// The empty table.
    #[must_use]
    pub fn empty() -> Self {
        RepoEpochs {
            slugs: [[0; limits::MAX_NAME]; 16],
            lens: [0; 16],
            epochs: [0; 16],
            digests: [[0; 32]; 16],
            count: 0,
        }
    }

    /// Read the table; a missing file is the empty table (no repos
    /// seen yet).
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
        let mut buf = [0u8; 4 + 2 + 1 + 16 * (1 + limits::MAX_NAME + 8 + 32)];
        let mut n = 0usize;
        loop {
            if n == buf.len() {
                let _ = fs.close(fd);
                return Err(Error::new(ErrorKind::Corruption, "repo table too large"));
            }
            let got = fs.read(fd, &mut buf[n..])?;
            if got == 0 {
                break;
            }
            n += got;
        }
        let _ = fs.close(fd);
        Self::parse(&buf[..n])
    }

    /// Parse (strict).
    ///
    /// # Errors
    /// [`ErrorKind::Corruption`] / [`ErrorKind::TooLarge`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::empty());
        }
        if bytes.len() < 7 || &bytes[..4] != b"AREP" {
            return Err(Error::new(ErrorKind::Corruption, "bad repo table magic"));
        }
        let mut r = Reader::new(&bytes[4..]);
        let ver = r
            .u16()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "repo table version truncated"))?;
        if ver != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unknown repo table version",
            ));
        }
        let count = r
            .u8()
            .ok_or_else(|| Error::new(ErrorKind::Corruption, "repo table count truncated"))?;
        if count as usize > 16 {
            return Err(Error::new(ErrorKind::TooLarge, "repo table above cap"));
        }
        let mut t = RepoEpochs {
            slugs: [[0; limits::MAX_NAME]; 16],
            lens: [0; 16],
            epochs: [0; 16],
            digests: [[0; 32]; 16],
            count,
        };
        for i in 0..count as usize {
            let slug = r.take_l8();
            if slug.is_empty() || slug.len() > limits::MAX_NAME {
                return Err(Error::new(ErrorKind::Corruption, "repo slug out of band"));
            }
            t.slugs[i][..slug.len()].copy_from_slice(slug);
            t.lens[i] = slug.len() as u8;
            t.epochs[i] = r
                .u64()
                .ok_or_else(|| Error::new(ErrorKind::Corruption, "repo epoch truncated"))?;
            t.digests[i] = r
                .hash32()
                .ok_or_else(|| Error::new(ErrorKind::Corruption, "repo digest truncated"))?;
        }
        if r.remaining() != 0 {
            return Err(Error::new(
                ErrorKind::Corruption,
                "trailing repo table bytes",
            ));
        }
        Ok(t)
    }

    /// Serialize into `out`; returns the length.
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] on overflow.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        use crate::{wr_bytes, wr_u16, wr_u64};
        let mut pos = 0usize;
        wr_bytes(out, &mut pos, b"AREP")?;
        wr_u16(out, &mut pos, 1)?;
        wr_bytes(out, &mut pos, &[self.count])?;
        for i in 0..self.count as usize {
            let n = self.lens[i] as usize;
            wr_bytes(out, &mut pos, &[n as u8])?;
            wr_bytes(out, &mut pos, &self.slugs[i][..n])?;
            wr_u64(out, &mut pos, self.epochs[i])?;
            wr_bytes(out, &mut pos, &self.digests[i])?;
        }
        Ok(pos)
    }

    /// Look up the last-seen pair for `slug`.
    #[must_use]
    pub fn seen(&self, slug: &[u8]) -> Option<(u64, [u8; 32])> {
        (0..self.count as usize)
            .find(|&i| &self.slugs[i][..self.lens[i] as usize] == slug)
            .map(|i| (self.epochs[i], self.digests[i]))
    }

    /// Record a new pair (upsert; capacity-checked).
    ///
    /// # Errors
    /// [`ErrorKind::TooLarge`] when the table is full.
    pub fn observe(&mut self, slug: &[u8], epoch: u64, digest: [u8; 32]) -> Result<()> {
        if let Some(i) =
            (0..self.count as usize).find(|&i| &self.slugs[i][..self.lens[i] as usize] == slug)
        {
            self.epochs[i] = epoch;
            self.digests[i] = digest;
            return Ok(());
        }
        if self.count as usize >= 16 || slug.is_empty() || slug.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "repo table full"));
        }
        let i = self.count as usize;
        self.slugs[i][..slug.len()].copy_from_slice(slug);
        self.lens[i] = slug.len() as u8;
        self.epochs[i] = epoch;
        self.digests[i] = digest;
        self.count += 1;
        Ok(())
    }

    /// Anti-replay check for a freshly fetched index: the epoch must
    /// be ≥ the last-seen epoch; equal epochs must carry the exact
    /// same digest (a different index at the same epoch is a
    /// rollback attempt or a repo bug — both refused).
    ///
    /// # Errors
    /// [`ErrorKind::Replay`] on regression or same-epoch mutation.
    pub fn check(&self, slug: &[u8], epoch: u64, digest: &[u8; 32]) -> Result<()> {
        match self.seen(slug) {
            None => Ok(()),
            Some((last_epoch, last_digest)) => {
                if epoch < last_epoch {
                    return Err(Error::new(ErrorKind::Replay, "index epoch regression"));
                }
                if epoch == last_epoch && &last_digest != digest {
                    return Err(Error::new(ErrorKind::Replay, "index mutated at same epoch"));
                }
                Ok(())
            }
        }
    }
}

/// Load one installed-package record by name.
///
/// # Errors
/// [`ErrorKind::NotInstalled`] when absent; parse errors as
/// [`InstalledPkg::parse`].
pub fn load_record(fs: &mut dyn crate::Fs, paths: &PkgPaths, name: &[u8]) -> Result<InstalledPkg> {
    let path = paths.record_path(name)?;
    let fd = match fs.open(&path, OpenFlags::RDONLY) {
        Ok(fd) => fd,
        Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => {
            return Err(Error::with(ErrorKind::NotInstalled, name));
        }
        Err(e) => return Err(e),
    };
    let mut buf = [0u8; 4 + 2 + 8 + 1 + limits::MAX_NAME + 32 + 4 + limits::MAX_MANIFEST];
    let mut n = 0usize;
    loop {
        if n == buf.len() {
            let _ = fs.close(fd);
            return Err(Error::new(ErrorKind::Corruption, "record too large"));
        }
        let got = fs.read(fd, &mut buf[n..])?;
        if got == 0 {
            break;
        }
        n += got;
    }
    let _ = fs.close(fd);
    InstalledPkg::parse(&buf[..n])
}
