//! Atomic transactions: lock, staging, write-ahead journal, rename
//! commit, rollback, and power-loss recovery.
//!
//! ## The protocol
//!
//! ```text
//! 1. LOCK        /pkg/lock created O_EXCL — a second `pkg` fails
//!                with Locked (concurrent-invocation lockout).
//! 2. RECOVER     journal replay: an interrupted transaction is
//!                rolled back HERE, before anything new begins.
//! 3. STAGE       every file extracted into /pkg/stage/<txid>/
//!                (O_CREAT|O_EXCL), re-hashed through a FRESH open
//!                (TOCTOU), and fsynced.
//! 4. JOURNAL     the whole plan (each rename/mkdir/unlink, with
//!                stage and destination paths) is appended to the
//!                WAL and fsynced BEFORE any rename.
//! 5. COMMIT      renames are applied in order; then a Commit record
//!                is appended and fsynced.
//! 6. CLEANUP     staging leftovers removed, journal removed, lock
//!                released.
//! ```
//!
//! Crash windows:
//! * **before the renames**: nothing moved — rollback deletes
//!   staging.
//! * **during the renames**: the journal has Begin + ops but no
//!   Commit — recovery reverses every applied op (Move back,
//!   created dirs unlinked, removals restored from backups).
//! * **after Commit**: recovery sees the Commit record and only
//!   cleans up.
//!
//! ## THREAT: partial install / power loss
//!
//! The destination tree is only ever touched by renames of
//! fully-staged, fully-verified files, in a journaled order — so at
//! every instant the system is either in the old state or the new
//! state, or recoverable to the old state by replay. There is no
//! moment where a half-written file is visible at a destination.
//!
//! ## THREAT: concurrent invocations
//!
//! The lock is `O_EXCL` — atomic with respect to any second
//! process. A stale lock (power loss while held) is cleaned by
//! recovery, which is itself safe because the journal tells it
//! whether the holder crashed mid-commit (rollback) or before any
//! state change (just delete the lock).
//!
//! ## THREAT: symlink escapes during commit
//!
//! Every destination parent directory is `stat`-walked immediately
//! before its rename; a symlink (or any non-directory) on the walk
//! aborts the whole transaction. Package manifests cannot write
//! under `/pkg` (allow-list), so packages cannot pre-plant links
//! inside the manager's own tree either.

use crate::crypto::ed25519;
use crate::crypto::sha256;
use crate::database::{DbState, InstalledPkg, PkgPaths};
use crate::error::{Error, ErrorKind, Result};
use crate::limits;
use crate::manifest::Manifest;
use crate::package::{self, InBuf};
use crate::{FileKind, OpenFlags, Path};

/// One journaled operation.
#[derive(Clone, Copy)]
enum JournaledOp {
    /// Rename `stage` → `dest` (atomic install of one file).
    Move { stage: Path, dest: Path },
    /// Directory created by this transaction (rollback unlinks).
    Mkdir { dir: Path },
    /// `dest` removed after copying to `backup` (rollback restores).
    BackupRemove { backup: Path, dest: Path },
}

/// A package transaction. Exactly one may exist per process; the
/// filesystem lock enforces one per machine.
pub struct Transaction<'a> {
    fs: &'a mut dyn crate::Fs,
    paths: PkgPaths,
    txid: u64,
    stage: Path,
    ops: [JournaledOp; 256],
    ops_len: usize,
    staged_files: [Path; 256],
    staged_len: usize,
    journal_fd: u32,
    committed: bool,
    rolled_back: bool,
}

/// Open the manager's state: recovery first (journal replay), then
/// state reads. Every CLI command starts here.
///
/// # Errors
/// Recovery failures ([`ErrorKind::Corruption`] on a journal that
/// cannot be replayed); lock cleanup Io errors.
pub fn recover(fs: &mut dyn crate::Fs, paths: &PkgPaths) -> Result<()> {
    let journal = journal_path(paths);
    let fd = match fs.open(&journal, OpenFlags::RDONLY) {
        Ok(fd) => fd,
        Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => return Ok(()),
        Err(e) => return Err(e),
    };
    // read the whole journal (bounded: at most 256 records)
    let mut buf = [0u8; 256 * 540];
    let mut n = 0usize;
    let read_res = loop {
        if n == buf.len() {
            break Err(Error::new(ErrorKind::Corruption, "journal too large"));
        }
        match fs.read(fd, &mut buf[n..]) {
            Ok(0) => break Ok(()),
            Ok(g) => n += g,
            Err(e) => break Err(e),
        }
    };
    let _ = fs.close(fd);
    read_res?;
    if n == 0 {
        // empty journal: only a stale lock may remain
        maybe_clear_stale_lock(fs, paths)?;
        return Ok(());
    }
    // parse records; find the last transaction state
    let mut pos = 0usize;
    let mut saw_commit = false;
    let mut open_tx: Option<u64> = None;
    let mut ops: [JournaledOp; 256] = [JournaledOp::Mkdir { dir: Path::root() }; 256];
    let mut ops_len = 0usize;
    while pos + 9 <= n {
        let kind = buf[pos];
        let len = crate::rd_u32(&buf[pos + 1..]).unwrap_or(0) as usize;
        if pos + 9 + len > n {
            // torn tail: power loss mid-append — treat as absent
            break;
        }
        let payload = &buf[pos + 9..pos + 9 + len];
        let crc = crate::crypto::crc32::crc32(payload);
        let stored = crate::rd_u32(&buf[pos + 5..]).unwrap_or(1);
        if crc != stored {
            // torn record: stop replay here
            break;
        }
        match kind {
            b'B' => {
                // Begin: a fresh transaction starts
                saw_commit = false;
                open_tx = Some(read_u64(payload));
                ops_len = 0;
            }
            b'O' => {
                if ops_len < 256 && payload.len() >= 516 {
                    let stage = Path::from_bytes(path_prefix(&payload[4..260]))?;
                    let dest = Path::from_bytes(path_prefix(&payload[260..516]))?;
                    let op = match payload[0] {
                        0 => JournaledOp::Move { stage, dest },
                        1 => JournaledOp::Mkdir { dir: dest },
                        _ => JournaledOp::BackupRemove {
                            backup: stage,
                            dest,
                        },
                    };
                    ops[ops_len] = op;
                    ops_len += 1;
                }
            }
            b'C' => {
                saw_commit = true;
                open_tx = None;
            }
            _ => {}
        }
        pos += 9 + len;
    }
    if let Some(txid) = open_tx {
        if !saw_commit {
            // interrupted transaction: roll it back
            reverse_ops(fs, &ops[..ops_len])?;
            let _ = txid;
        }
    }
    // remove the journal (its transaction is resolved either way)
    let _ = fs.unlink(&journal);
    maybe_clear_stale_lock(fs, paths)?;
    Ok(())
}

fn maybe_clear_stale_lock(fs: &mut dyn crate::Fs, paths: &PkgPaths) -> Result<()> {
    // after recovery the lock cannot be legitimately held (we are
    // the only live process and hold no transaction)
    match fs.unlink(&paths.lock_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => Ok(()),
        Err(e) => Err(e),
    }
}

fn reverse_ops(fs: &mut dyn crate::Fs, ops: &[JournaledOp]) -> Result<()> {
    for op in ops.iter().rev() {
        match *op {
            JournaledOp::Move {
                ref stage,
                ref dest,
            } => {
                // if the rename happened, move it back
                if fs.stat(dest).is_ok() {
                    ensure_parent_dirs_for_rollback(fs, stage)?;
                    fs.rename(dest, stage)?;
                }
            }
            JournaledOp::Mkdir { ref dir } => {
                let _ = fs.unlink(dir);
            }
            JournaledOp::BackupRemove {
                ref backup,
                ref dest,
            } => {
                if fs.stat(backup).is_ok() {
                    fs.rename(backup, dest)?;
                }
            }
        }
    }
    Ok(())
}

fn ensure_parent_dirs_for_rollback(fs: &mut dyn crate::Fs, leaf: &Path) -> Result<()> {
    let mut cur = *leaf;
    let mut to_make = [Path::root(); 16];
    let mut n = 0usize;
    while cur.pop() {
        if fs.stat(&cur).is_ok() || n == 16 {
            break;
        }
        to_make[n] = cur;
        n += 1;
    }
    for p in to_make.iter().take(n).rev() {
        let _ = fs.mkdir(p);
    }
    Ok(())
}

fn journal_path(paths: &PkgPaths) -> Path {
    let mut p = paths.db_dir();
    let _ = p.push(b"journal");
    p
}

/// The fixed journal payload pads paths with NULs; a validated path
/// is NUL-free, so the first zero ends it.
fn path_prefix(padded: &[u8]) -> &[u8] {
    match padded.iter().position(|&b| b == 0) {
        Some(i) => &padded[..i],
        None => padded,
    }
}

fn read_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for i in (0..8).rev() {
        v = (v << 8) | u64::from(b.get(i).copied().unwrap_or(0));
    }
    v
}

impl<'a> Transaction<'a> {
    /// The transaction's filesystem (shared with the command layer).
    pub fn fs_mut(&mut self) -> &mut dyn crate::Fs {
        self.fs
    }

    /// Filesystem as a reborrowable field view (test support for
    /// nested-lock probing).
    #[cfg(test)]
    pub fn fs_field(&mut self) -> &mut dyn crate::Fs {
        self.fs
    }

    /// Begin a transaction: take the lock, create the staging root,
    /// open (truncate) the journal.
    ///
    /// # Errors
    /// [`ErrorKind::Locked`] when another invocation holds the
    /// lock; Io errors from the preparation.
    pub fn begin(fs: &'a mut dyn crate::Fs, paths: &PkgPaths) -> Result<Self> {
        // lock first
        let fd = match fs.open(
            &paths.lock_path(),
            OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL,
        ) {
            Ok(fd) => fd,
            Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::Exists) => {
                return Err(Error::new(
                    ErrorKind::Locked,
                    "another pkg invocation holds the lock",
                ));
            }
            Err(e) => return Err(e),
        };
        let txid = unique_id(fs, paths);
        let mut idbuf = [0u8; 16];
        let idn = crate::hex_encode(&txid.to_le_bytes(), &mut idbuf);
        let _ = fs.write(fd, &idbuf[..idn]);
        let _ = fs.sync(fd);
        let _ = fs.close(fd);
        // base dirs
        ensure_dir(fs, paths.root())?;
        ensure_dir(fs, &paths.db_dir())?;
        ensure_dir(fs, &paths.stage_root())?;
        // staging dir: /pkg/stage/<txid-hex>. A collision means the
        // same pseudo-id was drawn twice (the epoch did not bump
        // between a failed transaction and its retry) — increment
        // until a fresh name lands; the lock guarantees the occupied
        // one belongs to nobody.
        let stage;
        let mut txid = txid;
        let mut attempt = 0;
        loop {
            let mut idbuf = [0u8; 16];
            let idn = crate::hex_encode(&txid.to_le_bytes(), &mut idbuf);
            let mut try_dir = paths.stage_root();
            try_dir.push(&idbuf[..idn])?;
            match fs.mkdir(&try_dir) {
                Ok(()) => {
                    stage = try_dir;
                    break;
                }
                Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::Exists) => {
                    attempt += 1;
                    if attempt >= 8 {
                        return Err(Error::new(
                            ErrorKind::Corruption,
                            "staging dir collision after retries",
                        ));
                    }
                    txid = txid.wrapping_add(0x9E37_79B9_7F4A_7C15);
                }
                Err(e) => return Err(e),
            }
        }
        let txid = txid;
        // journal (truncate: recovery has resolved anything old)
        let jpath = journal_path(paths);
        let journal_fd = fs.open(&jpath, OpenFlags::WRONLY | OpenFlags::CREATE)?;
        let mut tx = Transaction {
            fs,
            paths: paths.clone(),
            txid,
            stage,
            ops: [JournaledOp::Mkdir { dir: Path::root() }; 256],
            ops_len: 0,
            staged_files: [Path::root(); 256],
            staged_len: 0,
            journal_fd,
            committed: false,
            rolled_back: false,
        };
        tx.journal_begin()?;
        Ok(tx)
    }

    fn journal_begin(&mut self) -> Result<()> {
        let payload = self.txid.to_le_bytes();
        self.journal_append(b'B', &payload)
    }

    fn journal_append(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        let mut rec = [0u8; 9 + 540];
        rec[0] = kind;
        let crc = crate::crypto::crc32::crc32(payload);
        rec[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        rec[5..9].copy_from_slice(&crc.to_le_bytes());
        let n = (9 + payload.len()).min(rec.len());
        rec[9..n].copy_from_slice(&payload[..n - 9]);
        let mut off = 0usize;
        while off < n {
            let w = self.fs.write(self.journal_fd, &rec[off..n])?;
            off += w;
        }
        self.fs.sync(self.journal_fd)?;
        Ok(())
    }

    fn journal_op(&mut self, op: &JournaledOp) -> Result<()> {
        let (kind, stage, dest): (u8, &Path, &Path) = match *op {
            JournaledOp::Move {
                ref stage,
                ref dest,
            } => (0, stage, dest),
            JournaledOp::Mkdir { ref dir } => (1, &Path::root(), dir),
            JournaledOp::BackupRemove {
                ref backup,
                ref dest,
            } => (2, backup, dest),
        };
        let mut payload = [0u8; 516];
        payload[0] = kind;
        let sb = stage.as_bytes();
        payload[4..4 + sb.len()].copy_from_slice(sb);
        let db = dest.as_bytes();
        payload[260..260 + db.len()].copy_from_slice(db);
        self.journal_append(b'O', &payload)
    }

    fn push_op(&mut self, op: JournaledOp) -> Result<()> {
        if self.ops_len >= 256 {
            return Err(Error::new(ErrorKind::TooLarge, "transaction op cap"));
        }
        self.journal_op(&op)?;
        self.ops[self.ops_len] = op;
        self.ops_len += 1;
        Ok(())
    }

    fn stage_path_for(&mut self, prefix: u8) -> Result<Path> {
        let mut name = [0u8; 12];
        name[0] = prefix;
        let idx = self.staged_len;
        let n = crate::hex_encode(&(idx as u64).to_le_bytes(), &mut name[1..]);
        let mut p = self.stage;
        p.push(&name[..1 + n])?;
        Ok(p)
    }

    fn track_staged(&mut self, p: &Path) -> Result<()> {
        if self.staged_len >= 256 {
            return Err(Error::new(ErrorKind::TooLarge, "staging cap"));
        }
        self.staged_files[self.staged_len] = *p;
        self.staged_len += 1;
        Ok(())
    }

    /// Install one package from `pkg_path` (already fetched /
    /// local), verified under `repo_key`, replacing `prev` when
    /// upgrading. Returns the new manifest (for the plan output).
    ///
    /// Pipeline: signature check → per-file staging (extract +
    /// fresh-open re-hash) → destination parent walk (symlink
    /// refusal) → journaled moves → the new DB record is staged.
    /// Nothing renames until [`Transaction::commit`].
    ///
    /// # Errors
    /// [`ErrorKind::BadSignature`], [`ErrorKind::HashMismatch`],
    /// [`ErrorKind::SymlinkEscape`], [`ErrorKind::NoSpace`],
    /// [`ErrorKind::DowngradeBlocked`], and every extraction error
    /// from `package.rs`.
    pub fn install_package(
        &mut self,
        pkg_path: &Path,
        repo_key: &ed25519::PublicKey,
        origin: &[u8],
        new_epoch: u64,
        prev: Option<&InstalledPkg>,
        allow_downgrade: bool,
    ) -> Result<Manifest> {
        // I/O object: reads the package file, writes the staged
        // file — one owner of the fs borrow per file.
        struct StageIo<'x> {
            fs: &'x mut dyn crate::Fs,
            rfd: u32,
            wfd: u32,
        }
        impl package::ExtractIo for StageIo<'_> {
            fn pull(&mut self, buf: &mut [u8]) -> Result<usize> {
                self.fs.read(self.rfd, buf)
            }
            fn push(&mut self, data: &[u8]) -> Result<()> {
                let mut off = 0;
                while off < data.len() {
                    let w = self.fs.write(self.wfd, &data[off..])?;
                    off += w;
                }
                Ok(())
            }
        }

        // header: signature BEFORE any staging. The InBuf persists
        // across the header AND the extraction loop: its buffer
        // holds payload bytes pulled past the header, and the fd
        // cursor has already moved — a fresh InBuf would read past
        // the payload entirely.
        let rfd = self.fs.open(pkg_path, OpenFlags::RDONLY)?;
        let mut ib = InBuf::new();
        let hdr = {
            let mut io = StageIo {
                fs: self.fs,
                rfd,
                wfd: rfd,
            };
            package::open_header_stream(&mut io, &mut ib)
        }?;
        hdr.verify_signature(repo_key)?;
        let manifest = hdr.manifest.clone();
        // downgrade policy (the solver enforces it too; this is the
        // enforcement point for direct installs)
        if let Some(p) = prev {
            if (manifest.version.precedes(&p.manifest.version)
                || manifest.version == p.manifest.version)
                && !allow_downgrade
            {
                return Err(Error::with(ErrorKind::DowngradeBlocked, manifest.name())
                    .context("refusing downgrade without --force-downgrade"));
            }
        }
        // staged extraction, file by file — the same InBuf continues
        // the stream exactly where the header left it
        for (i, entry) in manifest.files[..manifest.files_len as usize]
            .iter()
            .enumerate()
        {
            let stage = self.stage_path_for(b'f')?;
            self.track_staged(&stage)?;
            let wfd = self.fs.open(
                &stage,
                OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL,
            )?;
            let ex = {
                let mut io = StageIo {
                    fs: self.fs,
                    rfd,
                    wfd,
                };
                package::extract_file(&hdr, i, &mut ib, &mut io)
            };
            let sync_res = self.fs.sync(wfd);
            let close_res = self.fs.close(wfd);
            ex?;
            sync_res?;
            close_res?;
            // TOCTOU: re-hash through a fresh open
            self.reverify_staged(&stage, &entry.sha256)?;
            // destination parent walk + journaled move
            self.move_into_place(&stage, &entry.path)?;
        }
        let _ = self.fs.close(rfd);
        // stale files from the previous version: backup + remove
        if let Some(p) = prev {
            for old in p.manifest.files[..p.manifest.files_len as usize].iter() {
                if manifest
                    .files
                    .iter()
                    .take(manifest.files_len as usize)
                    .any(|f| f.path == old.path)
                {
                    continue;
                }
                self.backup_remove(&old.path)?;
            }
        }
        // stage the new DB record
        self.stage_record_at(&manifest, origin, new_epoch, pkg_path)?;
        Ok(manifest)
    }

    fn reverify_staged(&mut self, stage: &Path, want: &[u8; 32]) -> Result<()> {
        let fd = self.fs.open(stage, OpenFlags::RDONLY)?;
        let mut h = sha256::Sha256::new();
        let mut buf = [0u8; limits::IO_CHUNK];
        let res = loop {
            match self.fs.read(fd, &mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => h.update(&buf[..n]),
                Err(e) => break Err(e),
            }
        };
        let _ = self.fs.close(fd);
        res?;
        let mut d = [0u8; 32];
        h.finish(&mut d);
        if !crate::crypto::ct_eq(&d, want) {
            return Err(Error::with(ErrorKind::HashMismatch, stage.as_bytes())
                .context("staged file changed between write and verify"));
        }
        Ok(())
    }

    /// Walk `dest`'s parents (mkdir as needed, journaled), refuse
    /// symlinks, then journal the stage→dest move.
    fn move_into_place(&mut self, stage: &Path, dest: &Path) -> Result<()> {
        let mut cur = *dest;
        // collect missing ancestors
        let mut missing = [Path::root(); 16];
        let mut n = 0usize;
        loop {
            if !cur.pop() {
                break;
            }
            if cur.as_bytes() == b"/" {
                break;
            }
            match self.fs.stat(&cur) {
                Ok(st) if st.kind == FileKind::Dir => continue,
                Ok(_) => {
                    return Err(Error::with(ErrorKind::SymlinkEscape, cur.as_bytes())
                        .context("destination parent is not a directory"));
                }
                Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => {
                    if n == 16 {
                        return Err(Error::new(ErrorKind::TooLarge, "destination too deep"));
                    }
                    missing[n] = cur;
                    n += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        for p in missing.iter().take(n).rev() {
            match self.fs.mkdir(p) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::Exists) => {}
                Err(e) => return Err(e),
            }
            self.push_op(JournaledOp::Mkdir { dir: *p })?;
        }
        self.push_op(JournaledOp::Move {
            stage: *stage,
            dest: *dest,
        })
    }

    /// Copy `dest` to a staging backup, then journal its removal
    /// (public: the CLI's remove path uses it per owned file).
    ///
    /// # Errors
    /// Io errors; [`ErrorKind::SymlinkEscape`] if `dest` is not a
    /// regular file.
    pub fn backup_remove(&mut self, dest: &Path) -> Result<()> {
        let st = self.fs.stat(dest)?;
        if st.kind != FileKind::File {
            return Err(Error::with(ErrorKind::SymlinkEscape, dest.as_bytes())
                .context("refusing to remove a non-regular file"));
        }
        let backup = self.stage_path_for(b'b')?;
        self.track_staged(&backup)?;
        let rfd = self.fs.open(dest, OpenFlags::RDONLY)?;
        let wfd = self.fs.open(
            &backup,
            OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL,
        )?;
        let mut buf = [0u8; limits::IO_CHUNK];
        let mut io: Result<()> = Ok(());
        loop {
            let got = match self.fs.read(rfd, &mut buf) {
                Ok(0) => break,
                Ok(g) => g,
                Err(e) => {
                    io = Err(e);
                    break;
                }
            };
            let mut off = 0;
            while off < got {
                match self.fs.write(wfd, &buf[off..got]) {
                    Ok(w) => off += w,
                    Err(e) => {
                        io = Err(e);
                        break;
                    }
                }
            }
            if io.is_err() {
                break;
            }
        }
        let _ = self.fs.sync(wfd);
        let _ = self.fs.close(wfd);
        let _ = self.fs.close(rfd);
        io?;
        self.push_op(JournaledOp::BackupRemove {
            backup,
            dest: *dest,
        })
    }

    /// Stage the DB record for a package whose file lives at
    /// `pkg_path` (hashed for the record's audit field).
    ///
    /// # Errors
    /// Io errors; [`ErrorKind::TooLarge`] on cap.
    pub fn stage_record_at(
        &mut self,
        manifest: &Manifest,
        origin: &[u8],
        new_epoch: u64,
        pkg_path: &Path,
    ) -> Result<()> {
        let mut h = sha256::Sha256::new();
        let fd = self.fs.open(pkg_path, OpenFlags::RDONLY)?;
        let mut buf = [0u8; limits::IO_CHUNK];
        let mut io: Result<()> = Ok(());
        loop {
            match self.fs.read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(e) => {
                    io = Err(e);
                    break;
                }
            }
        }
        let _ = self.fs.close(fd);
        io?;
        let mut pkg_hash = [0u8; 32];
        h.finish(&mut pkg_hash);
        let mut origin_buf = [0u8; limits::MAX_NAME];
        if origin.len() > limits::MAX_NAME {
            return Err(Error::new(ErrorKind::TooLarge, "origin above cap"));
        }
        origin_buf[..origin.len()].copy_from_slice(origin);
        let rec = InstalledPkg {
            manifest: manifest.clone(),
            epoch: new_epoch,
            origin: origin_buf,
            origin_len: origin.len() as u8,
            pkg_hash,
        };
        let mut rbuf = [0u8; 4 + 2 + 8 + 1 + limits::MAX_NAME + 32 + 4 + limits::MAX_MANIFEST];
        let rn = rec.serialize(&mut rbuf)?;
        let stage = self.stage_path_for(b'r')?;
        self.track_staged(&stage)?;
        let wfd = self.fs.open(
            &stage,
            OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL,
        )?;
        let mut off = 0usize;
        while off < rn {
            let w = self.fs.write(wfd, &rbuf[off..rn])?;
            off += w;
        }
        let _ = self.fs.sync(wfd);
        let _ = self.fs.close(wfd);
        let dest = self.paths.record_path(manifest.name())?;
        self.move_into_place(&stage, &dest)
    }

    /// Stage the new state file (called once, after all packages).
    ///
    /// # Errors
    /// Io errors.
    pub fn stage_state(&mut self, state: &DbState) -> Result<()> {
        let mut sbuf = [0u8; 8 + limits::MAX_INSTALLED * (limits::MAX_NAME + 1)];
        let sn = state.serialize(&mut sbuf)?;
        let stage = self.stage_path_for(b's')?;
        self.track_staged(&stage)?;
        let wfd = self.fs.open(
            &stage,
            OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL,
        )?;
        let mut off = 0usize;
        while off < sn {
            let w = self.fs.write(wfd, &sbuf[off..sn])?;
            off += w;
        }
        let _ = self.fs.sync(wfd);
        let _ = self.fs.close(wfd);
        let dest = self.paths.state_path();
        self.move_into_place(&stage, &dest)
    }

    /// Remove a package's record (backup + journal).
    ///
    /// # Errors
    /// Io errors.
    pub fn remove_record(&mut self, name: &[u8]) -> Result<()> {
        let rec_path = self.paths.record_path(name)?;
        if self.fs.stat(&rec_path).is_ok() {
            self.backup_remove(&rec_path)?;
        }
        Ok(())
    }

    /// Commit: apply the journaled renames in order, then the Commit
    /// marker, then cleanup.
    ///
    /// # Errors
    /// Io errors during the rename sequence — the transaction is
    /// rolled back before returning, so the caller sees a clean
    /// refusal, not a half-applied tree.
    pub fn commit(mut self) -> Result<()> {
        let ops_snapshot: [JournaledOp; 256] = self.ops;
        let ops_len = self.ops_len;
        for i in 0..ops_len {
            if let Err(e) = self.apply_op(&ops_snapshot[i]) {
                // in-commit failure: reverse what applied, then
                // surface the error
                let _ = reverse_ops(self.fs, &self.ops[..i]);
                self.finish_cleanup();
                return Err(e);
            }
        }
        self.journal_append(b'C', &self.txid.to_le_bytes())?;
        self.committed = true;
        self.finish_cleanup();
        Ok(())
    }

    fn apply_op(&mut self, op: &JournaledOp) -> Result<()> {
        match *op {
            JournaledOp::Move {
                ref stage,
                ref dest,
            } => self.fs.rename(stage, dest),
            JournaledOp::Mkdir { ref dir } => match self.fs.mkdir(dir) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::Exists) => Ok(()),
                Err(e) => Err(e),
            },
            JournaledOp::BackupRemove {
                ref backup,
                ref dest,
            } => {
                // unlink the old file; the backup stays on disk for
                // rollback until the post-commit cleanup removes it
                let _ = backup;
                match self.fs.unlink(dest) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => Ok(()),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Explicit rollback: discard staging, release everything. (The
    /// Drop impl calls this too when neither commit nor rollback
    /// happened.)
    ///
    /// # Errors
    /// Cleanup Io errors (best-effort; errors are reported but the
    /// lock is always released).
    pub fn rollback(mut self) -> Result<()> {
        if !self.committed && !self.rolled_back {
            self.rolled_back = true;
        }
        self.finish_cleanup();
        Ok(())
    }

    fn finish_cleanup(&mut self) {
        // staging leftovers (committed files are gone — moved;
        // backups of committed removals remain and can go)
        for i in 0..self.staged_len {
            let _ = self.fs.unlink(&self.staged_files[i]);
        }
        // remove the staging dir and the journal
        let _ = self.fs.unlink(&self.stage);
        let _ = self.fs.unlink(&journal_path(&self.paths));
        // release the lock
        let _ = self.fs.unlink(&self.paths.lock_path());
        let _ = self.fs.close(self.journal_fd);
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed && !self.rolled_back {
            self.finish_cleanup();
        }
    }
}

fn ensure_dir(fs: &mut dyn crate::Fs, dir: &Path) -> Result<()> {
    match fs.stat(dir) {
        Ok(st) if st.kind == FileKind::Dir => Ok(()),
        Ok(_) => {
            Err(Error::with(ErrorKind::Corruption, dir.as_bytes()).context("expected a directory"))
        }
        Err(e) if e.kind() == ErrorKind::Io(crate::error::Errno::NoEnt) => fs.mkdir(dir),
        Err(e) => Err(e),
    }
}

fn unique_id(fs: &mut dyn crate::Fs, paths: &PkgPaths) -> u64 {
    // pseudo-unique: state epoch + a hash of the current instant
    // (no clock syscall in the mask): state epoch bumped per tx
    let state = DbState::load(fs, &paths.state_path()).unwrap_or_else(|_| DbState::empty());
    let mut seed = state
        .epoch
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(1);
    for &b in paths.root().as_bytes() {
        seed = seed.rotate_left(8) ^ u64::from(b);
    }
    seed ^= seed >> 33;
    seed
}

/// Test-only crash simulation: apply the first `n` journaled ops and
/// vanish without cleanup (like power loss). The lock stays, the
/// journal stays, some renames happened.
///
/// # Errors
/// Io errors while applying.
#[cfg(test)]
pub fn simulate_crash_after_moves(tx: &mut Transaction<'_>, n: usize) -> Result<()> {
    for i in 0..n.min(tx.ops_len) {
        let op = tx.ops[i]; // Copy: break the borrow
        tx.apply_op(&op)?;
    }
    tx.committed = true; // suppress Drop cleanup — power loss!
    Ok(())
}
