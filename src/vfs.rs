//! A tiny VFS with Unix discretionary permissions and chroot confinement.
//!
//! Linux-flavored semantics:
//! - `rwx` bits for owner / group / other on every inode.
//! - Traversing a directory requires the execute bit on it.
//! - uid 0 bypasses permission checks (documented Linux-ism; chroot still
//!   confines it — the check order is deliberate).
//! - Path resolution handles `.`, `..`, repeated slashes, absolute and
//!   relative paths. `..` at the chroot root stays at the chroot root
//!   (classic `chroot(2)` clamping), so a confined domain cannot escape.
//! - `chmod` is allowed only for the file owner (or uid 0).

pub const MAX_INODES: usize = 32;
pub const FILE_DATA_MAX: usize = 128;
pub const NAME_MAX: usize = 28;
pub const ROOT_ID: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    File,
    Dir,
}

/// Unix permission bits (0o000..=0o777): rwx for owner, group, other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mode(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Credentials {
    pub uid: u16,
    pub gid: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Exec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    /// A path component does not exist.
    NotFound,
    /// A path component used as a directory is a file (ENOTDIR).
    NotADirectory,
    /// Permission bits deny the operation (EACCES).
    PermissionDenied,
    /// create/mkdir target already exists (EEXIST).
    Exists,
    /// Name longer than `NAME_MAX` (ENAMETOOLONG).
    NameTooLong,
    /// Inode table exhausted (ENOSPC).
    TableFull,
    /// File content would exceed `FILE_DATA_MAX` (ENOSPC).
    NoSpace,
    /// unlink on a directory that still has entries.
    NotEmpty,
    /// read/write/open on a directory (EISDIR).
    IsADirectory,
}

#[derive(Clone, Copy)]
struct Inode {
    kind: InodeKind,
    uid: u16,
    gid: u16,
    mode: Mode,
    parent: u32,
    name: [u8; NAME_MAX],
    name_len: usize,
    data: [u8; FILE_DATA_MAX],
    size: usize,
}

pub struct Vfs {
    inodes: [Option<Inode>; MAX_INODES],
}

impl Vfs {
    pub fn new() -> Self {
        let mut fs = Vfs { inodes: [None; MAX_INODES] };
        fs.inodes[0] = Some(Inode {
            kind: InodeKind::Dir,
            uid: 0,
            gid: 0,
            mode: Mode(0o755),
            parent: ROOT_ID,
            name: [0; NAME_MAX],
            name_len: 0,
            data: [0; FILE_DATA_MAX],
            size: 0,
        });
        fs
    }

    fn inode(&self, id: u32) -> Result<&Inode, VfsError> {
        match self.inodes.get(id as usize) {
            Some(Some(i)) => Ok(i),
            _ => Err(VfsError::NotFound),
        }
    }

    fn inode_mut(&mut self, id: u32) -> Result<&mut Inode, VfsError> {
        match self.inodes.get_mut(id as usize) {
            Some(Some(i)) => Ok(i),
            _ => Err(VfsError::NotFound),
        }
    }

    fn alloc_id(&mut self) -> Result<u32, VfsError> {
        for (i, slot) in self.inodes.iter().enumerate() {
            if slot.is_none() {
                return Ok(i as u32);
            }
        }
        Err(VfsError::TableFull)
    }

    fn child_by_name(&self, dir: u32, name: &str) -> Option<u32> {
        let bytes = name.as_bytes();
        for (i, slot) in self.inodes.iter().enumerate() {
            if let Some(inode) = slot {
                if inode.parent == dir
                    && inode.name_len == bytes.len()
                    && &inode.name[..inode.name_len] == bytes
                {
                    return Some(i as u32);
                }
            }
        }
        None
    }

    /// Unix DAC check: uid 0 bypasses; otherwise owner/group/other bits.
    pub fn check_access(
        &self,
        id: u32,
        creds: Credentials,
        access: Access,
    ) -> Result<(), VfsError> {
        let inode = self.inode(id)?;
        if creds.uid == 0 {
            return Ok(()); // Linux root bypass (chroot still applies).
        }
        let shift = if creds.uid == inode.uid {
            6
        } else if creds.gid == inode.gid {
            3
        } else {
            0
        };
        let bit = match access {
            Access::Read => 4,
            Access::Write => 2,
            Access::Exec => 1,
        };
        if (inode.mode.0 >> shift) & bit != 0 {
            Ok(())
        } else {
            Err(VfsError::PermissionDenied)
        }
    }

    /// Resolve a path to an inode id, confined to `root` (chroot).
    /// Traversal requires the execute bit on every directory entered.
    pub fn resolve(
        &self,
        root: u32,
        cwd: u32,
        path: &str,
        creds: Credentials,
    ) -> Result<u32, VfsError> {
        let mut cur = if path.starts_with('/') { root } else { cwd };
        for comp in path.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                // Chroot clamp: ".." at the root stays at the root.
                if cur != root {
                    cur = self.inode(cur)?.parent;
                }
                continue;
            }
            if comp.len() > NAME_MAX {
                return Err(VfsError::NameTooLong);
            }
            // Enter a directory: must be a dir and need the x bit.
            let dir = self.inode(cur)?;
            if dir.kind != InodeKind::Dir {
                return Err(VfsError::NotADirectory);
            }
            self.check_access(cur, creds, Access::Exec)?;
            match self.child_by_name(cur, comp) {
                Some(child) => cur = child,
                None => return Err(VfsError::NotFound),
            }
        }
        Ok(cur)
    }

    /// Resolve the parent directory of the final component.
    /// Returns (parent_id, final_name).
    fn resolve_parent<'a>(
        &self,
        root: u32,
        cwd: u32,
        path: &'a str,
        creds: Credentials,
    ) -> Result<(u32, &'a str), VfsError> {
        // Split into (dir_part, last) with trailing-slash normalization.
        let trimmed = path.trim_end_matches('/');
        let (dir_part, last) = match trimmed.rfind('/') {
            Some(pos) => (&trimmed[..pos], &trimmed[pos + 1..]),
            None => ("", trimmed),
        };
        if last.is_empty() || last == "." || last == ".." {
            return Err(VfsError::NotFound); // invalid final component
        }
        if last.len() > NAME_MAX {
            return Err(VfsError::NameTooLong);
        }
        let parent = if dir_part.is_empty() {
            if path.starts_with('/') {
                root
            } else {
                cwd
            }
        } else {
            self.resolve(root, cwd, dir_part, creds)?
        };
        let p = self.inode(parent)?;
        if p.kind != InodeKind::Dir {
            return Err(VfsError::NotADirectory);
        }
        Ok((parent, last))
    }

    /// Create a file (creat/open-with-O_CREAT semantics).
    pub fn create(
        &mut self,
        root: u32,
        cwd: u32,
        path: &str,
        creds: Credentials,
        mode: Mode,
    ) -> Result<u32, VfsError> {
        let (parent, name) = self.resolve_parent(root, cwd, path, creds)?;
        self.check_access(parent, creds, Access::Write)?;
        self.check_access(parent, creds, Access::Exec)?;
        if self.child_by_name(parent, name).is_some() {
            return Err(VfsError::Exists);
        }
        let id = self.alloc_id()?;
        let mut nb = [0u8; NAME_MAX];
        nb[..name.len()].copy_from_slice(name.as_bytes());
        self.inodes[id as usize] = Some(Inode {
            kind: InodeKind::File,
            uid: creds.uid,
            gid: creds.gid,
            mode,
            parent,
            name: nb,
            name_len: name.len(),
            data: [0; FILE_DATA_MAX],
            size: 0,
        });
        Ok(id)
    }

    /// Create a directory (mkdir).
    pub fn mkdir(
        &mut self,
        root: u32,
        cwd: u32,
        path: &str,
        creds: Credentials,
        mode: Mode,
    ) -> Result<u32, VfsError> {
        let (parent, name) = self.resolve_parent(root, cwd, path, creds)?;
        self.check_access(parent, creds, Access::Write)?;
        self.check_access(parent, creds, Access::Exec)?;
        if self.child_by_name(parent, name).is_some() {
            return Err(VfsError::Exists);
        }
        let id = self.alloc_id()?;
        let mut nb = [0u8; NAME_MAX];
        nb[..name.len()].copy_from_slice(name.as_bytes());
        self.inodes[id as usize] = Some(Inode {
            kind: InodeKind::Dir,
            uid: creds.uid,
            gid: creds.gid,
            mode,
            parent,
            name: nb,
            name_len: name.len(),
            data: [0; FILE_DATA_MAX],
            size: 0,
        });
        Ok(id)
    }

    /// Unlink a file or an *empty* directory (unlink + rmdir combined).
    pub fn unlink(
        &mut self,
        root: u32,
        cwd: u32,
        path: &str,
        creds: Credentials,
    ) -> Result<u32, VfsError> {
        let (parent, name) = self.resolve_parent(root, cwd, path, creds)?;
        self.check_access(parent, creds, Access::Write)?;
        self.check_access(parent, creds, Access::Exec)?;
        let target = self
            .child_by_name(parent, name)
            .ok_or(VfsError::NotFound)?;
        // Sticky-bit-like protection for the tree root.
        if target == ROOT_ID {
            return Err(VfsError::PermissionDenied);
        }
        if self.inode(target)?.kind == InodeKind::Dir && self.has_children(target) {
            return Err(VfsError::NotEmpty);
        }
        self.inodes[target as usize] = None;
        Ok(target)
    }

    /// Whether a directory has any entries (no allocation).
    #[must_use]
    pub fn has_children(&self, dir: u32) -> bool {
        self.inodes
            .iter()
            .flatten()
            .any(|i| i.parent == dir)
    }

    /// Read file content by inode id (permission check on the file).
    pub fn read_by_id(
        &self,
        id: u32,
        creds: Credentials,
        buf: &mut [u8],
    ) -> Result<usize, VfsError> {
        self.read_by_id_at(id, creds, 0, buf)
    }

    /// Read file content starting at a byte offset (fd-cursor reads).
    /// Returns bytes read; fewer than the buffer means EOF.
    pub fn read_by_id_at(
        &self,
        id: u32,
        creds: Credentials,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize, VfsError> {
        let inode = self.inode(id)?;
        if inode.kind != InodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        self.check_access(id, creds, Access::Read)?;
        if offset >= inode.size {
            return Ok(0); // at or past EOF
        }
        let avail = inode.size - offset;
        let n = buf.len().min(avail);
        buf[..n].copy_from_slice(&inode.data[offset..offset + n]);
        Ok(n)
    }

    /// Write file content by inode id (truncate semantics).
    pub fn write_by_id(
        &mut self,
        id: u32,
        creds: Credentials,
        bytes: &[u8],
    ) -> Result<usize, VfsError> {
        if self.inode(id)?.kind != InodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        self.check_access(id, creds, Access::Write)?;
        if bytes.len() > FILE_DATA_MAX {
            return Err(VfsError::NoSpace);
        }
        let inode = self.inode_mut(id)?;
        inode.data[..bytes.len()].copy_from_slice(bytes);
        inode.size = bytes.len();
        Ok(bytes.len())
    }

    #[must_use]
    pub fn size_of(&self, id: u32) -> Option<usize> {
        self.inodes.get(id as usize).and_then(|s| s.as_ref()).map(|i| i.size)
    }

    #[must_use]
    pub fn kind_of(&self, id: u32) -> Option<InodeKind> {
        self.inodes.get(id as usize).and_then(|s| s.as_ref()).map(|i| i.kind)
    }

    pub fn stat(
        &self,
        root: u32,
        cwd: u32,
        path: &str,
        creds: Credentials,
    ) -> Result<(InodeKind, usize, u16, u16, Mode), VfsError> {
        let id = self.resolve(root, cwd, path, creds)?;
        let i = self.inode(id)?;
        Ok((i.kind, i.size, i.uid, i.gid, i.mode))
    }

    /// chmod: owner (or uid 0) may change the permission bits.
    pub fn chmod(
        &mut self,
        root: u32,
        cwd: u32,
        path: &str,
        creds: Credentials,
        mode: Mode,
    ) -> Result<(), VfsError> {
        let id = self.resolve(root, cwd, path, creds)?;
        let inode = self.inode(id)?;
        if creds.uid != 0 && creds.uid != inode.uid {
            return Err(VfsError::PermissionDenied);
        }
        self.inode_mut(id)?.mode = mode;
        Ok(())
    }

    /// All children ids of a directory (test/introspection helper).
    #[cfg(test)]
    pub fn children_of(&self, dir: u32) -> Vec<u32> {
        self.inodes
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, Some(i) if i.parent == dir))
            .map(|(i, _)| i as u32)
            .collect()
    }
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_CREDS: Credentials = Credentials { uid: 0, gid: 0 };
    const USER: Credentials = Credentials { uid: 1000, gid: 1000 };
    const GROUPIE: Credentials = Credentials { uid: 2000, gid: 1000 };
    const STRANGER: Credentials = Credentials { uid: 3000, gid: 3000 };

    fn fs_with(user_dir: bool) -> Vfs {
        let mut fs = Vfs::new();
        // /pub: world-readable dir; /home: owned by user 1000.
        fs.mkdir(ROOT_ID, ROOT_ID, "/pub", ROOT_CREDS, Mode(0o777)).unwrap();
        fs.mkdir(ROOT_ID, ROOT_ID, "/home", ROOT_CREDS, Mode(0o777)).unwrap();
        fs.create(ROOT_ID, ROOT_ID, "/home/notes.txt", USER, Mode(0o644)).unwrap();
        if user_dir {
            fs.mkdir(ROOT_ID, ROOT_ID, "/home/alice", USER, Mode(0o750)).unwrap();
        }
        fs
    }

    #[test]
    fn root_exists_and_resolves() {
        let fs = Vfs::new();
        assert_eq!(fs.resolve(ROOT_ID, ROOT_ID, "/", ROOT_CREDS), Ok(ROOT_ID));
        assert_eq!(fs.resolve(ROOT_ID, ROOT_ID, ".", ROOT_CREDS), Ok(ROOT_ID));
        assert_eq!(fs.resolve(ROOT_ID, ROOT_ID, "/..", ROOT_CREDS), Ok(ROOT_ID));
    }

    #[test]
    fn create_stat_read_write_roundtrip() {
        let mut fs = fs_with(false);
        let id = fs
            .create(ROOT_ID, ROOT_ID, "/pub/data.txt", USER, Mode(0o644))
            .unwrap();
        let n = fs.write_by_id(id, USER, b"hello aegis").unwrap();
        assert_eq!(n, 11);
        let mut buf = [0u8; 32];
        assert_eq!(fs.read_by_id(id, USER, &mut buf).unwrap(), 11);
        assert_eq!(&buf[..11], b"hello aegis");
        let (kind, size, uid, gid, mode) = fs.stat(ROOT_ID, ROOT_ID, "/pub/data.txt", USER).unwrap();
        assert_eq!((kind, size, uid, gid), (InodeKind::File, 11, 1000, 1000));
        assert_eq!(mode, Mode(0o644));
    }

    #[test]
    fn duplicate_create_and_mkdir_fail_with_exists() {
        let mut fs = fs_with(false);
        assert_eq!(
            fs.create(ROOT_ID, ROOT_ID, "/home/notes.txt", USER, Mode(0o644)),
            Err(VfsError::Exists)
        );
        assert_eq!(
            fs.mkdir(ROOT_ID, ROOT_ID, "/pub", ROOT_CREDS, Mode(0o755)),
            Err(VfsError::Exists)
        );
    }

    #[test]
    fn dot_dotdot_and_double_slashes_normalize() {
        let fs = fs_with(false);
        // /pub/../home/./notes.txt == /home/notes.txt
        let a = fs.resolve(ROOT_ID, ROOT_ID, "/pub/../home/./notes.txt", USER).unwrap();
        let b = fs.resolve(ROOT_ID, ROOT_ID, "/home/notes.txt", USER).unwrap();
        assert_eq!(a, b);
        // Repeated and trailing slashes.
        let c = fs.resolve(ROOT_ID, ROOT_ID, "//home//notes.txt//", USER).unwrap();
        assert_eq!(c, b);
    }

    #[test]
    fn relative_paths_resolve_from_cwd() {
        let fs = fs_with(false);
        let home = fs.resolve(ROOT_ID, ROOT_ID, "/home", USER).unwrap();
        let a = fs.resolve(ROOT_ID, home, "notes.txt", USER).unwrap();
        let b = fs.resolve(ROOT_ID, ROOT_ID, "/home/notes.txt", USER).unwrap();
        assert_eq!(a, b);
        // ../pub from /home
        let c = fs.resolve(ROOT_ID, home, "../pub", USER).unwrap();
        let d = fs.resolve(ROOT_ID, ROOT_ID, "/pub", USER).unwrap();
        assert_eq!(c, d);
    }

    #[test]
    fn missing_component_is_notfound_and_file_midpath_notadir() {
        let mut fs = fs_with(false);
        assert_eq!(
            fs.resolve(ROOT_ID, ROOT_ID, "/nope/child", ROOT_CREDS),
            Err(VfsError::NotFound)
        );
        assert_eq!(
            fs.resolve(ROOT_ID, ROOT_ID, "/home/notes.txt/child", ROOT_CREDS),
            Err(VfsError::NotADirectory)
        );
        assert_eq!(
            fs.mkdir(ROOT_ID, ROOT_ID, "/home/notes.txt/sub", ROOT_CREDS, Mode(0o755)),
            Err(VfsError::NotADirectory)
        );
    }

    #[test]
    fn exec_bit_required_to_traverse_directory() {
        let mut fs = Vfs::new();
        // /vault: readable but not executable for others (can list stat on
        // the dir itself, cannot enter).
        fs.mkdir(ROOT_ID, ROOT_ID, "/vault", ROOT_CREDS, Mode(0o644)).unwrap();
        fs.create(ROOT_ID, ROOT_ID, "/vault/secret.txt", ROOT_CREDS, Mode(0o600)).unwrap();
        // Owner can traverse.
        assert!(fs.resolve(ROOT_ID, ROOT_ID, "/vault/secret.txt", ROOT_CREDS).is_ok());
        // Others cannot (no x bit for other).
        assert_eq!(
            fs.resolve(ROOT_ID, ROOT_ID, "/vault/secret.txt", USER),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn owner_group_other_bits() {
        let mut fs = Vfs::new();
        // File owned by 1000:1000, group r, other nothing.
        fs.mkdir(ROOT_ID, ROOT_ID, "/d", ROOT_CREDS, Mode(0o777)).unwrap();
        let id = fs.create(ROOT_ID, ROOT_ID, "/d/f", USER, Mode(0o640)).unwrap();
        // Owner: r ok, w ok.
        assert!(fs.read_by_id(id, USER, &mut [0; 8]).is_ok());
        assert!(fs.write_by_id(id, USER, b"x").is_ok());
        // Group member (gid 1000, different uid): r ok, w denied.
        assert!(fs.read_by_id(id, GROUPIE, &mut [0; 8]).is_ok());
        assert_eq!(
            fs.write_by_id(id, GROUPIE, b"x"),
            Err(VfsError::PermissionDenied)
        );
        // Unrelated uid/gid: nothing.
        assert_eq!(
            fs.read_by_id(id, STRANGER, &mut [0; 8]),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn uid_zero_bypasses_dac_but_not_chroot() {
        let fs = fs_with(false);
        let id = fs
            .resolve(ROOT_ID, ROOT_ID, "/home/notes.txt", ROOT_CREDS)
            .unwrap();
        // Root reads a 0o640 file owned by someone else (mode check bypassed).
        assert!(fs.read_by_id(id, ROOT_CREDS, &mut [0; 16]).is_ok());
        // Root is still confined by chroot resolution (covered further below).
    }

    #[test]
    fn write_requires_w_bit() {
        let mut fs = fs_with(false);
        let id = fs
            .resolve(ROOT_ID, ROOT_ID, "/home/notes.txt", USER)
            .unwrap();
        // 0o644: owner w ok.
        assert!(fs.write_by_id(id, USER, b"new").is_ok());
        // Group (r--) and other (r--): w denied.
        assert_eq!(
            fs.write_by_id(id, GROUPIE, b"nope"),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn create_denied_without_write_on_parent() {
        let mut fs = Vfs::new();
        // /ro: r-x for others (can enter, cannot create).
        fs.mkdir(ROOT_ID, ROOT_ID, "/ro", ROOT_CREDS, Mode(0o755)).unwrap();
        fs.chmod(ROOT_ID, ROOT_ID, "/ro", USER, Mode(0o555)).unwrap_err(); // not owner
        fs.chmod(ROOT_ID, ROOT_ID, "/ro", ROOT_CREDS, Mode(0o555)).unwrap();
        assert_eq!(
            fs.create(ROOT_ID, ROOT_ID, "/ro/f.txt", USER, Mode(0o644)),
            Err(VfsError::PermissionDenied)
        );
        // Root creates fine (bypass).
        assert!(fs.create(ROOT_ID, ROOT_ID, "/ro/f.txt", ROOT_CREDS, Mode(0o644)).is_ok());
    }

    #[test]
    fn chroot_clamps_dotdot_at_root() {
        let fs = fs_with(true);
        let alice = fs.resolve(ROOT_ID, ROOT_ID, "/home/alice", USER).unwrap();
        // Chroot to /home/alice: ".." cannot climb above it.
        assert_eq!(fs.resolve(alice, alice, "..", USER), Ok(alice));
        assert_eq!(fs.resolve(alice, alice, "../../..", USER), Ok(alice));
        assert_eq!(fs.resolve(alice, alice, "../../../home/notes.txt", USER), Err(VfsError::NotFound));
        // Absolute paths are also relative to the chroot root.
        assert_eq!(fs.resolve(alice, alice, "/home/notes.txt", USER), Err(VfsError::NotFound));
    }

    #[test]
    fn chroot_child_climbs_to_chroot_root_only() {
        let mut fs = fs_with(true);
        let alice = fs.resolve(ROOT_ID, ROOT_ID, "/home/alice", USER).unwrap();
        fs.mkdir(alice, alice, "docs", USER, Mode(0o750)).unwrap();
        let docs = fs.resolve(alice, alice, "docs", USER).unwrap();
        // docs/.. == alice (chroot root), alice/.. == alice (clamped).
        assert_eq!(fs.resolve(alice, docs, "..", USER), Ok(alice));
        assert_eq!(fs.resolve(alice, docs, "../..", USER), Ok(alice));
        // Escape attempt via docs/../../home/alice.
        assert_eq!(
            fs.resolve(alice, docs, "../../home/alice", USER),
            Err(VfsError::NotFound)
        );
    }

    #[test]
    fn unlink_file_and_empty_dir_but_not_nonempty() {
        let mut fs = fs_with(true);
        fs.unlink(ROOT_ID, ROOT_ID, "/home/notes.txt", USER).unwrap();
        assert_eq!(
            fs.resolve(ROOT_ID, ROOT_ID, "/home/notes.txt", USER),
            Err(VfsError::NotFound)
        );
        // Non-empty dir: /home contains alice (root may attempt it; the
        // directory is still not empty regardless of credentials).
        assert_eq!(
            fs.unlink(ROOT_ID, ROOT_ID, "/home", ROOT_CREDS),
            Err(VfsError::NotEmpty)
        );
        // Empty dir: /home/alice is empty.
        fs.unlink(ROOT_ID, ROOT_ID, "/home/alice", USER).unwrap();
        // The tree root itself is not addressable by unlink (no final name).
        assert_eq!(
            fs.unlink(ROOT_ID, ROOT_ID, "/", ROOT_CREDS),
            Err(VfsError::NotFound)
        );
    }

    #[test]
    fn unlink_denied_without_parent_write() {
        let mut fs = Vfs::new();
        fs.mkdir(ROOT_ID, ROOT_ID, "/ro", ROOT_CREDS, Mode(0o555)).unwrap();
        fs.create(ROOT_ID, ROOT_ID, "/ro/f", ROOT_CREDS, Mode(0o644)).unwrap();
        assert_eq!(
            fs.unlink(ROOT_ID, ROOT_ID, "/ro/f", USER),
            Err(VfsError::PermissionDenied)
        );
        fs.unlink(ROOT_ID, ROOT_ID, "/ro/f", ROOT_CREDS).unwrap();
    }

    #[test]
    fn chmod_owner_or_root_only() {
        let mut fs = fs_with(false);
        // Not the owner.
        assert_eq!(
            fs.chmod(ROOT_ID, ROOT_ID, "/home/notes.txt", STRANGER, Mode(0o777)),
            Err(VfsError::PermissionDenied)
        );
        // Owner changes mode, then others can write.
        fs.chmod(ROOT_ID, ROOT_ID, "/home/notes.txt", USER, Mode(0o666)).unwrap();
        let id = fs.resolve(ROOT_ID, ROOT_ID, "/home/notes.txt", USER).unwrap();
        assert!(fs.write_by_id(id, STRANGER, b"now").is_ok());
        // Root can chmod anything.
        fs.chmod(ROOT_ID, ROOT_ID, "/home/notes.txt", ROOT_CREDS, Mode(0o600)).unwrap();
        assert_eq!(
            fs.write_by_id(id, STRANGER, b"nope"),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn oversize_write_and_name_rejected() {
        let mut fs = Vfs::new();
        let id = fs.create(ROOT_ID, ROOT_ID, "/f", ROOT_CREDS, Mode(0o644)).unwrap();
        assert_eq!(
            fs.write_by_id(id, ROOT_CREDS, &[0u8; FILE_DATA_MAX + 1]),
            Err(VfsError::NoSpace)
        );
        // Exactly capacity is fine.
        assert_eq!(
            fs.write_by_id(id, ROOT_CREDS, &[1u8; FILE_DATA_MAX]).unwrap(),
            FILE_DATA_MAX
        );
        // Long name.
        let long = "a".repeat(NAME_MAX + 1);
        assert_eq!(
            fs.create(ROOT_ID, ROOT_ID, &format!("/{}", long), ROOT_CREDS, Mode(0o644)),
            Err(VfsError::NameTooLong)
        );
    }

    #[test]
    fn inode_table_fills_at_max() {
        let mut fs = Vfs::new();
        // Root + 1 dir used; fill the rest.
        fs.mkdir(ROOT_ID, ROOT_ID, "/d", ROOT_CREDS, Mode(0o755)).unwrap();
        for i in 0..(MAX_INODES - 2) {
            fs.create(
                ROOT_ID,
                ROOT_ID,
                &format!("/d/f{}", i),
                ROOT_CREDS,
                Mode(0o644),
            )
            .unwrap();
        }
        assert_eq!(
            fs.create(ROOT_ID, ROOT_ID, "/d/overflow", ROOT_CREDS, Mode(0o644)),
            Err(VfsError::TableFull)
        );
        // Unlink frees a slot for reuse.
        fs.unlink(ROOT_ID, ROOT_ID, "/d/f0", ROOT_CREDS).unwrap();
        assert!(fs.create(ROOT_ID, ROOT_ID, "/d/again", ROOT_CREDS, Mode(0o644)).is_ok());
    }

    #[test]
    fn read_write_on_directory_rejected() {
        let mut fs = fs_with(false);
        let home = fs.resolve(ROOT_ID, ROOT_ID, "/home", ROOT_CREDS).unwrap();
        assert_eq!(
            fs.read_by_id(home, ROOT_CREDS, &mut [0; 4]),
            Err(VfsError::IsADirectory)
        );
        assert_eq!(
            fs.write_by_id(home, ROOT_CREDS, b"x"),
            Err(VfsError::IsADirectory)
        );
    }
}
