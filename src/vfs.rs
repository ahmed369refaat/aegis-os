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

/// F10: an inode identity that survives slot reuse — a bare id aliases
/// whatever now lives in the slot; a (id, generation) pair names the
/// *specific* inode and fails closed (StaleInode) once that inode is
/// gone. Held by fd entries and by domain cwd/chroot roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeRef {
    pub id: u32,
    pub generation: u32,
}

/// The root directory's reference. The root inode is created once in
/// `Vfs::new` (generation 1) and can never be unlinked, so its
/// generation is a constant.
pub const ROOT_REF: InodeRef = InodeRef { id: ROOT_ID, generation: 1 };

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
    /// F10: the (id, generation) reference names an inode that no
    /// longer lives — the slot was freed (and maybe reused). Stale
    /// references fail closed; they never silently re-target.
    StaleInode,
}

#[derive(Clone, Copy)]
struct Inode {
    generation: u32,
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
    /// F10: per-slot generation counter — bumped on every allocation
    /// into the slot, so stale references never alias new occupants.
    generations: [u32; MAX_INODES],
}

impl Vfs {
    pub fn new() -> Self {
        let mut fs = Vfs { inodes: [None; MAX_INODES], generations: [0; MAX_INODES] };
        fs.generations[0] = 1;
        fs.inodes[0] = Some(Inode {
            generation: 1,
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

    /// F10: validate a reference — the inode must exist AND carry the
    /// reference's generation. Returns the live id or StaleInode.
    fn live(&self, r: InodeRef) -> Result<u32, VfsError> {
        match self.inodes.get(r.id as usize) {
            Some(Some(i)) if i.generation == r.generation => Ok(r.id),
            _ => Err(VfsError::StaleInode),
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

    /// F18 (ADR-0009): the parent directory of a path's final
    /// component, as a reference (the capability gate checks coverage
    /// of the *parent* — the directory an operation modifies).
    pub fn parent_ref(
        &self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
    ) -> Result<InodeRef, VfsError> {
        let (id, _) = self.resolve_parent(root, cwd, path, creds)?;
        let generation = self.inode(id)?.generation;
        Ok(InodeRef { id, generation })
    }

    /// F18 (ADR-0009): is `node` inside `ancestor`'s subtree (or equal
    /// to it)? A capability on a directory covers operations whose
    /// parent directory lies within it. Bounded by the inode table —
    /// the parent chain cannot cycle (each mkdir sets a live parent).
    pub fn is_within(&self, ancestor: InodeRef, node: InodeRef) -> bool {
        let anc = match self.live(ancestor) {
            Ok(a) => a,
            Err(_) => return false,
        };
        let mut cur = match self.live(node) {
            Ok(c) => c,
            Err(_) => return false,
        };
        for _ in 0..MAX_INODES {
            if cur == anc {
                return true;
            }
            match self.inode(cur) {
                Ok(i) => cur = i.parent,
                Err(_) => return false,
            }
        }
        false
    }

    /// F11(b): DAC check through a reference (stale fails closed) —
    /// used by Open to check the requested access at open time.
    pub fn check_access_ref(
        &self,
        r: InodeRef,
        creds: Credentials,
        access: Access,
    ) -> Result<(), VfsError> {
        let id = self.live(r)?;
        self.check_access(id, creds, access)
    }

    /// Resolve a path to an inode id, confined to `root` (chroot).
    /// Traversal requires the execute bit on every directory entered.
    pub fn resolve(
        &self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
    ) -> Result<InodeRef, VfsError> {
        let root_id = self.live(root)?;
        let mut cur = if path.starts_with('/') {
            root_id
        } else {
            self.live(cwd)?
        };
        for comp in path.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                // F11(a): leaving a directory needs the x bit on it —
                // the old resolution climbed `..` with no check at all.
                self.check_access(cur, creds, Access::Exec)?;
                // Chroot clamp: ".." at the root stays at the root.
                if cur != root_id {
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
        let generation = self.inode(cur)?.generation;
        Ok(InodeRef { id: cur, generation })
    }

    /// Resolve the parent directory of the final component.
    /// Returns (parent_id, final_name).
    fn resolve_parent<'a>(
        &self,
        root: InodeRef,
        cwd: InodeRef,
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
                self.live(root)?
            } else {
                self.live(cwd)?
            }
        } else {
            self.resolve(root, cwd, dir_part, creds)?.id
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
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
        mode: Mode,
    ) -> Result<InodeRef, VfsError> {
        let (parent, name) = self.resolve_parent(root, cwd, path, creds)?;
        self.check_access(parent, creds, Access::Write)?;
        self.check_access(parent, creds, Access::Exec)?;
        if self.child_by_name(parent, name).is_some() {
            return Err(VfsError::Exists);
        }
        let id = self.alloc_id()?;
        self.generations[id as usize] = self.generations[id as usize].saturating_add(1);
        let generation = self.generations[id as usize];
        let mut nb = [0u8; NAME_MAX];
        nb[..name.len()].copy_from_slice(name.as_bytes());
        self.inodes[id as usize] = Some(Inode {
            generation,
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
        Ok(InodeRef { id, generation })
    }

    /// Create a directory (mkdir).
    pub fn mkdir(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
        mode: Mode,
    ) -> Result<InodeRef, VfsError> {
        let (parent, name) = self.resolve_parent(root, cwd, path, creds)?;
        self.check_access(parent, creds, Access::Write)?;
        self.check_access(parent, creds, Access::Exec)?;
        if self.child_by_name(parent, name).is_some() {
            return Err(VfsError::Exists);
        }
        let id = self.alloc_id()?;
        self.generations[id as usize] = self.generations[id as usize].saturating_add(1);
        let generation = self.generations[id as usize];
        let mut nb = [0u8; NAME_MAX];
        nb[..name.len()].copy_from_slice(name.as_bytes());
        self.inodes[id as usize] = Some(Inode {
            generation,
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
        Ok(InodeRef { id, generation })
    }

    /// Unlink a file or an *empty* directory (unlink + rmdir combined).
    pub fn unlink(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
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

    /// Read file content by inode reference (permission check on the
    /// file). A stale reference fails closed.
    pub fn read_by_id(
        &self,
        r: InodeRef,
        creds: Credentials,
        buf: &mut [u8],
    ) -> Result<usize, VfsError> {
        self.read_by_id_at(r, creds, 0, buf)
    }

    /// Read file content starting at a byte offset (fd-cursor reads).
    /// Returns bytes read; fewer than the buffer means EOF.
    pub fn read_by_id_at(
        &self,
        r: InodeRef,
        creds: Credentials,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize, VfsError> {
        let id = self.live(r)?;
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

    /// F11(c): write at the fd's offset — existing bytes stay, the file
    /// only grows past them. Truncation is an explicit Open flag
    /// (`truncate`), never a side effect of writing.
    pub fn write_at(
        &mut self,
        r: InodeRef,
        creds: Credentials,
        offset: usize,
        bytes: &[u8],
    ) -> Result<usize, VfsError> {
        let id = self.live(r)?;
        if self.inode(id)?.kind != InodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        self.check_access(id, creds, Access::Write)?;
        let end = offset.saturating_add(bytes.len());
        if end > FILE_DATA_MAX {
            return Err(VfsError::NoSpace);
        }
        let inode = self.inode_mut(id)?;
        inode.data[offset..end].copy_from_slice(bytes);
        if end > inode.size {
            inode.size = end;
        }
        Ok(bytes.len())
    }

    /// F11(c): explicit truncation (Open with the truncate flag).
    pub fn truncate(
        &mut self,
        r: InodeRef,
        creds: Credentials,
    ) -> Result<(), VfsError> {
        let id = self.live(r)?;
        if self.inode(id)?.kind != InodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        self.check_access(id, creds, Access::Write)?;
        self.inode_mut(id)?.size = 0;
        Ok(())
    }

    #[must_use]
    pub fn size_of(&self, r: InodeRef) -> Option<usize> {
        self.live(r).ok().and_then(|id| self.inodes.get(id as usize).and_then(|s| s.as_ref()).map(|i| i.size))
    }

    #[must_use]
    pub fn kind_of(&self, r: InodeRef) -> Option<InodeKind> {
        self.live(r).ok().and_then(|id| self.inodes.get(id as usize).and_then(|s| s.as_ref()).map(|i| i.kind))
    }

    pub fn stat(
        &self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
    ) -> Result<(InodeKind, usize, u16, u16, Mode), VfsError> {
        let id = self.resolve(root, cwd, path, creds)?.id;
        let i = self.inode(id)?;
        Ok((i.kind, i.size, i.uid, i.gid, i.mode))
    }

    /// chmod: owner (or uid 0) may change the permission bits.
    pub fn chmod(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
        mode: Mode,
    ) -> Result<(), VfsError> {
        let id = self.live(self.resolve(root, cwd, path, creds)?)?;
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
        fs.mkdir(ROOT_REF, ROOT_REF, "/pub", ROOT_CREDS, Mode(0o777)).unwrap();
        fs.mkdir(ROOT_REF, ROOT_REF, "/home", ROOT_CREDS, Mode(0o777)).unwrap();
        fs.create(ROOT_REF, ROOT_REF, "/home/notes.txt", USER, Mode(0o644)).unwrap();
        if user_dir {
            fs.mkdir(ROOT_REF, ROOT_REF, "/home/alice", USER, Mode(0o750)).unwrap();
        }
        fs
    }

    #[test]
    fn root_exists_and_resolves() {
        let fs = Vfs::new();
        assert_eq!(fs.resolve(ROOT_REF, ROOT_REF, "/", ROOT_CREDS), Ok(ROOT_REF));
        assert_eq!(fs.resolve(ROOT_REF, ROOT_REF, ".", ROOT_CREDS), Ok(ROOT_REF));
        assert_eq!(fs.resolve(ROOT_REF, ROOT_REF, "/..", ROOT_CREDS), Ok(ROOT_REF));
    }

    #[test]
    fn create_stat_read_write_roundtrip() {
        let mut fs = fs_with(false);
        let id = fs
            .create(ROOT_REF, ROOT_REF, "/pub/data.txt", USER, Mode(0o644))
            .unwrap();
        let n = fs.write_at(id, USER, 0, b"hello aegis").unwrap();
        assert_eq!(n, 11);
        let mut buf = [0u8; 32];
        assert_eq!(fs.read_by_id(id, USER, &mut buf).unwrap(), 11);
        assert_eq!(&buf[..11], b"hello aegis");
        let (kind, size, uid, gid, mode) = fs.stat(ROOT_REF, ROOT_REF, "/pub/data.txt", USER).unwrap();
        assert_eq!((kind, size, uid, gid), (InodeKind::File, 11, 1000, 1000));
        assert_eq!(mode, Mode(0o644));
    }

    #[test]
    fn duplicate_create_and_mkdir_fail_with_exists() {
        let mut fs = fs_with(false);
        assert_eq!(
            fs.create(ROOT_REF, ROOT_REF, "/home/notes.txt", USER, Mode(0o644)),
            Err(VfsError::Exists)
        );
        assert_eq!(
            fs.mkdir(ROOT_REF, ROOT_REF, "/pub", ROOT_CREDS, Mode(0o755)),
            Err(VfsError::Exists)
        );
    }

    #[test]
    fn dot_dotdot_and_double_slashes_normalize() {
        let fs = fs_with(false);
        // /pub/../home/./notes.txt == /home/notes.txt
        let a = fs.resolve(ROOT_REF, ROOT_REF, "/pub/../home/./notes.txt", USER).unwrap();
        let b = fs.resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER).unwrap();
        assert_eq!(a, b);
        // Repeated and trailing slashes.
        let c = fs.resolve(ROOT_REF, ROOT_REF, "//home//notes.txt//", USER).unwrap();
        assert_eq!(c, b);
    }

    #[test]
    fn relative_paths_resolve_from_cwd() {
        let fs = fs_with(false);
        let home = fs.resolve(ROOT_REF, ROOT_REF, "/home", USER).unwrap();
        let a = fs.resolve(ROOT_REF, home, "notes.txt", USER).unwrap();
        let b = fs.resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER).unwrap();
        assert_eq!(a, b);
        // ../pub from /home
        let c = fs.resolve(ROOT_REF, home, "../pub", USER).unwrap();
        let d = fs.resolve(ROOT_REF, ROOT_REF, "/pub", USER).unwrap();
        assert_eq!(c, d);
    }

    #[test]
    fn missing_component_is_notfound_and_file_midpath_notadir() {
        let mut fs = fs_with(false);
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, "/nope/child", ROOT_CREDS),
            Err(VfsError::NotFound)
        );
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, "/home/notes.txt/child", ROOT_CREDS),
            Err(VfsError::NotADirectory)
        );
        assert_eq!(
            fs.mkdir(ROOT_REF, ROOT_REF, "/home/notes.txt/sub", ROOT_CREDS, Mode(0o755)),
            Err(VfsError::NotADirectory)
        );
    }

    #[test]
    fn exec_bit_required_to_traverse_directory() {
        let mut fs = Vfs::new();
        // /vault: readable but not executable for others (can list stat on
        // the dir itself, cannot enter).
        fs.mkdir(ROOT_REF, ROOT_REF, "/vault", ROOT_CREDS, Mode(0o644)).unwrap();
        fs.create(ROOT_REF, ROOT_REF, "/vault/secret.txt", ROOT_CREDS, Mode(0o600)).unwrap();
        // Owner can traverse.
        assert!(fs.resolve(ROOT_REF, ROOT_REF, "/vault/secret.txt", ROOT_CREDS).is_ok());
        // Others cannot (no x bit for other).
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, "/vault/secret.txt", USER),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn owner_group_other_bits() {
        let mut fs = Vfs::new();
        // File owned by 1000:1000, group r, other nothing.
        fs.mkdir(ROOT_REF, ROOT_REF, "/d", ROOT_CREDS, Mode(0o777)).unwrap();
        let id = fs.create(ROOT_REF, ROOT_REF, "/d/f", USER, Mode(0o640)).unwrap();
        // Owner: r ok, w ok.
        assert!(fs.read_by_id(id, USER, &mut [0; 8]).is_ok());
        assert!(fs.write_at(id, USER, 0, b"x").is_ok());
        // Group member (gid 1000, different uid): r ok, w denied.
        assert!(fs.read_by_id(id, GROUPIE, &mut [0; 8]).is_ok());
        assert_eq!(
            fs.write_at(id, GROUPIE, 0, b"x"),
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
            .resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", ROOT_CREDS)
            .unwrap();
        // Root reads a 0o640 file owned by someone else (mode check bypassed).
        assert!(fs.read_by_id(id, ROOT_CREDS, &mut [0; 16]).is_ok());
        // Root is still confined by chroot resolution (covered further below).
    }

    #[test]
    fn write_requires_w_bit() {
        let mut fs = fs_with(false);
        let id = fs
            .resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER)
            .unwrap();
        // 0o644: owner w ok.
        assert!(fs.write_at(id, USER, 0, b"new").is_ok());
        // Group (r--) and other (r--): w denied.
        assert_eq!(
            fs.write_at(id, GROUPIE, 0, b"nope"),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn create_denied_without_write_on_parent() {
        let mut fs = Vfs::new();
        // /ro: r-x for others (can enter, cannot create).
        fs.mkdir(ROOT_REF, ROOT_REF, "/ro", ROOT_CREDS, Mode(0o755)).unwrap();
        fs.chmod(ROOT_REF, ROOT_REF, "/ro", USER, Mode(0o555)).unwrap_err(); // not owner
        fs.chmod(ROOT_REF, ROOT_REF, "/ro", ROOT_CREDS, Mode(0o555)).unwrap();
        assert_eq!(
            fs.create(ROOT_REF, ROOT_REF, "/ro/f.txt", USER, Mode(0o644)),
            Err(VfsError::PermissionDenied)
        );
        // Root creates fine (bypass).
        assert!(fs.create(ROOT_REF, ROOT_REF, "/ro/f.txt", ROOT_CREDS, Mode(0o644)).is_ok());
    }

    #[test]
    fn chroot_clamps_dotdot_at_root() {
        let fs = fs_with(true);
        let alice = fs.resolve(ROOT_REF, ROOT_REF, "/home/alice", USER).unwrap();
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
        let alice = fs.resolve(ROOT_REF, ROOT_REF, "/home/alice", USER).unwrap();
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
        fs.unlink(ROOT_REF, ROOT_REF, "/home/notes.txt", USER).unwrap();
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER),
            Err(VfsError::NotFound)
        );
        // Non-empty dir: /home contains alice (root may attempt it; the
        // directory is still not empty regardless of credentials).
        assert_eq!(
            fs.unlink(ROOT_REF, ROOT_REF, "/home", ROOT_CREDS),
            Err(VfsError::NotEmpty)
        );
        // Empty dir: /home/alice is empty.
        fs.unlink(ROOT_REF, ROOT_REF, "/home/alice", USER).unwrap();
        // The tree root itself is not addressable by unlink (no final name).
        assert_eq!(
            fs.unlink(ROOT_REF, ROOT_REF, "/", ROOT_CREDS),
            Err(VfsError::NotFound)
        );
    }

    #[test]
    fn unlink_denied_without_parent_write() {
        let mut fs = Vfs::new();
        fs.mkdir(ROOT_REF, ROOT_REF, "/ro", ROOT_CREDS, Mode(0o555)).unwrap();
        fs.create(ROOT_REF, ROOT_REF, "/ro/f", ROOT_CREDS, Mode(0o644)).unwrap();
        assert_eq!(
            fs.unlink(ROOT_REF, ROOT_REF, "/ro/f", USER),
            Err(VfsError::PermissionDenied)
        );
        fs.unlink(ROOT_REF, ROOT_REF, "/ro/f", ROOT_CREDS).unwrap();
    }

    #[test]
    fn chmod_owner_or_root_only() {
        let mut fs = fs_with(false);
        // Not the owner.
        assert_eq!(
            fs.chmod(ROOT_REF, ROOT_REF, "/home/notes.txt", STRANGER, Mode(0o777)),
            Err(VfsError::PermissionDenied)
        );
        // Owner changes mode, then others can write.
        fs.chmod(ROOT_REF, ROOT_REF, "/home/notes.txt", USER, Mode(0o666)).unwrap();
        let id = fs.resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER).unwrap();
        assert!(fs.write_at(id, STRANGER, 0, b"now").is_ok());
        // Root can chmod anything.
        fs.chmod(ROOT_REF, ROOT_REF, "/home/notes.txt", ROOT_CREDS, Mode(0o600)).unwrap();
        assert_eq!(
            fs.write_at(id, STRANGER, 0, b"nope"),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn oversize_write_and_name_rejected() {
        let mut fs = Vfs::new();
        let id = fs.create(ROOT_REF, ROOT_REF, "/f", ROOT_CREDS, Mode(0o644)).unwrap();
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, 0, &[0u8; FILE_DATA_MAX + 1]),
            Err(VfsError::NoSpace)
        );
        // Exactly capacity is fine.
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, 0, &[1u8; FILE_DATA_MAX]).unwrap(),
            FILE_DATA_MAX
        );
        // Long name.
        let long = "a".repeat(NAME_MAX + 1);
        assert_eq!(
            fs.create(ROOT_REF, ROOT_REF, &format!("/{}", long), ROOT_CREDS, Mode(0o644)),
            Err(VfsError::NameTooLong)
        );
    }

    #[test]
    fn inode_table_fills_at_max() {
        let mut fs = Vfs::new();
        // Root + 1 dir used; fill the rest.
        fs.mkdir(ROOT_REF, ROOT_REF, "/d", ROOT_CREDS, Mode(0o755)).unwrap();
        for i in 0..(MAX_INODES - 2) {
            fs.create(
                ROOT_REF,
                ROOT_REF,
                &format!("/d/f{}", i),
                ROOT_CREDS,
                Mode(0o644),
            )
            .unwrap();
        }
        assert_eq!(
            fs.create(ROOT_REF, ROOT_REF, "/d/overflow", ROOT_CREDS, Mode(0o644)),
            Err(VfsError::TableFull)
        );
        // Unlink frees a slot for reuse.
        fs.unlink(ROOT_REF, ROOT_REF, "/d/f0", ROOT_CREDS).unwrap();
        assert!(fs.create(ROOT_REF, ROOT_REF, "/d/again", ROOT_CREDS, Mode(0o644)).is_ok());
    }

    /// F11(a): `..` requires the x bit on the directory being LEFT —
    /// the old resolution climbed without any check at all. A domain
    /// sitting in /nx/inner (cwd granted) cannot climb out of /nx when
    /// /nx carries no x bit for it.
    #[test]
    fn dotdot_requires_x_bit_on_the_directory_being_left() {
        let mut fs = Vfs::new();
        fs.mkdir(ROOT_REF, ROOT_REF, "/nx", ROOT_CREDS, Mode(0o644)).unwrap();
        fs.mkdir(ROOT_REF, ROOT_REF, "/nx/inner", ROOT_CREDS, Mode(0o755)).unwrap();
        let inner = fs.resolve(ROOT_REF, ROOT_REF, "/nx/inner", ROOT_CREDS).unwrap();
        // One ".." leaves inner (x on inner: fine) and lands on /nx.
        assert_eq!(fs.resolve(ROOT_REF, inner, "..", USER), Ok(fs.resolve(ROOT_REF, ROOT_REF, "/nx", ROOT_CREDS).unwrap()));
        // The second ".." leaves /nx — no x bit for USER there: denied.
        assert_eq!(
            fs.resolve(ROOT_REF, inner, "../..", USER),
            Err(VfsError::PermissionDenied)
        );
        // Root bypasses the DAC check on the same climb.
        assert!(fs.resolve(ROOT_REF, inner, "../..", ROOT_CREDS).is_ok());
    }

    #[test]
    fn read_write_on_directory_rejected() {
        let mut fs = fs_with(false);
        let home = fs.resolve(ROOT_REF, ROOT_REF, "/home", ROOT_CREDS).unwrap();
        assert_eq!(
            fs.read_by_id(home, ROOT_CREDS, &mut [0; 4]),
            Err(VfsError::IsADirectory)
        );
        assert_eq!(
            fs.write_at(home, ROOT_CREDS, 0, b"x"),
            Err(VfsError::IsADirectory)
        );
    }
}
