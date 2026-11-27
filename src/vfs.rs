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

/// Phase 6 S1: the boot root's inode budget. The kernel is
/// no_std — the table is a fixed BSS array, sized for the M3 boot
/// tree (/pub, /tmp, /dev, /bin, /proc + their files) with slack for
/// the file demos and the persistence round-trip. K20 (P0-1):
/// 64 -> 128 (the boot tree plus a shell session's creations plus a
/// service's scratch files). Measured cost: the inode record is
/// ~1.1 KiB, the table 68 -> ~140 KiB of the (budgeted, see
/// docs/capacity.md) `Kernel` state.
pub const MAX_INODES: usize = 128;
/// Phase 6 S1: a tmpfs file's inline data window — one full ext2
/// block (1 KiB, the persistence round's unit). No dynamic allocation
/// exists anywhere in the core: each inode carries its window inline
/// and `NoSpace` is the honest ENOSPC at the edge. K20 (P0-1) keeps
/// the 1 KiB window DELIBERATELY: it rides inline in every inode, so
/// it multiplies MAX_INODES; a 4 KiB window measurably overflowed the
/// deep-park host tests' stacks at 64 inodes. Real file data goes
/// through the ext2/FAT32 paths — this is the boot-time ramfs.
pub const FILE_DATA_MAX: usize = 1024;
/// K22: the ramfs large-file budget. The inline window above is
/// per-inode, so it multiplies `MAX_INODES`; the package manager's
/// journal alone is ≥ 1.6 KiB for the smallest install (3.2 KiB for a
/// one-file package), so a file that outgrows the window MOVES into
/// one of these side-table slots instead of answering ENOSPC
/// mid-transaction: `LARGE_FILE_SLOTS` files of up to `LARGE_FILE_MAX`
/// bytes may be live at once, the rest stay inline exactly as before.
/// The table is a flat 32 KiB of `Kernel` state (never per-inode);
/// a file that needs a slot when all are taken still answers the
/// honest `NoSpace`.
pub const LARGE_FILE_MAX: usize = 8192;
pub const LARGE_FILE_SLOTS: usize = 4;
/// `Inode.spill` value for "data is inline".
const NO_SPILL: u8 = 0xFF;
/// K20 (P0-1): 28 -> 64 bytes per path component — real file names
/// ("aegis-session-2026-11-26.log") no longer bounce off NAME_MAX.
/// Measured cost: +36 B per inode, +4.6 KiB over the table.
pub const NAME_MAX: usize = 64;
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
pub const ROOT_REF: InodeRef = InodeRef {
    id: ROOT_ID,
    generation: 1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    File,
    Dir,
    /// Phase 6 S2: a device node (devfs) — caller-INDEPENDENT
    /// semantics, owned here: Null discards writes and reads EOF;
    /// Zero discards writes and reads an endless stream of zeros.
    Device(DevKind),
    /// Phase 6 S2: a procfs node — the CONTENT is caller-dependent
    /// (whose domain, whose credentials), so the VFS only names the
    /// node; the policy EXECUTOR generates the text at read time
    /// (it is the component that knows the reading domain).
    Proc(ProcNode),
}

/// devfs device flavors (Phase 6 S2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevKind {
    /// /dev/null: writes discard, reads answer EOF.
    Null,
    /// /dev/zero: writes discard, reads answer zeros forever.
    Zero,
}

/// procfs node flavors (Phase 6 S2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcNode {
    /// /proc/self: the READING domain's identity (id, uid, gid) —
    /// one shared node, one honest answer per caller.
    Status,
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
    /// K22: `NO_SPILL` while the bytes live in `data`; otherwise the
    /// index of the `Vfs::spills` slot holding the whole file.
    spill: u8,
}

pub struct Vfs {
    inodes: [Option<Inode>; MAX_INODES],
    /// F10: per-slot generation counter — bumped on every allocation
    /// into the slot, so stale references never alias new occupants.
    generations: [u32; MAX_INODES],
    /// K22: the large-file side table (see `LARGE_FILE_MAX`). A slot
    /// is owned by exactly the inode whose `spill` names it, so
    /// unlink/replace free it with the inode — no separate free list.
    spills: [[u8; LARGE_FILE_MAX]; LARGE_FILE_SLOTS],
}

impl Vfs {
    pub fn new() -> Self {
        let mut fs = Vfs {
            inodes: [None; MAX_INODES],
            generations: [0; MAX_INODES],
            spills: [[0; LARGE_FILE_MAX]; LARGE_FILE_SLOTS],
        };
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
            spill: NO_SPILL,
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

    /// K22: the first spill slot no live inode owns, or `None` when
    /// every slot is taken (the caller answers `NoSpace`).
    fn free_slot(inodes: &[Option<Inode>; MAX_INODES]) -> Option<u8> {
        (0..LARGE_FILE_SLOTS as u8).find(|s| !inodes.iter().flatten().any(|i| i.spill == *s))
    }

    /// K22: the bytes of `inode` — inline, or its spill slot.
    fn bytes_of<'a>(
        spills: &'a [[u8; LARGE_FILE_MAX]; LARGE_FILE_SLOTS],
        inode: &'a Inode,
    ) -> &'a [u8] {
        if inode.spill == NO_SPILL {
            &inode.data
        } else {
            &spills[usize::from(inode.spill)]
        }
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
        Ok(InodeRef {
            id: cur,
            generation,
        })
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
            spill: NO_SPILL,
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
            spill: NO_SPILL,
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
        let target = self.child_by_name(parent, name).ok_or(VfsError::NotFound)?;
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

    /// rename(2): re-parent an inode. K21 (the package manager's
    /// commit primitive). POSIX subset: a file destination is
    /// REPLACED; a directory destination is refused (EISDIR — this
    /// kernel does not fold rmdir into rename); a directory cannot
    /// move into its own subtree (EINVAL folds into EISDIR here,
    /// the errno subset's documented approximation); the moved
    /// inode KEEPS its identity (same id, same generation) — stale
    /// InodeRefs stay valid across the rename, exactly the contract
    /// open file descriptors rely on.
    ///
    /// Permission model: write+exec on BOTH parents (the source
    /// parent for removal, the destination parent for creation) —
    /// the union of unlink's and create's rules, so rename grants
    /// nothing either alone would not.
    pub fn rename(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
        from: &str,
        to: &str,
        creds: Credentials,
    ) -> Result<InodeRef, VfsError> {
        let (src_parent, src_name) = self.resolve_parent(root, cwd, from, creds)?;
        self.check_access(src_parent, creds, Access::Write)?;
        self.check_access(src_parent, creds, Access::Exec)?;
        let src = self
            .child_by_name(src_parent, src_name)
            .ok_or(VfsError::NotFound)?;
        if src == ROOT_ID {
            return Err(VfsError::PermissionDenied);
        }
        let (dst_parent, dst_name) = self.resolve_parent(root, cwd, to, creds)?;
        self.check_access(dst_parent, creds, Access::Write)?;
        self.check_access(dst_parent, creds, Access::Exec)?;
        if dst_name.len() > NAME_MAX {
            return Err(VfsError::NameTooLong);
        }
        // A directory moving into its own subtree would orphan the
        // subtree: walk the destination parent chain to the root and
        // refuse if the moved node is on it.
        if self.inode(src)?.kind == InodeKind::Dir {
            let mut cur = dst_parent;
            loop {
                if cur == src {
                    return Err(VfsError::IsADirectory);
                }
                if cur == ROOT_ID {
                    break;
                }
                cur = self.inode(cur)?.parent;
            }
        }
        // Destination handling: same node is a POSIX no-op success;
        // a directory destination is refused; a file destination is
        // replaced (its slot frees — generation discipline makes
        // every stale reference to it fail closed).
        if let Some(dst) = self.child_by_name(dst_parent, dst_name) {
            if dst == src {
                let generation = self.inode(src)?.generation;
                return Ok(InodeRef {
                    id: src,
                    generation,
                });
            }
            if self.inode(dst)?.kind == InodeKind::Dir {
                return Err(VfsError::IsADirectory);
            }
            self.inodes[dst as usize] = None;
        }
        let generation = self.inode(src)?.generation;
        {
            let node = self.inode_mut(src)?;
            node.parent = dst_parent;
            node.name = [0; NAME_MAX];
            node.name[..dst_name.len()].copy_from_slice(dst_name.as_bytes());
            node.name_len = dst_name.len();
        }
        Ok(InodeRef {
            id: src,
            generation,
        })
    }

    /// Whether a directory has any entries (no allocation).
    #[must_use]
    pub fn has_children(&self, dir: u32) -> bool {
        self.inodes.iter().flatten().any(|i| i.parent == dir)
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
        match inode.kind {
            InodeKind::File => {}
            // Phase 6 S2: device reads — Null is an instant EOF, Zero
            // fills whatever the caller asked (the fd cursor is
            // meaningless on an endless stream; it advances by n).
            InodeKind::Device(DevKind::Null) => {
                self.check_access(id, creds, Access::Read)?;
                return Ok(0);
            }
            InodeKind::Device(DevKind::Zero) => {
                self.check_access(id, creds, Access::Read)?;
                buf.fill(0);
                return Ok(buf.len());
            }
            // Proc content is caller-dependent: the EXECUTOR
            // intercepts Proc reads before this layer (the VFS does
            // not know the reading domain). Reaching here means a
            // caller bypassed the intercept — refuse, never fabricate.
            InodeKind::Proc(_) | InodeKind::Dir => {
                return Err(VfsError::IsADirectory);
            }
        }
        self.check_access(id, creds, Access::Read)?;
        if offset >= inode.size {
            return Ok(0); // at or past EOF
        }
        let avail = inode.size - offset;
        let n = buf.len().min(avail);
        buf[..n].copy_from_slice(&Self::bytes_of(&self.spills, inode)[offset..offset + n]);
        Ok(n)
    }

    /// F11(c): write at the fd's offset — existing bytes stay, the file
    /// only grows past them. Truncation is an explicit Open flag
    /// (`truncate`), never a side effect of writing. K22: a file that
    /// outgrows the inline window moves into a spill slot first (the
    /// inline bytes ride along); the capacity then is `LARGE_FILE_MAX`,
    /// and a gap between the old size and the offset is zeroed — a
    /// slot's previous tenant must never show through a sparse write.
    pub fn write_at(
        &mut self,
        r: InodeRef,
        creds: Credentials,
        offset: usize,
        bytes: &[u8],
    ) -> Result<usize, VfsError> {
        let id = self.live(r)?;
        match self.inode(id)?.kind {
            InodeKind::File => {}
            // Phase 6 S2: both device flavors discard writes — the
            // answer is the byte count (the write "succeeded").
            InodeKind::Device(_) => {
                self.check_access(id, creds, Access::Write)?;
                return Ok(bytes.len());
            }
            // procfs is read-only: a write answers EACCES.
            InodeKind::Proc(_) | InodeKind::Dir => {
                return Err(VfsError::IsADirectory);
            }
        }
        self.check_access(id, creds, Access::Write)?;
        let end = offset.saturating_add(bytes.len());
        let spilled = self
            .inodes
            .get(id as usize)
            .and_then(|s| s.as_ref())
            .is_some_and(|i| i.spill != NO_SPILL);
        // The capacity edge: nothing past the slot; an inline file
        // crossing the window needs a free spill slot.
        if end > LARGE_FILE_MAX {
            return Err(VfsError::NoSpace);
        }
        let free = if !spilled && end > FILE_DATA_MAX {
            Some(Self::free_slot(&self.inodes).ok_or(VfsError::NoSpace)?)
        } else {
            None
        };
        // Field-split borrows: the inode and the side table are
        // distinct fields of self.
        let Self {
            inodes,
            spills,
            generations: _,
        } = self;
        let slot = inodes
            .get_mut(id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(VfsError::NotFound)?;
        if let Some(free) = free {
            // Promote: the inline bytes ride along, the rest of the
            // slot starts clean.
            spills[usize::from(free)][..FILE_DATA_MAX].copy_from_slice(&slot.data);
            spills[usize::from(free)][FILE_DATA_MAX..].fill(0);
            slot.spill = free;
        }
        let data: &mut [u8] = if slot.spill == NO_SPILL {
            &mut slot.data
        } else {
            &mut spills[usize::from(slot.spill)]
        };
        if offset > slot.size {
            data[slot.size..offset].fill(0);
        }
        data[offset..end].copy_from_slice(bytes);
        if end > slot.size {
            slot.size = end;
        }
        Ok(bytes.len())
    }

    /// F11(c): explicit truncation (Open with the truncate flag).
    /// Phase 6 S2: install a device node (supervisor API — kmain /
    /// the Phase-7 init; never a SysRequest, so no ring-3 caller can
    /// mint a device). Mode 0o666: any caller may read or write the
    /// device flavors; the flavor's semantics do the rest.
    pub fn create_device(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
        dev: DevKind,
    ) -> Result<InodeRef, VfsError> {
        self.create_kind(root, cwd, path, creds, Mode(0o666), InodeKind::Device(dev))
    }

    /// Phase 6 S2: install a procfs node (supervisor API, as above).
    /// Mode 0o444: world-readable, never writable.
    pub fn create_proc_node(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
        node: ProcNode,
    ) -> Result<InodeRef, VfsError> {
        self.create_kind(root, cwd, path, creds, Mode(0o444), InodeKind::Proc(node))
    }

    /// The shared creator behind create/create_device/create_proc_node.
    fn create_kind(
        &mut self,
        root: InodeRef,
        cwd: InodeRef,
        path: &str,
        creds: Credentials,
        mode: Mode,
        kind: InodeKind,
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
            kind,
            uid: creds.uid,
            gid: creds.gid,
            mode,
            parent,
            name: nb,
            name_len: name.len(),
            data: [0; FILE_DATA_MAX],
            size: 0,
            spill: NO_SPILL,
        });
        Ok(InodeRef { id, generation })
    }

    /// F11(c): explicit truncation (Open with the truncate flag). K22:
    /// an emptied file is inline again — its spill slot goes free with
    /// the bytes it held.
    pub fn truncate(&mut self, r: InodeRef, creds: Credentials) -> Result<(), VfsError> {
        let id = self.live(r)?;
        if self.inode(id)?.kind != InodeKind::File {
            return Err(VfsError::IsADirectory);
        }
        self.check_access(id, creds, Access::Write)?;
        let inode = self.inode_mut(id)?;
        inode.size = 0;
        inode.spill = NO_SPILL;
        Ok(())
    }

    #[must_use]
    pub fn size_of(&self, r: InodeRef) -> Option<usize> {
        self.live(r).ok().and_then(|id| {
            self.inodes
                .get(id as usize)
                .and_then(|s| s.as_ref())
                .map(|i| i.size)
        })
    }

    #[must_use]
    pub fn kind_of(&self, r: InodeRef) -> Option<InodeKind> {
        self.live(r).ok().and_then(|id| {
            self.inodes
                .get(id as usize)
                .and_then(|s| s.as_ref())
                .map(|i| i.kind)
        })
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

    /// List a directory's children as NUL-separated names into `out`
    /// from the first entry (the one-shot form; see `list_dir_at`).
    pub fn list_dir(&self, dir: u32, out: &mut [u8]) -> Result<usize, VfsError> {
        self.list_dir_at(dir, out, 0).map(|(n, _)| n)
    }

    /// K22: list a directory's children as NUL-separated names into
    /// `out`, resuming at table slot `start`; returns the byte count
    /// written and the cursor for the next call. A partial name is a
    /// lie, so a child that does not fit whole is left for the next
    /// call. The cursor is a slot index (stable while nothing is
    /// created or unlinked in the directory): a cursor at or past the
    /// last child writes nothing — 0 is the caller's end-of-list.
    pub fn list_dir_at(
        &self,
        dir: u32,
        out: &mut [u8],
        start: u32,
    ) -> Result<(usize, u32), VfsError> {
        let node = self.inode(dir)?;
        if node.kind != InodeKind::Dir {
            return Err(VfsError::NotADirectory);
        }
        let mut n = 0usize;
        let mut next = start.min(MAX_INODES as u32);
        for (i, slot) in self.inodes.iter().enumerate() {
            if (i as u32) < start {
                continue; // served on an earlier call
            }
            // The root is its own parent (Vfs::new): listing a
            // directory never lists the directory itself.
            if (i as u32) != dir {
                if let Some(child) = slot {
                    if child.parent == dir {
                        let need = child.name_len + 1;
                        if n + need > out.len() {
                            break; // does not fit whole: left for the next call
                        }
                        out[n..n + child.name_len].copy_from_slice(&child.name[..child.name_len]);
                        out[n + child.name_len] = 0;
                        n += need;
                    }
                }
            }
            next = i as u32 + 1;
        }
        Ok((n, next))
    }

    /// K22: resolve a listing handle's reference to a live directory
    /// id. A stale (id, generation) pair fails closed (StaleInode —
    /// never the directory that may have reused the slot) and a file
    /// answers NotADirectory.
    pub fn dir_of(&self, r: InodeRef) -> Result<u32, VfsError> {
        let id = self.live(r)?;
        if self.inode(id)?.kind != InodeKind::Dir {
            return Err(VfsError::NotADirectory);
        }
        Ok(id)
    }

    /// K22: how many spill slots are in use (introspection for the
    /// capacity tests and the boot's marker).
    #[must_use]
    pub fn spill_slots_used(&self) -> usize {
        self.inodes
            .iter()
            .flatten()
            .filter(|i| i.spill != NO_SPILL)
            .count()
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
    const USER: Credentials = Credentials {
        uid: 1000,
        gid: 1000,
    };
    const GROUPIE: Credentials = Credentials {
        uid: 2000,
        gid: 1000,
    };
    const STRANGER: Credentials = Credentials {
        uid: 3000,
        gid: 3000,
    };

    fn fs_with(user_dir: bool) -> Vfs {
        let mut fs = Vfs::new();
        // /pub: world-readable dir; /home: owned by user 1000.
        fs.mkdir(ROOT_REF, ROOT_REF, "/pub", ROOT_CREDS, Mode(0o777))
            .unwrap();
        fs.mkdir(ROOT_REF, ROOT_REF, "/home", ROOT_CREDS, Mode(0o777))
            .unwrap();
        fs.create(ROOT_REF, ROOT_REF, "/home/notes.txt", USER, Mode(0o644))
            .unwrap();
        if user_dir {
            fs.mkdir(ROOT_REF, ROOT_REF, "/home/alice", USER, Mode(0o750))
                .unwrap();
        }
        fs
    }

    #[test]
    fn root_exists_and_resolves() {
        let fs = Vfs::new();
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, "/", ROOT_CREDS),
            Ok(ROOT_REF)
        );
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, ".", ROOT_CREDS),
            Ok(ROOT_REF)
        );
        assert_eq!(
            fs.resolve(ROOT_REF, ROOT_REF, "/..", ROOT_CREDS),
            Ok(ROOT_REF)
        );
    }

    /// Phase 7: `list_dir` — the shell's `ls` surface. Names land
    /// NUL-separated, the root never lists itself (it is its own
    /// parent), the bound stops whole children, and a file fd's inode
    /// refuses with NotADirectory.
    #[test]
    fn list_dir_names_children_nul_separated() {
        let mut fs = Vfs::new();
        fs.mkdir(ROOT_REF, ROOT_REF, "/pub", ROOT_CREDS, Mode(0o777))
            .unwrap();
        fs.mkdir(ROOT_REF, ROOT_REF, "/tmp", ROOT_CREDS, Mode(0o777))
            .unwrap();
        fs.create(ROOT_REF, ROOT_REF, "/pub/data.txt", USER, Mode(0o644))
            .unwrap();
        let mut out = [0u8; 64];
        let n = fs.list_dir(ROOT_ID, &mut out).unwrap();
        let listing = &out[..n];
        // NUL-separated: "pub\0tmp\0" (creation order is not promised —
        // both names must appear, each exactly once, whole).
        assert_eq!(n, 8, "two 3-char names + two NULs: {listing:?}");
        let mut names: Vec<&[u8]> = listing.split(|b| *b == 0).collect();
        names.pop(); // the trailing NUL's empty tail
        let mut got: Vec<Vec<u8>> = names.iter().map(|s| s.to_vec()).collect();
        got.sort();
        assert_eq!(got, vec![b"pub".to_vec(), b"tmp".to_vec()]);

        // The children of /pub: exactly data.txt.
        let pub_id = fs
            .resolve(ROOT_REF, ROOT_REF, "/pub", ROOT_CREDS)
            .unwrap()
            .id;
        let n2 = fs.list_dir(pub_id, &mut out).unwrap();
        assert_eq!(&out[..n2], b"data.txt\0");

        // The bound: an out that cannot hold a child whole skips it —
        // never a partial name. "data.txt\0" needs 9; give it 8.
        let mut small = [0u8; 8];
        assert_eq!(fs.list_dir(pub_id, &mut small).unwrap(), 0);

        // A file's inode refuses (the arm translates ENOTDIR).
        let f = fs
            .resolve(ROOT_REF, ROOT_REF, "/pub/data.txt", USER)
            .unwrap();
        assert_eq!(fs.list_dir(f.id, &mut out), Err(VfsError::NotADirectory));
    }

    /// K22: the listing cursor. A buffer too small for the whole
    /// directory is filled with whole names only; the returned cursor
    /// resumes exactly at the first name that did not fit; a cursor at
    /// the end writes nothing (the caller's end-of-list), forever.
    #[test]
    fn list_dir_at_resumes_where_the_last_call_stopped() {
        let mut fs = Vfs::new();
        fs.mkdir(ROOT_REF, ROOT_REF, "/d", ROOT_CREDS, Mode(0o755))
            .unwrap();
        for i in 0..5 {
            fs.create(
                ROOT_REF,
                ROOT_REF,
                &format!("/d/file{i}"),
                ROOT_CREDS,
                Mode(0o644),
            )
            .unwrap();
        }
        let dir = fs.resolve(ROOT_REF, ROOT_REF, "/d", ROOT_CREDS).unwrap().id;
        // "fileN\0" is 6 bytes: a 13-byte buffer holds two whole names.
        let mut whole = [0u8; 64];
        let n = fs.list_dir(dir, &mut whole).unwrap();
        let mut walked = Vec::new();
        let mut cursor = 0u32;
        let mut calls = 0;
        loop {
            let mut chunk = [0u8; 13];
            let (got, next) = fs.list_dir_at(dir, &mut chunk, cursor).unwrap();
            assert!(got % 6 == 0, "whole names only, saw {got} bytes");
            walked.extend_from_slice(&chunk[..got]);
            calls += 1;
            assert!(calls < 10, "the walk must terminate");
            if got == 0 {
                assert_eq!(next, MAX_INODES as u32, "the end cursor is past the table");
                break;
            }
            assert_ne!(next, cursor, "the cursor must advance on a non-empty call");
            cursor = next;
        }
        // 5 names / 2 per call = 3 serving calls + the terminating 0.
        assert_eq!(calls, 4);
        assert_eq!(walked, &whole[..n]);
        // At the end cursor: nothing, and the cursor stays put.
        assert_eq!(
            fs.list_dir_at(dir, &mut [0u8; 64], cursor).unwrap(),
            (0, MAX_INODES as u32)
        );
        // A hostile cursor is clamped, never indexed out of bounds.
        assert_eq!(
            fs.list_dir_at(dir, &mut [0u8; 64], u32::MAX).unwrap(),
            (0, MAX_INODES as u32)
        );
        // The walk is idempotent from 0: a second full walk matches.
        let mut again = Vec::new();
        let mut cursor = 0u32;
        loop {
            let mut chunk = [0u8; 7];
            let (got, next) = fs.list_dir_at(dir, &mut chunk, cursor).unwrap();
            again.extend_from_slice(&chunk[..got]);
            cursor = next;
            if got == 0 {
                break;
            }
        }
        assert_eq!(again, walked);
        // Not a directory → the same refusal on the cursor form.
        let f = fs
            .resolve(ROOT_REF, ROOT_REF, "/d/file0", ROOT_CREDS)
            .unwrap();
        assert_eq!(
            fs.list_dir_at(f.id, &mut [0u8; 8], 0),
            Err(VfsError::NotADirectory)
        );
        assert_eq!(fs.dir_of(f), Err(VfsError::NotADirectory));
        assert_eq!(
            fs.dir_of(InodeRef {
                id: f.id,
                generation: 99
            }),
            Err(VfsError::StaleInode)
        );
        assert_eq!(fs.dir_of(ROOT_REF), Ok(ROOT_ID));
    }

    /// K22: a file that outgrows the inline window moves into a spill
    /// slot with its bytes intact, reads back whole through the
    /// window, and an emptied file releases the slot again.
    #[test]
    fn large_file_promotes_into_a_spill_slot_and_back() {
        let mut fs = Vfs::new();
        assert_eq!(fs.spill_slots_used(), 0);
        let id = fs
            .create(ROOT_REF, ROOT_REF, "/journal", ROOT_CREDS, Mode(0o600))
            .unwrap();
        assert_eq!(fs.spill_slots_used(), 0, "inline files take no slot");
        // The PM's journal shape: a run of small appends crossing the
        // window (17-byte and 525-byte records).
        let mut offset = 0usize;
        let mut body: Vec<u8> = Vec::new();
        for len in [17usize, 525, 525, 525, 17, 525, 525, 17] {
            let rec: Vec<u8> = (0..len).map(|i| ((offset + i) % 253) as u8).collect();
            assert_eq!(fs.write_at(id, ROOT_CREDS, offset, &rec).unwrap(), len);
            offset += len;
            body.extend_from_slice(&rec);
        }
        assert_eq!(offset, 2676, "the walk really crossed the window");
        assert_eq!(fs.size_of(id), Some(offset));
        assert_eq!(fs.spill_slots_used(), 1, "the file moved into a slot");
        let mut back = vec![0u8; offset];
        assert_eq!(
            fs.read_by_id_at(id, ROOT_CREDS, 0, &mut back).unwrap(),
            offset
        );
        assert_eq!(back, body);
        // Reads straddling the old window edge are seamless.
        let mut edge = [0u8; 8];
        fs.read_by_id_at(id, ROOT_CREDS, 1020, &mut edge).unwrap();
        assert_eq!(&edge, &body[1020..1028]);
        // Overwrite inside the slot, re-read.
        assert_eq!(fs.write_at(id, ROOT_CREDS, 2000, &[9u8; 16]).unwrap(), 16);
        fs.read_by_id_at(id, ROOT_CREDS, 2000, &mut edge).unwrap();
        assert_eq!(edge, [9u8; 8]);
        // The slot's ceiling is the honest ENOSPC now.
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, LARGE_FILE_MAX, &[1u8]),
            Err(VfsError::NoSpace)
        );
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, 0, &[0u8; LARGE_FILE_MAX + 1]),
            Err(VfsError::NoSpace)
        );
        // Truncate: empty AND inline again — the slot is free.
        fs.truncate(id, ROOT_CREDS).unwrap();
        assert_eq!(fs.size_of(id), Some(0));
        assert_eq!(fs.spill_slots_used(), 0);
        assert_eq!(fs.read_by_id_at(id, ROOT_CREDS, 0, &mut edge).unwrap(), 0);
    }

    /// K22: exactly `LARGE_FILE_SLOTS` large files at once; the next
    /// one answers NoSpace at the window edge (its inline bytes stay
    /// intact — a refused write is a no-op), and an unlink frees the
    /// slot for it.
    #[test]
    fn spill_slots_run_out_then_free_on_unlink() {
        let mut fs = Vfs::new();
        let over = [7u8; FILE_DATA_MAX + 1];
        for i in 0..LARGE_FILE_SLOTS {
            let id = fs
                .create(
                    ROOT_REF,
                    ROOT_REF,
                    &format!("/big{i}"),
                    ROOT_CREDS,
                    Mode(0o644),
                )
                .unwrap();
            assert_eq!(fs.write_at(id, ROOT_CREDS, 0, &over).unwrap(), over.len());
            assert_eq!(fs.spill_slots_used(), i + 1);
        }
        let fifth = fs
            .create(ROOT_REF, ROOT_REF, "/fifth", ROOT_CREDS, Mode(0o644))
            .unwrap();
        assert_eq!(
            fs.write_at(fifth, ROOT_CREDS, 0, &over),
            Err(VfsError::NoSpace)
        );
        // Inline-sized writes still work on the refused file.
        assert_eq!(fs.write_at(fifth, ROOT_CREDS, 0, &[3u8; 100]).unwrap(), 100);
        assert_eq!(fs.size_of(fifth), Some(100));
        // The refused write left nothing behind at the window edge.
        let mut probe = [0u8; 4];
        assert_eq!(
            fs.read_by_id_at(fifth, ROOT_CREDS, 100, &mut probe)
                .unwrap(),
            0
        );
        // Free one slot: the fifth file's retry succeeds.
        fs.unlink(ROOT_REF, ROOT_REF, "/big2", ROOT_CREDS).unwrap();
        assert_eq!(fs.spill_slots_used(), LARGE_FILE_SLOTS - 1);
        assert_eq!(
            fs.write_at(fifth, ROOT_CREDS, 0, &over).unwrap(),
            over.len()
        );
        assert_eq!(fs.spill_slots_used(), LARGE_FILE_SLOTS);
        // rename over a spilled destination frees ITS slot with it.
        fs.create(ROOT_REF, ROOT_REF, "/fresh", ROOT_CREDS, Mode(0o644))
            .unwrap();
        fs.rename(ROOT_REF, ROOT_REF, "/fresh", "/big0", ROOT_CREDS)
            .unwrap();
        assert_eq!(fs.spill_slots_used(), LARGE_FILE_SLOTS - 1);
        // A brand-new file can take the slot.
        let again = fs
            .create(ROOT_REF, ROOT_REF, "/again", ROOT_CREDS, Mode(0o644))
            .unwrap();
        assert_eq!(
            fs.write_at(again, ROOT_CREDS, 0, &over).unwrap(),
            over.len()
        );
    }

    /// K22: a recycled slot must never show its previous tenant through
    /// a sparse write — every byte below `size` was written or zeroed.
    #[test]
    fn a_recycled_spill_slot_never_leaks_the_previous_tenant() {
        let mut fs = Vfs::new();
        let secret = fs
            .create(ROOT_REF, ROOT_REF, "/secret", ROOT_CREDS, Mode(0o600))
            .unwrap();
        fs.write_at(secret, ROOT_CREDS, 0, &[0xAB; 2048]).unwrap();
        fs.unlink(ROOT_REF, ROOT_REF, "/secret", ROOT_CREDS)
            .unwrap();
        assert_eq!(fs.spill_slots_used(), 0);
        let heir = fs
            .create(ROOT_REF, ROOT_REF, "/heir", ROOT_CREDS, Mode(0o644))
            .unwrap();
        // One byte, then a byte far past the window: the gap (and the
        // slot's tail) must read as zeros, never as 0xAB.
        fs.write_at(heir, ROOT_CREDS, 0, &[1u8]).unwrap();
        fs.write_at(heir, ROOT_CREDS, 1500, &[2u8]).unwrap();
        let mut back = [0u8; 1501];
        assert_eq!(
            fs.read_by_id_at(heir, ROOT_CREDS, 0, &mut back).unwrap(),
            1501
        );
        assert_eq!(back[0], 1);
        assert_eq!(back[1500], 2);
        assert!(back[1..1500].iter().all(|&b| b == 0), "no previous tenant");
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
        let (kind, size, uid, gid, mode) =
            fs.stat(ROOT_REF, ROOT_REF, "/pub/data.txt", USER).unwrap();
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
        let a = fs
            .resolve(ROOT_REF, ROOT_REF, "/pub/../home/./notes.txt", USER)
            .unwrap();
        let b = fs
            .resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER)
            .unwrap();
        assert_eq!(a, b);
        // Repeated and trailing slashes.
        let c = fs
            .resolve(ROOT_REF, ROOT_REF, "//home//notes.txt//", USER)
            .unwrap();
        assert_eq!(c, b);
    }

    #[test]
    fn relative_paths_resolve_from_cwd() {
        let fs = fs_with(false);
        let home = fs.resolve(ROOT_REF, ROOT_REF, "/home", USER).unwrap();
        let a = fs.resolve(ROOT_REF, home, "notes.txt", USER).unwrap();
        let b = fs
            .resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER)
            .unwrap();
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
            fs.mkdir(
                ROOT_REF,
                ROOT_REF,
                "/home/notes.txt/sub",
                ROOT_CREDS,
                Mode(0o755)
            ),
            Err(VfsError::NotADirectory)
        );
    }

    #[test]
    fn exec_bit_required_to_traverse_directory() {
        let mut fs = Vfs::new();
        // /vault: readable but not executable for others (can list stat on
        // the dir itself, cannot enter).
        fs.mkdir(ROOT_REF, ROOT_REF, "/vault", ROOT_CREDS, Mode(0o644))
            .unwrap();
        fs.create(
            ROOT_REF,
            ROOT_REF,
            "/vault/secret.txt",
            ROOT_CREDS,
            Mode(0o600),
        )
        .unwrap();
        // Owner can traverse.
        assert!(fs
            .resolve(ROOT_REF, ROOT_REF, "/vault/secret.txt", ROOT_CREDS)
            .is_ok());
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
        fs.mkdir(ROOT_REF, ROOT_REF, "/d", ROOT_CREDS, Mode(0o777))
            .unwrap();
        let id = fs
            .create(ROOT_REF, ROOT_REF, "/d/f", USER, Mode(0o640))
            .unwrap();
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
        fs.mkdir(ROOT_REF, ROOT_REF, "/ro", ROOT_CREDS, Mode(0o755))
            .unwrap();
        fs.chmod(ROOT_REF, ROOT_REF, "/ro", USER, Mode(0o555))
            .unwrap_err(); // not owner
        fs.chmod(ROOT_REF, ROOT_REF, "/ro", ROOT_CREDS, Mode(0o555))
            .unwrap();
        assert_eq!(
            fs.create(ROOT_REF, ROOT_REF, "/ro/f.txt", USER, Mode(0o644)),
            Err(VfsError::PermissionDenied)
        );
        // Root creates fine (bypass).
        assert!(fs
            .create(ROOT_REF, ROOT_REF, "/ro/f.txt", ROOT_CREDS, Mode(0o644))
            .is_ok());
    }

    #[test]
    fn chroot_clamps_dotdot_at_root() {
        let fs = fs_with(true);
        let alice = fs.resolve(ROOT_REF, ROOT_REF, "/home/alice", USER).unwrap();
        // Chroot to /home/alice: ".." cannot climb above it.
        assert_eq!(fs.resolve(alice, alice, "..", USER), Ok(alice));
        assert_eq!(fs.resolve(alice, alice, "../../..", USER), Ok(alice));
        assert_eq!(
            fs.resolve(alice, alice, "../../../home/notes.txt", USER),
            Err(VfsError::NotFound)
        );
        // Absolute paths are also relative to the chroot root.
        assert_eq!(
            fs.resolve(alice, alice, "/home/notes.txt", USER),
            Err(VfsError::NotFound)
        );
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
        fs.unlink(ROOT_REF, ROOT_REF, "/home/notes.txt", USER)
            .unwrap();
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
        fs.mkdir(ROOT_REF, ROOT_REF, "/ro", ROOT_CREDS, Mode(0o555))
            .unwrap();
        fs.create(ROOT_REF, ROOT_REF, "/ro/f", ROOT_CREDS, Mode(0o644))
            .unwrap();
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
        fs.chmod(ROOT_REF, ROOT_REF, "/home/notes.txt", USER, Mode(0o666))
            .unwrap();
        let id = fs
            .resolve(ROOT_REF, ROOT_REF, "/home/notes.txt", USER)
            .unwrap();
        assert!(fs.write_at(id, STRANGER, 0, b"now").is_ok());
        // Root can chmod anything.
        fs.chmod(
            ROOT_REF,
            ROOT_REF,
            "/home/notes.txt",
            ROOT_CREDS,
            Mode(0o600),
        )
        .unwrap();
        assert_eq!(
            fs.write_at(id, STRANGER, 0, b"nope"),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn oversize_write_and_name_rejected() {
        let mut fs = Vfs::new();
        let id = fs
            .create(ROOT_REF, ROOT_REF, "/f", ROOT_CREDS, Mode(0o644))
            .unwrap();
        // K22: one byte past the INLINE window is no longer the edge —
        // the file promotes into a spill slot and the write lands.
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, 0, &[0u8; FILE_DATA_MAX + 1])
                .unwrap(),
            FILE_DATA_MAX + 1
        );
        // The spill slot's ceiling is the refusal edge.
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, 0, &[0u8; LARGE_FILE_MAX + 1]),
            Err(VfsError::NoSpace)
        );
        // Exactly capacity is fine.
        assert_eq!(
            fs.write_at(id, ROOT_CREDS, 0, &[1u8; LARGE_FILE_MAX])
                .unwrap(),
            LARGE_FILE_MAX
        );
        // Long name.
        let long = "a".repeat(NAME_MAX + 1);
        assert_eq!(
            fs.create(
                ROOT_REF,
                ROOT_REF,
                &format!("/{}", long),
                ROOT_CREDS,
                Mode(0o644)
            ),
            Err(VfsError::NameTooLong)
        );
    }

    #[test]
    fn inode_table_fills_at_max() {
        let mut fs = Vfs::new();
        // Root + 1 dir used; fill the rest.
        fs.mkdir(ROOT_REF, ROOT_REF, "/d", ROOT_CREDS, Mode(0o755))
            .unwrap();
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
        assert!(fs
            .create(ROOT_REF, ROOT_REF, "/d/again", ROOT_CREDS, Mode(0o644))
            .is_ok());
    }

    /// F11(a): `..` requires the x bit on the directory being LEFT —
    /// the old resolution climbed without any check at all. A domain
    /// sitting in /nx/inner (cwd granted) cannot climb out of /nx when
    /// /nx carries no x bit for it.
    #[test]
    fn dotdot_requires_x_bit_on_the_directory_being_left() {
        let mut fs = Vfs::new();
        fs.mkdir(ROOT_REF, ROOT_REF, "/nx", ROOT_CREDS, Mode(0o644))
            .unwrap();
        fs.mkdir(ROOT_REF, ROOT_REF, "/nx/inner", ROOT_CREDS, Mode(0o755))
            .unwrap();
        let inner = fs
            .resolve(ROOT_REF, ROOT_REF, "/nx/inner", ROOT_CREDS)
            .unwrap();
        // One ".." leaves inner (x on inner: fine) and lands on /nx.
        assert_eq!(
            fs.resolve(ROOT_REF, inner, "..", USER),
            Ok(fs.resolve(ROOT_REF, ROOT_REF, "/nx", ROOT_CREDS).unwrap())
        );
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

    /// Phase 6 S1: a tmpfs file is a real file — a full 1 KiB block of
    /// content round-trips byte-for-byte (the round-J cap was 128
    /// bytes — a real boot root holds files that do not fit in a
    /// serial line; the pin is ABSOLUTE so shrinking the window is a
    /// red test, not a silent regression).
    #[test]
    fn block_sized_file_roundtrips() {
        const BLOCK: usize = 1024;
        let mut fs = Vfs::new();
        let id = fs
            .create(ROOT_REF, ROOT_REF, "/big", ROOT_CREDS, Mode(0o644))
            .unwrap();
        let body: Vec<u8> = (0..BLOCK).map(|i| (i % 251) as u8).collect();
        assert_eq!(fs.write_at(id, ROOT_CREDS, 0, &body).unwrap(), BLOCK);
        let mut back = [0u8; BLOCK];
        assert_eq!(
            fs.read_by_id_at(id, ROOT_CREDS, 0, &mut back).unwrap(),
            BLOCK
        );
        assert_eq!(&back, body.as_slice());
        // EOF past the end; offset reads inside.
        assert_eq!(
            fs.read_by_id_at(id, ROOT_CREDS, BLOCK, &mut back).unwrap(),
            0
        );
        assert_eq!(
            fs.read_by_id_at(id, ROOT_CREDS, BLOCK - 10, &mut back[..5])
                .unwrap(),
            5
        );
        assert_eq!(fs.size_of(id), Some(BLOCK));
    }
}
