//! Per-domain file descriptor table (Unix semantics in miniature).
//!
//! - `alloc` returns the *lowest* free descriptor, like Linux.
//! - `replace_at` implements dup2 semantics: the target is closed silently
//!   if open, and the new target installed.
//! - Descriptors are plain small integers and are reused after close
//!   (this is the one place we deliberately do NOT use generation counters:
//!   fd numbers are a per-domain namespace, and stale-fd bugs are the
//!   caller's race, exactly as in Unix).

pub const MAX_FDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdTarget {
    /// VFS inode, with `pos` as the file cursor.
    File(crate::vfs::InodeRef),
    /// Reading end of pipe id.
    PipeRead(u32),
    /// Writing end of pipe id.
    PipeWrite(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdEntry {
    pub target: FdTarget,
    /// Read/write cursor for file targets (ignored for pipes).
    pub pos: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdError {
    TableFull,
    /// Descriptor index outside `0..MAX_FDS`.
    OutOfRange(u8),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FdTable {
    slots: [Option<FdEntry>; MAX_FDS],
}

impl FdTable {
    pub const fn new() -> Self {
        FdTable { slots: [None; MAX_FDS] }
    }

    /// Allocate the lowest free descriptor (Linux behavior).
    pub fn alloc(&mut self, target: FdTarget) -> Result<u8, FdError> {
        for i in 0..MAX_FDS {
            if self.slots[i].is_none() {
                self.slots[i] = Some(FdEntry { target, pos: 0 });
                return Ok(i as u8);
            }
        }
        Err(FdError::TableFull)
    }

    /// dup2 semantics: install `target` at exactly `fd`, closing any
    /// descriptor currently there. Returns the old entry if one existed.
    pub fn replace_at(&mut self, fd: u8, target: FdTarget) -> Result<Option<FdEntry>, FdError> {
        if fd as usize >= MAX_FDS {
            return Err(FdError::OutOfRange(fd));
        }
        let old = self.slots[fd as usize].take();
        self.slots[fd as usize] = Some(FdEntry { target, pos: 0 });
        Ok(old)
    }

    #[must_use]
    pub fn get(&self, fd: u8) -> Option<FdEntry> {
        if fd as usize >= MAX_FDS {
            return None;
        }
        self.slots[fd as usize]
    }

    /// Mutable access for cursor updates (read/write advance `pos`).
    pub fn get_mut(&mut self, fd: u8) -> Option<&mut FdEntry> {
        if fd as usize >= MAX_FDS {
            return None;
        }
        self.slots[fd as usize].as_mut()
    }

    /// Close a descriptor; returns the entry if it was open (EBADF → None).
    pub fn close(&mut self, fd: u8) -> Option<FdEntry> {
        if fd as usize >= MAX_FDS {
            return None;
        }
        self.slots[fd as usize].take()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len() == MAX_FDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(i: u32) -> FdTarget {
        FdTarget::File(crate::vfs::InodeRef { id: i, generation: 1 })
    }

    #[test]
    fn alloc_returns_lowest_free_first() {
        let mut t = FdTable::new();
        assert_eq!(t.alloc(file(1)).unwrap(), 0);
        assert_eq!(t.alloc(file(2)).unwrap(), 1);
        assert_eq!(t.alloc(file(3)).unwrap(), 2);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn close_then_reuse_reuses_same_index() {
        let mut t = FdTable::new();
        t.alloc(file(1)).unwrap();
        t.alloc(file(2)).unwrap();
        t.close(0).unwrap();
        // Linux reuses the lowest closed descriptor.
        assert_eq!(t.alloc(file(9)).unwrap(), 0);
        assert_eq!(t.get(0).unwrap().target, file(9));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn get_and_close_invalid_fds_return_none() {
        let mut t = FdTable::new();
        assert_eq!(t.get(0), None);
        assert_eq!(t.close(0), None);
        assert_eq!(t.get(MAX_FDS as u8), None);
        assert_eq!(t.close(MAX_FDS as u8), None);
        assert_eq!(t.get(255), None);
        assert!(t.is_empty());
    }

    #[test]
    fn replace_at_implements_dup2() {
        let mut t = FdTable::new();
        t.alloc(file(1)).unwrap(); // fd 0
        let old = t.replace_at(0, file(2)).unwrap();
        assert_eq!(old.unwrap().target, file(1)); // old silently closed
        assert_eq!(t.get(0).unwrap().target, file(2));
        // dup2 onto a free descriptor also works.
        assert!(t.replace_at(5, file(3)).unwrap().is_none());
        assert_eq!(t.get(5).unwrap().target, file(3));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn replace_at_out_of_range() {
        let mut t = FdTable::new();
        assert_eq!(
            t.replace_at(MAX_FDS as u8, file(1)),
            Err(FdError::OutOfRange(MAX_FDS as u8))
        );
        assert_eq!(t.replace_at(200, file(1)), Err(FdError::OutOfRange(200)));
    }

    #[test]
    fn table_fills_at_max_fds() {
        let mut t = FdTable::new();
        for i in 0..MAX_FDS {
            assert_eq!(t.alloc(file(i as u32)).unwrap(), i as u8);
        }
        assert!(t.is_full());
        assert_eq!(t.alloc(file(99)), Err(FdError::TableFull));
        // Closing one slot frees exactly one.
        t.close(7).unwrap();
        assert_eq!(t.alloc(file(99)).unwrap(), 7);
    }

    #[test]
    fn file_cursor_tracks_and_updates() {
        let mut t = FdTable::new();
        t.alloc(file(42)).unwrap();
        {
            let e = t.get_mut(0).unwrap();
            assert_eq!(e.pos, 0);
            e.pos = 17;
        }
        assert_eq!(t.get(0).unwrap().pos, 17);
        // Cursor does not survive close/reopen of the same index.
        t.close(0).unwrap();
        t.alloc(file(42)).unwrap();
        assert_eq!(t.get(0).unwrap().pos, 0);
    }

    #[test]
    fn pipe_and_file_targets_coexist() {
        let mut t = FdTable::new();
        t.alloc(FdTarget::PipeRead(0)).unwrap();
        t.alloc(FdTarget::PipeWrite(0)).unwrap();
        t.alloc(FdTarget::File(crate::vfs::InodeRef { id: 3, generation: 1 })).unwrap();
        assert_eq!(t.get(0).unwrap().target, FdTarget::PipeRead(0));
        assert_eq!(t.get(1).unwrap().target, FdTarget::PipeWrite(0));
        assert_eq!(t.get(2).unwrap().target, FdTarget::File(crate::vfs::InodeRef { id: 3, generation: 1 }));
        assert_eq!(t.len(), 3);
    }
}
