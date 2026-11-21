//! ADR-0022: the process table — the Unix lifecycle layer over the
//! domain table.
//!
//! - **Pids never repeat within a boot**: a monotonic counter starting
//!   at [`FIRST_DYNAMIC_PID`] (supervisor-created static domains keep
//!   small ids; PID 1 is init by convention). A stale wait/kill
//!   handle therefore fails closed FOREVER instead of hitting an
//!   unrelated successor — monotonic ids replace generation counters.
//! - **A meta slot exists for every process, living or zombie**: the
//!   domain table bounds concurrency, the meta table bounds
//!   live+un-reaped (the slot a zombie holds is the slot a new child
//!   cannot take).
//! - **Orphans reparent to init** (PID 1); with no living init there
//!   is no reaper, so exits DISCARD their status instead of leaking a
//!   zombie no one can ever wait for.
//!
//! All of it is pure bookkeeping over `Copy` data in fixed arrays —
//! host-testable, `#![forbid(unsafe_code)]` intact.

use crate::profile::app_profile;
use crate::syscall::SyscallMask;
use crate::vfs::NAME_MAX;

/// PID 1 by convention: the process orphans reparent to.
pub const INIT_PID: u32 = 1;
/// Supervisor-created static domains live below this; the monotonic
/// allocator starts here.
pub const FIRST_DYNAMIC_PID: u32 = 100;
/// Living + zombie processes: bounded by the domain table.
pub const MAX_PROCS: usize = crate::MAX_DOMAINS;
/// Entries in the exec policy table (ADR-0022 D5).
pub const MAX_EXEC_ENTRIES: usize = 16;

/// How a process ended. `code` is the raw wait status word's payload
/// (the exit code, or the signal number for kills).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Normal,
    Killed(u8),
    Fault { vector: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub code: u32,
    pub reason: ExitReason,
}

impl ExitStatus {
    #[must_use]
    pub const fn normal(code: u32) -> Self {
        ExitStatus {
            code,
            reason: ExitReason::Normal,
        }
    }

    #[must_use]
    pub const fn killed(sig: u8) -> Self {
        ExitStatus {
            code: sig as u32,
            reason: ExitReason::Killed(sig),
        }
    }

    #[must_use]
    pub const fn fault(vector: u8) -> Self {
        ExitStatus {
            code: vector as u32,
            reason: ExitReason::Fault { vector },
        }
    }
}

/// One process's lifecycle record. `exit: None` = alive; `Some` =
/// zombie (domain gone, status waiting for a parent's wait).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcMeta {
    pub pid: u32,
    /// The parent's pid (0 = parentless: supervisor-created with no
    /// init alive, or detached because no reaper exists).
    pub parent: u32,
    pub exit: Option<ExitStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    /// The domain or meta table is full.
    TooManyProcesses,
    /// The monotonic pid counter is exhausted (typed refusal, never a
    /// wraparound).
    PidExhausted,
    /// The parent's per-profile child limit is reached.
    TooManyChildren { limit: u16 },
    /// No live process with this pid.
    UnknownProcess(u32),
    /// ADR-0022 D2: the spawn request is wider than the parent's
    /// CURRENT state (fail closed; counted as an escalation attempt).
    ProfileEscalation,
    /// fd_map entry with an out-of-range or duplicated child fd.
    FdMapInvalid { fd: u8 },
    /// fd_map entry whose parent fd is not open.
    FdNotOpen(u8),
    /// wait: the caller has no children at all (ECHILD).
    NoChildren,
    /// wait: children exist but none has exited yet (EAGAIN / would
    /// block — the pure core never blocks; the kernel runtime does).
    WouldBlock,
    /// wait: that pid is not a child of the caller.
    NotAChild(u32),
    /// fork/exec on a quarantined process: its surface is exit-only.
    Quarantined(u32),
    /// The exec policy table is full.
    PolicyTableFull,
}

/// The process table: pid allocator + meta slots.
impl Default for ProcTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct ProcTable {
    next_pid: u32,
    metas: [Option<ProcMeta>; MAX_PROCS],
}

impl ProcTable {
    pub const fn new() -> Self {
        ProcTable {
            next_pid: FIRST_DYNAMIC_PID,
            metas: [None; MAX_PROCS],
        }
    }

    /// Allocate the next never-reused pid. Typed refusal at the end
    /// of the counter — the one honest answer to a 4-billion-process
    /// boot.
    pub fn alloc_pid(&mut self) -> Result<u32, ProcError> {
        if self.next_pid == u32::MAX {
            return Err(ProcError::PidExhausted);
        }
        let pid = self.next_pid;
        self.next_pid += 1;
        Ok(pid)
    }

    /// The next pid the allocator would hand out (test visibility).
    #[must_use]
    pub fn peek_pid(&self) -> u32 {
        self.next_pid
    }

    /// Insert a meta; refuses when every slot is held by a living
    /// process or a zombie.
    pub fn insert(&mut self, meta: ProcMeta) -> Result<(), ProcError> {
        for slot in &mut self.metas {
            if slot.is_none() {
                *slot = Some(meta);
                return Ok(());
            }
        }
        Err(ProcError::TooManyProcesses)
    }

    #[must_use]
    pub fn get(&self, pid: u32) -> Option<ProcMeta> {
        self.metas.iter().flatten().find(|m| m.pid == pid).copied()
    }

    /// Remove a meta (a reaped zombie, a supervisor destroy, or a
    /// discarded orphan). Returns what was removed.
    pub fn remove(&mut self, pid: u32) -> Option<ProcMeta> {
        for slot in &mut self.metas {
            if matches!(slot, Some(m) if m.pid == pid) {
                return slot.take();
            }
        }
        None
    }

    /// Mutate a meta in place (reparenting, status recording).
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcMeta> {
        self.metas.iter_mut().flatten().find(|m| m.pid == pid)
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.metas.iter().flatten().count()
    }

    /// How many children (living + zombie) `parent` holds — the
    /// max_children limit counts both, so an un-reaped zombie still
    /// occupies its parent's budget.
    #[must_use]
    pub fn children_count(&self, parent: u32) -> usize {
        self.metas
            .iter()
            .flatten()
            .filter(|m| m.parent == parent)
            .count()
    }

    /// Every meta whose parent is `parent`, in slot order.
    pub fn children_of(&self, parent: u32) -> impl Iterator<Item = ProcMeta> + '_ {
        self.metas
            .iter()
            .flatten()
            .filter(move |m| m.parent == parent)
            .copied()
    }
}

/// ADR-0022 D5: an executable's declared surface — the init-owned
/// policy table that decides what a binary may keep across execve.
/// Unlisted paths get the app default: `app_profile()`'s mask and
/// AuditOnly monitoring (Enforce is opt-in per binary).
#[derive(Clone, Copy)]
pub struct ExecPolicyEntry {
    pub path: [u8; NAME_MAX],
    pub path_len: usize,
    pub mask: SyscallMask,
    pub enforce: Option<bool>,
}

impl ExecPolicyEntry {
    #[must_use]
    pub fn path(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

impl Default for ExecPolicyTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct ExecPolicyTable {
    entries: [Option<ExecPolicyEntry>; MAX_EXEC_ENTRIES],
}

impl ExecPolicyTable {
    pub const fn new() -> Self {
        ExecPolicyTable {
            entries: [None; MAX_EXEC_ENTRIES],
        }
    }

    /// Declare (or overwrite, exact-path match) a binary's surface.
    /// Bounded by NAME_MAX; refusing a too-long path is fail-closed,
    /// not truncating.
    pub fn declare(
        &mut self,
        path: &str,
        mask: SyscallMask,
        enforce: Option<bool>,
    ) -> Result<(), ProcError> {
        let bytes = path.as_bytes();
        if bytes.len() > NAME_MAX {
            return Err(ProcError::PolicyTableFull);
        }
        // Overwrite an existing entry for the same path if present.
        for e in self.entries.iter_mut().flatten() {
            if e.path() == path {
                *e = Self::build(path, mask, enforce);
                return Ok(());
            }
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(Self::build(path, mask, enforce));
                return Ok(());
            }
        }
        Err(ProcError::PolicyTableFull)
    }

    fn build(path: &str, mask: SyscallMask, enforce: Option<bool>) -> ExecPolicyEntry {
        let mut entry = ExecPolicyEntry {
            path: [0; NAME_MAX],
            path_len: path.len(),
            mask,
            enforce,
        };
        entry.path[..path.len()].copy_from_slice(path.as_bytes());
        entry
    }

    /// The declared surface for a path, or the app default
    /// (`app_profile`'s mask, AuditOnly) for anything unlisted.
    #[must_use]
    pub fn declared_for(&self, path: &str) -> (SyscallMask, Option<bool>) {
        for e in self.entries.iter().flatten() {
            if e.path() == path {
                return (e.mask, e.enforce);
            }
        }
        (app_profile().syscalls, Some(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SYS_READ;

    #[test]
    fn pids_are_monotonic_and_exhaustion_is_typed() {
        let mut t = ProcTable::new();
        let first = t.alloc_pid().unwrap();
        assert_eq!(first, FIRST_DYNAMIC_PID);
        let second = t.alloc_pid().unwrap();
        assert_eq!(second, FIRST_DYNAMIC_PID + 1);
        // Wind the counter to the end: the last allocation is
        // u32::MAX - 1, the next is a typed refusal, never a
        // wraparound.
        t.next_pid = u32::MAX - 1;
        assert_eq!(t.alloc_pid().unwrap(), u32::MAX - 1);
        assert_eq!(t.alloc_pid(), Err(ProcError::PidExhausted));
        assert_eq!(t.alloc_pid(), Err(ProcError::PidExhausted));
    }

    #[test]
    fn meta_slots_fill_refuse_and_free() {
        let mut t = ProcTable::new();
        for i in 0..MAX_PROCS {
            t.insert(ProcMeta {
                pid: u32::try_from(i).unwrap(),
                parent: 0,
                exit: None,
            })
            .unwrap();
        }
        assert_eq!(
            t.insert(ProcMeta {
                pid: 99,
                parent: 0,
                exit: None
            }),
            Err(ProcError::TooManyProcesses)
        );
        assert!(t.remove(5).is_some());
        assert!(t
            .insert(ProcMeta {
                pid: 99,
                parent: 0,
                exit: None
            })
            .is_ok());
        assert_eq!(t.count(), MAX_PROCS);
    }

    #[test]
    fn children_count_includes_zombies() {
        let mut t = ProcTable::new();
        t.insert(ProcMeta {
            pid: 10,
            parent: 3,
            exit: None,
        })
        .unwrap();
        t.insert(ProcMeta {
            pid: 11,
            parent: 3,
            exit: Some(ExitStatus::normal(0)),
        })
        .unwrap();
        t.insert(ProcMeta {
            pid: 12,
            parent: 4,
            exit: None,
        })
        .unwrap();
        assert_eq!(t.children_count(3), 2);
        assert_eq!(t.children_count(4), 1);
        assert_eq!(t.children_count(5), 0);
    }

    #[test]
    fn exec_policy_declare_lookup_overwrite_default() {
        let mut t = ExecPolicyTable::new();
        let m1 = SyscallMask::from_bits(1u64 << SYS_READ);
        t.declare("/bin/a", m1, Some(true)).unwrap();
        assert_eq!(t.declared_for("/bin/a"), (m1, Some(true)));
        // Overwrite in place, no duplicate rows.
        let m2 = SyscallMask::from_bits(0);
        t.declare("/bin/a", m2, None).unwrap();
        assert_eq!(t.declared_for("/bin/a"), (m2, None));
        // Unlisted: the app default, AuditOnly.
        let (dfl_mask, dfl_mode) = t.declared_for("/not/there");
        assert_eq!(dfl_mask, app_profile().syscalls);
        assert_eq!(dfl_mode, Some(false));
        // The table fills and refuses with a typed error (one slot is
        // already taken by /bin/a above).
        for i in 0..(MAX_EXEC_ENTRIES - 1) {
            let path = [
                b'/',
                b'p',
                b'0' + ((i % 10) as u8),
                b'0' + (((i / 10) % 10) as u8),
            ];
            t.declare(core::str::from_utf8(&path).unwrap(), m1, None)
                .unwrap();
        }
        assert_eq!(
            t.declare("/overflow", m1, None),
            Err(ProcError::PolicyTableFull)
        );
    }

    #[test]
    fn exit_status_constructors_carry_the_reason() {
        assert_eq!(
            ExitStatus::normal(3),
            ExitStatus {
                code: 3,
                reason: ExitReason::Normal
            }
        );
        assert_eq!(ExitStatus::killed(9).reason, ExitReason::Killed(9));
        assert_eq!(
            ExitStatus::fault(14).reason,
            ExitReason::Fault { vector: 14 }
        );
    }
}
