//! ADR-0022: the process table — the Unix lifecycle layer over the
//! domain table.
//!
//! - **Pids never repeat within a boot**: a monotonic counter starting
//!   at [`FIRST_DYNAMIC_PID`][crate::proc::FIRST_DYNAMIC_PID]
//!   (supervisor-created static domains keep
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

use crate::syscall::SyscallMask;

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
/// ADR-0032 section B: entries are keyed by IMAGE IDENTITY — a 64-bit
/// content hash of the registry image (`image_id`) — never by a path
/// string: aliases of the same bytes resolve to the same entry, and
/// different bytes never inherit a policy they did not declare.
/// Unlisted images get no entry here; the caller inherits its own
/// monitor mode (the exec ratchet) and the app-default surface
/// intersected with its live mask.
#[derive(Clone, Copy)]
pub struct ExecPolicyEntry {
    pub image_id: u64,
    pub mask: SyscallMask,
    pub enforce: Option<bool>,
}

/// ADR-0032 section B: the IMAGE IDENTITY — a 64-bit FNV-1a content
/// hash. Deterministic, no_std, cheap; collisions are a policy-confusion
/// risk bounded by the registry's size (two images, embedded bytes),
/// and the table never widens anything by construction (masks only
/// intersect). NOT a cryptographic identity — recorded in the ADR as
/// a deliberate, environment-honest choice.
#[must_use]
pub fn image_id(bytes: &[u8]) -> u64 {
    // FNV-1a 64-bit offset basis and prime.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// ADR-0032 section B: lexical path canonicalization for the exec
/// registry lookup — collapse `//`, resolve `.` and `..`, clamp at the
/// root (POSIX), drop trailing slashes. Pure and bounded: the output
/// is written into `out` and the LENGTH returned; `None` refuses
/// (non-absolute input, or output longer than `out`). This is what
/// makes `/bin/x`, `//bin/x`, `/bin/./x`, and `/bin/../bin/x` one
/// registry entry — a path string can no longer dodge a declared
/// policy by spelling the same file differently.
#[must_use]
pub fn canonicalize_path(input: &str, out: &mut [u8]) -> Option<usize> {
    if !input.starts_with('/') {
        return None;
    }
    let mut out_len: usize = 0;
    let mut component_start = true;
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' {
            // Collapse runs of slashes; drop trailing ones.
            component_start = true;
            i += 1;
            continue;
        }
        if !component_start {
            // A byte inside the current component: copy verbatim.
            if out_len == out.len() {
                return None;
            }
            out[out_len] = b;
            out_len += 1;
            i += 1;
            continue;
        }
        // A component starts here.
        component_start = false;
        if b == b'.' && (i + 1 == bytes.len() || bytes[i + 1] == b'/') {
            // `.` — contributes nothing.
            i += 1;
            continue;
        }
        if b == b'.'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'.'
            && (i + 2 == bytes.len() || bytes[i + 2] == b'/')
        {
            // `..` — strip the last component (saturating: at the root
            // it clamps, never escaping upward).
            while out_len > 0 && out[out_len - 1] != b'/' {
                out_len -= 1;
            }
            out_len = out_len.saturating_sub(1); // the separating '/'
            i += 2;
            continue;
        }
        // A real component: the separating '/' first (the root '/' for
        // the first component), then the byte — checked, never
        // truncated.
        if out_len >= out.len() {
            return None;
        }
        out[out_len] = b'/';
        out_len += 1;
        if out_len == out.len() {
            return None;
        }
        out[out_len] = b;
        out_len += 1;
        i += 1;
    }
    // The empty result (the root itself) stays "/".
    if out_len == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'/';
        return Some(1);
    }
    Some(out_len)
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

    /// Declare (or overwrite) an IMAGE's surface, keyed by its content
    /// identity (`image_id` of the registry bytes). ADR-0032 section
    /// B: never by a path string — aliases of the same bytes resolve
    /// to the same entry by construction.
    pub fn declare(
        &mut self,
        image_id: u64,
        mask: SyscallMask,
        enforce: Option<bool>,
    ) -> Result<(), ProcError> {
        // Overwrite an existing entry for the same image if present.
        for e in self.entries.iter_mut().flatten() {
            if e.image_id == image_id {
                *e = ExecPolicyEntry {
                    image_id,
                    mask,
                    enforce,
                };
                return Ok(());
            }
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(ExecPolicyEntry {
                    image_id,
                    mask,
                    enforce,
                });
                return Ok(());
            }
        }
        Err(ProcError::PolicyTableFull)
    }

    /// The declared surface for an IMAGE identity, or None when the
    /// image is unlisted — the caller then inherits its own monitor
    /// mode (the exec ratchet in `exec_replace`) and the app-default
    /// surface intersected with its live mask. The old path-keyed
    /// lookup returned AuditOnly for unlisted paths, silently
    /// downgrading an enforcing domain (the round-A finding).
    #[must_use]
    pub fn declared_for(&self, image_id: u64) -> Option<(SyscallMask, Option<bool>)> {
        for e in self.entries.iter().flatten() {
            if e.image_id == image_id {
                return Some((e.mask, e.enforce));
            }
        }
        None
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
        let a_id = image_id(b"image a bytes");
        t.declare(a_id, m1, Some(true)).unwrap();
        assert_eq!(t.declared_for(a_id), Some((m1, Some(true))));
        // Overwrite in place, no duplicate rows.
        let m2 = SyscallMask::from_bits(0);
        t.declare(a_id, m2, None).unwrap();
        assert_eq!(t.declared_for(a_id), Some((m2, None)));
        // Unlisted (ADR-0032 §B): None — the caller arm inherits the
        // caller's monitor mode (the exec ratchet) and the
        // app-default surface; a policy for one image never applies to
        // different bytes.
        assert_eq!(t.declared_for(image_id(b"other bytes")), None);
        // The table fills and refuses with a typed error (one slot is
        // already taken by image a above).
        for i in 0..(MAX_EXEC_ENTRIES - 1) {
            let id = image_id(&[
                b'p',
                b'0' + ((i % 10) as u8),
                b'0' + (((i / 10) % 10) as u8),
            ]);
            t.declare(id, m1, None).unwrap();
        }
        assert_eq!(
            t.declare(image_id(b"overflow"), m1, None),
            Err(ProcError::PolicyTableFull)
        );
    }

    /// ADR-0032 section B: aliases collapse to one registry entry —
    /// `//`, `.`, `..`, and trailing slashes never dodge a declared
    /// policy by spelling the same file differently.
    #[test]
    fn path_aliases_canonicalize_to_one_entry() {
        let canon = |input: &str| -> String {
            let mut out = [0u8; 64];
            let n = canonicalize_path(input, &mut out).expect("canonical");
            core::str::from_utf8(&out[..n]).unwrap().to_string()
        };
        assert_eq!(canon("/bin/x"), "/bin/x");
        assert_eq!(canon("//bin/x"), "/bin/x");
        assert_eq!(canon("/bin//x"), "/bin/x");
        assert_eq!(canon("/bin/./x"), "/bin/x");
        assert_eq!(canon("/bin/../bin/x"), "/bin/x");
        assert_eq!(canon("/a/b/../c"), "/a/c");
        assert_eq!(canon("/a/b/../../c"), "/c");
        // .. above the root clamps (POSIX), never escapes upward.
        assert_eq!(canon("/../../bin/x"), "/bin/x");
        // Trailing slashes drop; the root itself stays "/".
        assert_eq!(canon("/bin/"), "/bin");
        assert_eq!(canon("///"), "/");
        assert_eq!(canon("/"), "/");
        assert_eq!(canon("/././."), "/");
        // Relative input is refused (the registry is absolute-only).
        assert!(canonicalize_path("bin/x", &mut [0u8; 64]).is_none());
        // A too-small output buffer refuses, never truncates.
        assert!(canonicalize_path("/bin/exec-target", &mut [0u8; 4]).is_none());
    }

    /// ADR-0032 section B: the image identity is a pure function of
    /// the bytes — same bytes, same id; different bytes, different id.
    #[test]
    fn image_identity_is_content_addressed() {
        assert_eq!(image_id(b"same bytes"), image_id(b"same bytes"));
        assert_ne!(image_id(b"same bytes"), image_id(b"same bytes "));
        // The empty image still has a well-defined identity.
        assert_ne!(image_id(b""), 0);
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
