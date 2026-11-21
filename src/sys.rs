//! The executing syscall layer: what happens *after* the fast-path gate
//! says yes.
//!
//! `Kernel::syscall` runs in two phases, strictly in this order:
//!
//! 1. **Gate** — the existing deterministic fast path (`dispatch`):
//!    bounds check, quarantine check, mask bit test, counter accounting.
//!    Nothing below runs unless the gate allows it.
//! 2. **Execute** — the operation itself against the kernel's Linux-like
//!    state: VFS (with Unix permissions and chroot), fd table, pipes,
//!    signals, rate-limited sockets.
//!
//! Every syscall argument and result is an enum value — no raw pointers,
//! no user-controlled sizes, no double-fetch hazards in this model.

use crate::buddy::BuddyError;
use crate::capability::Rights;
use crate::domain::Decision;
use crate::fd::{FdError, FdTarget};
use crate::memory::MemFlags;
use crate::net::{NetError, TokenBucket, DEFAULT_BURST_BYTES, DEFAULT_RATE_BYTES_PER_WINDOW};
use crate::pipe::PipeError;
use crate::signal::{DefaultAction, SignalError};
use crate::vfs::{Access, InodeKind, Mode, VfsError};
use crate::{
    syscall::{
        SYS_CHROOT, SYS_CLOSE, SYS_DUP, SYS_IOCTL, SYS_IPC_RECV, SYS_IPC_SEND, SYS_KILL, SYS_MKDIR,
        SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP, SYS_NET_RECV, SYS_NET_SEND, SYS_OPEN, SYS_PIPE,
        SYS_READ, SYS_SCHED_YIELD, SYS_SIGACTION, SYS_SPAWN, SYS_UNLINK, SYS_WRITE,
    },
    Kernel, KernelError,
};

/// A fully-marshaled syscall request (the ABI of this sample kernel).
#[derive(Debug)]
pub enum SysRequest<'a> {
    /// open(path, mode, O_CREAT?, READ?, WRITE?, TRUNC?) — returns a
    /// file descriptor. F11(b): the requested access is checked at open
    /// time; F11(c): truncation is this explicit flag, never a side
    /// effect of writing.
    Open {
        path: &'a str,
        mode: Mode,
        create: bool,
        read: bool,
        write: bool,
        truncate: bool,
    },
    /// read(fd, buf) — returns bytes read (short reads; 0 at EOF).
    Read {
        fd: u8,
        buf: &'a mut [u8],
    },
    /// write(fd, bytes) — returns bytes written (short writes on pipes).
    Write {
        fd: u8,
        bytes: &'a [u8],
    },
    /// close(fd) — closes pipe ends held by the descriptor.
    Close {
        fd: u8,
    },
    /// pipe() — returns (read_fd, write_fd).
    Pipe,
    /// dup2(fd, new_fd) — installs a copy at `new_fd`, closing what is there.
    Dup {
        fd: u8,
        new_fd: u8,
    },
    /// kill(target, sig) — Unix permission rules apply (uid 0 / same uid).
    Kill {
        target: u32,
        sig: u8,
    },
    /// nanosleep(now, cycles) — ADR-0023: park the caller until
    /// `now + cycles`, both in the core's unit-agnostic time base (the
    /// ABI layer converts ns to the kernel's). Returns the wake
    /// deadline. Zero cycles is a plain yield.
    Nanosleep {
        now: u64,
        cycles: u64,
    },
    /// sched_yield() — ADR-0023: volunteer the rest of the slice. The
    /// core records the call; the SWITCH decision is the kernel's
    /// (`Preemptor::on_yield`) because only it can park the run.
    SchedYield,
    /// rt_sigaction(signum, handler, restorer) — ADR-0023 D8: install
    /// a caught-signal disposition. SIGKILL/SIGSTOP refuse; signum
    /// must be 1..=63. Pointer validation is the ABI layer's.
    SigAction {
        signum: u8,
        handler: u64,
        restorer: u64,
    },
    /// chroot(path) — confinement change; unlike Linux, the cwd moves with
    /// the root (closes the historical chroot+cwd escape).
    Chroot {
        path: &'a str,
    },
    /// mkdir(path, mode).
    Mkdir {
        path: &'a str,
        mode: Mode,
    },
    /// unlink(path) — files and *empty* directories.
    Unlink {
        path: &'a str,
    },
    /// send(len) — bytes through the domain's brokered socket, rate-limited.
    NetSend {
        len: u32,
    },
    /// mmap(addr, len, flags) — map into the domain's policy space.
    /// F13: executes through the ten-check gate; refusals feed the
    /// monitor's fault signal automatically.
    Mmap {
        addr: usize,
        len: usize,
        flags: MemFlags,
    },
    /// munmap(addr, len) — withdraw a mapping from the policy space.
    Munmap {
        addr: usize,
        len: usize,
    },
    /// F13 stubs: mask bits without executors. They answer
    /// `NotImplemented(nr)` — never a silent success — and the gate has
    /// already counted the attempt for the monitor.
    Spawn {
        cmd: u32,
    },
    IpcSend {
        channel: u32,
        len: u32,
    },
    IpcRecv {
        channel: u32,
    },
    Ioctl {
        cmd: u32,
    },
    NetRecv {
        len: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysValue {
    Fd(u8),
    FdPair(u8, u8),
    /// Byte count (read/write/net) or remaining tokens (net).
    Count(usize),
    /// A mapped address (mmap).
    Addr(u64),
    Unit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// The mask (profile or tightening) denies this syscall.
    Masked(u8),
    /// The domain is quarantined; only EXIT passes.
    Quarantined(u8),
    BadSyscall(u8),
    UnknownDomain(u32),
    /// Descriptor not open in this domain (EBADF).
    BadFd(u8),
    /// The domain table is full (F14: surfaced, not collapsed).
    TooManyDomains,
    /// Domain id already in use.
    DuplicateDomain(u32),
    /// Domain id rejected by the credential-derivation rules.
    InvalidId(u32),
    /// F13: the syscall has a mask bit but no executor yet — never a
    /// silent success. The monitor counts the attempt (the gate already
    /// marks it used).
    NotImplemented(u8),
    /// Round J: I/O on a runtime-reserved descriptor (the stdio
    /// triplet). The slot exists — `alloc` cannot hand it out — but the
    /// policy core refuses to read or write through it; the runtime's
    /// device path (the console behind fd 1) serves it outside this
    /// table. Carries the fd.
    Reserved(u8),
    /// F13: a memory-policy refusal from MMAP/MUNMAP (identity kept).
    Mem(crate::memory::MemError),
    Fd(FdError),
    Vfs(VfsError),
    Pipe(PipeError),
    Signal(SignalError),
    Net(NetError),
    /// ADR-0004: endpoint-IPC refusals (dead ids, bounded queues,
    /// size limits, owner mismatches).
    Ipc(crate::ipc::IpcError),
    Buddy(BuddyError),
    /// kill() denied: sender is not uid 0 and not the same uid.
    PermissionDenied,
    /// ADR-0023: an argument value the core refuses outright (a sleep
    /// span whose deadline overflows, for one) — EINVAL at the ABI.
    InvalidArgument(u64),
}

/// F14: the two failure modes of `net_open`, kept distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetOpenError {
    UnknownDomain(u32),
    Net(crate::net::NetError),
}

impl<const N: usize> Kernel<N> {
    /// The executing syscall entry point: gate first, then execute.
    pub fn syscall<'a>(
        &mut self,
        domain_id: u32,
        req: SysRequest<'a>,
    ) -> Result<SysValue, SysError> {
        let nr = syscall_nr(&req);
        // Phase 1: the deterministic fast-path gate.
        match self.dispatch(domain_id, nr) {
            Ok(Decision::Allowed) => {}
            Ok(Decision::DeniedByMask(id)) => return Err(SysError::Masked(id)),
            Ok(Decision::DeniedQuarantined(id)) => return Err(SysError::Quarantined(id)),
            Ok(Decision::BadSyscall(id)) => return Err(SysError::BadSyscall(id)),
            Err(e) => return Err(into_sys(e)),
        }
        // Phase 2: execute against the kernel's Linux-like state.
        self.execute(domain_id, req)
    }

    /// Round J: Phase 2 alone — the executor, WITHOUT the gate. The
    /// ring-3 runtime calls this after running its own `dispatch` (the
    /// same gate, on the live domain, where the denial/used accounting
    /// must land exactly once); calling `syscall` from there would run
    /// the gate a second time and double every counter. Library callers
    /// that have not gated must use `syscall`.
    pub fn execute<'a>(
        &mut self,
        domain_id: u32,
        req: SysRequest<'a>,
    ) -> Result<SysValue, SysError> {
        // Phase 2: execute against the kernel's Linux-like state.
        let (creds, root, cwd) = {
            let d = self.domain_mut(domain_id).map_err(into_sys)?;
            (d.creds(), d.chroot_root, d.cwd)
        };
        match req {
            SysRequest::Open {
                path,
                mode,
                create,
                read,
                write,
                truncate,
            } => {
                // F18 (ADR-0009): the capability gate runs BEFORE any
                // resolution work — an FsNode capability covering the
                // path's parent directory, with the requested access.
                let parent = self
                    .vfs
                    .parent_ref(root, cwd, path, creds)
                    .map_err(SysError::Vfs)?;
                let mut access = crate::capability::Rights::NONE;
                if read {
                    access = access.union(Rights::READ);
                }
                if write || create {
                    access = access.union(Rights::WRITE);
                }
                if !access.is_empty() {
                    self.require_fs_cap(domain_id, parent, access)?;
                }
                let r = if create {
                    match self.vfs.resolve(root, cwd, path, creds) {
                        Ok(found) => {
                            if self.vfs.kind_of(found) != Some(InodeKind::File) {
                                return Err(SysError::Vfs(VfsError::IsADirectory));
                            }
                            found
                        }
                        Err(VfsError::NotFound) => self
                            .vfs
                            .create(root, cwd, path, creds, mode)
                            .map_err(SysError::Vfs)?,
                        Err(e) => return Err(SysError::Vfs(e)),
                    }
                } else {
                    let found = self
                        .vfs
                        .resolve(root, cwd, path, creds)
                        .map_err(SysError::Vfs)?;
                    if self.vfs.kind_of(found) != Some(InodeKind::File) {
                        return Err(SysError::Vfs(VfsError::IsADirectory));
                    }
                    found
                };
                // F11(b): permission for the requested access is checked
                // AT OPEN, not deferred to each read/write.
                if read {
                    self.vfs
                        .check_access_ref(r, creds, Access::Read)
                        .map_err(SysError::Vfs)?;
                }
                if write {
                    self.vfs
                        .check_access_ref(r, creds, Access::Write)
                        .map_err(SysError::Vfs)?;
                    // F11(c): truncation is explicit and requires write.
                    if truncate {
                        self.vfs.truncate(r, creds).map_err(SysError::Vfs)?;
                    }
                }
                let fd = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .alloc(FdTarget::File(r))
                    .map_err(SysError::Fd)?;
                Ok(SysValue::Fd(fd))
            }
            SysRequest::Read { fd, buf } => {
                let target = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .get(fd)
                    .ok_or(SysError::BadFd(fd))?
                    .target;
                match target {
                    FdTarget::File(inode) => {
                        let pos = self
                            .domain_mut(domain_id)
                            .map_err(into_sys)?
                            .fds
                            .get(fd)
                            .ok_or(SysError::BadFd(fd))?
                            .pos as usize;
                        let n = self
                            .vfs
                            .read_by_id_at(inode, creds, pos, buf)
                            .map_err(SysError::Vfs)?;
                        if let Some(e) = self
                            .domain_mut(domain_id)
                            .map_err(into_sys)?
                            .fds
                            .get_mut(fd)
                        {
                            e.pos = e.pos.saturating_add(n as u32);
                        }
                        Ok(SysValue::Count(n))
                    }
                    FdTarget::PipeRead(pipe) => {
                        let n = self.pipes.read(pipe, buf).map_err(SysError::Pipe)?;
                        Ok(SysValue::Count(n))
                    }
                    FdTarget::PipeWrite(_) => Err(SysError::BadFd(fd)),
                    // Round J: the stdio triplet exists but is not
                    // readable through the policy core (the runtime's
                    // device serves it, or nobody does).
                    FdTarget::Reserved => Err(SysError::Reserved(fd)),
                }
            }
            SysRequest::Write { fd, bytes } => {
                let target = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .get(fd)
                    .ok_or(SysError::BadFd(fd))?
                    .target;
                match target {
                    FdTarget::File(inode) => {
                        // F11(c): writes land at the fd's offset and
                        // advance it; existing bytes are not clobbered.
                        let pos = self
                            .domain_mut(domain_id)
                            .map_err(into_sys)?
                            .fds
                            .get(fd)
                            .ok_or(SysError::BadFd(fd))?
                            .pos as usize;
                        let n = self
                            .vfs
                            .write_at(inode, creds, pos, bytes)
                            .map_err(SysError::Vfs)?;
                        if let Some(e) = self
                            .domain_mut(domain_id)
                            .map_err(into_sys)?
                            .fds
                            .get_mut(fd)
                        {
                            e.pos = e.pos.saturating_add(n as u32);
                        }
                        Ok(SysValue::Count(n))
                    }
                    FdTarget::PipeWrite(pipe) => {
                        let n = self.pipes.write(pipe, bytes).map_err(SysError::Pipe)?;
                        Ok(SysValue::Count(n))
                    }
                    FdTarget::PipeRead(_) => Err(SysError::BadFd(fd)),
                    // Round J: reserved descriptors are not writable
                    // through the policy core. The ring-3 runtime's
                    // console alias (fd 1) is served by the device path
                    // BEFORE this executor is reached, so landing here
                    // means the alias was closed or the caller forged
                    // the fd — refuse, never fake a byte count.
                    FdTarget::Reserved => Err(SysError::Reserved(fd)),
                }
            }
            SysRequest::Close { fd } => {
                let entry = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .close(fd)
                    .ok_or(SysError::BadFd(fd))?;
                match entry.target {
                    // Closing a pipe fd drops one reference: the end closes
                    // (readers see EOF / writers get EPIPE) only when the
                    // last referencing descriptor goes away. An InvalidPipe
                    // error here means the slot was already reclaimed.
                    FdTarget::PipeRead(p) => {
                        let _ = self.pipes.release_read(p);
                    }
                    FdTarget::PipeWrite(p) => {
                        let _ = self.pipes.release_write(p);
                    }
                    FdTarget::File(_) => {}
                    // Round J: closing a reserved slot frees it for
                    // later allocation — after this, the runtime's
                    // device alias no longer has a table entry and the
                    // fd can be handed out by pipe()/open().
                    FdTarget::Reserved => {}
                }
                Ok(SysValue::Unit)
            }
            SysRequest::Pipe => {
                let pipe = self.pipes.create().map_err(SysError::Pipe)?;
                // Short-lived borrows only: fd table and pipe table are
                // distinct kernel objects touched one at a time.
                let read_fd = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .alloc(FdTarget::PipeRead(pipe))
                    .map_err(SysError::Fd)?;
                if let Err(e) = self.pipes.acquire_read(pipe) {
                    self.drop_quietly(domain_id, read_fd);
                    let _ = self.pipes.close_write(pipe);
                    return Err(SysError::Pipe(e));
                }
                let write_fd = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .alloc(FdTarget::PipeWrite(pipe));
                let write_fd = match write_fd {
                    Ok(fd) => fd,
                    Err(e) => {
                        // Roll back so a failed pipe() leaves no half-open
                        // descriptors behind.
                        self.drop_quietly(domain_id, read_fd);
                        let _ = self.pipes.release_read(pipe);
                        let _ = self.pipes.close_write(pipe);
                        return Err(SysError::Fd(e));
                    }
                };
                if let Err(e) = self.pipes.acquire_write(pipe) {
                    self.drop_quietly(domain_id, read_fd);
                    self.drop_quietly(domain_id, write_fd);
                    let _ = self.pipes.close_read(pipe);
                    let _ = self.pipes.close_write(pipe);
                    return Err(SysError::Pipe(e));
                }
                Ok(SysValue::FdPair(read_fd, write_fd))
            }
            SysRequest::Dup { fd, new_fd } => {
                // dup2(fd, fd) is a no-op (F2): it must not touch any
                // refcount — the old path acquired one and dropped the
                // replaced entry on the floor, leaking it.
                if fd == new_fd {
                    return Ok(SysValue::Fd(new_fd));
                }
                let (target, pos) = {
                    let d = self.domain_mut(domain_id).map_err(into_sys)?;
                    let e = d.fds.get(fd).ok_or(SysError::BadFd(fd))?;
                    (e.target, e.pos)
                };
                // A duplicated pipe end is a second reference to it.
                let acquire = match target {
                    FdTarget::PipeRead(p) => self.pipes.acquire_read(p),
                    FdTarget::PipeWrite(p) => self.pipes.acquire_write(p),
                    FdTarget::File(_) => Ok(()),
                    // Round J: a reserved slot carries no pipe/end
                    // refcount — dup copies it like any entry.
                    FdTarget::Reserved => Ok(()),
                };
                acquire.map_err(SysError::Pipe)?;
                // Replace the target fd, releasing whatever it held
                // (F2: the old entry was silently discarded, leaking a
                // pipe reference). A failed replace rolls the new
                // reference back so dup cannot leak in either direction.
                let replaced = {
                    let d = self.domain_mut(domain_id).map_err(into_sys)?;
                    d.fds.replace_at(new_fd, target)
                };
                let replaced = match replaced {
                    Ok(old) => old,
                    Err(e) => {
                        match target {
                            FdTarget::PipeRead(p) => {
                                let _ = self.pipes.release_read(p);
                            }
                            FdTarget::PipeWrite(p) => {
                                let _ = self.pipes.release_write(p);
                            }
                            FdTarget::File(_) => {}
                            FdTarget::Reserved => {}
                        }
                        return Err(SysError::Fd(e));
                    }
                };
                if let Some(old) = replaced {
                    match old.target {
                        FdTarget::PipeRead(p) => {
                            let _ = self.pipes.release_read(p);
                        }
                        FdTarget::PipeWrite(p) => {
                            let _ = self.pipes.release_write(p);
                        }
                        FdTarget::File(_) => {}
                        FdTarget::Reserved => {}
                    }
                }
                // The duplicate carries the source's file offset. NOTE:
                // this is a snapshot, not POSIX's shared live offset —
                // the fd table owns one offset per descriptor, and
                // Write-with-offset semantics arrive with F11.
                if let Ok(d) = self.domain_mut(domain_id) {
                    if let Some(e) = d.fds.get_mut(new_fd) {
                        e.pos = pos;
                    }
                }
                Ok(SysValue::Fd(new_fd))
            }
            SysRequest::Kill { target, sig } => {
                // Unix permission rules: uid 0, same uid, or self —
                // checked BEFORE the target's existence is revealed, so
                // domain ids cannot be enumerated through kill (F14): a
                // foreign target answers PermissionDenied whether it
                // exists or not; only root and self may learn
                // UnknownDomain. SIGSTOP note: the signal is delivered
                // (pending, unblockable) but this sample kernel has no
                // Stopped scheduling state — stopping is documented as
                // unsupported (see SECURITY-MODEL.md).
                // F18 (ADR-0009): the capability gate precedes the Unix
                // rules (and existence — F14's no-enumeration property
                // is preserved: an unauthorized sender gets the same
                // PermissionDenied for existing and missing targets).
                if target != domain_id {
                    self.require_domain_cap(domain_id, target)?;
                }
                let sender_uid = self.domain_mut(domain_id).map_err(into_sys)?.uid;
                if sender_uid != 0 && target != domain_id {
                    let same_uid = self
                        .domains
                        .iter()
                        .flatten()
                        .find(|d| d.id == target)
                        .is_some_and(|d| d.uid == sender_uid);
                    if !same_uid {
                        return Err(SysError::PermissionDenied);
                    }
                }
                let victim = self
                    .domains
                    .iter_mut()
                    .flatten()
                    .find(|d| d.id == target)
                    .ok_or(SysError::UnknownDomain(target))?;
                victim.signals.send(sig).map_err(SysError::Signal)?;
                Ok(SysValue::Unit)
            }
            SysRequest::Nanosleep { now, cycles } => {
                let wake = self.sleep_until(domain_id, now, cycles)?;
                Ok(SysValue::Count(wake as usize))
            }
            SysRequest::SchedYield => Ok(SysValue::Unit),
            SysRequest::SigAction {
                signum,
                handler,
                restorer,
            } => {
                if signum == 0 || signum >= 64 {
                    return Err(SysError::InvalidArgument(u64::from(signum)));
                }
                if crate::signal::is_unblockable(signum) {
                    // KILL/STOP are never catchable (the existing
                    // invariant, now reachable from ring 3).
                    return Err(SysError::InvalidArgument(u64::from(signum)));
                }
                let d = self.domain_mut(domain_id).map_err(into_sys)?;
                d.sig_handlers[usize::from(signum)] =
                    Some(crate::signal::SigHandler { handler, restorer });
                Ok(SysValue::Unit)
            }
            SysRequest::Chroot { path } => {
                // Resolve against the *current* root, then re-root.
                let id = self
                    .vfs
                    .resolve(root, cwd, path, creds)
                    .map_err(SysError::Vfs)?;
                if self.vfs.kind_of(id) != Some(InodeKind::Dir) {
                    return Err(SysError::Vfs(VfsError::NotADirectory));
                }
                // Risk treatment 2 (ADR-0009 addendum): chroot is also a
                // CAPABILITY boundary. Mint the jail capability (with the
                // profile's base_rights) and drop every FsNode capability
                // outside the jail — the table now matches the resolve
                // confinement instead of holding the tree-wide ROOT.
                // Attenuation-only: the scope can only ever shrink.
                // (`resolve` already returned a live InodeRef — the
                // generation is current by construction.)
                let jail = id;
                let base_rights = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .profile
                    .base_rights;
                // Mint first (a free slot may be needed), then prune.
                let _ = self.domain_mut(domain_id).map_err(into_sys)?.caps.insert(
                    crate::capability::Capability {
                        resource: crate::capability::Resource::FsNode(jail),
                        rights: base_rights,
                        generation: 0,
                    },
                );
                // Snapshot the live handles, then revoke every FsNode
                // capability whose directory is not within the jail.
                let mut handles = [crate::capability::CapHandle {
                    index: 0,
                    generation: 0,
                }; crate::capability::MAX_CAPABILITIES];
                let mut n = 0usize;
                {
                    let d = self.domain_mut(domain_id).map_err(into_sys)?;
                    for h in d.caps.handles() {
                        if n < handles.len() {
                            handles[n] = h;
                            n += 1;
                        }
                    }
                }
                for h in handles.iter().take(n) {
                    let outside = {
                        let d = self.domain_mut(domain_id).map_err(into_sys)?;
                        match d.caps.lookup(*h) {
                            Ok(crate::capability::Capability {
                                resource: crate::capability::Resource::FsNode(r),
                                ..
                            }) => !self.vfs.is_within(jail, r),
                            _ => false, // not an FsNode cap: untouched
                        }
                    };
                    if outside {
                        let _ = self
                            .domain_mut(domain_id)
                            .map_err(into_sys)?
                            .caps
                            .revoke(*h);
                    }
                }
                let d = self.domain_mut(domain_id).map_err(into_sys)?;
                d.chroot_root = jail;
                // Hardening beyond Linux: the cwd moves with the new root,
                // closing the classic chroot-escape-with-old-cwd attack.
                d.cwd = jail;
                Ok(SysValue::Unit)
            }
            SysRequest::Mkdir { path, mode } => {
                let parent = self
                    .vfs
                    .parent_ref(root, cwd, path, creds)
                    .map_err(SysError::Vfs)?;
                self.require_fs_cap(domain_id, parent, Rights::WRITE)?;
                self.vfs
                    .mkdir(root, cwd, path, creds, mode)
                    .map_err(SysError::Vfs)?;
                Ok(SysValue::Unit)
            }
            SysRequest::Unlink { path } => {
                let parent = self
                    .vfs
                    .parent_ref(root, cwd, path, creds)
                    .map_err(SysError::Vfs)?;
                self.require_fs_cap(domain_id, parent, Rights::WRITE)?;
                self.vfs
                    .unlink(root, cwd, path, creds)
                    .map_err(SysError::Vfs)?;
                Ok(SysValue::Unit)
            }
            SysRequest::NetSend { len } => {
                // F18 (ADR-0009): the brokered NIC needs the Device
                // capability with WRITE, before any socket work.
                self.require_device_cap(domain_id, Rights::WRITE)?;
                let sock = self
                    .sockets
                    .open_socket_of(domain_id)
                    .ok_or(SysError::Net(NetError::InvalidSocket(u32::MAX)))?;
                let slot = self
                    .buckets
                    .iter()
                    .position(|b| matches!(b, Some((bid, _)) if *bid == domain_id))
                    .or_else(|| self.buckets.iter().position(|b| b.is_none()))
                    .ok_or(SysError::Net(NetError::TableFull))?;
                if self.buckets[slot].is_none() {
                    self.buckets[slot] = Some((
                        domain_id,
                        TokenBucket::new(DEFAULT_RATE_BYTES_PER_WINDOW, DEFAULT_BURST_BYTES),
                    ));
                }
                let (owner, mut bucket) = self.buckets[slot].take().expect("bucket ensured");
                let result = self.sockets.send(sock, len, &mut bucket, self.clock);
                self.buckets[slot] = Some((owner, bucket));
                result
                    .map(|left| SysValue::Count(left as usize))
                    .map_err(SysError::Net)
            }
            SysRequest::Mmap { addr, len, flags } => {
                // F13: through the policy space — a refusal is also an
                // organic monitor fault (domain_map records it).
                self.domain_map(domain_id, addr, len, flags)
                    .map(|()| SysValue::Addr(addr as u64))
                    .map_err(SysError::Mem)
            }
            SysRequest::Munmap { addr, len: _ } => {
                let d = self.domain_mut(domain_id).map_err(into_sys)?;
                d.space
                    .unmap(addr)
                    .map(|_| SysValue::Unit)
                    .map_err(SysError::Mem)
            }
            SysRequest::Spawn { .. } => Err(SysError::NotImplemented(SYS_SPAWN)),
            SysRequest::IpcSend { channel, len } => {
                // ADR-0004 slice 1 (async send). Cheapest check first:
                // the fixed message size (§1), before any capability
                // work — the fast path stays trivial on the common
                // in-policy case.
                if len > crate::ipc::IPC_MAX_MSG_BYTES {
                    return Err(SysError::Ipc(crate::ipc::IpcError::TooLong(len)));
                }
                // The capability gate: WRITE == SEND (§4 mapping).
                self.require_endpoint_cap(domain_id, channel, Rights::WRITE)?;
                // A live capability on a destroyed endpoint fails
                // closed (ids are never reused — no ABA).
                self.endpoints
                    .owner_of(channel)
                    .ok_or(SysError::Ipc(crate::ipc::IpcError::InvalidHandle))?;
                self.endpoints
                    .push(channel, domain_id, len)
                    // Count = free queue slots after the push (the
                    // EAGAIN budget, mirroring NetSend's token count).
                    .map(SysValue::Count)
                    .map_err(SysError::Ipc)
            }
            SysRequest::IpcRecv { channel } => {
                // ADR-0004 slice 1 (async recv): READ == RECV, and the
                // queue is per-domain — only the owner drains it.
                self.require_endpoint_cap(domain_id, channel, Rights::READ)?;
                let owner = self
                    .endpoints
                    .owner_of(channel)
                    .ok_or(SysError::Ipc(crate::ipc::IpcError::InvalidHandle))?;
                if owner != domain_id {
                    return Err(SysError::Ipc(crate::ipc::IpcError::NotOwner(domain_id)));
                }
                self.endpoints
                    .pop(channel)
                    .map(|m| SysValue::Count(m.len as usize))
                    .map_err(SysError::Ipc)
            }
            SysRequest::Ioctl { .. } => Err(SysError::NotImplemented(SYS_IOCTL)),
            SysRequest::NetRecv { .. } => Err(SysError::NotImplemented(SYS_NET_RECV)),
        }
    }

    /// Deliver one pending unblocked signal to a domain. Signals whose
    /// default action is Terminate quarantine the domain (the AegisOS
    /// equivalent of a fatal signal: the domain is cut to SYS_EXIT only).
    pub fn deliver_signals(&mut self, domain_id: u32) -> Result<Option<u8>, KernelError> {
        let sig = self.domain_mut(domain_id)?.signals.deliver();
        if let Some(sig) = sig {
            if crate::signal::default_action(sig) == Ok(DefaultAction::Terminate) {
                self.domain_mut(domain_id)?.quarantine();
            }
        }
        Ok(sig)
    }

    /// Supervisor API: open the domain's brokered socket + rate bucket.
    /// F14: errors keep their identity — a full socket table is
    /// `Net(..)`, a missing domain is `UnknownDomain`; the old version
    /// folded both into UnknownDomain.
    pub fn net_open(&mut self, domain_id: u32) -> Result<u32, NetOpenError> {
        let exists = self.domains.iter().flatten().any(|d| d.id == domain_id);
        if !exists {
            return Err(NetOpenError::UnknownDomain(domain_id));
        }
        // Idempotent: return the existing open socket.
        if let Some(id) = self.sockets.open_socket_of(domain_id) {
            return Ok(id);
        }
        self.sockets.open(domain_id).map_err(NetOpenError::Net)
    }

    /// Advance the kernel clock (drives rate-limit windows).
    pub fn set_clock(&mut self, now_ticks: u64) {
        self.clock = now_ticks;
    }

    #[must_use]
    pub fn clock(&self) -> u64 {
        self.clock
    }

    /// Change a domain's nice level in the fair scheduler.
    pub fn set_nice_for(&mut self, domain_id: u32, nice: i8) -> Result<(), KernelError> {
        self.sched
            .set_nice(domain_id, nice)
            .map_err(|_| KernelError::UnknownDomain(domain_id))
    }
}

impl<const N: usize> Kernel<N> {
    /// Best-effort fd close used by rollback paths (never fails the caller).
    /// F18 (ADR-0009): require an FsNode capability covering `parent`
    /// (the operation's parent directory) with `access`. Unix DAC
    /// remains the second layer. A failure is an escalation signal on
    /// the live domain — the same recording path as the cap_* wrappers.
    fn require_fs_cap(
        &mut self,
        domain_id: u32,
        parent: crate::vfs::InodeRef,
        access: Rights,
    ) -> Result<(), SysError> {
        // no_std: a fixed-size snapshot (the table is bounded by
        // MAX_CAPABILITIES).
        let mut caps = [(crate::capability::Resource::Domain(0), Rights::NONE);
            crate::capability::MAX_CAPABILITIES];
        let mut n = 0usize;
        {
            let d = self.domain_mut(domain_id).map_err(into_sys)?;
            for c in d.caps.iter() {
                if n < caps.len() {
                    caps[n] = (c.resource, c.rights);
                    n += 1;
                }
            }
        }
        for (res, rights) in caps.iter().take(n) {
            if let crate::capability::Resource::FsNode(r) = res {
                if rights.contains(access) && self.vfs.is_within(*r, parent) {
                    return Ok(());
                }
            }
        }
        let d = self.domain_mut(domain_id).map_err(into_sys)?;
        d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
        Err(SysError::PermissionDenied)
    }

    /// F18 (ADR-0009): require the Device capability (the brokered NIC
    /// is device 0) with `access`.
    fn require_device_cap(&mut self, domain_id: u32, access: Rights) -> Result<(), SysError> {
        let mut caps = [(crate::capability::Resource::Domain(0), Rights::NONE);
            crate::capability::MAX_CAPABILITIES];
        let mut n = 0usize;
        {
            let d = self.domain_mut(domain_id).map_err(into_sys)?;
            for c in d.caps.iter() {
                if n < caps.len() {
                    caps[n] = (c.resource, c.rights);
                    n += 1;
                }
            }
        }
        for (res, rights) in caps.iter().take(n) {
            if let crate::capability::Resource::Device(dev) = res {
                if *dev == 0 && rights.contains(access) {
                    return Ok(());
                }
            }
        }
        let d = self.domain_mut(domain_id).map_err(into_sys)?;
        d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
        Err(SysError::PermissionDenied)
    }

    /// F18 (ADR-0009): require a Domain capability on `target` with
    /// WRITE. Self-signaling is always allowed: creation minted
    /// Domain(id), so the normal check passes with no special case.
    /// ADR-0004 (ADR-0009 discipline): require an Endpoint capability
    /// on THIS endpoint with `access`. Rights mapping: WRITE = SEND,
    /// READ = RECV. A capability on a dead (destroyed) endpoint still
    /// passes this gate — the executor's liveness check closes that
    /// hole with `IpcError::InvalidHandle`.
    fn require_endpoint_cap(
        &mut self,
        domain_id: u32,
        endpoint_id: u32,
        access: Rights,
    ) -> Result<(), SysError> {
        let mut caps = [(crate::capability::Resource::Domain(0), Rights::NONE);
            crate::capability::MAX_CAPABILITIES];
        let mut n = 0usize;
        {
            let d = self.domain_mut(domain_id).map_err(into_sys)?;
            for c in d.caps.iter() {
                if n < caps.len() {
                    caps[n] = (c.resource, c.rights);
                    n += 1;
                }
            }
        }
        for (res, rights) in caps.iter().take(n) {
            if let crate::capability::Resource::Endpoint(eid) = res {
                if *eid == endpoint_id && rights.contains(access) {
                    return Ok(());
                }
            }
        }
        let d = self.domain_mut(domain_id).map_err(into_sys)?;
        d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
        Err(SysError::PermissionDenied)
    }

    fn require_domain_cap(&mut self, domain_id: u32, target: u32) -> Result<(), SysError> {
        let mut caps = [(crate::capability::Resource::Domain(0), Rights::NONE);
            crate::capability::MAX_CAPABILITIES];
        let mut n = 0usize;
        {
            let d = self.domain_mut(domain_id).map_err(into_sys)?;
            for c in d.caps.iter() {
                if n < caps.len() {
                    caps[n] = (c.resource, c.rights);
                    n += 1;
                }
            }
        }
        for (res, rights) in caps.iter().take(n) {
            if let crate::capability::Resource::Domain(t) = res {
                if *t == target && rights.contains(Rights::WRITE) {
                    return Ok(());
                }
            }
        }
        let d = self.domain_mut(domain_id).map_err(into_sys)?;
        d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
        Err(SysError::PermissionDenied)
    }

    fn drop_quietly(&mut self, domain_id: u32, fd: u8) {
        if let Ok(d) = self.domain_mut(domain_id) {
            let _ = d.fds.close(fd);
        }
    }
}

fn syscall_nr(req: &SysRequest<'_>) -> u8 {
    match req {
        SysRequest::Open { .. } => SYS_OPEN,
        SysRequest::Read { .. } => SYS_READ,
        SysRequest::Write { .. } => SYS_WRITE,
        SysRequest::Close { .. } => SYS_CLOSE,
        SysRequest::Pipe => SYS_PIPE,
        SysRequest::Dup { .. } => SYS_DUP,
        SysRequest::Kill { .. } => SYS_KILL,
        SysRequest::Nanosleep { .. } => SYS_NANOSLEEP,
        SysRequest::SchedYield => SYS_SCHED_YIELD,
        SysRequest::SigAction { .. } => SYS_SIGACTION,
        SysRequest::Chroot { .. } => SYS_CHROOT,
        SysRequest::Mkdir { .. } => SYS_MKDIR,
        SysRequest::Unlink { .. } => SYS_UNLINK,
        SysRequest::NetSend { .. } => SYS_NET_SEND,
        SysRequest::Mmap { .. } => SYS_MMAP,
        SysRequest::Munmap { .. } => SYS_MUNMAP,
        SysRequest::Spawn { .. } => SYS_SPAWN,
        SysRequest::IpcSend { .. } => SYS_IPC_SEND,
        SysRequest::IpcRecv { .. } => SYS_IPC_RECV,
        SysRequest::Ioctl { .. } => SYS_IOCTL,
        SysRequest::NetRecv { .. } => SYS_NET_RECV,
    }
}

/// F14: every kernel error keeps its identity across the boundary —
/// the old catch-all mapped everything to `UnknownDomain(0)`, hiding
/// TooManyDomains/DuplicateDomain/InvalidId from callers.
fn into_sys(e: KernelError) -> SysError {
    match e {
        KernelError::UnknownDomain(id) => SysError::UnknownDomain(id),
        KernelError::TooManyDomains => SysError::TooManyDomains,
        KernelError::DuplicateDomain(id) => SysError::DuplicateDomain(id),
        KernelError::InvalidId(id) => SysError::InvalidId(id),
        // Risk treatment 3: a supervisor-only API called by a
        // non-privileged domain is a permission denial, full stop.
        KernelError::NotAuthorized(_) => SysError::PermissionDenied,
        KernelError::Ipc(e) => SysError::Ipc(e),
        // Round J: a supervisor-side reservation refusal surfacing
        // through a syscall-shaped path — the caller tried to operate
        // where the stdio slots were already spoken for.
        KernelError::StdioSlotOccupied(fd) => SysError::Reserved(fd),
    }
}
