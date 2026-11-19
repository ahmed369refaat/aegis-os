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
use crate::domain::Decision;
use crate::fd::{FdError, FdTarget};
use crate::net::{NetError, TokenBucket, DEFAULT_BURST_BYTES, DEFAULT_RATE_BYTES_PER_WINDOW};
use crate::pipe::PipeError;
use crate::signal::{DefaultAction, SignalError};
use crate::vfs::{InodeKind, Mode, VfsError};
use crate::{
    Kernel, KernelError,
    syscall::{
        SYS_CHROOT, SYS_CLOSE, SYS_DUP, SYS_KILL, SYS_MKDIR, SYS_NET_SEND, SYS_OPEN, SYS_PIPE,
        SYS_READ, SYS_UNLINK, SYS_WRITE,
    },
};

/// A fully-marshaled syscall request (the ABI of this sample kernel).
#[derive(Debug)]
pub enum SysRequest<'a> {
    /// open(path, O_CREAT?) — returns a file descriptor.
    Open { path: &'a str, mode: Mode, create: bool },
    /// read(fd, buf) — returns bytes read (short reads; 0 at EOF).
    Read { fd: u8, buf: &'a mut [u8] },
    /// write(fd, bytes) — returns bytes written (short writes on pipes).
    Write { fd: u8, bytes: &'a [u8] },
    /// close(fd) — closes pipe ends held by the descriptor.
    Close { fd: u8 },
    /// pipe() — returns (read_fd, write_fd).
    Pipe,
    /// dup2(fd, new_fd) — installs a copy at `new_fd`, closing what is there.
    Dup { fd: u8, new_fd: u8 },
    /// kill(target, sig) — Unix permission rules apply (uid 0 / same uid).
    Kill { target: u32, sig: u8 },
    /// chroot(path) — confinement change; unlike Linux, the cwd moves with
    /// the root (closes the historical chroot+cwd escape).
    Chroot { path: &'a str },
    /// mkdir(path, mode).
    Mkdir { path: &'a str, mode: Mode },
    /// unlink(path) — files and *empty* directories.
    Unlink { path: &'a str },
    /// send(len) — bytes through the domain's brokered socket, rate-limited.
    NetSend { len: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysValue {
    Fd(u8),
    FdPair(u8, u8),
    /// Byte count (read/write/net) or remaining tokens (net).
    Count(usize),
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
    Fd(FdError),
    Vfs(VfsError),
    Pipe(PipeError),
    Signal(SignalError),
    Net(NetError),
    Buddy(BuddyError),
    /// kill() denied: sender is not uid 0 and not the same uid.
    PermissionDenied,
}

impl Kernel {
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
        let (creds, root, cwd) = {
            let d = self.domain_mut(domain_id).map_err(into_sys)?;
            (d.creds(), d.chroot_root, d.cwd)
        };
        match req {
            SysRequest::Open { path, mode, create } => {
                let id = if create {
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
                let fd = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .alloc(FdTarget::File(id))
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
                        self.vfs
                            .write_by_id(inode, creds, bytes)
                            .map_err(SysError::Vfs)?;
                        Ok(SysValue::Count(bytes.len()))
                    }
                    FdTarget::PipeWrite(pipe) => {
                        let n = self.pipes.write(pipe, bytes).map_err(SysError::Pipe)?;
                        Ok(SysValue::Count(n))
                    }
                    FdTarget::PipeRead(_) => Err(SysError::BadFd(fd)),
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
                let target = self
                    .domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .get(fd)
                    .ok_or(SysError::BadFd(fd))?
                    .target;
                // A duplicated pipe end is a second reference to it.
                let acquire = match target {
                    FdTarget::PipeRead(p) => self.pipes.acquire_read(p),
                    FdTarget::PipeWrite(p) => self.pipes.acquire_write(p),
                    FdTarget::File(_) => Ok(()),
                };
                acquire.map_err(SysError::Pipe)?;
                self.domain_mut(domain_id)
                    .map_err(into_sys)?
                    .fds
                    .replace_at(new_fd, target)
                    .map_err(SysError::Fd)?;
                Ok(SysValue::Fd(new_fd))
            }
            SysRequest::Kill { target, sig } => {
                // Unix permission rules: uid 0, same uid, or self.
                let sender_uid = self.domain_mut(domain_id).map_err(into_sys)?.uid;
                let victim = self
                    .domains
                    .iter_mut()
                    .flatten()
                    .find(|d| d.id == target)
                    .ok_or(SysError::UnknownDomain(target))?;
                if sender_uid != 0 && sender_uid != victim.uid && domain_id != target {
                    return Err(SysError::PermissionDenied);
                }
                victim.signals.send(sig).map_err(SysError::Signal)?;
                Ok(SysValue::Unit)
            }
            SysRequest::Chroot { path } => {
                // Resolve against the *current* root, then re-root.
                let id = self.vfs.resolve(root, cwd, path, creds).map_err(SysError::Vfs)?;
                if self.vfs.kind_of(id) != Some(InodeKind::Dir) {
                    return Err(SysError::Vfs(VfsError::NotADirectory));
                }
                let d = self.domain_mut(domain_id).map_err(into_sys)?;
                d.chroot_root = id;
                // Hardening beyond Linux: the cwd moves with the new root,
                // closing the classic chroot-escape-with-old-cwd attack.
                d.cwd = id;
                Ok(SysValue::Unit)
            }
            SysRequest::Mkdir { path, mode } => {
                self.vfs.mkdir(root, cwd, path, creds, mode).map_err(SysError::Vfs)?;
                Ok(SysValue::Unit)
            }
            SysRequest::Unlink { path } => {
                self.vfs.unlink(root, cwd, path, creds).map_err(SysError::Vfs)?;
                Ok(SysValue::Unit)
            }
            SysRequest::NetSend { len } => {
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
                result.map(|left| SysValue::Count(left as usize)).map_err(SysError::Net)
            }
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
    pub fn net_open(&mut self, domain_id: u32) -> Result<u32, KernelError> {
        let exists = self.domains.iter().flatten().any(|d| d.id == domain_id);
        if !exists {
            return Err(KernelError::UnknownDomain(domain_id));
        }
        // Idempotent: return the existing open socket.
        if let Some(id) = self.sockets.open_socket_of(domain_id) {
            return Ok(id);
        }
        self.sockets.open(domain_id).map_err(|_| {
            // Not a KernelError variant; fold into UnknownDomain for now.
            KernelError::UnknownDomain(domain_id)
        })
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

impl Kernel {
    /// Best-effort fd close used by rollback paths (never fails the caller).
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
        SysRequest::Chroot { .. } => SYS_CHROOT,
        SysRequest::Mkdir { .. } => SYS_MKDIR,
        SysRequest::Unlink { .. } => SYS_UNLINK,
        SysRequest::NetSend { .. } => SYS_NET_SEND,
    }
}

fn into_sys(e: KernelError) -> SysError {
    match e {
        KernelError::UnknownDomain(id) => SysError::UnknownDomain(id),
        _ => SysError::UnknownDomain(0),
    }
}
