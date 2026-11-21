//! Round J: the ring-3 syscall ABI — the marshaling layer between the
//! six-register SYSCALL convention and the lib's `SysRequest` values.
//!
//! The register convention (internal `v0.x`, see docs/ABI-VERSION.md):
//!
//! | nr | call | a1 | a2 | a3 | RAX on success |
//! |----|------|----|----|----|----------------|
//! | 2 OPEN | open(path, flags) | path VA (NUL-terminated) | O_* flags | — | fd |
//! | 0 READ | read(fd, buf, len) | fd | buf VA | len | byte count |
//! | 1 WRITE | write(fd, buf, len) | fd | buf VA | len | byte count |
//! | 3 CLOSE | close(fd) | fd | — | — | 0 |
//! | 12 PIPE | pipe() | — | — | — | `(write_fd << 8) \| read_fd` |
//! | 13 DUP | dup2(fd, new_fd) | fd | new_fd | — | new_fd |
//!
//! Errors are Linux-style: RAX = `-errno`. The pipe pair packs into the
//! single RAX the naked entry returns (SYSRET clobbers RCX/R11, and the
//! entry stub's ABI is one quadword — the packing keeps both untouched).
//!
//! Everything here is pure and host-tested; the executor in
//! `syscall::exec` builds requests through exactly these functions, so
//! the bit layout, the errno map, and the packing are pinned by tests
//! the boot never has to guess at.

use aegis_os::sys::{SysError, SysValue};
use aegis_os::syscall::{SYS_CLOSE, SYS_DUP, SYS_OPEN, SYS_PIPE, SYS_READ, SYS_WRITE};

// ─── errno values (Linux x86_64 numbering — the compatibility target) ───
pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const ENFILE: i64 = 23;
pub const ENOSPC: i64 = 28;
pub const EPIPE: i64 = 32;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;

// ─── open(2) flags ───
pub const O_READ: u64 = 0x1;
pub const O_WRITE: u64 = 0x2;
pub const O_CREAT: u64 = 0x4;
pub const O_TRUNC: u64 = 0x8;
pub const KNOWN_OPEN_FLAGS: u64 = O_READ | O_WRITE | O_CREAT | O_TRUNC;

/// Longest path the kernel will copy in from ring-3 (bounds the copy;
/// component-length rules stay in the VFS, which owns NAME_MAX).
pub const MAX_PATH: usize = 128;

/// Longest SYS_READ the kernel services in one call (the read-side
/// mirror of syscall::MAX_WRITE).
pub const MAX_READ: usize = 256;

/// Decode the a2 flags word of SYS_OPEN. Unknown bits refuse (-EINVAL)
/// rather than ignore — an ABI the caller cannot predict is not an ABI.
/// O_TRUNC without O_WRITE refuses the same way (the lib only applies
/// truncation on the write path; POSIX leaves this combination
/// undefined, and undefined is not something we honor).
pub fn open_flags(bits: u64) -> Result<(bool, bool, bool, bool), i64> {
    if bits & !KNOWN_OPEN_FLAGS != 0 {
        return Err(-EINVAL);
    }
    let read = bits & O_READ != 0;
    let write = bits & O_WRITE != 0;
    let create = bits & O_CREAT != 0;
    let truncate = bits & O_TRUNC != 0;
    if truncate && !write {
        return Err(-EINVAL);
    }
    Ok((read, write, create, truncate))
}

/// The full SysError → errno table. Every lib refusal keeps a distinct
/// Linux meaning at the ring-3 boundary; nothing collapses into a
/// catch-all (the same F14 discipline `into_sys` applies inside the
/// lib). Host-tested one variant at a time.
pub fn errno_of(e: &SysError) -> i64 {
    match e {
        SysError::Masked(_) | SysError::Quarantined(_) => -EPERM,
        SysError::BadSyscall(_) => -ENOSYS,
        SysError::UnknownDomain(_) => -ESRCH,
        SysError::BadFd(_) => -EBADF,
        // fork-flavored resource exhaustion: try again later.
        SysError::TooManyDomains => -EAGAIN,
        SysError::DuplicateDomain(_) => -EEXIST,
        SysError::InvalidId(_) => -EINVAL,
        SysError::NotImplemented(_) => -ENOSYS,
        SysError::Reserved(_) => -EIO,
        SysError::Mem(m) => match m {
            aegis_os::memory::MemError::QuotaExceeded => -ENOMEM,
            aegis_os::memory::MemError::TableFull => -ENOMEM,
            // The rest are argument-shaped refusals: zero-length,
            // NULL base, unaligned, overflow, W+X, no access bits,
            // overlap, guard gap, not-found.
            _ => -EINVAL,
        },
        SysError::Fd(f) => match f {
            aegis_os::fd::FdError::TableFull => -EMFILE,
            aegis_os::fd::FdError::OutOfRange(_) => -EBADF,
        },
        SysError::Vfs(v) => match v {
            aegis_os::vfs::VfsError::NotFound => -ENOENT,
            aegis_os::vfs::VfsError::NotADirectory => -ENOTDIR,
            aegis_os::vfs::VfsError::PermissionDenied => -EACCES,
            aegis_os::vfs::VfsError::Exists => -EEXIST,
            aegis_os::vfs::VfsError::NameTooLong => -ENAMETOOLONG,
            aegis_os::vfs::VfsError::TableFull => -ENOSPC,
            aegis_os::vfs::VfsError::NoSpace => -ENOSPC,
            aegis_os::vfs::VfsError::NotEmpty => -ENOTEMPTY,
            aegis_os::vfs::VfsError::IsADirectory => -EISDIR,
            // A stale (id, generation) reference: the slot died. The
            // caller's handle is invalid — EBADF, not a retry.
            aegis_os::vfs::VfsError::StaleInode => -EBADF,
        },
        SysError::Pipe(p) => match p {
            aegis_os::pipe::PipeError::TableFull => -ENFILE,
            aegis_os::pipe::PipeError::InvalidPipe(_) => -EBADF,
            aegis_os::pipe::PipeError::WouldBlock => -EAGAIN,
            aegis_os::pipe::PipeError::BrokenPipe => -EPIPE,
        },
        SysError::Signal(aegis_os::signal::SignalError::InvalidSignal(_)) => -EINVAL,
        SysError::Net(n) => match n {
            aegis_os::net::NetError::TableFull => -ENFILE,
            aegis_os::net::NetError::InvalidSocket(_) => -EBADF,
            aegis_os::net::NetError::NotOpen(_) => -EBADF,
            aegis_os::net::NetError::RateLimited { .. } => -EAGAIN,
        },
        SysError::Ipc(i) => match i {
            aegis_os::ipc::IpcError::QueueFull => -EAGAIN,
            aegis_os::ipc::IpcError::QueueEmpty => -EAGAIN,
            aegis_os::ipc::IpcError::TooLong(_) => -EINVAL,
            aegis_os::ipc::IpcError::NotOwner(_) => -EPERM,
            aegis_os::ipc::IpcError::TableFull => -ENOMEM,
            aegis_os::ipc::IpcError::InvalidHandle => -EBADF,
            aegis_os::ipc::IpcError::NotAuthorized(_) => -EPERM,
            // A rights-derivation escalation attempt: permission, and
            // the monitor sees the attempt through the escalation feed.
            aegis_os::ipc::IpcError::Escalation => -EPERM,
            aegis_os::ipc::IpcError::UnknownDomain(_) => -ESRCH,
        },
        SysError::Buddy(_) => -ENOMEM,
        SysError::PermissionDenied => -EACCES,
    }
}

/// Pack a pipe's fd pair into the single RAX the entry stub returns.
/// Both fds fit the lib's MAX_FDS=16, so byte lanes cannot collide.
pub fn pack_pipe(read_fd: u8, write_fd: u8) -> u64 {
    (write_fd as u64) << 8 | read_fd as u64
}

/// Unpack (the mirror the host tests and the blob's ABI doc share).
pub fn unpack_pipe(rax: u64) -> Option<(u8, u8)> {
    let read_fd = (rax & 0xFF) as u8;
    let write_fd = ((rax >> 8) & 0xFF) as u8;
    if rax >> 16 != 0 {
        return None;
    }
    Some((read_fd, write_fd))
}

/// Convert an executor success value to the RAX word (the pipe packs;
/// everything else is already a plain non-negative integer).
pub fn rax_of(v: SysValue) -> u64 {
    match v {
        SysValue::Fd(fd) => fd as u64,
        SysValue::FdPair(r, w) => pack_pipe(r, w),
        SysValue::Count(n) => n as u64,
        SysValue::Addr(a) => a,
        SysValue::Unit => 0,
    }
}

/// The file-family syscall numbers this round wires, for the dispatch
/// table's exhaustiveness check.
pub const FILE_FAMILY: [u8; 6] = [SYS_READ, SYS_WRITE, SYS_OPEN, SYS_CLOSE, SYS_PIPE, SYS_DUP];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_decode_every_legal_combination() {
        assert_eq!(open_flags(O_READ), Ok((true, false, false, false)));
        assert_eq!(open_flags(O_WRITE), Ok((false, true, false, false)));
        assert_eq!(
            open_flags(O_READ | O_WRITE | O_CREAT | O_TRUNC),
            Ok((true, true, true, true))
        );
        // Flags==0 is a legal existence-probe open (no access bits).
        assert_eq!(open_flags(0), Ok((false, false, false, false)));
    }

    #[test]
    fn open_flags_refuse_unknown_bits_and_trunc_without_write() {
        // A bit the ABI does not define — refuse, never ignore.
        assert_eq!(open_flags(0x10), Err(-EINVAL));
        assert_eq!(open_flags(0x8000_0000), Err(-EINVAL));
        // O_TRUNC without O_WRITE: POSIX-undefined, kernel-refused.
        assert_eq!(open_flags(O_READ | O_TRUNC), Err(-EINVAL));
        assert_eq!(open_flags(O_CREAT | O_TRUNC), Err(-EINVAL));
    }

    #[test]
    fn pipe_packing_round_trips_and_rejects_high_bits() {
        assert_eq!(pack_pipe(3, 4), 0x0403);
        assert_eq!(unpack_pipe(pack_pipe(3, 4)), Some((3, 4)));
        assert_eq!(unpack_pipe(pack_pipe(0, 15)), Some((0, 15)));
        // The error convention is a negative i64 in RAX — high bits set
        // means "not a packed pair".
        assert_eq!(unpack_pipe((-EBADF) as u64), None);
        assert_eq!(unpack_pipe(u64::MAX), None);
    }

    #[test]
    fn sysvalue_to_rax_matches_the_convention() {
        assert_eq!(rax_of(SysValue::Fd(5)), 5);
        assert_eq!(rax_of(SysValue::FdPair(3, 4)), 0x0403);
        assert_eq!(rax_of(SysValue::Count(42)), 42);
        assert_eq!(rax_of(SysValue::Addr(0x400000)), 0x400000);
        assert_eq!(rax_of(SysValue::Unit), 0);
    }

    #[test]
    fn errno_map_keeps_every_refusal_distinct() {
        use aegis_os::fd::{FdError, FdTable, FdTarget, MAX_FDS};
        use aegis_os::ipc::IpcError;
        use aegis_os::memory::MemError;
        use aegis_os::net::NetError;
        use aegis_os::pipe::PipeError;
        use aegis_os::signal::SignalError;
        use aegis_os::vfs::VfsError;

        assert_eq!(errno_of(&SysError::Masked(2)), -EPERM);
        assert_eq!(errno_of(&SysError::Quarantined(2)), -EPERM);
        assert_eq!(errno_of(&SysError::BadSyscall(99)), -ENOSYS);
        assert_eq!(errno_of(&SysError::UnknownDomain(7)), -ESRCH);
        assert_eq!(errno_of(&SysError::BadFd(9)), -EBADF);
        assert_eq!(errno_of(&SysError::TooManyDomains), -EAGAIN);
        assert_eq!(errno_of(&SysError::DuplicateDomain(3)), -EEXIST);
        assert_eq!(errno_of(&SysError::InvalidId(3)), -EINVAL);
        assert_eq!(errno_of(&SysError::NotImplemented(6)), -ENOSYS);
        assert_eq!(errno_of(&SysError::Reserved(1)), -EIO);
        assert_eq!(errno_of(&SysError::Mem(MemError::QuotaExceeded)), -ENOMEM);
        assert_eq!(errno_of(&SysError::Mem(MemError::Overlap)), -EINVAL);
        assert_eq!(errno_of(&SysError::Mem(MemError::TableFull)), -ENOMEM);
        assert_eq!(errno_of(&SysError::Mem(MemError::NotFound)), -EINVAL);
        assert_eq!(errno_of(&SysError::Fd(FdError::TableFull)), -EMFILE);
        assert_eq!(errno_of(&SysError::Fd(FdError::OutOfRange(99))), -EBADF);
        assert_eq!(errno_of(&SysError::Vfs(VfsError::NotFound)), -ENOENT);
        assert_eq!(errno_of(&SysError::Vfs(VfsError::NotADirectory)), -ENOTDIR);
        assert_eq!(
            errno_of(&SysError::Vfs(VfsError::PermissionDenied)),
            -EACCES
        );
        assert_eq!(errno_of(&SysError::Vfs(VfsError::Exists)), -EEXIST);
        assert_eq!(
            errno_of(&SysError::Vfs(VfsError::NameTooLong)),
            -ENAMETOOLONG
        );
        assert_eq!(errno_of(&SysError::Vfs(VfsError::TableFull)), -ENOSPC);
        assert_eq!(errno_of(&SysError::Vfs(VfsError::NoSpace)), -ENOSPC);
        assert_eq!(errno_of(&SysError::Vfs(VfsError::NotEmpty)), -ENOTEMPTY);
        assert_eq!(errno_of(&SysError::Vfs(VfsError::IsADirectory)), -EISDIR);
        assert_eq!(errno_of(&SysError::Vfs(VfsError::StaleInode)), -EBADF);
        assert_eq!(errno_of(&SysError::Pipe(PipeError::TableFull)), -ENFILE);
        assert_eq!(errno_of(&SysError::Pipe(PipeError::InvalidPipe(1))), -EBADF);
        assert_eq!(errno_of(&SysError::Pipe(PipeError::WouldBlock)), -EAGAIN);
        assert_eq!(errno_of(&SysError::Pipe(PipeError::BrokenPipe)), -EPIPE);
        assert_eq!(
            errno_of(&SysError::Signal(SignalError::InvalidSignal(99))),
            -EINVAL
        );
        assert_eq!(errno_of(&SysError::Net(NetError::TableFull)), -ENFILE);
        assert_eq!(errno_of(&SysError::Net(NetError::InvalidSocket(1))), -EBADF);
        assert_eq!(errno_of(&SysError::Net(NetError::NotOpen(1))), -EBADF);
        assert_eq!(
            errno_of(&SysError::Net(NetError::RateLimited {
                requested: 10,
                available: 0
            })),
            -EAGAIN
        );
        assert_eq!(errno_of(&SysError::Ipc(IpcError::QueueFull)), -EAGAIN);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::QueueEmpty)), -EAGAIN);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::TooLong(9))), -EINVAL);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::NotOwner(2))), -EPERM);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::TableFull)), -ENOMEM);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::InvalidHandle)), -EBADF);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::Escalation)), -EPERM);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::UnknownDomain(9))), -ESRCH);
        assert_eq!(errno_of(&SysError::Ipc(IpcError::NotAuthorized(3))), -EPERM);
        assert_eq!(
            errno_of(&SysError::Buddy(
                aegis_os::buddy::BuddyError::OrderTooLarge(99)
            )),
            -ENOMEM
        );
        assert_eq!(errno_of(&SysError::PermissionDenied), -EACCES);
        // MAX_FDS bound sanity: the packing lanes cannot collide.
        assert!(MAX_FDS <= 16);
        let mut t = FdTable::new();
        assert_eq!(t.alloc(FdTarget::Reserved).unwrap(), 0);
    }

    #[test]
    fn file_family_numbers_match_the_lib() {
        // Pinned against aegis_os::syscall's constants — the dispatch
        // routes by these and a drift would silently misroute.
        assert_eq!(FILE_FAMILY, [0, 1, 2, 3, 12, 13]);
    }
}
