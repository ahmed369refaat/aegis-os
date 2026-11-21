//! The ring-3 syscall layer (PR-1.4 + Round J): the real syscall
//! surface.
//!
//! Invariants:
//! - **The gate runs before anything else.** Every entry calls the
//!   lib's `aegis_os::syscall::gate` — the *same* decision code the
//!   kernel-resident path uses — before any argument is even looked at.
//! - **No nr truncation before the bounds check**: a caller passing
//!   nr=256 must get -ENOSYS, not "SYS_READ" (`256 as u8 == 0` would
//!   smuggle a masked syscall through the gate). Host-tested.
//! - **User pointers are never trusted**: every buffer (write in,
//!   read out, open's path) is validated page-by-page through the
//!   *domain's own* page tables (present + U bit + below the split)
//!   before a single byte moves, and the copies are byte-exact through
//!   `memops` reads/writes at the user VA under the single blessed
//!   SMAP window (N4, ADR-0008).
//! - **The executor is the LIVE lib kernel** (Round J): the file
//!   family — OPEN/READ/WRITE/CLOSE/PIPE/DUP — marshals into
//!   `SysRequest` values and runs `Kernel::execute` on the same state
//!   the monitor reads. The runtime gates first (`dispatch`, where the
//!   accounting lands exactly once) and only an Allowed reaches the
//!   executor — the split's contract is host-tested in the lib.
//! - **SYS_EXIT never returns to ring-3**: it records the exit, swaps
//!   GS back to the kernel view, and longjmps to the launch point.
//!
//! SAFETY POLICY: this module is unsafe-free; the raw entry lives in
//! `arch::syscall_entry` (allowlisted), the resume longjmp in
//! `sched::context` (allowlisted).

use aegis_os::domain::Decision;
use core::sync::atomic::AtomicBool;

/// N1 (ADR-0007 §1): armed around the user-copy routine. The copy is
/// provably fault-free (it touches exactly the validated bytes), so a
/// CPL0 fault while this is set can only mean the invariant broke —
/// the exception path reports it as loudly as possible.
pub static IN_USER_COPY: AtomicBool = AtomicBool::new(false);

/// N1 (ADR-0007 §1): set by the first successful dispatch for the
/// active run — a CPL0 fault *before* this is the documented
/// launch-relay limitation; after it, a CPL0 fault is a kernel bug.
pub static SYSCALLS_SERVED: AtomicBool = AtomicBool::new(false);
use aegis_os::sys::{SysRequest, SysValue};
use aegis_os::syscall::{
    gate, SYSCALL_COUNT, SYS_CLOCK_GETTIME, SYS_EXIT, SYS_NANOSLEEP, SYS_SCHED_YIELD, SYS_WRITE,
};

/// errno values this layer returns (negated, Linux-style, in RAX).
pub const EPERM: i64 = 1;
pub const EBADF: i64 = 9;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;

/// Longest SYS_WRITE the kernel will service in one call (bounds the
/// copy loop; user code wanting more loops itself).
pub const MAX_WRITE: usize = 256;

/// ADR-0023: the Linux-ABI numbers of the time family map onto the
/// core's internal ids (the numbers below 64 that coincide with Linux
/// — read/write/open/close — pass through unchanged; the full
/// renumbering table is Phase 5's ABI-VERSION v0.4). Translation
/// BEFORE normalization: clock_gettime's 228 must not die in the
/// bounds check.
pub fn linux_to_core(nr: u64) -> u64 {
    match nr {
        24 => SYS_SCHED_YIELD as u64,    // sched_yield(2)
        35 => SYS_NANOSLEEP as u64,      // nanosleep(2)
        228 => SYS_CLOCK_GETTIME as u64, // clock_gettime(2)
        n => n,
    }
}

/// Normalize the raw RAX syscall number: `None` for anything outside
/// `0..SYSCALL_COUNT` — **checked on the full u64 before any cast**, so
/// nr=256 cannot truncate into SYS_READ.
pub fn normalize_nr(nr: u64) -> Option<u8> {
    if nr < SYSCALL_COUNT as u64 {
        Some(nr as u8)
    } else {
        None
    }
}

/// The pure routing table: gate decision → errno-or-zero (host-tested;
/// the target dispatch layer prints and accounts around exactly this).
pub fn errno_for(decision: &Decision) -> i64 {
    match decision {
        Decision::Allowed => 0,
        Decision::BadSyscall(_) => -ENOSYS,
        Decision::DeniedByMask(_) | Decision::DeniedQuarantined(_) => -EPERM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Round J: this import was missing all along — the module's outer
    // `#[cfg(not(test))]` (removed this round) meant these tests never
    // compiled, so the gap stayed invisible.
    use aegis_os::syscall::SyscallMask;

    fn mask() -> SyscallMask {
        SyscallMask::from_bits((1 << SYS_WRITE) | (1 << SYS_EXIT))
    }

    #[test]
    fn syscall_number_normalization_blocks_truncation_smuggling() {
        // nr=256 truncates to 0 (SYS_READ) if cast carelessly — the
        // exact attack the full-width check exists to stop.
        assert_eq!(normalize_nr(0), Some(0));
        assert_eq!(normalize_nr(SYS_WRITE as u64), Some(SYS_WRITE));
        assert_eq!(normalize_nr(63), Some(63));
        assert_eq!(normalize_nr(64), None);
        assert_eq!(normalize_nr(256), None, "must not become SYS_READ");
        assert_eq!(normalize_nr(u64::MAX), None);
    }

    #[test]
    fn gate_results_route_to_errnos() {
        let m = mask();
        assert_eq!(errno_for(&gate(&m, false, SYS_WRITE)), 0);
        assert_eq!(errno_for(&gate(&m, false, 200)), -ENOSYS);
        assert_eq!(errno_for(&gate(&m, false, 9)), -EPERM); // SYS_NET_SEND: not in mask
        assert_eq!(errno_for(&gate(&m, true, SYS_WRITE)), -EPERM); // quarantined
        assert_eq!(errno_for(&gate(&m, true, SYS_EXIT)), 0);
    }

    #[test]
    fn write_bounds_are_sane() {
        assert!(MAX_WRITE >= 64, "a hello fits comfortably");
        assert!(MAX_WRITE.is_power_of_two() || MAX_WRITE % 8 == 0);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only execution (console, user-run state, resume path).
// ─────────────────────────────────────────────────────────────────────────
#[cfg(not(test))]
mod exec {
    use super::*;
    use crate::sched::context::{self, ExitKind};
    use crate::{hw, memops, mm::pte, serial, strutil, sysabi};
    use core::sync::atomic::Ordering;

    /// The SYSCALL/SYSRET dispatch: called by the naked entry with the
    /// six-register ABI (nr in RAX, args in RDI, RSI, RDX, R10, R8, R9 —
    /// arg4 rides R10 per the syscall convention, not RCX). Returns the
    /// value RAX carries back to ring-3.
    pub fn syscall_dispatch(nr: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64) -> u64 {
        SYSCALLS_SERVED.store(true, Ordering::SeqCst);
        // ADR-0023: translate the Linux ABI numbers first (identity
        // for everything that already coincides).
        let nr = linux_to_core(nr);
        let run = context::current();

        // Full-width bounds check first (see `normalize_nr`), then the
        // shared policy gate — before any argument is examined.
        let Some(nr8) = normalize_nr(nr) else {
            run.bad_syscalls = run.bad_syscalls.saturating_add(1);
            // N2 (ADR-0007 §2): an unnormalizable nr is a denial on the
            // LIVE domain (out-of-profile by definition) and drives the
            // monitor clock.
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_unknown_syscall(run.domain);
                k.tick(crate::hw::read_tsc());
            }
            log_denied(run.domain, nr, "unknown syscall", -ENOSYS);
            return (-ENOSYS) as u64;
        };
        // N2 (ADR-0007 §2): the LIVE lib domain is the gate — stats,
        // used-bits and denials land where the monitor reads them, and
        // Tighten/Quarantine apply to the very next syscall. The
        // snapshot fields remain only as a no-kernel fallback (host
        // tests) and for display.
        let decision = match context::kernel_mut() {
            Some(k) => {
                k.tick(crate::hw::read_tsc());
                match k.dispatch(run.domain, nr8) {
                    Ok(d) => d,
                    // Unreachable: the run's domain was spawned by kmain.
                    Err(_) => Decision::BadSyscall(nr8),
                }
            }
            None => gate(&run.mask, run.quarantined, nr8),
        };
        match decision {
            Decision::Allowed if nr8 == SYS_EXIT => {
                run.exit = ExitKind::Exited(a1);
                // N2: close the window bookkeeping on the way out.
                if let Some(k) = context::kernel_mut() {
                    k.tick(crate::hw::read_tsc());
                }
                // GS back to the kernel view, then jump to the launch
                // point — SYSRET never happens for EXIT.
                hw::swapgs();
                context::resume_kernel();
            }
            Decision::Allowed if nr8 == SYS_WRITE => sys_write(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_SCHED_YIELD => sys_sched_yield(run),
            Decision::Allowed if nr8 == SYS_NANOSLEEP => sys_nanosleep(run, a1),
            Decision::Allowed if nr8 == SYS_CLOCK_GETTIME => sys_clock_gettime(run, a1, a2),
            // Round J: the file family runs on the LIVE lib kernel —
            // marshaled through sysabi, executed by `Kernel::execute`.
            Decision::Allowed if sysabi::FILE_FAMILY.contains(&nr8) => {
                sys_file(run, nr8, a1, a2, a3)
            }
            Decision::Allowed => {
                // In the mask, but not implemented (MMAP, SPAWN, IPC,
                // NET, ...). Not an attack signal — just unimplemented.
                log_denied(run.domain, nr, "not implemented yet", -ENOSYS);
                (-ENOSYS) as u64
            }
            Decision::BadSyscall(_) => {
                run.bad_syscalls = run.bad_syscalls.saturating_add(1);
                log_denied(run.domain, nr, "unknown syscall", -ENOSYS);
                (-ENOSYS) as u64
            }
            Decision::DeniedByMask(_) | Decision::DeniedQuarantined(_) => {
                run.denied = run.denied.saturating_add(1);
                log_denied(run.domain, nr, "denied by policy", -EPERM);
                (-EPERM) as u64
            }
        }
    }

    /// The file-family executor (Round J): marshal the six-register ABI
    /// into `SysRequest` values and run them on the LIVE lib kernel —
    /// the same domains, fd tables, pipes and VFS the monitor reads.
    /// The gate already allowed the nr; every argument below is still
    /// untrusted and re-validated.
    fn sys_file(
        run: &mut crate::sched::context::UserRun,
        nr: u8,
        a1: u64,
        a2: u64,
        a3: u64,
    ) -> u64 {
        use aegis_os::sys::SysRequest;
        use aegis_os::syscall::{SYS_CLOSE, SYS_DUP, SYS_OPEN, SYS_PIPE, SYS_READ};
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        match nr {
            SYS_OPEN => sys_open(run, k, a1, a2, a3),
            SYS_READ => sys_read(run, k, a1, a2, a3),
            SYS_CLOSE => match fd_arg(a1) {
                Ok(fd) => match k.execute(run.domain, SysRequest::Close { fd }) {
                    Ok(_) => 0,
                    Err(e) => sysabi::errno_of(&e) as u64,
                },
                Err(e) => e as u64,
            },
            SYS_PIPE => match k.execute(run.domain, SysRequest::Pipe) {
                Ok(v) => sysabi::rax_of(v),
                Err(e) => sysabi::errno_of(&e) as u64,
            },
            SYS_DUP => match (fd_arg(a1), fd_arg(a2)) {
                (Ok(fd), Ok(new_fd)) => match k.execute(run.domain, SysRequest::Dup { fd, new_fd })
                {
                    Ok(v) => sysabi::rax_of(v),
                    Err(e) => sysabi::errno_of(&e) as u64,
                },
                (_, Err(e)) | (Err(e), _) => e as u64,
            },
            _ => (-ENOSYS) as u64,
        }
    }

    /// An fd argument: no truncation smuggling (fd = 0x100 must be
    /// EBADF, not fd 0 — the same full-width discipline as the nr).
    fn fd_arg(a: u64) -> Result<u8, i64> {
        if a > u8::MAX as u64 {
            Err(-EBADF)
        } else {
            Ok(a as u8)
        }
    }

    /// SYS_OPEN(path, flags, mode): the path is a NUL-terminated
    /// string in user memory, read page-check-as-you-go (a short path
    /// before an absent page succeeds); flags decode through
    /// `sysabi::open_flags` (unknown bits refuse); mode is masked to
    /// 0o777 like Linux's O_CREAT mode argument.
    fn sys_open(
        run: &mut crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        path_va: u64,
        flags: u64,
        mode: u64,
    ) -> u64 {
        use aegis_os::sys::SysRequest;
        use aegis_os::vfs::Mode;
        let (read, write, create, truncate) = match sysabi::open_flags(flags) {
            Ok(f) => f,
            Err(e) => return e as u64,
        };
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        let mode = Mode((mode & 0o777) as u16);
        match k.execute(
            run.domain,
            SysRequest::Open {
                path,
                mode,
                create,
                read,
                write,
                truncate,
            },
        ) {
            Ok(v) => sysabi::rax_of(v),
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// The bounded, page-checked path copy-in (the SYS_OPEN reader).
    /// SMAP is armed around the whole walk: the page-table reads it
    /// interleaves are kernel accesses (unaffected by AC), the byte
    /// reads are user accesses (permitted only under the blessed
    /// window, N4/ADR-0008).
    fn read_user_path(
        run: &crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        va: u64,
        out: &mut [u8; sysabi::MAX_PATH],
    ) -> Result<usize, i64> {
        use crate::mm::user_range::{read_user_cstr, CstrError};
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let r = read_user_cstr(
            va,
            sysabi::MAX_PATH,
            pte::USER_LIMIT,
            pte::PAGE_SIZE_U64,
            &|page| match run.tables.pte_of(page) {
                Some(e) => e & pte::PTE_U != 0 && e & pte::PTE_P != 0,
                None => false,
            },
            &|va| memops::read_u8_va(va),
            out,
        );
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        match r {
            Ok(len) => Ok(len),
            // No NUL within MAX_PATH: the string is not path-shaped.
            Err(CstrError::TooLong) => Err(-ENAMETOOLONG),
            // A page the walk reached is not a present user page — an
            // organic fault signal on the live domain (N2).
            Err(CstrError::Fault) => {
                let _ = k.report_fault(run.domain);
                Err(-EFAULT)
            }
        }
    }

    /// sched_yield(2) — ADR-0023 D3: charge the slice, then either
    /// park-and-switch (the fair pick exists) or return 0 (solo).
    fn sys_sched_yield(run: &mut crate::sched::context::UserRun) -> u64 {
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match crate::sched::preempt::yield_decision(&mut k.sched, run.domain) {
            Some(_) => crate::sched::park::park_current_from_syscall(0),
            None => 0,
        }
    }

    /// nanosleep(2) — ADR-0023: read the timespec ONCE (page-checked,
    /// under the SMAP window), convert through THE calibrated clock
    /// (the same number the tick rides), register the sleep in the
    /// core, then park the run; the idle state covers the
    /// nothing-else-runnable case. The parked copy resumes with RAX=0
    /// — the syscall "returns" when the sleeper wakes.
    fn sys_nanosleep(run: &mut crate::sched::context::UserRun, req: u64) -> u64 {
        if !validate_user_range(run, req, 16, 16) {
            let _ = context::kernel_mut().map(|k| k.report_fault(run.domain));
            return (-EFAULT) as u64;
        }
        let mut ts = [0u8; 16];
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        for (off, b) in ts.iter_mut().enumerate() {
            *b = memops::read_u8_va(req + off as u64);
        }
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        let Some((sec, nsec)) = crate::clock::parse_timespec(&ts) else {
            return (-EINVAL) as u64;
        };
        let Some(ns) = crate::clock::timespec_to_ns(sec, nsec) else {
            return (-EINVAL) as u64;
        };
        if ns == 0 {
            // A zero sleep is a plain yield without the queue dance.
            return 0;
        }
        let Some(cycles) = crate::clock::ns_to_cycles(ns) else {
            return (-EINVAL) as u64;
        };
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            SysRequest::Nanosleep {
                now: crate::hw::read_tsc(),
                cycles,
            },
        ) {
            Ok(SysValue::Count(_)) => crate::sched::park::park_current_from_syscall(0),
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// clock_gettime(2) — ADR-0023 D4: CLOCK_MONOTONIC and
    /// CLOCK_REALTIME (equal: no RTC wiring yet — documented, not
    /// faked), computed from the calibrated TSC, copied out
    /// byte-exact through the page-checked write window.
    fn sys_clock_gettime(run: &mut crate::sched::context::UserRun, clk: u64, ts: u64) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        if clk > 1 {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, ts, 16, 16) {
            let _ = context::kernel_mut().map(|k| k.report_fault(run.domain));
            return (-EFAULT) as u64;
        }
        let ns = crate::clock::now_ns();
        let sec = (ns / 1_000_000_000u128) as u64;
        let nsec = (ns % 1_000_000_000u128) as u64;
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&sec.to_le_bytes());
        out[8..].copy_from_slice(&nsec.to_le_bytes());
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let _ = copy_out_bytes(ts, &out, &|va, b| memops::write_u8_va(va, b));
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        0
    }

    /// SYS_READ(fd, buf, len): the executor fills a KERNEL buffer
    /// (no double-fetch: the user pointer is read once, for the
    /// validation, and never again), then the bytes copy OUT
    /// byte-exact under the blessed SMAP window.
    fn sys_read(
        run: &mut crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        fd: u64,
        buf: u64,
        len: u64,
    ) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        use aegis_os::sys::SysRequest;
        if len as usize > sysabi::MAX_READ {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len, sysabi::MAX_READ as u64) {
            let _ = k.report_fault(run.domain);
            return (-EFAULT) as u64;
        }
        let fd = match fd_arg(fd) {
            Ok(fd) => fd,
            Err(e) => return e as u64,
        };
        let mut kbuf = [0u8; sysabi::MAX_READ];
        match k.execute(
            run.domain,
            SysRequest::Read {
                fd,
                buf: &mut kbuf[..len as usize],
            },
        ) {
            Ok(aegis_os::sys::SysValue::Count(n)) => {
                IN_USER_COPY.store(true, Ordering::SeqCst);
                if crate::hw::smap_active() {
                    crate::hw::stac();
                }
                let wrote = copy_out_bytes(buf, &kbuf[..n], &|va, b| memops::write_u8_va(va, b));
                if crate::hw::smap_active() {
                    crate::hw::clac();
                }
                IN_USER_COPY.store(false, Ordering::SeqCst);
                wrote
            }
            // READ always answers Count (short reads, 0 at EOF).
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// SYS_WRITE(fd, buf, len) — Round J: the full target set. fd 1 is
    /// the runtime's CONSOLE device alias exactly while the lib's fd
    /// table holds that slot Reserved (the spawn-time stdio triplet):
    /// the device path serves it without the fd table. Any other fd —
    /// or a fd 1 the domain closed/replaced — routes into the LIVE lib
    /// executor (files, pipe write ends), the same path a Unix write
    /// takes.
    fn sys_write(run: &mut crate::sched::context::UserRun, fd: u64, buf: u64, len: u64) -> u64 {
        use aegis_os::fd::FdTarget;
        if len as usize > MAX_WRITE {
            return (-EINVAL) as u64;
        }
        let console_alias = fd == 1
            && match context::kernel_mut() {
                Some(k) => match k.domain_mut(run.domain) {
                    Ok(d) => matches!(d.fds.get(1), Some(e) if e.target == FdTarget::Reserved),
                    Err(_) => false,
                },
                None => true, // no lib kernel: the PR-1.4 behavior
            };
        if console_alias {
            return sys_write_console(run, buf, len);
        }
        sys_write_file(run, fd, buf, len)
    }

    /// The console device path (PR-1.4's sys_write, unchanged): every
    /// page of the buffer must be a *user* page of this domain; the
    /// copy is byte-exact to the serial console under the blessed SMAP
    /// window.
    fn sys_write_console(run: &mut crate::sched::context::UserRun, buf: u64, len: u64) -> u64 {
        if !validate_user_range(run, buf, len, MAX_WRITE as u64) {
            // N2: a failed user-pointer validation is an organic fault
            // signal on the live domain (the exact feed the rogue
            // blob's crossing writes exercise).
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        // copy_from_user (N1, ADR-0007 §1): byte-exact — the copy span
        // equals the validated span by construction, so it cannot
        // fault. IN_USER_COPY is armed so that if this invariant ever
        // breaks, the fault is named, not billed to the user.
        IN_USER_COPY.store(true, Ordering::SeqCst);
        // N4 (ADR-0008): the single blessed SMAP window — the copy
        // reads user pages from CPL0, so it runs under STAC/CLAC when
        // (and only when) the CPU has SMAP.
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let written = crate::mm::user_range::copy_user_bytes(
            buf,
            len,
            &memops::read_u8_va,
            serial::write_byte,
        );
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        run.write_bytes += written;
        written
    }

    /// The file/pipe path (Round J): copy-IN byte-exact to a kernel
    /// buffer, then the LIVE lib executor — files write at the fd's
    /// cursor, pipes through the bounded ring, refusals keep their
    /// errno identities.
    fn sys_write_file(
        run: &mut crate::sched::context::UserRun,
        fd: u64,
        buf: u64,
        len: u64,
    ) -> u64 {
        use aegis_os::sys::{SysRequest, SysValue};
        if !validate_user_range(run, buf, len, MAX_WRITE as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let fd = match fd_arg(fd) {
            Ok(fd) => fd,
            Err(e) => return e as u64,
        };
        let mut kbuf = [0u8; MAX_WRITE];
        let mut pos = 0usize;
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        crate::mm::user_range::copy_user_bytes(buf, len, &memops::read_u8_va, |b| {
            kbuf[pos] = b;
            pos += 1;
        });
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        match context::kernel_mut() {
            Some(k) => match k.execute(
                run.domain,
                SysRequest::Write {
                    fd,
                    bytes: &kbuf[..len as usize],
                },
            ) {
                Ok(SysValue::Count(n)) => {
                    run.write_bytes += n as u64;
                    n as u64
                }
                // WRITE answers Count.
                Ok(_) => 0,
                Err(e) => sysabi::errno_of(&e) as u64,
            },
            None => (-ENOSYS) as u64,
        }
    }

    /// Every page overlapping [buf, buf+len): present, U set, and the
    /// whole range inside the user half. The walk uses the domain's own
    /// tables — the same tables its CR3 points at. `max` is the
    /// syscall's own bound (MAX_WRITE / MAX_READ — both 256 today, but
    /// the seam is explicit).
    fn validate_user_range(
        run: &crate::sched::context::UserRun,
        buf: u64,
        len: u64,
        max: u64,
    ) -> bool {
        // N1 (ADR-0007 §1): the arithmetic lives in the pure, host-
        // tested mm::user_range; this adapter only walks the domain's
        // own tables (the same tables its CR3 points at).
        crate::mm::user_range::validate_range(
            buf,
            len,
            max,
            pte::USER_LIMIT,
            pte::PAGE_SIZE_U64,
            &|va| match run.tables.pte_of(va) {
                Some(e) => e & pte::PTE_U != 0 && e & pte::PTE_P != 0,
                None => false,
            },
        )
    }

    fn log_denied(domain: u32, nr: u64, why: &str, errno: i64) {
        let mut bd = [0u8; 20];
        let mut bn = [0u8; 20];
        let mut be = [0u8; 20];
        serial::write_str("[SYSC] domain ");
        serial::write_str(strutil::dec(domain as u64, &mut bd));
        serial::write_str(" nr=");
        serial::write_str(strutil::dec(nr, &mut bn));
        serial::write_str(" ");
        serial::write_str(why);
        serial::write_str(" -> ");
        serial::write_str(strutil::dec(errno as u64, &mut be));
        serial::write_str(" (audited)\n");
    }
}

#[cfg(not(test))]
pub use exec::syscall_dispatch;
