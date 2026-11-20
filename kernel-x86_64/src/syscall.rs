//! The ring-3 syscall layer (PR-1.4): the first real syscalls.
//!
//! Invariants:
//! - **The gate runs before anything else.** Every entry calls the
//!   lib's `aegis_os::syscall::gate` — the *same* decision code the
//!   kernel-resident path uses — before any argument is even looked at.
//! - **No nr truncation before the bounds check**: a caller passing
//!   nr=256 must get -ENOSYS, not "SYS_READ" (`256 as u8 == 0` would
//!   smuggle a masked syscall through the gate). Host-tested.
//! - **User pointers are never trusted**: SYS_WRITE validates every
//!   page of [buf, buf+len) through the *domain's own* page tables
//!   (present + U bit + below the split) before a single byte is
//!   copied, and the copy goes through `memops` reads at the user VA
//!   (the domain's CR3 is active on entry, so reads fault — not walk —
//!   if the tables lie).
//! - **SYS_EXIT never returns to ring-3**: it records the exit, swaps
//!   GS back to the kernel view, and longjmps to the launch point.
//!
//! SAFETY POLICY: this module is unsafe-free; the raw entry lives in
//! `arch::syscall_entry` (allowlisted), the resume longjmp in
//! `sched::context` (allowlisted).

use aegis_os::domain::Decision;
use core::sync::atomic::{AtomicBool, Ordering};

/// N1 (ADR-0007 §1): armed around the user-copy routine. The copy is
/// provably fault-free (it touches exactly the validated bytes), so a
/// CPL0 fault while this is set can only mean the invariant broke —
/// the exception path reports it as loudly as possible.
pub static IN_USER_COPY: AtomicBool = AtomicBool::new(false);

/// N1 (ADR-0007 §1): set by the first successful dispatch for the
/// active run — a CPL0 fault *before* this is the documented
/// launch-relay limitation; after it, a CPL0 fault is a kernel bug.
pub static SYSCALLS_SERVED: AtomicBool = AtomicBool::new(false);
use aegis_os::syscall::{gate, SyscallMask, SYSCALL_COUNT, SYS_EXIT, SYS_WRITE};

/// errno values this layer returns (negated, Linux-style, in RAX).
pub const EPERM: i64 = 1;
pub const EBADF: i64 = 9;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 38;

/// Longest SYS_WRITE the kernel will service in one call (bounds the
/// copy loop; user code wanting more loops itself).
pub const MAX_WRITE: usize = 256;

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
    use crate::{hw, memops, mm::pte, serial, strutil};

    /// The SYSCALL/SYSRET dispatch: called by the naked entry with the
    /// six-register ABI (nr in RAX, args in RDI, RSI, RDX, R10, R8, R9 —
    /// arg4 rides R10 per the syscall convention, not RCX). Returns the
    /// value RAX carries back to ring-3.
    pub fn syscall_dispatch(nr: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64) -> u64 {
    SYSCALLS_SERVED.store(true, Ordering::SeqCst);
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
            Decision::Allowed if nr8 == SYS_WRITE => sys_write(run, a1, a2, a3),
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
            Decision::Allowed => {
                // In the mask, but not implemented in PR-1.4 (READ,
                // OPEN, ...). Not an attack signal — just unimplemented.
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

    /// SYS_WRITE(fd=1, buf, len) → console. Every page of the buffer
    /// must be a *user* page of this domain (present, U set, below the
    /// split); anything else is -EFAULT and the copy never starts.
    fn sys_write(run: &mut crate::sched::context::UserRun, fd: u64, buf: u64, len: u64) -> u64 {
        if fd != 1 {
            return (-EBADF) as u64;
        }
        if len as usize > MAX_WRITE {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len) {
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
        let written = crate::mm::user_range::copy_user_bytes(
            buf,
            len,
            &memops::read_u8_va,
            |b| serial::write_byte(b),
        );
        IN_USER_COPY.store(false, Ordering::SeqCst);
        run.write_bytes += written;
        written
    }

    /// Every page overlapping [buf, buf+len): present, U set, and the
    /// whole range inside the user half. The walk uses the domain's own
    /// tables — the same tables its CR3 points at.
    fn validate_user_range(
        run: &crate::sched::context::UserRun,
        buf: u64,
        len: u64,
    ) -> bool {
        // N1 (ADR-0007 §1): the arithmetic lives in the pure, host-
        // tested mm::user_range; this adapter only walks the domain's
        // own tables (the same tables its CR3 points at).
        crate::mm::user_range::validate_range(
            buf,
            len,
            MAX_WRITE as u64,
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
        serial::write_str(strutil::dec(errno as i64 as u64, &mut be));
        serial::write_str(" (audited)\n");
    }
}

#[cfg(not(test))]
pub use exec::syscall_dispatch;
