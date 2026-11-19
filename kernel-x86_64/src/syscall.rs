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
        let run = context::current();

        // Full-width bounds check first (see `normalize_nr`), then the
        // shared policy gate — before any argument is examined.
        let Some(nr8) = normalize_nr(nr) else {
            run.bad_syscalls = run.bad_syscalls.saturating_add(1);
            log_denied(run.domain, nr, "unknown syscall", -ENOSYS);
            return (-ENOSYS) as u64;
        };
        let decision = gate(&run.mask, run.quarantined, nr8);
        match decision {
            Decision::Allowed if nr8 == SYS_WRITE => sys_write(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_EXIT => {
                run.exit = ExitKind::Exited(a1);
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
            return (-EFAULT) as u64;
        }
        // copy_from_user: the domain's CR3 is active, so these reads go
        // through the domain's own tables (u64 at a time; x86 tolerates
        // the possibly-unaligned head/tail).
        let mut chunk = [0u8; 8];
        let mut written = 0u64;
        let mut off = 0u64;
        while off < len {
            let n = core::cmp::min(8, (len - off) as usize);
            let word = memops::read_u64_va(buf + off);
            chunk.copy_from_slice(&word.to_le_bytes());
            for b in chunk.iter().take(n) {
                serial::write_byte(*b);
            }
            written += n as u64;
            off += n as u64;
        }
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
        if len == 0 {
            return true;
        }
        let end = match buf.checked_add(len) {
            Some(e) if e > buf => e,
            _ => return false,
        };
        if buf >= pte::USER_LIMIT || end > pte::USER_LIMIT {
            return false;
        }
        let mut va = buf & !(pte::PAGE_SIZE_U64 - 1);
        while va < end {
            match run.tables.pte_of(va) {
                Some(e) if e & pte::PTE_U != 0 && e & pte::PTE_P != 0 => {}
                _ => return false,
            }
            va += 4096;
        }
        true
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
