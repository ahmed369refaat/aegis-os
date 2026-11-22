//! wait4(2) — the pure half of the ADR-0003 v1 slice 3 arm.
//!
//! The policy core owns the process semantics (`wait_process`, the
//! zombie bookkeeping of ADR-0022 D7); the kernel owns the ABI
//! surface. This module holds the pieces that must be host-tested
//! without the machine: the Linux option-word decode, the wstatus
//! encoding, and the ExitKind → ExitStatus translation. The arm
//! itself (blocking, the rip-2 re-execute park) lives in
//! `syscall.rs`'s exec section with the other live arms.
//!
//! The wstatus contract is Linux's, byte for byte: a normal exit
//! reports `(code & 0xff) << 8` (WIFEXITED: the low byte is 0,
//! WEXITSTATUS reads bits 8..15), a signal death reports the signal
//! in the low 7 bits (WIFSIGNALED), and a CPL3 fault death reports
//! the signal the fault maps to. We refuse option bits whose
//! semantics we cannot honor — the same slice-2 discipline as the
//! open(2) O_* word: WUNTRACED/WCONTINUED report job-control states
//! this kernel does not have; honoring them by silence would be a
//! lie. WNOHANG is honored (a not-ready wait answers 0, the pid is
//! reported later).

use super::sysabi::EINVAL;
use crate::sched::context::ExitKind;
use aegis_os::proc::ExitStatus;

/// Linux wait4(2) option bits (wait.h): only WNOHANG is honored.
pub const LINUX_WNOHANG: u64 = 0x1;
/// Every option bit the arm understands.
pub const KNOWN_WAIT_OPTIONS: u64 = LINUX_WNOHANG;

/// Decode the options word: Ok(true) = WNOHANG (a not-ready wait
/// answers 0 instead of blocking), Ok(false) = block. Any other bit
/// refuses -EINVAL — job-control reporting (WUNTRACED, WCONTINUED,
/// WNOWAIT) is a semantic we do not have, and a dropped semantic bit
/// is not an ABI.
pub fn decode_options(bits: u64) -> Result<bool, i64> {
    if bits & !KNOWN_WAIT_OPTIONS != 0 {
        return Err(-EINVAL);
    }
    Ok(bits & LINUX_WNOHANG != 0)
}

/// The wait status word (Linux encoding, 32-bit).
/// WIFEXITED(s) == (s & 0x7f) == 0; WEXITSTATUS(s) == (s >> 8) & 0xff;
/// WIFSIGNALED(s) == (s & 0x7f) != 0 (no core-dump bit: no cores).
pub fn wstatus_word(st: &ExitStatus) -> u32 {
    match st.reason {
        // The exit code rides the struct, not the variant.
        aegis_os::proc::ExitReason::Normal => (st.code & 0xff) << 8,
        aegis_os::proc::ExitReason::Killed(sig) => u32::from(sig & 0x7f),
        // A CPL3 fault death reads as the signal it maps to.
        aegis_os::proc::ExitReason::Fault { vector } => signal_of_fault(vector),
    }
}

/// The CPL3 fault vector → the signal a Linux parent would see in
/// wstatus. The kernel's ring-3 fault kills are the honest few:
/// divide error → SIGFPE, bad opcode → SIGILL, #GP/#PF at CPL3 →
/// SIGSEGV (the guard-page, NX, and kernel-VA probes all land
/// here); anything else reports SIGKILL — the process died at the
/// kernel's hand, not by a deliverable signal.
pub fn signal_of_fault(vector: u8) -> u32 {
    match vector {
        0 => 8,   // SIGFPE  — divide error
        6 => 4,   // SIGILL  — invalid opcode
        13 => 11, // SIGSEGV — general protection at CPL3
        14 => 11, // SIGSEGV — page fault (guard/NX/kernel-VA)
        _ => 9,   // SIGKILL — the kernel terminated the run
    }
}

/// Translate a completed run's ExitKind into the lib's ExitStatus
/// for the zombie record. Exit codes are masked to 8 bits — Linux's
/// WEXITSTATUS width; the blob's exit(7) crosses as Normal(7).
pub fn exit_status_of(kind: &ExitKind) -> ExitStatus {
    match kind {
        ExitKind::Exited(code) => ExitStatus::normal((code & 0xff) as u32),
        // The lib's own fault shape — the wstatus encoding derives
        // the signal at the boundary, the zombie keeps the vector.
        ExitKind::Fault { vector, .. } => ExitStatus::fault(*vector),
        // A completed mailbox entry is never Running; the defensive
        // mapping keeps the arm total (F14: no unreachable arms).
        ExitKind::Running => ExitStatus::normal(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_decode_wnohang_and_refuses_the_rest() {
        assert_eq!(decode_options(0), Ok(false));
        assert_eq!(decode_options(LINUX_WNOHANG), Ok(true));
        // Job-control semantics we do not have: refuse, never drop.
        assert_eq!(decode_options(2), Err(-EINVAL)); // WUNTRACED
        assert_eq!(decode_options(4), Err(-EINVAL)); // WCONTINUED
        assert_eq!(decode_options(0x0100_0000), Err(-EINVAL)); // WNOWAIT
        assert_eq!(decode_options(u64::MAX), Err(-EINVAL));
    }

    #[test]
    fn wstatus_is_the_linux_word() {
        // WIFEXITED, WEXITSTATUS == 7 — the blob's probe checks
        // exactly this word (0x0700).
        let st = ExitStatus::normal(7);
        assert_eq!(wstatus_word(&st), 0x0700);
        assert_eq!(wstatus_word(&st) & 0x7f, 0); // WIFEXITED
        assert_eq!((wstatus_word(&st) >> 8) & 0xff, 7); // WEXITSTATUS
                                                        // A signal death: the low 7 bits carry the signal.
        let k = ExitStatus::killed(11);
        assert_eq!(wstatus_word(&k), 11);
        assert!(wstatus_word(&k) & 0x7f != 0); // WIFSIGNALED
                                               // A CPL3 fault death reads as its mapped signal (#PF -> 11).
        let f = ExitStatus::fault(14);
        assert_eq!(wstatus_word(&f), 11);
        // Codes wider than 8 bits mask to Linux's WEXITSTATUS width.
        assert_eq!(wstatus_word(&ExitStatus::normal(0x1FF)), 0xFF00);
    }

    #[test]
    fn exit_kind_translates_for_the_zombie_record() {
        assert_eq!(
            exit_status_of(&ExitKind::Exited(7)).reason,
            aegis_os::proc::ExitReason::Normal
        );
        assert_eq!(exit_status_of(&ExitKind::Exited(7)).code, 7);
        // exit codes mask to 8 bits crossing the boundary.
        assert_eq!(exit_status_of(&ExitKind::Exited(0x1FF)).code, 0xFF);
        // The CPL3 fault keeps the vector in the zombie; the wstatus
        // word derives the signal (#PF -> SIGSEGV, #DE -> SIGFPE).
        assert_eq!(
            exit_status_of(&ExitKind::Fault {
                vector: 14,
                cr2: 0x403301,
                error_code: 3,
                rip: 0x40144e,
                user_rsp: 0x403000,
            })
            .reason,
            aegis_os::proc::ExitReason::Fault { vector: 14 }
        );
        assert_eq!(
            wstatus_word(&exit_status_of(&ExitKind::Fault {
                vector: 0,
                cr2: 0,
                error_code: 0,
                rip: 0,
                user_rsp: 0,
            })),
            8
        );
        // The defensive total: Running never completes, but the arm
        // stays total.
        assert_eq!(
            exit_status_of(&ExitKind::Running).reason,
            aegis_os::proc::ExitReason::Normal
        );
    }

    #[test]
    fn fault_vector_table_is_the_honest_few() {
        assert_eq!(signal_of_fault(0), 8); // SIGFPE
        assert_eq!(signal_of_fault(6), 4); // SIGILL
        assert_eq!(signal_of_fault(13), 11); // SIGSEGV
        assert_eq!(signal_of_fault(14), 11); // SIGSEGV
        assert_eq!(signal_of_fault(8), 9); // double fault: SIGKILL
        assert_eq!(signal_of_fault(255), 9); // anything else: SIGKILL
    }
}
