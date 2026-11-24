//! Pure fault classification for the exception dispatch (F4).
//!
//! The stack-guard selftest used to be recognized by comparing
//! `GUARD_VA == cr2` with no armed flag — and GUARD_VA's initial value
//! is 0, so a kernel NULL dereference (cr2 = 0) would print the
//! selftest's success marker and power off, hiding a real bug. The
//! classification lives here, pure and host-tested, so the dispatch
//! just asks this module.

/// True when a #PF is the armed stack-guard selftest (the terminal
/// write through a guard page). Anything else — including a NULL
/// dereference while unarmed — is not ours.
pub fn guard_selftest_hit(armed: bool, guard_va: u64, vector: u8, cr2: u64) -> bool {
    armed && vector == 14 && cr2 == guard_va
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_null_dereference_is_not_the_guard_selftest() {
        // GUARD_VA's unarmed value is 0; a NULL deref at cr2=0 used to
        // match it and print the success marker. It must not.
        assert!(!guard_selftest_hit(false, 0, 14, 0));
        // Even armed, only a #PF at exactly the armed VA matches.
        assert!(guard_selftest_hit(true, 0xdead_0000, 14, 0xdead_0000));
        assert!(!guard_selftest_hit(true, 0xdead_0000, 14, 0xdead_0004));
        assert!(!guard_selftest_hit(true, 0xdead_0000, 13, 0xdead_0000));
    }
}

/// N1 (ADR-0007 §1): who owns a fault that arrives while a user run is
/// active. Only CPL3 frames are the user's death; a CPL0 fault is a
/// kernel bug — inside the user-copy routine it is a validated-span
/// violation, anywhere else a plain kernel bug. Either way it must be
/// loud, never billed to the user, never silently resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultOwner {
    /// CPL3 frame: the domain's own fault — its death, kernel resumes.
    User,
    /// CPL0 fault inside the armed user-copy routine: the copy escaped
    /// the validated span (impossible by construction; loud if not).
    KernelBugUserCopy,
    /// CPL0 fault before the run's first syscall: the documented
    /// entry-relay limitation of this QEMU build
    /// (docs/arch/syscall-entry.md) — record + resume, kmain reports
    /// the run as blocked. Pre-syscall only: once the domain has
    /// served a syscall, launch-relay can no longer be the cause.
    LaunchRelayLimitation,
    /// Any other CPL0 fault while a run is active: a kernel bug.
    KernelBug,
}

/// Pure classification from the fault frame's privilege, the armed
/// copy flag, and whether the run has served a syscall yet
/// (host-tested).
pub fn fault_owner(cs_rpl: u8, in_user_copy: bool, syscall_served: bool) -> FaultOwner {
    if cs_rpl == 3 {
        return FaultOwner::User;
    }
    if in_user_copy {
        return FaultOwner::KernelBugUserCopy;
    }
    if !syscall_served {
        return FaultOwner::LaunchRelayLimitation;
    }
    FaultOwner::KernelBug
}

#[cfg(test)]
mod n1_tests {
    use super::*;

    #[test]
    fn only_cpl3_faults_belong_to_the_user() {
        assert_eq!(fault_owner(3, false, true), FaultOwner::User);
        assert_eq!(fault_owner(3, true, false), FaultOwner::User);
        // CPL0 while a run that already served syscalls is active is a
        // kernel bug — the PR-1.4 code billed it to the user and
        // resumed, hiding exactly the N1 over-read crash.
        assert_eq!(fault_owner(0, false, true), FaultOwner::KernelBug);
        assert_eq!(fault_owner(0, true, false), FaultOwner::KernelBugUserCopy);
        // CPL0 before the first syscall: the documented launch-relay
        // limitation (environment), resumed honestly.
        assert_eq!(
            fault_owner(0, false, false),
            FaultOwner::LaunchRelayLimitation
        );
    }
}

/// ADR-0031 section B: classification of a #DB (vector 1) trap.
///
/// The trap is reported with the frame of the instruction that was
/// ABOUT to execute when the trap fired (a trap, not a fault: the
/// trapped instruction already completed). Three sources are possible:
/// a user-set TF that survived the SYSCALL transition (kernel context,
/// inside the entry window), a ring-3 single-step (the domain's own
/// death — never a kernel halt), or a genuine kernel debug event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugTrap {
    /// CPL0, rip inside [lstar, sanitize_end]: a user-set TF that
    /// survived the transition and trapped inside the entry stub.
    /// The handler clears TF in the saved frame and resumes.
    EntryWindow,
    /// CPL3 frame: the domain single-stepped itself — the ordinary
    /// user-fault route (the domain dies, the kernel lives).
    User,
    /// CPL0 outside the window, or the window not yet captured
    /// (fails closed): the existing forensics dump.
    KernelBug,
}

/// Classify a #DB by its frame. `lstar` is the SYSCALL entry RIP (the
/// window's start — the trap-on-SYSCALL case reports rip == lstar in
/// kernel context); `sanitize_end` is the stub's runtime-captured
/// address of the instruction after the RFLAGS sanitize (the window's
/// end — once past it the stub has cleared TF itself, so any later
/// kernel-context trap is not ours). A zero `sanitize_end` means the
/// window was never captured (no syscall ran yet): fail CLOSED —
/// never resume an unknown debug event.
pub fn classify_debug(cs: u64, rip: u64, lstar: u64, sanitize_end: u64) -> DebugTrap {
    // The RPL bits name the privilege the trap fired under.
    if cs & 0x3 == 3 {
        return DebugTrap::User;
    }
    if lstar != 0 && sanitize_end != 0 && rip >= lstar && rip <= sanitize_end {
        return DebugTrap::EntryWindow;
    }
    DebugTrap::KernelBug
}

#[cfg(test)]
mod adr0031_db_tests {
    use super::*;

    const LSTAR: u64 = 0xFFFF_FFFF_8000_1000;
    const WEND: u64 = LSTAR + 0x40;

    #[test]
    fn ring3_single_step_is_the_users_own_death() {
        assert_eq!(classify_debug(0x2b, 0x400000, LSTAR, WEND), DebugTrap::User);
        // Even INSIDE the window's address range, a ring-3 frame is a
        // ring-3 trap — the privilege bits decide, the rip cannot.
        assert_eq!(classify_debug(0x2b, LSTAR, LSTAR, WEND), DebugTrap::User);
        assert_eq!(
            classify_debug(0x33, LSTAR + 8, LSTAR, WEND),
            DebugTrap::User
        );
    }

    #[test]
    fn kernel_context_inside_the_window_is_the_entry_resume() {
        // The trap-on-SYSCALL case: rip == lstar exactly.
        assert_eq!(
            classify_debug(0x30, LSTAR, LSTAR, WEND),
            DebugTrap::EntryWindow
        );
        // After the stub's first instruction.
        assert_eq!(
            classify_debug(0x30, LSTAR + 2, LSTAR, WEND),
            DebugTrap::EntryWindow
        );
        // The last in-window rip (the instruction after the sanitize).
        assert_eq!(
            classify_debug(0x30, WEND, LSTAR, WEND),
            DebugTrap::EntryWindow
        );
    }

    #[test]
    fn kernel_context_outside_the_window_is_a_kernel_bug() {
        assert_eq!(
            classify_debug(0x30, LSTAR + 0x41, LSTAR, WEND),
            DebugTrap::KernelBug
        );
        // Before the stub (impossible — LSTAR is the entry — but the
        // classifier must not accept it).
        assert_eq!(
            classify_debug(0x30, LSTAR - 8, LSTAR, WEND),
            DebugTrap::KernelBug
        );
    }

    #[test]
    fn an_uncaptured_window_fails_closed() {
        // sanitize_end == 0 (no syscall ever ran): never resume.
        assert_eq!(classify_debug(0x30, LSTAR, LSTAR, 0), DebugTrap::KernelBug);
        // lstar == 0 (MSR not armed): never resume.
        assert_eq!(classify_debug(0x30, 0x1000, 0, WEND), DebugTrap::KernelBug);
    }
}
