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
        assert!(guard_selftest_hit(true, 0xdead_000, 14, 0xdead_000));
        assert!(!guard_selftest_hit(true, 0xdead_000, 14, 0xdead_004));
        assert!(!guard_selftest_hit(true, 0xdead_000, 13, 0xdead_000));
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
        assert_eq!(fault_owner(0, false, false), FaultOwner::LaunchRelayLimitation);
    }
}
