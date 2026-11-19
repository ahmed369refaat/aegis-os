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
