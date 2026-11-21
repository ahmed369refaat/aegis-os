//! Scheduling context (PR-1.4 → M2-W2): the ring-3 launch/resume pair
//! (`context`), the parked-run table and the timer-driven context
//! switch (`preempt`, ADR-0012). Stage 4 (SMP) grows per-CPU runqueues
//! around the same `UserContext`/`UserRun`/`ParkedContext` types.
pub mod context;

/// ADR-0023: parking from inside a syscall (yield/sleep).
pub mod park;

#[cfg(not(test))]
pub mod preempt;
