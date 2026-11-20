//! POSIX-style signal sets and per-domain signal state.
//!
//! Semantics (Linux-flavored):
//! - Signal numbers 1..=31, stored as bits in a `u32` mask.
//! - Blocked signals stay pending; they are delivered once unblocked.
//! - `SIGKILL` (and `SIGSTOP`) cannot be blocked, caught, or ignored.
//! - Delivery order among pending unblocked signals: lowest number first.
//! - `send` on an already-pending signal is a no-op (standard coalescing).

pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGUSR2: u8 = 12;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGSTOP: u8 = 19;

pub const MAX_SIGNAL: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// 0 or > 31.
    InvalidSignal(u8),
}

/// Bitset of signals 1..=31 (bit `n-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalSet(pub u32);

impl SignalSet {
    pub const EMPTY: SignalSet = SignalSet(0);

    pub fn add(&mut self, sig: u8) -> Result<(), SignalError> {
        check(sig)?;
        self.0 |= 1u32 << (sig - 1);
        Ok(())
    }

    pub fn remove(&mut self, sig: u8) -> Result<(), SignalError> {
        check(sig)?;
        self.0 &= !(1u32 << (sig - 1));
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, sig: u8) -> bool {
        (1..=MAX_SIGNAL).contains(&sig) && self.0 & (1u32 << (sig - 1)) != 0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Signals in `self` that are not in `other`.
    #[must_use]
    pub fn difference(&self, other: SignalSet) -> SignalSet {
        SignalSet(self.0 & !other.0)
    }

    #[must_use]
    pub fn count(&self) -> u32 {
        self.0.count_ones()
    }
}

fn check(sig: u8) -> Result<(), SignalError> {
    if sig == 0 || sig > MAX_SIGNAL {
        return Err(SignalError::InvalidSignal(sig));
    }
    Ok(())
}

/// What happens to a domain that receives a signal with default handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Terminate,
    Ignore,
    Stop,
    Continue,
}

pub fn default_action(sig: u8) -> Result<DefaultAction, SignalError> {
    check(sig)?;
    Ok(match sig {
        SIGKILL | SIGTERM | SIGINT | SIGHUP | SIGQUIT => DefaultAction::Terminate,
        SIGSTOP => DefaultAction::Stop,
        SIGUSR1 | SIGUSR2 | SIGCHLD => DefaultAction::Ignore,
        _ => DefaultAction::Ignore,
    })
}

/// Unblockable, uncatchable signals (Linux: KILL and STOP).
#[must_use]
pub fn is_unblockable(sig: u8) -> bool {
    sig == SIGKILL || sig == SIGSTOP
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalState {
    pending: SignalSet,
    blocked: SignalSet,
}

impl SignalState {
    pub const fn new() -> Self {
        SignalState {
            pending: SignalSet::EMPTY,
            blocked: SignalSet::EMPTY,
        }
    }

    /// Mark a signal pending. Sending to an already-pending signal
    /// coalesces (no-op). Unblockable signals ignore the blocked mask.
    pub fn send(&mut self, sig: u8) -> Result<(), SignalError> {
        check(sig)?;
        let mut set = SignalSet::EMPTY;
        set.add(sig)?;
        self.pending.0 |= set.0;
        Ok(())
    }

    /// Block a signal (not allowed for SIGKILL/SIGSTOP).
    pub fn block(&mut self, sig: u8) -> Result<(), SignalError> {
        check(sig)?;
        if is_unblockable(sig) {
            return Err(SignalError::InvalidSignal(sig)); // EPERM-flavored
        }
        self.blocked.add(sig)?;
        Ok(())
    }

    pub fn unblock(&mut self, sig: u8) -> Result<(), SignalError> {
        check(sig)?;
        self.blocked.remove(sig)
    }

    /// Take the next deliverable signal: lowest pending number that is not
    /// blocked (unblockable signals are always deliverable).
    /// Clears it from pending and returns it.
    pub fn deliver(&mut self) -> Option<u8> {
        for sig in 1..=MAX_SIGNAL {
            if self.pending.contains(sig) && (is_unblockable(sig) || !self.blocked.contains(sig)) {
                let _ = self.pending.remove(sig);
                return Some(sig);
            }
        }
        None
    }

    /// Peek without consuming (for tests and status reporting).
    #[must_use]
    pub fn next_pending(&self) -> Option<u8> {
        (1..=MAX_SIGNAL).find(|&sig| {
            self.pending.contains(sig) && (is_unblockable(sig) || !self.blocked.contains(sig))
        })
    }

    #[must_use]
    pub fn pending(&self) -> SignalSet {
        self.pending
    }

    #[must_use]
    pub fn blocked(&self) -> SignalSet {
        self.blocked
    }

    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.next_pending().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_add_contains_remove() {
        let mut s = SignalSet::EMPTY;
        assert!(s.is_empty());
        s.add(SIGTERM).unwrap();
        s.add(SIGUSR1).unwrap();
        assert!(s.contains(SIGTERM) && s.contains(SIGUSR1));
        assert_eq!(s.count(), 2);
        s.remove(SIGTERM).unwrap();
        assert!(!s.contains(SIGTERM));
        assert!(s.contains(SIGUSR1));
        // Idempotent add (coalescing).
        s.add(SIGUSR1).unwrap();
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn invalid_signal_ids_rejected_everywhere() {
        let mut s = SignalSet::EMPTY;
        assert_eq!(s.add(0), Err(SignalError::InvalidSignal(0)));
        assert_eq!(s.add(32), Err(SignalError::InvalidSignal(32)));
        assert_eq!(s.add(255), Err(SignalError::InvalidSignal(255)));
        assert_eq!(s.remove(0), Err(SignalError::InvalidSignal(0)));
        assert_eq!(default_action(0), Err(SignalError::InvalidSignal(0)));
        assert_eq!(default_action(32), Err(SignalError::InvalidSignal(32)));
        assert!(!s.contains(0));
        assert!(!s.contains(32));
    }

    #[test]
    fn boundary_signal_31_is_valid() {
        let mut s = SignalSet::EMPTY;
        s.add(31).unwrap();
        assert!(s.contains(31));
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn blocked_signals_stay_pending_until_unblocked() {
        let mut st = SignalState::new();
        st.block(SIGUSR1).unwrap();
        st.send(SIGUSR1).unwrap();
        assert!(st.pending().contains(SIGUSR1));
        assert_eq!(st.deliver(), None, "blocked signal must not deliver");
        assert!(st.pending().contains(SIGUSR1), "still pending");
        st.unblock(SIGUSR1).unwrap();
        assert_eq!(st.deliver(), Some(SIGUSR1));
        assert!(!st.pending().contains(SIGUSR1));
        assert_eq!(st.deliver(), None);
    }

    #[test]
    fn sigkill_and_sigstop_cannot_be_blocked() {
        let mut st = SignalState::new();
        assert_eq!(st.block(SIGKILL), Err(SignalError::InvalidSignal(SIGKILL)));
        assert_eq!(st.block(SIGSTOP), Err(SignalError::InvalidSignal(SIGSTOP)));
        // Deliver even with a fully blocked mask.
        st.blocked = SignalSet(u32::MAX); // adversarial direct state
        st.send(SIGKILL).unwrap();
        assert_eq!(st.deliver(), Some(SIGKILL));
        st.send(SIGSTOP).unwrap();
        assert_eq!(st.deliver(), Some(SIGSTOP));
    }

    #[test]
    fn delivery_order_is_lowest_number_first() {
        let mut st = SignalState::new();
        for sig in [SIGUSR2, SIGHUP, SIGTERM, SIGCHLD] {
            st.send(sig).unwrap();
        }
        assert_eq!(st.deliver(), Some(SIGHUP)); // 1
        assert_eq!(st.deliver(), Some(SIGUSR2)); // 12
        assert_eq!(st.deliver(), Some(SIGTERM)); // 15
        assert_eq!(st.deliver(), Some(SIGCHLD)); // 17
        assert_eq!(st.deliver(), None);
    }

    #[test]
    fn delivery_skips_blocked_and_takes_next_unblocked() {
        let mut st = SignalState::new();
        st.block(SIGINT).unwrap();
        st.block(SIGTERM).unwrap();
        st.send(SIGINT).unwrap();
        st.send(SIGTERM).unwrap();
        st.send(SIGUSR1).unwrap();
        assert_eq!(st.deliver(), Some(SIGUSR1));
        assert_eq!(st.deliver(), None, "only blocked ones remain");
    }

    #[test]
    fn send_coalesces_duplicate_signals() {
        let mut st = SignalState::new();
        st.send(SIGUSR1).unwrap();
        st.send(SIGUSR1).unwrap();
        st.send(SIGUSR1).unwrap();
        assert_eq!(st.pending().count(), 1);
        assert_eq!(st.deliver(), Some(SIGUSR1));
        assert_eq!(st.deliver(), None);
    }

    #[test]
    fn default_actions_match_linux_semantics() {
        assert_eq!(default_action(SIGKILL).unwrap(), DefaultAction::Terminate);
        assert_eq!(default_action(SIGTERM).unwrap(), DefaultAction::Terminate);
        assert_eq!(default_action(SIGSTOP).unwrap(), DefaultAction::Stop);
        assert_eq!(default_action(SIGUSR1).unwrap(), DefaultAction::Ignore);
        assert_eq!(default_action(SIGCHLD).unwrap(), DefaultAction::Ignore);
    }

    #[test]
    fn difference_helper() {
        let mut a = SignalSet::EMPTY;
        a.add(SIGUSR1).unwrap();
        a.add(SIGUSR2).unwrap();
        let mut b = SignalSet::EMPTY;
        b.add(SIGUSR2).unwrap();
        let d = a.difference(b);
        assert!(d.contains(SIGUSR1));
        assert!(!d.contains(SIGUSR2));
    }

    #[test]
    fn has_pending_reflects_block_state() {
        let mut st = SignalState::new();
        assert!(!st.has_pending());
        st.block(SIGUSR1).unwrap();
        st.send(SIGUSR1).unwrap();
        assert!(!st.has_pending(), "blocked-only pending is not deliverable");
        st.send(SIGTERM).unwrap();
        assert!(st.has_pending());
        assert_eq!(st.next_pending(), Some(SIGTERM));
    }
}
