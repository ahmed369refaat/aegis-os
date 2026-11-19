//! The domain: the unit of isolation. Every process, service, driver, file
//! parser and plugin runs in its own domain with a private address space,
//! a capability table and an attenuation-only syscall mask.
//!
//! `request_syscall` is the deterministic fast path: one bounds check, one
//! state check, one bit test — no allocation, no analysis, no locking in
//! this sample. All heavier accounting happens on counters that the slow
//! path (the behavior monitor) reads asynchronously.

use crate::capability::CapabilityTable;
use crate::fd::FdTable;
use crate::memory::AddressSpace;
use crate::monitor::DomainStats;
use crate::profile::DomainProfile;
use crate::signal::SignalState;
use crate::syscall::{SyscallMask, SYS_EXIT};
use crate::vfs::{Credentials, InodeRef, ROOT_REF};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// Normal operation.
    Running,
    /// Surface narrowed by a graduated response; still serving traffic.
    Tightened,
    /// Cut off from everything except SYS_EXIT.
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Masked out for this domain.
    DeniedByMask(u8),
    /// Domain is quarantined; only SYS_EXIT passes.
    DeniedQuarantined(u8),
    /// Syscall id outside the known range.
    BadSyscall(u8),
}

pub struct Domain {
    pub id: u32,
    pub profile: DomainProfile,
    pub state: DomainState,
    /// Current syscall surface. Starts at `profile.syscalls`, only attenuates.
    mask: SyscallMask,
    pub caps: CapabilityTable,
    pub space: AddressSpace,
    pub stats: DomainStats,
    violations: u32,
    // ── Linux-like extensions ──
    /// Unix credentials of this domain (all its processes).
    pub uid: u16,
    pub gid: u16,
    /// Current working directory (VFS inode reference — F10: the
    /// generation makes stale cwd refs fail closed).
    pub cwd: InodeRef,
    /// Chroot root (VFS inode reference): path resolution cannot escape
    /// above it.
    pub chroot_root: InodeRef,
    /// Open file descriptors (files, pipe ends).
    pub fds: FdTable,
    /// Pending/blocked POSIX-style signals.
    pub signals: SignalState,
}

impl Domain {
    pub fn new(id: u32, profile: DomainProfile) -> Self {
        let mask = profile.syscalls;
        Domain {
            id,
            space: AddressSpace::new(profile.quota_pages),
            profile,
            state: DomainState::Running,
            mask,
            caps: CapabilityTable::new(),
            stats: DomainStats::default(),
            violations: 0,
            uid: 1000,
            gid: 1000,
            cwd: ROOT_REF,
            chroot_root: ROOT_REF,
            fds: FdTable::new(),
            signals: SignalState::new(),
        }
    }

    #[must_use]
    pub fn creds(&self) -> Credentials {
        Credentials { uid: self.uid, gid: self.gid }
    }

    #[must_use]
    pub fn mask(&self) -> SyscallMask {
        self.mask
    }

    #[must_use]
    pub fn state(&self) -> DomainState {
        self.state
    }

    #[must_use]
    pub fn violations(&self) -> u32 {
        self.violations
    }

    /// Deterministic fast-path syscall gate.
    ///
    /// In quarantine the domain's stats are frozen (denials there do not
    /// feed the monitor) so a quarantined domain cannot keep pumping its own
    /// risk score.
    pub fn request_syscall(&mut self, id: u8) -> Decision {
        let quarantined = self.state == DomainState::Quarantined;
        // The pure decision — shared verbatim with the Ring-3 entry path
        // (PR-1.4): one policy, two execution sites.
        let decision = crate::syscall::gate(&self.mask, quarantined, id);
        // Behavioral accounting on top; frozen under quarantine (denials
        // there do not feed the monitor) and skipped for unknown ids.
        if !quarantined && !matches!(decision, Decision::BadSyscall(_)) {
            // Attempts (even denied ones) are behavioral signal.
            self.stats.mark_used(id);
            self.stats.syscalls_total = self.stats.syscalls_total.saturating_add(1);
            if matches!(decision, Decision::DeniedByMask(_)) {
                self.violations = self.violations.saturating_add(1);
                self.stats.denied_syscalls = self.stats.denied_syscalls.saturating_add(1);
            } else {
                match id {
                    crate::syscall::SYS_NET_SEND | crate::syscall::SYS_NET_RECV => {
                        self.stats.net_ops = self.stats.net_ops.saturating_add(1);
                    }
                    crate::syscall::SYS_OPEN | crate::syscall::SYS_CLOSE => {
                        self.stats.file_ops = self.stats.file_ops.saturating_add(1);
                    }
                    crate::syscall::SYS_IPC_SEND | crate::syscall::SYS_IPC_RECV => {
                        self.stats.ipc_ops = self.stats.ipc_ops.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        decision
    }

    /// Narrow the syscall surface (monotonic: result is always a subset of
    /// the current mask). Never widens, never un-quarantines.
    pub fn tighten(&mut self, tighter: &SyscallMask) -> SyscallMask {
        self.mask = self.mask.attenuate(tighter);
        if self.state == DomainState::Running {
            self.state = DomainState::Tightened;
        }
        self.mask
    }

    /// Cut the domain down to SYS_EXIT only.
    pub fn quarantine(&mut self) {
        self.state = DomainState::Quarantined;
        self.mask = SyscallMask::from_bits(1u64 << SYS_EXIT);
    }

    /// Kernel-side hooks used by the fault path and the capability layer to
    /// feed the behavior monitor.
    pub fn record_fault(&mut self) {
        self.stats.faults = self.stats.faults.saturating_add(1);
    }

    /// A failed capability escalation or mask-widening attempt.
    pub fn record_escalation_attempt(&mut self) {
        self.stats.escalation_attempts =
            self.stats.escalation_attempts.saturating_add(1);
    }

    pub fn record_violation(&mut self) {
        self.violations = self.violations.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{parser_profile, service_profile};
    use crate::syscall::*;

    #[test]
    fn new_domain_inherits_profile_surface() {
        let d = Domain::new(1, parser_profile());
        assert_eq!(d.state(), DomainState::Running);
        assert_eq!(d.mask(), parser_profile().syscalls);
        assert_eq!(d.violations(), 0);
        assert_eq!(d.space.quota_pages(), parser_profile().quota_pages);
    }

    #[test]
    fn allowed_and_denied_syscalls_update_counters() {
        let mut d = Domain::new(7, parser_profile());
        assert_eq!(d.request_syscall(SYS_READ), Decision::Allowed);
        assert_eq!(d.request_syscall(SYS_MMAP), Decision::Allowed);
        // NET_SEND is out of the parser surface.
        assert_eq!(
            d.request_syscall(SYS_NET_SEND),
            Decision::DeniedByMask(SYS_NET_SEND)
        );
        assert_eq!(d.stats.syscalls_total, 3);
        assert_eq!(d.stats.denied_syscalls, 1);
        assert_eq!(d.violations(), 1);
        // The denied attempt is visible as out-of-profile usage.
        assert_eq!(d.stats.out_of_profile_bits(&d.mask()), 1);
    }

    #[test]
    fn out_of_range_ids_are_bad_syscalls() {
        let mut d = Domain::new(1, service_profile());
        assert_eq!(d.request_syscall(64), Decision::BadSyscall(64));
        assert_eq!(d.request_syscall(255), Decision::BadSyscall(255));
        // Bad ids do not touch the counters.
        assert_eq!(d.stats.syscalls_total, 0);
        assert_eq!(d.violations(), 0);
    }

    #[test]
    fn quarantine_denies_everything_but_exit() {
        let mut d = Domain::new(3, service_profile());
        d.quarantine();
        assert_eq!(d.state(), DomainState::Quarantined);
        assert_eq!(
            d.request_syscall(SYS_READ),
            Decision::DeniedQuarantined(SYS_READ)
        );
        assert_eq!(
            d.request_syscall(SYS_NET_SEND),
            Decision::DeniedQuarantined(SYS_NET_SEND)
        );
        assert_eq!(d.request_syscall(SYS_EXIT), Decision::Allowed);
        // Quarantine denial does not inflate stats or violations.
        assert_eq!(d.stats.syscalls_total, 0);
        assert_eq!(d.violations(), 0);
        // The quarantine mask is EXIT-only.
        assert_eq!(d.mask().count(), 1);
        assert!(d.mask().is_allowed(SYS_EXIT).unwrap());
    }

    #[test]
    fn tighten_is_monotonic_and_idempotent() {
        let mut d = Domain::new(2, service_profile());
        let before = d.mask();
        // Tightening with ALL changes nothing but flips the state.
        let m1 = d.tighten(&SyscallMask::ALL);
        assert_eq!(m1, before);
        assert_eq!(d.state(), DomainState::Tightened);

        let read_only = SyscallMask::from_ids(&[SYS_READ, SYS_EXIT]).unwrap();
        let m2 = d.tighten(&read_only);
        assert!(m2.is_subset_of(&before));
        assert_eq!(m2.count(), 2);
        // Tightening again with the same set is idempotent.
        let m3 = d.tighten(&read_only);
        assert_eq!(m3, m2);
        // Tightening with NONE collapses the surface entirely.
        let m4 = d.tighten(&SyscallMask::NONE);
        assert_eq!(m4, SyscallMask::NONE);
        assert!(d.request_syscall(SYS_READ).is_denied());
    }

    #[test]
    fn tighten_never_rescues_a_quarantined_domain() {
        let mut d = Domain::new(5, service_profile());
        d.quarantine();
        d.tighten(&SyscallMask::ALL);
        assert_eq!(d.state(), DomainState::Quarantined);
        assert_eq!(
            d.request_syscall(SYS_READ),
            Decision::DeniedQuarantined(SYS_READ)
        );
    }

    #[test]
    fn counters_saturate_instead_of_overflowing() {
        let mut d = Domain::new(9, service_profile());
        d.stats.faults = u64::MAX;
        d.stats.escalation_attempts = u64::MAX;
        d.stats.syscalls_total = u64::MAX;
        d.violations = u32::MAX;
        d.record_fault();
        d.record_escalation_attempt();
        d.record_violation();
        assert_eq!(d.stats.faults, u64::MAX);
        assert_eq!(d.stats.escalation_attempts, u64::MAX);
        assert_eq!(d.violations, u32::MAX);
        // request_syscall with a saturated total counter must not panic.
        let decision = d.request_syscall(SYS_READ);
        assert_eq!(decision, Decision::Allowed);
        assert_eq!(d.stats.syscalls_total, u64::MAX);
    }

    #[test]
    fn quarantine_from_tightened_keeps_exit() {
        let mut d = Domain::new(4, parser_profile());
        d.tighten(&SyscallMask::from_ids(&[SYS_READ, SYS_EXIT]).unwrap());
        d.quarantine();
        assert_eq!(d.request_syscall(SYS_READ), Decision::DeniedQuarantined(SYS_READ));
        assert_eq!(d.request_syscall(SYS_EXIT), Decision::Allowed);
    }
}

impl Decision {
    #[must_use]
    pub fn is_denied(&self) -> bool {
        !matches!(self, Decision::Allowed)
    }
}
