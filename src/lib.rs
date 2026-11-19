//! # AegisOS core
//!
//! A `no_std` sample of the AegisOS architecture: Unix-philosophy building
//! blocks (processes/domains, scheduling-relevant fast paths, memory, VFS
//! mediated by capabilities, drivers-as-domains, syscalls) under a policy of
//! strict isolation and least privilege, plus an integrated behavioral
//! security monitor with a graduated response.
//!
//! ## Layering
//!
//! ```text
//!  +-------------------------------------------------------------+
//!  |  User domains: apps / services / parsers / plugins / drivers |
//!  +------------------------------+------------------------------+
//!                                 | syscalls (mask-gated, O(1))
//!  +------------------------------v------------------------------+
//!  |  Domain layer: syscall mask (attenuation-only), capability   |
//!  |  table, private address space (W^X, guard gaps, quotas)      |
//!  +------------------------------+------------------------------+
//!          fast path (deterministic)          slow path (batched)
//!  +------------------------------v------------------------------+
//!  |  Dispatcher: bit-test gate,     |  BehaviorMonitor: integer  |
//!  |  saturating counters, telemetry |  risk score, hysteresis,   |
//!  |  ring (non-blocking push)       |  graduated response        |
//!  +---------------------------------+---------------------------+
//!                                    |
//!  +--------------------------------v----------------------------+
//!  |  Response: Log -> Tighten (reductive) -> Quarantine (exit-   |
//!  |  only), all recorded as SecurityEvent telemetry              |
//!  +-------------------------------------------------------------+
//! ```
//!
//! This crate is `no_std` in every non-test build (`cfg_attr`); unit and
//! integration tests run on the host with `std` enabled for assertions.
//! Zero dependencies: the entire supply-chain surface is this repository.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod capability;
pub mod domain;
pub mod memory;
pub mod monitor;
pub mod profile;
pub mod response;
pub mod ringbuf;
pub mod syscall;

use core::array;

use crate::domain::{Decision, Domain, DomainState};
use crate::monitor::{BehaviorMonitor, DomainStats, MonitorConfig, Verdict};
use crate::profile::DomainProfile;
use crate::response::{apply_response, SecurityEvent, TELEMETRY_CAPACITY};
use crate::ringbuf::RingBuffer;
use crate::syscall::SyscallMask;

/// Maximum simultaneously resident domains in this sample kernel.
pub const MAX_DOMAINS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    TooManyDomains,
    DuplicateDomain(u32),
    UnknownDomain(u32),
}

/// The sample kernel: owns domains, the behavior monitor and the telemetry
/// ring. `dispatch` is the deterministic fast path; `audit` is the batched
/// slow path that runs once per monitoring window.
pub struct Kernel {
    domains: [Option<Domain>; MAX_DOMAINS],
    monitor: BehaviorMonitor,
    telemetry: RingBuffer<SecurityEvent, TELEMETRY_CAPACITY>,
}

impl Kernel {
    pub fn new() -> Self {
        Kernel {
            domains: array::from_fn(|_| None),
            monitor: BehaviorMonitor::new(MonitorConfig::default()),
            telemetry: RingBuffer::new()
                .expect("TELEMETRY_CAPACITY is a power of two by construction"),
        }
    }

    /// Spawn a domain from a profile. The profile's mask is the *maximal*
    /// surface this domain will ever have.
    pub fn create_domain(&mut self, id: u32, profile: DomainProfile) -> Result<(), KernelError> {
        if self.domains.iter().flatten().any(|d| d.id == id) {
            return Err(KernelError::DuplicateDomain(id));
        }
        for slot in self.domains.iter_mut() {
            if slot.is_none() {
                *slot = Some(Domain::new(id, profile));
                return Ok(());
            }
        }
        Err(KernelError::TooManyDomains)
    }

    fn domain_mut(&mut self, id: u32) -> Result<&mut Domain, KernelError> {
        self.domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(KernelError::UnknownDomain(id))
    }

    /// Fast path: gate one syscall for one domain. O(1), allocation-free.
    pub fn dispatch(&mut self, domain_id: u32, syscall_id: u8) -> Result<Decision, KernelError> {
        Ok(self.domain_mut(domain_id)?.request_syscall(syscall_id))
    }

    /// Fault-path hook (page faults, guard-page hits, quota hits).
    pub fn report_fault(&mut self, domain_id: u32) -> Result<(), KernelError> {
        self.domain_mut(domain_id)?.record_fault();
        Ok(())
    }

    /// Escalation hook (failed capability derivation, mask-widening attempts).
    pub fn report_escalation_attempt(&mut self, domain_id: u32) -> Result<(), KernelError> {
        self.domain_mut(domain_id)?.record_escalation_attempt();
        Ok(())
    }

    /// Slow path, once per monitoring window: score the domain's window
    /// stats, apply the graduated response, then close the window (reset
    /// per-window counters).
    pub fn audit(&mut self, domain_id: u32) -> Result<Verdict, KernelError> {
        let (stats, mask, sensitivity) = {
            let d = self.domain_mut(domain_id)?;
            (d.stats, d.mask(), d.profile.sensitivity)
        };
        let verdict = self.monitor.evaluate(domain_id, &stats, &mask, sensitivity);
        if let Some(d) = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
        {
            let _ = apply_response(d, &verdict, &mut self.telemetry);
            // Window closed: per-window signals start fresh. Quarantine is
            // terminal — recovery is a supervised respawn, never a widen.
            d.stats = DomainStats::default();
        }
        Ok(verdict)
    }

    #[must_use]
    pub fn domain_state(&self, domain_id: u32) -> Option<DomainState> {
        self.domains
            .iter()
            .flatten()
            .find(|d| d.id == domain_id)
            .map(Domain::state)
    }

    #[must_use]
    pub fn domain_mask(&self, domain_id: u32) -> Option<SyscallMask> {
        self.domains
            .iter()
            .flatten()
            .find(|d| d.id == domain_id)
            .map(Domain::mask)
    }

    #[must_use]
    pub fn telemetry(&self) -> &RingBuffer<SecurityEvent, TELEMETRY_CAPACITY> {
        &self.telemetry
    }

    pub fn pop_event(&mut self) -> Option<SecurityEvent> {
        self.telemetry.pop()
    }
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience re-exports for downstream kernels and tests.
pub mod prelude {
    pub use crate::capability::{
        CapError, CapHandle, Capability, CapabilityTable, Resource, Rights, MAX_CAPABILITIES,
    };
    pub use crate::domain::{Decision, Domain, DomainState};
    pub use crate::{
        memory::{AddressSpace, MemError, MemFlags, Region, MAX_REGIONS, PAGE_SIZE},
        monitor::{
            BehaviorMonitor, DomainStats, MonitorConfig, MonitorWeights, Response, Verdict,
            MAX_MONITORED,
        },
    };
    pub use crate::profile::{
        driver_profile, parser_profile, plugin_profile, service_profile, DomainProfile,
    };
    pub use crate::response::{
        apply_response, tightened_surface, EventAction, Outcome, SecurityEvent,
        TELEMETRY_CAPACITY,
    };
    pub use crate::ringbuf::{RingBuffer, RingError};
    pub use crate::syscall::{
        MaskError, SyscallMask, SYSCALL_COUNT, SYS_CLOSE, SYS_EXIT, SYS_IOCTL, SYS_IPC_RECV,
        SYS_IPC_SEND, SYS_MMAP, SYS_MUNMAP, SYS_NET_RECV, SYS_NET_SEND, SYS_OPEN, SYS_READ,
        SYS_SPAWN, SYS_WRITE,
    };
    pub use crate::{Kernel, KernelError, MAX_DOMAINS};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{parser_profile, service_profile};

    #[test]
    fn domain_lifecycle_and_lookup_errors() {
        let mut k = Kernel::new();
        k.create_domain(1, parser_profile()).unwrap();
        assert_eq!(
            k.create_domain(1, service_profile()),
            Err(KernelError::DuplicateDomain(1))
        );
        assert_eq!(k.dispatch(42, SYS_READ_ID), Err(KernelError::UnknownDomain(42)));
        assert_eq!(k.report_fault(42), Err(KernelError::UnknownDomain(42)));
        assert_eq!(k.audit(42), Err(KernelError::UnknownDomain(42)));
        assert!(k.domain_state(42).is_none());
        assert!(k.domain_mask(42).is_none());
    }

    #[test]
    fn domain_table_fills_at_max_domains() {
        let mut k = Kernel::new();
        for id in 0..MAX_DOMAINS as u32 {
            k.create_domain(id, parser_profile()).unwrap();
        }
        assert_eq!(
            k.create_domain(MAX_DOMAINS as u32, parser_profile()),
            Err(KernelError::TooManyDomains)
        );
    }

    #[test]
    fn dispatch_gates_by_profile() {
        let mut k = Kernel::new();
        k.create_domain(7, parser_profile()).unwrap();
        assert_eq!(k.dispatch(7, SYS_READ_ID).unwrap(), Decision::Allowed);
        assert_eq!(
            k.dispatch(7, SYS_NET_SEND_ID).unwrap(),
            Decision::DeniedByMask(SYS_NET_SEND_ID)
        );
        assert_eq!(k.dispatch(7, 200).unwrap(), Decision::BadSyscall(200));
    }

    #[test]
    fn audit_applies_response_and_closes_window() {
        let mut k = Kernel::new();
        k.create_domain(3, service_profile()).unwrap();
        // Clean window: log.
        let v = k.audit(3).unwrap();
        assert_eq!(v.response, crate::monitor::Response::Log);
        // Counters were reset by the audit (window closed).
        let stats = k.domain_mut(3).unwrap().stats;
        assert_eq!(stats, DomainStats::default());
    }

    const SYS_READ_ID: u8 = crate::syscall::SYS_READ;
    const SYS_NET_SEND_ID: u8 = crate::syscall::SYS_NET_SEND;
}
