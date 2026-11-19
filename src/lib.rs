//! # AegisOS core
//!
//! A `no_std` sample of the AegisOS architecture: Unix-philosophy building
//! blocks under a policy of strict isolation and least privilege —
//! attenuation-only syscall masks, capabilities, W^X memory, buddy frame
//! allocation — plus a full Linux-like semantics layer (VFS with Unix
//! permissions and chroot, fd tables, pipes, signals, CFS scheduling,
//! brokered rate-limited sockets) and an integrated behavioral security
//! monitor with a graduated response.
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

pub mod buddy;
pub mod capability;
pub mod domain;
pub mod fd;
pub mod memory;
pub mod monitor;
pub mod net;
pub mod pipe;
pub mod profile;
pub mod response;
pub mod ringbuf;
pub mod sched;
pub mod signal;
pub mod sys;
pub mod syscall;
pub mod vfs;

use core::array;

use crate::buddy::BuddyAllocator;
use crate::domain::{Decision, Domain, DomainState};
use crate::fd::{FdTarget, MAX_FDS};
use crate::monitor::{BehaviorMonitor, DomainStats, MonitorConfig, Verdict};
use crate::net::{SocketTable, TokenBucket};
use crate::pipe::PipeTable;
use crate::profile::DomainProfile;
use crate::capability::{CapError, CapHandle, Capability, Rights};
use crate::memory::{MemError, MemFlags};
use crate::monitor::{MonitorMode, Response};
use crate::response::{apply_response, EventAction, SecurityEvent, TELEMETRY_CAPACITY};
use crate::ringbuf::RingBuffer;
use crate::sched::Scheduler;
use crate::syscall::SyscallMask;
use crate::vfs::Vfs;

/// Maximum simultaneously resident domains in this sample kernel.
pub const MAX_DOMAINS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    TooManyDomains,
    DuplicateDomain(u32),
    UnknownDomain(u32),
    /// The domain id cannot produce safe credentials through the
    /// derived-uid scheme (F3: wrapping to uid 0, or aliasing another
    /// id's uid). Explicit credentials via `create_domain_with` are the
    /// only way to such uids.
    InvalidId(u32),
}

/// The sample kernel: owns domains, the behavior monitor, the telemetry
/// ring and the Linux-like machinery (VFS, fd tables, pipes, signals,
/// scheduler, buddy allocator, brokered sockets).
///
/// `dispatch` is the deterministic fast path; `syscall` (in `sys.rs`) is
/// the executing layer that runs only after the gate allows; `audit` is
/// the batched slow path that runs once per monitoring window.
pub struct Kernel<const N: usize = { crate::buddy::FRAME_COUNT }> {
    pub(crate) domains: [Option<Domain>; MAX_DOMAINS],
    monitor: BehaviorMonitor,
    telemetry: RingBuffer<SecurityEvent, TELEMETRY_CAPACITY>,
    // ── Linux-like state ──
    /// Global filesystem with Unix permissions.
    pub(crate) vfs: Vfs,
    /// Anonymous pipes shared between domains via fds.
    pub(crate) pipes: PipeTable,
    /// Brokered sockets (owned by domains, rate-limited per domain).
    pub(crate) sockets: SocketTable,
    /// Per-domain token buckets (indexed by free slot, keyed by domain id).
    pub(crate) buckets: [Option<(u32, TokenBucket)>; MAX_DOMAINS],
    /// CFS-style fair scheduler over runnable domains.
    pub sched: Scheduler,
    /// Physical page-frame buddy allocator over `N` frames (the bootable
    /// kernel uses 4096 = its 16 MiB pool; the default is the library
    /// arena size — existing call sites and tests are unchanged).
    pub frames: BuddyAllocator<N>,
    /// Kernel clock in ticks (drives rate-limit windows).
    pub(crate) clock: u64,
    /// F9: AuditOnly computes+logs verdicts without applying them.
    monitor_mode: MonitorMode,
    /// F6: monitoring window length in ticks (drives `tick`).
    window_len: u64,
    /// Index of the last audited window (`tick` audits on change).
    last_window: u64,
}

impl Kernel<{ crate::buddy::FRAME_COUNT }> {
    /// Fresh kernel over the default 256-frame arena. Every existing
    /// call site and test constructs this; type-parameter defaults do
    /// not guide inference, so this pins the arena explicitly.
    pub fn new() -> Self {
        Kernel::new_over_arena()
    }
}

impl<const N: usize> Kernel<N> {
    /// Fresh kernel over an `N`-frame buddy arena. The bootable kernel
    /// uses `Kernel::<4096>::new_over_arena()` (its 16 MiB pool, PR-1.3).
    pub fn new_over_arena() -> Self {
        Kernel {
            domains: array::from_fn(|_| None),
            monitor: BehaviorMonitor::new(MonitorConfig::default()),
            telemetry: RingBuffer::new()
                .expect("TELEMETRY_CAPACITY is a power of two by construction"),
            vfs: Vfs::new(),
            pipes: PipeTable::new(),
            sockets: SocketTable::new(),
            buckets: [None; MAX_DOMAINS],
            sched: Scheduler::new(),
            frames: BuddyAllocator::new_over_arena(),
            clock: 0,
            monitor_mode: MonitorMode::default(),
            window_len: 100,
            last_window: 0,
        }
    }

    /// Spawn a domain from a profile. The profile's mask is the *maximal*
    /// surface this domain will ever have. Credentials are deterministic:
    /// uid = 1000 + id, gid = 100; nice = 0. Use `create_domain_with` for
    /// explicit control.
    pub fn create_domain(&mut self, id: u32, profile: DomainProfile) -> Result<(), KernelError> {
        // F3: derived credentials must be injective and never root.
        // The old `wrapping_add` made id 64536 wrap to uid 0 and let
        // every id > 65535 alias a low id's uid.
        if id > u16::MAX as u32 {
            return Err(KernelError::InvalidId(id));
        }
        let uid = match 1000u16.checked_add(id as u16) {
            Some(u) if u != 0 => u,
            _ => return Err(KernelError::InvalidId(id)),
        };
        self.create_domain_with(id, profile, uid, 100, 0)
    }

    /// Spawn a domain with explicit credentials and nice level.
    pub fn create_domain_with(
        &mut self,
        id: u32,
        profile: DomainProfile,
        uid: u16,
        gid: u16,
        nice: i8,
    ) -> Result<(), KernelError> {
        if self.domains.iter().flatten().any(|d| d.id == id) {
            return Err(KernelError::DuplicateDomain(id));
        }
        let slot = self
            .domains
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(KernelError::TooManyDomains)?;
        let mut d = Domain::new(id, profile);
        d.uid = uid;
        d.gid = gid;
        // Both the cwd and the chroot root start at the VFS root.
        d.cwd = crate::vfs::ROOT_ID;
        d.chroot_root = crate::vfs::ROOT_ID;
        *slot = Some(d);
        // Register with the fair scheduler (idempotent).
        let _ = self.sched.register(id, nice);
        Ok(())
    }

    /// Mutable access to a domain (its fields are public: address space,
    /// fd table, signal state, credentials). The syscall gate is the only
    /// way to *execute* anything; this accessor is for supervisors and the
    /// kernel runtime that manage domain state.
    pub fn domain_mut(&mut self, id: u32) -> Result<&mut Domain, KernelError> {
        self.domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(KernelError::UnknownDomain(id))
    }

    /// Destroy a domain and release everything it holds:
    ///
    /// - pipe ends referenced by its open descriptors (dup-aware: an end
    ///   closes only when its last referencing descriptor goes away),
    /// - its brokered socket and rate bucket,
    /// - its scheduler registration,
    /// - its table slot (immediately reusable).
    ///
    /// VFS inodes it created persist — files outlive their creators (Unix
    /// semantics). Works on quarantined domains too: this is the
    /// supervised-respawn removal path. Never widens anything anywhere.
    pub fn destroy_domain(&mut self, id: u32) -> Result<(), KernelError> {
        let slot = self
            .domains
            .iter()
            .position(|s| matches!(s, Some(d) if d.id == id))
            .ok_or(KernelError::UnknownDomain(id))?;
        // F7: the domain's monitor state dies with it — a respawned id
        // is born clean, never heir to its predecessor's quarantine.
        self.monitor.reset(id);
        // Close every descriptor, releasing pipe ends as we go.
        for fd in 0..MAX_FDS {
            if let Some(entry) = self.domains[slot].as_mut().expect("checked above").fds.close(fd as u8) {
                match entry.target {
                    FdTarget::PipeRead(p) => {
                        let _ = self.pipes.release_read(p);
                    }
                    FdTarget::PipeWrite(p) => {
                        let _ = self.pipes.release_write(p);
                    }
                    FdTarget::File(_) => {}
                }
            }
        }
        // Close its brokered socket and drop its rate bucket.
        if let Some(sock) = self.sockets.open_socket_of(id) {
            let _ = self.sockets.close(sock);
        }
        for b in self.buckets.iter_mut() {
            if matches!(b, Some((bid, _)) if *bid == id) {
                *b = None;
            }
        }
        // Unregister from the fair scheduler and free the slot.
        let _ = self.sched.unregister(id);
        self.domains[slot] = None;
        Ok(())
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
        match self.monitor_mode {
            // F9: the calibration mode — compute and log, apply nothing.
            MonitorMode::AuditOnly => {
                let action = match verdict.response {
                    Response::Log => EventAction::Log,
                    Response::Tighten => EventAction::Tighten,
                    Response::Quarantine => EventAction::Quarantine,
                };
                let _ = self.telemetry.push(SecurityEvent {
                    domain_id,
                    score: verdict.score,
                    action,
                });
            }
            MonitorMode::Enforce => {
                if let Some(d) = self
                    .domains
                    .iter_mut()
                    .flatten()
                    .find(|d| d.id == domain_id)
                {
                    let _ = apply_response(d, &verdict, &mut self.telemetry);
                }
            }
        }
        if let Some(d) = self
            .domains
            .iter_mut()
            .flatten()
            .find(|d| d.id == domain_id)
        {
            // Window closed: per-window signals start fresh. Quarantine is
            // terminal — recovery is a supervised respawn, never a widen.
            d.stats = DomainStats::default();
        }
        Ok(verdict)
    }

    /// F9: set the monitor mode (Enforce by default; AuditOnly is the
    /// calibration mode). Affects every subsequent audit/tick window.
    pub fn set_monitor_mode(&mut self, mode: MonitorMode) {
        self.monitor_mode = mode;
    }

    #[must_use]
    pub fn monitor_mode(&self) -> MonitorMode {
        self.monitor_mode
    }

    /// F7: supervisor-only monitor reset for one domain (the
    /// un-quarantine path after human review). Destroy clears the state
    /// automatically; this is the explicit, live-domain variant.
    /// Returns true if the domain had monitor state.
    pub fn reset_monitor(&mut self, domain_id: u32) -> bool {
        self.monitor.reset(domain_id)
    }

    /// F7: is the monitor's state table overflown (fail-safe notice
    /// for supervisors)?
    #[must_use]
    pub fn monitor_degraded(&self) -> bool {
        self.monitor.is_degraded()
    }

    /// F6: set the monitoring window length in ticks (>= 1; 0 clamps
    /// to 1). Window boundaries drive `tick`'s audits.
    pub fn set_monitor_window(&mut self, len: u64) {
        self.window_len = len.max(1);
    }

    /// F6: advance time; when a monitoring-window boundary is crossed,
    /// audit every live domain (the automatic slow path — `audit`
    /// remains the manual, single-domain API).
    pub fn tick(&mut self, now: u64) {
        let window = now / self.window_len;
        if window == self.last_window {
            return;
        }
        self.last_window = window;
        let ids = self.domain_ids();
        for id in ids.iter().flatten() {
            let _ = self.audit(*id);
        }
    }

    fn domain_ids(&self) -> [Option<u32>; MAX_DOMAINS] {
        let mut ids = [None; MAX_DOMAINS];
        for (slot, id) in self.domains.iter().flatten().map(|d| d.id).zip(ids.iter_mut()) {
            *id = Some(slot);
        }
        ids
    }

    /// F6: supervisor wrapper over `CapabilityTable::attenuate` — every
    /// failed operation (Escalation / MissingGrantRight / InvalidHandle)
    /// feeds the domain's escalation signal automatically. On success
    /// the child capability is inserted and its handle returned.
    pub fn cap_attenuate(
        &mut self,
        domain_id: u32,
        parent: CapHandle,
        rights: Rights,
    ) -> Result<CapHandle, CapError> {
        let d = match self.domain_mut(domain_id) {
            Ok(d) => d,
            // Supervisor misuse: an unknown domain cannot hold handles.
            Err(_) => return Err(CapError::InvalidHandle),
        };
        let derived = match d.caps.attenuate(parent, rights) {
            Ok(c) => c,
            Err(e @ (CapError::Escalation | CapError::MissingGrantRight | CapError::InvalidHandle)) => {
                d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        d.caps.insert(derived)
    }

    /// F6: supervisor wrapper; a stale handle is an escalation signal.
    pub fn cap_revoke(&mut self, domain_id: u32, handle: CapHandle) -> Result<Capability, CapError> {
        let d = match self.domain_mut(domain_id) {
            Ok(d) => d,
            Err(_) => return Err(CapError::InvalidHandle),
        };
        match d.caps.revoke(handle) {
            Ok(c) => Ok(c),
            Err(e @ CapError::InvalidHandle) => {
                d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// F6: supervisor wrapper; a stale handle is an escalation signal.
    pub fn cap_lookup(&mut self, domain_id: u32, handle: CapHandle) -> Result<Capability, CapError> {
        let d = match self.domain_mut(domain_id) {
            Ok(d) => d,
            Err(_) => return Err(CapError::InvalidHandle),
        };
        match d.caps.lookup(handle) {
            Ok(c) => Ok(c),
            Err(e @ CapError::InvalidHandle) => {
                d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// F6: map memory into a domain's policy space — every policy
    /// refusal (W^X, guard gap, quota, overlap) feeds the domain's
    /// fault signal automatically. This is the path MMAP (F13) uses.
    pub fn domain_map(
        &mut self,
        domain_id: u32,
        base: usize,
        len: usize,
        flags: MemFlags,
    ) -> Result<(), MemError> {
        let d = match self.domain_mut(domain_id) {
            Ok(d) => d,
            Err(_) => return Err(MemError::Overflow), // unreachable for callers that checked the id
        };
        match d.space.map(base, len, flags) {
            Ok(()) => Ok(()),
            Err(e @ (MemError::WxViolation
            | MemError::Overlap
            | MemError::GuardGap
            | MemError::QuotaExceeded)) => {
                d.stats.faults = d.stats.faults.saturating_add(1);
                Err(e)
            }
            Err(e) => Err(e),
        }
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
    pub use crate::buddy::{BuddyAllocator, BuddyError, FRAME_COUNT, MAX_ORDER};
    pub use crate::capability::{
        CapError, CapHandle, Capability, CapabilityTable, Resource, Rights, MAX_CAPABILITIES,
    };
    pub use crate::domain::{Decision, Domain, DomainState};
    pub use crate::fd::{FdEntry, FdError, FdTable, FdTarget, MAX_FDS};
    pub use crate::net::{
        NetError, Socket, SocketState, SocketTable, TokenBucket, RATE_WINDOW_TICKS,
    };
    pub use crate::pipe::{PipeError, PipeTable, MAX_PIPES, PIPE_CAPACITY};
    pub use crate::sched::{SchedEntity, SchedError, Scheduler, NICE0_WEIGHT, NICE_TO_WEIGHT};
    pub use crate::signal::{
        default_action, is_unblockable, SignalError, SignalSet, SignalState, SIGHUP, SIGINT,
        SIGKILL, SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2,
    };
    pub use crate::sys::{SysError, SysRequest, SysValue};
    pub use crate::syscall::{
        MaskError, SyscallMask, SYSCALL_COUNT, SYS_CHROOT, SYS_CLOSE, SYS_DUP, SYS_EXIT,
        SYS_IOCTL, SYS_IPC_RECV, SYS_IPC_SEND, SYS_KILL, SYS_MMAP, SYS_MKDIR, SYS_MUNMAP,
        SYS_NET_RECV, SYS_NET_SEND, SYS_OPEN, SYS_PIPE, SYS_READ, SYS_SPAWN, SYS_UNLINK,
        SYS_WRITE,
    };
    pub use crate::vfs::{
        Credentials, InodeKind, Mode, Vfs, VfsError, FILE_DATA_MAX, MAX_INODES, NAME_MAX, ROOT_ID,
    };
    pub use crate::{
        memory::{AddressSpace, MemError, MemFlags, Region, MAX_REGIONS, PAGE_SIZE},
        monitor::{
            BehaviorMonitor, DomainStats, MonitorConfig, MonitorWeights, Response, Verdict,
            MAX_MONITORED,
        },
        profile::{
            driver_profile, netd_profile, parser_profile, plugin_profile, service_profile,
            DomainProfile,
        },
        response::{
            apply_response, EventAction, Outcome, SecurityEvent,
            TELEMETRY_CAPACITY,
        },
    };
    pub use crate::ringbuf::{RingBuffer, RingError};
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

    /// F6: a failed capability operation (wididing / missing grant /
    /// stale handle) feeds the monitor's escalation signal automatically
    /// — through the Kernel wrappers, with no manual recording hook.
    #[test]
    fn failed_capability_ops_record_escalations_automatically() {
        use crate::capability::{CapError, Capability, Resource, Rights};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        let grantor = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability { resource: Resource::FsNode(1), rights: Rights::READ.union(Rights::GRANT), generation: 0 })
            .unwrap();
        let bare = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability { resource: Resource::FsNode(9), rights: Rights::READ, generation: 0 })
            .unwrap();
        let before = k.domain_mut(1).unwrap().stats.escalation_attempts;
        // Widening: child wants WRITE the parent never had.
        assert!(matches!(
            k.cap_attenuate(1, grantor, Rights::READ.union(Rights::WRITE)),
            Err(CapError::Escalation)
        ));
        // Deriving without GRANT.
        assert!(matches!(
            k.cap_attenuate(1, bare, Rights::READ),
            Err(CapError::MissingGrantRight)
        ));
        // Revoke once (succeeds), then the stale handle fails twice.
        assert!(k.cap_revoke(1, bare).is_ok());
        assert!(matches!(k.cap_revoke(1, bare), Err(CapError::InvalidHandle)));
        assert!(matches!(k.cap_lookup(1, bare), Err(CapError::InvalidHandle)));
        let after = k.domain_mut(1).unwrap().stats.escalation_attempts;
        assert_eq!(after - before, 4, "every failed capability operation is an escalation signal");
    }

    /// F6: memory-policy refusals (W^X, guard gap, quota, overlap) feed
    /// the monitor's fault signal automatically from the kernel's map
    /// path.
    #[test]
    fn memory_policy_refusals_record_faults_automatically() {
        use crate::memory::MemFlags;
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        let before = k.domain_mut(1).unwrap().stats.faults;
        // W^X refused by the policy.
        assert!(k
            .domain_map(1, 0x5000_0000, 4096, MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC)
            .is_err());
        // Legal map, then an overlapping one.
        assert!(k.domain_map(1, 0x6000_0000, 4096, MemFlags::READ).is_ok());
        assert!(k.domain_map(1, 0x6000_0000, 4096, MemFlags::READ).is_err());
        let after = k.domain_mut(1).unwrap().stats.faults;
        assert_eq!(after - before, 2, "each policy refusal is a fault signal");
    }

    /// F6: `tick` audits every domain exactly when a monitoring window
    /// boundary is crossed — and only then.
    #[test]
    fn tick_audits_every_domain_on_window_boundaries() {
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        k.create_domain_with(2, service_profile(), 1002, 100, 0).unwrap();
        k.set_monitor_window(10);
        // Dirty one domain's window through the organic syscall path.
        for _ in 0..4 {
            let _ = k.syscall(1, crate::sys::SysRequest::NetSend { len: 1 });
        }
        k.tick(9); // same window: no audit yet
        assert_eq!(k.domain_mut(1).unwrap().stats.syscalls_total, 4, "no window closed yet");
        k.tick(10); // boundary crossed: audit both domains
        assert_eq!(k.domain_mut(1).unwrap().stats.syscalls_total, 0, "window closed by tick");
        let mut events = 0;
        while k.pop_event().is_some() {
            events += 1;
        }
        assert!(events >= 2, "every domain audited on the boundary, got {events}");
    }

    /// F7: a respawned domain (same id, after a supervised destroy)
    /// must be born clean — the old monitor state used to stick and the
    /// replacement was born quarantined.
    #[test]
    fn respawn_after_quarantine_starts_clean() {
        use crate::domain::{Decision, DomainState};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        // Quarantine it through two organic bad windows (F6 machinery:
        // gate refusals + failed capability ops + refused mappings).
        k.set_monitor_window(10);
        let grantor = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(crate::capability::Capability {
                resource: crate::capability::Resource::FsNode(1),
                rights: crate::capability::Rights::READ.union(crate::capability::Rights::GRANT),
                generation: 0,
            })
            .unwrap();
        let misbehave = |k: &mut Kernel| {
            for _ in 0..10 {
                let _ = k.syscall(1, crate::sys::SysRequest::NetSend { len: 1 });
            }
            for _ in 0..4 {
                let _ = k.cap_attenuate(
                    1,
                    grantor,
                    crate::capability::Rights::READ.union(crate::capability::Rights::WRITE),
                );
            }
            for _ in 0..5 {
                let _ = k.domain_map(
                    1,
                    0x5000_0000,
                    4096,
                    crate::memory::MemFlags::READ | crate::memory::MemFlags::WRITE | crate::memory::MemFlags::EXEC,
                );
            }
        };
        misbehave(&mut k);
        k.tick(10);
        misbehave(&mut k);
        k.tick(20);
        assert_eq!(k.domain_state(1), Some(DomainState::Quarantined));
        // Supervised destroy + respawn under the same id.
        k.destroy_domain(1).unwrap();
        k.create_domain(1, service_profile()).unwrap();
        assert_eq!(k.domain_state(1), Some(DomainState::Running), "respawn is born clean");
        assert_eq!(
            k.domain_mut(1).unwrap().request_syscall(crate::syscall::SYS_READ),
            Decision::Allowed,
            "no quarantine sticks to the id"
        );
        // And the first audit of the fresh domain is a plain Log.
        let v = k.audit(1).unwrap();
        assert_eq!(v.response, crate::monitor::Response::Log);
    }

    /// F7: 100 distinct ids churned through the monitor (create, audit,
    /// destroy) must never push it into degraded mode — destroy clears
    /// the per-domain state and the table is sized from MAX_DOMAINS.
    #[test]
    fn monitor_churns_100_distinct_ids_without_degrading() {
        let mut k = Kernel::new();
        for i in 0..100u32 {
            let id = 5000 + i;
            k.create_domain_with(id, service_profile(), 2000, 100, 0).unwrap();
            let _ = k.audit(id);
            k.destroy_domain(id).unwrap();
        }
        assert!(!k.monitor_degraded(), "churn must not exhaust the state table");
        // And the supervisor-only reset exists for the rare manual path.
        k.create_domain(2, service_profile()).unwrap();
        let _ = k.audit(2);
        assert!(k.reset_monitor(2), "explicit supervisor reset works");
        assert!(!k.reset_monitor(9999));
    }

    /// F6 (the point of it all): a quarantine reached purely from
    /// organically generated events — denied syscalls through the real
    /// gate, failed capability operations, refused mappings — driven
    /// across windows by `tick`. No manual monitor hooks anywhere.
    #[test]
    fn quarantine_from_organic_events_only() {
        use crate::capability::{Capability, Resource, Rights};
        use crate::domain::DomainState;
        use crate::memory::MemFlags;
        use crate::sys::SysRequest;
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        k.set_monitor_window(10);
        let grantor = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability { resource: Resource::FsNode(1), rights: Rights::READ.union(Rights::GRANT), generation: 0 })
            .unwrap();
        let misbehave = |k: &mut Kernel| {
            // Gate refusals (NET_SEND is not on the service surface).
            for _ in 0..10 {
                let _ = k.syscall(1, SysRequest::NetSend { len: 1 });
            }
            // Failed capability operations (widening).
            for _ in 0..4 {
                let _ = k.cap_attenuate(1, grantor, Rights::READ.union(Rights::WRITE));
            }
            // Refused mappings (W^X).
            for _ in 0..5 {
                let _ = k.domain_map(1, 0x5000_0000, 4096, MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC);
            }
        };
        misbehave(&mut k);
        k.tick(10);
        assert_eq!(k.domain_state(1), Some(DomainState::Running), "hysteresis: first window only logs");
        misbehave(&mut k);
        k.tick(20);
        assert_eq!(
            k.domain_state(1),
            Some(DomainState::Quarantined),
            "two bad windows of organic events quarantine"
        );
    }

    /// F2 regression: dup2 onto an open fd used to discard the replaced
    /// entry's pipe reference (leak), and dup2(fd, fd) leaked an extra
    /// one. After closing everything and destroying the domain, no pipe
    /// slot may survive.
    #[test]
    fn dup2_releases_replaced_end_and_self_dup_is_a_noop() {
        use crate::sys::{SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        let pair = |k: &mut Kernel, d: u32| {
            match k.syscall(d, SysRequest::Pipe).unwrap() {
                SysValue::FdPair(r, w) => (r, w),
                other => panic!("{:?}", other),
            }
        };
        let (r_a, w_a) = pair(&mut k, 1);
        let (r_b, w_b) = pair(&mut k, 1);
        // dup2(w_a, r_b): pipe B's read end loses its reference here.
        match k.syscall(1, SysRequest::Dup { fd: w_a, new_fd: r_b }).unwrap() {
            SysValue::Fd(f) => assert_eq!(f, r_b),
            other => panic!("{:?}", other),
        }
        // dup2(fd, fd) must be a pure no-op (no refcount change).
        match k.syscall(1, SysRequest::Dup { fd: w_a, new_fd: w_a }).unwrap() {
            SysValue::Fd(f) => assert_eq!(f, w_a),
            other => panic!("{:?}", other),
        }
        for fd in [r_a, w_a, r_b, w_b] {
            k.syscall(1, SysRequest::Close { fd }).unwrap();
        }
        k.destroy_domain(1).unwrap();
        assert_eq!(k.pipes.len(), 0, "replaced/self-dup pipe ends must not leak");
    }

    /// F3 regression: the derived uid must never wrap (id 64536 would be
    /// born uid 0 = root), and ids that do not fit the derivation scheme
    /// are refused instead of silently colliding.
    #[test]
    fn create_domain_rejects_uid_wrapping_and_colliding_ids() {
        let mut k = Kernel::new();
        // 1000 + 64536 wraps to 0 — that would be root.
        assert!(matches!(
            k.create_domain(64536, service_profile()),
            Err(KernelError::InvalidId(_))
        ));
        // id > u16::MAX would alias the low ids' uids.
        assert!(matches!(
            k.create_domain(65536 + 7, service_profile()),
            Err(KernelError::InvalidId(_))
        ));
        assert!(matches!(
            k.create_domain(u32::MAX, service_profile()),
            Err(KernelError::InvalidId(_))
        ));
        // The normal range keeps working with the same derivation.
        k.create_domain(5, service_profile()).unwrap();
        assert_eq!(k.domain_mut(5).unwrap().uid, 1005);
        // uid 0 stays reachable only through the explicit-credential API.
        k.create_domain_with(9, service_profile(), 0, 0, 0).unwrap();
        assert_eq!(k.domain_mut(9).unwrap().uid, 0);
    }

    /// F9: in AuditOnly the verdict is still computed (and logged to
    /// telemetry with the would-be action), but no mask change and no
    /// quarantine is applied — the calibration mode.
    #[test]
    fn audit_only_computes_and_logs_but_never_applies() {
        use crate::capability::{CapError, CapHandle, Capability, Rights};
use crate::memory::{MemError, MemFlags};
use crate::monitor::{MonitorMode, Response};
        use crate::response::EventAction;
        use crate::sys::{SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        k.set_monitor_mode(MonitorMode::AuditOnly);
        assert_eq!(k.monitor_mode(), MonitorMode::AuditOnly);
        // Catastrophically bad windows (denied 100% + faults + escalations
        // + out-of-profile => score 85): would quarantine in Enforce.
        let make_bad = |k: &mut Kernel| {
            let d = k.domain_mut(1).unwrap();
            d.stats.syscalls_total = 2;
            d.stats.denied_syscalls = 2;
            d.stats.faults = 5;
            d.stats.escalation_attempts = 4;
            d.stats.mark_used(crate::syscall::SYS_KILL);
            d.stats.mark_used(crate::syscall::SYS_SPAWN);
        };
        make_bad(&mut k);
        let v1 = k.audit(1).unwrap();
        assert_eq!(v1.response, Response::Log, "hysteresis applies in audit-only too");
        make_bad(&mut k);
        let v2 = k.audit(1).unwrap();
        assert_eq!(v2.response, Response::Quarantine, "the verdict is still computed");
        // ...but nothing was applied:
        assert_eq!(k.domain_state(1), Some(crate::domain::DomainState::Running));
        assert_eq!(
            k.domain_mut(1).unwrap().request_syscall(crate::syscall::SYS_READ),
            crate::domain::Decision::Allowed,
            "mask untouched in AuditOnly"
        );
        // and the telemetry carries the would-have-been action:
        let mut saw_quarantine_event = false;
        while let Some(ev) = k.pop_event() {
            if ev.domain_id == 1 && ev.action == EventAction::Quarantine {
                saw_quarantine_event = true;
            }
        }
        assert!(saw_quarantine_event, "the computed verdict is logged");
        // The domain still executes normally through the syscall layer.
        assert!(matches!(
            k.syscall(1, SysRequest::Pipe).unwrap(),
            SysValue::FdPair(..)
        ));
    }

    #[test]
    fn destroy_domain_releases_pipes_socket_bucket_and_slot() {
        use crate::sys::{SysError, SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        // Open a pipe through the syscall layer: fds hold both ends.
        let (r, w) = match k
            .syscall(1, SysRequest::Pipe)
            .unwrap()
        {
            SysValue::FdPair(r, w) => (r, w),
            other => panic!("{:?}", other),
        };
        assert_eq!(k.pipes.len(), 1);
        // And a brokered socket + bucket.
        k.net_open(1).unwrap();
        assert_eq!(k.sockets.len(), 1);

        k.destroy_domain(1).unwrap();
        // Slot freed, pipe reclaimed, socket closed, scheduler unregistered.
        assert_eq!(k.domain_state(1), None);
        assert_eq!(k.pipes.len(), 0);
        assert_eq!(k.sockets.len(), 0);
        assert!(k.sched.entity(1).is_none());
        assert!(k
            .buckets
            .iter()
            .all(|b| !matches!(b, Some((bid, _)) if *bid == 1)));
        // The pipe fds died with the domain.
        assert_eq!(
            k.syscall(1, SysRequest::Close { fd: r }),
            Err(SysError::UnknownDomain(1))
        );
        let _ = w;
    }

    #[test]
    fn destroy_domain_is_dup_aware_on_pipe_ends() {
        use crate::sys::{SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        let (r, w) = match k.syscall(1, SysRequest::Pipe).unwrap() {
            SysValue::FdPair(r, w) => (r, w),
            other => panic!("{:?}", other),
        };
        // Duplicate the write end; destroy must release both references
        // exactly once and reclaim the pipe slot.
        k.syscall(1, SysRequest::Dup { fd: w, new_fd: 9 }).unwrap();
        k.destroy_domain(1).unwrap();
        assert_eq!(k.pipes.len(), 0);
        let _ = r;
    }

    #[test]
    fn destroy_domain_unknown_and_double_destroy_error() {
        let mut k = Kernel::new();
        assert_eq!(k.destroy_domain(9), Err(KernelError::UnknownDomain(9)));
        k.create_domain(2, parser_profile()).unwrap();
        k.destroy_domain(2).unwrap();
        assert_eq!(k.destroy_domain(2), Err(KernelError::UnknownDomain(2)));
    }

    #[test]
    fn destroy_domain_works_on_quarantined_domain() {
        // The supervised-respawn removal path must work post-quarantine.
        let mut k = Kernel::new();
        k.create_domain(5, parser_profile()).unwrap();
        k.domain_mut(5).unwrap().quarantine();
        assert_eq!(k.domain_state(5), Some(DomainState::Quarantined));
        k.destroy_domain(5).unwrap();
        assert_eq!(k.domain_state(5), None);
    }

    #[test]
    fn create_destroy_cycles_reuse_slots_without_leaks() {
        let mut k = Kernel::new();
        for i in 0..1000u32 {
            let id = 10 + (i % 3);
            k.create_domain(id, crate::profile::plugin_profile()).unwrap();
            k.destroy_domain(id).unwrap();
        }
        // All slots empty again and the scheduler has no leftover entities.
        assert_eq!(k.domains.iter().flatten().count(), 0);
        assert_eq!(k.sched.len(), 0);
        // A full table can still be created after the churn.
        for id in 0..MAX_DOMAINS as u32 {
            k.create_domain(id, parser_profile()).unwrap();
        }
        assert_eq!(
            k.create_domain(MAX_DOMAINS as u32, parser_profile()),
            Err(KernelError::TooManyDomains)
        );
    }
}
