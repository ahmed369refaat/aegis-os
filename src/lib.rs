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
use crate::response::{apply_response, SecurityEvent, TELEMETRY_CAPACITY};
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
        }
    }

    /// Spawn a domain from a profile. The profile's mask is the *maximal*
    /// surface this domain will ever have. Credentials are deterministic:
    /// uid = 1000 + id, gid = 100; nice = 0. Use `create_domain_with` for
    /// explicit control.
    pub fn create_domain(&mut self, id: u32, profile: DomainProfile) -> Result<(), KernelError> {
        self.create_domain_with(id, profile, 1000u16.wrapping_add(id as u16), 100, 0)
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
            apply_response, tightened_surface, EventAction, Outcome, SecurityEvent,
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
