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
pub mod dma;
pub mod dmar;
pub mod domain;
pub mod ext2;
pub mod fat32;
pub mod fd;
pub mod frame_share;
pub mod ipc;
pub mod ivrs;
pub mod memory;
pub mod monitor;
pub mod net;
pub mod part;
pub mod pipe;
pub mod preempt;
/// ADR-0022: the process table — pids, zombies, wait, exec policy.
pub mod proc;
pub mod profile;
pub mod response;
pub mod ringbuf;
pub mod sched;
pub mod sigframe;
pub mod signal;
pub mod sys;
pub mod syscall;
pub mod vfs;

use core::array;

use crate::buddy::BuddyAllocator;
use crate::capability::{CapError, CapHandle, Capability, Rights};
use crate::domain::{Decision, Domain, DomainState};
use crate::fd::{FdTarget, MAX_FDS};
use crate::memory::{MemError, MemFlags};
use crate::monitor::{BehaviorMonitor, DomainStats, MonitorConfig, Verdict};
use crate::monitor::{MonitorMode, Response};
use crate::net::{SocketTable, TokenBucket};
use crate::pipe::PipeTable;
use crate::profile::DomainProfile;
use crate::response::{apply_response, EventAction, SecurityEvent, TELEMETRY_CAPACITY};
use crate::ringbuf::RingBuffer;
use crate::sched::Scheduler;
use crate::syscall::SyscallMask;
use crate::vfs::Vfs;

/// Maximum simultaneously resident domains. ADR-0022 D1 raised this
/// 4 -> 32 (the scale-reality row): a shell with a pipeline needs
/// headroom and the fork-bomb guard needs something to guard. The
/// process meta table and the scheduler grow with it; the capacity
/// self-test pins the fill/refuse/drain/reuse behavior.
pub const MAX_DOMAINS: usize = 32;

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
    /// Risk treatment 3 (ADR-0009 addendum): a supervisor-only API was
    /// called by a non-privileged domain (carries the caller's id).
    NotAuthorized(u32),
    /// ADR-0004: endpoint-table refusals crossing the supervisor API
    /// boundary (table exhaustion, dead ids, non-conferable rights).
    Ipc(crate::ipc::IpcError),
    /// Round J: `reserve_stdio` found a real target sitting in one of
    /// fds 0..=2 — the runtime may only reserve what is free (or
    /// already reserved). Carries the offending fd.
    StdioSlotOccupied(u8),
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
    pub pipes: PipeTable,
    /// Brokered sockets (owned by domains, rate-limited per domain).
    pub(crate) sockets: SocketTable,
    /// ADR-0004 endpoints: per-domain queues behind capability gates.
    pub(crate) endpoints: ipc::EndpointTable,
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
    /// ADR-0022: the process table (pid allocator + metas; a meta
    /// slot exists for every process, living or zombie).
    pub procs: proc::ProcTable,
    /// ADR-0022 D5: init's exec policy table — the declared surface
    /// per executable path; unlisted = the app default (AuditOnly).
    pub exec_policy: proc::ExecPolicyTable,
    /// ADR-0023 D2: the sleep table — (domain, wake_at) pairs in the
    /// time base `tick` speaks (the core never learns the unit). One
    /// entry per sleeping domain; bounded by MAX_DOMAINS.
    pub(crate) sleepers: [Option<(u32, u64)>; MAX_DOMAINS],
    /// ADR-0026: the sync-IPC waiter table — one blocking wait per
    /// domain (a second call replaces the first, the sleepers' rule).
    pub(crate) ipc_waiters: [Option<crate::ipc::IpcWait>; MAX_DOMAINS],
    /// ADR-0026: the FIFO clock for call waiters (monotone; replies
    /// answer the oldest caller on the endpoint first).
    pub(crate) ipc_wait_seq: u64,
    /// ADR-0026: the wake list — (domain, resume value) pairs the
    /// reply/rendezvous executors produced. The KERNEL side drains it
    /// after the syscall and patches each parked image's RAX (the
    /// layering rule: the core decides, the kernel applies).
    pub(crate) ipc_wakes: [(u32, u64); MAX_DOMAINS],
    pub(crate) ipc_wake_n: usize,
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
            endpoints: ipc::EndpointTable::new(),
            sched: Scheduler::new(),
            frames: BuddyAllocator::new_over_arena(),
            clock: 0,
            monitor_mode: MonitorMode::default(),
            window_len: 100,
            last_window: 0,
            procs: proc::ProcTable::new(),
            exec_policy: proc::ExecPolicyTable::new(),
            sleepers: [None; MAX_DOMAINS],
            ipc_waiters: [None; MAX_DOMAINS],
            ipc_wait_seq: 0,
            ipc_wakes: [(0, 0); MAX_DOMAINS],
            ipc_wake_n: 0,
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
        // ADR-0022: every domain carries a process meta; metas are
        // bounded like domain slots, and zombies hold theirs until
        // reaped — a full meta table refuses new domains honestly.
        if self.procs.count() >= proc::MAX_PROCS {
            return Err(KernelError::TooManyDomains);
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
        d.cwd = crate::vfs::ROOT_REF;
        d.chroot_root = crate::vfs::ROOT_REF;
        *slot = Some(d);
        // ADR-0022: supervisor creations are PARENTLESS (kernel-managed
        // domains are not part of init's wait tree); the process tree
        // starts at init. A parentless exit is adopted by a living init
        // (the reaper of last resort), so no status is ever lost.
        let _ = self.procs.insert(proc::ProcMeta {
            pid: id,
            parent: 0,
            exit: None,
        });
        // Register with the fair scheduler (idempotent).
        let _ = self.sched.register(id, nice);
        Ok(())
    }

    /// Round J: reserve fds 0/1/2 for the runtime (the stdio triplet a
    /// spawned domain starts with, Unix-style). The slots are installed
    /// as `FdTarget::Reserved` so the domain's own `pipe()`/`open()`
    /// allocations begin at fd 3 — the runtime's device alias (the
    /// console behind fd 1) and the fd table can never collide. Only a
    /// supervisor calls this (spawn-time, before the domain runs);
    /// refusing a real target keeps it from silently shadowing one.
    pub fn reserve_stdio(&mut self, id: u32) -> Result<(), KernelError> {
        let d = self.domain_mut(id)?;
        for fd in 0u8..=2 {
            match d.fds.get(fd) {
                None => {
                    d.fds
                        .replace_at(fd, FdTarget::Reserved)
                        .map_err(|_| KernelError::StdioSlotOccupied(fd))?;
                }
                Some(entry) if entry.target == FdTarget::Reserved => {}
                Some(_) => return Err(KernelError::StdioSlotOccupied(fd)),
            }
        }
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

    /// ADR-0022: read-only access to a domain (procfs, tests, and the
    /// kernel runtime all observe; mutation stays behind the named
    /// APIs).
    #[must_use]
    pub fn domain(&self, id: u32) -> Option<&Domain> {
        self.domains.iter().flatten().find(|d| d.id == id)
    }

    /// ADR-0022: how many domains are live (the capacity self-test's
    /// heartbeat).
    #[must_use]
    pub fn live_domain_count(&self) -> usize {
        self.domains.iter().flatten().count()
    }

    #[must_use]
    pub fn proc_meta(&self, pid: u32) -> Option<proc::ProcMeta> {
        self.procs.get(pid)
    }

    #[must_use]
    pub fn proc_meta_count(&self) -> usize {
        self.procs.count()
    }

    /// ADR-0022 D2 — the native spawn primitive: a fresh process from
    /// an executable with EXPLICIT inheritance. `fd_map` is the ONLY
    /// thing the child receives (no ambient fds, no ambient caps: the
    /// child starts with just its self-signal capability plus
    /// attenuated copies of the parent's caps at
    /// `parent_cap ∩ request.base_rights`). The request's syscall
    /// surface must be a subset of the parent's CURRENT (live) mask
    /// and its quota no larger — anything wider is refused, fail
    /// closed, and counted as an escalation attempt.
    pub fn spawn_process(
        &mut self,
        parent_id: u32,
        profile_request: DomainProfile,
        fd_map: &[(u8, u8)],
    ) -> Result<u32, proc::ProcError> {
        use proc::ProcError as PE;

        // ── Phase 1: read the parent, validate everything. No mutation.
        let parent = self
            .domains
            .iter()
            .flatten()
            .find(|d| d.id == parent_id)
            .ok_or(PE::UnknownProcess(parent_id))?;
        if parent.state == DomainState::Quarantined {
            return Err(PE::Quarantined(parent_id));
        }
        let live_mask = parent.mask();
        let parent_quota = parent.space.quota_pages();
        let limit = parent.profile.max_children;
        let base_rights = profile_request.base_rights;
        let (uid, gid) = (parent.uid, parent.gid);
        let (cwd, chroot) = (parent.cwd, parent.chroot_root);
        let parent_caps = parent.caps.clone();
        let parent_fds = parent.fds;
        let nice = self.sched.entity(parent_id).map(|e| e.nice).unwrap_or(0);

        if self.procs.children_count(parent_id) >= usize::from(limit) {
            return Err(PE::TooManyChildren { limit });
        }
        if !profile_request.syscalls.is_subset_of(&live_mask)
            || profile_request.quota_pages > parent_quota
        {
            if let Ok(pd) = self.domain_mut(parent_id) {
                pd.record_escalation_attempt();
            }
            return Err(PE::ProfileEscalation);
        }
        for (pfd, cfd) in fd_map {
            if usize::from(*cfd) >= MAX_FDS {
                return Err(PE::FdMapInvalid { fd: *cfd });
            }
            if parent_fds.get(*pfd).is_none() {
                return Err(PE::FdNotOpen(*pfd));
            }
        }
        for i in 0..fd_map.len() {
            for j in (i + 1)..fd_map.len() {
                if fd_map[i].1 == fd_map[j].1 {
                    return Err(PE::FdMapInvalid { fd: fd_map[i].1 });
                }
            }
        }
        if self.domains.iter().all(|s| s.is_some()) || self.procs.count() >= proc::MAX_PROCS {
            return Err(PE::TooManyProcesses);
        }
        // ── Phase 2: commit. Every fallible decision ran above; the
        // only remaining error is pid exhaustion, which touches
        // nothing else (the counter only moves on success).
        let pid = self.procs.alloc_pid()?;
        self.procs.insert(proc::ProcMeta {
            pid,
            parent: parent_id,
            exit: None,
        })?;
        let mut child = Domain::spawned(pid, profile_request, uid, gid, cwd, chroot);
        // Attenuated copies of the parent's caps (rights ∩ base_rights;
        // a lying request still yields a subset), EXCLUDING caps aimed
        // at the parent itself — a spawned child cannot signal its
        // parent (the same discipline as fork). Best-effort bounded:
        // a full child table drops further copies — less authority,
        // never more.
        for cap in parent_caps.iter() {
            if matches!(cap.resource, crate::capability::Resource::Domain(d) if d == parent_id) {
                continue;
            }
            let _ = child.caps.insert(crate::capability::Capability {
                resource: cap.resource,
                rights: cap.rights.intersect(base_rights),
                generation: 0,
            });
        }
        // The explicit fd inheritance: positions snapshot, cloexec
        // starts clear, pipe ends acquire one reference each.
        for (pfd, cfd) in fd_map {
            if let Some(entry) = parent_fds.get(*pfd) {
                match entry.target {
                    FdTarget::PipeRead(pipe) => {
                        let _ = self.pipes.acquire_read(pipe);
                    }
                    FdTarget::PipeWrite(pipe) => {
                        let _ = self.pipes.acquire_write(pipe);
                    }
                    _ => {}
                }
                let _ = child.fds.replace_at(*cfd, entry.target);
                if let Some(e) = child.fds.get_mut(*cfd) {
                    e.pos = entry.pos;
                }
            }
        }
        if let Some(slot) = self.domains.iter_mut().find(|s| s.is_none()) {
            *slot = Some(child);
        }
        // The parent's signal capability over the child — best-effort:
        // the self-cap is STRUCTURAL (like SYS_EXIT, every process
        // holds its own), so a full parent table only loses kill(child),
        // never an invariant. wait() needs no capability.
        if let Ok(pd) = self.domain_mut(parent_id) {
            let _ = pd.caps.insert(crate::capability::Capability {
                resource: crate::capability::Resource::Domain(pid),
                rights: crate::capability::Rights::WRITE,
                generation: 0,
            });
        }
        let _ = self.sched.register(pid, nice);
        Ok(pid)
    }

    /// ADR-0022 D3 — fork: the child is a copy of the parent's CURRENT
    /// state and can only shrink from here. The live mask, caps (minus
    /// the parent's self-signal capability — a child cannot signal its
    /// parent), address-space ledger, credentials, directories and
    /// every fd (positions and cloexec flags, POSIX fd numbering) copy;
    /// pending signals and behavioral accounting start clean; the
    /// parent best-effort gains a `Domain(child)` capability (a full
    /// parent table skips it — wait needs no cap). The physical COW is
    /// the page-table layer's job (ADR-0024).
    pub fn fork_process(&mut self, parent_id: u32) -> Result<u32, proc::ProcError> {
        use proc::ProcError as PE;

        let parent = self
            .domains
            .iter()
            .flatten()
            .find(|d| d.id == parent_id)
            .ok_or(PE::UnknownProcess(parent_id))?;
        if parent.state == DomainState::Quarantined {
            return Err(PE::Quarantined(parent_id));
        }
        let limit = parent.profile.max_children;
        let template = parent.clone();
        let nice = self.sched.entity(parent_id).map(|e| e.nice).unwrap_or(0);

        if self.procs.children_count(parent_id) >= usize::from(limit) {
            return Err(PE::TooManyChildren { limit });
        }
        if self.domains.iter().all(|s| s.is_some()) || self.procs.count() >= proc::MAX_PROCS {
            return Err(PE::TooManyProcesses);
        }
        let pid = self.procs.alloc_pid()?;
        self.procs.insert(proc::ProcMeta {
            pid,
            parent: parent_id,
            exit: None,
        })?;
        let child = Domain::forked(pid, &template);
        // Every pipe end in the copied table gains one reference.
        for fd in 0..MAX_FDS {
            if let Some(entry) = template.fds.get(fd as u8) {
                match entry.target {
                    FdTarget::PipeRead(pipe) => {
                        let _ = self.pipes.acquire_read(pipe);
                    }
                    FdTarget::PipeWrite(pipe) => {
                        let _ = self.pipes.acquire_write(pipe);
                    }
                    _ => {}
                }
            }
        }
        // The parent's signal capability over the child — best-effort
        // (the self-cap is structural; see spawn_process).
        if let Ok(pd) = self.domain_mut(parent_id) {
            let _ = pd.caps.insert(crate::capability::Capability {
                resource: crate::capability::Resource::Domain(pid),
                rights: crate::capability::Rights::WRITE,
                generation: 0,
            });
        }
        if let Some(slot) = self.domains.iter_mut().find(|s| s.is_none()) {
            *slot = Some(child);
        }
        let _ = self.sched.register(pid, nice);
        Ok(pid)
    }

    /// ADR-0022 D4 — the exec bookkeeping (the loader validates the
    /// image, ADR-0025, then calls this): the live mask INTERSECTS with
    /// the declared surface (EXIT is unalienable), `cloexec` fds close
    /// with their pipe references released, the region ledger resets
    /// (the new image maps fresh; the quota survives), and the
    /// per-process monitor mode adopts the policy's decision. Never
    /// widens: intersection with the LIVE mask.
    pub fn exec_replace(
        &mut self,
        pid: u32,
        declared: &SyscallMask,
        monitor_enforce: Option<bool>,
    ) -> Result<(), proc::ProcError> {
        let d = self
            .domain_mut(pid)
            .map_err(|_| proc::ProcError::UnknownProcess(pid))?;
        d.exec_intersect(declared);
        d.monitor_enforce = monitor_enforce;
        // ADR-0023 D8: caught handlers reset to default across exec
        // (POSIX) — the new image installs its own.
        d.clear_caught_handlers();
        d.space.clear_for_exec();
        // Close cloexec fds, buffering the pipe releases: the domain
        // borrow and the pipe-table borrow cannot be live together.
        let mut released: [(bool, u32); MAX_FDS] = [(false, 0); MAX_FDS];
        let mut rn = 0usize;
        for fd in 0..MAX_FDS {
            let flagged = matches!(d.fds.get(fd as u8), Some(e) if e.cloexec);
            if flagged {
                if let Some(closed) = d.fds.close(fd as u8) {
                    match closed.target {
                        FdTarget::PipeRead(pipe) if rn < released.len() => {
                            released[rn] = (false, pipe);
                            rn += 1;
                        }
                        FdTarget::PipeWrite(pipe) if rn < released.len() => {
                            released[rn] = (true, pipe);
                            rn += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
        for &(is_write, pipe) in &released[..rn] {
            if is_write {
                let _ = self.pipes.release_write(pipe);
            } else {
                let _ = self.pipes.release_read(pipe);
            }
        }
        Ok(())
    }

    /// ADR-0022 D7 — exit: teardown + status recording. The domain and
    /// its resources go NOW (the kernel runtime frees frames/IOMMU
    /// BEFORE calling this, the `destroy_user` contract); the meta
    /// stays as a zombie until the parent (or init, the reaper of last
    /// resort) waits. With no reaper alive anywhere the status is
    /// DISCARDED, not leaked. The dead process's children — living and
    /// zombie — reparent the same way.
    pub fn exit_process(
        &mut self,
        pid: u32,
        status: proc::ExitStatus,
    ) -> Result<(), proc::ProcError> {
        let meta = self
            .procs
            .get(pid)
            .ok_or(proc::ProcError::UnknownProcess(pid))?;
        let parent_can_reap = meta.parent != 0
            && meta.parent != pid
            && self.domains.iter().flatten().any(|d| d.id == meta.parent);
        let init_adopts = pid != proc::INIT_PID
            && self
                .domains
                .iter()
                .flatten()
                .any(|d| d.id == proc::INIT_PID);
        self.teardown_domain(pid)
            .map_err(|_| proc::ProcError::UnknownProcess(pid))?;
        if parent_can_reap {
            if let Some(m) = self.procs.get_mut(pid) {
                m.exit = Some(status);
            }
        } else if init_adopts {
            if let Some(m) = self.procs.get_mut(pid) {
                m.parent = proc::INIT_PID;
                m.exit = Some(status);
            }
        } else {
            // No reaper exists: discard rather than leak a zombie.
            self.procs.remove(pid);
        }
        self.reparent_children(pid);
        Ok(())
    }

    /// ADR-0022 D7 — wait4: reap one child. `pid > 0` = that child,
    /// `-1` or `0` = any child (process groups do not exist yet, so 0
    /// reads as "any"); other negatives are refused. Reaping frees the
    /// zombie's meta slot. The pure core never blocks: nothing-ready
    /// is `WouldBlock` and the kernel runtime turns it into a block or
    /// EAGAIN (WNOHANG) at the ABI.
    pub fn wait_process(
        &mut self,
        parent_id: u32,
        pid: i64,
        _nohang: bool,
    ) -> Result<(u32, proc::ExitStatus), proc::ProcError> {
        use proc::ProcError as PE;
        if self.domain(parent_id).is_none() {
            return Err(PE::UnknownProcess(parent_id));
        }
        let target = if pid > 0 {
            Some(pid as u32)
        } else if pid == -1 || pid == 0 {
            None
        } else {
            // Process-group waits: not modeled yet; fail closed.
            return Err(PE::NotAChild(pid as u32));
        };
        if self.procs.children_count(parent_id) == 0 {
            return Err(PE::NoChildren);
        }
        match target {
            Some(t) => {
                // The iterator borrow ends with the statement; the
                // removal below runs on the released table.
                let found: Option<proc::ProcMeta> =
                    self.procs.children_of(parent_id).find(|m| m.pid == t);
                match found {
                    None => Err(PE::NotAChild(t)),
                    Some(m) if m.exit.is_some() => {
                        let st = m.exit.unwrap_or(proc::ExitStatus::normal(0));
                        self.procs.remove(t);
                        Ok((t, st))
                    }
                    Some(_) => Err(PE::WouldBlock),
                }
            }
            None => {
                let found: Option<proc::ProcMeta> =
                    self.procs.children_of(parent_id).find(|m| m.exit.is_some());
                match found {
                    Some(m) => {
                        let st = m.exit.unwrap_or(proc::ExitStatus::normal(0));
                        self.procs.remove(m.pid);
                        Ok((m.pid, st))
                    }
                    None => Err(PE::WouldBlock),
                }
            }
        }
    }

    /// ADR-0022 D6: the core primitive behind fcntl(F_SETFD).
    pub fn set_cloexec(&mut self, pid: u32, fd: u8, on: bool) -> Result<(), proc::ProcError> {
        let d = self
            .domain_mut(pid)
            .map_err(|_| proc::ProcError::UnknownProcess(pid))?;
        if d.fds.set_cloexec(fd, on) {
            Ok(())
        } else {
            Err(proc::ProcError::FdNotOpen(fd))
        }
    }

    /// ADR-0022 D5: declare an executable's surface in init's policy
    /// table (supervisor API — never a child-held syscall).
    pub fn exec_policy_declare(
        &mut self,
        path: &str,
        mask: &SyscallMask,
        enforce: Option<bool>,
    ) -> Result<(), proc::ProcError> {
        self.exec_policy.declare(path, *mask, enforce)
    }

    /// ADR-0022 D5: the declared surface for a path (unlisted = the
    /// app default, AuditOnly).
    #[must_use]
    pub fn exec_policy_declared_for(&self, path: &str) -> (SyscallMask, Option<bool>) {
        self.exec_policy.declared_for(path)
    }

    /// ADR-0022 D7: settle a dead process's children — living AND
    /// zombie. A living init adopts; without one, zombie children are
    /// reaped into nothing (their status is unobservable by anyone)
    /// and living children detach (parent 0, discarded at their own
    /// exit). Called by both `exit_process` and `destroy_domain`.
    fn reparent_children(&mut self, dead: u32) {
        let init_live = dead != proc::INIT_PID
            && self
                .domains
                .iter()
                .flatten()
                .any(|d| d.id == proc::INIT_PID);
        // Fixed buffer (no heap in the core): the pid list first, the
        // mutations after — the iterator borrow must end before
        // `get_mut`/`remove` run.
        let mut pids = [0u32; proc::MAX_PROCS];
        let mut n = 0usize;
        for m in self.procs.children_of(dead) {
            if n < pids.len() {
                pids[n] = m.pid;
                n += 1;
            }
        }
        for &pid in &pids[..n] {
            let is_zombie = self.procs.get(pid).is_some_and(|m| m.exit.is_some());
            if init_live {
                if let Some(x) = self.procs.get_mut(pid) {
                    x.parent = proc::INIT_PID;
                }
            } else if is_zombie {
                self.procs.remove(pid);
            } else if let Some(x) = self.procs.get_mut(pid) {
                x.parent = 0;
            }
        }
    }

    /// Destroy a domain and release everything it holds:
    ///
    /// - pipe ends referenced by its open descriptors (dup-aware: an end
    ///   closes only when its last referencing descriptor goes away),
    /// - its brokered socket and rate bucket,
    /// - its scheduler registration,
    /// - its process meta (no zombie: the wait protocol is opt-in via
    ///   ADR-0022's `exit_process`; this is the supervisor removal path),
    /// - its table slot (immediately reusable).
    ///
    /// VFS inodes it created persist — files outlive their creators (Unix
    /// semantics). Works on quarantined domains too: this is the
    /// supervised-respawn removal path. Never widens anything anywhere.
    pub fn destroy_domain(&mut self, id: u32) -> Result<(), KernelError> {
        self.teardown_domain(id)?;
        // ADR-0022: the supervisor path removes the meta outright (no
        // zombie — the supervisor opted out of the wait protocol) and
        // the dead process's children reparent exactly as with exit.
        self.procs.remove(id);
        self.reparent_children(id);
        Ok(())
    }

    /// The teardown half of `destroy_domain` (and of ADR-0022's
    /// `exit_process`): monitor reset, dup-aware fd close with pipe
    /// release, socket, bucket, scheduler unregister, slot free. The
    /// CALLER settles the process-meta question (zombie vs removed vs
    /// discarded) — kernel-side resources (frames, IOMMU) are the
    /// caller's job BEFORE this, the same `destroy_user` contract.
    fn teardown_domain(&mut self, id: u32) -> Result<(), KernelError> {
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
            if let Some(entry) = self.domains[slot]
                .as_mut()
                .expect("checked above")
                .fds
                .close(fd as u8)
            {
                match entry.target {
                    FdTarget::PipeRead(p) => {
                        let _ = self.pipes.release_read(p);
                    }
                    FdTarget::PipeWrite(p) => {
                        let _ = self.pipes.release_write(p);
                    }
                    FdTarget::File(_) => {}
                    FdTarget::Reserved => {}
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
        // ADR-0023: a dying domain's sleep entry dies with it (a wake
        // later must not reference a dead id).
        for slot in self.sleepers.iter_mut() {
            if matches!(*slot, Some((d, _)) if d == id) {
                *slot = None;
            }
        }
        // ADR-0026: a dying domain's IPC wait dies with it (a reply
        // later must not wake a dead id — wake_due's belt, same rule).
        for slot in self.ipc_waiters.iter_mut() {
            if matches!(*slot, Some(w) if w.domain == id) {
                *slot = None;
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

    /// N2 (ADR-0007 §2): an unnormalizable syscall number (>=
    /// SYSCALL_COUNT) attempted from ring 3 — counted as a denial on
    /// the live domain (out-of-profile by definition; the used-bits
    /// signal only has room for the 64 real ids).
    pub fn report_unknown_syscall(&mut self, domain_id: u32) -> Result<(), KernelError> {
        let d = self.domain_mut(domain_id)?;
        d.stats.denied_syscalls = d.stats.denied_syscalls.saturating_add(1);
        d.stats.syscalls_total = d.stats.syscalls_total.saturating_add(1);
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
        // ADR-0023 D2: the wake pass runs on EVERY tick — a sleeper
        // whose deadline passed must wake even inside the same monitor
        // window (audits stay window-gated, wakes are not). The count
        // is intentionally discarded here: tick callers do not act on
        // it (the scheduler state changed is the signal).
        let _ = self.wake_due(now);
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

    /// ADR-0023 D2: park the caller until `now + cycles` (both in the
    /// time base `tick` speaks). Zero cycles is a plain yield (no
    /// entry, nothing scheduled). A second sleep for the same domain
    /// REPLACES the first. Returns the wake deadline; a span whose
    /// deadline would overflow refuses — a deadline that can never be
    /// reached would be a lost wakeup.
    pub(crate) fn sleep_until(
        &mut self,
        domain: u32,
        now: u64,
        cycles: u64,
    ) -> Result<u64, crate::sys::SysError> {
        use crate::sys::SysError;
        if self.domain(domain).is_none() {
            return Err(SysError::UnknownDomain(domain));
        }
        if cycles == 0 {
            return Ok(now);
        }
        let wake = now
            .checked_add(cycles)
            .ok_or(SysError::InvalidArgument(cycles))?;
        let mut placed = false;
        for slot in self.sleepers.iter_mut() {
            if matches!(*slot, Some((d, _)) if d == domain) {
                *slot = Some((domain, wake));
                placed = true;
                break;
            }
        }
        if !placed {
            for slot in self.sleepers.iter_mut() {
                if slot.is_none() {
                    *slot = Some((domain, wake));
                    placed = true;
                    break;
                }
            }
        }
        if !placed {
            // Unreachable while sleepers are bounded by live domains,
            // but a lost sleep is worse than a typed refusal.
            return Err(SysError::TooManyDomains);
        }
        let _ = self.sched.set_runnable(domain, false);
        Ok(wake)
    }

    /// ADR-0023 D2: wake every sleeper whose deadline has passed,
    /// through the scheduler's wake path (the min_vruntime floor — a
    /// long sleep buys no priority). Returns how many woke.
    #[must_use]
    pub fn wake_due(&mut self, now: u64) -> u32 {
        let mut due: [Option<u32>; MAX_DOMAINS] = [None; MAX_DOMAINS];
        let mut n = 0usize;
        for slot in self.sleepers.iter_mut() {
            if let Some((d, at)) = *slot {
                if at <= now && n < due.len() {
                    *slot = None;
                    due[n] = Some(d);
                    n += 1;
                }
            }
        }
        let mut woke = 0u32;
        for &d in due[..n].iter().flatten() {
            // Only a still-live, still-registered domain wakes
            // (teardown cancels entries; this is the belt).
            if self.domain(d).is_some() && self.sched.entity(d).is_some() {
                let _ = self.sched.set_runnable(d, true);
                woke += 1;
            }
        }
        woke
    }

    /// ADR-0026: register (or replace) a domain's blocking IPC wait.
    /// One wait per domain — the sleepers' rule.
    pub(crate) fn ipc_wait_register(&mut self, domain: u32, kind: crate::ipc::IpcWaitKind) {
        self.ipc_wait_seq = self.ipc_wait_seq.wrapping_add(1);
        let wait = crate::ipc::IpcWait {
            domain,
            kind,
            seq: self.ipc_wait_seq,
        };
        // Replace in place if one exists; else the first free slot.
        for slot in self.ipc_waiters.iter_mut() {
            if matches!(*slot, Some(w) if w.domain == domain) {
                *slot = Some(wait);
                return;
            }
        }
        for slot in self.ipc_waiters.iter_mut() {
            if slot.is_none() {
                *slot = Some(wait);
                return;
            }
        }
        // Unreachable: waiters are bounded by live domains, and a
        // full table means a bookkeeping leak — fail loud, not silent.
        panic!("ipc_wait_register: the waiter table is full (bookkeeping bug)");
    }

    /// ADR-0026: clear a domain's wait (the reply consumed it).
    pub(crate) fn ipc_wait_clear(&mut self, domain: u32) {
        for slot in self.ipc_waiters.iter_mut() {
            if matches!(*slot, Some(w) if w.domain == domain) {
                *slot = None;
                return;
            }
        }
    }

    /// ADR-0026: the OLDEST awaiting-reply caller on an endpoint
    /// (FIFO by seq; None = nobody is asking).
    #[must_use]
    pub fn ipc_oldest_caller(&self, endpoint: u32) -> Option<u32> {
        self.ipc_waiters
            .iter()
            .flatten()
            .filter(|w| w.kind == crate::ipc::IpcWaitKind::AwaitingReply { endpoint })
            .min_by_key(|w| w.seq)
            .map(|w| w.domain)
    }

    /// ADR-0026: record a wake — (domain, resume value). The kernel
    /// side drains the list and patches each parked image's RAX.
    /// The domain's current IPC wait, if any (diagnostics; the
    /// deadlock post-mortem's eyes).
    pub fn ipc_wait_of(&self, domain: u32) -> Option<crate::ipc::IpcWaitKind> {
        self.ipc_waiters
            .iter()
            .flatten()
            .find(|w| w.domain == domain)
            .map(|w| w.kind)
    }

    pub(crate) fn ipc_wake_push(&mut self, domain: u32, value: u64) {
        if self.ipc_wake_n < self.ipc_wakes.len() {
            self.ipc_wakes[self.ipc_wake_n] = (domain, value);
            self.ipc_wake_n += 1;
        }
        // Overflow is unreachable: a waking syscall clears the wait
        // BEFORE pushing (one wake per waiter per drain), and the
        // drain runs after every waking syscall.
    }

    /// ADR-0026: the kernel-side drain — pops one (domain, value).
    /// The syscall layer applies each to the parked image's RAX.
    pub fn pop_ipc_wake(&mut self) -> Option<(u32, u64)> {
        if self.ipc_wake_n == 0 {
            return None;
        }
        self.ipc_wake_n -= 1;
        Some(self.ipc_wakes[self.ipc_wake_n])
    }

    /// ADR-0026: the rendezvous push — send AND call both come
    /// through here. After the bounded push, an owner parked in
    /// recv_wait on this endpoint consumes the message the moment it
    /// lands (pop what was pushed — the queue only holds the async
    /// backlog, never a message an AwaitingMsg owner will take).
    pub(crate) fn ipc_push_rendezvous(
        &mut self,
        channel: u32,
        sender: u32,
        len: u32,
    ) -> Result<usize, crate::sys::SysError> {
        use crate::sys::SysError;
        let free = self
            .endpoints
            .push(channel, sender, len)
            .map_err(SysError::Ipc)?;
        // The owner, if parked AwaitingMsg here, takes it now.
        let owner = match self.endpoints.owner_of(channel) {
            Some(o) => o,
            None => return Ok(free),
        };
        let waiting = self.ipc_waiters.iter().any(|w| {
            matches!(w, Some(w)
                if w.domain == owner
                    && w.kind == crate::ipc::IpcWaitKind::AwaitingMsg { endpoint: channel })
        });
        if waiting {
            // The pop returns exactly the just-pushed message: an
            // AwaitingMsg waiter implies the queue was empty at park
            // time, and every push since then rendezvoused (the
            // invariant that keeps this FIFO-safe).
            if self.endpoints.pop(channel).is_ok() {
                self.ipc_wait_clear(owner);
                self.ipc_wake_push(owner, u64::from(len));
                let _ = self.sched.set_runnable(owner, true);
                // The message left with the woken owner: the free
                // budget is the full depth again (honest telemetry).
                return Ok(crate::ipc::IPC_QUEUE_DEPTH);
            }
        }
        Ok(free)
    }

    /// ADR-0023 D7: the earliest FUTURE wake deadline — the idle loop's
    /// "how long may I sleep" answer. Callers must `tick(now)` first
    /// (due entries leave the table there); `None` = nothing sleeps.
    #[must_use]
    pub fn sleepers_due(&self, now: u64) -> Option<u64> {
        self.sleepers
            .iter()
            .flatten()
            .map(|&(_, at)| at)
            .filter(|at| *at > now)
            .min()
    }

    /// ADR-0023 D8: the next signal the kernel may DELIVER to
    /// `domain` — pending, unblocked, with an installed handler
    /// (caught), lowest signum first — removed from the pending set
    /// and answered with its disposition (signum, handler, restorer).
    /// Uncaught signals stay pending (their default action is the
    /// monitor's business, unchanged).
    pub fn pop_catchable_signal(&mut self, domain: u32) -> Option<(u8, u64, u64)> {
        let sig = {
            let d = self.domains.iter().flatten().find(|d| d.id == domain)?;
            let sig = d.signals.next_pending()?;
            // Pending but uncaught — not ours to deliver.
            d.sig_handlers[usize::from(sig)].as_ref()?;
            sig
        };
        let d = self.domains.iter_mut().flatten().find(|d| d.id == domain)?;
        let _ = d.signals.deliver();
        let h = d.sig_handlers[usize::from(sig)]?;
        Some((sig, h.handler, h.restorer))
    }

    /// ADR-0023: the wake deadline a domain sleeps toward, if any
    /// (test/procfs visibility).
    #[must_use]
    pub fn sleeping(&self, domain: u32) -> Option<u64> {
        self.sleepers
            .iter()
            .flatten()
            .find(|&&(d, _)| d == domain)
            .map(|&(_, at)| at)
    }

    fn domain_ids(&self) -> [Option<u32>; MAX_DOMAINS] {
        let mut ids = [None; MAX_DOMAINS];
        for (slot, id) in self
            .domains
            .iter()
            .flatten()
            .map(|d| d.id)
            .zip(ids.iter_mut())
        {
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
            Err(
                e @ (CapError::Escalation | CapError::MissingGrantRight | CapError::InvalidHandle),
            ) => {
                d.stats.escalation_attempts = d.stats.escalation_attempts.saturating_add(1);
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        d.caps.insert(derived)
    }

    /// F6: supervisor wrapper; a stale handle is an escalation signal.
    pub fn cap_revoke(
        &mut self,
        domain_id: u32,
        handle: CapHandle,
    ) -> Result<Capability, CapError> {
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
    /// Risk treatment 3 (ADR-0009 addendum): the supervisor grant
    /// path for Domain capabilities — the ONLY way a domain other than
    /// the target itself ever holds a Domain capability. Supervisor
    /// only: the caller must be uid 0. Returns the inserted handle
    /// through the normal capability table (generation-assigned,
    /// revocable, auditable).
    pub fn cap_grant_domain(
        &mut self,
        supervisor_id: u32,
        target_domain: u32,
    ) -> Result<crate::capability::CapHandle, KernelError> {
        if self.domain_mut(supervisor_id)?.uid != 0 {
            return Err(KernelError::NotAuthorized(supervisor_id));
        }
        // The target must exist — a capability for a missing domain is
        // meaningless (and would silently fail every later check).
        self.domain_mut(target_domain)?;
        let cap = crate::capability::Capability {
            resource: crate::capability::Resource::Domain(target_domain),
            rights: crate::capability::Rights::WRITE,
            generation: 0,
        };
        let d = self.domain_mut(supervisor_id)?;
        d.caps.insert(cap).map_err(|_| KernelError::TooManyDomains)
    }

    /// ADR-0027: confer a Domain(target)/WRITE capability on ANOTHER
    /// holder — the `ipc_endpoint_grant` shape for domain caps (a
    /// privileged, auditable bootstrap: grants never happen without a
    /// uid-0 caller). The holder's syscall gates (kill, page grants)
    /// then pass for that target.
    pub fn cap_grant_domain_to(
        &mut self,
        supervisor_id: u32,
        holder: u32,
        target: u32,
    ) -> Result<crate::capability::CapHandle, KernelError> {
        if self.domain_mut(supervisor_id)?.uid != 0 {
            return Err(KernelError::NotAuthorized(supervisor_id));
        }
        // Both ends must exist — a capability for (or held by) a
        // missing domain is meaningless.
        self.domain_mut(holder)?;
        self.domain_mut(target)?;
        let cap = crate::capability::Capability {
            resource: crate::capability::Resource::Domain(target),
            rights: crate::capability::Rights::WRITE,
            generation: 0,
        };
        let d = self.domain_mut(holder)?;
        d.caps.insert(cap).map_err(|_| KernelError::TooManyDomains)
    }

    /// ADR-0004 §2: create an endpoint owned by `owner_id` and mint
    /// the full conferable capability (READ|WRITE|GRANT) into the
    /// OWNER's table. Supervisor only (uid 0): endpoint creation is a
    /// grant, and grants never happen without a privileged, auditable
    /// caller. Transactional: if the owner's capability table is full,
    /// the endpoint is destroyed again — no orphaned queues.
    pub fn ipc_endpoint_create(
        &mut self,
        supervisor_id: u32,
        owner_id: u32,
    ) -> Result<(u32, crate::capability::CapHandle), KernelError> {
        if self.domain_mut(supervisor_id)?.uid != 0 {
            return Err(KernelError::NotAuthorized(supervisor_id));
        }
        self.domain_mut(owner_id)?; // the owner must exist
        let id = self.endpoints.create(owner_id).map_err(KernelError::Ipc)?;
        let cap = crate::capability::Capability {
            resource: crate::capability::Resource::Endpoint(id),
            rights: crate::capability::Rights::READ
                | crate::capability::Rights::WRITE
                | crate::capability::Rights::GRANT,
            generation: 0,
        };
        let inserted = {
            let d = self.domain_mut(owner_id)?;
            d.caps.insert(cap)
        };
        match inserted {
            Ok(h) => Ok((id, h)),
            Err(_) => {
                // Roll back: never leave an endpoint nobody can reach.
                let _ = self.endpoints.destroy(id);
                Err(KernelError::Ipc(crate::ipc::IpcError::TableFull))
            }
        }
    }

    /// ADR-0004 §4: delegate (a subset of) an endpoint's conferable
    /// rights to another domain. Supervisor only (uid 0); the rights
    /// must be a subset of READ|WRITE|GRANT — derivation is
    /// attenuation-only by construction.
    pub fn ipc_endpoint_grant(
        &mut self,
        supervisor_id: u32,
        endpoint_id: u32,
        target_id: u32,
        rights: crate::capability::Rights,
    ) -> Result<crate::capability::CapHandle, KernelError> {
        if self.domain_mut(supervisor_id)?.uid != 0 {
            return Err(KernelError::NotAuthorized(supervisor_id));
        }
        if self.endpoints.owner_of(endpoint_id).is_none() {
            return Err(KernelError::Ipc(crate::ipc::IpcError::InvalidHandle));
        }
        let conferable = crate::capability::Rights::READ
            | crate::capability::Rights::WRITE
            | crate::capability::Rights::GRANT;
        if !rights.is_subset_of(conferable) {
            return Err(KernelError::Ipc(crate::ipc::IpcError::Escalation));
        }
        self.domain_mut(target_id)?;
        let cap = crate::capability::Capability {
            resource: crate::capability::Resource::Endpoint(endpoint_id),
            rights,
            generation: 0,
        };
        let d = self.domain_mut(target_id)?;
        d.caps
            .insert(cap)
            .map_err(|_| KernelError::Ipc(crate::ipc::IpcError::TableFull))
    }

    /// ADR-0004: destroy an endpoint. Its queue is dropped with it and
    /// the id is dead forever — every capability on it fails closed on
    /// the next use (ids are never reused). Supervisor only (uid 0);
    /// revoking the *capabilities* themselves stays the normal
    /// capability-revocation path (`cap_revoke`).
    pub fn ipc_endpoint_destroy(
        &mut self,
        supervisor_id: u32,
        endpoint_id: u32,
    ) -> Result<(), KernelError> {
        if self.domain_mut(supervisor_id)?.uid != 0 {
            return Err(KernelError::NotAuthorized(supervisor_id));
        }
        self.endpoints
            .destroy(endpoint_id)
            .map_err(KernelError::Ipc)
    }

    pub fn cap_lookup(
        &mut self,
        domain_id: u32,
        handle: CapHandle,
    ) -> Result<Capability, CapError> {
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
            Err(
                e @ (MemError::WxViolation
                | MemError::Overlap
                | MemError::GuardGap
                | MemError::QuotaExceeded),
            ) => {
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

    /// M2-W2: the ring's own drop counter (events refused because the
    /// ring was full when pushed). A supervisor reading a nonzero value
    /// must drain faster — the ring never overwrites, by design.
    #[must_use]
    pub fn telemetry_dropped(&self) -> u64 {
        self.telemetry.dropped()
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
    pub use crate::dma::{
        DmaBroker, DmaDir, DmaError, DmaProt, DmaQuotas, DmaVerdict, MAX_DMA_REGIONS,
    };
    pub use crate::dmar::{Dmar, DmarError, Drhd, MAX_TABLE_BYTES};
    pub use crate::domain::{Decision, Domain, DomainState};
    pub use crate::fd::{FdEntry, FdError, FdTable, FdTarget, MAX_FDS};
    pub use crate::frame_share::{CowDecision, FrameShares, ShareError, MAX_SHARED};
    pub use crate::net::{
        NetError, Socket, SocketState, SocketTable, TokenBucket, RATE_WINDOW_TICKS,
    };
    pub use crate::pipe::{PipeError, PipeTable, MAX_PIPES, PIPE_CAPACITY};
    pub use crate::preempt::{Preemptor, TickDecision};
    pub use crate::ringbuf::{RingBuffer, RingError};
    pub use crate::sched::{SchedEntity, SchedError, Scheduler, NICE0_WEIGHT, NICE_TO_WEIGHT};
    pub use crate::sigframe::{InterruptedImage, SigframeError, SIGFRAME_BYTES, USER_CANON_MAX};
    pub use crate::signal::{
        default_action, is_unblockable, SignalError, SignalSet, SignalState, SIGHUP, SIGINT,
        SIGKILL, SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2,
    };
    pub use crate::sys::{SysError, SysRequest, SysValue};
    pub use crate::syscall::{
        MaskError, SyscallMask, SYSCALL_COUNT, SYS_CHROOT, SYS_CLOSE, SYS_DUP, SYS_EXIT, SYS_IOCTL,
        SYS_IPC_RECV, SYS_IPC_SEND, SYS_KILL, SYS_MKDIR, SYS_MMAP, SYS_MUNMAP, SYS_NET_RECV,
        SYS_NET_SEND, SYS_OPEN, SYS_PIPE, SYS_READ, SYS_SPAWN, SYS_UNLINK, SYS_WRITE,
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
        proc::{
            ExecPolicyEntry, ExecPolicyTable, ExitReason, ExitStatus, ProcError, ProcMeta,
            ProcTable, FIRST_DYNAMIC_PID, INIT_PID, MAX_EXEC_ENTRIES, MAX_PROCS,
        },
        profile::{
            app_profile, driver_profile, netd_profile, parser_profile, plugin_profile,
            service_profile, DomainProfile,
        },
        response::{apply_response, EventAction, Outcome, SecurityEvent, TELEMETRY_CAPACITY},
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
        assert_eq!(
            k.dispatch(42, SYS_READ_ID),
            Err(KernelError::UnknownDomain(42))
        );
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
            .insert(Capability {
                resource: Resource::FsNode(crate::vfs::InodeRef {
                    id: 1,
                    generation: 1,
                }),
                rights: Rights::READ.union(Rights::GRANT),
                generation: 0,
            })
            .unwrap();
        let bare = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability {
                resource: Resource::FsNode(crate::vfs::InodeRef {
                    id: 9,
                    generation: 1,
                }),
                rights: Rights::READ,
                generation: 0,
            })
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
        assert!(matches!(
            k.cap_revoke(1, bare),
            Err(CapError::InvalidHandle)
        ));
        assert!(matches!(
            k.cap_lookup(1, bare),
            Err(CapError::InvalidHandle)
        ));
        let after = k.domain_mut(1).unwrap().stats.escalation_attempts;
        assert_eq!(
            after - before,
            4,
            "every failed capability operation is an escalation signal"
        );
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
            .domain_map(
                1,
                0x5000_0000,
                4096,
                MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC
            )
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
        k.create_domain_with(2, service_profile(), 1002, 100, 0)
            .unwrap();
        k.set_monitor_window(10);
        // Dirty one domain's window through the organic syscall path.
        for _ in 0..4 {
            let _ = k.syscall(1, crate::sys::SysRequest::NetSend { len: 1 });
        }
        k.tick(9); // same window: no audit yet
        assert_eq!(
            k.domain_mut(1).unwrap().stats.syscalls_total,
            4,
            "no window closed yet"
        );
        k.tick(10); // boundary crossed: audit both domains
        assert_eq!(
            k.domain_mut(1).unwrap().stats.syscalls_total,
            0,
            "window closed by tick"
        );
        let mut events = 0;
        while k.pop_event().is_some() {
            events += 1;
        }
        assert!(
            events >= 2,
            "every domain audited on the boundary, got {events}"
        );
    }

    /// F10: stale inode references must fail closed. A domain chrooted
    /// into a directory whose slot was freed and reused by an unrelated
    /// inode must NOT silently re-root onto the new occupant: every
    /// path operation through the stale ref answers NotFound.
    #[test]
    fn stale_chroot_ref_fails_closed_after_slot_reuse() {
        use crate::sys::{SysError, SysRequest};
        use crate::vfs::Mode;
        let mut k = Kernel::new();
        // uid-0 domain builds the tree (needs parent write on /home).
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/home",
                mode: Mode(0o755),
            },
        )
        .unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/home/jail",
                mode: Mode(0o777),
            },
        )
        .unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/pub",
                mode: Mode(0o755),
            },
        )
        .unwrap();
        // The confined domain (uid 1001) chroots into /home/jail.
        k.create_domain(2, service_profile()).unwrap();
        k.syscall(2, SysRequest::Chroot { path: "/home/jail" })
            .unwrap();
        // Works while the jail lives.
        k.syscall(
            2,
            SysRequest::Mkdir {
                path: "/inside",
                mode: Mode(0o755),
            },
        )
        .unwrap();
        // The jail directory is removed and its inode slot reused by an
        // unrelated directory (root sweeps the parent first).
        k.syscall(
            1,
            SysRequest::Unlink {
                path: "/home/jail/inside",
            },
        )
        .unwrap();
        k.syscall(1, SysRequest::Unlink { path: "/home/jail" })
            .unwrap();
        // Reuse the freed slot from a different place.
        let mut reused = false;
        for i in 0..64 {
            let p = format!("/pub/d{}", i);
            if k.syscall(
                1,
                SysRequest::Mkdir {
                    path: &p,
                    mode: Mode(0o755),
                },
            )
            .is_ok()
            {
                reused = true;
            }
        }
        assert!(reused);
        // The confined domain's stale chroot/cwd refs must fail closed —
        // no silent re-root onto whatever now lives in the old slot.
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::Mkdir {
                    path: "/x",
                    mode: Mode(0o755)
                }
            ),
            Err(SysError::Vfs(crate::vfs::VfsError::StaleInode))
        ));
    }

    /// F11(b)+(c): Open takes read/write flags and checks permission at
    /// open time; Write writes at the fd offset; truncation is an
    /// explicit Open flag, not a side effect of every write.
    #[test]
    fn open_flags_and_offset_writes() {
        use crate::sys::{SysRequest, SysValue};
        use crate::vfs::Mode;
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        // Create a file, write a prefix.
        let fd = match k
            .syscall(
                1,
                SysRequest::Open {
                    path: "/log",
                    mode: Mode(0o600),
                    create: true,
                    read: true,
                    write: true,
                    truncate: false,
                },
            )
            .unwrap()
        {
            SysValue::Fd(f) => f,
            o => panic!("{:?}", o),
        };
        k.syscall(
            1,
            SysRequest::Write {
                fd,
                bytes: b"hello",
            },
        )
        .unwrap();
        // A second write CONTINUES at the offset (no truncation).
        k.syscall(
            1,
            SysRequest::Write {
                fd,
                bytes: b" world",
            },
        )
        .unwrap();
        // Read back through a fresh read-only fd.
        let rfd = match k
            .syscall(
                1,
                SysRequest::Open {
                    path: "/log",
                    mode: Mode(0o600),
                    create: false,
                    read: true,
                    write: false,
                    truncate: false,
                },
            )
            .unwrap()
        {
            SysValue::Fd(f) => f,
            o => panic!("{:?}", o),
        };
        let mut buf = [0u8; 32];
        let n = match k
            .syscall(
                1,
                SysRequest::Read {
                    fd: rfd,
                    buf: &mut buf,
                },
            )
            .unwrap()
        {
            SysValue::Count(n) => n,
            o => panic!("{:?}", o),
        };
        assert_eq!(&buf[..n], b"hello world", "writes continue at the offset");
        // Truncate is explicit: reopen with truncate and the file empties.
        let tfd = match k
            .syscall(
                1,
                SysRequest::Open {
                    path: "/log",
                    mode: Mode(0o600),
                    create: false,
                    read: false,
                    write: true,
                    truncate: true,
                },
            )
            .unwrap()
        {
            SysValue::Fd(f) => f,
            o => panic!("{:?}", o),
        };
        let _ = tfd;
        let n2 = match k
            .syscall(
                1,
                SysRequest::Read {
                    fd: rfd,
                    buf: &mut buf,
                },
            )
            .unwrap()
        {
            SysValue::Count(n) => n,
            o => panic!("{:?}", o),
        };
        assert_eq!(n2, 0, "explicit truncate emptied the file");
        // Opening write-only on a read-only-mode file is refused at open
        // (a non-root domain against a root-owned 0o444 file).
        k.syscall(
            1,
            SysRequest::Open {
                path: "/ro",
                mode: Mode(0o444),
                create: true,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap();
        k.create_domain(3, service_profile()).unwrap(); // uid 1003
        assert!(k
            .syscall(
                3,
                SysRequest::Open {
                    path: "/ro",
                    mode: Mode(0o444),
                    create: false,
                    read: false,
                    write: true,
                    truncate: false
                }
            )
            .is_err());
        // ...while opening it read-only succeeds for the same domain.
        assert!(k
            .syscall(
                3,
                SysRequest::Open {
                    path: "/ro",
                    mode: Mode(0o444),
                    create: false,
                    read: true,
                    write: false,
                    truncate: false
                }
            )
            .is_ok());
    }

    /// F13: MMAP/MUNMAP execute through the domain's policy space
    /// (refusals feed the monitor's fault signal automatically), and the
    /// mask-bit-without-executor syscalls answer NotImplemented — never
    /// a silent success.
    #[test]
    fn mmap_munmap_execute_and_stub_syscalls_never_succeed_silently() {
        use crate::memory::MemFlags;
        use crate::sys::{SysError, SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain(1, parser_profile()).unwrap(); // parser has MMAP/MUNMAP
                                                       // Legal mapping executes.
        assert!(matches!(
            k.syscall(
                1,
                SysRequest::Mmap {
                    addr: 0x5000_0000,
                    len: 8192,
                    flags: MemFlags::READ | MemFlags::WRITE
                }
            ),
            Ok(SysValue::Addr(0x5000_0000))
        ));
        // Unmap executes too.
        assert!(matches!(
            k.syscall(
                1,
                SysRequest::Munmap {
                    addr: 0x5000_0000,
                    len: 8192
                }
            ),
            Ok(SysValue::Unit)
        ));
        // A refused mapping is an error AND an organic monitor fault.
        let faults_before = k.domain_mut(1).unwrap().stats.faults;
        assert!(k
            .syscall(
                1,
                SysRequest::Mmap {
                    addr: 0x5000_0000,
                    len: 4096,
                    flags: MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC
                }
            )
            .is_err());
        assert_eq!(k.domain_mut(1).unwrap().stats.faults, faults_before + 1);
        // Stubs answer NotImplemented with their number, never Unit.
        let mut k2 = Kernel::new();
        k2.create_domain_with(2, crate::profile::driver_profile(), 1002, 100, 0)
            .unwrap(); // driver has IOCTL
        assert!(matches!(
            k2.syscall(2, SysRequest::Ioctl { cmd: 0 }),
            Err(SysError::NotImplemented(nr)) if nr == crate::syscall::SYS_IOCTL
        ));
        // And the monitor saw the attempt (the gate marks it used).
        let used = k2.domain_mut(2).unwrap().stats.used_mask();
        assert!(used & (1 << crate::syscall::SYS_IOCTL) != 0);
    }

    /// F14: `net_open` folded every NetError into UnknownDomain — a full
    /// socket table would have reported a missing domain. The signature
    /// now carries the real error. (The TableFull branch is structurally
    /// unreachable through this API today: sockets die with their
    /// domains and MAX_SOCKETS == MAX_DOMAINS, so a live table can never
    /// overflow — the type keeps the distinction for the day that
    /// decouples.) What is reachable is proven: UnknownDomain keeps its
    /// identity and a full table of live domains opens cleanly.
    #[test]
    fn net_open_preserves_its_error_variants() {
        use crate::sys::NetOpenError;
        let mut k = Kernel::new();
        assert!(matches!(
            k.net_open(9999),
            Err(NetOpenError::UnknownDomain(9999))
        ));
        // Every live domain opens: the table fills 4/4 with no folding.
        for i in 0..4u32 {
            let id = 4000 + i;
            k.create_domain_with(id, service_profile(), 2100, 100, 0)
                .unwrap();
            assert!(k.net_open(id).is_ok(), "domain {id} opens its socket");
        }
        assert_eq!(k.sockets.len(), 4);
    }

    /// F14: kernel error variants must survive the syscall boundary —
    /// the old `into_sys` collapsed everything but UnknownDomain into
    /// `UnknownDomain(0)`.
    #[test]
    fn kernel_error_variants_survive_the_boundary() {
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        // InvalidId through the syscall layer (derived-uid collision).
        assert!(matches!(
            k.create_domain(64536, service_profile()),
            Err(KernelError::InvalidId(64536))
        ));
        // DuplicateDomain surfaced, not UnknownDomain(0).
        assert!(k.syscall(1, SysRequest::Pipe).is_ok());
        // Direct: duplicate create surfaces its own variant.
        assert!(matches!(
            k.create_domain(1, service_profile()),
            Err(KernelError::DuplicateDomain(1))
        ));
        // Fill the table (MAX_DOMAINS=32 since ADR-0022; domain 1
        // exists) -> TooManyDomains surfaced.
        for id in 2..=MAX_DOMAINS as u32 {
            k.create_domain(id, service_profile()).unwrap();
        }
        assert!(matches!(
            k.create_domain(MAX_DOMAINS as u32 + 1, service_profile()),
            Err(KernelError::TooManyDomains)
        ));
        // And a syscall on a domain that does not exist keeps the id.
        assert!(matches!(
            k.syscall(99, SysRequest::Pipe),
            Err(SysError::UnknownDomain(99))
        ));
    }

    /// F14: an unauthorized sender must not learn whether a target id
    /// exists — PermissionDenied for both an existing foreign target and
    /// a missing one; uid 0 and self still get the honest UnknownDomain.
    #[test]
    fn kill_does_not_reveal_target_existence() {
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap(); // uid 1001
        k.create_domain_with(2, service_profile(), 1002, 100, 0)
            .unwrap();
        // Foreign target that EXISTS: PermissionDenied (not UnknownDomain).
        assert!(matches!(
            k.syscall(1, SysRequest::Kill { target: 2, sig: 15 }),
            Err(SysError::PermissionDenied)
        ));
        // Foreign target that does NOT exist: the same answer.
        assert!(matches!(
            k.syscall(
                1,
                SysRequest::Kill {
                    target: 7777,
                    sig: 15
                }
            ),
            Err(SysError::PermissionDenied)
        ));
        // Self still works, and a missing *own-uid* target... self-target
        // is domain 1 itself (exists): fine.
        assert!(k
            .syscall(1, SysRequest::Kill { target: 1, sig: 15 })
            .is_ok());
        // Root without a Domain capability is unauthorized too (F18,
        // ADR-0009 supersedes the old root-UnknownDomain expectation) —
        // and gets the SAME answer for a missing target: no enumeration.
        k.create_domain_with(9, service_profile(), 0, 0, 0).unwrap(); // uid 0
        assert!(matches!(
            k.syscall(
                9,
                SysRequest::Kill {
                    target: 7777,
                    sig: 15
                }
            ),
            Err(SysError::PermissionDenied)
        ));
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
                resource: crate::capability::Resource::FsNode(crate::vfs::InodeRef {
                    id: 1,
                    generation: 1,
                }),
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
                    crate::memory::MemFlags::READ
                        | crate::memory::MemFlags::WRITE
                        | crate::memory::MemFlags::EXEC,
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
        assert_eq!(
            k.domain_state(1),
            Some(DomainState::Running),
            "respawn is born clean"
        );
        assert_eq!(
            k.domain_mut(1)
                .unwrap()
                .request_syscall(crate::syscall::SYS_READ),
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
            k.create_domain_with(id, service_profile(), 2000, 100, 0)
                .unwrap();
            let _ = k.audit(id);
            k.destroy_domain(id).unwrap();
        }
        assert!(
            !k.monitor_degraded(),
            "churn must not exhaust the state table"
        );
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
            .insert(Capability {
                resource: Resource::FsNode(crate::vfs::InodeRef {
                    id: 1,
                    generation: 1,
                }),
                rights: Rights::READ.union(Rights::GRANT),
                generation: 0,
            })
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
                let _ = k.domain_map(
                    1,
                    0x5000_0000,
                    4096,
                    MemFlags::READ | MemFlags::WRITE | MemFlags::EXEC,
                );
            }
        };
        misbehave(&mut k);
        k.tick(10);
        assert_eq!(
            k.domain_state(1),
            Some(DomainState::Running),
            "hysteresis: first window only logs"
        );
        misbehave(&mut k);
        k.tick(20);
        assert_eq!(
            k.domain_state(1),
            Some(DomainState::Quarantined),
            "two bad windows of organic events quarantine"
        );
    }

    /// N2 (ADR-0007 §2): a ring-3-shaped event sequence — gate refusals
    /// through the LIVE domain, faults, unknown syscalls — driven across
    /// windows by tick with a fake clock — must reach Tighten first
    /// (mask reduced to the profile's degraded surface) and Quarantine
    /// after (only SYS_EXIT passes the live gate).
    #[test]
    fn ring3_shaped_sequence_reaches_tighten_then_quarantine() {
        use crate::domain::{Decision, DomainState};
        use crate::sys::SysRequest;
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        k.set_monitor_window(10);
        // The rogue escalates (the exact signals the ring-3 dispatch
        // feeds, N2). Phase 1 — under the spike baseline (128/window),
        // one forbidden id: denied 20 + faults 25 + out-bits 2.5 = 47.5
        // — tighten territory [35, 65) for the service profile.
        let misbehave_low = |k: &mut Kernel| {
            for _ in 0..100 {
                let _ = k.dispatch(1, crate::syscall::SYS_NET_SEND).unwrap();
            }
            for _ in 0..5 {
                k.report_fault(1).unwrap();
            }
        };
        // Phase 2 — full volume, three distinct forbidden ids: denied
        // 20 + faults 25 + out-bits 7.5 + spike 15 = 67.5 — quarantine
        // territory (>= 65).
        let misbehave_high = |k: &mut Kernel| {
            for _ in 0..100 {
                let _ = k.dispatch(1, crate::syscall::SYS_NET_SEND).unwrap();
                let _ = k.dispatch(1, crate::syscall::SYS_SPAWN).unwrap();
                let _ = k.dispatch(1, crate::syscall::SYS_IOCTL).unwrap();
            }
            for _ in 0..5 {
                k.report_fault(1).unwrap();
            }
        };
        // Window 1: tighten territory, but hysteresis wants two.
        misbehave_low(&mut k);
        k.tick(10);
        assert_eq!(k.domain_state(1), Some(DomainState::Running));
        misbehave_low(&mut k);
        k.tick(20);
        // Two hot windows: Tighten has applied — the LIVE mask is the
        // profile's degraded surface now (OPEN dropped, local I/O kept).
        assert_eq!(
            k.dispatch(1, crate::syscall::SYS_OPEN).unwrap(),
            Decision::DeniedByMask(crate::syscall::SYS_OPEN),
            "tightened live mask refuses new opens"
        );
        assert_eq!(
            k.dispatch(1, crate::syscall::SYS_WRITE).unwrap(),
            Decision::Allowed,
            "the core function stays alive while degraded"
        );
        assert_eq!(k.domain_state(1), Some(DomainState::Tightened));
        // Escalate: the next tier is quarantine.
        misbehave_high(&mut k);
        k.tick(30);
        misbehave_high(&mut k);
        k.tick(40);
        assert_eq!(k.domain_state(1), Some(DomainState::Quarantined));
        // Only SYS_EXIT passes the live gate now.
        assert_eq!(
            k.dispatch(1, crate::syscall::SYS_EXIT).unwrap(),
            Decision::Allowed,
            "quarantine keeps the exit door open"
        );
        assert_eq!(
            k.dispatch(1, crate::syscall::SYS_WRITE).unwrap(),
            Decision::DeniedQuarantined(crate::syscall::SYS_WRITE)
        );
        let _ = SysRequest::Pipe; // (import shape check)
    }

    /// Risk treatment 2 (ADR-0009 addendum): chroot is also a
    /// capability boundary — the jail capability is minted and every
    /// FsNode capability outside the jail is dropped (attenuation-only;
    /// resolve already confined the paths, now the capability table
    /// matches that confinement instead of holding the tree-wide ROOT).
    #[test]
    fn chroot_attenuates_the_fs_capability_to_the_jail() {
        use crate::capability::Resource;
        use crate::sys::{SysRequest, SysValue};
        use crate::vfs::{Mode, ROOT_REF};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/home",
                mode: Mode(0o755),
            },
        )
        .unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/home/jail",
                mode: Mode(0o777),
            },
        )
        .unwrap();
        k.create_domain(2, service_profile()).unwrap();
        // Sanity: creation minted the tree-wide root capability.
        {
            let d = k.domain_mut(2).unwrap();
            assert!(
                d.caps
                    .iter()
                    .any(|c| c.resource == Resource::FsNode(ROOT_REF)),
                "creation mints FsNode(ROOT)"
            );
        }
        k.syscall(2, SysRequest::Chroot { path: "/home/jail" })
            .unwrap();
        let jail = k.domain_mut(2).unwrap().chroot_root;
        assert_ne!(jail, ROOT_REF);
        {
            let d = k.domain_mut(2).unwrap();
            assert!(
                !d.caps
                    .iter()
                    .any(|c| c.resource == Resource::FsNode(ROOT_REF)),
                "the tree-wide ROOT capability must be dropped at chroot"
            );
            assert!(
                d.caps.iter().any(|c| c.resource == Resource::FsNode(jail)),
                "the jail capability must be minted at chroot"
            );
        }
        // The domain still works inside the jail — the fresh capability
        // covers it; only the scope shrank, nothing else changed.
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::Mkdir {
                    path: "/inside",
                    mode: Mode(0o755)
                }
            ),
            Ok(SysValue::Unit)
        ));
        // Deepening: a second chroot drops the previous jail capability
        // too — the scope only ever shrinks (attenuation-only).
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/home/jail/deeper",
                mode: Mode(0o777),
            },
        )
        .unwrap();
        k.syscall(2, SysRequest::Chroot { path: "/deeper" })
            .unwrap();
        let deeper = k.domain_mut(2).unwrap().chroot_root;
        assert_ne!(deeper, jail);
        {
            let d = k.domain_mut(2).unwrap();
            assert!(
                !d.caps.iter().any(|c| c.resource == Resource::FsNode(jail)),
                "the previous jail capability must be dropped on a deeper chroot"
            );
            assert!(d
                .caps
                .iter()
                .any(|c| c.resource == Resource::FsNode(deeper)));
        }
    }

    /// Risk treatment 3 (ADR-0009 addendum): the supervisor grant path
    /// is a real, checked API — uid-0 callers only, unknown targets
    /// refused, the minted capability recorded through the normal
    /// table (no raw supervisor pokes required anywhere).
    #[test]
    fn cap_grant_domain_is_supervisor_only() {
        use crate::capability::{Resource, Rights};
        use crate::sys::{SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain_with(2, service_profile(), 4242, 100, 0)
            .unwrap();
        k.create_domain_with(9, service_profile(), 0, 0, 0).unwrap();
        // A non-root domain cannot grant itself anything.
        assert!(
            k.cap_grant_domain(2, 2).is_err(),
            "non-root grant must be refused"
        );
        // Root grants a Domain(2) capability to itself...
        let h = k.cap_grant_domain(9, 2).unwrap();
        let c = k.cap_lookup(9, h).unwrap();
        assert_eq!(c.resource, Resource::Domain(2));
        assert!(c.rights.contains(Rights::WRITE));
        // ...and can then signal domain 2 (the capability gate passes;
        // uid 0 passes the Unix layer).
        assert!(matches!(
            k.syscall(9, SysRequest::Kill { target: 2, sig: 15 }),
            Ok(SysValue::Unit)
        ));
        // Granting for an unknown target fails cleanly.
        assert!(k.cap_grant_domain(9, 7777).is_err());
    }

    // ── ADR-0004 slice 1: capability-endpoint IPC (async half) ──
    // Rights mapping (ADR-0004 §4 → the existing Rights bitset):
    // SEND = WRITE, RECV = READ, GRANT = GRANT. Derivation stays
    // subset-only through the existing `attenuate`.

    /// The gate: no Endpoint capability, no send. The refusal is
    /// counted as an escalation attempt (an organic monitor signal),
    /// exactly like the FsNode/Device/Domain gates.
    #[test]
    fn ipc_send_requires_the_endpoint_capability() {
        use crate::capability::Rights;
        use crate::sys::{SysError, SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        k.create_domain(3, service_profile()).unwrap();
        let (ep, _h) = k.ipc_endpoint_create(1, 3).unwrap();
        // Domain 2 holds no Endpoint capability: refused and counted.
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            ),
            Err(SysError::PermissionDenied)
        ));
        assert_eq!(k.domain_mut(2).unwrap().stats.escalation_attempts, 1);
        // The supervisor grants a WRITE-only capability: the send passes.
        k.ipc_endpoint_grant(1, ep, 2, Rights::WRITE).unwrap();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            ),
            Ok(SysValue::Count(_))
        ));
    }

    /// ADR-0004 §2: bounded per-endpoint queue, FIFO, EAGAIN-style
    /// failure when full — never a block, never a silent drop.
    #[test]
    fn ipc_queue_is_bounded_and_fifo_with_eagain() {
        use crate::ipc::IpcError;
        use crate::sys::{SysError, SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        let (ep, _h) = k.ipc_endpoint_create(1, 2).unwrap();
        // The owner's minted cap is WRITE+READ+GRANT: fill the queue.
        for len in [8u32, 16, 24, 32] {
            assert!(matches!(
                k.syscall(2, SysRequest::IpcSend { channel: ep, len }),
                Ok(SysValue::Count(_))
            ));
        }
        // Depth exhausted: the 5th send fails EAGAIN-style.
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 40
                }
            ),
            Err(SysError::Ipc(IpcError::QueueFull))
        ));
        // Delivery order is FIFO (asserted through the lengths).
        for len in [8u32, 16, 24, 32] {
            assert!(matches!(
                k.syscall(2, SysRequest::IpcRecv { channel: ep }),
                Ok(SysValue::Count(n)) if n == len as usize
            ));
        }
        // Drained: a further recv reports empty, not a block.
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecv { channel: ep }),
            Err(SysError::Ipc(IpcError::QueueEmpty))
        ));
    }

    /// ADR-0004 §2: queues are per-domain — RECV is owner-only. A
    /// delegated READ capability proves knowledge of the endpoint but
    /// does not move the queue (that is a later, explicit slice).
    #[test]
    fn ipc_recv_is_owner_only_and_capability_gated() {
        use crate::capability::Rights;
        use crate::ipc::IpcError;
        use crate::sys::{SysError, SysRequest, SysValue};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        k.create_domain(3, service_profile()).unwrap();
        let (ep, h) = k.ipc_endpoint_create(1, 2).unwrap();
        // Put one message in the queue.
        assert!(k
            .syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            )
            .is_ok());
        // Domain 3 gets a READ+WRITE delegation: it may send, but it
        // is still not the owner — the queue does not move for it.
        k.ipc_endpoint_grant(1, ep, 3, Rights::READ | Rights::WRITE)
            .unwrap();
        assert!(matches!(
            k.syscall(3, SysRequest::IpcRecv { channel: ep }),
            Err(SysError::Ipc(IpcError::NotOwner(_)))
        ));
        // The owner without its capability: the cap gate fires first.
        k.cap_revoke(2, h).unwrap();
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecv { channel: ep }),
            Err(SysError::PermissionDenied)
        ));
        // The owner, re-granted a READ capability, drains the queue.
        let _ = k.syscall(
            3,
            SysRequest::IpcSend {
                channel: ep,
                len: 12,
            },
        );
        k.ipc_endpoint_grant(1, ep, 2, Rights::READ).unwrap();
        // FIFO: the owner's earlier self-send (8) precedes domain 3's
        // message (12) — order is preserved end to end.
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecv { channel: ep }),
            Ok(SysValue::Count(8))
        ));
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecv { channel: ep }),
            Ok(SysValue::Count(12))
        ));
    }

    /// Revocation and endpoint destruction both fail closed — a stale
    /// handle (revoked cap) and a dead endpoint id (destroyed table
    /// entry) are distinct, precise refusals.
    #[test]
    fn ipc_revoked_and_stale_capabilities_fail_closed() {
        use crate::ipc::IpcError;
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        k.create_domain(3, service_profile()).unwrap();
        let (ep, h) = k.ipc_endpoint_create(1, 2).unwrap();
        assert!(k
            .syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            )
            .is_ok());
        // Revoked cap: the capability gate refuses (PermissionDenied).
        k.cap_revoke(2, h).unwrap();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            ),
            Err(SysError::PermissionDenied)
        ));
        // Destroyed endpoint: domains 2 and 3 keep live caps in their
        // tables, but the endpoint id is dead forever (never reused).
        k.ipc_endpoint_grant(1, ep, 3, crate::capability::Rights::WRITE)
            .unwrap();
        k.ipc_endpoint_grant(1, ep, 2, crate::capability::Rights::READ)
            .unwrap();
        k.ipc_endpoint_destroy(1, ep).unwrap();
        // Both now fail at the LIVENESS check — the capability gates
        // pass, the dead id does not (the no-ABA guarantee).
        assert!(matches!(
            k.syscall(
                3,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            ),
            Err(SysError::Ipc(IpcError::InvalidHandle))
        ));
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecv { channel: ep }),
            Err(SysError::Ipc(IpcError::InvalidHandle))
        ));
    }

    /// Delegation is attenuation-only: a grant can never carry rights
    /// the endpoint does not confer, and a delegated WRITE cap cannot
    /// be used to receive.
    #[test]
    fn ipc_delegation_attenuation_only() {
        use crate::capability::Rights;
        use crate::sys::SysRequest;
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        let (ep, h) = k.ipc_endpoint_create(1, 2).unwrap();
        // EXEC is not among the endpoint's conferable rights: refused.
        assert!(k.ipc_endpoint_grant(1, ep, 2, Rights::EXEC).is_err());
        // WRITE-only delegation: the child can send...
        let child = k.cap_attenuate(2, h, Rights::WRITE).unwrap();
        assert!(k
            .syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 4
                }
            )
            .is_ok());
        // ...and the derivation is recorded as a strict subset.
        let c = k.cap_lookup(2, child).unwrap();
        assert!(c
            .rights
            .is_subset_of(Rights::READ | Rights::WRITE | Rights::GRANT));
        assert!(!c.rights.contains(Rights::READ));
        // Escalation through the table is still refused.
        assert!(k
            .cap_attenuate(2, child, Rights::READ | Rights::WRITE)
            .is_err());
    }

    /// ADR-0004 §1: messages are fixed-size (<= 64 bytes). The size
    /// check is the cheapest test and runs before any capability work.
    #[test]
    fn ipc_message_size_limit_is_64_bytes() {
        use crate::ipc::IpcError;
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        let (ep, _h) = k.ipc_endpoint_create(1, 2).unwrap();
        assert!(k
            .syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 64
                }
            )
            .is_ok());
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 65
                }
            ),
            Err(SysError::Ipc(IpcError::TooLong(65)))
        ));
    }

    /// Quarantine cuts IPC like every other syscall: only EXIT passes.
    #[test]
    fn quarantined_domain_cannot_ipc() {
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        let (ep, _h) = k.ipc_endpoint_create(1, 2).unwrap();
        assert!(k
            .syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            )
            .is_ok());
        k.domain_mut(2).unwrap().quarantine();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 8
                }
            ),
            Err(SysError::Quarantined(crate::syscall::SYS_IPC_SEND))
        ));
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecv { channel: ep }),
            Err(SysError::Quarantined(crate::syscall::SYS_IPC_RECV))
        ));
    }

    /// The supervisor APIs are uid-0 only and fail loud on every
    /// boundary: non-root callers, unknown owners, exhausted tables.
    #[test]
    fn ipc_supervisor_apis_are_uid0_only_and_fail_loud() {
        use crate::ipc::{IpcError, MAX_ENDPOINTS};
        use crate::KernelError;
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        // Non-root cannot create, grant, or destroy.
        assert!(matches!(
            k.ipc_endpoint_create(2, 2),
            Err(KernelError::NotAuthorized(2))
        ));
        assert!(matches!(
            k.ipc_endpoint_destroy(2, 0),
            Err(KernelError::NotAuthorized(2))
        ));
        // Unknown owner: precise refusal, no side effects.
        assert!(matches!(
            k.ipc_endpoint_create(1, 7777),
            Err(KernelError::UnknownDomain(7777))
        ));
        // Table exhaustion is surfaced (F14 discipline: never silent).
        let mut made = 0;
        loop {
            match k.ipc_endpoint_create(1, 2) {
                Ok(_) => made += 1,
                Err(KernelError::Ipc(IpcError::TableFull)) => break,
                Err(e) => panic!("unexpected: {e:?}"),
            }
        }
        assert_eq!(made, MAX_ENDPOINTS);
        // Destroy frees a slot (a later create succeeds), and the
        // freed endpoint's id is never handed out again.
        let first_id = 1; // ids start at 1, monotonic
        k.ipc_endpoint_destroy(1, first_id).unwrap();
        let (new_id, _h) = k.ipc_endpoint_create(1, 2).unwrap();
        assert_ne!(new_id, first_id, "endpoint ids are never reused");
    }

    /// F18: the capability layer is load-bearing — a domain with the
    /// right syscall mask and passing Unix DAC is STILL denied when it
    /// holds no FsNode capability covering the operation, and the
    /// failure feeds the escalation signal.
    #[test]
    fn right_mask_but_no_capability_is_denied_and_recorded() {
        use crate::sys::{SysError, SysRequest, SysValue};
        use crate::vfs::Mode;
        let mut k = Kernel::new();
        // Root builds a world-readable file in a world-executable tree.
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/pub",
                mode: Mode(0o777),
            },
        )
        .unwrap();
        k.syscall(
            1,
            SysRequest::Open {
                path: "/pub/x",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: true,
                truncate: false,
            },
        )
        .unwrap();
        // The service (mask: OPEN is on; DAC: /pub is 0o777, /pub/x is
        // 0o644 with other: r) opens it for read — works today ONLY
        // because caps are not enforced (the RED state).
        k.create_domain(2, service_profile()).unwrap();
        let open = |k: &mut Kernel| {
            k.syscall(
                2,
                SysRequest::Open {
                    path: "/pub/x",
                    mode: Mode(0o644),
                    create: false,
                    read: true,
                    write: false,
                    truncate: false,
                },
            )
        };
        // Sanity today: with the minted root capability, the open works.
        assert!(
            open(&mut k).is_ok(),
            "the minted FsNode(ROOT) capability must cover the tree"
        );
        // Revoke EVERY FsNode capability the domain holds.
        {
            let d = k.domain_mut(2).unwrap();
            let mut revoked_any = false;
            for _ in 0..crate::capability::MAX_CAPABILITIES {
                let Some(h) = d.caps.handles().next() else {
                    break;
                };
                // Revoke one at a time; keep only if it was an FsNode —
                // revoke everything, assert at least one FsNode went.
                match d.caps.revoke(h) {
                    Ok(c) => {
                        if matches!(c.resource, crate::capability::Resource::FsNode(_)) {
                            revoked_any = true;
                        }
                    }
                    Err(_) => break,
                }
            }
            assert!(
                revoked_any,
                "the domain must have held an FsNode capability"
            );
        }
        let escalations = k.domain_mut(2).unwrap().stats.escalation_attempts;
        match open(&mut k) {
            Err(SysError::PermissionDenied) => {}
            other => panic!(
                "mask+DAC pass but no capability must be denied, got {:?}",
                other.map(|_| ())
            ),
        }
        assert_eq!(
            k.domain_mut(2).unwrap().stats.escalation_attempts,
            escalations + 1,
            "the failed capability check is an escalation signal"
        );
        let _ = SysValue::Unit;
    }

    /// F18: revocation bites on the very next syscall — netd loses its
    /// Device capability and NetSend is refused (mask still on, bucket
    /// still full).
    #[test]
    fn revoked_device_capability_fails_the_next_syscall() {
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain(1, crate::profile::netd_profile()).unwrap();
        // A send with the minted Device(0) capability: passes the cap
        // gate; the token bucket is fresh, so the only refusal reason
        // left would be the (unimplemented) executor — count attempts.
        let _ = k.syscall(1, SysRequest::NetSend { len: 4 });
        // Revoke the Device capability.
        {
            let d = k.domain_mut(1).unwrap();
            let mut revoked = false;
            for _ in 0..crate::capability::MAX_CAPABILITIES {
                let Some(h) = d.caps.handles().next() else {
                    break;
                };
                if let Ok(c) = d.caps.revoke(h) {
                    if matches!(c.resource, crate::capability::Resource::Device(_)) {
                        revoked = true;
                        break;
                    }
                }
            }
            assert!(revoked, "netd must have held a Device capability");
        }
        assert!(matches!(
            k.syscall(1, SysRequest::NetSend { len: 4 }),
            Err(SysError::PermissionDenied)
        ));
    }

    /// F18: derivation never exceeds the parent, and the failed
    /// derivation inserts nothing.
    #[test]
    fn derived_capability_cannot_exceed_parent() {
        use crate::capability::{CapError, Capability, Resource, Rights};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        let grantor = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability {
                resource: Resource::FsNode(crate::vfs::ROOT_REF),
                rights: Rights::READ.union(Rights::GRANT),
                generation: 0,
            })
            .unwrap();
        let before = k.domain_mut(1).unwrap().caps.len();
        assert!(matches!(
            k.cap_attenuate(1, grantor, Rights::READ.union(Rights::WRITE)),
            Err(CapError::Escalation)
        ));
        assert_eq!(
            k.domain_mut(1).unwrap().caps.len(),
            before,
            "a failed derivation inserts nothing"
        );
        // And a legal derivation stays inside the parent's rights.
        let child = k.cap_attenuate(1, grantor, Rights::READ).unwrap();
        let c = k.cap_lookup(1, child).unwrap();
        assert!(c.rights.is_subset_of(Rights::READ));
    }

    /// F18: a domain cannot mint capabilities — no syscall grows its
    /// table; only supervisor APIs can.
    #[test]
    fn a_domain_cannot_mint_capabilities() {
        use crate::sys::SysRequest;
        use crate::vfs::Mode;
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.syscall(
            1,
            SysRequest::Mkdir {
                path: "/pub",
                mode: Mode(0o777),
            },
        )
        .unwrap();
        k.create_domain(2, service_profile()).unwrap();
        let minted = k.domain_mut(2).unwrap().caps.len();
        assert!(
            minted >= 3,
            "creation mints FsNode/Device/Domain (got {minted})"
        );
        // A battery of everything the domain can attempt.
        for req in [
            SysRequest::Open {
                path: "/pub/x",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: true,
                truncate: false,
            },
            SysRequest::Mkdir {
                path: "/pub/d",
                mode: Mode(0o755),
            },
            SysRequest::Kill { target: 2, sig: 15 },
            SysRequest::Pipe,
        ] {
            let _ = k.syscall(2, req);
        }
        assert_eq!(
            k.domain_mut(2).unwrap().caps.len(),
            minted,
            "no syscall may grow a domain's capability table"
        );
    }

    /// F18 + F14 layering: Kill needs a Domain capability (self-kill
    /// always works through the minted self-capability); with a granted
    /// capability the Unix DAC layer still applies; an unauthorized
    /// sender — root included — gets the same PermissionDenied for
    /// existing and missing targets (no enumeration).
    #[test]
    fn kill_requires_a_domain_capability_then_unix_rules() {
        use crate::capability::{Capability, Resource, Rights};
        use crate::sys::{SysError, SysRequest};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap(); // uid 1001
        k.create_domain_with(2, service_profile(), 1001, 100, 0)
            .unwrap(); // same uid
                       // Self-kill: the minted Domain(self) capability passes.
        assert!(k
            .syscall(1, SysRequest::Kill { target: 1, sig: 15 })
            .is_ok());
        // No Domain(2) capability: denied, existing or not (F14 shape).
        assert!(matches!(
            k.syscall(1, SysRequest::Kill { target: 2, sig: 15 }),
            Err(SysError::PermissionDenied)
        ));
        assert!(matches!(
            k.syscall(
                1,
                SysRequest::Kill {
                    target: 7777,
                    sig: 15
                }
            ),
            Err(SysError::PermissionDenied)
        ));
        // Root is unauthorized too without a grant — same answer for
        // existing and missing (this supersedes F14's root-UnknownDomain
        // expectation; ADR-0009 §3).
        k.create_domain_with(9, service_profile(), 0, 0, 0).unwrap();
        assert!(matches!(
            k.syscall(9, SysRequest::Kill { target: 2, sig: 15 }),
            Err(SysError::PermissionDenied)
        ));
        // Supervisor grants a Domain(2) capability: now the cap gate
        // passes and the Unix layer decides — same uid: allowed.
        k.domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability {
                resource: Resource::Domain(2),
                rights: Rights::WRITE,
                generation: 0,
            })
            .unwrap();
        assert!(k
            .syscall(1, SysRequest::Kill { target: 2, sig: 15 })
            .is_ok());
        // ...different uid: the DAC layer refuses even with the cap.
        k.domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability {
                resource: Resource::Domain(9),
                rights: Rights::WRITE,
                generation: 0,
            })
            .unwrap();
        assert!(matches!(
            k.syscall(1, SysRequest::Kill { target: 9, sig: 15 }),
            Err(SysError::PermissionDenied)
        ));
    }

    /// N2 mirror of ring3-rogue mode 3: per iteration six forbidden
    /// syscalls (unknown 200 + NET_SEND/NET_RECV/SPAWN/IOCTL/MMAP — all
    /// off the service surface) and one allowed-but-refused crossing
    /// write (-EFAULT -> fault signal). Denied ratio 6/7, faults, a
    /// rate spike and 5 out-of-profile bits -> quarantine territory.
    #[test]
    fn rogue_blob_shape_quarantines_the_service_domain() {
        use crate::domain::DomainState;
        use crate::syscall::{SYS_IOCTL, SYS_MMAP, SYS_NET_RECV, SYS_NET_SEND, SYS_SPAWN};
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        k.set_monitor_window(10);
        let spam = |k: &mut Kernel| {
            for _ in 0..200 {
                k.report_unknown_syscall(1).unwrap(); // forged nr
                let _ = k.dispatch(1, SYS_NET_SEND).unwrap();
                let _ = k.dispatch(1, SYS_NET_RECV).unwrap();
                let _ = k.dispatch(1, SYS_SPAWN).unwrap();
                let _ = k.dispatch(1, SYS_IOCTL).unwrap();
                let _ = k.dispatch(1, SYS_MMAP).unwrap();
                // The crossing write: allowed by the mask, refused by
                // validation -> an organic fault.
                k.report_fault(1).unwrap();
            }
        };
        spam(&mut k);
        k.tick(10);
        spam(&mut k);
        k.tick(20);
        assert_eq!(
            k.domain_state(1),
            Some(DomainState::Quarantined),
            "the rogue's own signals must quarantine it (service sensitivity 40)"
        );
    }

    /// N2: unknown syscall numbers (>= SYSCALL_COUNT, unnormalizable)
    /// feed the monitor's denied signal through the live domain.
    #[test]
    fn unknown_syscalls_feed_the_denied_signal() {
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        let before = k.domain_mut(1).unwrap().stats.denied_syscalls;
        k.report_unknown_syscall(1).unwrap();
        k.report_unknown_syscall(1).unwrap();
        let after = k.domain_mut(1).unwrap().stats.denied_syscalls;
        assert_eq!(after - before, 2, "every forged nr is a denial");
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
        let pair = |k: &mut Kernel, d: u32| match k.syscall(d, SysRequest::Pipe).unwrap() {
            SysValue::FdPair(r, w) => (r, w),
            other => panic!("{:?}", other),
        };
        let (r_a, w_a) = pair(&mut k, 1);
        let (r_b, w_b) = pair(&mut k, 1);
        // dup2(w_a, r_b): pipe B's read end loses its reference here.
        match k
            .syscall(
                1,
                SysRequest::Dup {
                    fd: w_a,
                    new_fd: r_b,
                },
            )
            .unwrap()
        {
            SysValue::Fd(f) => assert_eq!(f, r_b),
            other => panic!("{:?}", other),
        }
        // dup2(fd, fd) must be a pure no-op (no refcount change).
        match k
            .syscall(
                1,
                SysRequest::Dup {
                    fd: w_a,
                    new_fd: w_a,
                },
            )
            .unwrap()
        {
            SysValue::Fd(f) => assert_eq!(f, w_a),
            other => panic!("{:?}", other),
        }
        for fd in [r_a, w_a, r_b, w_b] {
            k.syscall(1, SysRequest::Close { fd }).unwrap();
        }
        k.destroy_domain(1).unwrap();
        assert_eq!(
            k.pipes.len(),
            0,
            "replaced/self-dup pipe ends must not leak"
        );
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
        assert_eq!(
            v1.response,
            Response::Log,
            "hysteresis applies in audit-only too"
        );
        make_bad(&mut k);
        let v2 = k.audit(1).unwrap();
        assert_eq!(
            v2.response,
            Response::Quarantine,
            "the verdict is still computed"
        );
        // ...but nothing was applied:
        assert_eq!(k.domain_state(1), Some(crate::domain::DomainState::Running));
        assert_eq!(
            k.domain_mut(1)
                .unwrap()
                .request_syscall(crate::syscall::SYS_READ),
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
        let (r, w) = match k.syscall(1, SysRequest::Pipe).unwrap() {
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
            k.create_domain(id, crate::profile::plugin_profile())
                .unwrap();
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

// ── ADR-0026: sync call/reply over the park machinery ──────────

#[cfg(test)]
mod adr0026_sync_ipc {
    use super::*;
    use crate::capability::Rights;
    use crate::ipc::{IpcError, IpcWaitKind};
    use crate::profile::service_profile;
    use crate::sys::{SysError, SysRequest, SysValue};

    /// The common frame: a uid-0 supervisor (1), an endpoint owner
    /// (3), and callers (2, 4) granted WRITE on the owner's endpoint.
    fn frame() -> (Kernel<{ crate::buddy::FRAME_COUNT }>, u32) {
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 0, 0, 0).unwrap();
        k.create_domain(2, service_profile()).unwrap();
        k.create_domain(3, service_profile()).unwrap();
        k.create_domain(4, service_profile()).unwrap();
        let (ep, _h) = k.ipc_endpoint_create(1, 3).unwrap();
        k.ipc_endpoint_grant(1, ep, 2, Rights::WRITE).unwrap();
        k.ipc_endpoint_grant(1, ep, 4, Rights::WRITE).unwrap();
        (k, ep)
    }

    /// call blocks the caller and registers the wait; reply answers
    /// the OLDEST caller first (FIFO) and produces the wake pair.
    #[test]
    fn call_blocks_and_reply_wakes_fifo() {
        let (mut k, ep) = frame();
        // Two callers call; both park with Unit.
        for d in [2u32, 4] {
            assert!(matches!(
                k.syscall(
                    d,
                    SysRequest::IpcCall {
                        channel: ep,
                        len: 7
                    }
                ),
                Ok(SysValue::Unit)
            ));
            assert!(!k.sched.entity(d).unwrap().runnable, "caller {d} blocked");
        }
        // The owner replies: the FIRST caller (domain 2) wakes first.
        assert!(matches!(
            k.syscall(
                3,
                SysRequest::IpcReply {
                    channel: ep,
                    len: 0x11
                }
            ),
            Ok(SysValue::Count(1))
        ));
        assert!(
            k.sched.entity(2).unwrap().runnable,
            "the oldest caller woke"
        );
        assert!(
            !k.sched.entity(4).unwrap().runnable,
            "the second still waits"
        );
        assert_eq!(k.pop_ipc_wake(), Some((2, 0x11)));
        assert_eq!(k.pop_ipc_wake(), None, "one reply, one wake");
        // The second reply wakes the second caller.
        assert!(matches!(
            k.syscall(
                3,
                SysRequest::IpcReply {
                    channel: ep,
                    len: 0x22
                }
            ),
            Ok(SysValue::Count(1))
        ));
        assert!(k.sched.entity(4).unwrap().runnable);
        assert_eq!(k.pop_ipc_wake(), Some((4, 0x22)));
    }

    /// The owner's recv_wait fast path: a waiting message pops now
    /// (Count), no block.
    #[test]
    fn recv_wait_fast_path_pops_without_blocking() {
        let (mut k, ep) = frame();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 9
                }
            ),
            Ok(SysValue::Count(_))
        ));
        assert!(matches!(
            k.syscall(3, SysRequest::IpcRecvWait { channel: ep }),
            Ok(SysValue::Count(9))
        ));
        assert!(k.sched.entity(3).unwrap().runnable, "never parked");
        assert_eq!(k.pop_ipc_wake(), None);
    }

    /// recv_wait on empty parks the owner; the next push RENDEZVOUSES
    /// (the message self-consumes; the owner wakes with the len; the
    /// queue stays empty).
    #[test]
    fn recv_wait_blocks_and_the_push_rendezvouses() {
        let (mut k, ep) = frame();
        assert!(matches!(
            k.syscall(3, SysRequest::IpcRecvWait { channel: ep }),
            Ok(SysValue::Unit)
        ));
        assert!(!k.sched.entity(3).unwrap().runnable, "the owner parked");
        // An async SEND (not just call) wakes the parked owner.
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcSend {
                    channel: ep,
                    len: 5
                }
            ),
            Ok(SysValue::Count(_))
        ));
        assert!(
            k.sched.entity(3).unwrap().runnable,
            "rendezvous woke the owner"
        );
        assert_eq!(k.pop_ipc_wake(), Some((3, 5)));
        // The message left with the owner: the queue is empty again
        // (the async backlog never holds a rendezvoused message).
        assert!(
            matches!(
                k.syscall(3, SysRequest::IpcRecvWait { channel: ep }),
                Ok(SysValue::Unit)
            ),
            "the queue is empty — the owner parks again"
        );
    }

    /// The call's push rides the same rendezvous: an owner parked in
    /// recv_wait takes the CALL's message immediately.
    #[test]
    fn the_call_message_rendezvouses_too() {
        let (mut k, ep) = frame();
        assert!(matches!(
            k.syscall(3, SysRequest::IpcRecvWait { channel: ep }),
            Ok(SysValue::Unit)
        ));
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcCall {
                    channel: ep,
                    len: 12
                }
            ),
            Ok(SysValue::Unit)
        ));
        // Both the owner (the message) and the caller (awaiting
        // reply) are in their waits; the owner is RUNNABLE (woken).
        assert!(k.sched.entity(3).unwrap().runnable);
        assert!(!k.sched.entity(2).unwrap().runnable);
        assert_eq!(k.pop_ipc_wake(), Some((3, 12)));
        // The caller's wait is the AwaitingReply kind on ep.
        assert!(k.ipc_waiters.iter().any(|w| matches!(w,
            Some(w) if w.domain == 2
                && w.kind == IpcWaitKind::AwaitingReply { endpoint: ep })));
    }

    /// reply with nobody asking is the transient truth: EAGAIN-style.
    #[test]
    fn reply_with_no_waiter_refuses_eagain() {
        let (mut k, ep) = frame();
        assert!(matches!(
            k.syscall(
                3,
                SysRequest::IpcReply {
                    channel: ep,
                    len: 1
                }
            ),
            Err(SysError::Ipc(IpcError::QueueEmpty))
        ));
    }

    /// A dying domain's wait dies with it: the reply finds no waiter.
    #[test]
    fn destroy_clears_the_wait() {
        let (mut k, ep) = frame();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcCall {
                    channel: ep,
                    len: 3
                }
            ),
            Ok(SysValue::Unit)
        ));
        k.destroy_domain(2).unwrap();
        assert!(k.ipc_waiters.iter().all(|w| w.is_none()));
        assert!(matches!(
            k.syscall(
                3,
                SysRequest::IpcReply {
                    channel: ep,
                    len: 1
                }
            ),
            Err(SysError::Ipc(IpcError::QueueEmpty))
        ));
    }

    /// A second call while one is outstanding REPLACES the wait (the
    /// sleepers' rule: one blocking wait per domain).
    #[test]
    fn a_second_call_replaces_the_wait() {
        let (mut k, ep) = frame();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcCall {
                    channel: ep,
                    len: 1
                }
            ),
            Ok(SysValue::Unit)
        ));
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcCall {
                    channel: ep,
                    len: 2
                }
            ),
            Ok(SysValue::Unit)
        ));
        let n = k
            .ipc_waiters
            .iter()
            .flatten()
            .filter(|w| w.domain == 2)
            .count();
        assert_eq!(n, 1, "one wait per domain, replaced not stacked");
        // And the reply finds exactly that one.
        assert!(matches!(
            k.syscall(
                3,
                SysRequest::IpcReply {
                    channel: ep,
                    len: 9
                }
            ),
            Ok(SysValue::Count(1))
        ));
    }

    /// The no-cap gate holds on the sync arms exactly as on send:
    /// WRITE gates call, READ gates recv_wait/reply, and the owner
    /// check refuses a non-owner's recv_wait/reply.
    #[test]
    fn the_sync_arms_keep_the_gates() {
        let (mut k, ep) = frame();
        // A caller granted only WRITE cannot recv_wait or reply: the
        // READ gate refuses FIRST (the async recv's order — the cap
        // denial is the stronger, earlier signal).
        assert!(matches!(
            k.syscall(2, SysRequest::IpcRecvWait { channel: ep }),
            Err(SysError::PermissionDenied)
        ));
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcReply {
                    channel: ep,
                    len: 1
                }
            ),
            Err(SysError::PermissionDenied)
        ));
    }
}

// ── ADR-0027: page grants — the core gate ─────────────────────

#[cfg(test)]
mod adr0027_grants {
    use super::*;
    use crate::profile::service_profile;
    use crate::sys::{SysError, SysRequest, SysValue};

    /// The grant frame: domain 2 is the GRANTER (uid 0 —
    /// cap_grant_domain is the supervisor self-grant API, the kill
    /// pattern), domain 1 the grantee-side target.
    fn frame() -> Kernel<{ crate::buddy::FRAME_COUNT }> {
        let mut k = Kernel::new();
        k.create_domain_with(1, service_profile(), 101, 0, 0)
            .unwrap();
        k.create_domain_with(2, service_profile(), 0, 0, 0).unwrap();
        k
    }

    /// The gate: no Domain capability on dst, no grant. The refusal
    /// is an escalation attempt (the organic monitor signal), like
    /// every other capability gate.
    #[test]
    fn grant_requires_the_domain_capability() {
        let mut k = frame();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcGrantFrames {
                    dst: 1,
                    va: 0x1000,
                    len: 4096
                }
            ),
            Err(SysError::PermissionDenied)
        ));
        assert_eq!(k.domain_mut(2).unwrap().stats.escalation_attempts, 1);
        // The granter self-grants the Domain cap (the kill pattern):
        // the gate passes.
        k.cap_grant_domain(2, 1).unwrap();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcGrantFrames {
                    dst: 1,
                    va: 0x1000,
                    len: 4096
                }
            ),
            Ok(SysValue::Unit)
        ));
    }

    /// The supervisor's conferral API: a uid-0 caller puts the
    /// Domain(target) cap in ANOTHER holder's list (the endpoint-grant
    /// shape); a non-root caller refuses.
    #[test]
    fn cap_grant_domain_to_confers_on_the_holder() {
        let mut k = frame();
        // Domain 1 (uid 101) holds nothing yet: the gate refuses.
        assert!(matches!(
            k.syscall(
                1,
                SysRequest::IpcGrantFrames {
                    dst: 2,
                    va: 0x1000,
                    len: 4096
                }
            ),
            Err(SysError::PermissionDenied)
        ));
        // A non-root caller cannot confer.
        assert!(k.cap_grant_domain_to(1, 1, 2).is_err());
        // The uid-0 granter (2) confers Domain(2) on 1: the gate now
        // passes from 1's side.
        k.cap_grant_domain_to(2, 1, 2).unwrap();
        assert!(matches!(
            k.syscall(
                1,
                SysRequest::IpcGrantFrames {
                    dst: 2,
                    va: 0x1000,
                    len: 4096
                }
            ),
            Ok(SysValue::Unit)
        ));
    }

    /// A dead grantee is ESRCH, not a silent drop.
    #[test]
    fn grant_to_a_dead_domain_refuses() {
        let mut k = frame();
        // The cap exists for a target that DIES holding it — the
        // liveness check must catch it (an unknown id would need its
        // own cap, and cap_grant_domain refuses missing targets).
        k.create_domain(3, service_profile()).unwrap();
        k.cap_grant_domain(2, 3).unwrap();
        k.destroy_domain(3).unwrap();
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcGrantFrames {
                    dst: 3,
                    va: 0x1000,
                    len: 4096
                }
            ),
            Err(SysError::UnknownDomain(3))
        ));
    }

    /// The bound: page-granular, nonzero, and never above the shares
    /// table's own capacity (MAX_SHARED pages).
    #[test]
    fn grant_len_is_bounded_and_page_granular() {
        let mut k = frame();
        k.cap_grant_domain(2, 1).unwrap();
        for bad in [
            0u32,
            1,
            4097,
            (crate::frame_share::MAX_SHARED as u32 + 1) * 4096,
        ] {
            assert!(
                matches!(
                    k.syscall(
                        2,
                        SysRequest::IpcGrantFrames {
                            dst: 1,
                            va: 0x1000,
                            len: bad
                        }
                    ),
                    Err(SysError::InvalidArgument(_))
                ),
                "len {bad} must refuse"
            );
        }
        // The exact table capacity is fine.
        assert!(matches!(
            k.syscall(
                2,
                SysRequest::IpcGrantFrames {
                    dst: 1,
                    va: 0x1000,
                    len: (crate::frame_share::MAX_SHARED as u32) * 4096
                }
            ),
            Ok(SysValue::Unit)
        ));
    }
}
