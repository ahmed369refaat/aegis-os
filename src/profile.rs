//! Domain profiles: templates that define the initial, *maximal* surface a
//! domain of a given class ever gets. Live masks start from the profile and
//! can only attenuate from there.
//!
//! Policy choices (deliberately narrow defaults — least privilege):
//! - Parsers get no network, no spawn, no ioctl, no write.
//! - Plugins get read + IPC only.
//! - Network egress is brokered: `netd_profile` is the ONLY profile that
//!   carries NET_* rights, and its sends are kernel rate-limited per client.
//! - The Linux-like process-management syscalls (PIPE/DUP/KILL/CHROOT)
//!   belong to the service profile exclusively; the file-family
//!   mutators (MKDIR/UNLINK/LISTDIR/STAT/RENAME) are shared with the
//!   package manager, whose whole surface they nearly are (K22).

use crate::capability::Rights;
use crate::syscall::{
    SyscallMask, SYS_CHROOT, SYS_CLOCK_GETTIME, SYS_CLOSE, SYS_DEVREG, SYS_DUP, SYS_EXEC, SYS_EXIT,
    SYS_FORK, SYS_IPC_CALL, SYS_IPC_GRANT, SYS_IPC_RECV, SYS_IPC_RECV_WAIT, SYS_IPC_REPLY,
    SYS_IPC_SEND, SYS_KILL, SYS_LISTDIR, SYS_MKDIR, SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP,
    SYS_NET_RECV, SYS_NET_SEND, SYS_OPEN, SYS_PIPE, SYS_PIPE_READ, SYS_PIPE_WRITE, SYS_READ,
    SYS_RENAME, SYS_SCHED_YIELD, SYS_SIGACTION, SYS_STAT, SYS_UNLINK, SYS_WAIT, SYS_WRITE,
};

/// The surface a domain of this class keeps while *degraded* (the
/// monitor's Tighten tier, F8). Per-profile instead of one global mask:
/// a strict subset of `syscalls`, always containing SYS_EXIT, and it
/// keeps the profile's core function alive (driver keeps IOCTL, netd
/// keeps NET_*). The old global `tightened_surface()` was a no-op for
/// plugin and removed the entire purpose of driver and netd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegradedSurface(pub SyscallMask);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainProfile {
    pub name: &'static str,
    /// Initial (maximal) syscall surface for this class of domain.
    pub syscalls: SyscallMask,
    /// Memory quota in pages.
    pub quota_pages: usize,
    /// Rights baked into capabilities minted for this domain at creation.
    pub base_rights: Rights,
    /// 0..=100: how jumpy the behavior monitor is for this class. Higher
    /// sensitivity lowers the tighten/quarantine thresholds for the domain.
    pub sensitivity: u8,
    /// The Tighten-tier surface (F8): a strict subset of `syscalls`,
    /// always keeping SYS_EXIT and the profile's core function.
    pub degraded_syscalls: SyscallMask,
    /// ADR-0022: how many live+ zombie children this class of process
    /// may hold at once (the fork/spawn limit; checked at every
    /// spawn/fork against the PARENT's profile).
    pub max_children: u16,
}

/// ADR-0032 section A: the typed reason a profile request is not an
/// attenuation of its parent. One variant per authority axis — the
/// audit trail names what was attacked, not just "escalation".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileViolation {
    /// The requested syscall surface is not a subset of the parent's
    /// LIVE mask (the possibly-tightened one, not the class profile).
    MaskWiderThanParentLive,
    /// The requested memory quota exceeds the parent's live quota.
    QuotaAboveParent,
    /// Monitor sensitivity would DROP relative to the parent — the
    /// child would be watched less closely.
    SensitivityBelowParent,
    /// The Tighten-tier surface is not strictly narrower than the full
    /// surface (`degraded == syscalls` makes Tighten a no-op).
    DegradedNotNarrower,
    /// The Tighten tier drops the exit call — a tightened domain could
    /// never leave.
    DegradedDropsExit,
    /// The child's fan-out limit is not strictly below the parent's.
    FanOutNotStricter,
    /// The requested base rights exceed the parent's base rights.
    RightsBroaderThanParent,
}

impl DomainProfile {
    /// ADR-0032 section A: is this REQUEST an attenuation of the
    /// parent? Pure, host-tested, and used at every point a requested
    /// profile becomes a live domain. The parent's LIVE state is passed
    /// in (mask and quota may be tighter than its class profile — the
    /// child must fit under what the parent has NOW).
    ///
    /// The destructure below is EXHAUSTIVE on purpose — no `..`: adding
    /// a field to `DomainProfile` breaks this function until someone
    /// classifies the new field as authority, limit, or monitor
    /// parameter and extends the relation. `name` is classified as
    /// pure metadata (a label, no authority).
    pub fn is_attenuation_of(
        &self,
        parent: &DomainProfile,
        parent_live_mask: &SyscallMask,
        parent_live_quota: usize,
    ) -> Result<(), ProfileViolation> {
        let DomainProfile {
            name: _child_name,
            syscalls: child_syscalls,
            quota_pages: child_quota,
            base_rights: child_rights,
            sensitivity: child_sensitivity,
            degraded_syscalls: child_degraded,
            max_children: child_max_children,
        } = self;
        if !child_syscalls.is_subset_of(parent_live_mask) {
            return Err(ProfileViolation::MaskWiderThanParentLive);
        }
        if *child_quota > parent_live_quota {
            return Err(ProfileViolation::QuotaAboveParent);
        }
        if *child_sensitivity < parent.sensitivity {
            return Err(ProfileViolation::SensitivityBelowParent);
        }
        // The Tighten tier must be a PROPER subset of the surface (an
        // equal tier makes Tighten a no-op) and must always keep the
        // exit call (a tightened domain can always leave).
        if !child_degraded.is_subset_of(child_syscalls) || child_degraded == child_syscalls {
            return Err(ProfileViolation::DegradedNotNarrower);
        }
        if !child_degraded.is_allowed(SYS_EXIT).unwrap_or(false) {
            return Err(ProfileViolation::DegradedDropsExit);
        }
        if *child_max_children >= parent.max_children {
            return Err(ProfileViolation::FanOutNotStricter);
        }
        if !child_rights.is_subset_of(parent.base_rights) {
            return Err(ProfileViolation::RightsBroaderThanParent);
        }
        Ok(())
    }
}

/// Long-running local service (vfsd-style): full file I/O + IPC + the
/// Linux-like process-management syscalls, still no direct network.
pub const fn service_profile() -> DomainProfile {
    DomainProfile {
        name: "service",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_OPEN)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_IPC_SEND)
                | (1u64 << SYS_IPC_RECV)
                | (1u64 << SYS_IPC_CALL)
                | (1u64 << SYS_IPC_RECV_WAIT)
                | (1u64 << SYS_IPC_REPLY)
                | (1u64 << SYS_IPC_GRANT)
                | (1u64 << SYS_PIPE)
                | (1u64 << SYS_PIPE_READ)
                | (1u64 << SYS_PIPE_WRITE)
                | (1u64 << SYS_DUP)
                | (1u64 << SYS_KILL)
                | (1u64 << SYS_CHROOT)
                | (1u64 << SYS_MKDIR)
                | (1u64 << SYS_UNLINK)
                | (1u64 << SYS_LISTDIR)
                | (1u64 << SYS_STAT)
                | (1u64 << SYS_RENAME)
                | (1u64 << SYS_MMAP)
                | (1u64 << SYS_MUNMAP)
                | (1u64 << SYS_FORK)
                | (1u64 << SYS_EXEC)
                | (1u64 << SYS_WAIT)
                | (1u64 << SYS_NANOSLEEP)
                | (1u64 << SYS_SCHED_YIELD)
                | (1u64 << SYS_CLOCK_GETTIME)
                | (1u64 << SYS_SIGACTION)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded service: existing local I/O and IPC stay; every path
        // that opens NEW resources (open/mkdir/unlink/stat/rename) or
        // manages other domains (kill/chroot) drops.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_IPC_SEND)
                | (1u64 << SYS_IPC_RECV)
                | (1u64 << SYS_IPC_CALL)
                | (1u64 << SYS_IPC_RECV_WAIT)
                | (1u64 << SYS_IPC_REPLY)
                | (1u64 << SYS_IPC_GRANT)
                | (1u64 << SYS_PIPE)
                | (1u64 << SYS_PIPE_READ)
                | (1u64 << SYS_PIPE_WRITE)
                | (1u64 << SYS_DUP)
                | (1u64 << SYS_WAIT)
                | (1u64 << SYS_EXIT),
        ),
        quota_pages: 256,
        base_rights: Rights::READ.union(Rights::WRITE),
        sensitivity: 40,
        max_children: 8,
    }
}

/// Untrusted file parser (e.g. image/font/document decoder): read + map only.
pub const fn parser_profile() -> DomainProfile {
    DomainProfile {
        name: "parser",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_MMAP)
                | (1u64 << SYS_MUNMAP)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded parser: no new mappings — decode what is already
        // mapped and get out.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ) | (1u64 << SYS_CLOSE) | (1u64 << SYS_EXIT),
        ),
        quota_pages: 64,
        base_rights: Rights::READ,
        sensitivity: 70,
        max_children: 2,
    }
}

/// Device driver domain (ADR-0017's shape, v2): the whole surface is
/// the device-register channel — `SYS_DEVREG`, routed to the domain's
/// OWN registered core, window-checked — plus the exit. No file I/O,
/// no IPC, no ioctl: the MMIO window and the broker-mapped frames of
/// its own domain are literally everything the driver can reach.
/// The degraded tier drops the channel and keeps the exit: a
/// tightened driver can always stop cleanly.
pub const fn driver_profile() -> DomainProfile {
    DomainProfile {
        name: "driver",
        syscalls: SyscallMask::from_bits((1u64 << SYS_DEVREG) | (1u64 << SYS_EXIT)),
        degraded_syscalls: SyscallMask::from_bits(1u64 << SYS_EXIT),
        quota_pages: 16,
        base_rights: Rights::NONE,
        sensitivity: 50,
        max_children: 0,
    }
}

/// Third-party plugin: the most restrictive surface that is still useful.
pub const fn plugin_profile() -> DomainProfile {
    DomainProfile {
        name: "plugin",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_IPC_SEND)
                | (1u64 << SYS_IPC_RECV)
                | (1u64 << SYS_IPC_CALL)
                | (1u64 << SYS_IPC_RECV_WAIT)
                | (1u64 << SYS_IPC_REPLY)
                | (1u64 << SYS_IPC_GRANT)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded plugin: keep its IPC lifeline, stop reading new
        // inputs.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_IPC_SEND)
                | (1u64 << SYS_IPC_RECV)
                | (1u64 << SYS_IPC_CALL)
                | (1u64 << SYS_IPC_RECV_WAIT)
                | (1u64 << SYS_IPC_REPLY)
                | (1u64 << SYS_IPC_GRANT)
                | (1u64 << SYS_EXIT),
        ),
        quota_pages: 32,
        base_rights: Rights::READ,
        sensitivity: 80,
        max_children: 2,
    }
}

/// The network broker (netd): the ONLY profile that touches the NIC.
/// Every other domain sends through it over IPC; its own sends are
/// rate-limited per-client by the kernel (see `net`).
pub const fn netd_profile() -> DomainProfile {
    DomainProfile {
        name: "netd",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_IPC_SEND)
                | (1u64 << SYS_IPC_RECV)
                | (1u64 << SYS_IPC_CALL)
                | (1u64 << SYS_IPC_RECV_WAIT)
                | (1u64 << SYS_IPC_REPLY)
                | (1u64 << SYS_IPC_GRANT)
                | (1u64 << SYS_NET_SEND)
                | (1u64 << SYS_NET_RECV)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded netd: NET_* is the whole point — it stays; the IPC
        // side channels drop.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_NET_SEND)
                | (1u64 << SYS_NET_RECV)
                | (1u64 << SYS_EXIT),
        ),
        quota_pages: 128,
        base_rights: Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
        sensitivity: 30,
        max_children: 4,
    }
}

/// K22: the package manager domain (`/bin/pkg`). The file family's
/// whole working set — read, write, open (with O_EXCL), close, mkdir,
/// unlink, listdir, stat, rename — and NOTHING from the process
/// family: it installs files, it never starts, signals, jails or
/// pipes anything, it holds no IPC and no network (a repo fetch is a
/// broker round-trip that does not exist yet — until it does, the
/// mask says so). The transaction layer's needs are exactly this
/// list: the O_EXCL lock, staged files, journaled mkdir, the rename
/// commit, stat for the destination-parent walks, getdents for the
/// repo-config listing.
///
/// A pure attenuation of `service_profile` on every axis (the host
/// test pins it): the quota covers the image's mapped pages plus the
/// 64-page stack its no_alloc buffers need under the service exec
/// layout (see `mm::user_layout::ExecLayout` in the kernel).
pub const fn package_manager_profile() -> DomainProfile {
    DomainProfile {
        name: "pkg",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_OPEN)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_MKDIR)
                | (1u64 << SYS_UNLINK)
                | (1u64 << SYS_LISTDIR)
                | (1u64 << SYS_STAT)
                | (1u64 << SYS_RENAME)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded pkg: drain what is already open and leave — every
        // path that touches the tree by name (open/mkdir/unlink/
        // listdir/stat/rename) drops, so a tightened manager can never
        // start a transaction.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ) | (1u64 << SYS_WRITE) | (1u64 << SYS_CLOSE) | (1u64 << SYS_EXIT),
        ),
        quota_pages: 192,
        base_rights: Rights::READ.union(Rights::WRITE),
        sensitivity: 40,
        max_children: 0,
    }
}

/// ADR-0022: the default profile for spawned processes and for any
/// executable the exec policy table does not list — "app". File I/O +
/// pipes + the process family (fork/exec/wait); NO kill, NO chroot,
/// NO mkdir/unlink, NO net, NO IPC. Monitoring starts AuditOnly
/// (the exec policy may mark a binary Enforce explicitly).
pub const fn app_profile() -> DomainProfile {
    DomainProfile {
        name: "app",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_OPEN)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_PIPE)
                | (1u64 << SYS_PIPE_READ)
                | (1u64 << SYS_PIPE_WRITE)
                | (1u64 << SYS_DUP)
                | (1u64 << SYS_FORK)
                | (1u64 << SYS_EXEC)
                | (1u64 << SYS_WAIT)
                | (1u64 << SYS_MMAP)
                | (1u64 << SYS_MUNMAP)
                | (1u64 << SYS_NANOSLEEP)
                | (1u64 << SYS_SCHED_YIELD)
                | (1u64 << SYS_CLOCK_GETTIME)
                | (1u64 << SYS_SIGACTION)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded app: keep draining what is already open; the power
        // to start anything new (fork/exec/open) drops.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_WAIT)
                | (1u64 << SYS_EXIT),
        ),
        quota_pages: 64,
        base_rights: Rights::READ.union(Rights::WRITE),
        sensitivity: 60,
        max_children: 8,
    }
}

#[cfg(test)]
mod degraded_tests {
    use super::*;
    use crate::syscall::{
        SYS_CLOSE, SYS_DUP, SYS_EXIT, SYS_IOCTL, SYS_IPC_RECV, SYS_MMAP, SYS_NET_RECV,
        SYS_NET_SEND, SYS_OPEN, SYS_PIPE, SYS_READ, SYS_WRITE,
    };

    /// F8: every profile's degraded surface is a STRICT subset of its
    /// live surface, always keeps SYS_EXIT, and keeps the profile's
    /// core function alive (driver keeps IOCTL, netd keeps NET_*,
    /// service keeps local I/O). The old global `tightened_surface()`
    /// was a no-op for plugin and removed the entire purpose of driver
    /// (IOCTL) and netd (NET_*).
    #[test]
    fn degraded_surface_is_a_strict_subset_that_keeps_exit_and_core() {
        let all = [
            service_profile(),
            parser_profile(),
            driver_profile(),
            plugin_profile(),
            netd_profile(),
            package_manager_profile(),
        ];
        for p in all {
            let d = p.degraded_syscalls;
            assert!(
                d.is_subset_of(&p.syscalls),
                "{}: degraded must be a subset",
                p.name
            );
            assert_ne!(
                d, p.syscalls,
                "{}: degraded must actually drop something",
                p.name
            );
            assert!(
                d.is_allowed(SYS_EXIT).unwrap(),
                "{}: EXIT always reachable",
                p.name
            );
        }
        // Core functions survive degradation:
        assert!(
            service_profile()
                .degraded_syscalls
                .is_allowed(SYS_WRITE)
                .unwrap(),
            "service: local I/O"
        );
        assert!(service_profile()
            .degraded_syscalls
            .is_allowed(SYS_PIPE)
            .unwrap());
        assert!(service_profile()
            .degraded_syscalls
            .is_allowed(SYS_DUP)
            .unwrap());
        // The v2 driver is the DELIBERATE exception: its whole purpose
        // (the DEVREG channel) is exactly what Tighten removes — a
        // tightened driver is a STOPPED driver, the same containment
        // the core's refusal ladder enforces from the device side. The
        // old profile kept an ioctl stub that was never implemented;
        // the v2 surface is DEVREG+EXIT, and the degraded tier keeps
        // only the exit (the loop above already pinned that).
        assert!(
            !driver_profile()
                .degraded_syscalls
                .is_allowed(SYS_DEVREG)
                .unwrap(),
            "driver: Tighten stops the channel by design"
        );
        assert!(
            !driver_profile().syscalls.is_allowed(SYS_IOCTL).unwrap(),
            "driver v2: the ioctl stub is gone"
        );
        assert!(
            netd_profile()
                .degraded_syscalls
                .is_allowed(SYS_NET_SEND)
                .unwrap(),
            "netd: egress"
        );
        assert!(
            netd_profile()
                .degraded_syscalls
                .is_allowed(SYS_NET_RECV)
                .unwrap(),
            "netd: ingress"
        );
        assert!(
            plugin_profile()
                .degraded_syscalls
                .is_allowed(SYS_IPC_SEND)
                .unwrap(),
            "plugin: IPC"
        );
        assert!(plugin_profile()
            .degraded_syscalls
            .is_allowed(SYS_IPC_RECV)
            .unwrap());
        // The dangerous paths really drop:
        assert!(
            !service_profile()
                .degraded_syscalls
                .is_allowed(SYS_OPEN)
                .unwrap(),
            "no new opens degraded"
        );
        assert!(
            !parser_profile()
                .degraded_syscalls
                .is_allowed(SYS_MMAP)
                .unwrap(),
            "no new mappings degraded"
        );
        // G: a REAL assertion (was `|| true`, a no-op): the degraded
        // service keeps reading — existing local I/O stays alive.
        assert!(
            service_profile()
                .degraded_syscalls
                .is_allowed(SYS_READ)
                .unwrap(),
            "the degraded service keeps its local I/O lifeline"
        );
        let _ = (
            SYS_CLOSE,
            SYS_WRITE,
            SYS_IPC_SEND,
            SYS_IPC_RECV,
            SYS_NET_RECV,
        );
    }

    /// The degraded surface must be what `apply_response` uses for
    /// Tighten — a domain of each profile tightens to its own degraded
    /// mask, not the old global one.
    #[test]
    fn tighten_uses_the_profile_degraded_surface() {
        for p in [
            service_profile(),
            parser_profile(),
            driver_profile(),
            plugin_profile(),
            netd_profile(),
            package_manager_profile(),
        ] {
            let mut d = crate::domain::Domain::new(7, p);
            d.tighten(&p.degraded_syscalls);
            assert_eq!(
                d.mask(),
                p.degraded_syscalls,
                "{}: tighten = degraded",
                p.name
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::{SYS_IOCTL, SYS_NET_RECV, SYS_NET_SEND, SYS_SPAWN};

    const ALL_PROFILES: [DomainProfile; 4] = [
        service_profile(),
        parser_profile(),
        driver_profile(),
        plugin_profile(),
    ];

    #[test]
    fn every_profile_mask_is_subset_of_all() {
        for p in ALL_PROFILES {
            assert!(p.syscalls.is_subset_of(&SyscallMask::ALL), "{}", p.name);
            assert!(
                !p.syscalls.is_allowed(SYS_SPAWN).unwrap(),
                "{} may not spawn",
                p.name
            );
        }
    }

    #[test]
    fn every_profile_keeps_exit_reachable() {
        for p in ALL_PROFILES {
            assert!(
                p.syscalls.is_allowed(SYS_EXIT).unwrap(),
                "{} must always allow EXIT",
                p.name
            );
        }
    }

    #[test]
    fn parser_is_minimal_io() {
        let p = parser_profile();
        for allowed in [SYS_READ, SYS_CLOSE, SYS_MMAP, SYS_MUNMAP] {
            assert!(p.syscalls.is_allowed(allowed).unwrap());
        }
        for denied in [
            SYS_WRITE,
            SYS_OPEN,
            SYS_SPAWN,
            SYS_IOCTL,
            SYS_IPC_SEND,
            SYS_NET_SEND,
            SYS_NET_RECV,
        ] {
            assert!(
                !p.syscalls.is_allowed(denied).unwrap(),
                "parser must not use {}",
                denied
            );
        }
    }

    #[test]
    fn driver_is_devreg_and_exit_only() {
        let p = driver_profile();
        assert!(p.syscalls.is_allowed(SYS_DEVREG).unwrap());
        assert!(p.syscalls.is_allowed(SYS_EXIT).unwrap());
        // The old round-5 surface (read/write/ioctl/ipc) is gone: the
        // MMIO window + the broker's own-domain frames are the whole
        // surface a driver domain can reach.
        for denied in [
            SYS_IOCTL,
            SYS_READ,
            SYS_WRITE,
            SYS_IPC_SEND,
            SYS_SPAWN,
            SYS_NET_SEND,
            SYS_MMAP,
        ] {
            assert!(!p.syscalls.is_allowed(denied).unwrap());
        }
    }

    #[test]
    fn plugin_surface_is_read_plus_ipc_only() {
        let p = plugin_profile();
        for allowed in [SYS_READ, SYS_IPC_SEND, SYS_IPC_RECV] {
            assert!(p.syscalls.is_allowed(allowed).unwrap());
        }
        for denied in [SYS_WRITE, SYS_OPEN, SYS_MMAP, SYS_IOCTL, SYS_SPAWN] {
            assert!(!p.syscalls.is_allowed(denied).unwrap());
        }
    }

    #[test]
    fn only_the_broker_profile_has_network_egress() {
        // Every non-broker profile must be NET-free...
        for p in [
            service_profile(),
            parser_profile(),
            driver_profile(),
            plugin_profile(),
            package_manager_profile(),
        ] {
            assert!(!p.syscalls.is_allowed(SYS_NET_SEND).unwrap(), "{}", p.name);
            assert!(!p.syscalls.is_allowed(SYS_NET_RECV).unwrap(), "{}", p.name);
        }
        // ...and netd (the broker) is the only one that holds NET_*.
        let netd = netd_profile();
        assert!(netd.syscalls.is_allowed(SYS_NET_SEND).unwrap());
        assert!(netd.syscalls.is_allowed(SYS_NET_RECV).unwrap());
        assert!(!netd.syscalls.is_allowed(SYS_SPAWN).unwrap());
        assert!(
            !netd.syscalls.is_allowed(SYS_KILL).unwrap(),
            "the broker may not kill"
        );
    }

    /// The process-management half of the Linux-like family — pipes,
    /// descriptor games, kill, chroot — is the service profile's
    /// alone: no other class may hold it, the package manager
    /// included.
    #[test]
    fn service_holds_the_process_management_syscalls_exclusively() {
        let s = service_profile();
        for allowed in [SYS_PIPE, SYS_DUP, SYS_KILL, SYS_CHROOT] {
            assert!(
                s.syscalls.is_allowed(allowed).unwrap(),
                "service may use {}",
                allowed
            );
        }
        for p in [
            parser_profile(),
            driver_profile(),
            plugin_profile(),
            netd_profile(),
            package_manager_profile(),
        ] {
            for denied in [SYS_PIPE, SYS_DUP, SYS_KILL, SYS_CHROOT] {
                assert!(
                    !p.syscalls.is_allowed(denied).unwrap(),
                    "{} may not use {}",
                    p.name,
                    denied
                );
            }
        }
    }

    /// The file-family mutators are the service's and the package
    /// manager's — K22 re-scoped the old "service exclusively" rule
    /// for exactly these five calls; every other class still holds
    /// none of them.
    #[test]
    fn the_file_family_mutators_belong_to_service_and_pkg() {
        for p in [service_profile(), package_manager_profile()] {
            for allowed in [SYS_MKDIR, SYS_UNLINK, SYS_LISTDIR, SYS_STAT, SYS_RENAME] {
                assert!(
                    p.syscalls.is_allowed(allowed).unwrap(),
                    "{} may use {}",
                    p.name,
                    allowed
                );
            }
        }
        for p in [
            parser_profile(),
            driver_profile(),
            plugin_profile(),
            netd_profile(),
        ] {
            for denied in [SYS_MKDIR, SYS_UNLINK, SYS_LISTDIR, SYS_STAT, SYS_RENAME] {
                assert!(
                    !p.syscalls.is_allowed(denied).unwrap(),
                    "{} may not use {}",
                    p.name,
                    denied
                );
            }
        }
    }

    /// K22: the package manager's exact surface — the file family and
    /// nothing else — and its shape as an attenuation of the service
    /// profile on every axis (so a supervisor may hand it down to a
    /// service's child without a policy exception).
    #[test]
    fn the_package_manager_is_the_file_family_and_a_service_attenuation() {
        let p = package_manager_profile();
        let expected = SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_OPEN)
                | (1u64 << SYS_CLOSE)
                | (1u64 << SYS_MKDIR)
                | (1u64 << SYS_UNLINK)
                | (1u64 << SYS_LISTDIR)
                | (1u64 << SYS_STAT)
                | (1u64 << SYS_RENAME)
                | (1u64 << SYS_EXIT),
        );
        assert_eq!(p.syscalls, expected, "the mask is exactly the file family");
        assert_eq!(p.name, "pkg");
        assert_eq!(p.max_children, 0, "the manager never forks or spawns");
        assert_eq!(p.base_rights, Rights::READ.union(Rights::WRITE));
        assert_eq!(
            p.degraded_syscalls,
            SyscallMask::from_bits(
                (1u64 << SYS_READ) | (1u64 << SYS_WRITE) | (1u64 << SYS_CLOSE) | (1u64 << SYS_EXIT)
            )
        );
        for denied in [
            SYS_PIPE,
            SYS_DUP,
            SYS_KILL,
            SYS_CHROOT,
            SYS_FORK,
            SYS_EXEC,
            SYS_SPAWN,
            SYS_MMAP,
            SYS_IPC_SEND,
            SYS_NET_SEND,
            SYS_NET_RECV,
            SYS_DEVREG,
        ] {
            assert!(
                !p.syscalls.is_allowed(denied).unwrap(),
                "pkg must not use {}",
                denied
            );
        }
        let s = service_profile();
        assert_eq!(
            p.is_attenuation_of(&s, &s.syscalls, s.quota_pages),
            Ok(()),
            "pkg is a pure attenuation of service"
        );
        // The quota is a real ceiling for the service exec layout: the
        // image (~35 pages) + 64 stack pages + the trampoline fit; a
        // second image's worth on top does not.
        assert!(p.quota_pages >= 35 + 65); // 35 image pages + 64 stack + 1 trampoline
        assert!(p.quota_pages < s.quota_pages);
    }

    #[test]
    fn sensitivity_and_quotas_in_range() {
        for p in ALL_PROFILES {
            assert!(p.sensitivity <= 100, "{}", p.name);
            assert!(p.quota_pages > 0, "{}", p.name);
        }
        // Untrusted classes must be more sensitive than trusted ones.
        assert!(plugin_profile().sensitivity > service_profile().sensitivity);
        assert!(parser_profile().sensitivity > driver_profile().sensitivity);
    }

    #[test]
    fn base_rights_follow_least_privilege() {
        assert!(parser_profile().base_rights.is_subset_of(Rights::READ));
        assert!(plugin_profile().base_rights.is_subset_of(Rights::READ));
        assert!(service_profile()
            .base_rights
            .is_subset_of(Rights::READ | Rights::WRITE));
    }
}

#[cfg(test)]
mod adr0032_tests {
    use super::*;

    /// A fully-specified legal parent (sensitivity 40, fan-out 4,
    /// rights READ|WRITE, quota 100).
    fn parent() -> DomainProfile {
        DomainProfile {
            name: "axis-parent",
            syscalls: SyscallMask::from_bits(
                1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT,
            ),
            quota_pages: 100,
            base_rights: Rights::READ.union(Rights::WRITE),
            sensitivity: 40,
            degraded_syscalls: SyscallMask::from_bits(1u64 << SYS_EXIT),
            max_children: 4,
        }
    }

    /// An attenuated request: legal on every axis.
    fn legal_child() -> DomainProfile {
        DomainProfile {
            name: "child",
            syscalls: SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_EXIT),
            quota_pages: 50,
            base_rights: Rights::READ,
            sensitivity: 60,
            degraded_syscalls: SyscallMask::from_bits(1u64 << SYS_EXIT),
            max_children: 3,
        }
    }

    #[test]
    fn a_legal_request_passes() {
        let p = parent();
        assert_eq!(
            legal_child().is_attenuation_of(&p, &p.syscalls, p.quota_pages),
            Ok(())
        );
    }

    #[test]
    fn each_axis_has_a_typed_reason() {
        let p = parent();
        // Mask wider than the parent's LIVE mask (the class profile is
        // wider here — the live one is not).
        let mut r = legal_child();
        r.syscalls =
            SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT);
        assert_eq!(
            r.is_attenuation_of(&p, &SyscallMask::from_bits(1u64 << SYS_EXIT), 100),
            Err(ProfileViolation::MaskWiderThanParentLive)
        );
        // Quota above the live quota.
        let mut r = legal_child();
        r.quota_pages = 101;
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::QuotaAboveParent)
        );
        // Sensitivity below the parent's.
        let mut r = legal_child();
        r.sensitivity = 39;
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::SensitivityBelowParent)
        );
        // Degraded tier equal to the surface (Tighten becomes a no-op).
        let mut r = legal_child();
        r.degraded_syscalls = r.syscalls;
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::DegradedNotNarrower)
        );
        // Degraded tier outside the surface is equally refused.
        let mut r = legal_child();
        r.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_WRITE | 1u64 << SYS_EXIT);
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::DegradedNotNarrower)
        );
        // Degraded tier dropping the exit call.
        let mut r = legal_child();
        r.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_READ);
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::DegradedDropsExit)
        );
        // Fan-out equal to the parent's (strict decay is required).
        let mut r = legal_child();
        r.max_children = 4;
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::FanOutNotStricter)
        );
        // Base rights broader than the parent's.
        let mut r = legal_child();
        r.base_rights = Rights::READ.union(Rights::WRITE).union(Rights::GRANT);
        assert_eq!(
            r.is_attenuation_of(&p, &p.syscalls, 100),
            Err(ProfileViolation::RightsBroaderThanParent)
        );
    }

    #[test]
    fn the_live_mask_can_be_tighter_than_the_class_profile() {
        // The parent's class surface includes WRITE, but its LIVE mask
        // has been tightened to READ|EXIT: a request keeping WRITE —
        // legal against the class profile — must be refused against
        // the live one.
        let p = parent();
        let mut r = legal_child();
        r.syscalls =
            SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT);
        let live = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_EXIT);
        assert_eq!(
            r.is_attenuation_of(&p, &live, 100),
            Err(ProfileViolation::MaskWiderThanParentLive)
        );
    }

    /// ADR-0032 section A, the property form: 10k seeded random pairs —
    /// a request that PASSES is never weaker on ANY axis.
    #[test]
    fn property_passing_requests_never_weaken_any_axis() {
        let p = parent();
        let mut s: u64 = 0x00AD_0032_5EED_0001;
        for _ in 0..10_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let mut r = legal_child();
            if s & 1 != 0 {
                r.syscalls = SyscallMask::from_bits(s);
            }
            if (s >> 8) & 1 != 0 {
                r.quota_pages = (s >> 16) as usize % 300;
            }
            if (s >> 9) & 1 != 0 {
                r.sensitivity = ((s >> 20) % 101) as u8;
            }
            if (s >> 10) & 1 != 0 {
                r.degraded_syscalls = SyscallMask::from_bits(s >> 24);
            }
            if (s >> 11) & 1 != 0 {
                r.max_children = ((s >> 28) % 8) as u16;
            }
            if (s >> 12) & 1 != 0 {
                r.base_rights = Rights::from_bits((s >> 32) as u8);
            }
            if r.is_attenuation_of(&p, &p.syscalls, 100).is_ok() {
                // The never-weaker guarantee, axis by axis.
                assert!(r.syscalls.is_subset_of(&p.syscalls));
                assert!(r.quota_pages <= 100);
                assert!(r.sensitivity >= p.sensitivity);
                assert!(r.degraded_syscalls.is_subset_of(&r.syscalls));
                assert!(r.degraded_syscalls != r.syscalls);
                assert!(r.degraded_syscalls.is_allowed(SYS_EXIT).unwrap_or(false));
                assert!(r.max_children < p.max_children);
                assert!(r.base_rights.is_subset_of(p.base_rights));
            }
        }
    }
}
