//! Domain profiles: templates that define the initial, *maximal* surface a
//! domain of a given class ever gets. Live masks start from the profile and
//! can only attenuate from there.
//!
//! Policy choices (deliberately narrow defaults — least privilege):
//! - Parsers get no network, no spawn, no ioctl, no write.
//! - Plugins get read + IPC only.
//! - Network egress is brokered: `netd_profile` is the ONLY profile that
//!   carries NET_* rights, and its sends are kernel rate-limited per client.
//! - The Linux-like process syscalls (PIPE/DUP/KILL/CHROOT/MKDIR/UNLINK/
//!   LISTDIR) belong to the service profile exclusively.

use crate::capability::Rights;
use crate::syscall::{
    SyscallMask, SYS_CHROOT, SYS_CLOCK_GETTIME, SYS_CLOSE, SYS_DUP, SYS_EXEC, SYS_EXIT, SYS_FORK,
    SYS_IOCTL, SYS_IPC_CALL, SYS_IPC_GRANT, SYS_IPC_RECV, SYS_IPC_RECV_WAIT, SYS_IPC_REPLY,
    SYS_IPC_SEND, SYS_KILL, SYS_LISTDIR, SYS_MKDIR, SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP,
    SYS_NET_RECV, SYS_NET_SEND, SYS_OPEN, SYS_PIPE, SYS_PIPE_READ, SYS_PIPE_WRITE, SYS_READ,
    SYS_SCHED_YIELD, SYS_SIGACTION, SYS_UNLINK, SYS_WAIT, SYS_WRITE,
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
        // that opens NEW resources (open/mkdir/unlink) or manages other
        // domains (kill/chroot) drops.
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

/// Device driver domain: controlled by a vendor, still untrusted to the kernel.
pub const fn driver_profile() -> DomainProfile {
    DomainProfile {
        name: "driver",
        syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ)
                | (1u64 << SYS_WRITE)
                | (1u64 << SYS_IOCTL)
                | (1u64 << SYS_IPC_SEND)
                | (1u64 << SYS_IPC_RECV)
                | (1u64 << SYS_IPC_CALL)
                | (1u64 << SYS_IPC_RECV_WAIT)
                | (1u64 << SYS_IPC_REPLY)
                | (1u64 << SYS_IPC_GRANT)
                | (1u64 << SYS_EXIT),
        ),
        // Degraded driver: IOCTL is the whole point — it stays; the
        // side channels (IPC) drop.
        degraded_syscalls: SyscallMask::from_bits(
            (1u64 << SYS_READ) | (1u64 << SYS_WRITE) | (1u64 << SYS_IOCTL) | (1u64 << SYS_EXIT),
        ),
        quota_pages: 128,
        base_rights: Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
        sensitivity: 50,
        max_children: 2,
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
        SYS_CLOSE, SYS_DUP, SYS_EXIT, SYS_IOCTL, SYS_IPC_RECV, SYS_IPC_SEND, SYS_MMAP,
        SYS_NET_RECV, SYS_NET_SEND, SYS_OPEN, SYS_PIPE, SYS_READ, SYS_WRITE,
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
        assert!(
            driver_profile()
                .degraded_syscalls
                .is_allowed(SYS_IOCTL)
                .unwrap(),
            "driver: its whole purpose"
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
    use crate::syscall::{SYS_NET_RECV, SYS_NET_SEND, SYS_SPAWN};

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
    fn driver_has_ioctl_but_no_spawn_or_net() {
        let p = driver_profile();
        assert!(p.syscalls.is_allowed(SYS_IOCTL).unwrap());
        assert!(!p.syscalls.is_allowed(SYS_SPAWN).unwrap());
        assert!(!p.syscalls.is_allowed(SYS_NET_SEND).unwrap());
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

    #[test]
    fn service_holds_the_linux_like_syscalls_exclusively() {
        let s = service_profile();
        for allowed in [
            SYS_PIPE,
            SYS_DUP,
            SYS_KILL,
            SYS_CHROOT,
            SYS_MKDIR,
            SYS_UNLINK,
            SYS_LISTDIR,
        ] {
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
        ] {
            for denied in [
                SYS_PIPE,
                SYS_DUP,
                SYS_KILL,
                SYS_CHROOT,
                SYS_MKDIR,
                SYS_UNLINK,
                SYS_LISTDIR,
            ] {
                assert!(
                    !p.syscalls.is_allowed(denied).unwrap(),
                    "{} may not use {}",
                    p.name,
                    denied
                );
            }
        }
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
