//! ADR-0022 process-model tests, all through the public `Kernel` API.
//!
//! Cast: a supervisor (uid 0, service profile) builds the VFS tree;
//! init is PID 1; parents live at small supervisor-chosen ids;
//! spawn-allocated pids start at 100 and never repeat.

use aegis_os::prelude::*;
use aegis_os::proc::{ExitStatus, ProcError};
use aegis_os::syscall::{SYS_EXEC, SYS_FORK, SYS_WAIT};

const SUPERVISOR: u32 = 0;
const INIT: u32 = 1;
const PARENT: u32 = 2;

/// A tree with /pub (world-writable) + /pub/notes.txt, an init domain,
/// and a service parent (uid 1001) holding: fd 3 = the file positioned
/// at byte 4, fds 4/5 = a pipe (read/write).
fn kernel_with_parent() -> Kernel {
    let mut k = Kernel::new();
    k.create_domain_with(SUPERVISOR, service_profile(), 0, 0, 0)
        .unwrap();
    k.create_domain_with(INIT, service_profile(), 0, 0, 0)
        .unwrap();
    k.create_domain_with(PARENT, service_profile(), 1001, 100, 0)
        .unwrap();
    k.syscall(
        SUPERVISOR,
        SysRequest::Mkdir {
            path: "/pub",
            mode: Mode(0o777),
        },
    )
    .unwrap();
    // Reserve the stdio triplet so the parent's real fds start at 3.
    k.reserve_stdio(PARENT).unwrap();
    // Create + fill the file, then reopen it read-only and advance to
    // byte 4 so the position snapshot is observable.
    k.syscall(
        PARENT,
        SysRequest::Open {
            path: "/pub/notes.txt",
            mode: Mode(0o644),
            create: true,
            read: false,
            write: true,
            truncate: false,
            excl: false,
        },
    )
    .unwrap();
    match k
        .syscall(
            PARENT,
            SysRequest::Write {
                fd: 3,
                bytes: b"12345678",
            },
        )
        .unwrap()
    {
        SysValue::Count(8) => {}
        other => panic!("expected 8 bytes written, got {:?}", other),
    }
    match k.syscall(PARENT, SysRequest::Close { fd: 3 }).unwrap() {
        SysValue::Unit => {}
        other => panic!("expected close, got {:?}", other),
    }
    match k
        .syscall(
            PARENT,
            SysRequest::Open {
                path: "/pub/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false,
                excl: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(3) => {}
        other => panic!("expected fd 3 back, got {:?}", other),
    }
    match k
        .syscall(
            PARENT,
            SysRequest::Read {
                fd: 3,
                buf: &mut [0u8; 4],
            },
        )
        .unwrap()
    {
        SysValue::Count(4) => {}
        other => panic!("expected 4 bytes read, got {:?}", other),
    }
    match k.syscall(PARENT, SysRequest::Pipe).unwrap() {
        SysValue::FdPair(r, w) => assert_eq!((r, w), (4, 5)),
        other => panic!("expected a pipe, got {:?}", other),
    }
    k
}

/// ADR-0032: a legal CHILD request of a service parent — the app class
/// with a strictly smaller fan-out (the profile relation now requires
/// every spawn to attenuate on every axis; same-class max_children
/// would be refused).
fn child_app() -> aegis_os::profile::DomainProfile {
    let mut p = app_profile();
    p.max_children = 7;
    p
}

fn read_fd(k: &Kernel, pid: u32, fd: u8) -> Option<FdEntry> {
    k.domain(pid).and_then(|d| d.fds.get(fd))
}

#[test]
fn spawn_allocates_monotonic_pids_from_100() {
    let mut k = kernel_with_parent();
    let c1 = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let c2 = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let c3 = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    assert!(c1 >= 100, "spawn pids start at 100, got {c1}");
    assert_ne!(c1, c2);
    assert_ne!(c2, c3);
    assert_ne!(c1, c3);
    // Supervisor-chosen ids coexist untouched.
    assert!(k.domain(INIT).is_some());
    assert!(k.domain(PARENT).is_some());
}

#[test]
fn spawn_inherits_exactly_the_fd_map_and_nothing_else() {
    let mut k = kernel_with_parent();
    // Parent fds: 3 = file (pos 4), 4 = pipe read, 5 = pipe write.
    let child = k
        .spawn_process(PARENT, child_app(), &[(3, 0), (4, 7)])
        .unwrap();
    let ce = read_fd(&k, child, 0).expect("child fd 0 = the file");
    match ce.target {
        FdTarget::File(_) => {}
        other => panic!("fd 0 should be the file, got {other:?}"),
    }
    assert_eq!(ce.pos, 4, "the file position snapshots at spawn");
    assert!(read_fd(&k, child, 7).is_some(), "child fd 7 = pipe read");
    for absent in [1u8, 2, 3, 4, 5, 6] {
        assert!(
            read_fd(&k, child, absent).is_none(),
            "fd {absent} must NOT exist: no ambient inheritance"
        );
    }
    // The pipe's read end gained exactly one reference.
    if let FdTarget::PipeRead(id) = read_fd(&k, child, 7).unwrap().target {
        assert_eq!(k.channel_refs(id).map(|(r, _)| r), Some(2));
    } else {
        panic!("fd 7 should be a pipe read end");
    }
}

#[test]
fn spawn_refuses_a_fd_map_referencing_a_closed_fd() {
    let mut k = kernel_with_parent();
    let before_domains = k.live_domain_count();
    let err = k.spawn_process(PARENT, child_app(), &[(9, 0)]).unwrap_err();
    assert_eq!(err, ProcError::FdNotOpen(9));
    assert_eq!(k.live_domain_count(), before_domains, "no child leaked");
}

#[test]
fn spawn_refuses_out_of_range_and_duplicate_child_fds() {
    let mut k = kernel_with_parent();
    // K20 (P0-1): the out-of-range child fd is the constant, not a
    // literal (MAX_FDS rose 16 -> 32 and fd 16 became legal).
    let e1 = k
        .spawn_process(PARENT, child_app(), &[(3, aegis_os::fd::MAX_FDS as u8)])
        .unwrap_err();
    assert_eq!(
        e1,
        ProcError::FdMapInvalid {
            fd: aegis_os::fd::MAX_FDS as u8
        }
    );
    let e2 = k
        .spawn_process(PARENT, child_app(), &[(3, 0), (4, 0)])
        .unwrap_err();
    assert_eq!(e2, ProcError::FdMapInvalid { fd: 0 });
}

#[test]
fn spawn_refuses_a_profile_wider_than_the_parents_live_mask() {
    let mut k = kernel_with_parent();
    // The parser surface is NOT a subset of the live (post-tighten)
    // service mask once the parent has been narrowed below it.
    let mut narrow = service_profile();
    narrow.syscalls = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_WRITE);
    // service parent, narrowed by exec to read+write only:
    k.exec_replace(PARENT, &narrow.syscalls, None).unwrap();
    let err = k.spawn_process(PARENT, service_profile(), &[]).unwrap_err();
    assert_eq!(err, ProcError::ProfileEscalation);
    // The refusal fed the parent's escalation counter.
    let stats = k.domain(PARENT).map(|d| d.stats).unwrap();
    assert!(stats.escalation_attempts >= 1);
}

#[test]
fn spawn_refuses_quota_above_the_parents() {
    let mut k = kernel_with_parent();
    let mut greedy = app_profile();
    greedy.quota_pages = service_profile().quota_pages + 1;
    let err = k.spawn_process(PARENT, greedy, &[]).unwrap_err();
    assert_eq!(err, ProcError::ProfileEscalation);
}

#[test]
fn spawned_children_get_no_ambient_capabilities_only_attenuated_copies() {
    let mut k = kernel_with_parent();
    // Jail the parent: its root capability attenuates to /pub.
    k.syscall(PARENT, SysRequest::Chroot { path: "/pub" })
        .unwrap();
    let child = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let parent_caps = k.domain(PARENT).map(|d| d.caps.clone()).unwrap();
    let child_caps = k.domain(child).map(|d| d.caps.clone()).unwrap();
    assert!(!child_caps.is_empty());
    for c in child_caps.iter() {
        // The self-signal cap is STRUCTURAL (like SYS_EXIT — every
        // process holds its own); everything else needs a cover.
        if matches!(c.resource, Resource::Domain(d) if d == child) {
            continue;
        }
        let covered = parent_caps
            .iter()
            .any(|p| same_resource(p.resource, c.resource) && c.rights.is_subset_of(p.rights));
        assert!(
            covered,
            "child cap {c:?} has no covering capability in the parent"
        );
    }
    // And the self-cap: the child may signal itself, nothing else new.
    assert!(child_caps
        .iter()
        .any(|c| matches!(c.resource, Resource::Domain(d) if d == child)));
    // The child did NOT receive a capability aimed at the parent.
    assert!(!child_caps
        .iter()
        .any(|c| matches!(c.resource, Resource::Domain(d) if d == PARENT)));
}

fn same_resource(a: Resource, b: Resource) -> bool {
    match (a, b) {
        (Resource::FsNode(x), Resource::FsNode(y)) => x == y,
        (Resource::Device(x), Resource::Device(y)) => x == y,
        (Resource::Domain(x), Resource::Domain(y)) => x == y,
        (Resource::Endpoint(x), Resource::Endpoint(y)) => x == y,
        _ => false,
    }
}

#[test]
fn fork_copies_mask_fds_positions_cloexec_and_caps() {
    let mut k = kernel_with_parent();
    k.set_cloexec(PARENT, 3, true).unwrap();
    let child = k.fork_process(PARENT).unwrap();
    // Mask: a copy of the live mask.
    assert_eq!(
        k.domain(child).unwrap().mask().bits(),
        k.domain(PARENT).unwrap().mask().bits()
    );
    // Fds: same numbers, same targets, same positions, same flag.
    for fd in [3u8, 4, 5] {
        let p = read_fd(&k, PARENT, fd).unwrap();
        let c = read_fd(&k, child, fd).expect("fork keeps fd numbers");
        assert_eq!(c.pos, p.pos, "fd {fd} position");
        assert!(same_fd_target(c.target, p.target), "fd {fd} target");
    }
    assert!(read_fd(&k, child, 3).unwrap().cloexec, "cloexec rides fork");
    // Pipe ends gained a reference each.
    if let FdTarget::PipeRead(id) = read_fd(&k, child, 4).unwrap().target {
        assert_eq!(k.channel_refs(id).map(|(r, _)| r), Some(2));
    }
    if let FdTarget::PipeWrite(id) = read_fd(&k, child, 5).unwrap().target {
        assert_eq!(k.channel_refs(id).map(|(_, w)| w), Some(2));
    }
    // Credentials and jail copy.
    let (pu, pg) = (k.domain(PARENT).unwrap().uid, k.domain(PARENT).unwrap().gid);
    let (cu, cg) = (k.domain(child).unwrap().uid, k.domain(child).unwrap().gid);
    assert_eq!((pu, pg), (cu, cg));
    assert!(k.domain(child).unwrap().caps.len() <= k.domain(PARENT).unwrap().caps.len() + 1);
    // The child holds its own self-cap, not the parent's.
    let caps = k.domain(child).map(|d| d.caps.clone()).unwrap();
    assert!(caps
        .iter()
        .any(|c| matches!(c.resource, Resource::Domain(d) if d == child)));
    assert!(!caps
        .iter()
        .any(|c| matches!(c.resource, Resource::Domain(d) if d == PARENT)));
}

fn same_fd_target(a: FdTarget, b: FdTarget) -> bool {
    match (a, b) {
        (FdTarget::File(x), FdTarget::File(y)) => x == y,
        (FdTarget::PipeRead(x), FdTarget::PipeRead(y)) => x == y,
        (FdTarget::PipeWrite(x), FdTarget::PipeWrite(y)) => x == y,
        (FdTarget::Reserved, FdTarget::Reserved) => true,
        _ => false,
    }
}

#[test]
fn fork_of_a_narrowed_parent_is_born_narrowed() {
    let mut k = kernel_with_parent();
    let narrow = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_EXIT);
    k.exec_replace(PARENT, &narrow, None).unwrap();
    let child = k.fork_process(PARENT).unwrap();
    assert_eq!(
        k.domain(child).unwrap().mask().bits(),
        narrow.attenuate(&narrow).bits() | (1u64 << SYS_EXIT),
        "the child is born inside the parent's narrowed surface"
    );
}

#[test]
fn exec_intersects_never_widens_and_keeps_exit() {
    let mut k = kernel_with_parent();
    let child = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let live = k.domain(child).unwrap().mask();
    // A declared surface WIDER than live: intersection stays live.
    let wide = SyscallMask::from_bits(u64::MAX);
    k.exec_replace(child, &wide, None).unwrap();
    assert_eq!(k.domain(child).unwrap().mask().bits(), live.bits());
    // A declared surface NARROWER: narrows.
    let tiny = SyscallMask::from_bits(1u64 << SYS_READ);
    k.exec_replace(child, &tiny, None).unwrap();
    let got = k.domain(child).unwrap().mask().bits();
    assert_eq!(
        got,
        1u64 << SYS_READ | 1u64 << SYS_EXIT,
        "exit is unalienable"
    );
}

#[test]
fn exec_closes_cloexec_fds_and_keeps_the_rest() {
    let mut k = kernel_with_parent();
    k.set_cloexec(PARENT, 4, true).unwrap();
    let child = k.fork_process(PARENT).unwrap();
    if let FdTarget::PipeRead(id) = read_fd(&k, PARENT, 4).unwrap().target {
        assert_eq!(k.channel_refs(id).map(|(r, _)| r), Some(2));
        k.exec_replace(child, &app_profile().syscalls, Some(false))
            .unwrap();
        assert!(read_fd(&k, child, 4).is_none(), "cloexec fd closed");
        assert_eq!(
            k.channel_refs(id).map(|(r, _)| r),
            Some(1),
            "the reference went home"
        );
        assert!(read_fd(&k, child, 3).is_some(), "unflagged fds survive");
    } else {
        panic!("fd 4 should be a pipe read end");
    }
}

#[test]
fn exec_resets_regions_but_keeps_the_quota() {
    let mut k = kernel_with_parent();
    let quota = k.domain(PARENT).unwrap().space.quota_pages();
    // The service surface has no MMAP; the app surface does — exec
    // into app first, then map, then exec again and watch the ledger
    // reset.
    k.exec_replace(PARENT, &app_profile().syscalls, None)
        .unwrap();
    k.syscall(
        PARENT,
        SysRequest::Mmap {
            addr: 0x0100_0000,
            len: 2 * PAGE_SIZE,
            flags: MemFlags::READ | MemFlags::WRITE,
        },
    )
    .unwrap();
    assert_eq!(k.domain(PARENT).unwrap().space.region_count(), 1);
    k.exec_replace(PARENT, &app_profile().syscalls, None)
        .unwrap();
    let space = &k.domain(PARENT).unwrap().space;
    assert_eq!(space.region_count(), 0, "the image is replaced");
    assert_eq!(space.used_pages(), 0);
    assert_eq!(space.quota_pages(), quota, "the quota survives exec");
}

#[test]
fn exit_records_the_status_and_makes_a_zombie() {
    let mut k = kernel_with_parent();
    let child = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let status = ExitStatus::killed(9);
    k.exit_process(child, status).unwrap();
    // The domain is gone: further syscalls fail closed.
    assert!(k.domain(child).is_none());
    // The meta stays as a zombie.
    let meta = k.proc_meta(child).expect("zombie meta");
    assert_eq!(meta.exit, Some(status));
    assert_eq!(meta.parent, PARENT);
}

#[test]
fn wait_reaps_specific_any_and_nohang_children() {
    let mut k = kernel_with_parent();
    let c = [
        k.spawn_process(PARENT, child_app(), &[]).unwrap(),
        k.spawn_process(PARENT, child_app(), &[]).unwrap(),
        k.spawn_process(PARENT, child_app(), &[]).unwrap(),
    ];
    // Nothing has exited: nohang refuses, a blocking wait would too.
    assert_eq!(
        k.wait_process(PARENT, -1, true).unwrap_err(),
        ProcError::WouldBlock
    );
    k.exit_process(c[0], ExitStatus::normal(7)).unwrap();
    // nohang now reaps.
    let (pid, st) = k.wait_process(PARENT, -1, true).unwrap();
    assert_eq!(pid, c[0]);
    assert_eq!(st, ExitStatus::normal(7));
    assert!(k.proc_meta(c[0]).is_none(), "reaped metas are freed");
    k.exit_process(c[1], ExitStatus::normal(11)).unwrap();
    k.exit_process(c[2], ExitStatus::normal(13)).unwrap();
    // Specific waits.
    let (p2, s2) = k.wait_process(PARENT, c[2] as i64, false).unwrap();
    assert_eq!((p2, s2), (c[2], ExitStatus::normal(13)));
    let (p1, s1) = k.wait_process(PARENT, c[1] as i64, false).unwrap();
    assert_eq!((p1, s1), (c[1], ExitStatus::normal(11)));
    // All reaped: ECHILD, for any and specific alike.
    assert_eq!(
        k.wait_process(PARENT, -1, true).unwrap_err(),
        ProcError::NoChildren
    );
    assert_eq!(
        k.wait_process(PARENT, c[0] as i64, true).unwrap_err(),
        ProcError::NoChildren
    );
}

#[test]
fn wait_on_a_non_child_is_refused() {
    let mut k = kernel_with_parent();
    // PARENT must hold a child of its own so the refusal is about
    // WHOSE child the stranger is, not about having none.
    let _own = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let stranger = k.spawn_process(INIT, child_app(), &[]).unwrap();
    assert_eq!(
        k.wait_process(PARENT, stranger as i64, true).unwrap_err(),
        ProcError::NotAChild(stranger)
    );
    // A stranger's pid that does not exist at all is also NotAChild.
    assert_eq!(
        k.wait_process(PARENT, 4242, true).unwrap_err(),
        ProcError::NotAChild(4242)
    );
}

#[test]
fn orphans_reparent_to_init_and_init_drains_their_zombies() {
    let mut k = kernel_with_parent();
    let grandparent_spawns = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let orphan_baby = k.fork_process(grandparent_spawns).unwrap();
    // The middle generation dies: the baby and its zombie siblings go to init.
    k.exit_process(grandparent_spawns, ExitStatus::normal(1))
        .unwrap();
    let m = k.proc_meta(orphan_baby).unwrap();
    assert_eq!(m.parent, INIT, "orphans reparent to PID 1");
    k.exit_process(orphan_baby, ExitStatus::normal(2)).unwrap();
    let (pid, st) = k.wait_process(INIT, -1, true).unwrap();
    assert_eq!(pid, orphan_baby);
    assert_eq!(st, ExitStatus::normal(2));
    // The middle generation is still a zombie under the living PARENT
    // — init has no children at all right now (ECHILD).
    assert_eq!(
        k.wait_process(INIT, grandparent_spawns as i64, true)
            .unwrap_err(),
        ProcError::NoChildren
    );
    // PARENT dies: its own zombie is adopted by init (reaper of last
    // resort) and the middle generation's zombie reparents with it.
    k.exit_process(PARENT, ExitStatus::normal(0)).unwrap();
    let mut reaped = Vec::new();
    while let Ok((pid, _)) = k.wait_process(INIT, -1, true) {
        reaped.push(pid);
    }
    assert!(reaped.contains(&grandparent_spawns));
    assert!(reaped.contains(&PARENT));
}

#[test]
fn orphans_without_a_living_init_are_auto_reaped() {
    let mut k = kernel_with_parent();
    k.exit_process(INIT, ExitStatus::normal(0)).unwrap();
    let parent = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    let baby = k.fork_process(parent).unwrap();
    k.exit_process(parent, ExitStatus::normal(1)).unwrap();
    // No init to adopt: the orphan keeps running under a dead parent.
    assert!(k.proc_meta(baby).is_some());
    k.exit_process(baby, ExitStatus::normal(2)).unwrap();
    assert!(
        k.proc_meta(baby).is_none(),
        "with no reaper alive the exit status is discarded, not leaked"
    );
}

#[test]
fn a_dying_parents_zombies_reparent_to_init() {
    let mut k = kernel_with_parent();
    let child = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    k.exit_process(child, ExitStatus::normal(5)).unwrap();
    k.exit_process(PARENT, ExitStatus::normal(0)).unwrap();
    // init reaps both, zombie first or any order — both must be reachable.
    let mut reaped = Vec::new();
    for _ in 0..2 {
        let (pid, _) = k.wait_process(INIT, -1, true).unwrap();
        reaped.push(pid);
    }
    assert!(reaped.contains(&child));
    assert!(reaped.contains(&PARENT));
}

#[test]
fn children_limit_binds_spawn_and_fork() {
    let mut k = kernel_with_parent();
    let mut fertile = service_profile();
    fertile.syscalls =
        SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT);
    fertile.max_children = 2;
    // ADR-0032: the Tighten tier must be a proper subset keeping exit.
    fertile.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    let parent = k.spawn_process(PARENT, fertile, &[]).unwrap();
    let a = k.fork_process(parent).unwrap();
    let _b = k.fork_process(parent).unwrap();
    assert_eq!(
        k.fork_process(parent).unwrap_err(),
        ProcError::TooManyChildren { limit: 2 }
    );
    // ADR-0032: the over-limit request must ALSO be a legal attenuation
    // (fan-out strictly below the parent's 2), or the profile check
    // would refuse it before the children-count check runs.
    let mut grandchild = fertile;
    grandchild.max_children = 1;
    assert_eq!(
        k.spawn_process(parent, grandchild, &[]).unwrap_err(),
        ProcError::TooManyChildren { limit: 2 }
    );
    // Exiting alone does NOT free the budget: the zombie still holds
    // its parent's child slot (un-reaped, it occupies the meta table).
    k.exit_process(a, ExitStatus::normal(0)).unwrap();
    assert!(k.fork_process(parent).is_err());
    // Reaping it does.
    let _ = k.wait_process(parent, a as i64, true).unwrap();
    assert!(k.fork_process(parent).is_ok());
}

#[test]
fn meta_table_full_refuses_children_until_reaped() {
    let mut k = Kernel::new();
    // ADR-0032: bootstrap a BIG supervisor (create_domain_with makes no
    // attenuation check — it is the root), then request a legal chain:
    // supervisor -> parent -> kids. K20 (P0-1): every bound below is
    // derived from MAX_DOMAINS (64), not a literal — the profile
    // ceilings are the story, the table is the edge.
    const DOMS: u16 = aegis_os::MAX_DOMAINS as u16;
    let mut big = service_profile();
    big.max_children = DOMS;
    k.create_domain_with(SUPERVISOR, big, 0, 0, 0).unwrap();
    let mut many = service_profile();
    // max_children attenuates strictly down the chain (the
    // ProfileEscalation gate): supervisor DOMS -> parent DOMS-1 ->
    // kids DOMS-2, which exactly fills the table.
    many.max_children = DOMS - 1;
    many.syscalls = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT);
    many.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    let parent = k.spawn_process(SUPERVISOR, many, &[]).unwrap();
    let mut kid = many;
    kid.max_children = DOMS - 2;
    // Fill every remaining meta slot with children (supervisor +
    // parent + DOMS-2 kids = MAX_DOMAINS).
    let mut kids = Vec::new();
    while let Ok(pid) = k.spawn_process(parent, kid, &[]) {
        kids.push(pid);
    }
    assert_eq!(
        kids.len(),
        (aegis_os::MAX_DOMAINS - 2),
        "MAX_DOMAINS = {}: supervisor + parent + kids",
        aegis_os::MAX_DOMAINS
    );
    assert_eq!(
        k.spawn_process(parent, kid, &[]).unwrap_err(),
        ProcError::TooManyProcesses
    );
    // Kill them all: zombies still hold their meta slots.
    for pid in &kids {
        k.exit_process(*pid, ExitStatus::normal(0)).unwrap();
    }
    assert_eq!(
        k.spawn_process(parent, kid, &[]).unwrap_err(),
        ProcError::TooManyProcesses,
        "zombies still hold meta slots"
    );
    // Reap them all: the table is usable again.
    for _ in 0..kids.len() {
        let (pid, _) = k.wait_process(parent, -1, true).unwrap();
        assert!(kids.contains(&pid));
    }
    assert!(k.spawn_process(parent, kid, &[]).is_ok());
}

#[test]
fn capacity_selftest_fill_refuse_drain_reuse() {
    let mut k = Kernel::new();
    // K20 (P0-1): the fill bound is the constant (MAX_DOMAINS), not a
    // literal — this is the fill/refuse/drain/reuse proof the
    // MAX_DOMAINS doc comment promises, at whatever the limit is.
    let n = aegis_os::MAX_DOMAINS as u32;
    for id in 1..=n {
        k.create_domain(id, parser_profile()).unwrap();
    }
    assert_eq!(
        k.create_domain(n + 1, parser_profile()).unwrap_err(),
        KernelError::TooManyDomains
    );
    for id in 1..=n {
        k.destroy_domain(id).unwrap();
    }
    k.create_domain(1, parser_profile()).unwrap();
}

#[test]
fn exec_policy_table_declare_lookup_default() {
    let mut k = Kernel::new();
    let sh_mask = SyscallMask::from_bits(
        1u64 << SYS_READ
            | 1u64 << SYS_FORK
            | 1u64 << SYS_EXEC
            | 1u64 << SYS_WAIT
            | 1u64 << SYS_EXIT,
    );
    // ADR-0032 §B: the table is keyed by IMAGE IDENTITY, never by a
    // path string.
    let sh_id = aegis_os::proc::image_id(b"the shell image bytes");
    k.exec_policy_declare(sh_id, &sh_mask, Some(true)).unwrap();
    let got = k.exec_policy_declared_for(sh_id).unwrap();
    assert_eq!(got.0.bits(), sh_mask.bits());
    assert_eq!(got.1, Some(true));
    // Unlisted: no entry — the caller arm inherits the caller's
    // monitor mode and the app-default surface (the exec ratchet makes
    // that inheritance never a downgrade).
    assert_eq!(
        k.exec_policy_declared_for(aegis_os::proc::image_id(b"other bytes")),
        None
    );
}

#[test]
fn exec_sets_the_monitor_mode_from_the_policy() {
    let mut k = kernel_with_parent();
    let child = k.spawn_process(PARENT, child_app(), &[]).unwrap();
    assert_eq!(k.domain(child).unwrap().monitor_enforce, None);
    k.exec_replace(child, &app_profile().syscalls, Some(false))
        .unwrap();
    assert_eq!(k.domain(child).unwrap().monitor_enforce, Some(false));
    k.exec_replace(child, &app_profile().syscalls, Some(true))
        .unwrap();
    assert_eq!(k.domain(child).unwrap().monitor_enforce, Some(true));
}

#[test]
fn a_tightened_parent_spawns_tightened_children() {
    let mut k = kernel_with_parent();
    // Narrow the parent below the app surface, then try to spawn an
    // app child (app's mask includes OPEN, the parent no longer has).
    let narrow = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_EXIT);
    k.exec_replace(PARENT, &narrow, None).unwrap();
    assert_eq!(
        k.spawn_process(PARENT, child_app(), &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
    // A request INSIDE the narrowed surface is fine and is born narrowed.
    let mut tiny = app_profile();
    tiny.syscalls = narrow;
    // ADR-0032: strictly narrower than the surface, keeping exit, and
    // fan-out strictly below the (service) parent's 8.
    tiny.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    tiny.max_children = 7;
    let child = k.spawn_process(PARENT, tiny, &[]).unwrap();
    assert_eq!(
        k.domain(child).unwrap().mask().bits(),
        1u64 << SYS_READ | 1u64 << SYS_EXIT
    );
}

// ── property: attenuation over random trees ────────────────────────────

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn random_trees_never_escalate_authority() {
    let mut k = kernel_with_parent();
    let mut rng = Rng(0xC0FFEE);
    let mut live: Vec<u32> = vec![PARENT, INIT];

    // Derivation-time check: at the moment a child is born it must be
    // a subset of its parent — mask, quota, and every non-structural
    // cap. (The self-signal cap is structural; parent-minted Domain
    // caps are checked here against the DIRECT parent only.)
    let assert_child_subset = |k: &Kernel, child: u32, parent: u32| {
        let (c, p) = (k.domain(child).unwrap(), k.domain(parent).unwrap());
        assert!(
            c.mask().is_subset_of(&p.mask()),
            "newborn {child} escaped parent {parent}'s live mask"
        );
        assert!(
            c.space.quota_pages() <= p.space.quota_pages(),
            "newborn {child} out-quota'd parent {parent}"
        );
        for cap in c.caps.iter() {
            if matches!(cap.resource, Resource::Domain(d) if d == child) {
                continue; // structural self-cap
            }
            let covered = p.caps.iter().any(|pc| {
                same_resource(pc.resource, cap.resource) && cap.rights.is_subset_of(pc.rights)
            });
            assert!(
                covered,
                "newborn {child} holds cap {cap:?} beyond parent {parent}"
            );
        }
    };

    for _ in 0..200 {
        let &actor = &live[rng.below(live.len() as u64) as usize];
        let cur_mask = k.domain(actor).unwrap().mask();
        let cur_quota = k.domain(actor).unwrap().space.quota_pages();
        match rng.below(3) {
            0 => {
                // spawn: a random attenuation of the live surface.
                let mut req = app_profile();
                let mut bits = cur_mask.bits();
                // drop a random subset of bits, keep EXIT.
                bits &= !(rng.next() & bits & !(1u64 << SYS_EXIT));
                req.syscalls = SyscallMask::from_bits(bits);
                // ADR-0032: the Tighten tier is a proper subset keeping
                // exit; fan-out decays strictly down the tree.
                req.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
                let parent_fanout = k.domain(actor).unwrap().profile.max_children;
                req.max_children = parent_fanout.saturating_sub(1).max(1);
                req.quota_pages = rng.below(cur_quota as u64 + 1) as usize;
                if let Ok(pid) = k.spawn_process(actor, req, &[]) {
                    assert_child_subset(&k, pid, actor);
                    live.push(pid);
                }
            }
            1 => {
                if let Ok(pid) = k.fork_process(actor) {
                    assert_child_subset(&k, pid, actor);
                    live.push(pid);
                }
            }
            _ => {
                // exec: a random sub-mask of the live one.
                let mut bits = cur_mask.bits();
                bits &= !(rng.next() & bits & !(1u64 << SYS_EXIT));
                let _ = k.exec_replace(actor, &SyscallMask::from_bits(bits), None);
            }
        }
    }

    // Invariant: every live process's mask/quota ⊆ every ancestor's.
    for &pid in &live {
        if k.domain(pid).is_none() {
            continue;
        }
        let mut cur = pid;
        let mut hops = 0;
        while let Some(meta) = k.proc_meta(cur) {
            let ancestor = meta.parent;
            if ancestor == 0 || ancestor == cur || hops > 40 {
                break;
            }
            if let (Some(c), Some(a)) = (k.domain(pid), k.domain(ancestor)) {
                // The ancestor's BIRTH CEILING (its profile mask): the
                // ancestor may narrow afterwards without retroactively
                // shrinking its children — what must never happen is a
                // descendant exceeding any ancestor's ceiling.
                assert!(
                    k.domain(pid)
                        .unwrap()
                        .mask()
                        .is_subset_of(&a.profile.syscalls),
                    "pid {pid} escaped the mask ceiling of ancestor {ancestor}"
                );
                assert!(
                    c.space.quota_pages() <= a.space.quota_pages(),
                    "pid {pid} out-quota'd ancestor {ancestor}"
                );
                for cap in c.caps.iter() {
                    // Domain caps are signal plumbing scoped to the
                    // direct parent (checked at derivation time above):
                    // the self-cap is structural, and a parent-minted
                    // Domain(child) cap is legitimately absent from
                    // grandparents. RESOURCE authority (FsNode, Device,
                    // Endpoint) must attenuate down the whole tree.
                    if matches!(cap.resource, Resource::Domain(_)) {
                        continue;
                    }
                    let covered = a.caps.iter().any(|p| {
                        same_resource(p.resource, cap.resource) && cap.rights.is_subset_of(p.rights)
                    });
                    assert!(covered, "pid {pid} holds a cap beyond ancestor {ancestor}");
                }
            }
            cur = ancestor;
            hops += 1;
        }
    }
}

// ── lifecycle fuzz: no panic, conservation after teardown ─────────────

#[test]
fn random_lifecycles_conserve_everything_after_teardown() {
    let mut k = kernel_with_parent();
    let mut rng = Rng(0xBADF00D);
    let mut live: Vec<u32> = vec![PARENT];

    for _ in 0..400 {
        let op = rng.below(6);
        if live.is_empty() {
            break;
        }
        let idx = rng.below(live.len() as u64) as usize;
        let actor = live[idx];
        match op {
            0 | 1 => {
                let mut req = app_profile();
                let bits = k.domain(actor).unwrap().mask().bits();
                req.syscalls = SyscallMask::from_bits(bits);
                req.degraded_syscalls = SyscallMask::from_bits(bits);
                req.quota_pages = 8;
                if let Ok(pid) = k.spawn_process(actor, req, &[]) {
                    live.push(pid);
                }
            }
            2 => {
                if let Ok(pid) = k.fork_process(actor) {
                    live.push(pid);
                }
            }
            3 => {
                let bits = k.domain(actor).unwrap().mask().bits();
                let _ = k.exec_replace(actor, &SyscallMask::from_bits(bits), None);
            }
            4 => {
                k.exit_process(actor, ExitStatus::normal(rng.below(256) as u32))
                    .unwrap();
                live.swap_remove(idx);
            }
            _ => {
                let _ = k.wait_process(actor, -1, true);
            }
        }
    }

    // Full teardown: exit everyone but init, drain through init, then
    // exit init itself (its un-reaped zombies auto-reap with it).
    for pid in live {
        let _ = k.exit_process(pid, ExitStatus::normal(0));
    }
    while k.wait_process(INIT, -1, true).is_ok() {}
    let _ = k.exit_process(INIT, ExitStatus::normal(0));
    let _ = k.exit_process(SUPERVISOR, ExitStatus::normal(0));

    assert_eq!(k.live_domain_count(), 0, "every domain slot returned home");
    assert_eq!(k.proc_meta_count(), 0, "every meta slot returned home");
    assert_eq!(k.live_endpoint_count(), 0, "every pipe reclaimed");
    assert!(
        k.sched.entity(PARENT).is_none(),
        "scheduler empty for PARENT"
    );
}

// ── ADR-0032 section A: attenuation is checked on EVERY axis ────────
// Red first: against the current spawn (which validates only mask and
// quota), each single-axis weakening below must be REFUSED, and the
// round-A reproduction (sensitivity=0 + degraded=syscalls +
// max_children=1000 under a max_children=2 parent) must be refused
// with an escalation attempt recorded on the parent.

/// The controlled parent for the axis tests: a legal child of PARENT
/// with a narrow, fully-specified profile.
fn axis_parent_profile() -> aegis_os::profile::DomainProfile {
    let mut p = service_profile();
    p.syscalls = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT);
    p.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    p.quota_pages = 100;
    p.max_children = 4;
    p.sensitivity = 40;
    p.base_rights = aegis_os::capability::Rights::READ.union(aegis_os::capability::Rights::WRITE);
    p
}

#[test]
fn spawn_refuses_the_reproduced_weakening_request() {
    let mut k = kernel_with_parent();
    let mut req = axis_parent_profile();
    req.max_children = 2;
    let parent = k.spawn_process(PARENT, req, &[]).unwrap();
    // The round-A reproduction verbatim: sensitivity=0 (a nearly blind
    // monitor), degraded=syscalls (Tighten becomes a no-op), and
    // max_children=1000 (a 500x fan-out) under a max_children=2 parent.
    let mut bad = axis_parent_profile();
    bad.syscalls = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_EXIT);
    bad.degraded_syscalls = bad.syscalls;
    bad.sensitivity = 0;
    bad.max_children = 1000;
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
    // The refused request is an escalation attempt on the PARENT.
    let before = k.domain(parent).unwrap().stats.escalation_attempts;
    assert!(
        before >= 1,
        "the refused request must be recorded on the parent"
    );
}

#[test]
fn spawn_refuses_a_wider_mask_than_the_parents_live_one() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    // OPEN is not in the parent's live surface.
    bad.syscalls = SyscallMask::from_bits(
        1u64 << SYS_READ | 1u64 << SYS_WRITE | 1u64 << SYS_EXIT | 1u64 << SYS_OPEN,
    );
    bad.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_refuses_a_quota_above_the_parents_live_one() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    bad.quota_pages = 101; // the parent's live quota is 100
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_refuses_a_sensitivity_below_the_parents() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    bad.sensitivity = 39; // the parent's is 40: the child would be watched less closely
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_refuses_a_degraded_tier_equal_to_the_surface() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    bad.degraded_syscalls = bad.syscalls; // Tighten becomes a no-op
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_refuses_a_degraded_tier_that_drops_exit() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    // A proper subset of the surface — but without the exit call, a
    // tightened domain could never leave.
    bad.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_READ);
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_refuses_a_fan_out_equal_to_the_parents() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    bad.max_children = 4; // == the parent's: fan-out must strictly decay
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_refuses_broader_base_rights() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    let mut bad = axis_parent_profile();
    bad.base_rights = aegis_os::capability::Rights::READ
        .union(aegis_os::capability::Rights::WRITE)
        .union(aegis_os::capability::Rights::GRANT); // GRANT is not the parent's
    assert_eq!(
        k.spawn_process(parent, bad, &[]).unwrap_err(),
        ProcError::ProfileEscalation
    );
}

#[test]
fn spawn_accepts_a_strictly_attenuated_request() {
    let mut k = kernel_with_parent();
    let parent = k.spawn_process(PARENT, axis_parent_profile(), &[]).unwrap();
    // Everything strictly inside: mask subset, quota below, sensitivity
    // at or above, degraded a proper subset keeping exit, fan-out
    // strictly below, rights a subset.
    let mut good = axis_parent_profile();
    good.syscalls = SyscallMask::from_bits(1u64 << SYS_READ | 1u64 << SYS_EXIT);
    good.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    good.quota_pages = 50;
    good.sensitivity = 60;
    good.max_children = 3;
    good.base_rights = aegis_os::capability::Rights::READ;
    let child = k.spawn_process(parent, good, &[]).unwrap();
    assert!(k.domain(child).unwrap().mask().bits() == (1u64 << SYS_READ) | (1u64 << SYS_EXIT));
}
