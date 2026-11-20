//! End-to-end tests for the Linux-like extensions, all through the public
//! `Kernel` API (fast-path gate + executing syscall layer).
//!
//! Cast: a supervisor domain (uid 0, service profile) sets up the VFS tree;
//! unprivileged domains operate under Unix permissions and chroot.

use aegis_os::prelude::*;

const SUPERVISOR: u32 = 0;
const SERVICE: u32 = 1;
const PARSER: u32 = 2;

fn kernel_with_tree() -> Kernel {
    let mut k = Kernel::new();
    // Supervisor: uid 0 — may create anywhere (root bypasses DAC).
    k.create_domain_with(SUPERVISOR, service_profile(), 0, 0, 0).unwrap();
    // Unprivileged service domain: uid 1001.
    k.create_domain_with(SERVICE, service_profile(), 1001, 100, 0).unwrap();
    // Untrusted parser: no file syscalls at all.
    k.create_domain_with(PARSER, parser_profile(), 1002, 100, 0).unwrap();

    // Tree: /pub (world-writable scratch), /home + /home/notes.txt (root-owned).
    k.syscall(SUPERVISOR, SysRequest::Mkdir { path: "/pub", mode: Mode(0o777) }).unwrap();
    k.syscall(SUPERVISOR, SysRequest::Mkdir { path: "/home", mode: Mode(0o755) }).unwrap();
    k.syscall(
        SUPERVISOR,
        SysRequest::Open { path: "/home/notes.txt", mode: Mode(0o644), create: true , read: true, write: false, truncate: false },
    )
    .unwrap();
    let fd = match k.syscall(SUPERVISOR, SysRequest::Open { path: "/home/notes.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd) => fd,
        other => panic!("expected fd, got {:?}", other),
    };
    k.syscall(SUPERVISOR, SysRequest::Write { fd, bytes: b"root secret" }).unwrap();
    k.syscall(SUPERVISOR, SysRequest::Close { fd }).unwrap();
    k
}

#[test]
fn vfs_unix_permissions_end_to_end() {
    let mut k = kernel_with_tree();

    // The unprivileged service can read a 0o644 root-owned file (other: r)…
    let fd = match k.syscall(SERVICE, SysRequest::Open { path: "/home/notes.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    let mut buf = [0u8; 32];
    match k.syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf }).unwrap() {
        SysValue::Count(n) => assert_eq!(&buf[..n], b"root secret"),
        other => panic!("{:?}", other),
    }
    // …but cannot write it (other: no w)…
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Write { fd, bytes: b"hijack" }),
        Err(SysError::Vfs(VfsError::PermissionDenied))
    );
    // …and cannot create inside root-owned /home (no w on parent).
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Open { path: "/home/evil", mode: Mode(0o644), create: true , read: true, write: false, truncate: false }),
        Err(SysError::Vfs(VfsError::PermissionDenied))
    );
    // …while /pub (0o777) is writable for everyone. The file the service
    // creates is owned by the service itself (uid 1001), so it can write
    // it again later — ownership works end to end.
    match k.syscall(SERVICE, SysRequest::Open { path: "/pub/mine.txt", mode: Mode(0o644), create: true , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd2) => {
            k.syscall(SERVICE, SysRequest::Write { fd: fd2, bytes: b"service data" }).unwrap();
            k.syscall(SERVICE, SysRequest::Close { fd: fd2 }).unwrap();
        }
        other => panic!("{:?}", other),
    }
    let fd3 = match k.syscall(SERVICE, SysRequest::Open { path: "/pub/mine.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(SERVICE, SysRequest::Write { fd: fd3, bytes: b"owner overwrite" }).unwrap();
    k.syscall(SERVICE, SysRequest::Close { fd: fd3 }).unwrap();
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
}

#[test]
fn file_cursor_reads_short_then_eof() {
    let mut k = kernel_with_tree();
    let fd = match k.syscall(SERVICE, SysRequest::Open { path: "/pub/data.bin", mode: Mode(0o644), create: true , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(SERVICE, SysRequest::Write { fd, bytes: b"0123456789" }).unwrap();
    // F11(c): the writer's offset moved with the write — read back
    // through a fresh read-only descriptor.
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    let fd = match k
        .syscall(SERVICE, SysRequest::Open { path: "/pub/data.bin", mode: Mode(0o644), create: false, read: true, write: false, truncate: false })
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };

    let mut buf = [0u8; 4];
    match k.syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf }).unwrap() {
        SysValue::Count(n) => {
            assert_eq!(n, 4);
            assert_eq!(&buf, b"0123");
        }
        other => panic!("{:?}", other),
    }
    match k.syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf }).unwrap() {
        SysValue::Count(n) => {
            assert_eq!(n, 4);
            assert_eq!(&buf, b"4567");
        }
        other => panic!("{:?}", other),
    }
    let mut big = [0u8; 16];
    match k.syscall(SERVICE, SysRequest::Read { fd, buf: &mut big }).unwrap() {
        SysValue::Count(n) => {
            assert_eq!(n, 2, "short read at the tail");
            assert_eq!(&big[..2], b"89");
        }
        other => panic!("{:?}", other),
    }
    // EOF: 0.
    match k.syscall(SERVICE, SysRequest::Read { fd, buf: &mut big }).unwrap() {
        SysValue::Count(n) => assert_eq!(n, 0),
        other => panic!("{:?}", other),
    }
    // Bad fd after close.
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Read { fd, buf: &mut big }),
        Err(SysError::BadFd(fd))
    );
}

#[test]
fn parser_is_masked_out_of_all_linux_syscalls() {
    let mut k = kernel_with_tree();
    // The fast-path gate denies every file/process syscall for the parser.
    assert_eq!(
        k.syscall(PARSER, SysRequest::Open { path: "/home/notes.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }),
        Err(SysError::Masked(SYS_OPEN))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Mkdir { path: "/pub/x", mode: Mode(0o755) }),
        Err(SysError::Masked(SYS_MKDIR))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Unlink { path: "/home/notes.txt" }),
        Err(SysError::Masked(SYS_UNLINK))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Chroot { path: "/pub" }),
        Err(SysError::Masked(SYS_CHROOT))
    );
    assert_eq!(k.syscall(PARSER, SysRequest::Pipe), Err(SysError::Masked(SYS_PIPE)));
    assert_eq!(
        k.syscall(PARSER, SysRequest::Dup { fd: 0, new_fd: 3 }),
        Err(SysError::Masked(SYS_DUP))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Kill { target: SERVICE, sig: SIGKILL }),
        Err(SysError::Masked(SYS_KILL))
    );
    // …and the denied attempts feed the behavior monitor.
    assert_eq!(k.dispatch(PARSER, SYS_OPEN).unwrap(), Decision::DeniedByMask(SYS_OPEN));
}

#[test]
fn pipe_lifecycle_with_dup_semantics() {
    let mut k = kernel_with_tree();
    let (r, w) = match k.syscall(SERVICE, SysRequest::Pipe).unwrap() {
        SysValue::FdPair(r, w) => (r, w),
        other => panic!("{:?}", other),
    };
    // Write through the original descriptor.
    match k.syscall(SERVICE, SysRequest::Write { fd: w, bytes: b"hello pipe" }).unwrap() {
        SysValue::Count(n) => assert_eq!(n, 10),
        other => panic!("{:?}", other),
    }
    // dup2: install a second write end at fd 5.
    assert_eq!(k.syscall(SERVICE, SysRequest::Dup { fd: w, new_fd: 5 }), Ok(SysValue::Fd(5)));
    // Closing the original write end does NOT close the pipe (dup holds it).
    k.syscall(SERVICE, SysRequest::Close { fd: w }).unwrap();
    k.syscall(SERVICE, SysRequest::Write { fd: 5, bytes: b"!" }).unwrap();
    // Read everything in order.
    let mut buf = [0u8; 32];
    match k.syscall(SERVICE, SysRequest::Read { fd: r, buf: &mut buf }).unwrap() {
        SysValue::Count(n) => assert_eq!(&buf[..n], b"hello pipe!"),
        other => panic!("{:?}", other),
    }
    // Empty + writer open: WouldBlock.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Read { fd: r, buf: &mut buf }),
        Err(SysError::Pipe(PipeError::WouldBlock))
    );
    // Close the last write end: EOF.
    k.syscall(SERVICE, SysRequest::Close { fd: 5 }).unwrap();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Read { fd: r, buf: &mut buf }),
        Ok(SysValue::Count(0))
    );
    // Write end gone entirely: reading after EOF keeps returning 0.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Read { fd: r, buf: &mut buf }),
        Ok(SysValue::Count(0))
    );
    k.syscall(SERVICE, SysRequest::Close { fd: r }).unwrap();
    // Reading from a write end is EBADF-flavored.
    let (_, w2) = match k.syscall(SERVICE, SysRequest::Pipe).unwrap() {
        SysValue::FdPair(r, w) => (r, w),
        other => panic!("{:?}", other),
    };
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Read { fd: w2, buf: &mut buf }),
        Err(SysError::BadFd(w2))
    );
}

#[test]
fn chroot_confinement_through_syscalls() {
    let mut k = kernel_with_tree();
    // The service chroots itself into /pub (world-writable scratch).
    assert_eq!(k.syscall(SERVICE, SysRequest::Chroot { path: "/pub" }), Ok(SysValue::Unit));
    // Inside the chroot it can create and read its own files…
    let fd = match k.syscall(SERVICE, SysRequest::Open { path: "box.txt", mode: Mode(0o644), create: true , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(SERVICE, SysRequest::Write { fd, bytes: b"confined" }).unwrap();
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    // …but every escape attempt misses:
    //   absolute paths resolve from the chroot root,
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Open { path: "/home/notes.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }),
        Err(SysError::Vfs(VfsError::NotFound))
    );
    //   as do ..-climbs…
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Open { path: "../../../home/notes.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }),
        Err(SysError::Vfs(VfsError::NotFound))
    );
    //   …and unlinking outside is equally impossible.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Unlink { path: "../home/notes.txt" }),
        Err(SysError::Vfs(VfsError::NotFound))
    );
    // The supervisor (not chrooted) still sees the whole tree.
    assert!(k.syscall(SUPERVISOR, SysRequest::Open { path: "/home/notes.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }).is_ok());
    // The confined service can still chroot deeper (within its root).
    k.syscall(SUPERVISOR, SysRequest::Mkdir { path: "/pub/jail", mode: Mode(0o777) }).unwrap();
    assert_eq!(k.syscall(SERVICE, SysRequest::Chroot { path: "jail" }), Ok(SysValue::Unit));
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Open { path: "../box.txt", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }),
        Err(SysError::Vfs(VfsError::NotFound))
    );
}

#[test]
fn kill_permissions_and_fatal_signal_delivery() {
    let mut k = kernel_with_tree();
    // Same-uid kill is allowed; different uid is denied (Unix rules).
    let other_uid_domain = 3u32;
    k.create_domain_with(other_uid_domain, service_profile(), 4242, 100, 0).unwrap();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Kill { target: other_uid_domain, sig: SIGTERM }),
        Err(SysError::PermissionDenied)
    );
    // Killing yourself is always allowed.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Kill { target: SERVICE, sig: SIGUSR1 }),
        Ok(SysValue::Unit)
    );
    // Invalid signal numbers are rejected.
    assert_eq!(
        k.syscall(SUPERVISOR, SysRequest::Kill { target: SERVICE, sig: 0 }),
        Err(SysError::Signal(SignalError::InvalidSignal(0)))
    );
    // Supervisor (uid 0) SIGTERMs the parser: pending until delivered.
    assert_eq!(
        k.syscall(SUPERVISOR, SysRequest::Kill { target: PARSER, sig: SIGTERM }),
        Ok(SysValue::Unit)
    );
    assert_eq!(k.domain_state(PARSER), Some(DomainState::Running));
    // Delivery applies the default action: Terminate -> quarantine.
    assert_eq!(k.deliver_signals(PARSER).unwrap(), Some(SIGTERM));
    assert_eq!(k.domain_state(PARSER), Some(DomainState::Quarantined));
    // A quarantined domain cannot even attempt syscalls anymore.
    assert_eq!(
        k.syscall(PARSER, SysRequest::Open { path: "/pub/x", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }),
        Err(SysError::Quarantined(SYS_OPEN))
    );
    // SIGUSR1 (default: Ignore) does NOT terminate the target.
    assert_eq!(
        k.syscall(SUPERVISOR, SysRequest::Kill { target: SERVICE, sig: SIGUSR1 }),
        Ok(SysValue::Unit)
    );
    assert_eq!(k.deliver_signals(SERVICE).unwrap(), Some(SIGUSR1));
    assert_eq!(k.domain_state(SERVICE), Some(DomainState::Running));
    // Killing an unknown domain fails cleanly.
    assert_eq!(
        k.syscall(SUPERVISOR, SysRequest::Kill { target: 99, sig: SIGKILL }),
        Err(SysError::UnknownDomain(99))
    );
}

#[test]
fn cfs_scheduler_fairness_through_kernel() {
    let mut k = Kernel::new();
    k.create_domain_with(1, service_profile(), 1001, 100, 0).unwrap();
    k.create_domain_with(2, service_profile(), 1002, 100, 0).unwrap();
    k.create_domain_with(3, service_profile(), 1003, 100, 5).unwrap(); // low priority
    // Two equal domains alternate; the nice+5 domain gets fewer slices.
    let mut counts = [0u32; 4];
    // Scheduling settles into a 7-slice cycle [3,1,2,1,2,1,2]; after the
    // 2 warm-up slices, 56 more = 8 full cycles: nice-0 domains get
    // exactly 25 slices each, nice+5 gets 8.
    for _ in 0..58 {
        let id = k.sched.schedule_slice(4).expect("runnable domains exist");
        counts[id as usize] += 1;
    }
    assert_eq!(counts[1], counts[2], "equal nice must share equally: {:?}", counts);
    assert_eq!(counts[1], 25);
    assert_eq!(counts[3], 8, "nice +5 is charged more virtual time per slice");
    assert!(counts[1] > counts[3], "nice +5 must get fewer slices: {:?}", counts);
    // Sleeping a domain removes it from contention; waking restores it.
    k.sched.set_runnable(1, false).unwrap();
    for _ in 0..10 {
        let id = k.sched.schedule_slice(4).unwrap();
        assert!(id == 2 || id == 3);
    }
    k.sched.set_runnable(1, true).unwrap();
    // F12: the woken domain is placed at min_vruntime — it no longer
    // wins outright with its stale low vruntime, but it must get the
    // CPU again promptly (no starvation either).
    let mut picked_one = false;
    for _ in 0..8 {
        if k.sched.schedule_slice(4).unwrap() == 1 {
            picked_one = true;
            break;
        }
    }
    assert!(picked_one, "the woken domain must be scheduled again promptly");
    // Changing nice re-weights on the fly.
    k.set_nice_for(3, -10).unwrap();
    let e = k.sched.entity(3).unwrap();
    assert_eq!(e.nice, -10);
    assert_eq!(e.weight, aegis_os::sched::weight_for(-10));
}

#[test]
fn buddy_allocator_through_kernel() {
    let mut k = Kernel::new();
    // Fresh kernel owns its whole frame arena as one max block.
    assert_eq!(k.frames.frames_free(), 256);
    let a = k.frames.alloc(0).unwrap();
    let b = k.frames.alloc(2).unwrap();
    assert_ne!(a, b);
    assert_eq!(k.frames.frames_in_use(), 5);
    // Freeing in any order coalesces back to the full arena.
    k.frames.free(b).unwrap();
    k.frames.free(a).unwrap();
    assert_eq!(k.frames.frames_in_use(), 0);
    assert_eq!(k.frames.largest_free_order(), aegis_os::buddy::MAX_ORDER);
    // Double free still rejected through the kernel-owned allocator.
    assert_eq!(k.frames.free(a), Err(BuddyError::NotAllocated(a)));
}

#[test]
fn net_broker_send_is_rate_limited() {
    let mut k = kernel_with_tree();
    let netd = 3u32;
    k.create_domain_with(netd, netd_profile(), 50, 50, 0).unwrap();
    // Supervisor opens the broker socket for netd.
    assert_eq!(k.net_open(netd).unwrap(), 0);

    // Burst budget is 64 bytes: 60 passes…
    match k.syscall(netd, SysRequest::NetSend { len: 60 }).unwrap() {
        SysValue::Count(left) => assert_eq!(left, 4),
        other => panic!("{:?}", other),
    }
    // …then a 10-byte send is throttled with the exact deficit.
    assert_eq!(
        k.syscall(netd, SysRequest::NetSend { len: 10 }),
        Err(SysError::Net(NetError::RateLimited { requested: 10, available: 4 }))
    );
    // One window later (RATE_WINDOW_TICKS = 100) the bucket refills.
    k.set_clock(100);
    assert!(k.syscall(netd, SysRequest::NetSend { len: 50 }).is_ok());
    // Any other profile is masked out of NET_SEND entirely.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::NetSend { len: 1 }),
        Err(SysError::Masked(SYS_NET_SEND))
    );
}

#[test]
fn mkdir_unlink_roundtrip_and_nonempty_dir() {
    let mut k = kernel_with_tree();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Mkdir { path: "/pub/dir", mode: Mode(0o755) }),
        Ok(SysValue::Unit)
    );
    // Duplicate mkdir: EEXIST.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Mkdir { path: "/pub/dir", mode: Mode(0o755) }),
        Err(SysError::Vfs(VfsError::Exists))
    );
    // Non-empty dir cannot be unlinked…
    let fd = match k.syscall(SERVICE, SysRequest::Open { path: "/pub/dir/f", mode: Mode(0o644), create: true , read: true, write: false, truncate: false }).unwrap() {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Unlink { path: "/pub/dir" }),
        Err(SysError::Vfs(VfsError::NotEmpty))
    );
    // …empty the directory, then both file and dir removal work.
    assert_eq!(k.syscall(SERVICE, SysRequest::Unlink { path: "/pub/dir/f" }), Ok(SysValue::Unit));
    assert_eq!(k.syscall(SERVICE, SysRequest::Unlink { path: "/pub/dir" }), Ok(SysValue::Unit));
    // Gone for real.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Open { path: "/pub/dir", mode: Mode(0o644), create: false , read: true, write: false, truncate: false }),
        Err(SysError::Vfs(VfsError::NotFound))
    );
}
