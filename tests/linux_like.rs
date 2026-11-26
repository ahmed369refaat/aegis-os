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
    k.create_domain_with(SUPERVISOR, service_profile(), 0, 0, 0)
        .unwrap();
    // Unprivileged service domain: uid 1001.
    k.create_domain_with(SERVICE, service_profile(), 1001, 100, 0)
        .unwrap();
    // Untrusted parser: no file syscalls at all.
    k.create_domain_with(PARSER, parser_profile(), 1002, 100, 0)
        .unwrap();

    // Tree: /pub (world-writable scratch), /home + /home/notes.txt (root-owned).
    k.syscall(
        SUPERVISOR,
        SysRequest::Mkdir {
            path: "/pub",
            mode: Mode(0o777),
        },
    )
    .unwrap();
    k.syscall(
        SUPERVISOR,
        SysRequest::Mkdir {
            path: "/home",
            mode: Mode(0o755),
        },
    )
    .unwrap();
    k.syscall(
        SUPERVISOR,
        SysRequest::Open {
            path: "/home/notes.txt",
            mode: Mode(0o644),
            create: true,
            read: true,
            write: false,
            truncate: false,
        },
    )
    .unwrap();
    let fd = match k
        .syscall(
            SUPERVISOR,
            SysRequest::Open {
                path: "/home/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("expected fd, got {:?}", other),
    };
    k.syscall(
        SUPERVISOR,
        SysRequest::Write {
            fd,
            bytes: b"root secret",
        },
    )
    .unwrap();
    k.syscall(SUPERVISOR, SysRequest::Close { fd }).unwrap();
    k
}

#[test]
fn vfs_unix_permissions_end_to_end() {
    let mut k = kernel_with_tree();

    // The unprivileged service can read a 0o644 root-owned file (other: r)…
    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/home/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    let mut buf = [0u8; 32];
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(&buf[..n], b"root secret"),
        other => panic!("{:?}", other),
    }
    // …but cannot write it (other: no w)…
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Write {
                fd,
                bytes: b"hijack"
            }
        ),
        Err(SysError::Vfs(VfsError::PermissionDenied))
    );
    // …and cannot create inside root-owned /home (no w on parent).
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Open {
                path: "/home/evil",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Vfs(VfsError::PermissionDenied))
    );
    // …while /pub (0o777) is writable for everyone. The file the service
    // creates is owned by the service itself (uid 1001), so it can write
    // it again later — ownership works end to end.
    match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/mine.txt",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd2) => {
            k.syscall(
                SERVICE,
                SysRequest::Write {
                    fd: fd2,
                    bytes: b"service data",
                },
            )
            .unwrap();
            k.syscall(SERVICE, SysRequest::Close { fd: fd2 }).unwrap();
        }
        other => panic!("{:?}", other),
    }
    let fd3 = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/mine.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(
        SERVICE,
        SysRequest::Write {
            fd: fd3,
            bytes: b"owner overwrite",
        },
    )
    .unwrap();
    k.syscall(SERVICE, SysRequest::Close { fd: fd3 }).unwrap();
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
}

#[test]
fn file_cursor_reads_short_then_eof() {
    let mut k = kernel_with_tree();
    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/data.bin",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(
        SERVICE,
        SysRequest::Write {
            fd,
            bytes: b"0123456789",
        },
    )
    .unwrap();
    // F11(c): the writer's offset moved with the write — read back
    // through a fresh read-only descriptor.
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/data.bin",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };

    let mut buf = [0u8; 4];
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => {
            assert_eq!(n, 4);
            assert_eq!(&buf, b"0123");
        }
        other => panic!("{:?}", other),
    }
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => {
            assert_eq!(n, 4);
            assert_eq!(&buf, b"4567");
        }
        other => panic!("{:?}", other),
    }
    let mut big = [0u8; 16];
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut big })
        .unwrap()
    {
        SysValue::Count(n) => {
            assert_eq!(n, 2, "short read at the tail");
            assert_eq!(&big[..2], b"89");
        }
        other => panic!("{:?}", other),
    }
    // EOF: 0.
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut big })
        .unwrap()
    {
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
        k.syscall(
            PARSER,
            SysRequest::Open {
                path: "/home/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Masked(SYS_OPEN))
    );
    assert_eq!(
        k.syscall(
            PARSER,
            SysRequest::Mkdir {
                path: "/pub/x",
                mode: Mode(0o755)
            }
        ),
        Err(SysError::Masked(SYS_MKDIR))
    );
    assert_eq!(
        k.syscall(
            PARSER,
            SysRequest::Unlink {
                path: "/home/notes.txt"
            }
        ),
        Err(SysError::Masked(SYS_UNLINK))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Chroot { path: "/pub" }),
        Err(SysError::Masked(SYS_CHROOT))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Pipe),
        Err(SysError::Masked(SYS_PIPE))
    );
    assert_eq!(
        k.syscall(PARSER, SysRequest::Dup { fd: 0, new_fd: 3 }),
        Err(SysError::Masked(SYS_DUP))
    );
    assert_eq!(
        k.syscall(
            PARSER,
            SysRequest::Kill {
                target: SERVICE,
                sig: SIGKILL
            }
        ),
        Err(SysError::Masked(SYS_KILL))
    );
    // …and the denied attempts feed the behavior monitor.
    assert_eq!(
        k.dispatch(PARSER, SYS_OPEN).unwrap(),
        Decision::DeniedByMask(SYS_OPEN)
    );
}

#[test]
fn pipe_lifecycle_with_dup_semantics() {
    let mut k = kernel_with_tree();
    let (r, w) = match k.syscall(SERVICE, SysRequest::Pipe).unwrap() {
        SysValue::FdPair(r, w) => (r, w),
        other => panic!("{:?}", other),
    };
    // Write through the original descriptor.
    match k
        .syscall(
            SERVICE,
            SysRequest::Write {
                fd: w,
                bytes: b"hello pipe",
            },
        )
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(n, 10),
        other => panic!("{:?}", other),
    }
    // dup2: install a second write end at fd 5.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Dup { fd: w, new_fd: 5 }),
        Ok(SysValue::Fd(5))
    );
    // Closing the original write end does NOT close the pipe (dup holds it).
    k.syscall(SERVICE, SysRequest::Close { fd: w }).unwrap();
    k.syscall(SERVICE, SysRequest::Write { fd: 5, bytes: b"!" })
        .unwrap();
    // Read everything in order.
    let mut buf = [0u8; 32];
    match k
        .syscall(
            SERVICE,
            SysRequest::Read {
                fd: r,
                buf: &mut buf,
            },
        )
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(&buf[..n], b"hello pipe!"),
        other => panic!("{:?}", other),
    }
    // Empty + writer open: WouldBlock.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Read {
                fd: r,
                buf: &mut buf
            }
        ),
        Err(SysError::Pipe(PipeError::WouldBlock))
    );
    // Close the last write end: EOF.
    k.syscall(SERVICE, SysRequest::Close { fd: 5 }).unwrap();
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Read {
                fd: r,
                buf: &mut buf
            }
        ),
        Ok(SysValue::Count(0))
    );
    // Write end gone entirely: reading after EOF keeps returning 0.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Read {
                fd: r,
                buf: &mut buf
            }
        ),
        Ok(SysValue::Count(0))
    );
    k.syscall(SERVICE, SysRequest::Close { fd: r }).unwrap();
    // Reading from a write end is EBADF-flavored.
    let (_, w2) = match k.syscall(SERVICE, SysRequest::Pipe).unwrap() {
        SysValue::FdPair(r, w) => (r, w),
        other => panic!("{:?}", other),
    };
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Read {
                fd: w2,
                buf: &mut buf
            }
        ),
        Err(SysError::BadFd(w2))
    );
}

#[test]
fn chroot_confinement_through_syscalls() {
    let mut k = kernel_with_tree();
    // The service chroots itself into /pub (world-writable scratch).
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Chroot { path: "/pub" }),
        Ok(SysValue::Unit)
    );
    // Inside the chroot it can create and read its own files…
    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "box.txt",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(
        SERVICE,
        SysRequest::Write {
            fd,
            bytes: b"confined",
        },
    )
    .unwrap();
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    // …but every escape attempt misses:
    //   absolute paths resolve from the chroot root,
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Open {
                path: "/home/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Vfs(VfsError::NotFound))
    );
    //   as do ..-climbs…
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Open {
                path: "../../../home/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Vfs(VfsError::NotFound))
    );
    //   …and unlinking outside is equally impossible.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Unlink {
                path: "../home/notes.txt"
            }
        ),
        Err(SysError::Vfs(VfsError::NotFound))
    );
    // The supervisor (not chrooted) still sees the whole tree.
    assert!(k
        .syscall(
            SUPERVISOR,
            SysRequest::Open {
                path: "/home/notes.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        )
        .is_ok());
    // The confined service can still chroot deeper (within its root).
    k.syscall(
        SUPERVISOR,
        SysRequest::Mkdir {
            path: "/pub/jail",
            mode: Mode(0o777),
        },
    )
    .unwrap();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Chroot { path: "jail" }),
        Ok(SysValue::Unit)
    );
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Open {
                path: "../box.txt",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Vfs(VfsError::NotFound))
    );
}

#[test]
fn kill_permissions_and_fatal_signal_delivery() {
    let mut k = kernel_with_tree();
    // Same-uid kill is allowed; different uid is denied (Unix rules).
    let other_uid_domain = 3u32;
    k.create_domain_with(other_uid_domain, service_profile(), 4242, 100, 0)
        .unwrap();
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Kill {
                target: other_uid_domain,
                sig: SIGTERM
            }
        ),
        Err(SysError::PermissionDenied)
    );
    // Killing yourself is always allowed.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Kill {
                target: SERVICE,
                sig: SIGUSR1
            }
        ),
        Ok(SysValue::Unit)
    );
    // F18 (ADR-0009): even the supervisor needs Domain capabilities to
    // signal other domains — granted through the official, uid-0-only
    // API (risk treatment 3: no raw supervisor table pokes).
    for target in [PARSER, SERVICE] {
        k.cap_grant_domain(SUPERVISOR, target).unwrap();
    }
    // Invalid signal numbers are rejected.
    assert_eq!(
        k.syscall(
            SUPERVISOR,
            SysRequest::Kill {
                target: SERVICE,
                sig: 0
            }
        ),
        Err(SysError::Signal(SignalError::InvalidSignal(0)))
    );
    // Supervisor (uid 0) SIGTERMs the parser: pending until delivered.
    assert_eq!(
        k.syscall(
            SUPERVISOR,
            SysRequest::Kill {
                target: PARSER,
                sig: SIGTERM
            }
        ),
        Ok(SysValue::Unit)
    );
    assert_eq!(k.domain_state(PARSER), Some(DomainState::Running));
    // Delivery applies the default action: Terminate -> quarantine.
    assert_eq!(k.deliver_signals(PARSER).unwrap(), Some(SIGTERM));
    assert_eq!(k.domain_state(PARSER), Some(DomainState::Quarantined));
    // A quarantined domain cannot even attempt syscalls anymore.
    assert_eq!(
        k.syscall(
            PARSER,
            SysRequest::Open {
                path: "/pub/x",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Quarantined(SYS_OPEN))
    );
    // SIGUSR1 (default: Ignore) does NOT terminate the target.
    assert_eq!(
        k.syscall(
            SUPERVISOR,
            SysRequest::Kill {
                target: SERVICE,
                sig: SIGUSR1
            }
        ),
        Ok(SysValue::Unit)
    );
    assert_eq!(k.deliver_signals(SERVICE).unwrap(), Some(SIGUSR1));
    assert_eq!(k.domain_state(SERVICE), Some(DomainState::Running));
    // F18 (ADR-0009): the capability gate precedes existence — an
    // unauthorized sender (no Domain capability for the target) gets
    // PermissionDenied for a MISSING target too, so ids cannot be
    // enumerated (the F14 property, preserved under the new order).
    assert_eq!(
        k.syscall(
            SUPERVISOR,
            SysRequest::Kill {
                target: 99,
                sig: SIGKILL
            }
        ),
        Err(SysError::PermissionDenied)
    );
}

#[test]
fn cfs_scheduler_fairness_through_kernel() {
    let mut k = Kernel::new();
    k.create_domain_with(1, service_profile(), 1001, 100, 0)
        .unwrap();
    k.create_domain_with(2, service_profile(), 1002, 100, 0)
        .unwrap();
    k.create_domain_with(3, service_profile(), 1003, 100, 5)
        .unwrap(); // low priority
                   // Two equal domains alternate; the nice+5 domain gets fewer slices.
    let mut counts = [0u32; 4];
    // Scheduling settles into a 7-slice cycle [3,1,2,1,2,1,2]; after the
    // 2 warm-up slices, 56 more = 8 full cycles: nice-0 domains get
    // exactly 25 slices each, nice+5 gets 8.
    for _ in 0..58 {
        let id = k.sched.schedule_slice(4).expect("runnable domains exist");
        counts[id as usize] += 1;
    }
    assert_eq!(
        counts[1], counts[2],
        "equal nice must share equally: {:?}",
        counts
    );
    assert_eq!(counts[1], 25);
    assert_eq!(
        counts[3], 8,
        "nice +5 is charged more virtual time per slice"
    );
    assert!(
        counts[1] > counts[3],
        "nice +5 must get fewer slices: {:?}",
        counts
    );
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
    assert!(
        picked_one,
        "the woken domain must be scheduled again promptly"
    );
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
    k.create_domain_with(netd, netd_profile(), 50, 50, 0)
        .unwrap();
    // Supervisor opens the broker socket for netd.
    assert_eq!(k.net_open(netd).unwrap(), 0);

    // K20 (P0-2): the burst speaks Ethernet now (MAX_NET_FRAME_BYTES
    // = 1514) — a 1500-byte frame passes…
    match k.syscall(netd, SysRequest::NetSend { len: 1500 }).unwrap() {
        SysValue::Count(left) => assert_eq!(left, 14),
        other => panic!("{:?}", other),
    }
    // …then a 15-byte send is throttled with the exact deficit.
    assert_eq!(
        k.syscall(netd, SysRequest::NetSend { len: 15 }),
        Err(SysError::Net(NetError::RateLimited {
            requested: 15,
            available: 14
        }))
    );
    // A frame that can NEVER fit any window is a value error
    // (EMSGSIZE family), not a throttle — and it burns no tokens:
    // the 14 survivors are still there.
    assert_eq!(
        k.syscall(
            netd,
            SysRequest::NetSend {
                len: MAX_NET_FRAME_BYTES + 1
            }
        ),
        Err(SysError::Net(NetError::TooLong(MAX_NET_FRAME_BYTES + 1)))
    );
    assert_eq!(
        k.syscall(netd, SysRequest::NetSend { len: 14 }).unwrap(),
        SysValue::Count(0)
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

/// K20 (P0-2): the receive half of the brokered socket — the Device
/// capability with READ gates it (WRITE gated sending), the socket
/// must be the caller's own, and successful receives are accounted on
/// the socket (the policy half; data movement is the kernel's).
#[test]
fn net_recv_is_cap_gated_and_accounted() {
    let mut k = kernel_with_tree();
    let netd = 3u32;
    k.create_domain_with(netd, netd_profile(), 50, 50, 0)
        .unwrap();
    // No socket yet: precise refusal.
    assert_eq!(
        k.syscall(netd, SysRequest::NetRecv { len: 512 }),
        Err(SysError::Net(NetError::InvalidSocket(u32::MAX)))
    );
    k.net_open(netd).unwrap();
    // netd holds Device(0) with READ|WRITE|GRANT (netd_profile's
    // base_rights): the gate passes and the len is admitted.
    assert_eq!(
        k.syscall(netd, SysRequest::NetRecv { len: 512 }).unwrap(),
        SysValue::Count(512)
    );
    // A rights-less domain: Device(0) cap exists but carries NO READ
    // — receiving refuses with the capability error.
    let client = 4u32;
    let mut ro = netd_profile();
    ro.base_rights = aegis_os::capability::Rights::NONE;
    k.create_domain_with(client, ro, 51, 51, 0).unwrap();
    assert_eq!(
        k.syscall(client, SysRequest::NetRecv { len: 512 }),
        Err(SysError::PermissionDenied)
    );
    // Masked out entirely for a profile without NET_RECV.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::NetRecv { len: 512 }),
        Err(SysError::Masked(SYS_NET_RECV))
    );
    // Accounting rides the executor's callback with the ACTUAL count
    // (the policy gate admitted the request; this is the truth).
    k.net_recv_account(netd, 590);
    k.net_recv_account(netd, 590);
    assert_eq!(k.sockets_bytes_recvd(netd), Some(1180));
}

#[test]
fn mkdir_unlink_roundtrip_and_nonempty_dir() {
    let mut k = kernel_with_tree();
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Mkdir {
                path: "/pub/dir",
                mode: Mode(0o755)
            }
        ),
        Ok(SysValue::Unit)
    );
    // Duplicate mkdir: EEXIST.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Mkdir {
                path: "/pub/dir",
                mode: Mode(0o755)
            }
        ),
        Err(SysError::Vfs(VfsError::Exists))
    );
    // Non-empty dir cannot be unlinked…
    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/dir/f",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Unlink { path: "/pub/dir" }),
        Err(SysError::Vfs(VfsError::NotEmpty))
    );
    // …empty the directory, then both file and dir removal work.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Unlink { path: "/pub/dir/f" }),
        Ok(SysValue::Unit)
    );
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Unlink { path: "/pub/dir" }),
        Ok(SysValue::Unit)
    );
    // Gone for real.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/dir",
                mode: Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false
            }
        ),
        Err(SysError::Vfs(VfsError::NotFound))
    );
}

// ─── Round J: the stdio triplet, Reserved targets, and the gate/execute split ───

#[test]
fn reserve_stdio_moves_allocation_past_the_triplet() {
    let mut k = kernel_with_tree();
    k.reserve_stdio(SERVICE).unwrap();
    // The domain's own allocations now begin at fd 3, Unix-style —
    // the runtime's device alias (console behind fd 1) and the fd
    // table cannot collide anymore.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Pipe),
        Ok(SysValue::FdPair(3, 4))
    );
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Open {
                path: "/pub/scratch",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: true,
                truncate: false
            }
        ),
        Ok(SysValue::Fd(5))
    );
}

#[test]
fn reserved_fds_refuse_io_but_close_and_dup_like_entries() {
    let mut k = kernel_with_tree();
    k.reserve_stdio(SERVICE).unwrap();
    let mut buf = [0u8; 4];
    // The policy core refuses I/O through the reserved triplet.
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Read {
                fd: 0,
                buf: &mut buf
            }
        ),
        Err(SysError::Reserved(0))
    );
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Write {
                fd: 1,
                bytes: b"no"
            }
        ),
        Err(SysError::Reserved(1))
    );
    // dup copies a Reserved entry like any other (no refcount work).
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Dup { fd: 1, new_fd: 9 }),
        Ok(SysValue::Fd(9))
    );
    assert_eq!(
        k.syscall(
            SERVICE,
            SysRequest::Write {
                fd: 9,
                bytes: b"no"
            }
        ),
        Err(SysError::Reserved(9))
    );
    // Closing a reserved slot frees it: lowest-free hands fd 1 back out
    // (fd 0 and fd 2 stay reserved — only 1 was closed).
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Close { fd: 1 }),
        Ok(SysValue::Unit)
    );
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Pipe),
        Ok(SysValue::FdPair(1, 3))
    );
}

#[test]
fn reserve_stdio_refuses_real_targets_and_is_idempotent() {
    let mut k = kernel_with_tree();
    // A real target already sitting in 0..=2: refuse, shadowing is worse.
    k.syscall(
        SERVICE,
        SysRequest::Open {
            path: "/home/notes.txt",
            mode: Mode(0o644),
            create: false,
            read: true,
            write: false,
            truncate: false,
        },
    )
    .unwrap(); // fd 0
    assert_eq!(
        k.reserve_stdio(SERVICE),
        Err(KernelError::StdioSlotOccupied(0))
    );
    // Idempotent on a clean reservation.
    k.reserve_stdio(PARSER).unwrap();
    assert_eq!(k.reserve_stdio(PARSER), Ok(()));
}

#[test]
fn execute_runs_only_after_the_caller_gates_the_split_contract() {
    let mut k = kernel_with_tree();
    // The parser profile has no OPEN bit: `syscall` (gate + execute)
    // refuses, exactly as before.
    assert_eq!(
        k.syscall(PARSER, open_notes()),
        Err(SysError::Masked(SYS_OPEN))
    );
    assert_eq!(k.domain_mut(PARSER).unwrap().stats.denied_syscalls, 1);
    // `execute` is Phase 2 ALONE — it never gates, by contract. This
    // is the seam the ring-3 runtime uses: it runs its own `dispatch`
    // (where the live accounting must land) and only an Allowed
    // reaches `execute`. Proof that the caller MUST gate: execute
    // hands the parser a real fd for a syscall its mask forbids.
    let fd = k.execute(PARSER, open_notes()).unwrap();
    assert_eq!(fd, SysValue::Fd(0));
    // And the denial counter did not move — no double accounting.
    assert_eq!(k.domain_mut(PARSER).unwrap().stats.denied_syscalls, 1);
    // A runtime that gated first (dispatch → Allowed) then executed
    // sees the served path accounted exactly once by its own dispatch.
    assert_eq!(k.dispatch(SERVICE, SYS_OPEN).unwrap(), Decision::Allowed);
    assert!(k.execute(SERVICE, open_notes()).is_ok());
}

fn open_notes() -> SysRequest<'static> {
    SysRequest::Open {
        path: "/home/notes.txt",
        mode: Mode(0o644),
        create: false,
        read: true,
        write: false,
        truncate: false,
    }
}

/// Round J, the boot's run-8 phase F exactly as the files blob drives
/// it (same domain shape, same /pub, same fd arithmetic): if this
/// passes on the host, the boot-side failure is in the marshaling
/// layer, not the executor.
#[test]
fn files_blob_phase_f_on_the_host() {
    let mut k = Kernel::new();
    // The boot's supervisor (uid 0) prepares /pub world-writable.
    k.create_domain_with(13, service_profile(), 0, 0, 0)
        .unwrap();
    k.syscall(
        13,
        SysRequest::Mkdir {
            path: "/pub",
            mode: Mode(0o777),
        },
    )
    .unwrap();
    let _ = k.destroy_domain(13);
    // The blob's domain: service profile, derived uid (1000 + 14).
    // (The boot's spawn_user_blob reserves the stdio triplet; this
    // host stand-in does the same by hand.)
    k.create_domain(14, service_profile()).unwrap();
    k.reserve_stdio(14).unwrap();
    // Phase P's leftovers: pipe (3,4), dup(3 -> 7), close(3).
    assert_eq!(k.syscall(14, SysRequest::Pipe), Ok(SysValue::FdPair(3, 4)));
    assert_eq!(
        k.syscall(14, SysRequest::Dup { fd: 3, new_fd: 7 }),
        Ok(SysValue::Fd(7))
    );
    assert_eq!(
        k.syscall(14, SysRequest::Close { fd: 3 }),
        Ok(SysValue::Unit)
    );
    // Phase F: open(O_CREAT|O_RDWR, 0644) -> 5.
    let fd = match k
        .syscall(
            14,
            SysRequest::Open {
                path: "/pub/round-j.txt",
                mode: Mode(0o644),
                create: true,
                read: true,
                write: true,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("open: {:?}", other),
    };
    // fd 3 was freed by close(3): lowest-free recycles it (the Unix
    // rule the blob asserts live).
    assert_eq!(fd, 3);
    // dup(3 -> 6) BEFORE the write: the duplicate's cursor is 0.
    assert_eq!(
        k.syscall(14, SysRequest::Dup { fd: 3, new_fd: 6 }),
        Ok(SysValue::Fd(6))
    );
    // write 21 bytes of FMSG via the original.
    let fmsg = b"aegis file roundtrip\n";
    assert_eq!(fmsg.len(), 21);
    assert_eq!(
        k.syscall(14, SysRequest::Write { fd: 3, bytes: fmsg }),
        Ok(SysValue::Count(21))
    );
    // read back through the duplicate's snapshot cursor.
    let mut buf = [0u8; 64];
    assert_eq!(
        k.syscall(
            14,
            SysRequest::Read {
                fd: 6,
                buf: &mut buf
            }
        ),
        Ok(SysValue::Count(21))
    );
    assert_eq!(&buf[..21], fmsg);
    // close the original; the duplicate survives and reads EOF.
    assert_eq!(
        k.syscall(14, SysRequest::Close { fd: 3 }),
        Ok(SysValue::Unit)
    );
    // and the closed fd refuses a write — the blob's third negative.
    assert_eq!(
        k.syscall(
            14,
            SysRequest::Write {
                fd: 3,
                bytes: b"no"
            }
        ),
        Err(SysError::BadFd(3))
    );
    let mut tail = [0u8; 8];
    assert_eq!(
        k.syscall(
            14,
            SysRequest::Read {
                fd: 6,
                buf: &mut tail
            }
        ),
        Ok(SysValue::Count(0))
    );
}

/// Phase 6 S2: devfs — /dev/null discards writes and answers EOF;
/// /dev/zero discards writes and reads an endless stream of zeros.
#[test]
fn devfs_null_and_zero_semantics() {
    use aegis_os::vfs::DevKind;
    let mut k = kernel_with_tree();
    k.syscall(
        SUPERVISOR,
        SysRequest::Mkdir {
            path: "/dev",
            mode: Mode(0o755),
        },
    )
    .unwrap();
    k.install_device("/dev/null", DevKind::Null).unwrap();
    k.install_device("/dev/zero", DevKind::Zero).unwrap();

    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/dev/null",
                mode: Mode(0o666),
                create: false,
                read: true,
                write: true,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    // Write 12 bytes into the void: all of them "land".
    match k
        .syscall(
            SERVICE,
            SysRequest::Write {
                fd,
                bytes: b"lost to null",
            },
        )
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(n, 12),
        other => panic!("{:?}", other),
    }
    // Read back: instant EOF.
    let mut buf = [7u8; 8];
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(n, 0),
        other => panic!("{:?}", other),
    }
    let _ = k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();

    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/dev/zero",
                mode: Mode(0o666),
                create: false,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    let mut buf = [0xFFu8; 16];
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(n, 16),
        other => panic!("{:?}", other),
    }
    assert!(buf.iter().all(|&b| b == 0), "zero must zero-fill: {buf:?}");
    let _ = k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
}

/// Phase 6 S2: procfs — one shared /proc/self node, one honest answer
/// per caller (the READING domain's identity), single-shot then EOF,
/// and never writable.
#[test]
fn procfs_self_names_the_caller() {
    use aegis_os::vfs::ProcNode;
    let mut k = kernel_with_tree();
    k.syscall(
        SUPERVISOR,
        SysRequest::Mkdir {
            path: "/proc",
            mode: Mode(0o755),
        },
    )
    .unwrap();
    k.install_proc_node("/proc/self", ProcNode::Status).unwrap();

    let fd = match k
        .syscall(
            SERVICE,
            SysRequest::Open {
                path: "/proc/self",
                mode: Mode(0o444),
                create: false,
                read: true,
                write: false,
                truncate: false,
            },
        )
        .unwrap()
    {
        SysValue::Fd(fd) => fd,
        other => panic!("{:?}", other),
    };
    let mut buf = [0u8; 64];
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(
            &buf[..n],
            format!("domain {SERVICE} uid 1001 gid 100\n").as_bytes()
        ),
        other => panic!("{:?}", other),
    }
    // Single-shot: the next read is EOF.
    match k
        .syscall(SERVICE, SysRequest::Read { fd, buf: &mut buf })
        .unwrap()
    {
        SysValue::Count(n) => assert_eq!(n, 0),
        other => panic!("{:?}", other),
    }
    // And the node refuses writes outright.
    assert_eq!(
        k.syscall(SERVICE, SysRequest::Write { fd, bytes: b"x" }),
        Err(SysError::Vfs(VfsError::IsADirectory))
    );
    let _ = k.syscall(SERVICE, SysRequest::Close { fd }).unwrap();
}
