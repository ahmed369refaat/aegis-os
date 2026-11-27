//! K22 lane reproduction on the host: the boot provisioning tree
//! versus the package manager's own credentials.
//!
//! The in-VM lane provisioned the repo fixture as a root supervisor
//! and the manager (uid 1070, gid 100 — a `spawn_user_blob`-derived
//! identity) answered `EACCES` somewhere in its install path
//! (`pkg: Io(Access)`), exit 1. This test replays the EXACT tree and
//! the EXACT identity through the public `Kernel` API and walks every
//! filesystem step `install` performs, so the refusing step names
//! itself on the host in seconds instead of inside QEMU.

use aegis_os::prelude::*;
use aegis_os::profile::pkg_caller_profile;
use aegis_os::sys::{SysError, SysValue};

/// The K22 lane's ids: the caller/Pm domain 70 (uid 1070), the
/// provisioning supervisor 71 (root, the manager's group).
const PROBE: u32 = 71;
const PM: u32 = 70;

fn kernel_with_tree() -> Kernel {
    let mut k = Kernel::new();
    // The boot lane's supervisor: uid 0 (the DAC bypass), gid 100 (the
    // manager's group, so what it creates lands in that group).
    k.create_domain_with(PROBE, service_profile(), 0, 100, 0)
        .unwrap();
    // The manager's own identity, exactly as spawn_user_blob derives
    // it for domain 70 (uid 1000 + 70, gid 100).
    k.create_domain_with(PM, pkg_caller_profile(), 1070, 100, 0)
        .unwrap();
    for &(path, m) in &[
        ("/r1", 0o755u16),
        ("/pkg", 0o770),
        ("/pkg/repos", 0o755),
        ("/usr", 0o770),
    ] {
        k.syscall(
            PROBE,
            SysRequest::Mkdir {
                path,
                mode: Mode(m),
            },
        )
        .unwrap();
    }
    for &(path, bytes) in &[
        ("/r1/index.aki", b"AKI1fixture".as_slice()),
        ("/r1/r1.hello.akp", b"AKP1fixture".as_slice()),
        ("/pkg/trust", b"ATSTfixture".as_slice()),
        ("/pkg/repos/r1.repo", b"ARPSfixture".as_slice()),
    ] {
        let Ok(SysValue::Fd(fd)) = k.syscall(
            PROBE,
            SysRequest::Open {
                path,
                mode: Mode(0o644),
                create: true,
                read: false,
                write: true,
                truncate: true,
                excl: false,
            },
        ) else {
            panic!("probe could not write {path}");
        };
        k.syscall(PROBE, SysRequest::Write { fd, bytes }).unwrap();
        k.syscall(PROBE, SysRequest::Close { fd }).unwrap();
    }
    k
}

/// One step of the manager's walk, answered plainly (the fd is closed
/// again so the next step sees a clean table).
fn pm_open(
    k: &mut Kernel,
    path: &str,
    create: bool,
    write: bool,
    excl: bool,
) -> Result<(), SysError> {
    let r = k.syscall(
        PM,
        SysRequest::Open {
            path,
            mode: Mode(0o644),
            create,
            read: !write,
            write,
            truncate: create && !excl,
            excl,
        },
    );
    match r {
        Ok(SysValue::Fd(fd)) => {
            let _ = k.syscall(PM, SysRequest::Close { fd });
            Ok(())
        }
        Ok(_) => unreachable!("open answers Fd"),
        Err(e) => Err(e),
    }
}

#[test]
fn the_manager_can_walk_its_whole_install_tree() {
    let mut k = kernel_with_tree();
    // The read side: the anchors, the repo config, the repo itself.
    for path in [
        "/pkg/trust",
        "/pkg/repos/r1.repo",
        "/r1/index.aki",
        "/r1/r1.hello.akp",
    ] {
        pm_open(&mut k, path, false, false, false)
            .unwrap_or_else(|e| panic!("the manager must READ {path}: {e:?}"));
    }
    // The write side: the lock (O_CREAT|O_EXCL), the state dirs, the
    // payload tree, the record — everything `install` touches.
    pm_open(&mut k, "/pkg/lock", true, true, true).unwrap_or_else(|e| panic!("the lock: {e:?}"));
    for dir in ["/pkg/db", "/pkg/cache", "/pkg/stage", "/usr/bin"] {
        k.syscall(
            PM,
            SysRequest::Mkdir {
                path: dir,
                mode: Mode(0o755),
            },
        )
        .unwrap_or_else(|e| panic!("mkdir {dir} refused: {e:?}"));
    }
    for path in [
        "/pkg/db/r1.hello.rec",
        "/pkg/db/state",
        "/pkg/db/repo-epochs",
        "/pkg/stage/1",
        "/usr/bin/pkg-hello",
    ] {
        pm_open(&mut k, path, true, true, false)
            .unwrap_or_else(|e| panic!("the manager must CREATE {path}: {e:?}"));
    }
    // The directory listing the repo-config scan does — through the
    // REAL arm (SYS_LISTDIR on the open dir fd; a plain Read on a
    // directory answers EISDIR, as it should).
    let Ok(SysValue::Fd(fd)) = k.syscall(
        PM,
        SysRequest::Open {
            path: "/pkg/repos",
            mode: Mode(0),
            create: false,
            read: true,
            write: false,
            truncate: false,
            excl: false,
        },
    ) else {
        panic!("the manager must open /pkg/repos for listing");
    };
    let mut buf = [0u8; 512];
    match k.syscall(PM, SysRequest::ListDir { fd, buf: &mut buf }) {
        Ok(SysValue::Count(n)) => assert!(n > 0, "the repo dir lists its config"),
        other => panic!("listdir answered {other:?}"),
    }
    let _ = k.syscall(PM, SysRequest::Close { fd });

    // The metadata walk (`stat` on a staged file), the commit re-parent
    // (`rename`), and the lock cleanup (`unlink`).
    let mut st = [0u8; 24];
    k.syscall(
        PM,
        SysRequest::Stat {
            path: "/pkg/stage/1",
            out: &mut st,
        },
    )
    .unwrap_or_else(|e| panic!("stat /pkg/stage/1: {e:?}"));
    k.syscall(
        PM,
        SysRequest::Rename {
            from: "/pkg/stage/1",
            to: "/usr/bin/pkg-hello",
        },
    )
    .unwrap_or_else(|e| panic!("the commit rename: {e:?}"));
    k.syscall(PM, SysRequest::Unlink { path: "/pkg/lock" })
        .unwrap_or_else(|e| panic!("unlink /pkg/lock: {e:?}"));

    // And the negative space: the manager must NOT be able to rewrite
    // its own anchors (root-owned 0644, group read only).
    assert!(
        pm_open(&mut k, "/pkg/trust", false, true, false).is_err(),
        "trust stays root-owned"
    );
    assert!(
        pm_open(&mut k, "/r1/index.aki", false, true, false).is_err(),
        "the repo stays root-owned"
    );
}

#[test]
fn the_tree_looks_like_the_boot_lane_provisioned_it() {
    let mut k = kernel_with_tree();
    // The supervisor reads everything back (uid 0 bypass).
    let Ok(SysValue::Fd(fd)) = k.syscall(
        PROBE,
        SysRequest::Open {
            path: "/pkg/trust",
            mode: Mode(0),
            create: false,
            read: true,
            write: false,
            truncate: false,
            excl: false,
        },
    ) else {
        panic!("probe opens /pkg/trust");
    };
    let mut buf = [0u8; 512];
    match k.syscall(PROBE, SysRequest::Read { fd, buf: &mut buf }) {
        Ok(SysValue::Count(n)) => assert_eq!(&buf[..n], b"ATSTfixture"),
        other => panic!("probe read answered {other:?}"),
    }
    let _ = k.syscall(PROBE, SysRequest::Close { fd });
}
