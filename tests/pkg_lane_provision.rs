//! K23 lane reproduction on the host: the boot provisioning tree
//! versus the package manager's own credentials — with the shared-gid
//! coupling REMOVED.
//!
//! K22 let the manager ride the generic boot gid 100 and made /pkg
//! 0770 root:100: the shared group WAS the write path, and every
//! domain the default derivation spawns carries gid 100. K23 gives
//! the manager its own identity (uid 1070, gid 150 —
//! `profile::PKG_UID`/`PKG_GID`): /pkg and /usr are 0770 root:150 (the
//! only group that can write either), the trust anchors and the /r1
//! repo stay root:root 0644/0755. These tests replay the EXACT tree
//! through the public `Kernel` API: the POSITIVE run (the manager
//! walks its whole install), the FOREIGN run (a different uid AND gid
//! meets EACCES on /pkg but still reads the root:root 0644 anchors),
//! and the ANCHOR run (the manager itself cannot write what it reads).

use aegis_os::prelude::*;
use aegis_os::profile::{pkg_caller_profile, PKG_GID, PKG_UID};
use aegis_os::sys::{SysError, SysValue};
use aegis_os::vfs::VfsError;

/// The lane's ids: the caller/Pm domain 70, the root provisioning
/// supervisor 71, the group-carving probe 73 (K23), and the foreign
/// identity's lane 74.
const PROBE: u32 = 71;
const PM: u32 = 70;
const GROUP: u32 = 73;
const FOREIGN: u32 = 74;
/// The foreign identity: different uid AND different gid — no owner
/// match, no group match anywhere in the tree, so the OTHER bits are
/// its whole world. That is the point: it proves the tightened /pkg
/// (0770 root:150, other = ---) refuses it while the root:root 0644
/// anchors (other = r--) still serve it.
const FOREIGN_UID: u16 = 3000;
const FOREIGN_GID: u16 = 300;

fn kernel_with_tree() -> Kernel {
    let mut k = Kernel::new();
    // The group probe (uid 0, gid 150): mints the WRITE path —
    // everything it creates lands root:150.
    k.create_domain_with(GROUP, service_profile(), 0, PKG_GID, 0)
        .unwrap();
    // The root probe (uid 0, gid 0): mints the READ-ONLY world —
    // everything it creates lands root:root.
    k.create_domain_with(PROBE, service_profile(), 0, 0, 0)
        .unwrap();
    // The manager's own identity, exactly as the K23 boot lane
    // declares it for domain 70 (spawn_user_blob_as: uid 1070, its
    // OWN gid 150 — no longer the derived gid 100).
    k.create_domain_with(PM, pkg_caller_profile(), PKG_UID, PKG_GID, 0)
        .unwrap();
    // A foreign identity for the negative runs — same file-family
    // lane (pkg_caller_profile) so its refusals come from the DAC
    // walk, not from the mask.
    k.create_domain_with(FOREIGN, pkg_caller_profile(), FOREIGN_UID, FOREIGN_GID, 0)
        .unwrap();
    for &(dom, path, m) in &[
        (GROUP, "/pkg", 0o770u16),
        (GROUP, "/usr", 0o770),
        (PROBE, "/r1", 0o755),
        (PROBE, "/pkg/repos", 0o755),
    ] {
        k.syscall(
            dom,
            SysRequest::Mkdir {
                path,
                mode: Mode(m),
            },
        )
        .unwrap();
    }
    for &(path, bytes) in &[
        ("/r1/index.aki", b"AKI1fixture".as_slice()),
        // K23: the repo layout is version-qualified — the boot lane
        // provisions BOTH versions, and the manager must read either
        // one the plan picks (1.0.0 for install, 1.1.0 for upgrade).
        ("/r1/r1.hello-1.0.0.akp", b"AKP1v10fixture".as_slice()),
        ("/r1/r1.hello-1.1.0.akp", b"AKP1v11fixture".as_slice()),
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

/// One step of a domain's walk, answered plainly (the fd is closed
/// again so the next step sees a clean table).
fn open_as(
    k: &mut Kernel,
    dom: u32,
    path: &str,
    create: bool,
    write: bool,
    excl: bool,
) -> Result<(), SysError> {
    let r = k.syscall(
        dom,
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
            let _ = k.syscall(dom, SysRequest::Close { fd });
            Ok(())
        }
        Ok(_) => unreachable!("open answers Fd"),
        Err(e) => Err(e),
    }
}

/// The refusal we expect everywhere the tightened tree says no.
fn is_eacces(r: Result<(), SysError>) -> bool {
    matches!(r, Err(SysError::Vfs(VfsError::PermissionDenied)))
}

#[test]
fn the_manager_can_walk_its_whole_install_tree() {
    let mut k = kernel_with_tree();
    // The read side: the anchors, the repo config, the repo itself —
    // both version-qualified package files (K23: the upgrade round's
    // transaction reads the 1.1.0 one), all root:root, read through
    // the 0644 other bits.
    for path in [
        "/pkg/trust",
        "/pkg/repos/r1.repo",
        "/r1/index.aki",
        "/r1/r1.hello-1.0.0.akp",
        "/r1/r1.hello-1.1.0.akp",
    ] {
        open_as(&mut k, PM, path, false, false, false)
            .unwrap_or_else(|e| panic!("the manager must READ {path}: {e:?}"));
    }
    // The write side: the lock (O_CREAT|O_EXCL), the state dirs, the
    // payload tree, the record — everything `install` touches, all
    // through /pkg and /usr's 0770 root:150 GROUP bits (uid 1070
    // matches neither owner — the group is the write path, and it is
    // the manager's own).
    open_as(&mut k, PM, "/pkg/lock", true, true, true)
        .unwrap_or_else(|e| panic!("the lock: {e:?}"));
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
        open_as(&mut k, PM, path, true, true, false)
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
}

#[test]
fn a_foreign_identity_cannot_write_pkg_but_reads_the_anchors() {
    let mut k = kernel_with_tree();
    // The write refusals: creating a file in /pkg, creating a dir in
    // /pkg, creating a file in /usr, and open-for-write on /pkg
    // itself — every shape dies the same death: /pkg and /usr are
    // 0770 root:150 and the foreign identity matches neither the
    // owner nor the group, so the other bits (---) are its whole
    // world. Path resolution needs the x bit on /pkg first, so the
    // refusal is EACCES either way — at the traversal, never at the
    // file.
    assert!(
        is_eacces(open_as(&mut k, FOREIGN, "/pkg/foreign", true, true, false)),
        "a foreign identity must not create inside /pkg"
    );
    assert!(
        is_eacces(
            k.syscall(
                FOREIGN,
                SysRequest::Mkdir {
                    path: "/pkg/foreign-dir",
                    mode: Mode(0o755),
                },
            )
            .map(|_| ())
        ),
        "a foreign identity must not mkdir inside /pkg"
    );
    assert!(
        is_eacces(open_as(&mut k, FOREIGN, "/usr/foreign", true, true, false)),
        "a foreign identity must not create inside /usr"
    );
    // Even the read-open (the listing handle) of /pkg itself is
    // EACCES: the open-time Read check classifies the foreign
    // identity by the other bits (---). A write-open would die
    // earlier with EISDIR — a directory never opens for write —
    // which says nothing about DAC, so the listing refusal is the
    // honest shape here.
    assert!(
        is_eacces(open_as(&mut k, FOREIGN, "/pkg", false, false, false)),
        "a foreign identity must not even list /pkg"
    );
    // The read side: the root:root 0644/0755 repo tree still serves
    // the foreign identity through its other bits — tightening /pkg
    // never made the repo world unreadable. (The anchors INSIDE /pkg
    // — /pkg/trust, /pkg/repos — are one step further closed to this
    // identity: reaching them needs x on /pkg, which 0770 root:150
    // does not grant the other class. The /r1 tree carries the same
    // root:root ownership and is the reachable proof.)
    for path in [
        "/r1/index.aki",
        "/r1/r1.hello-1.0.0.akp",
        "/r1/r1.hello-1.1.0.akp",
    ] {
        open_as(&mut k, FOREIGN, path, false, false, false)
            .unwrap_or_else(|e| panic!("a foreign identity still READS {path}: {e:?}"));
    }
    // ...and it cannot even RESOLVE into /pkg (the traversal refusal
    // is the stronger fact: the tightened tree hides /pkg's contents
    // from every identity outside the group, reads included).
    assert!(
        is_eacces(open_as(&mut k, FOREIGN, "/pkg/trust", false, false, false)),
        "a foreign identity must not even traverse /pkg"
    );
}

#[test]
fn the_manager_cannot_write_its_own_anchors() {
    let mut k = kernel_with_tree();
    // The manager reads its anchors (other bits, 0644)...
    open_as(&mut k, PM, "/pkg/trust", false, false, false)
        .unwrap_or_else(|e| panic!("the manager must READ /pkg/trust: {e:?}"));
    // ...and can never WRITE them: /pkg/trust and /r1/* are root:root
    // 0644 — for the manager (uid 1070, gid 150) that is the other
    // class, r-- and nothing more. Both the plain write-open and the
    // truncate flavor (write+truncate) refuse; a compromised manager
    // cannot forge its own trust or repo bytes.
    assert!(
        is_eacces(open_as(&mut k, PM, "/pkg/trust", false, true, false)),
        "the manager must not write /pkg/trust"
    );
    assert!(
        is_eacces(open_as(&mut k, PM, "/pkg/trust", true, true, false)),
        "the manager must not replace /pkg/trust either (O_CREAT on existing)"
    );
    assert!(
        is_eacces(open_as(&mut k, PM, "/r1/index.aki", false, true, false)),
        "the manager must not write the repo index"
    );
    assert!(
        is_eacces(open_as(
            &mut k,
            PM,
            "/r1/r1.hello-1.0.0.akp",
            false,
            true,
            false
        )),
        "the manager must not write the repo package (1.0.0)"
    );
    assert!(
        is_eacces(open_as(
            &mut k,
            PM,
            "/r1/r1.hello-1.1.0.akp",
            false,
            true,
            false
        )),
        "the manager must not write the repo package (1.1.0)"
    );
    // The repo configs sit one level deeper: their parent /pkg/repos
    // is root:root 0755, so the manager cannot even unlink or rename
    // over them — parent-write is the gate for both, and the other
    // class has no w bit there.
    assert!(
        is_eacces(
            k.syscall(
                PM,
                SysRequest::Unlink {
                    path: "/pkg/repos/r1.repo"
                }
            )
            .map(|_| ())
        ),
        "the manager must not unlink a repo config"
    );
    assert!(
        is_eacces(
            k.syscall(
                PM,
                SysRequest::Rename {
                    from: "/pkg/repos/r1.repo",
                    to: "/pkg/stolen",
                },
            )
            .map(|_| ())
        ),
        "the manager must not rename a repo config away"
    );
    // (Known edge, deliberate this round: /pkg/trust's parent IS the
    // group-writable /pkg, so unlink/rename-against-it stay possible
    // for the manager — POSIX gates those on the parent alone. A
    // sticky bit or a root-owned anchor directory is the documented
    // next hardening step.)
}

#[test]
fn the_tree_looks_like_the_boot_lane_provisioned_it() {
    let mut k = kernel_with_tree();
    // The root supervisor reads everything back (uid 0 bypass) —
    // including the anchors the manager can only read.
    for (path, want) in [
        ("/pkg/trust", b"ATSTfixture".as_slice()),
        ("/r1/index.aki", b"AKI1fixture".as_slice()),
        ("/pkg/repos/r1.repo", b"ARPSfixture".as_slice()),
    ] {
        let Ok(SysValue::Fd(fd)) = k.syscall(
            PROBE,
            SysRequest::Open {
                path,
                mode: Mode(0),
                create: false,
                read: true,
                write: false,
                truncate: false,
                excl: false,
            },
        ) else {
            panic!("probe opens {path}");
        };
        let mut buf = [0u8; 512];
        match k.syscall(PROBE, SysRequest::Read { fd, buf: &mut buf }) {
            Ok(SysValue::Count(n)) => assert_eq!(&buf[..n], want),
            other => panic!("probe read answered {other:?}"),
        }
        let _ = k.syscall(PROBE, SysRequest::Close { fd });
    }
}
