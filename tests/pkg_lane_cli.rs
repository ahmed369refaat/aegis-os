//! K22/K23 end-to-end on the host: the REAL `run_cli` against the
//! REAL kernel, through the REAL pkg-mkrepo fixture bytes — the whole
//! install → upgrade → remove lifecycle the in-VM lane drives.
//!
//! The in-VM lane's manager answered `pkg: Io(Access)` and exit 1;
//! the per-op DAC walk (pkg_lane_provision.rs) passed, so the refusing
//! step lives in the CLI's actual sequence. This test forwards the
//! crate's `Fs` trait to `Kernel::syscall` (the host-side mirror of
//! the target adapter — same flag translation, same one-page
//! chunking) and traces every filesystem call, so the failing step
//! names itself in the test output.
//!
//! It is also the honest host proof of the whole lane: the provisioned
//! tree + the manager's credentials + the signed repo = a committed
//! install with the payload byte-exact at its destination — and, since
//! K23, a real upgrade (the payload MOVES to 1.1.0's bytes) and a real
//! remove (payload, record and state entry all gone).

use aegis_os::prelude::*;
use aegis_os::profile::{PKG_GID, PKG_UID};
use aegis_os::sys::{SysError, SysValue};
use aegis_os::vfs::VfsError;
use aegis_pkg::cli::run_cli;
use aegis_pkg::database::PkgPaths;
use aegis_pkg::error::{Errno, Error, ErrorKind};
use aegis_pkg::{FileKind, Fs, OpenFlags, Path, Stat};

const PROBE: u32 = 71;
const PM: u32 = 70;
/// K23: the group-carving probe (root uid, the manager's gid 150) —
/// mints the root:150 write path; the root probe mints root:root.
const GROUP: u32 = 73;

/// The REAL fixture bytes (boot.sh step [0e] builds them; the same
/// files the kernel's K22/K23 lane embeds). K23: the repo layout is
/// version-qualified, so the fixture carries BOTH versions.
static TRUST: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/trust");
static REPO_CFG: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.repo");
static INDEX: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/index.aki");
static PACKAGE_V10: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.hello-1.0.0.akp");
static PACKAGE_V11: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.hello-1.1.0.akp");
/// P1-2: the netcat client's package — a REAL third-party static
/// binary through the signed path (the in-VM lane's fourth round).
static PACKAGE_NETCAT: &[u8] =
    include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.netcat-1.0.0.akp");
/// P1-2's fourth package: the RUSTC citizen (the lane's fifth round).
static PACKAGE_RUSTHELLO: &[u8] =
    include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.rust-hello-1.0.0.akp");
/// The payload each version installs — different bytes AND sizes, so
/// an upgrade that "succeeded" without moving the payload cannot pass.
/// P1-2: the 1.1.0 payload is the REAL stripped gcc ELF (the same
/// file the ext2 disk serves as /bin/hello — the upgrade installs a
/// genuine loadable image), and the netcat payload is the P1-1 socket
/// citizen itself.
const PAYLOAD_V10: &[u8] = b"hello world\n";
static PAYLOAD_V11: &[u8] = include_bytes!("../kernel-x86_64/blob/userland-hello.elf");
static NETCAT_ELF: &[u8] = include_bytes!("../kernel-x86_64/blob/netcatd.bin");
static RUSTHELLO_ELF: &[u8] = include_bytes!("../kernel-x86_64/blob/rust-hello.elf");

fn kernel_with_fixture() -> Kernel {
    let mut k = Kernel::new();
    // The K23 boot tree, mirrored: the group probe (uid 0, gid 150)
    // carves the write path, the root probe (uid 0, gid 0) carves the
    // read-only world, and the manager runs as its OWN group.
    k.create_domain_with(GROUP, service_profile(), 0, PKG_GID, 0)
        .unwrap();
    k.create_domain_with(PROBE, service_profile(), 0, 0, 0)
        .unwrap();
    k.create_domain_with(
        PM,
        aegis_os::profile::pkg_caller_profile(),
        PKG_UID,
        PKG_GID,
        0,
    )
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
        ("/r1/index.aki", INDEX),
        // K23: BOTH versions — the upgrade round's solver picks 1.1.0
        // and its transaction reads the 1.1.0 file. P1-2: the netcat
        // and rust-hello packages ride the same repo.
        ("/r1/r1.hello-1.0.0.akp", PACKAGE_V10),
        ("/r1/r1.hello-1.1.0.akp", PACKAGE_V11),
        ("/r1/r1.netcat-1.0.0.akp", PACKAGE_NETCAT),
        ("/r1/r1.rust-hello-1.0.0.akp", PACKAGE_RUSTHELLO),
        ("/pkg/trust", TRUST),
        ("/pkg/repos/r1.repo", REPO_CFG),
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
        let mut off = 0;
        while off < bytes.len() {
            let want = (bytes.len() - off).min(4096);
            k.syscall(
                PROBE,
                SysRequest::Write {
                    fd,
                    bytes: &bytes[off..off + want],
                },
            )
            .unwrap();
            off += want;
        }
        k.syscall(PROBE, SysRequest::Close { fd }).unwrap();
    }
    k
}

fn path_str(p: &Path) -> &str {
    core::str::from_utf8(p.as_bytes()).expect("fixture paths are ASCII")
}

/// Read a whole file back through the ROOT supervisor (the probe's
/// DAC bypass): the verification half of every round, mirroring the
/// in-VM lane's PKG_VERIFY reads.
fn probe_read_all(k: &mut Kernel, path: &str) -> Option<Vec<u8>> {
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
        return None;
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match k.syscall(PROBE, SysRequest::Read { fd, buf: &mut buf }) {
            Ok(SysValue::Count(0)) => break,
            Ok(SysValue::Count(n)) => out.extend_from_slice(&buf[..n]),
            _ => {
                let _ = k.syscall(PROBE, SysRequest::Close { fd });
                return None;
            }
        }
    }
    let _ = k.syscall(PROBE, SysRequest::Close { fd });
    Some(out)
}

/// Run one CLI command as the manager's domain and return (code, out).
fn pm_cli(k: &mut Kernel, args: &[&[u8]], paths: &PkgPaths) -> (i32, String) {
    let mut fs = KernelFs { k, dom: PM };
    let mut out = String::new();
    let code = run_cli(args, &mut fs, paths, None, &mut out);
    println!("cli said (exit {code}): {out}");
    (code, out)
}

fn vfs_err(e: SysError, ctx: &str) -> Error {
    let kind = match e {
        SysError::Vfs(VfsError::PermissionDenied) => ErrorKind::Io(Errno::Access),
        SysError::Vfs(VfsError::NotFound) => ErrorKind::Io(Errno::NoEnt),
        SysError::Vfs(VfsError::Exists) => ErrorKind::Io(Errno::Exists),
        SysError::Vfs(VfsError::NotADirectory) => ErrorKind::Io(Errno::NotDir),
        SysError::Vfs(VfsError::IsADirectory) => ErrorKind::Io(Errno::IsDir),
        SysError::Vfs(VfsError::NotEmpty) => ErrorKind::Io(Errno::NotEmpty),
        SysError::Vfs(VfsError::NoSpace) | SysError::Vfs(VfsError::TableFull) => {
            ErrorKind::Io(Errno::NoSpace)
        }
        SysError::Vfs(VfsError::NameTooLong) => ErrorKind::Io(Errno::Io),
        SysError::Vfs(VfsError::StaleInode) => ErrorKind::Io(Errno::Io),
        other => panic!("{ctx} answered a non-VFS error: {other:?}"),
    };
    Error::new(kind, ctx)
}

/// The `Fs` port over `Kernel::syscall`, as the manager's own domain —
/// the host mirror of the target adapter (`pkg/src/main.rs`): the same
/// open-flag translation, the same one-page chunking, the same
/// "only a 0 ends the read" rule. Every call is traced.
struct KernelFs<'a> {
    k: &'a mut Kernel,
    dom: u32,
}

impl Fs for KernelFs<'_> {
    fn open(&mut self, path: &Path, flags: OpenFlags) -> aegis_pkg::Result<u32> {
        let p = path_str(path);
        println!("fs: open {p} (flags {:#o})", flags.0);
        let write = flags.has(OpenFlags::WRONLY);
        let create = flags.has(OpenFlags::CREATE);
        let excl = flags.has(OpenFlags::EXCL);
        match self.k.syscall(
            self.dom,
            SysRequest::Open {
                path: p,
                mode: Mode(0o644),
                create,
                read: !write,
                write,
                truncate: write && !excl,
                excl,
            },
        ) {
            Ok(SysValue::Fd(fd)) => Ok(fd as u32),
            Ok(_) => unreachable!("open answers Fd"),
            Err(e) => Err(vfs_err(e, "open")),
        }
    }

    fn read(&mut self, fd: u32, buf: &mut [u8]) -> aegis_pkg::Result<usize> {
        let mut total = 0usize;
        while total < buf.len() {
            let want = (buf.len() - total).min(4096);
            match self.k.syscall(
                self.dom,
                SysRequest::Read {
                    fd: fd as u8,
                    buf: &mut buf[total..total + want],
                },
            ) {
                Ok(SysValue::Count(0)) => break,
                Ok(SysValue::Count(n)) => total += n,
                Ok(_) => unreachable!("read answers Count"),
                Err(e) => return Err(vfs_err(e, "read")),
            }
        }
        println!("fs: read fd={fd} -> {total}");
        Ok(total)
    }

    fn write(&mut self, fd: u32, buf: &[u8]) -> aegis_pkg::Result<usize> {
        let mut total = 0usize;
        while total < buf.len() {
            let want = (buf.len() - total).min(4096);
            match self.k.syscall(
                self.dom,
                SysRequest::Write {
                    fd: fd as u8,
                    bytes: &buf[total..total + want],
                },
            ) {
                Ok(SysValue::Count(n)) => total += n,
                Ok(_) => unreachable!("write answers Count"),
                Err(e) => return Err(vfs_err(e, "write")),
            }
        }
        println!("fs: write fd={fd} len={total}");
        Ok(total)
    }

    fn close(&mut self, fd: u32) -> aegis_pkg::Result<()> {
        println!("fs: close fd={fd}");
        match self.k.syscall(self.dom, SysRequest::Close { fd: fd as u8 }) {
            Ok(_) => Ok(()),
            Err(e) => Err(vfs_err(e, "close")),
        }
    }

    fn sync(&mut self, _fd: u32) -> aegis_pkg::Result<()> {
        Ok(()) // the kernel VFS is write-through
    }

    fn stat(&mut self, path: &Path) -> aegis_pkg::Result<Stat> {
        let p = path_str(path);
        println!("fs: stat {p}");
        let mut out = [0u8; 24];
        match self.k.syscall(
            self.dom,
            SysRequest::Stat {
                path: p,
                out: &mut out,
            },
        ) {
            Ok(_) => {
                let kind = match out[0] {
                    0 => FileKind::File,
                    1 => FileKind::Dir,
                    _ => FileKind::Symlink,
                };
                let size = u64::from_le_bytes(out[8..16].try_into().unwrap());
                let perm = u16::from_le_bytes(out[16..18].try_into().unwrap());
                Ok(Stat { kind, size, perm })
            }
            Err(e) => Err(vfs_err(e, "stat")),
        }
    }

    fn mkdir(&mut self, path: &Path) -> aegis_pkg::Result<()> {
        let p = path_str(path);
        println!("fs: mkdir {p}");
        match self.k.syscall(
            self.dom,
            SysRequest::Mkdir {
                path: p,
                mode: Mode(0o755),
            },
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(vfs_err(e, "mkdir")),
        }
    }

    fn unlink(&mut self, path: &Path) -> aegis_pkg::Result<()> {
        let p = path_str(path);
        println!("fs: unlink {p}");
        match self.k.syscall(self.dom, SysRequest::Unlink { path: p }) {
            Ok(_) => Ok(()),
            Err(e) => Err(vfs_err(e, "unlink")),
        }
    }

    fn rename(&mut self, from: &Path, to: &Path) -> aegis_pkg::Result<()> {
        let f = path_str(from);
        let t = path_str(to);
        println!("fs: rename {f} -> {t}");
        match self
            .k
            .syscall(self.dom, SysRequest::Rename { from: f, to: t })
        {
            Ok(_) => Ok(()),
            Err(e) => Err(vfs_err(e, "rename")),
        }
    }

    fn getdents(&mut self, fd: u32, out: &mut [u8]) -> aegis_pkg::Result<usize> {
        println!("fs: getdents fd={fd} len={}", out.len());
        let want = out.len().min(4096);
        match self.k.syscall(
            self.dom,
            SysRequest::ListDir {
                fd: fd as u8,
                buf: &mut out[..want],
            },
        ) {
            Ok(SysValue::Count(n)) => Ok(n),
            Ok(_) => unreachable!("listdir answers Count"),
            Err(e) => Err(vfs_err(e, "getdents")),
        }
    }
}

#[test]
fn the_real_cli_installs_from_the_provisioned_repo() {
    let mut k = kernel_with_fixture();
    let paths = PkgPaths::new(b"/pkg").unwrap();
    let (code, out) = pm_cli(&mut k, &[b"install", b"r1/hello@1.0.0"], &paths);
    assert_eq!(code, 0, "the real install failed: {out}");

    // The tree, read back through the root supervisor.
    assert_eq!(
        probe_read_all(&mut k, "/usr/bin/pkg-hello").as_deref(),
        Some(PAYLOAD_V10),
        "the payload must be byte-exact at /usr/bin/pkg-hello"
    );
}

/// K23: the whole lifecycle through the REAL CLI over the REAL kernel
/// bytes — the host mirror of the boot lane's three execve rounds.
#[test]
fn the_real_cli_runs_the_whole_lifecycle() {
    let mut k = kernel_with_fixture();
    let paths = PkgPaths::new(b"/pkg").unwrap();

    // ── install: 1.0.0 commits its 12-B payload ──
    let (code, out) = pm_cli(&mut k, &[b"install", b"r1/hello@1.0.0"], &paths);
    assert_eq!(code, 0, "install: {out}");
    assert_eq!(
        probe_read_all(&mut k, "/usr/bin/pkg-hello").as_deref(),
        Some(PAYLOAD_V10)
    );

    // ── upgrade: the plan must MOVE the package to 1.1.0, not "keep"
    // it (the found-live bug: VersionReq::any() targets resolved to
    // [keep] forever and `pkg upgrade` was a structural no-op) ──
    let (code, out) = pm_cli(&mut k, &[b"upgrade"], &paths);
    assert_eq!(code, 0, "upgrade: {out}");
    assert!(
        out.contains("r1/hello"),
        "the upgrade plan must name the package: {out}"
    );
    assert!(
        !out.contains("nothing to do"),
        "1.1.0 IS available — a no-op answer is the old bug back: {out}"
    );
    // The payload moved: 17 B, byte-exact v1.1 (different bytes AND a
    // different size than 1.0.0's — proof the file was replaced).
    assert_eq!(
        probe_read_all(&mut k, "/usr/bin/pkg-hello").as_deref(),
        Some(PAYLOAD_V11),
        "the upgraded payload must be the v1.1 bytes"
    );
    // The record moved too, not just the file: `pkg list` reads the
    // db record, so a stale 1.0.0 record would answer 1.0.0 here.
    let (code, out) = pm_cli(&mut k, &[b"list"], &paths);
    assert_eq!(code, 0, "list: {out}");
    assert!(
        out.contains("r1/hello 1.1.0"),
        "the record must say 1.1.0: {out}"
    );

    // ── up-to-date idempotence: a second upgrade has nothing above
    // 1.1.0, so it answers the empty-plan path (exit 0, "nothing to
    // do") — the `up_to_date_ok` branch, proven here so the in-VM
    // lane only needs the real-move round ──
    let (code, out) = pm_cli(&mut k, &[b"upgrade"], &paths);
    assert_eq!(code, 0, "second upgrade: {out}");
    assert!(
        out.contains("nothing to do (up to date)"),
        "nothing above 1.1.0 — the empty-plan answer: {out}"
    );

    // ── remove: the payload, the record and the state entry go away ──
    let (code, out) = pm_cli(&mut k, &[b"remove", b"r1/hello"], &paths);
    assert_eq!(code, 0, "remove: {out}");
    // stat answers ENOENT (the kernel's VfsError::NotFound — the
    // exact errno the manager's adapter maps to NoEnt).
    let mut st = [0u8; 24];
    assert!(
        matches!(
            k.syscall(
                PM,
                SysRequest::Stat {
                    path: "/usr/bin/pkg-hello",
                    out: &mut st,
                }
            ),
            Err(SysError::Vfs(VfsError::NotFound))
        ),
        "stat /usr/bin/pkg-hello must answer ENOENT after remove"
    );
    assert!(
        probe_read_all(&mut k, "/pkg/db/r1.hello").is_none(),
        "the db record must be gone"
    );
    let state =
        probe_read_all(&mut k, "/pkg/db/state").expect("the state file survives the remove");
    assert!(
        state.starts_with(b"ASTT"),
        "the state stays a valid state file: {state:?}"
    );
    assert!(
        !state.windows(8).any(|w| w == b"r1/hello"),
        "the state must not list the removed package: {state:?}"
    );
    // and the lifecycle is re-runnable: a fresh install commits again.
    let (code, out) = pm_cli(&mut k, &[b"install", b"r1/hello@1.0.0"], &paths);
    assert_eq!(code, 0, "install after remove: {out}");
    assert_eq!(
        probe_read_all(&mut k, "/usr/bin/pkg-hello").as_deref(),
        Some(PAYLOAD_V10)
    );

    // ── P1-2: the REAL third-party binary round — install the netcat
    // client's package and prove the installed file is the genuine
    // ELF (byte-exact AND a valid exec plan, the loader's own gate) —
    // the host mirror of the in-VM lane's fourth round. ──
    let (code, out) = pm_cli(&mut k, &[b"install", b"r1/netcat@1.0.0"], &paths);
    assert_eq!(code, 0, "install netcat: {out}");
    assert_eq!(
        probe_read_all(&mut k, "/usr/bin/netcat").as_deref(),
        Some(NETCAT_ELF),
        "the installed netcat must be the stripped socket client, byte-exact"
    );
    assert!(
        aegis_os::elf::build_exec_plan(NETCAT_ELF).is_ok(),
        "the installed citizen must parse as a genuine exec image"
    );
    let (code, out) = pm_cli(&mut k, &[b"list"], &paths);
    assert_eq!(code, 0, "list after netcat: {out}");
    assert!(
        out.contains("r1/netcat 1.0.0"),
        "the record must say r1/netcat 1.0.0: {out}"
    );

    // ── P1-2's fifth round: the RUSTC citizen — the third compiler
    // path through one signed repo, byte-exact + plan-parsed (the
    // host mirror of the lane's round 5). ──
    let (code, out) = pm_cli(&mut k, &[b"install", b"r1/rust-hello@1.0.0"], &paths);
    assert_eq!(code, 0, "install rust-hello: {out}");
    assert_eq!(
        probe_read_all(&mut k, "/usr/bin/rust-hello").as_deref(),
        Some(RUSTHELLO_ELF),
        "the installed rust-hello must be the packed rustc ELF, byte-exact"
    );
    assert!(
        aegis_os::elf::build_exec_plan(RUSTHELLO_ELF).is_ok(),
        "the third citizen must parse as a genuine exec image"
    );
    let (code, out) = pm_cli(&mut k, &[b"list"], &paths);
    assert_eq!(code, 0, "list after rust-hello: {out}");
    assert!(
        out.contains("r1/rust-hello 1.0.0"),
        "the record must say r1/rust-hello 1.0.0: {out}"
    );
}
