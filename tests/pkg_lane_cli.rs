//! K22 end-to-end on the host: the REAL `run_cli("install")` against
//! the REAL kernel, through the REAL pkg-mkrepo fixture bytes.
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
//! install with the payload byte-exact at its destination.

use aegis_os::prelude::*;
use aegis_os::sys::{SysError, SysValue};
use aegis_os::vfs::VfsError;
use aegis_pkg::cli::run_cli;
use aegis_pkg::database::PkgPaths;
use aegis_pkg::error::{Errno, Error, ErrorKind};
use aegis_pkg::{FileKind, Fs, OpenFlags, Path, Stat};

const PROBE: u32 = 71;
const PM: u32 = 70;

/// The REAL fixture bytes (boot.sh step [0e] builds them; the same
/// files the kernel's K22 lane embeds).
static TRUST: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/trust");
static REPO_CFG: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.repo");
static INDEX: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/index.aki");
static PACKAGE: &[u8] = include_bytes!("../kernel-x86_64/blob/pkg-fixture/r1.hello.akp");

fn kernel_with_fixture() -> Kernel {
    let mut k = Kernel::new();
    k.create_domain_with(PROBE, service_profile(), 0, 100, 0)
        .unwrap();
    k.create_domain_with(PM, aegis_os::profile::pkg_caller_profile(), 1070, 100, 0)
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
        ("/r1/index.aki", INDEX),
        ("/r1/r1.hello.akp", PACKAGE),
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
    let mut fs = KernelFs { k: &mut k, dom: PM };
    let paths = PkgPaths::new(b"/pkg").unwrap();
    let mut out = String::new();
    let code = run_cli(&[b"install", b"r1/hello"], &mut fs, &paths, None, &mut out);
    println!("cli said (exit {code}): {out}");
    assert_eq!(code, 0, "the real install failed: {out}");

    // The tree, read back through the root supervisor.
    let Ok(SysValue::Fd(fd)) = k.syscall(
        PROBE,
        SysRequest::Open {
            path: "/usr/bin/pkg-hello",
            mode: Mode(0),
            create: false,
            read: true,
            write: false,
            truncate: false,
            excl: false,
        },
    ) else {
        panic!("the payload file must exist at /usr/bin/pkg-hello");
    };
    let mut buf = [0u8; 64];
    match k.syscall(PROBE, SysRequest::Read { fd, buf: &mut buf }) {
        Ok(SysValue::Count(n)) => assert_eq!(&buf[..n], b"hello world\n"),
        other => panic!("payload read answered {other:?}"),
    }
    let _ = k.syscall(PROBE, SysRequest::Close { fd });
}
