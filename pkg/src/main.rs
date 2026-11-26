//! The `pkg` binary entry point.
//!
//! Two shapes:
//!
//! * **Host** (development, testing, repo tooling): a normal `main`
//!   that parses `std::env::args()` and runs the CLI over a
//!   host-filesystem adapter sandboxed under `./pkg-root` (or
//!   `$PKG_ROOT`).
//! * **AegisOS target** (`x86_64-unknown-none`): `#![no_main]`, a
//!   panic handler that exits via `SYS_EXIT`, and a `pkg_main`
//!   entry the boot image calls with the argument vector. The
//!   filesystem adapter is the raw syscall surface (see BUILD.md
//!   for the mask and the K21 wiring points).
//!
//! The library stays `no_std`; only this file knows about `std`,
//! and only on the host cfg.

// the binary is no_std ONLY for the AegisOS target; the host build
// is a normal std binary (the library keeps its own no_std gate)
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

// ── host build ──

#[cfg(not(target_os = "none"))]
mod host_main {
    use aegis_pkg::error::{Errno, Error, ErrorKind};
    use aegis_pkg::{FileKind, Fs, OpenFlags, Path, Stat};

    /// Host filesystem adapter: implements the crate's `Fs` trait
    /// over `std::fs`, rooted at a sandbox directory so the host
    /// binary cannot scribble outside its root by accident.
    struct StdFs {
        root: std::path::PathBuf,
    }

    impl StdFs {
        fn new() -> Self {
            let root = std::env::var("PKG_ROOT").unwrap_or_else(|_| "./pkg-root".into());
            let p = std::path::PathBuf::from(root);
            let _ = std::fs::create_dir_all(&p);
            StdFs { root: p }
        }

        fn real(&self, p: &Path) -> std::path::PathBuf {
            // crate paths are validated absolute paths; joining them
            // under the sandbox root is traversal-safe by construction
            let s = String::from_utf8_lossy(p.as_bytes()).into_owned();
            self.root.join(s.trim_start_matches('/'))
        }
    }

    fn io_err(e: std::io::Error) -> Error {
        let eno = match e.kind() {
            std::io::ErrorKind::NotFound => Errno::NoEnt,
            std::io::ErrorKind::AlreadyExists => Errno::Exists,
            std::io::ErrorKind::PermissionDenied => Errno::Access,
            std::io::ErrorKind::DirectoryNotEmpty => Errno::NotEmpty,
            _ => Errno::Io,
        };
        Error::new(ErrorKind::Io(eno), &e.to_string())
    }

    fn fd_of(e: &std::io::Error) -> Error {
        io_err(std::io::Error::from(e.kind()))
    }

    impl Fs for StdFs {
        fn open(&mut self, path: &Path, flags: OpenFlags) -> aegis_pkg::Result<u32> {
            use std::io::Write;
            let real = self.real(path);
            let mut opts = std::fs::OpenOptions::new();
            if flags.has(OpenFlags::WRONLY) {
                opts.write(true);
                if flags.has(OpenFlags::CREATE) {
                    opts.create(true);
                }
                if flags.has(OpenFlags::EXCL) {
                    opts.create_new(true);
                }
                if !flags.has(OpenFlags::CREATE) && !flags.has(OpenFlags::EXCL) {
                    opts.truncate(true);
                }
            } else {
                opts.read(true);
            }
            if flags.has(OpenFlags::DIRECTORY) {
                if !real.is_dir() {
                    return Err(io_err(std::io::Error::from(std::io::ErrorKind::NotFound)));
                }
            }
            let f = opts.open(&real).map_err(io_err)?;
            let fd = next_fd();
            fd_table().lock().unwrap().insert(fd, f);
            if flags.has(OpenFlags::DIRECTORY) {
                path_table().lock().unwrap().insert(fd, real);
            }
            Ok(fd)
        }

        fn read(&mut self, fd: u32, buf: &mut [u8]) -> aegis_pkg::Result<usize> {
            use std::io::Read;
            let mut table = fd_table().lock().unwrap();
            match table.get_mut(&fd) {
                Some(f) => f.read(buf).map_err(io_err),
                None => Err(fd_of(&std::io::Error::from(std::io::ErrorKind::NotFound))),
            }
        }

        fn write(&mut self, fd: u32, buf: &[u8]) -> aegis_pkg::Result<usize> {
            use std::io::Write;
            let mut table = fd_table().lock().unwrap();
            match table.get_mut(&fd) {
                Some(f) => f.write(buf).map_err(io_err),
                None => Err(fd_of(&std::io::Error::from(std::io::ErrorKind::NotFound))),
            }
        }

        fn close(&mut self, fd: u32) -> aegis_pkg::Result<()> {
            fd_table().lock().unwrap().remove(&fd);
            path_table().lock().unwrap().remove(&fd);
            Ok(())
        }

        fn sync(&mut self, fd: u32) -> aegis_pkg::Result<()> {
            use std::io::Write;
            let mut table = fd_table().lock().unwrap();
            match table.get_mut(&fd) {
                Some(f) => f.sync_all().map_err(io_err),
                None => Err(fd_of(&std::io::Error::from(std::io::ErrorKind::NotFound))),
            }
        }

        fn stat(&mut self, path: &Path) -> aegis_pkg::Result<Stat> {
            let real = self.real(path);
            let meta = std::fs::symlink_metadata(&real).map_err(io_err)?;
            let kind = if meta.file_type().is_symlink() {
                FileKind::Symlink
            } else if meta.is_dir() {
                FileKind::Dir
            } else if meta.is_file() {
                FileKind::File
            } else {
                FileKind::Other
            };
            let perm = {
                use std::os::unix::fs::PermissionsExt;
                (meta.permissions().mode() & 0o777) as u16
            };
            Ok(Stat {
                kind,
                size: meta.len(),
                perm,
            })
        }

        fn mkdir(&mut self, path: &Path) -> aegis_pkg::Result<()> {
            std::fs::create_dir(self.real(path)).map_err(io_err)
        }

        fn unlink(&mut self, path: &Path) -> aegis_pkg::Result<()> {
            let real = self.real(path);
            match std::fs::remove_file(&real) {
                Ok(()) => Ok(()),
                Err(e) => std::fs::remove_dir(&real).map_err(|_| io_err(e)),
            }
        }

        fn rename(&mut self, from: &Path, to: &Path) -> aegis_pkg::Result<()> {
            std::fs::rename(self.real(from), self.real(to)).map_err(io_err)
        }

        fn getdents(&mut self, fd: u32, out: &mut [u8]) -> aegis_pkg::Result<usize> {
            let dir = path_table()
                .lock()
                .unwrap()
                .get(&fd)
                .cloned()
                .ok_or_else(|| fd_of(&std::io::Error::from(std::io::ErrorKind::NotFound)))?;
            let mut names: Vec<Vec<u8>> = Vec::new();
            for entry in std::fs::read_dir(&dir).map_err(io_err)? {
                let entry = entry.map_err(io_err)?;
                let mut n = entry
                    .file_name()
                    .into_string()
                    .unwrap_or_default()
                    .into_bytes();
                n.push(0);
                names.push(n);
            }
            let mut pos = 0usize;
            for n in names {
                if pos + n.len() > out.len() {
                    break;
                }
                out[pos..pos + n.len()].copy_from_slice(&n);
                pos += n.len();
            }
            Ok(pos)
        }
    }

    static FD_TABLE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u32, std::fs::File>>,
    > = std::sync::OnceLock::new();
    static PATH_TABLE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u32, std::path::PathBuf>>,
    > = std::sync::OnceLock::new();

    fn fd_table() -> &'static std::sync::Mutex<std::collections::HashMap<u32, std::fs::File>> {
        FD_TABLE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
    }

    fn path_table() -> &'static std::sync::Mutex<std::collections::HashMap<u32, std::path::PathBuf>>
    {
        PATH_TABLE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
    }

    static NEXT_FD: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(3);

    fn next_fd() -> u32 {
        NEXT_FD.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn main() {
        let args: Vec<Vec<u8>> = std::env::args().skip(1).map(|a| a.into_bytes()).collect();
        let args_ref: Vec<&[u8]> = args.iter().map(|a| a.as_slice()).collect();
        let mut fs = StdFs::new();
        let paths = aegis_pkg::database::PkgPaths::new(b"/pkg").expect("constant root path");
        let mut out = String::new();
        let code = aegis_pkg::cli::run_cli(&args_ref, &mut fs, &paths, None, &mut out);
        print!("{out}");
        std::process::exit(code);
    }
}

#[cfg(not(target_os = "none"))]
fn main() {
    host_main::main()
}

// ── AegisOS (x86_64-unknown-none) target ──

#[cfg(target_os = "none")]
mod target_main {
    use aegis_pkg::error::{Error, ErrorKind};

    /// The kernel's syscall numbers (aegis-os/src/syscall.rs).
    pub const SYS_READ: u64 = 0;
    pub const SYS_WRITE: u64 = 1;
    pub const SYS_OPEN: u64 = 2;
    pub const SYS_CLOSE: u64 = 3;
    pub const SYS_NET_SEND: u64 = 9;
    pub const SYS_NET_RECV: u64 = 10;
    pub const SYS_MKDIR: u64 = 16;
    pub const SYS_UNLINK: u64 = 17;
    pub const SYS_EXIT: u64 = 63;
    // K21 wiring points: the VFS arms the kernel still has to
    // expose for the manager's full surface (BUILD.md documents
    // these; until then these numbers are reserved).
    pub const SYS_STAT: u64 = 64;
    pub const SYS_RENAME: u64 = 65;
    pub const SYS_GETDENTS: u64 = 66;

    /// Raw syscall. Register order follows the kernel's ABI:
    /// rdi, rsi, rdx, with the number in rax.
    ///
    /// # Safety
    /// The kernel validates every user pointer; the caller must
    /// pass buffers that are valid for the given length. All call
    /// sites below pass stack arrays or validated path buffers.
    #[inline]
    pub unsafe fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
        let ret: i64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                out("rcx") _,
                out("r11") _,
            );
        }
        ret
    }

    /// The PM domain's filesystem: exactly the least-privilege
    /// surface from BUILD.md.
    pub struct SysFs;

    fn errno_of(ret: i64) -> Error {
        // kernel convention: negative errno in the return value
        let eno = u32::try_from(-ret).unwrap_or(0);
        let e = match eno {
            2 => ErrorKind::Io(aegis_pkg::error::Errno::NoEnt),
            13 => ErrorKind::Io(aegis_pkg::error::Errno::Access),
            17 => ErrorKind::Io(aegis_pkg::error::Errno::Exists),
            20 => ErrorKind::Io(aegis_pkg::error::Errno::NotDir),
            21 => ErrorKind::Io(aegis_pkg::error::Errno::IsDir),
            28 => ErrorKind::Io(aegis_pkg::error::Errno::NoSpace),
            39 => ErrorKind::Io(aegis_pkg::error::Errno::NotEmpty),
            _ => ErrorKind::Io(aegis_pkg::error::Errno::Io),
        };
        Error::new(e, "syscall")
    }

    impl aegis_pkg::Fs for SysFs {
        fn open(
            &mut self,
            path: &aegis_pkg::Path,
            flags: aegis_pkg::OpenFlags,
        ) -> aegis_pkg::Result<u32> {
            let mut buf = [0u8; 257];
            path.to_cstr(&mut buf)?;
            let mut mode: u64 = 0;
            if flags.has(aegis_pkg::OpenFlags::WRONLY) {
                mode |= 1;
            }
            if flags.has(aegis_pkg::OpenFlags::CREATE) {
                mode |= 2;
            }
            if flags.has(aegis_pkg::OpenFlags::EXCL) {
                mode |= 4;
            }
            if flags.has(aegis_pkg::OpenFlags::DIRECTORY) {
                mode |= 8;
            }
            // SAFETY: `buf` is a 257-byte stack array holding a
            // NUL-terminated, validated path; the kernel
            // bounds-checks the user pointer.
            let ret = unsafe { syscall4(SYS_OPEN, buf.as_ptr() as u64, mode, 0) };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(ret as u32)
            }
        }

        fn read(&mut self, fd: u32, buf: &mut [u8]) -> aegis_pkg::Result<usize> {
            // SAFETY: `buf` is a caller-provided slice; the kernel
            // validates the pointer/length pair.
            let ret = unsafe {
                syscall4(
                    SYS_READ,
                    u64::from(fd),
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                )
            };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(ret as usize)
            }
        }

        fn write(&mut self, fd: u32, buf: &[u8]) -> aegis_pkg::Result<usize> {
            // SAFETY: `buf` is a caller-provided immutable slice.
            let ret = unsafe {
                syscall4(
                    SYS_WRITE,
                    u64::from(fd),
                    buf.as_ptr() as u64,
                    buf.len() as u64,
                )
            };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(ret as usize)
            }
        }

        fn close(&mut self, fd: u32) -> aegis_pkg::Result<()> {
            // SAFETY: plain scalar arguments.
            let ret = unsafe { syscall4(SYS_CLOSE, u64::from(fd), 0, 0) };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }

        fn sync(&mut self, _fd: u32) -> aegis_pkg::Result<()> {
            // The AegisOS VFS is currently write-through; fsync is a
            // documented no-op here (BUILD.md). The contract stays
            // so a cached VFS later becomes correct without touching
            // this crate.
            Ok(())
        }

        fn stat(&mut self, path: &aegis_pkg::Path) -> aegis_pkg::Result<aegis_pkg::Stat> {
            let mut buf = [0u8; 257];
            path.to_cstr(&mut buf)?;
            let mut out = [0u8; 24];
            // SAFETY: both are stack arrays; the kernel validates
            // the pointers.
            let ret =
                unsafe { syscall4(SYS_STAT, buf.as_ptr() as u64, out.as_mut_ptr() as u64, 0) };
            if ret < 0 {
                return Err(errno_of(ret));
            }
            let kind = match out[0] {
                0 => aegis_pkg::FileKind::File,
                1 => aegis_pkg::FileKind::Dir,
                2 => aegis_pkg::FileKind::Symlink,
                _ => aegis_pkg::FileKind::Other,
            };
            let size = u64::from_le_bytes([
                out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15],
            ]);
            let perm = u16::from_le_bytes([out[16], out[17]]);
            Ok(aegis_pkg::Stat { kind, size, perm })
        }

        fn mkdir(&mut self, path: &aegis_pkg::Path) -> aegis_pkg::Result<()> {
            let mut buf = [0u8; 257];
            path.to_cstr(&mut buf)?;
            // SAFETY: NUL-terminated validated path buffer.
            let ret = unsafe { syscall4(SYS_MKDIR, buf.as_ptr() as u64, 0, 0) };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }

        fn unlink(&mut self, path: &aegis_pkg::Path) -> aegis_pkg::Result<()> {
            let mut buf = [0u8; 257];
            path.to_cstr(&mut buf)?;
            // SAFETY: NUL-terminated validated path buffer.
            let ret = unsafe { syscall4(SYS_UNLINK, buf.as_ptr() as u64, 0, 0) };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }

        fn rename(
            &mut self,
            from: &aegis_pkg::Path,
            to: &aegis_pkg::Path,
        ) -> aegis_pkg::Result<()> {
            let mut b1 = [0u8; 257];
            let mut b2 = [0u8; 257];
            from.to_cstr(&mut b1)?;
            to.to_cstr(&mut b2)?;
            // SAFETY: two NUL-terminated validated path buffers.
            let ret = unsafe { syscall4(SYS_RENAME, b1.as_ptr() as u64, b2.as_ptr() as u64, 0) };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }

        fn getdents(&mut self, fd: u32, out: &mut [u8]) -> aegis_pkg::Result<usize> {
            // SAFETY: caller-provided output slice.
            let ret = unsafe {
                syscall4(
                    SYS_GETDENTS,
                    u64::from(fd),
                    out.as_mut_ptr() as u64,
                    out.len() as u64,
                )
            };
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(ret as usize)
            }
        }
    }

    /// Fixed line-buffer output: the CLI writes into this; the entry
    /// flushes with SYS_WRITE(1, ...) after the run.
    pub struct OutBuf {
        buf: [u8; 4096],
        len: usize,
    }

    impl OutBuf {
        /// New empty buffer.
        pub const fn new() -> Self {
            OutBuf {
                buf: [0; 4096],
                len: 0,
            }
        }

        /// Flush to the console fd.
        pub fn flush(&mut self) {
            while self.len > 0 {
                // SAFETY: pointer/length in bounds by construction.
                let ret =
                    unsafe { syscall4(SYS_WRITE, 1, self.buf.as_ptr() as u64, self.len as u64) };
                if ret <= 0 {
                    break;
                }
                let n = ret as usize;
                self.buf.copy_within(n..self.len, 0);
                self.len -= n;
            }
        }
    }

    impl core::fmt::Write for OutBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let b = s.as_bytes();
            if self.len + b.len() > self.buf.len() {
                self.flush();
            }
            let n = b.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
            self.len += n;
            Ok(())
        }
    }
}

/// The AegisOS entry: the boot image (or a shell domain) calls
/// `pkg_main(argc, argv)` with NUL-terminated byte-string arguments.
///
/// # Safety
/// `argv` must point at `argc` NUL-terminated byte strings that
/// remain valid for the call's duration (the execve contract).
#[cfg(target_os = "none")]
#[no_mangle]
pub unsafe extern "C" fn pkg_main(argc: i32, argv: *const *const u8) -> i32 {
    let mut storage: [[u8; 128]; 16] = [[0; 128]; 16];
    let mut lens = [0usize; 16];
    let n = (argc as usize).min(16);
    for i in 0..n {
        // SAFETY: caller contract above.
        let p = unsafe { *argv.add(i) };
        let mut j = 0usize;
        while j < 127 {
            // SAFETY: NUL-terminated by contract.
            let c = unsafe { *p.add(j) };
            if c == 0 {
                break;
            }
            storage[i][j] = c;
            j += 1;
        }
        lens[i] = j;
    }
    let mut refs: [&[u8]; 16] = [b""; 16];
    for i in 0..n {
        refs[i] = &storage[i][..lens[i]];
    }
    let mut fs = target_main::SysFs;
    let paths = aegis_pkg::database::PkgPaths::new(b"/pkg")
        .unwrap_or_else(|_| aegis_pkg::database::PkgPaths::new(b"/").expect("root path"));
    let mut out = target_main::OutBuf::new();
    let code = aegis_pkg::cli::run_cli(&refs[..n], &mut fs, &paths, None, &mut out);
    out.flush();
    code
}

/// Panic handler for the freestanding target: exit loudly (134).
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: scalars only.
    unsafe { target_main::syscall4(target_main::SYS_EXIT, 134, 0, 0) };
    loop {}
}
