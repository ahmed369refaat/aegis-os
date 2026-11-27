//! The `pkg` binary entry point.
//!
//! Two shapes:
//!
//! * **Host** (development, testing, repo tooling): a normal `main`
//!   that parses `std::env::args()` and runs the CLI over a
//!   host-filesystem adapter sandboxed under `./pkg-root` (or
//!   `$PKG_ROOT`).
//! * **AegisOS target** (`x86_64-unknown-none`): `#![no_main]`, a
//!   `_start` shim that reads the SysV initial stack the kernel's
//!   execve builds (`[rsp] = argc`, then the argv vector), a panic
//!   handler that exits via `SYS_EXIT`, and the syscall adapter
//!   (`target_abi`) — see BUILD.md for the mask and the wiring.
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
            if flags.has(OpenFlags::DIRECTORY) && !real.is_dir() {
                return Err(io_err(std::io::Error::from(std::io::ErrorKind::NotFound)));
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

// ── AegisOS target: the syscall adapter (K22) ──
//
// Compiled for the target AND for the host test build. The half that
// can be wrong — the open-flag translation, the one-page chunking, the
// errno mapping — is pure over the `Io` port below, so the host tests
// at the end of this file drive the REAL adapter against a fake kernel
// that enforces the kernel's actual bounds.
#[cfg(any(target_os = "none", test))]
mod target_abi {
    use aegis_pkg::error::{Errno, Error, ErrorKind};
    use aegis_pkg::{FileKind, Fs, OpenFlags, Path, Stat};

    /// The kernel's syscall numbers (aegis-os/src/syscall.rs).
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_READ: u64 = 0;
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_WRITE: u64 = 1;
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_OPEN: u64 = 2;
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_CLOSE: u64 = 3;
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_MKDIR: u64 = 16;
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_UNLINK: u64 = 17;
    /// list_dir(fd, buf): NUL-separated names + count (the kernel's
    /// getdents64 subset; Linux 259 maps here). The fd is a listing
    /// cursor: 0 bytes = end.
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_LISTDIR: u64 = 32;
    /// stat(2): the 24-byte metadata struct (K21 — landed).
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_STAT: u64 = 34;
    /// rename(2): the atomic re-parent (K21 — landed).
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_RENAME: u64 = 35;
    #[cfg_attr(not(target_os = "none"), allow(dead_code))]
    pub const SYS_EXIT: u64 = 63;

    /// The kernel's INTERNAL open(2) flag word (`sysabi.rs`) — not
    /// Linux's, and not this crate's `OpenFlags` bits: O_RDONLY is the
    /// PRESENCE of `O_READ` here (0 would be "no access at all").
    pub const O_READ: u64 = 0x1;
    pub const O_WRITE: u64 = 0x2;
    pub const O_CREAT: u64 = 0x4;
    pub const O_TRUNC: u64 = 0x8;
    pub const O_EXCL: u64 = 0x10;

    /// The permission bits a created file gets (the crate's reference
    /// Fs creates 0o644; setuid/setgid are never expected).
    pub const FILE_MODE: u64 = 0o644;

    /// The stat(2) contract: kind u8 @0, size u64 LE @8, perm u16 LE @16.
    pub const STAT_SIZE: usize = 24;

    /// The kernel answers at most ONE PAGE per read / write / listdir
    /// (`MAX_READ` / `MAX_WRITE` = 4096; a longer call is `-EINVAL`).
    /// Every buffer the manager hands over is chunked to this.
    pub const IO_CHUNK: usize = 4096;

    /// The kernel port: one typed call per syscall the manager speaks.
    /// `path` slices arrive NUL-terminated (`Path::to_cstr` built
    /// them). The real port is the `syscall` instruction; the host
    /// tests answer from a fake that enforces the kernel's bounds.
    pub trait Io {
        /// SYS_OPEN(path, flags, mode) → fd or `-errno`.
        fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> i64;
        /// SYS_READ(fd, buf) → count (0 = EOF) or `-errno`.
        fn read(&mut self, fd: u32, buf: &mut [u8]) -> i64;
        /// SYS_WRITE(fd, bytes) → count or `-errno`.
        fn write(&mut self, fd: u32, bytes: &[u8]) -> i64;
        /// SYS_CLOSE(fd) → 0 or `-errno`.
        fn close(&mut self, fd: u32) -> i64;
        /// SYS_STAT(path, out) → 0 (the 24 bytes land in `out`) or `-errno`.
        fn stat(&mut self, path: &[u8], out: &mut [u8; STAT_SIZE]) -> i64;
        /// SYS_MKDIR(path) → 0 or `-errno`.
        fn mkdir(&mut self, path: &[u8]) -> i64;
        /// SYS_UNLINK(path) → 0 or `-errno`.
        fn unlink(&mut self, path: &[u8]) -> i64;
        /// SYS_RENAME(from, to) → 0 or `-errno`.
        fn rename(&mut self, from: &[u8], to: &[u8]) -> i64;
        /// SYS_LISTDIR(fd, buf) → count (0 = end) or `-errno`.
        fn listdir(&mut self, fd: u32, buf: &mut [u8]) -> i64;
    }

    /// Map a kernel `-errno` (the `errno_of` table in sysabi.rs) onto
    /// the crate's errno family.
    pub fn errno_of(ret: i64) -> Error {
        // kernel convention: negative errno in the return value
        let eno = u32::try_from(-ret).unwrap_or(0);
        let e = match eno {
            1 | 13 => ErrorKind::Io(Errno::Access),
            2 => ErrorKind::Io(Errno::NoEnt),
            9 => ErrorKind::Io(Errno::Io),
            12 => ErrorKind::Io(Errno::NoSpace),
            17 => ErrorKind::Io(Errno::Exists),
            20 => ErrorKind::Io(Errno::NotDir),
            21 => ErrorKind::Io(Errno::IsDir),
            22 => ErrorKind::Io(Errno::Io),
            28 => ErrorKind::Io(Errno::NoSpace),
            36 => ErrorKind::Io(Errno::Io),
            39 => ErrorKind::Io(Errno::NotEmpty),
            _ => ErrorKind::Io(Errno::Io),
        };
        Error::new(e, "syscall")
    }

    /// Translate the crate's `OpenFlags` into the kernel's internal
    /// open(2) word. The crate's contract is four shapes; the kernel
    /// wants a 5-bit word:
    ///
    /// | crate flags                  | kernel word                        |
    /// | ---------------------------- | ---------------------------------- |
    /// | `RDONLY` (+ `DIRECTORY`)     | `O_READ`                           |
    /// | `WRONLY`                     | `O_WRITE \| O_TRUNC`               |
    /// | `WRONLY \| CREATE`           | `O_WRITE \| O_TRUNC \| O_CREAT`    |
    /// | `WRONLY \| CREATE \| EXCL`   | `O_WRITE \| O_CREAT \| O_EXCL`     |
    ///
    /// `WRONLY` truncates (the documented "truncate on open"); `EXCL`
    /// implies `O_CREAT` (the kernel refuses `O_EXCL` without it —
    /// POSIX leaves that combination undefined) and answers `-EEXIST`
    /// for ANY existing path before the truncate flag is ever read.
    /// `DIRECTORY` is not a kernel bit: a directory OPENS for read and
    /// the fd's target is the directory itself (what `listdir` walks).
    #[must_use]
    pub fn kernel_open_flags(flags: OpenFlags) -> u64 {
        if !flags.has(OpenFlags::WRONLY) {
            return O_READ;
        }
        if flags.has(OpenFlags::EXCL) {
            return O_WRITE | O_CREAT | O_EXCL;
        }
        if flags.has(OpenFlags::CREATE) {
            return O_WRITE | O_TRUNC | O_CREAT;
        }
        O_WRITE | O_TRUNC
    }

    /// Decode the kernel's 24-byte stat record.
    #[must_use]
    pub fn parse_stat(out: &[u8; STAT_SIZE]) -> Stat {
        let kind = match out[0] {
            0 => FileKind::File,
            1 => FileKind::Dir,
            2 => FileKind::Symlink,
            _ => FileKind::Other,
        };
        let mut size_b = [0u8; 8];
        size_b.copy_from_slice(&out[8..16]);
        Stat {
            kind,
            size: u64::from_le_bytes(size_b),
            perm: u16::from_le_bytes([out[16], out[17]]),
        }
    }

    /// The manager's filesystem on AegisOS: the least-privilege surface
    /// from BUILD.md, spoken through an [`Io`] port.
    ///
    /// Every buffer crosses in pages: the kernel refuses a read, a
    /// write or a listing longer than [`IO_CHUNK`] with `-EINVAL`, and
    /// the crate's own streaming buffers are bigger than that (the
    /// repository fetch hands over 8 KiB chunks).
    pub struct SysFs<I: Io> {
        io: I,
    }

    impl<I: Io> SysFs<I> {
        /// A filesystem over `io`.
        pub const fn new(io: I) -> Self {
            SysFs { io }
        }

        /// The port back (the tests read the call log out of it).
        #[cfg(test)]
        pub fn into_inner(self) -> I {
            self.io
        }

        fn open_path(&mut self, path: &Path, flags: OpenFlags) -> aegis_pkg::Result<i64> {
            let mut buf = [0u8; 257];
            let n = path.to_cstr(&mut buf)?;
            Ok(self
                .io
                .open(&buf[..=n], kernel_open_flags(flags), FILE_MODE))
        }

        fn path_call(
            &mut self,
            path: &Path,
            f: impl FnOnce(&mut I, &[u8]) -> i64,
        ) -> aegis_pkg::Result<()> {
            let mut buf = [0u8; 257];
            let n = path.to_cstr(&mut buf)?;
            let ret = f(&mut self.io, &buf[..=n]);
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }
    }

    /// `ret` is a count answer: negative is an errno, and a count is
    /// never longer than the buffer it was asked to fill.
    fn count_of(ret: i64, want: usize) -> aegis_pkg::Result<usize> {
        if ret < 0 {
            return Err(errno_of(ret));
        }
        Ok((ret as usize).min(want))
    }

    impl<I: Io> Fs for SysFs<I> {
        fn open(&mut self, path: &Path, flags: OpenFlags) -> aegis_pkg::Result<u32> {
            let ret = self.open_path(path, flags)?;
            if ret < 0 {
                return Err(errno_of(ret));
            }
            Ok(ret as u32)
        }

        /// Page-chunked: fills `buf` across as many kernel calls as it
        /// takes. A short answer is asked again — only a 0 ends the fill
        /// (EOF) — so a kernel that serves a page or less at a time
        /// still hands the caller whole buffers.
        fn read(&mut self, fd: u32, buf: &mut [u8]) -> aegis_pkg::Result<usize> {
            let mut total = 0usize;
            while total < buf.len() {
                let want = (buf.len() - total).min(IO_CHUNK);
                let ret = self.io.read(fd, &mut buf[total..total + want]);
                if ret < 0 {
                    // Bytes already gathered are returned; the caller
                    // retries and meets the errno on the next call.
                    return if total == 0 {
                        Err(errno_of(ret))
                    } else {
                        Ok(total)
                    };
                }
                if ret == 0 {
                    break; // EOF
                }
                total += (ret as usize).min(want);
            }
            Ok(total)
        }

        /// Page-chunked: writes the whole buffer, page by page. A
        /// failure after the first page answers with the bytes written
        /// so far — the trait's "short writes are retried by the
        /// caller" rule.
        fn write(&mut self, fd: u32, buf: &[u8]) -> aegis_pkg::Result<usize> {
            let mut total = 0usize;
            while total < buf.len() {
                let want = (buf.len() - total).min(IO_CHUNK);
                let ret = self.io.write(fd, &buf[total..total + want]);
                if ret <= 0 {
                    return if total > 0 {
                        Ok(total)
                    } else if ret < 0 {
                        Err(errno_of(ret))
                    } else {
                        // A zero-length answer makes no progress: fail
                        // rather than spin on a kernel that answers 0.
                        Err(Error::new(ErrorKind::Io(Errno::Io), "zero write"))
                    };
                }
                total += (ret as usize).min(want);
            }
            Ok(total)
        }

        fn close(&mut self, fd: u32) -> aegis_pkg::Result<()> {
            let ret = self.io.close(fd);
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }

        fn sync(&mut self, _fd: u32) -> aegis_pkg::Result<()> {
            // The AegisOS VFS is write-through; fsync is a documented
            // no-op here (BUILD.md). The contract stays so a cached VFS
            // later becomes correct without touching this crate.
            Ok(())
        }

        fn stat(&mut self, path: &Path) -> aegis_pkg::Result<Stat> {
            let mut buf = [0u8; 257];
            let n = path.to_cstr(&mut buf)?;
            let mut out = [0u8; STAT_SIZE];
            let ret = self.io.stat(&buf[..=n], &mut out);
            if ret < 0 {
                return Err(errno_of(ret));
            }
            Ok(parse_stat(&out))
        }

        fn mkdir(&mut self, path: &Path) -> aegis_pkg::Result<()> {
            self.path_call(path, Io::mkdir)
        }

        fn unlink(&mut self, path: &Path) -> aegis_pkg::Result<()> {
            self.path_call(path, Io::unlink)
        }

        fn rename(&mut self, from: &Path, to: &Path) -> aegis_pkg::Result<()> {
            let mut b1 = [0u8; 257];
            let mut b2 = [0u8; 257];
            let n1 = from.to_cstr(&mut b1)?;
            let n2 = to.to_cstr(&mut b2)?;
            let ret = self.io.rename(&b1[..=n1], &b2[..=n2]);
            if ret < 0 {
                Err(errno_of(ret))
            } else {
                Ok(())
            }
        }

        /// One page per call: the names are whole NUL-terminated
        /// strings on both sides of a page edge (the kernel's listing
        /// cursor advances per name), and the contract's "0 = end"
        /// arrives on the call after the last name.
        fn getdents(&mut self, fd: u32, out: &mut [u8]) -> aegis_pkg::Result<usize> {
            let n = out.len().min(IO_CHUNK);
            let ret = self.io.listdir(fd, &mut out[..n]);
            count_of(ret, n)
        }
    }
}

// ── AegisOS target: the real port, the entry, the panic handler ──

#[cfg(target_os = "none")]
mod target_main {
    use super::target_abi::*;

    /// The real kernel port: the `syscall` instruction. Register order
    /// follows the kernel's ABI: rdi, rsi, rdx, the number in rax.
    pub struct Syscall;

    impl Io for Syscall {
        fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe { raw(SYS_OPEN, path.as_ptr() as u64, flags, mode) }
        }
        fn read(&mut self, fd: u32, buf: &mut [u8]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe {
                raw(
                    SYS_READ,
                    u64::from(fd),
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                )
            }
        }
        fn write(&mut self, fd: u32, bytes: &[u8]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe {
                raw(
                    SYS_WRITE,
                    u64::from(fd),
                    bytes.as_ptr() as u64,
                    bytes.len() as u64,
                )
            }
        }
        fn close(&mut self, fd: u32) -> i64 {
            // SAFETY: scalars only.
            unsafe { raw(SYS_CLOSE, u64::from(fd), 0, 0) }
        }
        fn stat(&mut self, path: &[u8], out: &mut [u8; STAT_SIZE]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe { raw(SYS_STAT, path.as_ptr() as u64, out.as_mut_ptr() as u64, 0) }
        }
        fn mkdir(&mut self, path: &[u8]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe { raw(SYS_MKDIR, path.as_ptr() as u64, 0, 0) }
        }
        fn unlink(&mut self, path: &[u8]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe { raw(SYS_UNLINK, path.as_ptr() as u64, 0, 0) }
        }
        fn rename(&mut self, from: &[u8], to: &[u8]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe { raw(SYS_RENAME, from.as_ptr() as u64, to.as_ptr() as u64, 0) }
        }
        fn listdir(&mut self, fd: u32, buf: &mut [u8]) -> i64 {
            // SAFETY: the slice is this method's own argument — a
            // valid pointer/length pair for exactly this call.
            unsafe {
                raw(
                    SYS_LISTDIR,
                    u64::from(fd),
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                )
            }
        }
    }

    /// Raw syscall. Register order follows the kernel's ABI: rdi,
    /// rsi, rdx, with the number in rax.
    ///
    /// # Safety
    /// The kernel validates every user pointer; the caller must pass
    /// buffers that are valid for the given length. Every call site
    /// is an `Io` method handing over one of its own slices.
    #[inline]
    pub(super) unsafe fn raw(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
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
            let mut io = Syscall;
            while self.len > 0 {
                let n = match io.write(1, &self.buf[..self.len]) {
                    n if n > 0 => n as usize,
                    _ => break,
                };
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

// The process entry. The kernel's execve enters the image at
// `_start` with the SysV initial stack: `[rsp] = argc`, then the
// argv pointers, NULL. A plain `extern "C"` Rust function cannot
// read its arguments there (they arrive on the stack, not in
// registers) — this shim does, aligns the stack, calls `pkg_main`,
// and exits with its answer. It never returns.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "    mov rdi, [rsp]",     // argc
    "    lea rsi, [rsp + 8]", // argv
    "    xor ebp, ebp",       // the outermost frame
    "    and rsp, -16",       // the SysV call boundary
    "    call pkg_main",
    "    mov edi, eax", // the exit code
    "    mov eax, 63",  // SYS_EXIT
    "    syscall",
    "    ud2",
);

/// The CLI over the kernel's filesystem. `argc`/`argv` are the execve
/// arguments (each at most 127 bytes — the kernel's own argv bound is
/// a path); a longer one is truncated, never read past.
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn pkg_main(argc: i32, argv: *const *const u8) -> i32 {
    let mut storage: [[u8; 128]; 16] = [[0; 128]; 16];
    let mut lens = [0usize; 16];
    let n = (argc.max(0) as usize).min(16);
    for i in 0..n {
        // SAFETY: the execve contract — `argv` holds `argc` pointers
        // to NUL-terminated strings inside this address space.
        let p = unsafe { *argv.add(i) };
        let mut j = 0usize;
        while j < 127 {
            // SAFETY: NUL-terminated by the contract above.
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
        let end = lens[i];
        refs[i] = &storage[i][..end];
    }
    let mut fs = target_abi::SysFs::new(target_main::Syscall);
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
    unsafe { target_main::raw(target_abi::SYS_EXIT, 134, 0, 0) };
    loop {}
}

// ── host tests for the adapter's pure half ──

#[cfg(test)]
mod target_abi_tests {
    use super::target_abi::*;
    use aegis_pkg::error::{Errno, ErrorKind};
    use aegis_pkg::{Fs, OpenFlags, Path};
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// A fake kernel with the REAL bounds: a call longer than a page
    /// is `-EINVAL` before anything is served, a read answers at most
    /// `short` bytes at a time (the kernel may answer short), and the
    /// log records every call's length.
    struct FakeKernel {
        file: Vec<u8>,
        cursor: usize,
        written: Vec<u8>,
        short: usize,
        max_len_seen: usize,
        calls: usize,
        pending_err: VecDeque<i64>,
        dir_names: Vec<u8>,
        last_open: (u64, u64),
        last_path: Vec<u8>,
    }

    const EINVAL: i64 = -22;

    impl FakeKernel {
        fn new(file: &[u8], short: usize) -> Self {
            FakeKernel {
                file: file.to_vec(),
                cursor: 0,
                written: Vec::new(),
                short,
                max_len_seen: 0,
                calls: 0,
                pending_err: VecDeque::new(),
                dir_names: b"alpha\0beta\0".to_vec(),
                last_open: (u64::MAX, u64::MAX),
                last_path: Vec::new(),
            }
        }
    }

    impl Io for FakeKernel {
        fn open(&mut self, path: &[u8], flags: u64, mode: u64) -> i64 {
            self.last_path = path.to_vec();
            self.last_open = (flags, mode);
            3
        }
        fn read(&mut self, _fd: u32, buf: &mut [u8]) -> i64 {
            self.calls += 1;
            self.max_len_seen = self.max_len_seen.max(buf.len());
            if buf.len() > IO_CHUNK {
                return EINVAL;
            }
            if let Some(e) = self.pending_err.pop_front() {
                return e;
            }
            let n = (self.file.len() - self.cursor)
                .min(buf.len())
                .min(self.short);
            buf[..n].copy_from_slice(&self.file[self.cursor..self.cursor + n]);
            self.cursor += n;
            n as i64
        }
        fn write(&mut self, _fd: u32, bytes: &[u8]) -> i64 {
            self.calls += 1;
            self.max_len_seen = self.max_len_seen.max(bytes.len());
            if bytes.len() > IO_CHUNK {
                return EINVAL;
            }
            if let Some(e) = self.pending_err.pop_front().filter(|e| *e < 0) {
                return e;
            }
            self.written.extend_from_slice(bytes);
            bytes.len() as i64
        }
        fn close(&mut self, _fd: u32) -> i64 {
            0
        }
        fn stat(&mut self, _path: &[u8], out: &mut [u8; STAT_SIZE]) -> i64 {
            out[0] = 1;
            out[8] = 0x10;
            out[16] = 0xed;
            out[17] = 0x01;
            0
        }
        fn mkdir(&mut self, _path: &[u8]) -> i64 {
            0
        }
        fn unlink(&mut self, _path: &[u8]) -> i64 {
            0
        }
        fn rename(&mut self, _from: &[u8], _to: &[u8]) -> i64 {
            0
        }
        fn listdir(&mut self, _fd: u32, buf: &mut [u8]) -> i64 {
            self.calls += 1;
            self.max_len_seen = self.max_len_seen.max(buf.len());
            if buf.len() > IO_CHUNK {
                return EINVAL;
            }
            if self.dir_names.is_empty() {
                return 0;
            }
            let n = self.dir_names.len().min(buf.len());
            buf[..n].copy_from_slice(&self.dir_names[..n]);
            self.dir_names.drain(..n);
            n as i64
        }
    }

    fn path(p: &[u8]) -> Path {
        Path::from_bytes(p).expect("valid path")
    }

    /// The flag translation is the whole table from the doc comment.
    #[test]
    fn open_flags_translate_to_the_kernel_word() {
        assert_eq!(kernel_open_flags(OpenFlags::RDONLY), O_READ);
        assert_eq!(
            kernel_open_flags(OpenFlags::RDONLY | OpenFlags::DIRECTORY),
            O_READ
        );
        assert_eq!(kernel_open_flags(OpenFlags::WRONLY), O_WRITE | O_TRUNC);
        assert_eq!(
            kernel_open_flags(OpenFlags::WRONLY | OpenFlags::CREATE),
            O_WRITE | O_TRUNC | O_CREAT
        );
        assert_eq!(
            kernel_open_flags(OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL),
            O_WRITE | O_CREAT | O_EXCL
        );
        // EXCL on its own still creates (the kernel refuses O_EXCL
        // without O_CREAT — POSIX-undefined).
        assert_eq!(
            kernel_open_flags(OpenFlags::WRONLY | OpenFlags::EXCL),
            O_WRITE | O_CREAT | O_EXCL
        );
        // Nothing outside the kernel's known word (0x1F).
        for f in [
            OpenFlags::RDONLY,
            OpenFlags::WRONLY,
            OpenFlags::WRONLY | OpenFlags::CREATE,
            OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL,
        ] {
            assert_eq!(kernel_open_flags(f) & !0x1f, 0);
        }
    }

    /// Every kernel word decodes to what the crate meant — checked
    /// against the kernel's OWN decoder rules (sysabi.rs).
    #[test]
    fn the_kernel_decodes_the_word_back() {
        let decode = |bits: u64| {
            (
                bits & O_READ != 0,
                bits & O_WRITE != 0,
                bits & O_CREAT != 0,
                bits & O_TRUNC != 0,
                bits & O_EXCL != 0,
            )
        };
        assert_eq!(
            decode(kernel_open_flags(OpenFlags::RDONLY)),
            (true, false, false, false, false)
        );
        assert_eq!(
            decode(kernel_open_flags(OpenFlags::WRONLY)),
            (false, true, false, true, false)
        );
        assert_eq!(
            decode(kernel_open_flags(OpenFlags::WRONLY | OpenFlags::CREATE)),
            (false, true, true, true, false)
        );
        assert_eq!(
            decode(kernel_open_flags(
                OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::EXCL
            )),
            (false, true, true, false, true)
        );
    }

    /// A 10 KiB file comes back whole across three kernel calls, none
    /// longer than a page — the old adapter would have asked for all
    /// 10 KiB at once and taken `-EINVAL`.
    #[test]
    fn read_crosses_pages_and_never_exceeds_the_kernel_bound() {
        let file: Vec<u8> = (0..10 * 1024).map(|i| (i % 251) as u8).collect();
        let mut fs = SysFs::new(FakeKernel::new(&file, usize::MAX));
        let mut got = vec![0u8; 10 * 1024];
        let n = fs.read(3, &mut got).expect("read");
        assert_eq!(n, file.len());
        assert_eq!(got, file);
        let k = fs.into_inner();
        assert_eq!(k.calls, 3, "two pages and the 2 KiB tail");
        assert_eq!(k.max_len_seen, IO_CHUNK, "no call longer than a page");
    }

    /// A short-reading kernel (a page or less at a time) still hands
    /// the caller whole buffers: the adapter keeps asking.
    #[test]
    fn a_short_kernel_read_still_fills_the_buffer() {
        let file: Vec<u8> = (0..6000).map(|i| (i % 7) as u8).collect();
        let mut fs = SysFs::new(FakeKernel::new(&file, 1000));
        let mut got = vec![0u8; 6000];
        let n = fs.read(3, &mut got).expect("read");
        assert_eq!(n, 6000);
        assert_eq!(got, file);
        assert_eq!(fs.into_inner().calls, 6);
    }

    /// EOF: the last page ends short, and the next read answers 0.
    #[test]
    fn eof_answers_zero_and_a_short_tail_is_the_callers_signal() {
        let mut fs = SysFs::new(FakeKernel::new(&[7u8; 5000], usize::MAX));
        let mut got = vec![0u8; 8192];
        assert_eq!(fs.read(3, &mut got).expect("read"), 5000);
        assert_eq!(fs.read(3, &mut got).expect("read"), 0);
    }

    /// An 8 KiB chunk (the repository fetch's size) goes out in two
    /// pages; a failure on the second page answers with the first.
    #[test]
    fn write_crosses_pages_and_reports_partial_progress() {
        let data: Vec<u8> = (0..8192).map(|i| (i % 13) as u8).collect();
        let mut fs = SysFs::new(FakeKernel::new(&[], usize::MAX));
        assert_eq!(fs.write(4, &data).expect("write"), 8192);
        let k = fs.into_inner();
        assert_eq!(k.written, data);
        assert_eq!(k.calls, 2);
        assert_eq!(k.max_len_seen, IO_CHUNK);

        let mut k = FakeKernel::new(&[], usize::MAX);
        k.pending_err.push_back(1); // page one goes through
        k.pending_err.push_back(-28); // page two hits the wall
        let mut fs = SysFs::new(k);
        assert_eq!(fs.write(4, &data).expect("short write"), IO_CHUNK);
    }

    /// A write that fails on its very first page is the errno.
    #[test]
    fn a_first_page_failure_is_the_errno() {
        let mut k = FakeKernel::new(&[], usize::MAX);
        k.pending_err.push_back(-28);
        let mut fs = SysFs::new(k);
        let e = fs.write(4, &[1u8; 100]).expect_err("no space");
        assert!(format!("{e:?}").contains("NoSpace"), "{e:?}");
        // And a read that fails with nothing gathered yet.
        let mut k = FakeKernel::new(&[], usize::MAX);
        k.pending_err.push_back(-9);
        let mut fs = SysFs::new(k);
        assert!(fs.read(3, &mut [0u8; 10]).is_err());
    }

    /// The errno family the manager acts on: EEXIST is the lock
    /// primitive, ENOSPC triggers the rollback, ENOENT is a plain miss.
    #[test]
    fn the_kernel_errnos_map_onto_the_crate_family() {
        let kind = |ret: i64| match errno_of(ret).kind() {
            ErrorKind::Io(e) => e,
            other => panic!("expected an Io error, got {other:?}"),
        };
        assert!(matches!(kind(-17), Errno::Exists));
        assert!(matches!(kind(-28), Errno::NoSpace));
        assert!(matches!(kind(-2), Errno::NoEnt));
        assert!(matches!(kind(-13), Errno::Access));
        assert!(matches!(kind(-20), Errno::NotDir));
        assert!(matches!(kind(-21), Errno::IsDir));
        assert!(matches!(kind(-39), Errno::NotEmpty));
        assert!(
            matches!(kind(-1), Errno::Access),
            "EPERM is a permission refusal too"
        );
        assert!(matches!(kind(-9999), Errno::Io));
    }

    /// The listing: one page per call, the names arrive whole, 0
    /// ends.
    #[test]
    fn getdents_is_one_page_and_zero_ends_it() {
        let mut fs = SysFs::new(FakeKernel::new(&[], usize::MAX));
        let mut out = [0u8; 8192];
        let n = fs.getdents(5, &mut out).expect("listdir");
        assert_eq!(&out[..n], b"alpha\0beta\0");
        assert_eq!(fs.getdents(5, &mut out).expect("listdir"), 0);
        let k = fs.into_inner();
        assert_eq!(
            k.max_len_seen, IO_CHUNK,
            "an 8 KiB buffer is still one page per call"
        );
    }

    /// Paths cross NUL-terminated and carry the translated word.
    #[test]
    fn open_passes_a_nul_terminated_path_and_the_word() {
        let k = FakeKernel::new(&[], usize::MAX);
        let mut fs = SysFs::new(k);
        let fd = fs
            .open(
                &path(b"/pkg/db/installed"),
                OpenFlags::WRONLY | OpenFlags::CREATE,
            )
            .expect("open");
        assert_eq!(fd, 3);
        let k = fs.into_inner();
        assert_eq!(k.last_path, b"/pkg/db/installed\0".to_vec());
        assert_eq!(k.last_open, (O_WRITE | O_TRUNC | O_CREAT, 0o644));
        let mut fs = SysFs::new(FakeKernel::new(&[], usize::MAX));
        fs.open(
            &path(b"/pkg/repos"),
            OpenFlags::RDONLY | OpenFlags::DIRECTORY,
        )
        .expect("open dir");
        let k = fs.into_inner();
        assert_eq!(k.last_open, (O_READ, 0o644));
    }

    /// The 24-byte stat record decodes: kind, size, perm.
    #[test]
    fn stat_decodes_the_kernel_record() {
        let mut fs = SysFs::new(FakeKernel::new(&[], usize::MAX));
        let st = fs.stat(&path(b"/pkg")).expect("stat");
        assert_eq!(st.kind, aegis_pkg::FileKind::Dir);
        assert_eq!(st.size, 0x10);
        assert_eq!(st.perm, 0o755);
    }
}
