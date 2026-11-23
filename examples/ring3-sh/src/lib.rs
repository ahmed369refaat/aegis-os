//! aegis-sh (Phase 7, M3): the shell — a REAL ELF64 image the init
//! child execve's, speaking Linux v1 nrs only.
//!
//! The M3 exit story: init (PID 1) forks, the child execve's
//! "/bin/sh", and the shell reads the session from fd 0 (the TTY's
//! console-in alias — the IRQ-driven serial ring) and answers on
//! fd 1. The command set is the M3 contract: echo, ls (getdents64),
//! cat, mkdir, rm, cp, mv (copy-then-unlink), exit.
//!
//! Every command checks the kernel's answers; a failed syscall
//! prints the errno and exits 97 (init's wait4 turns that into a
//! loud nonzero wstatus — a red lane, never a silent lie). An idle
//! console (a lane without stdin) is NOT an error: after ~2 s of
//! quiet the shell says so and exits 0, so the base lanes stay
//! green while the shell-lane greps carry the actual command
//! proofs.
//!
//! Budget discipline: the exec cage is one page of text+rodata
//! (0x400000..0x403000) and one of data+bss (0x403000..0x404000) —
//! no formatting machinery, no core::fmt, byte-honest output, all
//! state in a few hundred bytes of bss.
#![no_std]
#![no_main]

use core::arch::asm;

/// The syscall trampoline: nr in RAX, args in RDI/RSI/RDX (RCX/R11
/// are clobbered by the instruction itself).
#[inline(always)]
fn sys3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

fn write_out(s: &[u8]) {
    let _ = sys3(1, 1, s.as_ptr() as u64, s.len() as u64);
}

fn exit(c: i64) -> ! {
    let _ = sys3(231, c as u64, 0, 0);
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // A panic in the shell is a shell bug: exit 91, loud.
    exit(91);
}



/// One command's argument list (a view into the line buffer).
const MAX_ARGS: usize = 8;

struct Cmd<'a> {
    args: [&'a [u8]; MAX_ARGS],
    n: usize,
}

fn parse(line: &[u8]) -> Cmd<'_> {
    let mut c = Cmd {
        args: [&[]; MAX_ARGS],
        n: 0,
    };
    let mut i = 0usize;
    while i < line.len() && c.n < MAX_ARGS {
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        let start = i;
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
            i += 1;
        }
        if i > start {
            c.args[c.n] = &line[start..i];
            c.n += 1;
        }
    }
    c
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// zpath: a NUL-terminated STACK copy of one path. The kernel reads
/// to the NUL, and the line buffer is reused without clearing — a
/// slice into it carries whatever the longer previous command left
/// behind ("mkdir /pub/shdir" once "succeeded" by creating
/// /pub/shdiraegis-sh, and the cp after it died on ENOENT for a
/// file the supervisor's probe could see present). One copy per
/// path, bounded by the line buffer's own 96 bytes, zeroed tail —
/// the cage budget stays honest.
const ZPATH_MAX: usize = 96;

fn zpath(src: &[u8]) -> [u8; ZPATH_MAX] {
    let mut z = [0u8; ZPATH_MAX];
    let n = src.len().min(ZPATH_MAX - 1);
    z[..n].copy_from_slice(&src[..n]);
    z
}

/// echo: the args, one space between, one newline after.
fn cmd_echo(c: &Cmd) -> bool {
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    for (i, a) in c.args[..c.n].iter().enumerate().skip(1) {
        if i > 1 && n + 1 < buf.len() {
            buf[n] = b' ';
            n += 1;
        }
        for &b in a.iter() {
            if n + 1 < buf.len() {
                buf[n] = b;
                n += 1;
            }
        }
    }
    if n < buf.len() {
        buf[n] = b'\n';
        n += 1;
    }
    write_out(b"[SH] e ");
    write_out(&buf[..n]);
    true
}

/// ls PATH: open + getdents64, the names one line.
fn cmd_ls(c: &Cmd) -> bool {
    let path = if c.n > 1 {
        c.args[1]
    } else {
        b"/"
    };
    let zp = zpath(path);
    let fd = sys3(2, zp.as_ptr() as u64, 0, 0); // O_RDONLY
    if fd < 0 {
        fail(b"ls open", path, fd);
        return false;
    }
    let mut names = [0u8; 256];
    let r = sys3(259, fd as u64, names.as_mut_ptr() as u64, names.len() as u64);
    let _ = sys3(3, fd as u64, 0, 0); // close
    if r < 0 {
        fail(b"ls getdents", path, r);
        return false;
    }
    write_out(b"[SH] l ");
    write_out(path);
    write_out(b":");
    let mut i = 0usize;
    while i < r as usize {
        let start = i;
        while i < r as usize && names[i] != 0 {
            i += 1;
        }
        if i > start {
            write_out(b" ");
            write_out(&names[start..i]);
        }
        i += 1; // the NUL
    }
    write_out(b"\n");
    true
}

/// cat PATH: the content, chunked.
fn cmd_cat(c: &Cmd) -> bool {
    if c.n < 2 {
        write_out(b"[SH] arg\n");
        return false;
    }
    let path = c.args[1];
    let zp = zpath(path);
    let fd = sys3(2, zp.as_ptr() as u64, 0, 0);
    if fd < 0 {
        fail(b"cat open", path, fd);
        return false;
    }
    write_out(b"[SH] c ");
    write_out(path);
    write_out(b": ");
    let mut chunk = [0u8; 256];
    loop {
        let r = sys3(0, fd as u64, chunk.as_mut_ptr() as u64, chunk.len() as u64);
        if r < 0 {
            fail(b"cat read", path, r);
            return false;
        }
        if r == 0 {
            break;
        }
        write_out(&chunk[..r as usize]);
    }
    write_out(b"\n");
    let _ = sys3(3, fd as u64, 0, 0);
    true
}

/// mkdir PATH.
fn cmd_mkdir(c: &Cmd) -> bool {
    if c.n < 2 {
        write_out(b"[SH] arg\n");
        return false;
    }
    let path = c.args[1];
    let zp = zpath(path);
    let r = sys3(83, zp.as_ptr() as u64, 0o755, 0);
    if r != 0 {
        fail(b"mkdir", path, r);
        return false;
    }
    ok(b"mkdir", path);
    true
}

/// rm PATH (unlink/rmdir folded — the arm's contract).
fn cmd_rm(c: &Cmd) -> bool {
    if c.n < 2 {
        write_out(b"[SH] arg\n");
        return false;
    }
    let path = c.args[1];
    let zp = zpath(path);
    let r = sys3(87, zp.as_ptr() as u64, 0, 0);
    if r != 0 {
        fail(b"rm", path, r);
        return false;
    }
    ok(b"rm", path);
    true
}

/// cp SRC DST (mv is cp + rm — the honest copy-then-unlink).
fn cmd_cp(c: &Cmd, label: &[u8]) -> bool {
    if c.n < 3 {
        write_out(b"[SH] arg\n");
        return false;
    }
    let src = c.args[1];
    let dst = c.args[2];
    let zsrc = zpath(src);
    let zdst = zpath(dst);
    let sfd = sys3(2, zsrc.as_ptr() as u64, 0, 0);
    if sfd < 0 {
        fail(b"cp open src", src, sfd);
        return false;
    }
    // O_WRONLY|O_CREAT = 0x41 (the v1-translated word).
    let dfd = sys3(2, zdst.as_ptr() as u64, 0x41, 0o644);
    if dfd < 0 {
        let _ = sys3(3, sfd as u64, 0, 0);
        fail(b"cp open dst", dst, dfd);
        return false;
    }
    let mut chunk = [0u8; 256];
    let mut total = 0usize;
    loop {
        let r = sys3(0, sfd as u64, chunk.as_mut_ptr() as u64, chunk.len() as u64);
        if r < 0 {
            fail(b"cp read", src, r);
            return false;
        }
        if r == 0 {
            break;
        }
        let w = sys3(1, dfd as u64, chunk.as_ptr() as u64, r as u64);
        if w != r {
            fail(b"cp write", dst, w);
            return false;
        }
        total += r as usize;
    }
    let _ = sys3(3, sfd as u64, 0, 0);
    let _ = sys3(3, dfd as u64, 0, 0);
    if eq(label, b"mv") {
        let r = sys3(87, zsrc.as_ptr() as u64, 0, 0);
        if r != 0 {
            fail(b"mv unlink", src, r);
            return false;
        }
    }
    write_out(b"[SH] ");
    write_out(label);
    write_out(b" ");
    write_out(src);
    write_out(b" ");
    write_out(dst);
    write_out(b" ");
    write_dec(total);
    write_out(b" bytes\n");
    true
}

fn ok(what: &[u8], path: &[u8]) {
    write_out(b"[SH] ");
    write_out(what);
    write_out(b" ");
    write_out(path);
    write_out(b": ok\n");
}

fn fail(what: &[u8], path: &[u8], e: i64) {
    write_out(b"[SH] F ");
    write_out(what);
    write_out(b" ");
    write_out(path);
    write_out(b": ");
    write_out(b" e=");
    write_dec((-e) as usize);
    write_out(b"\n");
}

/// Decimal, byte-honest (no core::fmt in the cage budget) — written
/// straight out, no static scratch anywhere.
fn write_dec(mut v: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if v == 0 {
        write_out(b"0");
        return;
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    write_out(&buf[i..]);
}

fn run_command(line: &[u8]) -> bool {
    let c = parse(line);
    if c.n == 0 {
        return true; // an empty line is not an error
    }
    let head = c.args[0];
    if eq(head, b"echo") {
        cmd_echo(&c)
    } else if eq(head, b"ls") {
        cmd_ls(&c)
    } else if eq(head, b"cat") {
        cmd_cat(&c)
    } else if eq(head, b"mkdir") {
        cmd_mkdir(&c)
    } else if eq(head, b"rm") {
        cmd_rm(&c)
    } else if eq(head, b"cp") {
        cmd_cp(&c, b"cp")
    } else if eq(head, b"mv") {
        cmd_cp(&c, b"mv")
    } else if eq(head, b"exit") {
        write_out(b"[SH] x\n");
        exit(0);
    } else {
        write_out(b"[SH] ? ");
        write_out(head);
        write_out(b"\n");
        false
    }
}

/// The idle budget: ~2 s of quiet (40 polls × 50 ms) means no
/// console session — exit clean so the lane without stdin stays
/// green (the shell-lane greps carry the command proofs).
const IDLE_POLLS: u32 = 40;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_out(b"[SH] up\n");
    let mut line = [0u8; 96];
    let mut n = 0usize;
    let mut idle = 0u32;
    loop {
        let mut b = [0u8; 1];
        let r = sys3(0, 0, b.as_mut_ptr() as u64, 1);
        if r == 1 {
            idle = 0;
            let ch = b[0];
            if ch == b'\n' {
                let ok = run_command(&line[..n]);
                if !ok {
                    exit(97);
                }
                n = 0;
            } else if ch == b'\r' {
                // ignore CR (CRLF scripts)
            } else if n < line.len() {
                line[n] = ch;
                n += 1;
            }
            continue;
        }
        if r < 0 {
            // A read errno on fd 0 — the alias contract is broken.
            exit(92);
        }
        // 0 = nothing typed yet: the documented poll signal.
        idle += 1;
        if idle >= IDLE_POLLS {
            write_out(b"[SH] idle\n");
            exit(0);
        }
        let ts = [0u64, 50_000_000u64]; // timespec {0s, 50ms}
        let _ = sys3(35, ts.as_ptr() as u64, 0, 0);
    }
}
