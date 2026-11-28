//! Ring-3 pkg caller (K22/K23): the tiny flat blob whose whole job is
//! to execve("/bin/pkg", …) — the package manager image the kernel
//! carries in its second 2 MiB leaf.
//!
//! K23/P1-2: ONE blob now drives the whole lifecycle. The kernel
//! writes a COMMAND SELECTOR into byte 0 of this blob's data page
//! before launch (0 = install hello, 1 = upgrade, 2 = remove,
//! 3 = install netcat — P1-2's REAL third-party binary round,
//! 4 = install rust-hello — the RUSTC citizen round); the blob reads
//! it first thing, builds the strings and the matching argv table in
//! the same page, and execve's with that table. The K22 shape (a
//! separate blob per command) would have needed five more embedded
//! binaries for four extra commands — the selector keeps the
//! registry and the boot image size flat while the lane grows.
//!
//! On success the syscall never returns: the image replaces this blob
//! under the `SERVICE` memory contract (its own profile's policy —
//! declared for the image's identity at boot), resolves r1/hello
//! against the signed local repo, runs the command, prints its report
//! on fd 1, and exit(0)s. The kernel-side lane verifies the
//! installed/upgraded/removed tree, the live mask and the stack
//! high-water after each round. On a REFUSAL the blob dies naming the
//! errno: exit code 100 + |errno| (ENOENT=102, ENOEXEC=108,
//! ENOMEM=112, EFAULT=114...), so the boot's error line says exactly
//! which arm refused.
//!
//! This caller speaks the INTERNAL syscall numbers (nr 19 = execve):
//! unlike K20's /bin/hello caller (Linux 59 — that image speaks
//! exit_group 231), the pkg image's own numbers are internal
//! (READ=0..EXIT=63), and the ABI flag survives exec, so the domain
//! must stay Internal from the first syscall on.
//!
//! argv shape per the manager's own CLI (pkg/src/cli.rs): `remove`
//! takes a bare package name, `upgrade` takes none (it walks the
//! installed set itself), and the install round PINS the version —
//! `r1/hello@1.0.0` — because the K23 repo serves two versions and a
//! bare name resolves NEWEST-first (the solver's documented walk), so
//! only the pinned request installs 1.0.0 and leaves the upgrade
//! round something to move TO. pkg_main skips argv[0] (the program
//! path); run_cli's args[0] is the COMMAND.
//!
//! Data-page layout (0x403000, one page):
//!   +0x00  the kernel-written selector (read, then left alone)
//!   +0x10  "/bin/pkg\0"
//!   +0x20  "install\0"   +0x28 "upgrade\0"   +0x30 "remove\0"
//!   +0x38  "r1/hello@1.0.0\0"   +0x48 "r1/hello\0" (remove's name)
//!   +0x52  "r1/netcat@1.0.0\0" (P1-2's fourth round, pinned — clear
//!          of r1/hello's NUL at +0x51)
//!   +0x68  "r1/rust-hello@1.0.0\0" (the fifth round — ends at
//!          +0x7C, clear of the argv tables at +0x80)
//!   +0x80 + sel*0x20  the FIVE argv tables (4 qwords, NULL-
//!          terminated — the exec arm reads them BEFORE the point of
//!          no return, from this blob's pages)
//!
//! Invariants (the flat-blob contract): position-dependent code,
//! one data page at 0x403000, ends in SYS_EXIT.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* K23: read the kernel-written command selector FIRST — the
     * string writes below must not clobber byte 0 before it is in a
     * register. movzx zero-extends, so sel*0x20 cannot smear into the
     * upper half of rcx. */
    movzx ecx, byte ptr [0x00403000]
    shl rcx, 5
    /* The strings live in the data page — the exec arm reads them
     * BEFORE the point of no return (they live in this blob's
     * pages). Every NUL is written explicitly: the page's zeros are a
     * pool scrub detail, not a contract. */
    movabs rax, 0x676b702f6e69622f    /* "/bin/pkg" */
    mov qword ptr [0x00403010], rax
    mov dword ptr [0x00403018], 0     /* the NUL */
    movabs rax, 0x006c6c6174736e69    /* "install\0" */
    mov qword ptr [0x00403020], rax
    movabs rax, 0x0065646172677075    /* "upgrade\0" */
    mov qword ptr [0x00403028], rax
    movabs rax, 0x000065766f6d6572    /* "remove\0" */
    mov qword ptr [0x00403030], rax
    movabs rax, 0x6f6c6c65682f3172    /* "r1/hello" */
    mov qword ptr [0x00403038], rax
    movabs rax, 0x0000302e302e3140    /* "@1.0.0\0\0" — the pinned
                                       * install target's tail */
    mov qword ptr [0x00403040], rax
    /* remove's target: the bare name (cmd_remove takes no version). */
    movabs rax, 0x6f6c6c65682f3172    /* "r1/hello" */
    mov qword ptr [0x00403048], rax
    mov dword ptr [0x00403050], 0     /* the NUL */
    /* P1-2's fourth round: the netcat install's pinned target — at
     * +0x52, clear of "r1/hello\0" at +0x48..+0x51 (a first cut at
     * +0x50 clobbered that string's NUL: every later reader of the
     * bare name would have walked straight into this one). */
    movabs rax, 0x616374656e2f3172    /* "r1/netca" */
    mov qword ptr [0x00403052], rax
    movabs rax, 0x00302e302e314074    /* "t@1.0.0\0\0" */
    mov qword ptr [0x0040305a], rax
    /* The fifth round's target: the rustc citizen's pinned request
     * at +0x68 (ends +0x7C, clear of the tables at +0x80). */
    movabs rax, 0x2d747375722f3172    /* "r1/rust-" */
    mov qword ptr [0x00403068], rax
    movabs rax, 0x2e31406f6c6c6568    /* "hello@1." */
    mov qword ptr [0x00403070], rax
    mov dword ptr [0x00403078], 0x00302e30    /* "0.0\0" */
    /* argv tables at +0x80 + sel*0x20 — ["/bin/pkg", cmd, target?,
     * NULL]. upgrade takes no argument (cmd_upgrade walks the
     * installed set), so its table ends at the NULL after the
     * command. */
    mov qword ptr [0x00403080], 0x00403010
    mov qword ptr [0x00403088], 0x00403020
    mov qword ptr [0x00403090], 0x00403038
    mov qword ptr [0x00403098], 0
    mov qword ptr [0x004030a0], 0x00403010
    mov qword ptr [0x004030a8], 0x00403028
    mov qword ptr [0x004030b0], 0
    mov qword ptr [0x004030b8], 0
    mov qword ptr [0x004030c0], 0x00403010
    mov qword ptr [0x004030c8], 0x00403030
    mov qword ptr [0x004030d0], 0x00403048
    mov qword ptr [0x004030d8], 0
    mov qword ptr [0x004030e0], 0x00403010
    mov qword ptr [0x004030e8], 0x00403020
    mov qword ptr [0x004030f0], 0x00403052
    mov qword ptr [0x004030f8], 0
    mov qword ptr [0x00403100], 0x00403010
    mov qword ptr [0x00403108], 0x00403020
    mov qword ptr [0x00403110], 0x00403068
    mov qword ptr [0x00403118], 0
    /* rcx = the selected table (base + sel*0x20, computed above). */
    add rcx, 0x00403080
    /* execve(path, argv, envp=NULL) — INTERNAL nr 19. */
    mov eax, 19
    mov rdi, 0x00403010
    mov rsi, rcx
    xor edx, edx
    syscall                           /* never returns on success */
    /* execve refused — die NAMING the errno (100 + |errno|). */
    neg rax
    mov edi, 100
    add edi, eax
    mov eax, 63
    syscall
"#
);
