//! Ring-3 pkg caller (K22): the tiny flat blob whose whole job is to
//! execve("/bin/pkg", ["pkg", "install", "r1/hello"]) — the package
//! manager image the kernel now carries in its second 2 MiB leaf.
//!
//! On success the syscall never returns: the image replaces this blob
//! under the `SERVICE` memory contract (its own profile's policy —
//! declared for the image's identity at boot), resolves r1/hello
//! against the signed local repo, installs it, prints its report on
//! fd 1, and exit(0)s. The kernel-side lane verifies the installed
//! tree, the live mask and the stack high-water. On a REFUSAL the blob
//! dies naming the errno: exit code 100 + |errno|
//! (ENOENT=102, ENOEXEC=108, ENOMEM=112, EFAULT=114...), so the
//! boot's error line says exactly which arm refused.
//!
//! This caller speaks the INTERNAL syscall numbers (nr 19 = execve):
//! unlike K20's /bin/hello caller (Linux 59 — that image speaks
//! exit_group 231), the pkg image's own numbers are internal
//! (READ=0..EXIT=63), and the ABI flag survives exec, so the domain
//! must stay Internal from the first syscall on.
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
    /* The argv strings live in the data page — the exec arm reads
     * them BEFORE the point of no return (they live in this blob's
     * pages). argv[0] is the program path, argv[1] the command,
     * argv[2] the target — the execve marshalling builds the image's
     * initial stack from these exact pointers. */
    movabs rax, 0x676b702f6e69622f    /* "/bin/pkg" */
    mov qword ptr [0x00403000], rax
    mov dword ptr [0x00403008], 0     /* the NUL (the page is zeroed) */
    movabs rax, 0x006c6c6174736e69    /* "install\0" */
    mov qword ptr [0x00403010], rax
    movabs rax, 0x6f6c6c65682f3172    /* "r1/hello" */
    mov qword ptr [0x00403020], rax
    mov dword ptr [0x00403028], 0     /* the NUL */
    /* argv[] at +0x30: ["/bin/pkg", "install", "r1/hello", NULL] */
    mov qword ptr [0x00403030], 0x00403000
    mov qword ptr [0x00403038], 0x00403010
    mov qword ptr [0x00403040], 0x00403020
    mov qword ptr [0x00403048], 0
    /* execve(path, argv, envp=NULL) — INTERNAL nr 19. */
    mov eax, 19
    mov rdi, 0x00403000
    mov rsi, 0x00403030
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
