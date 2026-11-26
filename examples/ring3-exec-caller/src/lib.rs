//! Ring-3 exec caller (K20/P0-3): the tiny flat blob whose whole job
//! is to execve("/bin/hello") — the gcc-built userland image the boot
//! read off the ext2 disk into the exec registry's disk slot.
//!
//! On success the syscall never returns: the image replaces this
//! blob, writes its pattern, and exit_group(42)s — the kernel-side
//! verification keys on that exit code and the pattern page. On a
//! REFUSAL the blob dies naming the errno: exit code 100 + |errno|
//! (ENOENT=102, ENOEXEC=108, ENOMEM=112, EFAULT=114, ESRCH=115...),
//! so the boot's error line says exactly which arm refused.
//!
//! Invariants (the flat-blob contract): position-dependent code,
//! one data page at 0x403000, ends in SYS_EXIT. The domain speaks
//! the Linux ABI (the exec number 59 and the image's exit_group 231
//! both need the translation), set by the spawning step.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* Build "/bin/hello\0" and argv in the data page — the exec arm
     * reads the strings BEFORE the point of no return (they live in
     * the old image's pages, i.e. this page). */
    movabs rax, 0x6c65682f6e69622f    /* "/bin/hel" */
    mov qword ptr [0x00403000], rax
    mov dword ptr [0x00403008], 0x00006f6c /* "lo\0\0" */
    mov qword ptr [0x00403010], 0x00403000 /* argv[0] -> "/bin/hello" */
    mov qword ptr [0x00403018], 0          /* argv[1] = NULL */
    mov eax, 59                       /* execve(path, argv, NULL) */
    mov rdi, 0x00403000
    mov rsi, 0x00403010
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
