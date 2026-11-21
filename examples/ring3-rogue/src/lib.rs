//! Ring-3 rogue (PR-1.4 security example): performs exactly one hostile
//! act per run, selected by the mode byte the kernel places at
//! DATA_BASE before the launch:
//!   mode 0 — call into the non-executable data page (NX must fault),
//!   mode 1 — read through the direct-map base (U/S must fault),
//!   mode 2 — call unknown syscall 200 (must return -ENOSYS, audited),
//!            then verify the errno and exit 42 on success / 99 if the
//!            kernel answered anything else.
//!   mode 3 — spam six forbidden syscalls plus one crossing write per
//!            iteration (N2): denials, out-of-profile bits, a rate
//!            spike and -EFAULT faults, across many monitor windows —
//!            the live monitor must quarantine the domain while the
//!            kernel keeps running.
//! The hostile act always terminates the run (fault) or verifies the
//! kernel's answer (exit code); the program never loops.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    movzx eax, byte ptr [0x00403000]   /* kernel-chosen mode */
    test al, al
    jz 2f                              /* mode 0: NX exec */
    cmp al, 1
    je 1f                              /* mode 1: kernel-VA read */
    cmp al, 3
    je 5f                              /* mode 3: monitor spam */
    /* ── mode 2: forged syscall, verify -ENOSYS ── */
    mov eax, 200
    syscall
    cmp rax, -38                       /* -ENOSYS? */
    jne 3f
    mov eax, 63
    mov edi, 42                        /* exit(42): kernel refused properly */
    syscall
3:  mov eax, 63
    mov edi, 99                        /* exit(99): WRONG answer — loud */
    syscall
5:  /* ── mode 3 (N2): quarantine spam — five forbidden syscalls and a
       crossing write per iteration; the counter lives in the data page
       because SYSCALL destroys RCX/R11. ADR-0022 recalibration: the
       MMAP spam (nr 4) left this list because MMAP/MUNMAP/FORK/EXEC/
       WAIT entered the SERVICE surface with the process model — a
       syscall the profile allows is no longer a "forbidden" spam
       seed, and its ENOSYS-en route halved the denied-ratio signal
       (measured: audit-only score 64 vs the 65 quarantine threshold,
       one point short — the audit-only lane caught it). ── */
    mov dword ptr [0x00403008], 30000
6:  mov eax, 200                      /* unknown nr: a denial */
    syscall
    mov eax, 9                        /* SYS_NET_SEND: off-profile */
    syscall
    mov eax, 10                       /* SYS_NET_RECV */
    syscall
    mov eax, 6                        /* SYS_SPAWN */
    syscall
    mov eax, 11                       /* SYS_IOCTL */
    syscall
    mov eax, 1                        /* SYS_WRITE with a crossing
                                          pointer: -EFAULT = a fault */
    mov edi, 1
    mov rsi, 0x00404000
    mov edx, 1
    syscall
    sub dword ptr [0x00403008], 1
    jnz 6b
    mov eax, 63                       /* SYS_EXIT (open even when
                                          quarantined) */
    mov edi, 0
    syscall
1:  /* ── mode 1: read through the kernel direct map ── */
    mov rax, [0xFFFF888000000000]      /* must #PF (supervisor page) */
    ret                                /* unreachable */
2:  /* ── mode 0: execute the non-executable data page ── */
    mov eax, 0x00403000
    call rax                           /* must #PF (instruction fetch, NX) */
    ret                                /* unreachable */
"#,
);
