//! Ring-3 preemption example (M2-W2 / ADR-0012): the two actors of the
//! starvation-freedom proof, one blob, two modes selected by the mode
//! byte the kernel places at DATA_BASE (0x403000) before launch:
//!
//!   mode 0 — **spinner**: a long pure-compute loop, no syscalls, then
//!     exit(7). Without preemption this monopolizes the CPU forever;
//!     under the timer it is charged one CFS slice per tick exactly
//!     like everyone else.
//!   mode 1 — **writer**: four rounds of (SYS_WRITE a message, spin a
//!     little), then exit(0). The messages live in the data page at
//!     0x403010 + round*0x20 (the kernel copies them in at spawn).
//!
//! Register discipline (ADR-0012): live loop state lives in R12/R13 —
//! the interrupt-frame switch preserves every GPR, but a *handover*
//! resume (SYSRET-based, after another domain exits) necessarily
//! clobbers RCX/R11, the same pair every SYSCALL clobbers. The timer
//! switch itself is invisible to this code.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    movzx eax, byte ptr [0x00403000]  /* kernel-chosen mode */
    test al, al
    jz 2f                             /* mode 0: the spinner */

    /* ── mode 1: the writer ─────────────────────────────────────── */
    xor r12d, r12d                    /* round counter (R12: survives
                                         syscalls AND preemption AND
                                         handover resumes) */
1:  /* write msg[round]: 0x403010 + round*0x20, 22 bytes */
    mov rax, r12
    shl rax, 5
    mov rsi, 0x00403010
    add rsi, rax
    mov eax, 1                        /* SYS_WRITE */
    mov edi, 1                        /* fd: console */
    mov edx, 22
    syscall
    /* a short compute burst between writes (the preemption window) */
    mov r13d, 4000000
6:  sub r13d, 1
    jnz 6b
    add r12d, 1
    cmp r12d, 4
    jb 1b
    mov eax, 63                       /* SYS_EXIT */
    xor edi, edi                      /* code 0: clean exit */
    syscall

2:  /* ── mode 0: the spinner ────────────────────────────────────── */
    mov r13, 400000000                /* 64-bit loop counter in R13:
                                         never a syscall, never a
                                         yield — the timer is the ONLY
                                         thing that can take the CPU
                                         away from this loop */
3:  sub r13, 1
    jnz 3b
    mov eax, 63                       /* SYS_EXIT */
    mov edi, 7                        /* code 7: the spinner's exit */
    syscall
"#,
);
