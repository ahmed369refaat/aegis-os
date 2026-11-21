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
//!   mode 2 — **sleeper** (ADR-0023): clock_gettime around a 100 ms
//!     nanosleep, a sched_yield while solo, and exit(0) ONLY if the
//!     measured delta covers the span (the wake cannot land early) —
//!     the blob verifies its own answers, exit 95..99 names the step
//!     that failed. Scratch (RW data page): t0 @0x403010, t1
//!     @0x403020, the timespec @0x403030, rem @0x403040.
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
    cmp al, 2
    je 5f                             /* mode 2: the sleeper */

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

5:  /* ── mode 2: the sleeper (ADR-0023) ─────────────────────────── */
    /* t0 = clock_gettime(CLOCK_MONOTONIC, &0x403010) */
    mov eax, 228
    mov edi, 1
    mov rsi, 0x00403010
    syscall
    test rax, rax
    jnz 95f
    /* sched_yield() while solo — must answer 0 */
    mov eax, 24
    syscall
    test rax, rax
    jnz 96f
    /* nanosleep({{0, 100ms}}, &rem) — the sleep that parks the run
       and (solo) engages the kernel's idle state */
    mov qword ptr [0x00403030], 0     /* tv_sec */
    mov rax, 100000000
    mov qword ptr [0x00403038], rax   /* tv_nsec = 100 ms */
    mov eax, 35
    mov rdi, 0x00403030
    mov rsi, 0x00403040
    syscall
    test rax, rax
    jnz 97f
    /* t1 = clock_gettime(CLOCK_MONOTONIC, &0x403020) */
    mov eax, 228
    mov edi, 1
    mov rsi, 0x00403020
    syscall
    test rax, rax
    jnz 98f
    /* delta = t1_ns - t0_ns; ns = sec*1e9 + nsec (mul's high half is
       zero for any boot-time sec; the low half carries the delta) */
    mov rax, [0x00403010]             /* t0.sec */
    mov rcx, 1000000000
    mul rcx
    add rax, [0x00403018]             /* + t0.nsec */
    mov rdi, rax                      /* t0_ns */
    mov rax, [0x00403020]             /* t1.sec */
    mul rcx
    add rax, [0x00403028]             /* + t1.nsec */
    sub rax, rdi                      /* delta_ns */
    cmp rax, 100000000                /* >= the span? (never early) */
    jl 99f
    mov eax, 63                       /* SYS_EXIT */
    xor edi, edi                      /* 0: every step verified */
    syscall

95: mov eax, 63
    mov edi, 95                       /* t0 read failed */
    syscall
96: mov eax, 63
    mov edi, 96                       /* solo yield failed */
    syscall
97: mov eax, 63
    mov edi, 97                       /* nanosleep failed */
    syscall
98: mov eax, 63
    mov edi, 98                       /* t1 read failed */
    syscall
99: mov eax, 63
    mov edi, 99                       /* the wake landed early */
    syscall
"#,
);
