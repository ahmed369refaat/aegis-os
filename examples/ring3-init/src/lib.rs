//! Ring-3 init blob (Phase 7, M3): PID 1's wait4 loop — the Unix init
//! pattern, proven end to end at CPL=3.
//!
//! The cast: PID 1 forks child A; A forks the grandchild B and
//! exit_group(7)s; B — orphaned the moment A dies — is REPARENTED to
//! PID 1 (ADR-0022 D7's `reparent_children`, live in the lib since
//! round K) and exit_group(33)s. Whichever order the dispatcher picks,
//! init's BLOCKING wait4(-1) loop reaps BOTH (the wstatus values are
//! the identity proof: 7<<8 is A, 33<<8 is the adopted orphan), and
//! the loop only ends when wait4 answers -ECHILD — no child left,
//! zombie or live. That drain loop IS init's job description; this
//! blob is the smallest honest version of it.
//!
//! One page of state: a PRIVATE mmap'd wstatus target, allocated
//! AFTER the fork (the CoW rule mode 13 pinned: fork marks every
//! shared page read-only in both tables — a fresh mmap after it is
//! parent-private RW). Counters ride r12 (A) / r13 (B).
//!
//! Every step checks the kernel's answer; the failure exits name
//! their step (90..95) so a red boot says where. Only a fully
//! drained loop with exactly one child of each exits 0.
//!
//! ABI: LINUX v1 (ADR-0003) — the supervisor declares it via
//! set_domain_abi (fork children inherit it). nr in RAX; args in
//! RDI, RSI, RDX, R10; RAX = result or -errno.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    mov eax, 57                       /* fork() — nr 57: child A */
    syscall
    test rax, rax
    js 90f                            /* fork refused */
    jz 10f                            /* rax == 0: we are A */
    mov r15, rax                      /* init: A's pid (diagnostics) */
    /* The wstatus target must be PRIVATE (the CoW rule): a fresh
       mmap AFTER the fork is parent-private RW. */
    mov eax, 9                        /* mmap(0, 4096, RW, 0x22) — nr 9 */
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 0x22
    syscall
    cmp rax, 0x1000
    jl 91f                            /* the wstatus mmap failed */
    mov r14, rax                      /* the wstatus target */
    xor r12d, r12d                    /* A reaped (wstatus 7<<8) */
    xor r13d, r13d                    /* B reaped (wstatus 33<<8) */
1:  mov eax, 61                       /* wait4(-1, ws, 0, 0) — nr 61:
                                          the BLOCKING reap. Parks while
                                          children run; a completion
                                          wakes it; ECHILD ends it. */
    mov rdi, -1
    mov rsi, r14
    xor edx, edx
    xor r10d, r10d
    syscall
    cmp rax, -10                      /* -ECHILD: the loop is drained */
    je 2f
    cmp rax, 3
    jl 92f                            /* an errno that is not ECHILD */
    mov ecx, dword ptr [r14]          /* the reaped child's wstatus */
    cmp ecx, 0x0700                   /* A's exit_group(7): WIFEXITED,
                                          WEXITSTATUS == 7 */
    jne 3f
    inc r12d
    jmp 1b
3:  cmp ecx, 0x2100                   /* B's exit_group(33): the adopted
                                          orphan crossed the boundary */
    jne 93f                           /* a wstatus we did not order */
    inc r13d
    jmp 1b
2:  cmp r12d, 1                       /* exactly one of each — no
                                          stray child, no double reap */
    jne 94f
    cmp r13d, 1
    jne 94f
    mov eax, 231                      /* exit_group(0): the loop
                                          drained clean */
    xor edi, edi
    syscall

10: /* we are A: fork the grandchild, then exit(7). B is born our
       child; our death orphans it — PID 1 must adopt it. */
    mov eax, 57                       /* fork() — nr 57: grandchild B */
    syscall
    test rax, rax
    js 95f                            /* A's fork refused */
    jz 20f                            /* rax == 0: we are B */
    mov eax, 231                      /* exit_group(7) — nr 231 */
    mov edi, 7
    syscall

20: /* we are B: the orphan. exit_group(33) — whether we die before
       or after our parent, PID 1's loop is the one that reaps us. */
    mov eax, 231
    mov edi, 33
    syscall

    /* ── the failure exits: the number names the step ── */
90: mov eax, 231
    mov edi, 90                       /* init's fork refused */
    syscall
91: mov eax, 231
    mov edi, 91                       /* the wstatus mmap failed */
    syscall
92: mov eax, 231
    mov edi, 92                       /* wait4 answered an errno != ECHILD */
    syscall
93: mov eax, 231
    mov edi, 93                       /* an unexpected wstatus */
    syscall
94: mov eax, 231
    mov edi, 94                       /* wrong reap counts */
    syscall
95: mov eax, 231
    mov edi, 95                       /* A's fork refused */
    syscall
"#,
);
