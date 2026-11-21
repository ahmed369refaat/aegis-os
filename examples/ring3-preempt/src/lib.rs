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
//!   mode 3 — **victim** (ADR-0023 D8): rt_sigaction(SIGUSR1) with an
//!     in-blob handler, write "armed", sleep 200 ms (the killer
//!     strikes mid-sleep); on wake the handler must have run (its flag
//!     @0x403060) and sigreturn must have resumed this code — exit(0)
//!     only then.
//!   mode 4 — **killer**: a compute burst, then kill(23, SIGUSR1),
//!     exit(0).
//!   mode 5 — **forger**: rt_sigreturn with a garbage stack and no
//!     delivery in flight — the kernel MUST refuse (nonzero RAX);
//!     exit(0) only if it did.
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
    cmp al, 3
    je 7f                             /* mode 3: the victim */
    cmp al, 4
    je 10f                            /* mode 4: the killer */
    cmp al, 5
    je 11f                            /* mode 5: the forger */
    cmp al, 6
    je 12f                            /* mode 6: the mmap proof */

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

7:  /* ── mode 3: the victim (ADR-0023 D8) ──────────────────────── */
    /* rt_sigaction(SIGUSR1=10, handler, trampoline) — called at the
       INTERNAL number 25 (the Linux nr 13 collides with the round-J
       internal-DUP ABI; Phase 5's table resolves the whole space) */
    mov eax, 25
    mov edi, 10
    /* the handler's runtime address: this blob links flat at
       CODE_BASE=0x400000, and _ring3_start sits at section offset 0,
       so handler = 0x400000 + its section offset — obtained without
       any rip-relative form (this toolchain's global_asm pre-parser
       rejects them): call pushes the return address, pop reads it,
       and the handler is a FIXED positive delta from here. */
    call next_instr
next_instr:
    pop rsi
    add rsi, 0x1A5                    /* measured: sig_handler - next_instr (objdump-pinned) */              /* measured: sig_handler - next_instr */
    mov rdx, 0x0040C000               /* the kernel's trampoline page */
    syscall
    test rax, rax
    jnz 103f
    /* write "victim armed" (fd 1, 13 bytes @0x403010) */
    mov eax, 1
    mov edi, 1
    mov rsi, 0x00403010
    mov edx, 13
    syscall
    /* nanosleep 200 ms — the killer strikes mid-sleep */
    mov qword ptr [0x00403030], 0
    mov rax, 200000000
    mov qword ptr [0x00403038], rax
    mov eax, 35
    mov rdi, 0x00403030
    mov rsi, 0x00403040
    syscall
    test rax, rax
    jnz 104f
    /* A kernel->user boundary that is ALWAYS crossed (belt for the
       tick-switch wake path, where delivery defers to the next
       syscall): sched_yield while solo answers 0. */
    mov eax, 24
    syscall
    test rax, rax
    jnz 108f
    /* the handler ran (flag) and sigreturn resumed this code */
    cmp qword ptr [0x00403060], 0x51515151
    jne 105f
    mov eax, 63
    xor edi, edi                      /* 0: every step verified */
    syscall

10: /* ── mode 4: the killer ────────────────────────────────────── */
    mov r13, 30000000                 /* a compute burst well INSIDE the
                                        victim's 200 ms sleep — the victim
                                        then wakes through the IDLE path
                                        (nothing else runnable), which is
                                        the path that delivers the signal
                                        at unpark */
killer_spin:
    sub r13, 1
    jnz killer_spin
    mov eax, 62                       /* kill(23, SIGUSR1) */
    mov edi, 23
    mov esi, 10
    syscall
    test rax, rax
    jnz 106f
    mov eax, 63
    xor edi, edi
    syscall

11: /* ── mode 5: the forger ────────────────────────────────────── */
    mov rax, 0x1111222233334444       /* garbage where a frame would be */
    push rax
    mov eax, 15                       /* rt_sigreturn, no delivery */
    syscall
    test rax, rax
    jz 107f                           /* ZERO means the kernel ACCEPTED
                                         a forged frame — the failure */
    mov eax, 63
    xor edi, edi                      /* refused (nonzero): the proof */
    syscall

12: /* ── mode 6: the mmap proof (ADR-0024 D1) ──────────────────── */
    /* mmap(NULL, 4096, PROT_READ|PROT_WRITE) — the INTERNAL nr 4
       (the Linux nr 9 collides with the round-J internal NET_SEND;
       the full renumbering is Phase 5's ABI-VERSION table) */
    mov eax, 4
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r12, rax                      /* window A (survives syscalls) */
    cmp rax, 0x0040D000
    jb 110f                           /* below the trampoline floor */
    /* write + read back a pattern through A */
    mov rax, 0x600DF00D
    mov [r12], rax
    mov rbx, [r12]                    /* rbx: stub-restored, safe */
    cmp rbx, rax
    jne 111f
    /* a SECOND window — strictly above A (the allocator's guard gaps) */
    mov eax, 4
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r13, rax                      /* window B */
    cmp rax, r12
    jbe 112f
    mov rax, 0xFACEB00C
    mov [r13], rax
    mov rbx, [r13]
    cmp rbx, rax
    jne 113f
    /* munmap window B — the INTERNAL nr 5 */
    mov eax, 5
    mov rdi, r13
    mov rsi, 4096
    syscall
    test rax, rax
    jnz 114f
    /* A survived B's unmap, pattern intact */
    mov rbx, [r12]
    cmp rbx, 0x600DF00D
    jne 115f
    /* the flag: every step verified; the next read is deliberate */
    mov rax, 0x7A7A7A7A
    mov qword ptr [0x00403060], rax
    /* the deliberate read of the FREED page: #PF ends this run, and
       the kernel's proof reads cr2 */
    mov rax, [r13]
    jmp 116f                          /* unreachable; the fault wins */

sig_handler:                          /* SIGUSR1: set the flag, ret */
    mov rax, 0x51515151
    mov qword ptr [0x00403060], rax
    ret                               /* -> the trampoline -> sigreturn */

103: mov eax, 63
    mov edi, 103                      /* sigaction failed */
    syscall
104: mov eax, 63
    mov edi, 104                      /* the nanosleep failed */
    syscall
105: mov eax, 63
    mov edi, 105                      /* the handler did not run */
    syscall
106: mov eax, 63
    mov edi, 106                      /* the kill failed */
    syscall
107: mov eax, 63
    mov edi, 107                      /* a forged frame was accepted */
    syscall
108: mov eax, 63
    mov edi, 108                      /* the post-sleep yield failed */
    syscall
110: mov eax, 63
    mov edi, 110                      /* window A below the floor */
    syscall
111: mov eax, 63
    mov edi, 111                      /* A's pattern round-trip failed */
    syscall
112: mov eax, 63
    mov edi, 112                      /* window B not above A */
    syscall
113: mov eax, 63
    mov edi, 113                      /* B's pattern round-trip failed */
    syscall
114: mov eax, 63
    mov edi, 114                      /* munmap refused */
    syscall
115: mov eax, 63
    mov edi, 115                      /* A damaged by B's unmap */
    syscall
116: mov eax, 63
    mov edi, 116                      /* the freed read did NOT fault */
    syscall
"#,
);
