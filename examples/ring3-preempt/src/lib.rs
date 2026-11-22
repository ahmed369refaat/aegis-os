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
    cmp al, 7
    je 13f                            /* mode 7: the fork/CoW proof */
    cmp al, 8
    je 14f                            /* mode 8: the IPC pair */
    cmp al, 9
    je 15f                            /* mode 9: the sync pair */

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
    add rsi, 0x416                    /* measured: sig_handler - next_instr (objdump-pinned) */              /* measured: sig_handler - next_instr */
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

13: /* ── mode 7: the fork/CoW proof (ADR-0024 D2) ──────────────── */
    /* a private mmap page — the CoW subject */
    mov eax, 4
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r12, rax                      /* survives syscalls AND the
                                         fork's parked image */
    cmp rax, 0x0040D000
    jb 120f
    /* the parent pattern */
    mov rax, 0x1111AAAA
    mov [r12], rax
    /* fork — the Linux nr 57 (translated to the internal 18) */
    mov eax, 57
    syscall
    test rax, rax
    jz fork_child                     /* the child's rax is 0 */
    /* ── the parent: rax = the child id ── */
    /* sched_yield: hand the CPU to the child NOW (deterministic —
       the tick could otherwise steal it mid-run and the exits would
       race); the child runs to its exit through the nested
       dispatcher, and this code resumes when the child is done. */
    mov eax, 24
    syscall
    test rax, rax
    jnz 123f
    /* Overwrite the pattern: the page was demoted at fork, so this
       write takes the CoW fault and lands on a private copy. */
    mov rax, 0x2222BBBB
    mov [r12], rax
    mov rbx, [r12]
    cmp rbx, rax
    jne 121f
    mov eax, 63
    xor edi, edi                      /* 0: parent verified */
    syscall

fork_child:
    /* ── the child: rax = 0, r12 = the same window ── */
    /* A DIFFERENT pattern: its own CoW copy, its own page. */
    mov rax, 0x3333CCCC
    mov [r12], rax
    mov rbx, [r12]
    cmp rbx, rax
    jne 122f
    mov eax, 63
    xor edi, edi                      /* 0: child verified */
    syscall

14: /* ── mode 8: the IPC pair (ADR-0025) ──────────────────────── */
    /* data[1]: 0 = sender, 1 = receiver. data[2..10]: channel A,
       [10..18]: channel B, [18..26]: channel C (LE u64s). Both roles
       POLL with bounded retries: the tick may run either party at any
       point, so exact interleavings are the scheduler's business —
       the proof is the CONTRACT (bounded queues, caps, lengths). */
    movzx eax, byte ptr [0x00403001]
    mov rbx, qword ptr [0x00403002]    /* channel A */
    test eax, eax
    jnz ipc_receiver

    /* The opening yield (ADR-0025 hunt): park into dispatch_next
       BEFORE any send, so the resume chain and RESUME_RIP are set by
       a real resume_parked — a receiver that exits through the TICK
       path (unpark_into_frame) lands on RESUME_RIP, and without this
       the last setter is kmain's flat launch label (found live: the
       take() panic right after the cow marker). */
    mov eax, 24
    syscall

    /* ── the sender: fill A until -EAGAIN, fill B until -EAGAIN,
       prove the no-cap channel refuses -EPERM, then YIELD (the
       nested dispatcher runs the parked receivers to completion) ── */
    mov r12d, 0                         /* delivered to A */
ipc_tx_a:
    mov eax, 7
    mov rdi, rbx
    mov rsi, 7
    syscall
    cmp rax, -11                        /* EAGAIN: the queue is full */
    je ipc_tx_a_done
    cmp rax, 0
    jl 133f                             /* any other refusal: a bug */
    inc r12
    cmp r12, 64
    jb ipc_tx_a                         /* drain-and-refill is fine */
ipc_tx_a_done:
    test r12, r12
    jz 133f                             /* zero delivered: a bug */
    mov rbx, qword ptr [0x0040300A]     /* channel B */
    mov r13d, 0
ipc_tx_b:
    mov eax, 7
    mov rdi, rbx
    mov rsi, 7
    syscall
    cmp rax, -11
    je ipc_tx_b_done
    cmp rax, 0
    jl 133f
    inc r13
    cmp r13, 64
    jb ipc_tx_b
ipc_tx_b_done:
    test r13, r13
    jz 133f
    /* the no-cap probe: channel C exists, never granted */
    mov rbx, qword ptr [0x00403012]
    mov eax, 7
    mov rdi, rbx
    mov rsi, 7
    syscall
    cmp rax, -13                        /* -EACCES: the cap gate's refusal
                                          errno (sysabi maps PermissionDenied
                                          to EACCES; EPERM is the
                                          mask/quarantine errno) */
    jne 136f
    /* hand the CPU to the receivers (the nested dispatcher); this
       code resumes only after both have exited, then exits clean */
    mov eax, 24
    syscall
    mov eax, 63
    xor edi, edi
    syscall

ipc_receiver:
    /* ── the receiver: drain until >= 4 AND the queue reads empty
       (-EAGAIN), yielding between empty polls (the sender is still
       filling); a wrong length or an unexpected errno exits nonzero ── */
    mov r12d, 0                         /* drained */
    mov r14d, 0                         /* empty polls */
ipc_rx_loop:
    mov eax, 8
    mov rdi, rbx
    syscall
    cmp rax, -11                        /* empty NOW */
    je ipc_rx_empty
    cmp rax, 7                          /* the fixed length */
    jne 135f
    inc r12
    jmp ipc_rx_loop
ipc_rx_empty:
    cmp r12, 4
    jae ipc_rx_done                     /* >= 4 drained: the EAGAIN counts */
    inc r14
    cmp r14, 64
    jae 139f                            /* starved: a bug */
    mov eax, 24                         /* yield: let the sender fill */
    syscall
    jmp ipc_rx_loop
ipc_rx_done:
    mov eax, 63
    xor edi, edi
    syscall

15: /* ── mode 9: the sync pair (ADR-0026) ──────────────────────── */
    /* data[1]: 0 = caller, 1 = callee (the endpoint owner).
       data[2..10]: channel D (LE u64). TWO round-trips, and the two
       halves of the unified contract both fire, deterministically:
       exchange 1 through the RENDEZVOUS (the callee parks in
       recv_wait before the caller's call — the push self-consumes
       and the callee wakes with the request len), exchange 2 through
       the QUEUED fast path (the callee YIELDS between reply and the
       next recv_wait; the caller's call lands while nobody waits —
       the message queues; the callee's recv_wait POPS it, no park).
       The interleaving is pinned by the yields, not by luck. */
    movzx eax, byte ptr [0x00403001]
    mov rbx, qword ptr [0x00403002]    /* channel D */
    test eax, eax
    jnz sync_callee

    /* ── the caller: two calls, each returns exactly the reply len
       the callee sent — the wake patched RAX ── */
    /* the opening yield — the round-M discipline: the resume chain
       set by a real resume_parked before anything else runs */
    mov eax, 24
    syscall
    mov eax, 26                        /* ipc_call(D, 7) */
    mov rdi, rbx
    mov rsi, 7
    syscall
    cmp rax, 0x11                      /* the reply len, delivered */
    jne 140f
    mov eax, 26                        /* ipc_call(D, 9) */
    mov rdi, rbx
    mov rsi, 9
    syscall
    cmp rax, 0x22
    jne 140f
    mov eax, 63
    xor edi, edi
    syscall

sync_callee:
    /* ── the callee: recv_wait blocks (or pops), reply answers;
       the yield between the exchanges pins the queued path ── */
    mov eax, 27                        /* ipc_recv_wait(D) */
    mov rdi, rbx
    syscall
    cmp rax, 7                         /* the request len */
    jne 141f
    mov eax, 28                        /* ipc_reply(D, 0x11) */
    mov rdi, rbx
    mov rsi, 0x11
    syscall
    cmp rax, 1                         /* one waiter woken */
    jne 142f
    /* the pin: yield NOW — the caller's second call must land while
       nobody is waiting (the message queues; no rendezvous) */
    mov eax, 24
    syscall
    mov eax, 27                        /* recv_wait: POPS the queued 9 */
    mov rdi, rbx
    syscall
    cmp rax, 9
    jne 141f
    mov eax, 28                        /* ipc_reply(D, 0x22) */
    mov rdi, rbx
    mov rsi, 0x22
    syscall
    cmp rax, 1
    jne 142f
    mov eax, 63
    xor edi, edi
    syscall

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
120: mov eax, 63
    mov edi, 120                      /* the mmap window below the floor */
    syscall
121: mov eax, 63
    mov edi, 121                      /* the parent's CoW write failed */
    syscall
122: mov eax, 63
    mov edi, 122                      /* the child's CoW write failed */
    syscall
123: mov eax, 63
    mov edi, 123                      /* the post-fork yield failed */
    syscall
133: mov eax, 63
    mov edi, 133                      /* a send refused before the count */
    syscall
134: mov eax, 63
    mov edi, 134                      /* the full-queue EAGAIN missing */
    syscall
135: mov eax, 63
    mov edi, 135                      /* the receiver's count short */
    syscall
136: mov eax, 63
    mov edi, 136                      /* the no-cap send NOT refused */
    syscall
137: mov eax, 63
    mov edi, 137                      /* the empty-queue EAGAIN missing */
    syscall
138: mov eax, 63
    mov edi, 138                      /* the sender's fill ran away */
    syscall
139: mov eax, 63
    mov edi, 139                      /* the receiver starved */
    syscall
140: mov eax, 63
    mov edi, 140                      /* a call returned the wrong reply */
    syscall
141: mov eax, 63
    mov edi, 141                      /* a recv_wait returned the wrong len */
    syscall
142: mov eax, 63
    mov edi, 142                      /* a reply did not wake one waiter */
    syscall
"#,
);
