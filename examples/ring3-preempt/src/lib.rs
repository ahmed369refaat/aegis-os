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
    cmp al, 10
    je 16f                            /* mode 10: the grant pair */
    cmp al, 11
    je 17f                            /* mode 11: the bench pair */
    cmp al, 12
    je 18f                            /* mode 12: the pipe pair */
    cmp al, 13
    je 19f                            /* mode 13: the Linux-ABI blob */

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
    add rsi, 0x947                    /* measured: sig_handler - next_instr (objdump-pinned) */              /* measured: sig_handler - next_instr */
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

16: /* ── mode 10: the grant pair (ADR-0027) ────────────────────── */
    /* data[1]: 0 = granter, 1 = grantee. data[2..10]: channel E
       (owned by the grantee, WRITE granted to the granter).
       data[10]: the grantee's domain id (the grant's dst).
       The granter mmaps a page, writes a pattern, grants it RW, and
       passes the granted VA in the receiver through TWO u16 sends
       (the IPC message bound is 64 bytes — a VA does not fit whole);
       the sync call/reply then confirms the read. The grantee reads
       the pattern through the grant, writes its own mark, replies.
       The granter's own page must then carry the mark — the
       bidirectional shared-memory proof. */
    movzx eax, byte ptr [0x00403001]
    mov rbx, qword ptr [0x00403002]    /* channel E */
    test eax, eax
    jnz grant_grantee

    /* ── the granter: mmap, pattern, grant, tell, call, verify ── */
    mov eax, 24                        /* the opening yield — the
                                          round-M discipline */
    syscall
    mov eax, 4                         /* mmap(NULL, 4096, RW) */
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r12, rax                       /* A_va: survives syscalls */
    cmp rax, 0x0040D000
    jb 145f
    mov rax, 0x600D600D                /* the pattern at +0 */
    mov [r12], rax
    mov rax, 0xAB12                    /* a second word at +8 */
    mov [r12+8], rax
    movzx edi, byte ptr [0x0040300A]   /* dst: the grantee's id */
    mov rsi, r12                       /* va: my page */
    mov edx, 4096                      /* len: one page */
    mov eax, 29                        /* ipc_grant_frames */
    syscall
    mov r13, rax                       /* B_va: where it landed */
    cmp rax, 0x0040D000
    jb 145f
    test rax, 0xFFF
    jnz 145f                           /* not page-aligned: a bug */
    /* tell the grantee where: the page number in two 6-bit halves
       (the message bound is 64 — a raw address half would refuse;
       B_va is page-aligned and the user half is tiny, so the page
       number fits 12 bits) */
    mov rax, r13
    shr rax, 12                        /* the page number */
    mov r14, rax
    and r14, 0x3F                      /* lo6 */
    mov r15, rax
    shr r15, 6                         /* hi6 */
    mov eax, 7                         /* ipc_send(E, lo16) */
    mov rdi, rbx
    mov rsi, r14
    syscall
    cmp rax, 0
    jl 147f
    mov eax, 7                         /* ipc_send(E, hi16) */
    mov rdi, rbx
    mov rsi, r15
    syscall
    cmp rax, 0
    jl 147f
    /* the sync confirmation: call(E, 7) -> the grantee's 0x5EED */
    mov eax, 26
    mov rdi, rbx
    mov rsi, 7
    syscall
    cmp rax, 42
    jne 148f
    /* the mark through MY page: the grant is shared memory */
    mov rbx, [r12+16]
    mov rax, 0xF00DF00D
    cmp rbx, rax
    jne 149f
    mov eax, 63
    xor edi, edi
    syscall

grant_grantee:
    /* ── the grantee: two recvs (the VA halves), read the pattern
       through the grant, write the mark, reply ── */
    mov eax, 27                        /* recv_wait: lo6 */
    mov rdi, rbx
    syscall
    cmp rax, 0x3F
    ja 150f
    mov r12, rax                       /* lo6 */
    mov eax, 27                        /* recv_wait: hi6 */
    mov rdi, rbx
    syscall
    cmp rax, 0x3F
    ja 151f
    shl rax, 6
    or r12, rax                        /* the page number */
    shl r12, 12                        /* B_va = page << 12 */
    /* the granter's pattern, through the grant */
    mov rax, [r12]
    cmp rax, 0x600D600D
    jne 152f
    mov rax, [r12+8]
    cmp rax, 0xAB12
    jne 153f
    mov rax, 0xF00DF00D                /* my mark at +16 */
    mov [r12+16], rax
    mov r14, rax                       /* keep the mark for the check
                                          (imm32 sign-extends; the
                                          register form compares) —
                                          r14, NEVER rbx: rbx is the
                                          CHANNEL the reply needs */
    mov rax, [r12+16]
    cmp rax, r14
    jne 154f                           /* my write did not stick */
    /* reply(E, 42) — with the bounded EAGAIN retry: the tick may
       have run ME ahead of the caller's call (its park had not
       happened yet when my first reply fired) — the -EAGAIN is the
       transient truth, not an error; yield so the caller reaches
       its call, then answer it. */
    mov r13d, 0                        /* the retry budget */
grant_reply:
    mov eax, 28
    mov rdi, rbx
    mov rsi, 42
    syscall
    cmp rax, 1
    je grant_reply_done
    cmp rax, -11                       /* EAGAIN: nobody parked yet */
    jne 155f
    inc r13
    cmp r13, 64
    jae 155f                           /* starved: a bug */
    mov eax, 24                        /* yield: let the caller call */
    syscall
    jmp grant_reply
grant_reply_done:
    mov eax, 63
    xor edi, edi
    syscall

17: /* ── mode 11: the bench pair (ADR-0028) ────────────────────── */
    /* The honest measurement round: rdtsc INSIDE the blob, around
       each operation end-to-end (syscall entry, park, wake, resume —
       everything a real caller pays). Two roles: 0 = the measurer
       (yield baseline, call/reply RTT, the grant syscall, the CoW
       fault+copy), 1 = the responder (recv_wait -> reply, exits on
       the 63 sentinel). The report: raw TSC deltas in hex through
       SYS_WRITE — the decoder script converts with the kernel's
       ACPI-calibrated tsc_hz. No numbers are guessed anywhere. */
    movzx eax, byte ptr [0x00403001]
    mov rbx, qword ptr [0x00403002]    /* channel E */
    test eax, eax
    jnz bench_responder

    /* ── the measurer ── */
    mov eax, 24                        /* the opening yield (the
                                          discipline; also hands the
                                          responder the CPU so it is
                                          parked in recv_wait before
                                          any measurement) */
    syscall
    /* three windows: A = the metrics buffer (r12), B = the CoW
       subject (r13, mapped later), C = the grant source (r14) */
    mov eax, 4
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r12, rax
    cmp rax, 0x0040D000
    jb 160f
    /* the phase self-check anchor: the true window, parked where
       NOTHING may touch it; every phase then asserts r12 against it
       (a distinct exit code names the phase that lost it) */
    mov qword ptr [0x00403040], rax
    mov eax, 4
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r14, rax
    cmp rax, r12
    jbe 160f
    /* ── the yield baseline: the park+dispatch floor (nobody else
       runnable — the responder is BLOCKED, not runnable) ── */
    mov r8, -1                         /* min = MAX */
    xor r9, r9                         /* sum */
    mov r15, 16
bench_yield:
    rdtsc
    mov r10d, eax                      /* t0 */
    mov eax, 24
    syscall
    rdtsc
    sub eax, r10d                      /* d (32-bit deltas: safe) */
    mov r11d, eax
    add r9, r11
    cmp r11d, r8d
    jae bench_yield_next
    mov r8d, r11d
bench_yield_next:
    dec r15
    jnz bench_yield
    mov [r12], r8
    mov [r12+8], r9
    mov rax, [0x00403040]
    cmp r12, rax
    jne 170f                           /* r12 lost in the yield phase */
    /* ── the call/reply RTT (the responder is parked in recv_wait;
       every call rendezvouses: park, wake it, it runs and replies,
       we wake — the full cycle) ── */
    mov r8, -1
    xor r9, r9
    mov r15, 32
bench_rtt:
    rdtsc
    mov r10d, eax
    mov eax, 26                        /* call(E, 7) */
    mov rdi, rbx
    mov rsi, 7
    syscall
    cmp rax, 42
    jne 160f
    rdtsc
    sub eax, r10d
    mov r11d, eax
    add r9, r11
    cmp r11d, r8d
    jae bench_rtt_next
    mov r8d, r11d
bench_rtt_next:
    dec r15
    jnz bench_rtt
    mov [r12+0x10], r8
    mov [r12+0x18], r9
    mov rax, [0x00403040]
    cmp r12, rax
    jne 171f                           /* r12 lost in the RTT phase */
    /* ── the grant syscall (walk + refcounts + map through the
       receiver's policy; the receiver stays parked throughout) ── */
    mov rax, 0x1234BEEF                /* a pattern into C */
    mov [r14], rax
    rdtsc
    mov r10d, eax
    movzx edi, byte ptr [0x0040300A]   /* dst: the responder's id */
    mov rsi, r14
    mov edx, 4096
    mov eax, 29                        /* ipc_grant_frames */
    syscall
    mov r13, rax                       /* the landed VA */
    cmp rax, 0x0040D000
    jb 160f
    rdtsc
    sub eax, r10d
    mov r11d, eax
    mov [r12+0x28], r11
    mov rax, [0x00403040]
    cmp r12, rax
    jne 172f                           /* r12 lost in the grant phase */
    /* ── the CoW fault+copy: fork (all writable pages demoted,
       every frame refcounted — the child lives parked), then ONE
       write: the fault, the copy, the remap, the resume — inside
       one instruction's wall time. The yield reaps the child (its
       D2 exit-release drops our shared refs back to one). ── */
    mov eax, 4
    xor edi, edi
    mov rsi, 4096
    mov edx, 3
    syscall
    mov r13, rax                       /* B: the CoW subject */
    cmp rax, r14
    jbe 160f
    mov rax, 0x0DEFACED                /* a pre-fault pattern */
    mov [r13], rax
    mov r8, -1
    xor r9, r9
    mov r15, 4
bench_cow:
    mov eax, 57                        /* fork */
    syscall
    test rax, rax
    jz bench_child
    rdtsc
    mov r10d, eax
    mov rax, 0x0DEFACED
    mov [r13], rax                     /* THE write: fault+copy */
    rdtsc
    sub eax, r10d
    mov r11d, eax
    add r9, r11
    cmp r11d, r8d
    jae bench_cow_next
    mov r8d, r11d
bench_cow_next:
    mov eax, 24                        /* yield: reap the child */
    syscall
    dec r15
    jnz bench_cow
    mov [r12+0x30], r8
    mov [r12+0x38], r9
    /* ── the sentinel: the responder exits on 63 ── */
    mov eax, 7
    mov rdi, rbx
    mov rsi, 63
    syscall
    cmp rax, 0
    jl 160f
    /* ── the self-report: "[BENCH] " + 10 hex words + newline ── */
    mov rax, 0x205D48434E45425B        /* "[BENCH] " LE: 5B 42 45 4E 43 48 5D 20 */
    mov [r12+0x100], rax
    /* the readback guard: did MY store land where I can see it? */
    mov rbx, [r12+0x100]
    cmp rbx, rax
    jne 162f                           /* my own store vanished */
    lea rdi, [r12+0x108]
    mov rsi, [r12]
    call bench_fmt
    mov rsi, [r12+8]
    call bench_fmt
    mov rsi, 16
    call bench_fmt
    mov rsi, [r12+0x10]
    call bench_fmt
    mov rsi, [r12+0x18]
    call bench_fmt
    mov rsi, 32
    call bench_fmt
    mov rsi, [r12+0x28]
    call bench_fmt
    mov rsi, [r12+0x30]
    call bench_fmt
    mov rsi, [r12+0x38]
    call bench_fmt
    mov rsi, 4
    call bench_fmt
    mov al, 10                          /* the newline */
    mov [rdi], al
    inc rdi
    mov rsi, rdi
    sub rsi, r12
    sub rsi, 0x100                      /* the length */
    mov eax, 1                          /* write(1, buf, len) */
    mov edi, 1
    mov rdx, rsi
    mov rsi, r12
    add rsi, 0x100
    syscall
    cmp rax, rdx
    jne 160f
    mov eax, 63
    xor edi, edi
    syscall

bench_child:
    mov eax, 63                         /* the fork child: its job
                                           is to EXIST (keep the
                                           share alive for the
                                           parent's fault) */
    xor edi, edi
    syscall

bench_responder:
    /* ── the responder: recv_wait -> reply, 63 = done ── */
    mov eax, 27
    mov rdi, rbx
    syscall
    cmp rax, 63
    je bench_resp_done
    xor r13d, r13d                      /* the retry budget */
bench_resp_reply:
    mov eax, 28                         /* reply(E, 42) */
    mov rdi, rbx
    mov rsi, 42
    syscall
    cmp rax, 1
    je bench_responder
    cmp rax, -11                        /* EAGAIN: the transient */
    jne 161f
    inc r13
    cmp r13, 64
    jae 161f
    mov eax, 24                         /* yield: let it park */
    syscall
    jmp bench_resp_reply
bench_resp_done:
    mov eax, 63
    xor edi, edi
    syscall

bench_fmt:
    /* rsi = value, rdi = dst: 16 hex chars + a space. rcx/rax are
       scratch (no syscall inside; the caller re-loads them). */
    mov ecx, 16
bench_fmt_digit:
    rol rsi, 4
    mov eax, esi
    and eax, 0xF
    add al, '0'
    cmp al, '9'
    jbe bench_fmt_store
    add al, 7
bench_fmt_store:
    mov [rdi], al
    inc rdi
    dec ecx
    jnz bench_fmt_digit
    mov al, ' '
    mov [rdi], al
    inc rdi
    ret

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
18: /* ── mode 12: the pipe pair (ADR-0029) ──────────────────────── */
    /* data[1]: 0 = the WRITER (holds WRITE on F only), 1 = the
       READER (F's owner). data[2..10]: channel F; data[10..18]:
       channel G (the no-cap probe target). ORDER-AGNOSTIC BY
       CONSTRUCTION (the ADR-0026 rule — the first cut pinned the
       interleaving with yields and a q35 tick broke it: preempted
       between drain and the EAGAIN probe, the reader saw the
       writer's next write land). Every check below holds under ANY
       interleaving: the wake value is the first write's count; the
       24/40 reads are exact-size FIFO drains; B is polled; the
       final EAGAIN probe runs after the writer's LAST F-write by
       program order; the bounded fill and the fd round-trip are
       local state only. */
    movzx eax, byte ptr [0x00403001]
    mov rbx, qword ptr [0x00403002]    /* channel F */
    mov rbp, qword ptr [0x0040300A]    /* channel G */
    test eax, eax
    jnz pipe_reader

pipe_writer:
    /* the opening yield (the round-M discipline) */
    mov eax, 24
    syscall
    /* pattern A at 0x403200 (24 bytes) */
    movabs rax, 0xAAAAAAAAAAAAAAAA
    mov qword ptr [0x00403200], rax
    movabs rax, 0xBBBBBBBBBBBBBBBB
    mov qword ptr [0x00403208], rax
    movabs rax, 0xCCCCCCCCCCCCCCCC
    mov qword ptr [0x00403210], rax
    /* pattern B at 0x403240 (40 bytes) */
    movabs rax, 0x1111111111111111
    mov qword ptr [0x00403240], rax
    movabs rax, 0x2222222222222222
    mov qword ptr [0x00403248], rax
    movabs rax, 0x3333333333333333
    mov qword ptr [0x00403250], rax
    movabs rax, 0x4444444444444444
    mov qword ptr [0x00403258], rax
    movabs rax, 0x5555555555555555
    mov qword ptr [0x00403260], rax
    /* exchange 1: 24 bytes of A onto F — deterministic (the ring is
       empty; the reader's recv_wait wake value is exactly this
       write's count, whatever the interleaving) */
    mov eax, 31                        /* pipe_write(F, A, 24) */
    mov rdi, rbx
    mov rsi, 0x00403200
    mov edx, 24
    syscall
    cmp rax, 24
    jne 180f
    /* the no-cap probe: G must refuse -EACCES (stateless — never
       racy) */
    mov eax, 31
    mov rdi, rbp
    mov rsi, 0x00403200
    mov edx, 8
    syscall
    cmp rax, -13
    jne 181f
    /* the pin: yield — the reader wakes and drains (or a tick
       interleaves; every check below is order-agnostic) */
    mov eax, 24
    syscall
    /* exchange 2: 40 bytes of B onto F — deterministic (64 <= 256;
       a short write is impossible) */
    mov eax, 31
    mov rdi, rbx
    mov rsi, 0x00403240
    mov edx, 40
    syscall
    cmp rax, 40
    jne 182f
    /* the pin: yield — the reader drains B and runs its fd
       round-trip */
    mov eax, 24
    syscall
    /* the PRIVATE bounded fill: the writer's OWN pipe() (fd path,
       local — zero cross-domain interleaving). Fill exactly 256
       (MAX_WRITE = the ring's capacity), then one more byte must
       refuse -EAGAIN: a channel is not an unbounded privilege. */
    mov eax, 12                        /* pipe() -> (w << 8) | r */
    syscall
    cmp rax, 0
    jle 183f
    mov r12, rax
    mov eax, 1                         /* write(wfd, A, 256) */
    mov edi, r12d
    shr edi, 8
    mov rsi, 0x00403200
    mov edx, 256
    syscall
    cmp rax, 256
    jne 184f
    mov eax, 1                         /* write(wfd, A, 1) on a FULL ring */
    mov edi, r12d
    shr edi, 8
    mov rsi, 0x00403200
    mov edx, 1
    syscall
    cmp rax, -11
    jne 185f
    mov eax, 3                         /* close(wfd) */
    mov edi, r12d
    shr edi, 8
    syscall
    cmp rax, 0
    jne 183f
    mov eax, 3                         /* close(rfd) */
    movzx edi, r12b
    syscall
    cmp rax, 0
    jne 183f
    mov eax, 63
    xor edi, edi
    syscall

pipe_reader:
    /* recv_wait parks (the ring is empty — the writer's opening
       yield hands this run the slot first); the first write's
       rendezvous wakes it with EXACTLY 24 (the write's count, not
       the queue total — deterministic under any interleaving) */
    mov eax, 27
    mov rdi, rbx
    syscall
    cmp rax, 24
    jne 190f
    /* drain A: ask EXACTLY 24 — the FIFO returns A's bytes whether
       or not B landed behind them */
    mov eax, 30                        /* pipe_read(F, buf, 24) */
    mov rdi, rbx
    mov rsi, 0x00403400
    mov edx, 24
    syscall
    cmp rax, 24
    jne 191f
    movabs rax, 0xAAAAAAAAAAAAAAAA
    cmp rax, qword ptr [0x00403400]
    jne 192f
    movabs rax, 0xBBBBBBBBBBBBBBBB
    cmp rax, qword ptr [0x00403408]
    jne 192f
    movabs rax, 0xCCCCCCCCCCCCCCCC
    cmp rax, qword ptr [0x00403410]
    jne 192f
    /* B: poll until the writer's 40 lands — order-agnostic by
       construction (a syscall is atomic from ring 3: the 40 is all
       there or none of it is; EAGAIN -> yield -> retry, bounded) */
    xor r13d, r13d                     /* retry counter (R13 survives) */
pipe_b_poll:
    mov eax, 30                        /* pipe_read(F, buf, 40) */
    mov rdi, rbx
    mov rsi, 0x00403440
    mov edx, 40
    syscall
    cmp rax, 40
    je pipe_b_got
    cmp rax, -11
    jne 195f
    inc r13d
    cmp r13d, 16
    jge 196f                           /* loud: B never landed */
    mov eax, 24                        /* yield: give the writer a slot */
    syscall
    jmp pipe_b_poll
pipe_b_got:
    movabs rax, 0x1111111111111111
    cmp rax, qword ptr [0x00403440]
    jne 197f
    movabs rax, 0x3333333333333333
    cmp rax, qword ptr [0x00403450]
    jne 197f
    movabs rax, 0x5555555555555555
    cmp rax, qword ptr [0x00403460]
    jne 197f
    /* empty, PROVABLY now: the writer writes nothing more on F (the
       bounded fill moved to its own private channel) — EAGAIN is
       deterministic under any interleaving */
    mov eax, 30                        /* pipe_read(F, buf, 1) */
    mov rdi, rbx
    mov rsi, 0x00403400
    mov edx, 1
    syscall
    cmp rax, -11
    jne 193f
    /* the fd round-trip: pipe() now creates a channel endpoint —
       write through the write fd, read through the read fd, close
       both (the fd-scoped channel reclaims itself). Local state
       only: deterministic. */
    mov eax, 12                        /* pipe() -> (w << 8) | r */
    syscall
    cmp rax, 0
    jle 198f
    mov r12, rax
    movabs rax, 0x0000217369676561     /* "aegis!" */
    mov qword ptr [0x00403280], rax
    mov eax, 1                         /* write(wfd, buf, 6) */
    mov edi, r12d
    shr edi, 8
    mov rsi, 0x00403280
    mov edx, 6
    syscall
    cmp rax, 6
    jne 199f
    mov eax, 0                         /* read(rfd, buf, 16) */
    movzx edi, r12b
    mov rsi, 0x00403480
    mov edx, 16
    syscall
    cmp rax, 6
    jne 199f
    movabs rax, 0x0000217369676561
    cmp rax, qword ptr [0x00403480]
    jne 199f
    mov eax, 3                         /* close(wfd) */
    mov edi, r12d
    shr edi, 8
    syscall
    cmp rax, 0
    jne 198f
    mov eax, 3                         /* close(rfd) */
    movzx edi, r12b
    syscall
    cmp rax, 0
    jne 198f
    mov eax, 63
    xor edi, edi
    syscall

19: /* ── mode 13: the Linux-ABI blob (ADR-0003 v1) ─────────────── */
    /* ONE domain speaking ONLY Linux x86_64 numbers: the v1
       whitelist translates at the entry, BEFORE the bounds check
       and the policy gate. Every nr below is Linux's. Data page:
       0x403300 'L', 0x403310 pattern (16 B), 0x403330 read buf,
       0x403301 the child's 'C'. */
    mov byte ptr [0x00403300], 0x4C   /* 'L' */
    mov eax, 1                        /* write(1, "L", 1) — nr 1 */
    mov edi, 1
    mov rsi, 0x00403300
    mov edx, 1
    syscall
    cmp rax, 1
    jne 200f
    mov eax, 22                       /* pipe() — nr 22: rax=rfd, rdx=wfd (the v1 SPLIT) */
    syscall
    cmp rax, 3
    jl 201f
    mov r12, rax                      /* rfd */
    mov r13, rdx                      /* wfd */
    movabs rax, 0x0123456789ABCDEF
    mov qword ptr [0x00403310], rax
    movabs rax, 0xFEDCBA9876543210
    mov qword ptr [0x00403318], rax
    mov eax, 1                        /* write(wfd, pat, 16) — nr 1 */
    mov edi, r13d
    mov rsi, 0x00403310
    mov edx, 16
    syscall
    cmp rax, 16
    jne 202f
    mov eax, 0                        /* read(rfd, buf, 16) — nr 0 */
    mov edi, r12d
    mov rsi, 0x00403330
    mov edx, 16
    syscall
    cmp rax, 16
    jne 203f
    movabs rax, 0x0123456789ABCDEF
    cmp rax, qword ptr [0x00403330]
    jne 204f
    movabs rax, 0xFEDCBA9876543210
    cmp rax, qword ptr [0x00403338]
    jne 204f
    mov eax, 3                        /* close(wfd) — nr 3 */
    mov edi, r13d
    syscall
    cmp rax, 0
    jne 205f
    mov eax, 0                        /* read(rfd, buf, 8) — nr 0: 0 = EOF (D7 via Linux nrs) */
    mov edi, r12d
    mov rsi, 0x00403330
    mov edx, 8
    syscall
    cmp rax, 0
    jne 206f
    mov eax, 9                        /* mmap(0, 4096, RW, MAP_PRIVATE|MAP_ANONYMOUS) — nr 9 */
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 0x22
    syscall
    cmp rax, 0x1000
    jle 207f
    mov r14, rax
    mov byte ptr [r14], 0x4D          /* 'M' — the fresh page holds a byte */
    movzx eax, byte ptr [r14]
    cmp eax, 0x4D
    jne 207f
    mov eax, 9                        /* mmap(..., MAP_SHARED) must refuse -EINVAL */
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 0x01
    syscall
    cmp rax, -22
    jne 208f
    mov eax, 11                       /* munmap(base, 4096) — nr 11 */
    mov rdi, r14
    mov esi, 4096
    syscall
    cmp rax, 0
    jne 209f
    mov eax, 63                       /* uname — nr 63: THE probe. Internal 63 is EXIT;
                                          the whitelist must answer -ENOSYS, not exit */
    syscall
    cmp rax, -38
    jne 210f
    mov eax, 39                       /* getpid — nr 39: unmapped -> -ENOSYS */
    syscall
    cmp rax, -38
    jne 211f
    /* open(2) — nr 2, the slice-2 arm: the O_* word is TRANSLATED at
       the entry, never passed through (the internal encoding is a
       4-bit contract; a raw Linux word would set bits that mean
       something else there). Path "/l" is self-written at 0x4033a0,
       the read-back buffer at 0x403340 (0x403330 is the pipe buf);
       the path is "/pub/s.txt" (the round-J writable subtree). */
    /* The round-J convention: /pub is the world-writable subtree
       (the domain's uid is 1000+id — root-owned "/" refuses). */
    movabs rax, 0x742E732F6275702F /* "/pub/s.t" */
    mov qword ptr [0x004033a0], rax
    mov dword ptr [0x004033a8], 0x00007478 /* "xt\0\0" */
    mov eax, 2                        /* open("/l", O_RDWR|O_CREAT=0x42, 0o644) */
    mov rdi, 0x004033a0
    mov esi, 0x42
    mov edx, 0x1A4
    syscall
    cmp rax, 3
    jl 213f
    mov r15, rax                      /* the file fd */
    mov eax, 1                        /* write(fd, pat, 16) — nr 1 */
    mov edi, r15d
    mov rsi, 0x00403310
    mov edx, 16
    syscall
    cmp rax, 16
    jne 214f
    mov eax, 3                        /* close(fd) — nr 3 */
    mov edi, r15d
    syscall
    cmp rax, 0
    jne 215f
    mov eax, 2                        /* reopen("/l", O_RDONLY=0, 0): an
                                          independent cursor must read
                                          the sixteen bytes back */
    mov rdi, 0x004033a0
    xor esi, esi
    xor edx, edx
    syscall
    cmp rax, 3
    jl 216f
    mov r15, rax
    mov eax, 0                        /* read(fd, buf, 16) — nr 0 */
    mov edi, r15d
    mov rsi, 0x00403340
    mov edx, 16
    syscall
    cmp rax, 16
    jne 217f
    movabs rax, 0x0123456789ABCDEF
    cmp rax, qword ptr [0x00403340]
    jne 218f
    movabs rax, 0xFEDCBA9876543210
    cmp rax, qword ptr [0x00403348]
    jne 218f
    mov eax, 3                        /* close(fd) — nr 3 */
    mov edi, r15d
    syscall
    cmp rax, 0
    jne 219f
    mov eax, 2                        /* O_EXCL (0x80): we have no
                                          exclusive-create semantics, so
                                          the word must REFUSE -EINVAL —
                                          silently dropping the bit would
                                          let an "only create if absent"
                                          caller open an existing file */
    mov rdi, 0x004033a0
    mov esi, 0xC2                     /* O_RDWR|O_CREAT|O_EXCL */
    xor edx, edx
    syscall
    cmp rax, -22
    jne 220f
    mov eax, 2                        /* O_APPEND (0x400): no append mode
                                          in the internal VFS — refuse,
                                          not approximate */
    mov rdi, 0x004033a0
    mov esi, 0x442                    /* O_RDWR|O_CREAT|O_APPEND */
    xor edx, edx
    syscall
    cmp rax, -22
    jne 221f
    mov eax, 57                       /* fork() — nr 57 */
    syscall
    test rax, rax
    jz 21f                            /* the child */
    mov r15, rax                      /* the child's pid (r15 is free:
                                          every file fd is closed) */
    /* The wstatus target must be a PRIVATE writable page: fork marked
       every shared page read-only in BOTH tables (CoW), and the
       kernel's direct write refuses loudly (ADR-0007: a CPL0 fault is
       a kernel bug) instead of servicing the copy the user's own
       store would. A fresh mmap after fork is parent-private RW. */
    mov eax, 9                        /* mmap(0, 4096, RW, 0x22) — nr 9 */
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 0x22
    syscall
    cmp rax, 0x1000
    jl 226f                           /* the scratch mmap failed */
    mov r14, rax                      /* the wstatus target */
    mov eax, 61                       /* wait4(-1, ws, 0, WNOHANG) — nr 61:
                                          the child is fork-parked, nothing
                                          is ready -> exactly 0 (the
                                          non-blocking probe) */
    mov rdi, -1
    mov rsi, r14
    xor edx, edx
    mov r10d, 1                       /* WNOHANG */
    syscall
    test rax, rax
    jnz 222f
    mov eax, 61                       /* wait4(-1, ws, 0, 0): the BLOCKING
                                          wait — the syscall parks (rip-2:
                                          resume RE-EXECUTES it), the
                                          dispatcher runs the child, its
                                          exit(7) wakes this run, and the
                                          re-executed wait4 reaps it */
    mov rdi, -1
    mov rsi, r14
    xor edx, edx
    xor r10d, r10d
    syscall
    cmp rax, 3                        /* a pid, never an errno */
    jl 223f
    cmp rax, r15                      /* the reaped pid IS the fork's child */
    jne 223f
    cmp dword ptr [r14], 0x0700        /* wstatus == 7 << 8: WIFEXITED,
                                           WEXITSTATUS == 7 — the status
                                           crossed the boundary */
    jne 224f
    mov eax, 61                       /* after the reap: no children ->
                                          -ECHILD (Linux 10), even WNOHANG */
    mov rdi, -1
    xor esi, esi
    xor edx, edx
    mov r10d, 1
    syscall
    cmp rax, -10
    jne 225f
    jmp 20f
21: /* child: the store into the CoW-shared data page faults and
       takes a private copy (fork/CoW under the Linux ABI too) */
    mov byte ptr [0x00403301], 0x43   /* 'C' */
    mov eax, 1                        /* write(1, "C", 1) — nr 1 */
    mov edi, 1
    mov rsi, 0x00403301
    mov edx, 1
    syscall
    cmp rax, 1
    jne 212f
    mov eax, 231                      /* exit_group(7) — a NONZERO code on
                                          purpose: the parent's wstatus
                                          check (7 << 8) is the proof the
                                          exit status crossed the boundary */
    mov edi, 7
    syscall
20: mov eax, 231                      /* exit_group(0) — nr 231 (the alias) */
    xor edi, edi
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
145: mov eax, 63
    mov edi, 145                      /* the granter: mmap/grant window failed */
    syscall
147: mov eax, 63
    mov edi, 147                      /* the granter: a send failed */
    syscall
148: mov eax, 63
    mov edi, 148                      /* the granter: the call returned wrong */
    syscall
149: mov eax, 63
    mov edi, 149                      /* the granter: the mark never landed */
    syscall
146: mov eax, 63
    mov edi, 146                      /* the grantee: a granted read/write failed */
    syscall
150: mov eax, 63
    mov edi, 150                      /* the grantee: recv lo6 out of bound */
    syscall
151: mov eax, 63
    mov edi, 151                      /* the grantee: recv hi6 out of bound */
    syscall
152: mov eax, 63
    mov edi, 152                      /* the grantee: the w0 pattern wrong */
    syscall
153: mov eax, 63
    mov edi, 153                      /* the grantee: the w1 pattern wrong */
    syscall
154: mov eax, 63
    mov edi, 154                      /* the grantee: the write did not stick */
    syscall
155: mov eax, 63
    mov edi, 155                      /* the grantee: the reply did not wake */
    syscall
160: mov eax, 63
    mov edi, 160                      /* the measurer: a bench step failed */
    syscall
162: mov eax, 63
    mov edi, 162                      /* the measurer: own readback failed */
    syscall
161: mov eax, 63
    mov edi, 161                      /* the responder: a reply failed */
    syscall
170: mov eax, 63
    mov edi, 170                      /* r12 lost in the yield phase */
    syscall
171: mov eax, 63
    mov edi, 171                      /* r12 lost in the RTT phase */
    syscall
172: mov eax, 63
    mov edi, 172                      /* r12 lost in the grant phase */
    syscall
180: mov eax, 63
    mov edi, 180                      /* the pipe writer: write 1 short */
    syscall
181: mov eax, 63
    mov edi, 181                      /* the pipe writer: no-cap EACCES missing */
    syscall
182: mov eax, 63
    mov edi, 182                      /* the pipe writer: write 2 short */
    syscall
183: mov eax, 63
    mov edi, 183                      /* the pipe writer: the private pipe failed */
    syscall
184: mov eax, 63
    mov edi, 184                      /* the pipe writer: the bounded fill short */
    syscall
185: mov eax, 63
    mov edi, 185                      /* the pipe writer: full-ring EAGAIN missing */
    syscall
190: mov eax, 63
    mov edi, 190                      /* the pipe reader: the rendezvous count wrong */
    syscall
191: mov eax, 63
    mov edi, 191                      /* the pipe reader: drain 1 short */
    syscall
192: mov eax, 63
    mov edi, 192                      /* the pipe reader: pattern A wrong */
    syscall
193: mov eax, 63
    mov edi, 193                      /* the pipe reader: empty-channel EAGAIN missing */
    syscall
194: mov eax, 63
    mov edi, 194                      /* the pipe reader: the fast path wrong */
    syscall
195: mov eax, 63
    mov edi, 195                      /* the pipe reader: the B poll wrong errno */
    syscall
196: mov eax, 63
    mov edi, 196                      /* the pipe reader: B never landed */
    syscall
197: mov eax, 63
    mov edi, 197                      /* the pipe reader: pattern B wrong */
    syscall
198: mov eax, 63
    mov edi, 198                      /* the pipe reader: the fd pipe/close failed */
    syscall
199: mov eax, 63
    mov edi, 199                      /* the pipe reader: the fd write/read wrong */
    syscall
200: mov eax, 231
    mov edi, 200                      /* the console write (nr 1) short */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 200
    syscall
201: mov eax, 231
    mov edi, 201                      /* pipe (nr 22) did not split rax/rdx */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 201
    syscall
202: mov eax, 231
    mov edi, 202                      /* the pipe write (nr 1) short */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 202
    syscall
203: mov eax, 231
    mov edi, 203                      /* the pipe read (nr 0) short */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 203
    syscall
204: mov eax, 231
    mov edi, 204                      /* the readback pattern wrong */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 204
    syscall
205: mov eax, 231
    mov edi, 205                      /* close (nr 3) nonzero */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 205
    syscall
206: mov eax, 231
    mov edi, 206                      /* EOF after the write end closed: not 0 */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 206
    syscall
207: mov eax, 231
    mov edi, 207                      /* mmap (nr 9) refused or the page dead */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 207
    syscall
208: mov eax, 231
    mov edi, 208                      /* MAP_SHARED did not refuse -EINVAL */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 208
    syscall
209: mov eax, 231
    mov edi, 209                      /* munmap (nr 11) nonzero */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 209
    syscall
210: mov eax, 231
    mov edi, 210                      /* uname (nr 63) is not -ENOSYS — the whitelist */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 210
    syscall
211: mov eax, 231
    mov edi, 211                      /* getpid (nr 39) is not -ENOSYS */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 211
    syscall
212: mov eax, 231
    mov edi, 212                      /* the child's write (nr 1) short */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 212
    syscall
213: mov eax, 231
    mov edi, 213                      /* open(nr 2, O_RDWR|O_CREAT) gave no fd */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 213
    syscall
214: mov eax, 231
    mov edi, 214                      /* the file write (nr 1) short */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 214
    syscall
215: mov eax, 231
    mov edi, 215                      /* close(file) (nr 3) failed */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 215
    syscall
216: mov eax, 231
    mov edi, 216                      /* reopen(O_RDONLY) gave no fd */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 216
    syscall
217: mov eax, 231
    mov edi, 217                      /* the read-back (nr 0) short */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 217
    syscall
218: mov eax, 231
    mov edi, 218                      /* the read-back bytes wrong */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 218
    syscall
219: mov eax, 231
    mov edi, 219                      /* close(reopened) (nr 3) failed */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 219
    syscall
220: mov eax, 231
    mov edi, 220                      /* O_EXCL did not refuse -EINVAL */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 220
    syscall
221: mov eax, 231
    mov edi, 221                      /* O_APPEND did not refuse -EINVAL */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 221
    syscall
222: mov eax, 231
    mov edi, 222                      /* wait4 WNOHANG did not answer 0 */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 222
    syscall
223: mov eax, 231
    mov edi, 223                      /* the blocking wait4 gave a wrong pid */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 223
    syscall
224: mov eax, 231
    mov edi, 224                      /* wstatus != 7 << 8 */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 224
    syscall
225: mov eax, 231
    mov edi, 225                      /* no -ECHILD after the reap */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 225
    syscall
226: mov eax, 231
    mov edi, 226                      /* the wstatus scratch mmap failed */
    syscall
    mov eax, 63                       /* the internal fallback (pre-v1 legibility) */
    mov edi, 226
    syscall
"#,
);
