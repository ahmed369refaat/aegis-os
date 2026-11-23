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

    /* ── Phase 7: init launches the shell — the third child. The
       child execve("/bin/sh") and never returns; the parent's
       BLOCKING wait4 is the init-shape relationship. The shell
       exits 0 on a finished script AND on an idle console (~2 s
       without input — the base lanes' case), so both worlds reap a
       clean wstatus; anything else dies loudly. ── */
    mov eax, 57                       /* fork() — nr 57: the shell */
    syscall
    test rax, rax
    js 96f                            /* fork refused */
    jz 30f                            /* we are the exec child */
    mov r15, rax                      /* the shell's pid (diagnostics) */
    /* The CoW rule mode 13 pinned, applied to OURSELVES: THIS fork
       demoted the old wstatus page (r14, a private mmap made before
       this fork) to read-only in both tables — and the wait4 arm
       demands a WRITABLE wstatus target (-EFAULT otherwise, measured
       live: init died 34 = 20+EFAULT). A fresh mmap AFTER the fork
       is parent-private RW. */
    mov eax, 9                        /* mmap(0, 4096, RW, 0x22) — nr 9 */
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 0x22
    syscall
    cmp rax, 0x1000
    jl 99f                            /* the wstatus mmap failed */
    mov r14, rax
4:  mov eax, 61                       /* wait4(-1, ws, 0, 0) — blocks
                                          while the shell runs; a
                                          reaped pid is POSITIVE, so
                                          the loop keeps waiting until
                                          ECHILD ends it (the drain
                                          discipline, again) */
    mov rdi, -1
    mov rsi, r14
    xor edx, edx
    xor r10d, r10d
    syscall
    cmp rax, -10                      /* ECHILD: the shell reaped, no
                                          children left */
    je 5f
    cmp rax, 3
    jge 6f                            /* a pid — check the wstatus */
    /* wait4 answered an errno that is not ECHILD: init exits
       20+|errno| so the kmain error line NAMES the refusal. */
    mov rdi, 20
    sub rdi, rax
    mov eax, 231
    syscall
6:  cmp dword ptr [r14], 0            /* the reaped child's wstatus:
                                          0 = the script ran or the
                                          console was idle — both
                                          clean. (An execve refusal
                                          lands here as 40+|errno|.) */
    jne 7f                            /* NONZERO: die naming the code —
                                          init exits 100+(wstatus>>8):
                                          142=execve ENOENT, 148=ENOEXEC,
                                          152=ENOMEM, 154=EFAULT (the
                                          child's 40+|errno| encoder),
                                          197=the shell's own 97 */
    jmp 4b                            /* wait again — ECHILD ends it */
5:  mov eax, 231                      /* exit_group(0): the loop
                                          drained clean AND the shell
                                          came home clean */
    xor edi, edi
    syscall

30: /* we are the exec child: build "/bin/sh" and argv in the data
       page (the arm reads the strings BEFORE the point of no
       return — the old image's pages), then execve. */
    movabs rax, 0x0068732f6e69622f    /* "/bin/sh\0" */
    mov qword ptr [0x00403000], rax
    mov dword ptr [0x00403008], 0x00006873 /* "sh\0\0" — argv[0] */
    mov qword ptr [0x00403010], 0x00403008 /* argv[0] -> "sh" */
    mov qword ptr [0x00403018], 0          /* argv[1] = NULL */
    mov eax, 59                       /* execve(path, argv, NULL) */
    mov rdi, 0x00403000
    mov rsi, 0x00403010
    xor edx, edx
    syscall                           /* never returns on success */
    /* execve refused — die NAMING the errno: the exit code is
       40 + |errno| (ENOENT=42, ENOEXEC=48, ENOMEM=52, EFAULT=54...),
       so init's error line says exactly which arm refused. */
    mov rdi, 40
    sub rdi, rax
    mov eax, 231
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
    /* unreachable-here marker */
96: mov eax, 231
    mov edi, 96                       /* the shell fork refused, or
                                          execve("/bin/sh") refused */
    syscall
7:  /* the wstatus namer: exit 100 + (wstatus >> 8) */
    mov ecx, dword ptr [r14]
    shr ecx, 8
    add ecx, 100
    mov eax, 231
    mov edi, ecx
    syscall
97: mov eax, 231
    mov edi, 97                       /* the shell wait answered an
                                          errno that is not ECHILD */
    syscall
98: mov eax, 231
    mov edi, 98                       /* the shell's wstatus nonzero */
    syscall
99: mov eax, 231
    mov edi, 99                       /* the shell-wait wstatus mmap
                                          failed */
    syscall
"#,
);
