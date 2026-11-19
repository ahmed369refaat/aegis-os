//! Ring-3 rogue (PR-1.4 security example): performs exactly one hostile
//! act per run, selected by the mode byte the kernel places at
//! DATA_BASE before the launch:
//!   mode 0 — call into the non-executable data page (NX must fault),
//!   mode 1 — read through the direct-map base (U/S must fault),
//!   mode 2 — call unknown syscall 200 (must return -ENOSYS, audited),
//!            then verify the errno and exit 42 on success / 99 if the
//!            kernel answered anything else.
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
1:  /* ── mode 1: read through the kernel direct map ── */
    mov rax, [0xFFFF888000000000]      /* must #PF (supervisor page) */
    ret                                /* unreachable */
2:  /* ── mode 0: execute the non-executable data page ── */
    mov eax, 0x00403000
    call rax                           /* must #PF (instruction fetch, NX) */
    ret                                /* unreachable */
"#,
);
