//! Ring-3 ROGUE DRIVER DOMAIN (ADR-0017's quarantine proof): a
//! deliberately bad driver whose register messages fall outside its
//! granted window. The ring-0 core refuses every one — counted, so
//! the monitor sees them — and after the refusal LADDER closes the
//! channel, even a LEGAL offset answers the refusal sentinel: a bad
//! driver loses its device, the boot continues.
//!
//! The report (the domain's data page at 0x403000): 5 = every hostile
//! message was refused AND the post-closure legal read too; 0xDEAD =
//! some message was served (the kernel treats that as a loud failure
//! of the containment).
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* The SYS_DEVREG read: rdi=0, rsi=off, rdx=len, r8=region,
     * rax=33 → rax = the value or u64::MAX (refused). */
.macro devreg_read off, len, region
    xor edi, edi
    mov rsi, \off
    mov edx, \len
    mov r8d, \region
    mov eax, 33
    syscall
.endm

    /* Four hostile reads: offsets far outside the granted window —
     * the core refuses each one (counted: the monitor feed). */
    devreg_read 0x10000, 4, 3
    cmp rax, -1
    jne fail
    devreg_read 0x10000, 4, 3
    cmp rax, -1
    jne fail
    devreg_read 0x10000, 4, 3
    cmp rax, -1
    jne fail
    devreg_read 0x10000, 4, 3
    cmp rax, -1
    jne fail

    /* The fourth refusal tripped the ladder — the channel is CLOSED.
     * The proof: a LEGAL offset (the config's first dword) now
     * refuses too — the ladder check runs before the window check. */
    devreg_read 0, 4, 3
    cmp rax, -1
    jne fail

    /* Report: every hostile message refused, the closure confirmed. */
    mov qword ptr [0x403000], 5
    mov eax, 63                     /* SYS_EXIT */
    xor edi, edi                    /* 0: the rogue ran its course */
    syscall

fail:
    /* A message was SERVED (or the closure failed) — the containment
     * itself is broken; loud. */
    mov qword ptr [0x403000], 0xdead
    mov eax, 63
    mov edi, 9
    syscall
"#,
);
