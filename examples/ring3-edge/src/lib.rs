//! Ring-3 edge blob (N1 security example): probes the exact boundary
//! the SYS_WRITE copy must respect — the last bytes of the mapped data
//! page (0x403000..0x404000) and the first byte of the absent next page.
//!
//!   write(1, 0x403FFD, 3)  -> 3  (ends EXACTLY at the page end: the
//!                                 copy must read only these 3 bytes)
//!   write(1, 0x403FFF, 1)  -> 1  (the page's final byte)
//!   write(1, 0x404000, 1)  -> -EFAULT (crosses into the absent page)
//!
//! Any other answer exits 99 (loud). Exits 42 only when the kernel
//! answered all three correctly — the kernel prints the CI markers.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* ── tail write: 3 bytes ending exactly at the data-page end ── */
    mov eax, 1                 /* SYS_WRITE */
    mov edi, 1                 /* fd: console */
    mov rsi, 0x00403FFD        /* DATA_BASE + 4096 - 3 */
    mov edx, 3
    syscall
    cmp rax, 3
    jne 9f
    /* ── the data page's final single byte ── */
    mov eax, 1
    mov edi, 1
    mov rsi, 0x00403FFF
    mov edx, 1
    syscall
    cmp rax, 1
    jne 9f
    /* ── crossing: the first byte of the ABSENT next page ── */
    mov eax, 1
    mov edi, 1
    mov rsi, 0x00404000
    mov edx, 1
    syscall
    cmp rax, -14               /* -EFAULT? */
    jne 9f
    mov eax, 63                /* SYS_EXIT */
    mov edi, 42                /* every answer was correct */
    syscall
9:  mov eax, 63                /* SYS_EXIT */
    mov edi, 99                /* WRONG answer — loud */
    syscall
"#,
);
