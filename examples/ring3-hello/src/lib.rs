//! Ring-3 hello (PR-1.4 example blob): write a greeting to the console
//! through the first real syscall, then exit cleanly.
//!
//! Invariants: pure position-dependent code at the canonical
//! `mm::user_layout` addresses (code page at 0x400000, data at
//! 0x403000 — the kernel copies the message into the data page before
//! launch); touches nothing but its own pages; ends in SYS_EXIT, never
//! in a fault or a loop. 26 = the exact length of
//! "hello from ring 3 (CPL=3)\n".
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    mov eax, 1              /* SYS_WRITE */
    mov edi, 1              /* fd: console */
    mov esi, 0x00403000     /* DATA_BASE (message lives here) */
    mov edx, 26             /* len */
    syscall
    mov eax, 63             /* SYS_EXIT */
    mov edi, 0              /* code 0: clean exit */
    syscall
"#,
);
