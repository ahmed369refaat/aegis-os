//! The execve target (ADR-0003 v1 slice 4): the first REAL ELF64
//! image this kernel execs.
//!
//! Every other ring-3 example is a FLAT blob — raw .text bytes the
//! kernel copies at a fixed base and enters at that base. This one is
//! a linked ELF: PT_LOAD segments at their DECLARED vaddrs (text RX
//! at 0x400000, data RW at 0x403000 with a bss tail), an entry point
//! the loader reads from `e_entry` (_start), and a bss byte that must
//! read ZERO on a correctly zero-filled fresh image — the loader's
//! contract, probed live from the exec'd code itself.
//!
//! Speaks LINUX nrs (the child it execs from runs Linux mode; the
//! ABI is a domain property, inherited across exec like fork): fd-1
//! console write(2), then exit_group(11) — the 11 becomes the
//! wstatus word the forking parent's wait4(2) reaps (11 << 8), the
//! slice's round-trip proof.
//!
//! Lengths are baked like every blob here (39 = the clean marker,
//! 28 = the dirty marker at 0x403027 — the .data page holds both).
//! Invariants: only its own cage pages; ends in exit_group, never a
//! fault or a loop; no stack use before the kernel's fresh stack is
//! proven (it pushes nothing at all).
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text
    .globl _start
_start:
    /* bss probe: the zero-fill contract. The byte at 0x403800 is in
     * the RW segment's memsz-but-not-filesz tail — nothing in the
     * file ever sets it, so a NON-zero read means the loader mapped
     * a dirty or stale frame and answered a lie. */
    mov rax, [0x403800]
    test rax, rax
    jnz .dirty

    mov eax, 1                  /* write(2) */
    mov edi, 1                  /* fd 1: the console alias */
    mov esi, 0x00403000         /* the clean marker */
    mov edx, 39
    syscall
    jmp .done
.dirty:
    mov eax, 1
    mov edi, 1
    mov esi, 0x00403027        /* the dirty marker */
    mov edx, 28
    syscall
.done:
    mov eax, 231                /* exit_group(2) */
    mov edi, 11                /* the code the parent's wait4 reaps */
    syscall
6:  hlt                         /* unreachable: EXIT never returns */
    jmp 6b

    .section .data
msg_clean: .ascii "[M3] exec-target: bss-clean entry live\n"
msg_dirty: .ascii "[M3] exec-target: BSS-DIRTY\n"

    .section .bss
    .globl exec_bss_probe
exec_bss_probe:
    .quad 0                     /* lands at 0x403800 per exec.ld */
"#,
);
