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
//! slice's round-trip proof. A MISSING argc/argv (Phase 6 S3) exits
//! 12 instead — a distinct, loud refusal.
//!
//! Lengths are baked like every blob here (61 = the clean marker at
//! 0x403000, 28 = the dirty marker at 0x40303D, 17 = the path copy
//! at 0x403059, 36 = the argv-missing marker at 0x40306A — the .data
//! page holds all four; GAS lays .ascii sequentially, no padding).
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
    /* Phase 6 S3: the argc/argv materialization probe — the kernel
     * must build the SysV initial stack before entering this image:
     * [rsp] = argc, then the argv pointers, argv[0] = the exec path
     * string. Pre-S3 (the zero-register, bare-stack entry) reads
     * argc = 0 and lands at 12 — the parent's wait4 expects 11<<8,
     * so a regressed kernel is loud, never silent. */
    mov rax, [rsp]              /* argc */
    cmp rax, 1                  /* the mode-13 child: (path, NULL) — argv[0] alone */
    jne .argv_bad
    mov rsi, [rsp + 8]          /* argv[0] */
    mov rdi, 0x00403059        /* the expected path (a .data copy) */
    mov rcx, 18                /* 17 bytes incl NUL; NUL ends both */
1:  mov al, [rsi]
    cmp al, [rdi]
    jne .argv_bad
    test al, al
    jz 2f
    inc rsi
    inc rdi
    dec rcx
    jnz 1b
2:  /* argc/argv verified — the bss probe: the zero-fill contract.
     * The byte at 0x403800 is in the RW segment's memsz-but-not-
     * filesz tail — nothing in the file ever sets it, so a NON-zero
     * read means the loader mapped a dirty or stale frame. */
    mov rax, [0x403800]
    test rax, rax
    jnz .dirty

    mov eax, 1                  /* write(2) */
    mov edi, 1                  /* fd 1: the console alias */
    mov esi, 0x00403000         /* the clean marker */
    mov edx, 61
    syscall
    jmp .done
.dirty:
    mov eax, 1
    mov edi, 1
    mov esi, 0x0040303D        /* the dirty marker */
    mov edx, 28
    syscall
    jmp .done
.argv_bad:
    mov eax, 1
    mov edi, 1
    mov esi, 0x0040306A        /* the argv-missing marker */
    mov edx, 36
    syscall
    mov eax, 231
    mov edi, 12                /* distinct: the parent reaps 12<<8 */
    syscall
.done:
    mov eax, 231                /* exit_group(2) */
    mov edi, 11                /* the code the parent's wait4 reaps */
    syscall
6:  hlt                         /* unreachable: EXIT never returns */
    jmp 6b

    .section .data
msg_clean: .ascii "[M3] exec-target: bss-clean entry live, argc 1 argv verified\n" /* 0x403000 */
msg_dirty: .ascii "[M3] exec-target: BSS-DIRTY\n"   /* 0x40303D */
path_ref:  .ascii "/bin/exec-target\0"              /* 0x403059 */
msg_argv:  .ascii "[M3] exec-target: argc/argv MISSING\n" /* 0x40306A */

    .section .bss
    .globl exec_bss_probe
exec_bss_probe:
    .quad 0                     /* lands at 0x403800 per exec.ld */
"#,
);
