//! The RUSTC userland citizen (P1-2's third installable): a REAL
//! rustc-built ELF64 — the same recipe as the exec target (rustc
//! `--emit=obj` + `ld -T`), the same CANONICAL cage — delivered
//! through the SIGNED PACKAGE path.
//!
//! Why a citizen this small exists at all: the repo's other two
//! package payloads (the stripped gcc hello ELF, 8,496 B; the netcat
//! client, 8,576 B) both live in the ramfs's 10-KiB large-file spill
//! windows, and the netcat transaction's commit peak already holds
//! four of the five slots. A rustc image of THIS size (512 B) stays
//! under the 1-KiB INLINE window: its .akp (~700 B), its staged copy
//! and its installed file all ride inline — the third package fits
//! the memory budget with margin, not luck.
//!
//! The packed layout's coupling: `ld -n` lays the text at file offset
//! 0xB0 and the data at 0xD2; the link script pins the vaddrs at
//! 0x4000B0/0x4030D2 so `vaddr % 4096 == offset % 4096` — the
//! loader's congruence gate (src/elf.rs) holds BY CONSTRUCTION, and
//! scripts/check-citizen.py fails the build if an ld layout drift
//! ever breaks it. The page geometry is the canonical cage's: the
//! same two pages RX/RW with the guard gap between — only the
//! intra-page offsets shift.
//!
//! It is a genuine program, not padding: the `syscall` instruction
//! with the INTERNAL number table (WRITE=1, EXIT=63 — the flat-blob
//! family's convention), fd-1 console write, then a clean exit(0).
//! The lane does NOT run it (the exec registry resolves compiled-in
//! and disk-sourced slots, not /usr/bin/* — exec-from-VFS is a
//! named P2 item): the proof is byte-exact install + the loader's
//! own `build_exec_plan` gate, exactly like the netcat round.
//!
//! Invariants (the flat-blob contract, kept through the linker):
//! position-dependent, text RX at 0x400000, data RW at 0x403000, no
//! stack use, ends in SYS_EXIT.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text
    .globl _start
_start:
    mov eax, 1                  /* SYS_WRITE (internal nr 1) */
    mov edi, 1                  /* fd 1: the console alias */
    mov esi, 0x004030d2         /* the message (the packed .data base) */
    mov edx, 19                 /* its length */
    syscall
    mov eax, 63                 /* SYS_EXIT (internal nr 63) */
    xor edi, edi                /* exit code 0 */
    syscall
1:  hlt                         /* unreachable: EXIT never returns */
    jmp 1b

    .section .data
msg: .ascii "RUST-CITIZEN-AEGIS\n" /* 0x403000, 19 B — GAS lays
                                     .ascii without padding */
"#,
);
