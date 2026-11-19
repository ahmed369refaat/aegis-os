//! Multiboot v1 header and the 32-bit entry stub.
//!
//! The flow (classic multiboot → long mode; see `docs/M1-PLAN.md` §3.1):
//!
//! 1. QEMU (`-kernel`, `-machine pc`) loads this ELF at 1 MiB and enters
//!    `_start` in 32-bit protected mode with `EAX = 0x2BADB002` and
//!    `EBX` pointing at the multiboot info struct.
//! 2. Stash the multiboot registers and an early TSC stamp into statics
//!    (defined in `hw`), switch to our own GDT and stack.
//! 3. Call `setup_page_tables` (Rust, `paging.rs`) to identity-map the
//!    first 1 GiB with 2 MiB pages.
//! 4. Enable PAE → load CR3 → set EFER.LME → set CR0.PG, then far-jump
//!    into the 64-bit code segment.
//! 5. Reload data segments, set the 64-bit stack, and call `kmain`
//!    with the saved multiboot registers as `(magic, info)` arguments.
//!
//! SAFETY: this is freestanding machine code by definition; it runs before
//! any Rust invariant exists. It is kept as small as possible — everything
//! that can be Rust is Rust.

use core::arch::global_asm;

global_asm!(
    // AT&T syntax keeps every operand's meaning explicit (immediate vs
    // memory) — no guessing about `OFFSET` keywords.
    r#"
.section .boot, "a"
.align 4
multiboot_header:
    .long 0x1BADB002          /* magic                                  */
    .long 0x00000003          /* flags: page-align modules | want memory info */
    .long 0xE4524FFB          /* checksum: -(magic + flags)             */

.section .text
.code32
.globl _start
_start:
    cli
    /* Stash the multiboot registers before anything can clobber them. */
    movl    %eax, MULTIBOOT_MAGIC
    movl    %ebx, MULTIBOOT_INFO
    /* First timestamp: TSC at the first instruction we control. */
    rdtsc
    movl    %eax, BOOT_TSC_LO
    movl    %edx, BOOT_TSC_HI
    /* Stack lives in .bss (256 KiB, see linker.ld). */
    movl    $stack_top, %esp
    /* Load our own GDT: the loader's descriptor tables are unspecified. */
    lgdt    gdt_descriptor
    ljmp    $0x08, $1f
1:
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs
    /* Build the identity page tables (Rust, still 32-bit code). */
    call    setup_page_tables
    /* PAE (CR4.PAE). */
    movl    %cr4, %eax
    orl     $0x20, %eax
    movl    %eax, %cr4
    /* CR3 = PML4 (linked at 1 MiB, identity-mapped). */
    movl    $BOOT_PML4, %eax
    movl    %eax, %cr3
    /* EFER.LME (MSR 0xC0000080, bit 8). */
    movl    $0xC0000080, %ecx
    rdmsr
    orl     $0x100, %eax
    wrmsr
    /* Enable paging: still executing 32-bit (compatibility mode). */
    movl    %cr0, %eax
    orl     $0x80000000, %eax
    movl    %eax, %cr0
    /* Far jump into the 64-bit code segment (selector 0x18). */
    ljmp    $0x18, $2f
2:
.code64
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs
    movq    $stack_top, %rsp
    /* kmain(magic, info) — SysV: rdi, rsi. */
    movl    MULTIBOOT_MAGIC, %edi
    movl    MULTIBOOT_INFO, %esi
    call    aegis_kmain_entry
3:
    cli
    hlt
    jmp     3b

.p2align 4
/* null | 32-bit code (0x08) | data (0x10) | 64-bit code (0x18) */
gdt:
    .quad   0
    .quad   0x00CF9A000000FFFF
    .quad   0x00CF92000000FFFF
    .quad   0x00AF9A000000FFFF
gdt_descriptor:
    .word   31                     /* 4 entries * 8 bytes - 1 */
    .long   gdt
"#,
    options(att_syntax)
);
