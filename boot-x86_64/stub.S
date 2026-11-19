/*
 * AegisOS x86_64 boot stub (stage 1 of the two-stage boot).
 *
 * WHY THIS EXISTS: QEMU's `-kernel` multiboot loader only accepts ELF32
 * images ("Cannot load x86-64 image, give a 32bit one"), while the kernel
 * proper is 64-bit Rust linked as ELF64. The stub is therefore a tiny
 * ELF32 multiboot-v1 image that:
 *
 *   1. gets loaded by QEMU (-kernel) or GRUB at 1 MiB, entered in 32-bit
 *      protected mode with EAX = 0x2BADB002, EBX = multiboot info address,
 *   2. stashes the multiboot registers and an early TSC stamp,
 *   3. loads its own GDT (the loader's is unspecified),
 *   4. builds identity page tables for the first 1 GiB (2 MiB pages),
 *   5. enables PAE -> EFER.LME -> CR0.PG and far-jumps into 64-bit code,
 *   6. jumps to the 64-bit kernel entry, passing:
 *        RDI = multiboot magic, RSI = info address, RDX = boot TSC.
 *
 * The 64-bit kernel blob is embedded by `.incbin` at its 2 MiB link base
 * (see stub.ld), so no copying is needed. The kernel's entry address is
 * injected at stub link time: `ld --defsym=kernel_entry=<addr>` (boot.sh
 * reads it from the kernel ELF header).
 *
 * TRUST BASE: this file is pure assembly with no logic and no data
 * interpretation; it is the machine-state setup the Rust kernel cannot
 * perform for itself. Keep it minimal and commented.
 */

.set MB_MAGIC,      0x1BADB002
.set MB_FLAGS,      0x3             /* page-align modules | want memory info */
.set MB_CHECKSUM,   -(MB_MAGIC + MB_FLAGS)

.section .mbheader, "a"
.align 4
mb_header:
    .long   MB_MAGIC
    .long   MB_FLAGS
    .long   MB_CHECKSUM

.section .text
.code32
.globl _start
_start:
    cli
    /* Stash the multiboot registers into our own bss before anything
     * can clobber them. */
    movl    %eax, (mb_magic_saved)
    movl    %ebx, (mb_info_saved)
    /* Early TSC stamp: the first instruction we control. */
    rdtsc
    movl    %eax, (stub_tsc_lo)
    movl    %edx, (stub_tsc_hi)
    /* Stack in our own bss. */
    movl    $stub_stack_top, %esp
    /* Our own GDT: the loader's descriptor tables are unspecified. */
    lgdt    gdt_descriptor
    ljmp    $0x08, $1f
1:
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs

    /* ── identity page tables (in .bss, zeroed by the loader) ── */
    /* PML4[0] = PDPT | PRESENT|WRITE */
    movl    $boot_pml4, %eax
    movl    $boot_pdpt, %ecx
    orl     $3, %ecx
    movl    %ecx, (%eax)
    /* PDPT[0] = PD | PRESENT|WRITE */
    movl    $boot_pdpt, %eax
    movl    $boot_pd, %ecx
    orl     $3, %ecx
    movl    %ecx, (%eax)
    /* PD[i] = (i << 21) | PRESENT|WRITE|HUGE(0x83), 512 entries = 1 GiB. */
    movl    $boot_pd, %edi
    movl    $0x83, %eax              /* entry value for i = 0 */
    xorl    %ecx, %ecx
2:
    movl    %eax, (%edi)
    addl    $8, %edi
    addl    $0x200000, %eax          /* next 2 MiB block */
    incl    %ecx
    cmpl    $512, %ecx
    jb      2b

    /* ── long mode ── */
    /* CR4.PAE */
    movl    %cr4, %eax
    orl     $0x20, %eax
    movl    %eax, %cr4
    /* CR3 = PML4 (identity: link address == physical address). */
    movl    $boot_pml4, %eax
    movl    %eax, %cr3
    /* EFER.LME (MSR 0xC0000080, bit 8). */
    movl    $0xC0000080, %ecx
    rdmsr
    orl     $0x100, %eax
    wrmsr
    /* CR0.PG — we are now in compatibility mode. */
    movl    %cr0, %eax
    orl     $0x80000000, %eax
    movl    %eax, %cr0

    /* ── stage the 64-bit handoff ──
     * The i386 assembler cannot emit x86-64 relocations, so the 64-bit
     * section below must be relocation-free: everything it needs is
     * staged here, on the stack (esp is already the stub stack) and in
     * ECX. After the pushes the stack layout is:
     *   [rsp]    tsc_hi
     *   [rsp+4]  tsc_lo
     *   [rsp+8]  multiboot info address
     *   [rsp+12] multiboot magic
     */
    pushl   (mb_magic_saved)
    pushl   (mb_info_saved)
    pushl   (stub_tsc_lo)
    pushl   (stub_tsc_hi)
    /* Kernel entry address (absolute, --defsym at link time) staged in
     * ECX; the far jump preserves it. */
    movl    $kernel_entry, %ecx
    /* Far jump into the 64-bit code segment (selector 0x18). */
    ljmp    $0x18, $3f
3:
.code64
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs
    /* rsp is unchanged by the far jump: still the stub stack, with the
     * staged handoff words on top. */

    /* ── hand off to the 64-bit kernel ── */
    movl    12(%rsp), %edi        /* RDI = multiboot magic  */
    movl    8(%rsp), %esi         /* RSI = info address     */
    movl    (%rsp), %edx          /* RDX = TSC high half    */
    shlq    $32, %rdx
    orl     4(%rsp), %edx         /* RDX = full boot TSC    */
    addq    $16, %rsp             /* drop the staged words  */
    /* Jump to the kernel entry (staged in RCX by the 32-bit code). */
    jmp     *%rcx
    /* Never reached. */
4:
    cli
    hlt
    jmp     4b

/* ── data ── */
.p2align 4
/* null | 32-bit code (0x08) | data (0x10) | 64-bit code (0x18) */
gdt:
    .quad   0
    .quad   0x00CF9A000000FFFF
    .quad   0x00CF92000000FFFF
    .quad   0x00AF9A000000FFFF
gdt_descriptor:
    .word   31                      /* 4 entries * 8 - 1 */
    .long   gdt

/* The 64-bit kernel blob, embedded at its 2 MiB link base (stub.ld).
 * The path is relative to the repository root; boot.sh runs from there. */
.section .kernelbin, "a"
.p2align 12
kernel_blob_start:
    .incbin "target/kernel.bin"
kernel_blob_end:

/* ── bss (zeroed by the multiboot loader) ── */
.section .bss
.p2align 4
mb_magic_saved:  .long 0
mb_info_saved:   .long 0
stub_tsc_lo:     .long 0
stub_tsc_hi:     .long 0
