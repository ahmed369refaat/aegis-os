/*
 * AegisOS x86_64 kernel link script.
 *
 * The kernel is a multiboot v1 image loaded by QEMU (-kernel) at 1 MiB
 * physical. Link address == physical address everywhere: the boot page
 * tables identity-map the first 1 GiB, so symbols can be dereferenced
 * directly once paging is on.
 *
 * Layout notes:
 * - .boot comes first so the multiboot header lands within the first
 *   8 KiB of the file (a multiboot requirement).
 * - A 256 KiB boot stack lives at the end of .bss; nothing else may grow
 *   into it (see the ASSERTs).
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

SECTIONS
{
    . = 1M;

    .boot : ALIGN(4)
    {
        KEEP(*(.boot))
    }

    .text : ALIGN(16)
    {
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
        . = ALIGN(8);
    }

    .bss : ALIGN(4096)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        stack_bottom = .;
        . += 256K;
        stack_top = .;
        _bss_end = .;
    }

    _kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}

/* The kernel image + bss + stack must stay far below the frame pool at
 * 16 MiB (the pool is claimed at runtime after multiboot validation). */
ASSERT(_kernel_end < 8M, "kernel image overlaps the pre-pool safety region")
