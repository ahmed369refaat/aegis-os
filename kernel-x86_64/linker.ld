/*
 * AegisOS x86_64 kernel link script (stage 2 of the two-stage boot).
 *
 * The kernel links at 2 MiB as a normal ELF64. The boot stub
 * (boot-x86_64/stub.S) embeds the flat binary of this kernel at its 2 MiB
 * link base, sets up long mode + identity paging, and jumps to the entry
 * address (passed via --defsym at stub link time).
 *
 * `aegis_entry_64` is pinned to the very start of .text so the entry
 * address is deterministic (0x200000) — though the stub reads the real
 * value from the ELF header anyway.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(aegis_entry_64)

SECTIONS
{
    . = 2M;

    .text : ALIGN(16)
    {
        KEEP(*(.text.entry))
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

/* Image + bss + stack must stay far below the frame pool at 16 MiB. */
ASSERT(_kernel_end < 8M, "kernel image overlaps the pre-pool safety region")
