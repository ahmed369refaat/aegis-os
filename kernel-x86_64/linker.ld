/*
 * AegisOS x86_64 kernel link script (stage 2 of the two-stage boot).
 *
 * Higher-half kernel (ADR-0002): the kernel is LINKED at the high virtual
 * base 0xFFFFFFFF80000000 but LOADED at physical 2 MiB (`AT(0x200000)`;
 * objcopy -O binary places sections by their LMA, so the flat blob still
 * starts at PA 2 MiB, exactly where the boot stub embeds it). The stub
 * maps this window with one 2 MiB huge page (PML4[511] → PDPT[510] →
 * PD[0]) before entering the kernel at the high entry address.
 *
 * `aegis_entry_64` stays pinned to the very start of .text so the entry
 * address is deterministic (0xFFFFFFFF80000000); boot.sh reads the real
 * value from the ELF header and passes it to the stub in two 32-bit
 * halves (the i386 stub cannot hold a 64-bit absolute).
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(aegis_entry_64)

KERNEL_BASE = 0xFFFFFFFF80000000;
KERNEL_PHYS_BASE = 0x200000;

SECTIONS
{
    . = KERNEL_BASE;

    /* F15 (ADR-0006): every section page-aligned with exported
     * boundaries — mm::init rebuilds the image as 4 KiB PTEs:
     * .text RX, .rodata RO+NX, .data/.bss RW+NX, inter-section gaps
     * and the boot-stack guard page absent. */
    .text : AT(KERNEL_PHYS_BASE) ALIGN(4096)
    {
        __text_start = .;
        KEEP(*(.text.entry))
        *(.text .text.*)
        . = ALIGN(4096);
        __text_end = .;
    }

    .rodata : ALIGN(4096)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        . = ALIGN(4096);
        __rodata_end = .;
    }

    .data : ALIGN(4096)
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*) /* orphaned by nothing: writable, belongs here */
        . = ALIGN(4096);
        __data_end = .;
    }

    .bss : ALIGN(4096)
    {
        __bss_start = .;
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        /* F15: one absent guard page below the boot stack — an
         * overflow writes it and faults instead of corrupting
         * whatever sits below. */
        __stack_guard = .;
        . += 4096;
        stack_bottom = .;
        . += 256K;
        stack_top = .;
        . = ALIGN(4096);
        __bss_end = .;
        _bss_end = .;
    }

    _kernel_end = .;
    _kernel_phys_end = _kernel_end - KERNEL_BASE + KERNEL_PHYS_BASE;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}

/* The whole kernel (image + bss + boot stack) must fit inside the single
 * 2 MiB huge page the stub maps at PA 2 MiB (PA 2..4 MiB) — which also
 * keeps it far below the frame pool at 16 MiB. */
ASSERT(_kernel_phys_end <= 0x400000, "kernel image exceeds the single 2 MiB higher-half huge page (PA 2..4 MiB)")