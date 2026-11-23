/* The exec target's link layout — the image the ELF loader honors.
 *
 * Not the flat-blob convention (code at 0x400000, entered at its
 * base): a real two-PT_LOAD ELF. Text is RX at 0x400000 with the
 * rodata folded in (read-only); data is RW at 0x403000 with the bss
 * tail pinned at 0x403800 — inside the SAME page, inside the memsz
 * (not the filesz) tail, so the loader's zero-fill is the only thing
 * that can make the exec'd code's bss probe read zero.
 *
 * Every address is inside the kernel's exec cage
 * [0x400000, 0x404000): the stack (0x408000) and trampoline
 * (0x40C000) are kernel-provisioned and untouched.
 */
ENTRY(_start)

PHDRS {
    text PT_LOAD FLAGS(5);  /* R + X */
    data PT_LOAD FLAGS(6);  /* R + W */
}

SECTIONS {
    . = 0x400000;
    .text : {
        *(.text*)
        *(.rodata*)
    } :text

    . = 0x403000;
    .data : {
        *(.data*)
    } :data

    . = 0x403800;
    .bss : {
        *(.bss*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
