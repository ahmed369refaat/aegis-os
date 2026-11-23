/* aegis-sh's link layout — the same cage contract as the exec
 * target's: text RX at 0x400000 (rodata folded in, read-only), data
 * RW at 0x403000 with the bss tail pinned at 0x403800 — all inside
 * the kernel's exec cage [0x400000, 0x404000). The stack (0x408000)
 * and trampoline (0x40C000) are kernel-provisioned and untouched.
 * The bss budget is half a page: the line buffer, the dirent and
 * copy chunks, and a few words of state — the shell's whole world.
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

    . = 0x405000;
    .data : {
        *(.data*)
        *(.got*)
        *(.data.rel.ro*)
    } :data

    . = 0x405800;
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
