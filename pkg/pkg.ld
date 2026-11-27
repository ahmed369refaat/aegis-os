/* pkg's link layout — the SERVICE memory contract (K22; the kernel's
 * mm/user_layout.rs `SERVICE`).
 *
 * Three PT_LOADs inside the image cage [0x400000, 0x480000), each
 * separated from the next by ONE ABSENT PAGE: the kernel's ten-check
 * policy refuses adjacent regions (GuardGap), and the exec arm maps
 * every PT_LOAD as a region of its own. Everything above the cage is
 * kernel-provisioned and untouched here — the 256 KiB stack at
 * 0x600000, the signal trampoline at 0x644000.
 *
 *   0x400000  text    R+X   code (the `_start` shim included)
 *   (guard)
 *   next+1   rodata  R     read-only data, its own page
 *   (guard)
 *   next+1   data    R+W   data with the bss tail contiguous in the
 *                          SAME phdr (one region — a bss PT_LOAD of
 *                          its own would sit adjacent and be refused)
 *
 * The ELF headers sit at the very start of the text page (ET_EXEC,
 * e_phoff = 64) exactly as the kernel's loader insists.
 */
ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);  /* R + X */
    rodata PT_LOAD FLAGS(4);  /* R     */
    data   PT_LOAD FLAGS(6);  /* R + W */
}

SECTIONS {
    . = 0x400000;
    .text : {
        *(.text .text.*)
    } :text

    /* One absent page above the text, whatever its length. */
    . = ALIGN(4096) + 4096;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.rel.ro .rel.ro.*)
    } :rodata

    . = ALIGN(4096) + 4096;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.*)
        *(.data.rel.ro .data.rel.ro.*)
    } :data
    /* The bss tail follows the data CONTIGUOUSLY in the same phdr: one
     * PT_LOAD whose memsz reaches past its filesz — one RW region. */
    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
