/* tcpipd's link layout — the NETSVC memory contract (P1-1; the
 * kernel's mm/user_layout.rs `NETSVC`).
 *
 * Three PT_LOADs inside the image cage [0x400000, 0x480000), each
 * separated from the next by ONE ABSENT PAGE (the ten-check policy
 * refuses adjacent regions — GuardGap). Everything above the cage is
 * kernel-provisioned and untouched here: the 96-page stack at
 * 0x500000, the signal trampoline at 0xE040000.
 *
 *   0x400000  text    R+X   code (the `_start` shim included)
 *   (guard)
 *   next+1    rodata  R     read-only data, its own page
 *   (guard)
 *   0x420000  data    R+W   the SHARED PAGE first — the config block
 *                          the kernel patches before the first
 *                          instruction (0x420000) and the report
 *                          block the service writes before exit
 *                          (0x420400) — then the image's own data
 *                          and the bss tail in the SAME phdr (one
 *                          region; a bss phdr of its own would sit
 *                          adjacent and be refused).
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
    } :rodata

    /* The data segment starts at the shared page — pinned, so the
     * kernel's patch and this image's idea of the config block can
     * never drift apart. */
    .data 0x420000 : {
        KEEP(*(.netcfg.config))
        . = 0x420400;
        KEEP(*(.netcfg.report))
        . = 0x421000;
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.*)
        *(.data.rel.ro)
    } :data

    . = ALIGN(4096);
    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
