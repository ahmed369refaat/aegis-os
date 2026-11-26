/* K20 (P0-3): the gcc userland image's link — the exec cage's shape.
 *
 * Two PT_LOADs at the cage's declared vaddrs: text RX at 0x400000,
 * data RW at 0x403000 (rodata and bss folded in — no W+X, the bss
 * tail gives the loader's zero-fill contract a real byte to honor).
 * Entry _start; everything lives inside [0x400000, 0x408000).
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
SECTIONS
{
  . = 0x400000;
  .text : { *(.text .text.*) } :text
  . = 0x403000;
  .data : { *(.data .data.* .rodata .rodata.* .bss .bss.* COMMON) } :data
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
PHDRS
{
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}
