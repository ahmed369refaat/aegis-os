/* netcat.ld — the gcc userland net client's link (P1-1).
 *
 * The CANONICAL exec cage's shape (the same geometry as
 * userland-hello's): text RX at 0x400000, data RW at 0x403000 with
 * the kernel-patched config block pinned at 0x403800 and the report
 * block at 0x403C00. Everything lives inside [0x400000, 0x407000);
 * the one-page stack (0x408000) and the trampoline (0x40C000) are
 * kernel-provisioned and untouched here.
 *
 * NOTE: assignments INSIDE an output section are offsets from the
 * section's start (the ld rule) — the pinned blocks are written as
 * 0x800/0xC00 offsets of the .data section that starts at 0x403000.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
SECTIONS
{
  . = 0x400000;
  .text : { *(.text .text.*) } :text
  . = 0x403000;
  .data : {
      *(.rodata .rodata.*)
      *(.data .data.*)
      . = 0x800;   /* 0x403800: the kernel-patched config block */
      *(.netcfg)
      . = 0xC00;   /* 0x403C00: the report block */
      *(.netrep)
      . = 0x1000;  /* 0x404000: the bss buffers land here (one RW
                      region with the data — no adjacent-region
                      refusal, they are the same mapping) */
      *(.bss .bss.*)
      *(COMMON)
  } :data
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
PHDRS
{
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}
