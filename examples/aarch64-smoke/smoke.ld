/* smoke.ld — the AArch64 boot smoke's link (P1-4).
 *
 * The virt board's RAM begins at 0x40000000; QEMU's -kernel loader
 * honors the ELF's own addresses, and the conventional kernel base
 * (0x40080000) keeps the image clear of QEMU's boot rom area. One
 * R+X PT_LOAD carries text + rodata: this smoke builds no page
 * tables and enforces no W^X — it is the boot-path proof, not a
 * kernel.
 */
OUTPUT_FORMAT(elf64-littleaarch64)
ENTRY(_start)
SECTIONS
{
  . = 0x40080000;
  .text : {
    KEEP(*(.text))
    *(.rodata .rodata.*)
  } :text
  /DISCARD/ : { *(.comment) *(.note*) }
}
PHDRS
{
  text PT_LOAD FLAGS(5);
}
