/* rust-hello.ld — the rustc userland citizen's link (P1-2).
 *
 * The CANONICAL exec cage's PAGE geometry (the same two pages as
 * /bin/hello's and the exec target's: RX [0x400000,0x401000), RW
 * [0x403000,0x404000), one absent guard page between — the ten-check
 * policy's no-adjacent-regions rule), but linked with `ld -n`
 * (nmagic: segments PACKED in the file instead of padded to 4-KiB
 * offsets) and the vaddrs chosen so the loader's congruence gate
 * (src/elf.rs: p_vaddr % 4096 == p_offset % 4096 — the byte copy at
 * [vaddr, vaddr+filesz) must be page-honest) holds BY CONSTRUCTION:
 * the text lands at file offset 0xB0, so its vaddr is 0x4000B0; the
 * data lands at 0xD2, so its vaddr is 0x4030D2.
 *
 * Why jump through this: the image is a GENUINE program at ~512 B
 * instead of the 8.2-KiB floor the standard 0x1000/0x2000 file-offset
 * padding imposes — small enough to ride the ramfs's 1-KiB INLINE
 * window, so the third package costs no large-file spill slot (the
 * netcat transaction's commit peak already holds four of the five).
 * scripts/check-citizen.py pins the congruence at every build, so an
 * ld layout drift dies here, not at boot.
 *
 * Invariants: position-dependent, no stack use, ends in SYS_EXIT.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
SECTIONS
{
  . = 0x4000b0;
  .text : { *(.text .text.*) } :text
  . = 0x4030d2;
  .data : { *(.data .data.*) } :data
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
PHDRS
{
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}
