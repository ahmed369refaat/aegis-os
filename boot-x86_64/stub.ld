/*
 * Link script for the AegisOS ELF32 boot stub.
 *
 * Layout:
 *   1 MiB   stub: multiboot header, 32-bit entry, GDT, page tables, stack
 *   2 MiB   the embedded 64-bit kernel blob (.incbin from stub.S) at its
 *           link base — no copying, the loader maps it there directly.
 *
 * `kernel_entry` is provided externally at link time:
 *   ld --defsym=kernel_entry=<entry address from the kernel ELF header>
 */
OUTPUT_FORMAT(elf32-i386)
ENTRY(_start)

SECTIONS
{
    . = 1M;

    /* Multiboot header must be within the first 8 KiB of the file. */
    .mbheader : ALIGN(4)
    {
        KEEP(*(.mbheader))
    }

    .text : ALIGN(16)
    {
        *(.text .text.*)
    }

    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(16)
    {
        *(.data .data.*)
        . = ALIGN(16);
    }

    .bss : ALIGN(4096)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        boot_pml4 = .;  . += 4096;    /* level 4 table                     */
        boot_pdpt  = .;  . += 4096;    /* level 3: identity 1 GiB (PML4[0]) */
        boot_pd    = .;  . += 4096;    /* level 2: 512 x 2 MiB = 1 GiB      */
        boot_pdpt_hh = .; . += 4096;   /* level 3: kernel window (PML4[511])*/
        boot_pd_hh  = .;  . += 4096;   /* level 2: kernel image @ PA 2 MiB  */
        boot_pdpt_dm = .; . += 4096;   /* level 3: direct map (PML4[273])   */
        . = ALIGN(16);
        stub_stack_bottom = .;
        . += 16K;
        stub_stack_top = .;
        _bss_end = .;
    }

    /* The 64-bit kernel blob at its 2 MiB link base. */
    . = 2M;
    .kernel : ALIGN(4096)
    {
        kernel_blob = .;
        KEEP(*(.kernelbin))
        kernel_blob_end = .;
    }

    _stub_end = .;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}

ASSERT(_stub_end <= 4M, "kernel blob exceeds the 2..4 MiB window")
