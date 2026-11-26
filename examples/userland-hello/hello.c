/* K20 (P0-3): the first gcc-built userland citizen.
 *
 * Compiled with the REAL toolchain (gcc 14.2, -ffreestanding
 * -nostdlib — no libc, no startup files: this is the whole program),
 * linked at the exec cage's declared vaddrs (text RX at 0x400000,
 * data RW at 0x403000), and carried on the ext2 root as the file
 * "hello". The kernel reads those bytes off the AHCI disk at boot,
 * registers them as the execve image "/bin/hello", and a ring-3
 * caller execve's into them — the loader, the cage, and the
 * exit_group path all see a REAL compiler's output, not a
 * hand-assembled blob.
 *
 * The program itself is the honest minimum: prove the image is
 * RUNNING (write a recognizable pattern into the image's own data
 * page), prove the syscall ABI (exit_group(42) — the kernel-side
 * verification keys on the code), and nothing else. The raw syscall
 * ABI is the M3 flat-blob one: eax = nr, rdi/rsi/rdx = args.
 */
void _start(void)
{
    volatile unsigned char *const page = (volatile unsigned char *)0x403000;
    static const char msg[] = "GCC-USERLAND-AEGIS";

    for (int i = 0; i < (int)sizeof(msg) - 1; i++)
        page[64 + i] = (unsigned char)msg[i];
    page[0] = 0xA7;
    page[1] = 0x5A;
    __asm__ volatile("mov $231, %%eax\n\t"
                     "mov $42, %%edi\n\t"
                     "syscall\n\t"
                     :
                     :
                     : "eax", "edi", "memory");
    __builtin_unreachable();
}
