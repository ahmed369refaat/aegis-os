//! The AArch64 boot smoke (P1-4): the second architecture's FIRST
//! boot — a bare-metal stub that proves the bring-up path end to end
//! on `qemu-system-aarch64 -M virt`: the CPU enters at its highest
//! implemented exception level (EL2 on cortex-a57 with `-bios none`),
//! the PL011 UART at 0x09000000 carries the markers out, and PSCI
//! SYSTEM_OFF (0x84000008) powers the machine down so QEMU EXITS
//! cleanly — via SEMIHOSTING SYS_EXIT (op 0x18, the `hlt #0xf000`
//! trap; the gate passes `-semihosting`), with the
//! ADP_Stopped_ApplicationExit reason so QEMU exits 0.
//!
//! The exit lesson, found live: PSCI was the first cut and BOTH
//! conduits dead-end on this machine shape — HVC from EL1 (no EL2)
//! and SMC from EL1 (no EL3, `secure=off` is the virt default) fault
//! into a vector table this smoke deliberately does not build, and
//! the machine hangs until the gate's timeout. PSCI belongs to a
//! round that brings EL2/EL3 up; a boot smoke's exit must be
//! deterministic, and semihosting's is.
//!
//! This is deliberately NOT a kernel: no MMU, no page tables, no
//! exception vectors, no PSCI (see the exit lesson below). It is the
//! boot-path smoke the mission named —
//! the HAL seam's (ADR-0011) first target hardware behind it — plus
//! the toolchain proof: rustc's bundled LLVM assembles the AArch64
//! asm (`--target aarch64-unknown-none-softfloat`, `--emit=obj`) and
//! `rust-lld` links it. The gate script (scripts/aa64-smoke.sh)
//! builds, runs, greps the markers, and requires the QEMU exit.
//!
//! The bytes are counted by hand like every asm blob here: the EL
//! prefix is 34 chars + the digit, the exit line 27. The first cut
//! got BOTH wrong (32 and 26 — the markers printed one char short of
//! their own text every run), and the first FIX for that misread the
//! symptom as an exit/chardev RACE and added a FR.TXFE drain loop:
//! QEMU's PL011 never sets TXFE in this configuration, the drain
//! hung, and the smoke stopped exiting at all. Wrong lengths, no
//! race — QEMU flushes the chardev on the semihosting exit.
//!
//! The bytes are counted by hand like every asm blob here: the EL
//! line is 34 chars, the PSCI line 26.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text
    .globl _start
_start:
    /* The PL011's base (the virt board's fixed mapping). */
    ldr x0, =0x09000000
    /* The exception level we entered at — CurrentEL bits [3:2].
     * cortex-a57 + -bios none + -M virt: EL2. */
    mrs x1, CurrentEL
    lsr x1, x1, #2

    /* Write the marker line: the fixed prefix from .rodata, then the
     * EL digit, then CR LF. */
    adr x2, msg1
    mov x3, #34                  /* the prefix's length */
1:  ldrb w4, [x2], #1
    bl putchar
    subs x3, x3, #1
    b.ne 1b
    add w4, w1, #0x30            /* the EL as ASCII */
    bl putchar
    mov w4, #0x0d
    bl putchar
    mov w4, #0x0a
    bl putchar

    /* The PSCI marker, then the call. */
    adr x2, msg2
    mov x3, #27
2:  ldrb w4, [x2], #1
    bl putchar
    subs x3, x3, #1
    b.ne 2b

    /* Semihosting SYS_EXIT: x0 = the op, x1 = the two-field reason
     * block (ADP_Stopped_ApplicationExit -> QEMU exits 0). The gate
     * passes -semihosting; without it this hlt faults into nothing
     * and the run times out — a loud fail, never a false pass. */
    mov x0, #0x18
    adr x1, exitblk
    hlt #0xf000
3:  wfe
    b 3b

/* putchar: w4 = the byte, x0 = the PL011 base. The FR register is at
 * +0x18; bit 5 is TXFF (the transmit FIFO full). */
putchar:
4:  ldr w5, [x0, #0x18]
    tbz w5, #5, 5f
    b 4b
5:  strb w4, [x0]
    ret

    .section .rodata
msg1: .ascii "[AA64] smoke live: PL011 uart, EL="
msg2: .ascii "[AA64] semihosting SYS_EXIT"
exitblk: .word 0x20026, 0
"#,
);
