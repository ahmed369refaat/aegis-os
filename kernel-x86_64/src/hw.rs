//! Hardware primitives: port I/O, timestamp counter, halt, QEMU poweroff.
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (with `boot` and
//! `memops`). Every function here is a one-instruction wrapper with an
//! explicit `SAFETY` note; none of them interpret data.

#![allow(unsafe_code)]

use core::arch::asm;

// State stashed by the 32-bit entry stub (see boot/asm.rs) before any Rust
// code runs. Written exactly once by assembly; read-only afterwards.
#[unsafe(no_mangle)]
pub static mut MULTIBOOT_MAGIC: u32 = 0;
#[unsafe(no_mangle)]
pub static mut MULTIBOOT_INFO: u32 = 0;
#[unsafe(no_mangle)]
pub static mut BOOT_TSC_LO: u32 = 0;
#[unsafe(no_mangle)]
pub static mut BOOT_TSC_HI: u32 = 0;

/// Write one byte to an I/O port.
///
/// SAFETY: `out` is a privileged ring-0 instruction (CPL0 guaranteed);
/// callers own the semantics of the port they touch.
pub fn outb(port: u16, val: u8) {
    // SAFETY: ring-0 CPL; no memory effects beyond the device.
    unsafe { asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags)) }
}

/// Write one word to an I/O port.
///
/// SAFETY: as `outb`.
pub fn outw(port: u16, val: u16) {
    // SAFETY: ring-0 CPL; no memory effects beyond the device.
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags)) }
}

/// Read one byte from an I/O port.
///
/// SAFETY: as `outb`.
pub fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: ring-0 CPL; a pure device read.
    unsafe { asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags)) }
    val
}

/// Read the timestamp counter.
///
/// SAFETY: `rdtsc` has no memory or register side effects beyond its
/// outputs (which the asm! block declares).
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: no memory access, no flags clobber declared by the ISA spec.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack)) }
    ((hi as u64) << 32) | lo as u64
}

/// The TSC value captured at the very first kernel instruction
/// (written by the entry stub before the stack even existed).
pub fn boot_tsc() -> u64 {
    // SAFETY: written once by the entry stub, before any Rust code runs;
    // there is no concurrent accesser.
    unsafe { ((BOOT_TSC_HI as u64) << 32) | BOOT_TSC_LO as u64 }
}

/// The multiboot magic value the loader passed us.
pub fn multiboot_magic_saved() -> u32 {
    // SAFETY: as `boot_tsc`.
    unsafe { MULTIBOOT_MAGIC }
}

/// The multiboot info physical address the loader passed us.
pub fn multiboot_info_saved() -> u32 {
    // SAFETY: as `boot_tsc`.
    unsafe { MULTIBOOT_INFO }
}

/// Halt forever (interrupts disabled). Never returns.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` with interrupts disabled parks the CPU; this is
        // the terminal state for boot failures.
        unsafe { asm!("hlt") }
    }
}

/// Power the QEMU machine off cleanly so CI gets an exit and can time the
/// whole boot. Tries the modern ACPI PM1a port (0x604, `-machine pc`),
/// then the legacy Bochs/QEMU port (0xB004); halts if neither works.
pub fn shutdown_qemu() -> ! {
    outw(0x604, 0x2000);
    outw(0xB004, 0x2000);
    halt_forever()
}
