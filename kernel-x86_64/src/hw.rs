//! Hardware primitives: port I/O, timestamp counter, halt, QEMU poweroff.
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (with `boot` and
//! `memops`). Every function here is a one-instruction wrapper with an
//! explicit `SAFETY` note; none of them interpret data.

#![allow(unsafe_code)]

use core::arch::asm;

// Boot TSC stamp: the ELF32 boot stub captures the TSC at its first
// instruction and passes it in RDX; `aegis_entry_64` stores it here
// (after zeroing .bss). Written exactly once; read-only afterwards.
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

/// Read the page-fault linear address (CR2).
///
/// SAFETY: a pure register read; only meaningful inside a #PF handler.
pub fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: no memory access; the ISA guarantees no side effects.
    unsafe { asm!("movq %cr2, %rax", out("rax") v, options(att_syntax, nostack, preserves_flags)) }
    v
}

/// Read the page-table base (CR3). Returns the physical address of the
/// active PML4 (flag/PCID bits must be masked by the caller).
///
/// SAFETY: a pure register read.
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: no memory access; the ISA guarantees no side effects.
    unsafe { asm!("movq %cr3, %rax", out("rax") v, options(att_syntax, nostack, preserves_flags)) }
    v
}

/// Load CR3 (page-table base). Reloading the same value is the cheap
/// full non-global TLB flush.
///
/// SAFETY: `pml4_pa` must be a present, page-aligned PML4 physical
/// address (the active one, or a fully-built replacement); a wrong value
/// instantly and unrecoverably breaks all further memory access.
pub fn write_cr3(pml4_pa: u64) {
    // SAFETY: caller guarantees a valid active PML4 (see above).
    unsafe { asm!("movq %rax, %cr3", in("rax") pml4_pa, options(att_syntax, nostack, preserves_flags)) }
}

/// Invalidate the TLB entry for one virtual address (`invlpg`).
/// Required after unmapping a page that may have been touched.
///
/// SAFETY: `va` is any canonical address; the instruction takes no
/// memory operands and is CPL0-safe.
pub fn invlpg(va: u64) {
    // SAFETY: single-address TLB invalidation, no other effects.
    unsafe { asm!("invlpg (%rax)", in("rax") va, options(att_syntax, nostack, preserves_flags)) }
}

/// Write a model-specific register (the `edx:eax` pair per the ISA).
///
/// SAFETY: `msr` must exist on this CPU; several MSRs change CPU state
/// (GS base, EFER, ...) — callers own the semantics they program.
pub fn wrmsr(msr: u32, value: u64) {
    // SAFETY: no memory effects beyond the register pair.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(att_syntax, nostack, preserves_flags),
        )
    }
}

/// Read control register CR4 (feature flags: PAE, PGE, ...).
///
/// SAFETY: a pure register read.
pub fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: no memory access; the ISA guarantees no side effects.
    unsafe { asm!("movq %cr4, %rax", out("rax") v, options(att_syntax, nostack, preserves_flags)) }
    v
}

/// Write control register CR4 (enable/disable CPU features).
///
/// SAFETY: `v` must be a valid CR4 image — callers own every bit they
/// flip (a cleared PAE or a bogus reserved bit is instant #GP or worse).
pub fn write_cr4(v: u64) {
    // SAFETY: caller guarantees a valid value (see above).
    unsafe { asm!("movq %rax, %cr4", in("rax") v, options(att_syntax, nostack, preserves_flags)) }
}

/// Read a model-specific register.
///
/// SAFETY: `msr` must exist on this CPU; a pure register read otherwise.
pub fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: see above.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(att_syntax, nostack, preserves_flags),
        )
    }
    ((hi as u64) << 32) | lo as u64
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
