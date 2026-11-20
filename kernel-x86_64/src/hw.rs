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
/// N2 (ADR-0007 §2): the monitor's window clock (until a real timer
/// exists). Raw RDTSC — only window *boundaries* matter, so ordering
/// against speculation is irrelevant here.
/// N4 (ADR-0008): CPUID leaf 7 sub-leaf 0's EBX — the SMEP/SMAP
/// capability word. Decoding is pure (arch/features.rs).
pub fn cpuid7_ebx() -> u64 {
    let a: u32;
    let b: u64;
    let c: u32;
    let d: u32;
    // SAFETY: CPUID is unprivileged. RBX cannot be an asm operand
    // (LLVM reserves it), and an `out(reg)` temporary is allocation
    // luck — if the allocator picks RBX itself, the restore-pop
    // clobbers the result (observed: SMEP/SMAP read as off in one
    // build, on in another). Bulletproof pattern instead: push a slot,
    // CPUID, store EBX INTO the slot, and pop the slot straight into
    // the operand — no intermediate register at all.
    unsafe {
        core::arch::asm!(
            "push %rbx",
            "cpuid",
            "movq %rbx, (%rsp)",
            "pop {b}",
            in("eax") 7u32,
            in("ecx") 0u32,
            lateout("eax") a,
            lateout("ecx") c,
            lateout("edx") d,
            b = out(reg) b,
            options(att_syntax),
        );
    }
    let _ = (a, c, d);
    b
}

/// N4 (ADR-0008): set once at boot when SMAP is enabled — the user-copy
/// path wraps itself in STAC/CLAC only when the CPU supports it (STAC
/// on a CPU without it is #UD).
static SMAP_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_smap_active(on: bool) {
    SMAP_ACTIVE.store(on, core::sync::atomic::Ordering::SeqCst);
}

#[must_use]
pub fn smap_active() -> bool {
    SMAP_ACTIVE.load(core::sync::atomic::Ordering::SeqCst)
}

/// N4 (ADR-0008): open the SMAP window for the current instruction
/// stream (allow supervisor access to user pages). Allowlisted.
pub fn stac() {
    // SAFETY: STAC is a privileged-ring-agnostic no-flags instruction;
    // the caller owns the window's extent.
    unsafe { core::arch::asm!("stac", options(nostack, preserves_flags)) };
}

/// N4 (ADR-0008): close the SMAP window.
pub fn clac() {
    // SAFETY: see stac().
    unsafe { core::arch::asm!("clac", options(nostack, preserves_flags)) };
}

pub fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC is unprivileged and touches no memory.
    unsafe {
        core::arch::asm!("rdtsc", lateout("eax") lo, lateout("edx") hi, options(nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

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

/// Exchange GS_BASE with KERNEL_GS_BASE (`swapgs`). The ring-3 state
/// machine (PR-1.4) in one instruction: while user code runs GS holds
/// the user value and the kernel percpu sits in the shadow MSR; the
/// SYSCALL entry swaps them, SYSRET (and every exit-to-kernel path)
/// swaps them back. Privileged (#GP in ring-3).
///
/// SAFETY: changes the GS base — the caller owns the pairing (every
/// swap in must have exactly one swap out on the same path).
pub fn swapgs() {
    // SAFETY: no memory access of its own; see the fn doc for the
    // pairing contract the caller must uphold.
    unsafe { asm!("swapgs", options(nostack, preserves_flags)) }
}

/// Read control register CR4 (feature flags: PAE, PGE, ...).
///
/// SAFETY: a pure register read.
/// F15 (ADR-0006): CR0 read — WP (bit 16) makes R-only pages stick
/// for supervisor writes too.
pub fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading CR0 is unprivileged-safe and touches no memory.
    unsafe { core::arch::asm!("movq %cr0, %rax", out("rax") v, options(att_syntax, nostack, preserves_flags)) };
    v
}

/// F15 (ADR-0006): CR0 write.
pub fn write_cr0(v: u64) {
    // SAFETY: the caller owns the value written (mm::init sets WP).
    unsafe { core::arch::asm!("movq %rax, %cr0", in("rax") v, options(att_syntax, nostack, preserves_flags)) };
}

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
