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

/// Write one dword to an I/O port. PCI config cycles REQUIRE this
/// width for the 0xCF8 address register: byte-wise writes land on
/// 0xCF9 — the chipset reset control register on q35 — not on the
/// address register's second byte (observed live: the driver-stack
/// bus scan read garbage until this primitive existed).
///
/// SAFETY: as `outb`; callers own the port's semantics.
pub fn outl(port: u16, val: u32) {
    // SAFETY: ring-0 CPL; no memory effects beyond the device.
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags)) }
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

/// Read one word from an I/O port — the natural width of the ICH9
/// TCO watchdog's registers (16-bit I/O at PMBASE+0x60; byte pairs
/// would depend on the region's per-byte decode, and dword reads
/// would smear the neighboring register into the value).
///
/// SAFETY: as `inb`.
pub fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: ring-0 CPL; a pure device read.
    unsafe { asm!("in ax, dx", out("ax") val, in("dx") port, options(nostack, preserves_flags)) }
    val
}

/// Read one dword from an I/O port — the natural width of the PCI
/// config data register (0xCFC).
///
/// SAFETY: as `inb`.
pub fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: ring-0 CPL; a pure device read.
    unsafe { asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags)) }
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

/// CPUID leaf 1's ECX — the feature word carrying TSC-deadline (bit 24;
/// decoded in arch/features). Same ADR-0008 bulletproof pattern as
/// `cpuid7_ebx`: RBX cannot be an asm operand (LLVM reserves it), so
/// the wanted value travels through the pushed stack slot, never a
/// temporary register the allocator might recycle.
pub fn cpuid1_ecx() -> u64 {
    let a: u32;
    let c: u64;
    let d: u32;
    let e: u32;
    // SAFETY: CPUID is unprivileged; the push/store/pop sequence moves
    // ECX's result through the pushed slot (see cpuid7_ebx for the
    // allocation-luck failure this avoids). ECX's final register value
    // is dead (the slot already saved it), hence the throwaway `e`.
    unsafe {
        core::arch::asm!(
            "push %rbx",
            "cpuid",
            "movq %rcx, (%rsp)",
            "pop {c}",
            in("eax") 1u32,
            in("ecx") 0u32,
            lateout("eax") a,
            lateout("ecx") e,
            lateout("edx") d,
            c = out(reg) c,
            options(att_syntax),
        );
    }
    let _ = (a, d, e);
    c
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
    ((hi as u64) << 32) | lo as u64
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
    unsafe {
        asm!("movq %rax, %cr3", in("rax") pml4_pa, options(att_syntax, nostack, preserves_flags))
    }
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
/// Mask every line on both 8259 PICs. No IRQ source is armed yet (the
/// LAPIC timer arrives with preemption, M2-W2) and the kernel runs IF=0
/// in CPL0 — but ring-3 runs IF=1 (USER_RFLAGS), so an unmasked line
/// fires at the very first SYSRET boundary. With no handler mapped that
/// delivery faults mid-switch and escalates to #DF carrying the pending
/// user frame — the exact failure PR-1.4 misdiagnosed as an environment
/// block (see docs/arch/syscall-entry.md). Masking is the honest state
/// until a handler exists; the IDT's 32..=47 catch-all backstops it.
pub fn pic_mask_all() {
    // `outb` is itself the safe port-I/O wrapper — no unsafe needed here.
    outb(0xA1, 0xFF); // slave IMR: all 8 lines masked
    outb(0x21, 0xFF); // master IMR: all 8 lines masked (incl. cascade)
}

/// F15 (ADR-0006): CR0 read — WP (bit 16) makes R-only pages stick
/// for supervisor writes too.
pub fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading CR0 is unprivileged-safe and touches no memory.
    unsafe {
        core::arch::asm!("movq %cr0, %rax", out("rax") v, options(att_syntax, nostack, preserves_flags))
    };
    v
}

/// F15 (ADR-0006): CR0 write.
pub fn write_cr0(v: u64) {
    // SAFETY: the caller owns the value written (mm::init sets WP).
    unsafe {
        core::arch::asm!("movq %rax, %cr0", in("rax") v, options(att_syntax, nostack, preserves_flags))
    };
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

/// Enable interrupts (set IF). The kernel's convention is IF=0 in
/// CPL0; the ONE deliberate exception is ADR-0019's bounded delivery
/// window (`irq::wait_for_delivery`), which pairs this with `cli`
/// microseconds later — every vector that can land in the window is
/// one the IDT deliberately gates.
///
/// SAFETY: caller owns the window's extent: STI lets any unmasked
/// interrupt (or NMI) through on the next instruction boundary.
pub fn sti() {
    // SAFETY: a single-instruction flag change; the pairing contract
    // is documented above.
    unsafe { asm!("sti", options(nostack)) }
}

/// Disable interrupts (clear IF).
///
/// SAFETY: none beyond the convention — the kernel's default state.
pub fn cli() {
    // SAFETY: see sti(); the default kernel state.
    unsafe { asm!("cli", options(nostack, preserves_flags)) }
}

/// `monitor` — arm an address watch for the following `mwait`
/// (CPUID.01H:ECX bit 3; decoded in arch/features).
///
/// SAFETY: no memory access of its own (it arms the line-sized
/// region at `addr` for wake purposes); `addr` must be a normal
/// writable virtual address.
pub fn monitor(addr: u64, ext: u64) {
    // SAFETY: single instruction; the arming is architectural.
    unsafe { asm!("monitor", in("rax") addr, in("rcx") ext, in("rdx") 0u64, options(nostack)) }
}

/// `mwait` — wait for the armed `monitor` line or an unmasked
/// interrupt. The idle instruction the Stage-4 idle loop wants;
/// ADR-0019's proof runs it once with a pending LAPIC deadline.
///
/// SAFETY: caller guarantees `monitor` was armed (an mwait without a
/// preceding monitor is architecturally valid but wakes immediately —
/// useless and confusing, so the caller owns the pairing).
pub fn mwait(eax: u64, ecx: u64) {
    // SAFETY: single instruction; the wake conditions are the
    // caller's contract.
    unsafe { asm!("mwait", in("rax") eax, in("rcx") ecx, options(nostack)) }
}

/// `rdrand` — the on-CPU entropy instruction (CPUID.01H:ECX bit 30).
/// Returns None when the hardware reports RDRAND failure (it can —
/// undersubscribed entropy is a documented state, not a bug); callers
/// retry with a bounded loop and fall back to the pool.
///
/// SAFETY: no memory or register side effects beyond RAX and the
/// carry flag (both declared).
pub fn rdrand64() -> Option<u64> {
    let v: u64;
    let ok: u8;
    // SAFETY: the ISA-defined retry-able primitive; the carry flag
    // gates whether the value register is valid this attempt
    // (`setc` materializes CF into a byte).
    unsafe {
        asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nostack))
    }
    if ok == 1 {
        Some(v)
    } else {
        None
    }
}

/// `rdseed` — the seed-quality entropy instruction (CPUID.07H:EBX
/// bit 18). Slower and possibly absent where RDRAND exists; the pool
/// prefers it when present.
///
/// SAFETY: as `rdrand64`.
pub fn rdseed64() -> Option<u64> {
    let v: u64;
    let ok: u8;
    // SAFETY: as rdrand64 — the carry flag gates RAX via `setc`.
    unsafe {
        asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nostack))
    }
    if ok == 1 {
        Some(v)
    } else {
        None
    }
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
