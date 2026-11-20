//! Per-CPU state, anchored at the GS base MSR (PR-1.2 of Stage 1).
//!
//! One `PerCpu` per processor; `init` points IA32_GS_BASE at it, `get`
//! reads it back through the same MSR. Single-CPU today — Stage 4 (SMP)
//! swaps `get` for per-field `%gs:`-relative loads and gives each CPU
//! its own instance; the ABI (GS base = this struct) is the part that
//! must not change.
//!
//! SAFETY POLICY: allowlisted module (the GS-base pointer deref); the
//! MSR access itself is `hw::wrmsr`/`rdmsr` (also allowlisted).

#![allow(unsafe_code)]

use crate::hw;

/// IA32_GS_BASE — where `gs:`-relative addressing and this module anchor.
const MSR_GS_BASE: u32 = 0xC000_0101;

/// Per-processor kernel state.
pub struct PerCpu {
    /// Stable CPU index (BSP = 0).
    pub cpu_id: u32,
    /// Domain currently running on this CPU (0 = the kernel itself;
    /// domain ids start at 1).
    pub current: u32,
    /// Top of this CPU's boot kernel stack (RSP0 target for ring-3
    /// entry, PR-1.4).
    pub kstack_top: u64,
}

// Linker-provided top of the boot kernel stack (linker.ld `stack_top`).
extern "C" {
    static stack_top: u8;
}

static mut PERCPU: PerCpu = PerCpu { cpu_id: 0, current: 0, kstack_top: 0 };

/// Point the GS base at this CPU's state. Called once from `mm::init`,
/// single-CPU bring-up.
pub fn init() {
    // SAFETY: single-CPU bring-up; PERCPU is written exactly once here,
    // before the GS base points at it, so no accesser can race.
    unsafe {
        let p = core::ptr::addr_of_mut!(PERCPU);
        (*p).kstack_top = core::ptr::addr_of!(stack_top) as u64;
        hw::wrmsr(MSR_GS_BASE, p as u64);
    }
}

/// Point `kstack_top` at the dedicated (guarded) syscall stack. Called
/// from `kmain` once the frame pool exists; the SYSCALL entry stub loads
/// RSP from here via `%gs:` (SYSCALL itself does not switch stacks), and
/// TSS.RSP0 is set to the same value for the exception path.
pub fn set_kstack_top(top: u64) {
    // SAFETY: single CPU, written exactly once from kmain before any
    // ring-3 context exists; readers only ever see the final value.
    unsafe {
        (*core::ptr::addr_of_mut!(PERCPU)).kstack_top = top;
    }
}

/// This CPU's state. The address comes from the GS base MSR — the same
/// anchor `gs:`-relative addressing uses, so whatever points GS at a
/// `PerCpu`, this reads it.
pub fn get() -> &'static PerCpu {
    // SAFETY: `init` ran before any `get` (mm::init is called from kmain
    // before the selftest sequence that reads this); the GS base is never
    // re-pointed afterwards, and there is exactly one CPU.
    unsafe { &*(hw::rdmsr(MSR_GS_BASE) as *const PerCpu) }
}
