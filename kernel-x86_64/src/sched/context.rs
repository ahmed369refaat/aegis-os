//! Ring-3 scheduling context: the user run state, and the launch /
//! resume pair that crosses the privilege boundary (PR-1.4).
//!
//! SAFETY POLICY: allowlisted module (same class as `arch`: naked
//! assembly entries + the single-CPU run state; see `docs/adr/0005`
//! and `docs/arch/syscall-entry.md`). Everything unsafe here is a
//! static read/write under the single-CPU, single-run-at-a-time
//! invariant, or the naked launch/resume pair below.
//!
//! Invariants:
//! - **Stack discipline**: `enter_ring3` is a naked function — it saves
//!   the caller's RSP (pointing at its return address) *before* the
//!   `iretq` and never touches any callee-saved register, so
//!   `resume_kernel` can `mov rsp, saved; ret` and the kernel continues
//!   as if the launch had simply returned. No frame is left half-built.
//! - **GS pairing**: `enter_ring3` executes one `swapgs` on the way in
//!   (GS: user value, KERNEL_GS_BASE: percpu). Every path back to the
//!   kernel — SYSRET in the syscall entry, SYS_EXIT in the dispatch,
//!   the user-fault branch in the exception dispatch — executes exactly
//!   one `swapgs` of its own. Unbalanced pairs are a kernel bug by
//!   construction.
//! - **One run at a time**: `USER_RUN` holds the single active user
//!   domain (single CPU, no preemption until Stage 4). `begin` before
//!   `enter_ring3`, `take` after `resume_kernel` reaches kmain.

#![allow(unsafe_code)]

use aegis_os::memory::AddressSpace;
use aegis_os::syscall::SyscallMask;

use crate::mm::page_table::PageTables;

/// RFLAGS for a freshly launched user context: interrupts on (IF, bit 1
/// in this encoding), reserved bit 1 set as the architecture requires,
/// everything else clear — no FPU carry-over, no trap flag.
pub const USER_RFLAGS: u64 = 0x202;

/// The register image `iretq` needs to enter ring-3 (CPL=3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserContext {
    pub rip: u64,
    /// Full selector including RPL 3 (0x2b with the PR-1.4 GDT layout).
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    /// Full selector including RPL 3 (0x23).
    pub ss: u64,
}

impl UserContext {
    /// A context entering `rip` with the stack pointer at `rsp`, on the
    /// user segments from `arch::gdt` (which SYSRET's arithmetic also
    /// targets — the two entry paths agree by construction).
    pub fn new(rip: u64, rsp: u64) -> Self {
        UserContext {
            rip,
            cs: (crate::arch::gdt::USER_CODE | 3) as u64,
            rflags: USER_RFLAGS,
            rsp,
            ss: (crate::arch::gdt::USER_DATA | 3) as u64,
        }
    }
}

/// How a user run ended. `Fault` carries everything the security log
/// prints: what faulted, where, and under which error-code bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// The domain called SYS_EXIT(code).
    Exited(u64),
    /// A CPU fault at CPL3 (the domain is terminated; the kernel lives).
    Fault {
        vector: u8,
        cr2: u64,
        error_code: u64,
        rip: u64,
        user_rsp: u64,
    },
}

/// The single active user run: hardware context + gate snapshot +
/// the run's telemetry. Plain data, no pointers — safe to park in a
/// static between the launch and the resume.
pub struct UserRun {
    /// The domain's page tables (PR-1.3) — the dispatch validates user
    /// pointers by walking these.
    pub tables: PageTables,
    /// The policy space that gated every mapped region.
    pub space: AddressSpace,
    /// Lib domain id (audit/accounting identity; frames are pool-owned
    /// by this id).
    pub domain: u32,
    /// Gate snapshot (checked by the same `aegis_os::syscall::gate` the
    /// kernel-resident path uses).
    pub mask: SyscallMask,
    pub quarantined: bool,
    /// How the run ended (written by SYS_EXIT or the fault branch).
    pub exit: ExitKind,
    /// SYS_WRITE byte count (the run's positive contribution).
    pub write_bytes: u64,
    /// Unknown-syscall attempts (audit signal, replayed into the lib
    /// telemetry after the resume).
    pub bad_syscalls: u32,
    /// Policy-denied syscall attempts (masked or quarantined).
    pub denied: u32,
    /// Measured SYSCALL→SYSRET round-trip of the first write (TSC).
    pub roundtrip_tsc: u64,
}

impl UserRun {
    pub fn new(
        tables: PageTables,
        space: AddressSpace,
        domain: u32,
        mask: SyscallMask,
        quarantined: bool,
    ) -> Self {
        UserRun {
            tables,
            space,
            domain,
            mask,
            quarantined,
            exit: ExitKind::Exited(0),
            write_bytes: 0,
            bad_syscalls: 0,
            denied: 0,
            roundtrip_tsc: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_targets_ring3_with_interrupts_on() {
        let c = UserContext::new(0x40_0000, 0x40_9000);
        assert_eq!(c.cs & 0b11, 3, "RPL 3");
        assert_eq!(c.ss & 0b11, 3, "RPL 3");
        assert_eq!(c.cs, crate::arch::gdt::USER_CODE as u64 + 3);
        assert_eq!(c.ss, crate::arch::gdt::USER_DATA as u64 + 3);
        assert_eq!(c.rflags, 0x202);
        assert!(
            c.rflags & (1 << 9) != 0,
            "IF=1: user code runs interruptible"
        );
        assert_eq!(c.rflags & (1 << 8), 0, "TF clear");
        assert_eq!(c.rflags & (1 << 10), 0, "DF clear");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only: the run state and the naked launch/resume pair.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(not(test))]
mod entry {
    use super::{ExitKind, UserContext, UserRun};
    use core::arch::naked_asm;

    /// Where `enter_ring3` parked the kernel's resume point (RSP holding
    /// its return address). Written once per launch, consumed once per
    /// resume — single CPU, single run.
    /// The kernel resume point, as an explicit (RSP, RIP) pair — immune
    /// to calling-convention games: `enter_ring3` is `-> !`, so the
    /// optimizer may legally turn its call site into a tail jump with
    /// no return address on the stack. `set_resume_point` records both
    /// values from a *returning* function; `resume_kernel` restores the
    /// stack and jumps to the label. Single CPU, single run at a time.
    static mut RESUME_RSP: u64 = 0;
    static mut RESUME_RIP: u64 = 0;

    /// The active run, or `None` between runs.
    static mut USER_RUN: Option<UserRun> = None;

    /// N2 (ADR-0007 §2): the live lib Kernel, set once by kmain before
    /// the first ring-3 launch. The ring-3 syscall path gates through
    /// it (stats, denials, Tighten/Quarantine apply to the very next
    /// syscall) and drives its monitor windows from the TSC.
    /// SAFETY POLICY: part of the documented unsafe allowlist (sched/),
    /// same single-CPU static-mut pattern as USER_RUN above: set once
    /// during bring-up, read-only afterwards, never aliased
    /// concurrently (the dispatch runs on the kernel stack of the only
    /// CPU; nested entry is impossible — SYSCALL never re-enters the
    /// kernel — and the fault path runs after the dispatch returned).
    static mut KERNEL: Option<*mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>> = None;

    /// Install the run state. Called from kmain just before
    /// `enter_ring3`.
    pub fn begin(run: UserRun) {
        // SAFETY: single CPU; written before the launch, and nothing
        // reads it until the dispatch runs (which is after the launch).
        unsafe { USER_RUN = Some(run) }
    }

    /// A mutable handle to the active run. Only valid while a user
    /// context is launched (between `begin` and `take`).
    pub fn current() -> &'static mut UserRun {
        // SAFETY: single CPU; called only from the syscall/exception
        // dispatch paths, which run strictly inside a launched run.
        // SAFETY: single CPU; USER_RUN is written only by begin/take
        // around a launched run (no concurrent access exists).
        unsafe { (*core::ptr::addr_of_mut!(USER_RUN)).as_mut() }
            .unwrap_or_else(|| panic!("user run state missing"))
    }

    /// Is a user run launched right now? (Exception path: a CPL3 fault
    /// with no active run would be a kernel bug, reported loudly.)
    pub fn active() -> bool {
        // SAFETY: single CPU; a plain read of the Option's discriminant.
        unsafe { (*core::ptr::addr_of!(USER_RUN)).is_some() }
    }

    /// Record a ring-3 fault as the run's exit reason (exception path).
    /// N2: install the live kernel pointer (kmain, once, before the
    /// first ring-3 launch).
    pub fn set_kernel(k: *mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>) {
        // SAFETY: single CPU, bring-up phase, before any ring-3 launch.
        unsafe {
            KERNEL = Some(k);
        }
    }

    /// N2: the live kernel, when installed (host tests never install
    /// one — callers fall back to the snapshot).
    pub fn kernel_mut(
    ) -> Option<&'static mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>> {
        // SAFETY: the pointer was set once from a live `&mut Kernel`
        // that outlives every ring-3 run (kmain owns it for the whole
        // boot); single CPU, no nesting (see the static's comment).
        unsafe { KERNEL.map(|p| &mut *p) }
    }

    /// N2: the active run's domain id (for the fault-path live feeds).
    pub fn active_domain() -> Option<u32> {
        // addr_of on a static mut is safe (no reference is formed).
        let run = core::ptr::addr_of!(USER_RUN);
        // SAFETY: single CPU; a read-only peek at the installed run —
        // the raw pointer was just taken, no aliasing reference exists.
        unsafe { (*run).as_ref().map(|r| r.domain) }
    }

    /// N2 (ADR-0007 §2): feed a user-context fault to the LIVE domain
    /// (organic fault signal) and drive the monitor clock. Called from
    /// the exception dispatch's user-death branch, after the run's
    /// exit was recorded.
    #[cfg(not(test))]
    pub fn note_live_fault() {
        let Some(id) = active_domain() else { return };
        if let Some(k) = kernel_mut() {
            let _ = k.report_fault(id);
            k.tick(crate::hw::read_tsc());
        }
    }

    #[cfg(test)]
    pub fn note_live_fault() {}

    pub fn record_fault(vector: u8, cr2: u64, error_code: u64, rip: u64, user_rsp: u64) {
        // SAFETY: single CPU; called only from the exception dispatch,
        // which runs strictly inside a launched run (checked by the
        // caller via `active()`).
        let run = core::ptr::addr_of_mut!(USER_RUN);
        // SAFETY: single CPU; the raw pointer was just taken.
        unsafe {
            if let Some(r) = (*run).as_mut() {
                r.exit = ExitKind::Fault {
                    vector,
                    cr2,
                    error_code,
                    rip,
                    user_rsp,
                };
            }
        }
    }

    /// The parked kernel resume RIP (diagnostics).
    pub fn saved_rip() -> u64 {
        // SAFETY: single CPU; plain read of what set_resume_point wrote.
        unsafe { RESUME_RIP }
    }

    /// The parked kernel resume point (diagnostics).
    pub fn saved_rsp() -> u64 {
        // SAFETY: single CPU; plain read of the value `enter_ring3` wrote.
        unsafe { RESUME_RSP }
    }

    /// Withdraw the run state (kmain, after `resume_kernel`).
    pub fn take() -> UserRun {
        // SAFETY: single CPU; called exactly once after the resume,
        // before the next `begin`.
        match unsafe { (*core::ptr::addr_of_mut!(USER_RUN)).take() } {
            Some(r) => r,
            None => panic!("user run state missing on take"),
        }
    }

    /// Record the resume point (RSP + the label below, inside this very
    /// function) and tail-jump into `enter_ring3`. The launch itself
    /// never returns; when the user run ends (SYS_EXIT or a fault), the
    /// dispatch calls `resume_kernel`, which restores the saved RSP and
    /// jumps to the label — and this function then returns to kmain
    /// normally, exactly once per run. Being a plain `()` function (not
    /// `-> !`), nothing after the call site is unreachable and the
    /// optimizer cannot delete the post-run code.
    pub fn launch(ctx: &UserContext) {
        // SAFETY: writes the two statics once per run (single CPU); the
        // asm stores addresses and tail-jumps to the naked entry. The
        // label is reached only via resume_kernel's jump, on the saved
        // stack — the ordinary epilogue then returns to the caller.
        unsafe {
            core::arch::asm!(
                "lea 9f(%rip), %rax",
                "movq %rax, {rip_slot}(%rip)",
                "movq %rsp, {rsp_slot}(%rip)",
                "jmp {enter}",
                "9:",
                enter = sym enter_ring3,
                rip_slot = sym RESUME_RIP,
                rsp_slot = sym RESUME_RSP,
                options(att_syntax),
                in("rdi") ctx,
            );
        }
    }

    /// Enter ring-3 via `iretq`. Naked; the kernel resume point is NOT
    /// taken from the stack here (see `set_resume_point` — the call site
    /// may be a tail jump) — call `set_resume_point` immediately before
    /// this.
    ///
    /// Why SYSRET and not IRETQ for the initial entry: SYSRET loads
    /// CS/SS from the STAR slot arithmetic (no descriptor-validation
    /// stack-switch cycle — the exact cycle IRETQ performs on a
    /// privilege change), so the entry cannot fault mid-switch. The
    /// context's `cs`/`ss` fields stay documentation: what runs is the
    /// STAR contract (same selectors — pinned by gdt's host test).
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    /// NOTE: declared as returning `()` on purpose — it never returns
    /// (the `iretq` leaves for ring-3 and the kernel resumes through
    /// `resume_kernel`'s jump), but a `-> !` signature lets the
    /// optimizer tail-jump the call site *and delete everything after
    /// it as unreachable*, which would erase the post-resume code.
    pub extern "C" fn enter_ring3(ctx: &UserContext) {
        naked_asm!(
            // rdi = ctx (SysV first arg). The kernel resume point was
            // recorded by `set_resume_point` just before this call.
            "movq 0x00(%rdi), %rax", // rip
            "movq 0x08(%rdi), %rcx", // cs
            "movq 0x10(%rdi), %rdx", // rflags
            "movq 0x18(%rdi), %rsi", // rsp
            "movq 0x20(%rdi), %rdi", // ss (last: rdi was needed)
            "pushq %rdi",            // ss
            "pushq %rsi",            // rsp
            "pushq %rdx",            // rflags
            "pushq %rcx",            // cs
            "pushq %rax",            // rip
            "swapgs",                // GS: user / KERNEL_GS_BASE: percpu
            "iretq",                 // CPL=3, IF per rflags
            options(att_syntax),
        );
    }

    /// Jump back to the kernel point `set_resume_point` recorded:
    /// restore RSP, jump to the label. Never returns (the label is the
    /// resume point; execution continues from there normally).
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub extern "C" fn resume_kernel() -> ! {
        naked_asm!(
            "movq {rsp_slot}(%rip), %rsp",
            "jmpq *{rip_slot}(%rip)",
            rsp_slot = sym RESUME_RSP,
            rip_slot = sym RESUME_RIP,
            options(att_syntax),
        );
    }
}

#[cfg(not(test))]
pub use entry::{
    active, active_domain, begin, current, enter_ring3, kernel_mut, launch, note_live_fault,
    record_fault, resume_kernel, saved_rip, saved_rsp, set_kernel, take,
};
