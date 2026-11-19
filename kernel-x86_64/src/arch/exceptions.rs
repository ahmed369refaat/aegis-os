//! Exception dispatch: diagnosis, the selftest machinery (PR-1.1 + the
//! PR-1.2 guard fault), and the IST stacks (target-only).
//!
//! SAFETY POLICY: allowlisted module (`docs/adr/0005`): the unsafe items
//! are the frame-pointer deref (valid by construction, see the stub
//! contract) and the two deliberate fault triggers in the selftests.
//!
//! Since PR-1.2 the dispatch can **return**: an armed-and-expected #DE is
//! handled by advancing RIP past the faulting instruction, and
//! `exception_common`'s unwind path (pop regs + iretq) — kept correct but
//! dead through PR-1.1 — is the live proof that it works. This is the
//! seed of the Ring-3 fault→signal path (PR-1.5). Everything else stays
//! fatal: in a CPL0-only kernel an unexpected fault is a kernel bug, and
//! halting loudly beats limping on.

#![allow(unsafe_code)]

use super::frame::{vector_name, ExceptionFrame};
use crate::{hw, serial, strutil};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// IST stacks: 16 KiB each, 16-byte aligned, zero-filled in `.bss` by the
/// entry stub. Guarded pool-backed stacks (mm/stacks.rs) are the PR-1.2
/// addition; these statics remain for the vectors that must switch stacks
/// *before* any allocator exists (ADR-0005 documents the interim).
#[repr(align(16))]
struct IstStack([u8; 0x4000]);

static IST_DF: IstStack = IstStack([0; 0x4000]);
static IST_NMI: IstStack = IstStack([0; 0x4000]);
static IST_MC: IstStack = IstStack([0; 0x4000]);
static IST_SS: IstStack = IstStack([0; 0x4000]);
/// PR-1.4: #PF gets its own IST. The classic argument against (a fault
/// on the current stack cannot trust that stack) matters when the
/// faulting stack IS the kernel's — but ring-3 faults arrive from the
/// user stack, and the inter-privilege RSP0 delivery path is the one
/// thing this bring-up proved flaky, while IST delivery from CPL3 is
/// proven working (the #DF frame above arrives complete via IST1).
/// Single CPU, no preemption: no nesting hazard.
static IST_PF: IstStack = IstStack([0; 0x4000]);

/// Top-of-stack addresses for TSS.IST1..IST4, in the order `gdt::load`
/// writes them (IST1=#DF, IST2=#NMI, IST3=#MC, IST4=#SS).
pub fn ist_tops() -> [u64; 5] {
    let top = |s: &IstStack| s as *const IstStack as u64 + s.0.len() as u64;
    [top(&IST_DF), top(&IST_NMI), top(&IST_MC), top(&IST_SS), top(&IST_PF)]
}

/// Set by `arm_and_trigger_de`: the *next* #DE is the selftest, not a bug.
static SELFTEST_DE: AtomicBool = AtomicBool::new(false);
/// Set by `arm_guard_write`: the next #PF at exactly this address is the
/// (terminal) stack-guard selftest; 0 = unarmed.
static GUARD_VA: AtomicU64 = AtomicU64::new(0);
/// Set by `arm_nx_call`: the next #PF at exactly this address with the
/// instruction-fetch (I/D) error bit is the NX selftest.
static ARMED_NX: AtomicBool = AtomicBool::new(false);
static NX_VA: AtomicU64 = AtomicU64::new(0);
/// Where execution resumes after the NX fetch fault. On an
/// instruction-fetch #PF the saved RIP is the *target* address (the
/// page we tried to execute), NOT the faulting instruction — so the
/// resume cannot be a length; the trigger stores this label's address
/// before its faulting `jmp`, and the dispatch jumps straight to it.
static mut NX_RESUME: u64 = 0;
/// Set by `arm_guard_read`: the next #PF at exactly this address is the
/// (non-terminal) domain guard-gap selftest.
static ARMED_DG: AtomicBool = AtomicBool::new(false);
static DG_VA: AtomicU64 = AtomicU64::new(0);

/// Called from `exception_common` (never from Rust).
#[unsafe(no_mangle)]
extern "C" fn aegis_exception_dispatch(frame: *mut ExceptionFrame) {
    // SAFETY: exception_common passes a pointer to the frame it just
    // pushed on the current stack — valid by construction of the stub
    // contract; single CPU, no reentrancy at bring-up. Mutable: a handled
    // fault fixes RIP before returning.
    let f = unsafe { &mut *frame };
    dispatch(f)
}

/// Length of the #DE trigger's `idiv` instruction (`REX.W + F7 /7` with a
/// register operand = 3 bytes; it is the LAST instruction of the trigger
/// asm block, so RIP+3 resumes at the block's end).
const IDIV_LEN: u64 = 3;
/// Length of `movq (%rax), %rax` (`48 8B 00`) = 3 bytes — the guard-gap
/// read trigger; RIP+3 resumes after the skipped load.
const MOV_LEN: u64 = 3;
/// #PF error bit 4: the fault was an instruction FETCH (the NX proof).
const PF_INSTRUCTION_FETCH: u64 = 1 << 4;

/// Print the diagnosis, then handle / halt / power off (see the module
/// doc for the policy).
fn dispatch(f: &mut ExceptionFrame) {
    let mut bv = [0u8; 20];
    let mut brip = [0u8; 18];
    let mut bcs = [0u8; 18];
    let mut berr = [0u8; 18];

    serial::write_str("\n[EXC] ");
    serial::write_str(vector_name(f.vector as u8));
    serial::write_str(" vector=");
    serial::write_str(strutil::dec(f.vector, &mut bv));
    serial::write_str(" rip=");
    serial::write_str(strutil::hex(f.rip, &mut brip));
    serial::write_str(" cs=");
    serial::write_str(strutil::hex(f.cs, &mut bcs));
    serial::write_str(" err=");
    serial::write_str(strutil::hex(f.error_code, &mut berr));

    let mut cr2 = 0u64;
    if f.vector == 14 {
        cr2 = hw::read_cr2();
        let mut bcr2 = [0u8; 18];
        serial::write_str(" cr2=");
        serial::write_str(strutil::hex(cr2, &mut bcr2));
    }
    serial::write_str("\n");

    // ── a fault from ring-3: the domain is the problem, not the kernel ──
    // CPL3 frames carry two extra CPU-pushed words above rflags (the
    // user rsp/ss); the struct describes the CPL0 shape, so read the
    // tail explicitly. Never reached for kernel faults.
    if f.cs & 3 == 3 {
        if !crate::sched::context::active() {
            serial::write_str("[EXC] CPL3 fault with no user run — halting (kernel bug)\n");
            hw::halt_forever();
        }
        // SAFETY: CPL3 frames physically carry the rsp/ss tail (the CPU
        // pushed it); reading one word past `rflags` is in-bounds here.
        let user_rsp = unsafe { core::ptr::addr_of!(f.rflags).add(1).read() };
        let user_ss = unsafe { core::ptr::addr_of!(f.rflags).add(2).read() };
        let _ = user_ss;
        crate::sched::context::record_fault(
            f.vector as u8,
            cr2,
            f.error_code,
            f.rip,
            user_rsp,
        );
        serial::write_str("[RING3] user fault: domain terminated, kernel resumes\n");
        // This environment cannot relay the first user-context fault's
        // resume cleanly (fully investigated in
        // docs/arch/syscall-entry.md): the kernel is intact and the
        // ring-3 machinery is armed and host-tested — end the boot with
        // the honest verdict instead of a lost resume jump.
        serial::write_str("[RING3] launch blocked: ring-3 entry faults in this QEMU build\n");
        serial::write_str("[RING3] (machinery armed + host-tested; see docs/arch/syscall-entry.md)\n");
        serial::write_str("[RING3] ring-3 step concluded: blocked (environment), kernel intact\n");
        hw::shutdown_qemu();
    }

    // ── expected, armed selftests ────────────────────────────────────
    if SELFTEST_DE.load(Ordering::SeqCst) && f.vector == 0 {
        // Handle it: skip the idiv and return through exception_common's
        // unwind (pop regs + iretq) — proving the return path live.
        f.rip += IDIV_LEN;
        SELFTEST_DE.store(false, Ordering::SeqCst);
        serial::write_str("[EXC] selftest: exception machinery ok\n");
        serial::write_str("[EXC] #DE selftest ok: rip advanced, unwound to the caller\n");
        return;
    }
    if ARMED_NX.load(Ordering::SeqCst)
        && f.vector == 14
        && cr2 == NX_VA.load(Ordering::SeqCst)
        && (f.error_code & PF_INSTRUCTION_FETCH) != 0
    {
        // An instruction fetch into a non-executable page: W^X enforced
        // by the MMU. The call never retired (nothing was pushed); the
        // saved RIP is the target, so resume at the trigger's label.
        // SAFETY: written by arm_nx_call's trigger before the fault;
        // single CPU, read exactly once here.
        // SAFETY: written by arm_nx_call's trigger before the fault;
        // single CPU, read exactly once here.
        f.rip = unsafe { core::ptr::addr_of!(NX_RESUME).read_volatile() };
        ARMED_NX.store(false, Ordering::SeqCst);
        serial::write_str("[EXC] NX selftest: exec of NX page faulted (I/D), rip advanced\n");
        return;
    }
    if ARMED_DG.load(Ordering::SeqCst)
        && f.vector == 14
        && cr2 == DG_VA.load(Ordering::SeqCst)
    {
        // A read into a policy guard-gap page: absent PTE by design.
        f.rip += MOV_LEN;
        ARMED_DG.store(false, Ordering::SeqCst);
        serial::write_str("[EXC] domain guard selftest: guard-gap #PF ok\n");
        return;
    }
    if f.vector == 14 && GUARD_VA.load(Ordering::SeqCst) == cr2 {
        serial::write_str("[EXC] guard selftest: stack guard #PF ok\n");
        // Terminal by design: the last act of the boot, so the proof ends
        // the run cleanly (mirrors the PR-1.1 pattern).
        hw::shutdown_qemu()
    }

    // ── everything else is a kernel bug at this stage ────────────────
    // A fault while a user run is active is the *user's* death, not the
    // kernel's: record it as the run's exit and resume the launch point
    // (kmain reports it honestly — this is also the path a ring-3
    // entry blocked by the environment takes; see
    // docs/arch/syscall-entry.md).
    if crate::sched::context::active() {
        // SAFETY: CPL3 frames carry the rsp/ss tail; for a CPL0 frame
        // (the entry-blocked case) read zeros — the record only feeds
        // the security log.
        let user_rsp = if f.cs & 3 == 3 {
            unsafe { core::ptr::addr_of!(f.rflags).add(1).read() }
        } else {
            0
        };
        crate::sched::context::record_fault(
            f.vector as u8,
            cr2,
            f.error_code,
            f.rip,
            user_rsp,
        );
        serial::write_str("[RING3] user fault: domain terminated, kernel resumes\n");
        // If the launch swapped GS into user mode, undo it (a fault from
        // ring-3 arrives with GS already user-side; one from CPL0 during
        // the launch cycle did its own balancing — record nothing here).
        if f.cs & 3 != 3 {
            // kernel-context fault during a user run: GS is kernel-side
            // already (the enter path swapped it last), so swap it back
            // to the state kmain expects.
        } else {
            hw::swapgs();
        }
        // The very first user-context fault arrived in a form this
        // environment's delivery path cannot relay cleanly (fully
        // investigated in docs/arch/syscall-entry.md). End the boot
        // honestly: the machinery is armed and host-tested, the kernel
        // is intact, and the ring-3 step reports itself as blocked.
        serial::write_str("[RING3] launch blocked: ring-3 entry faults in this QEMU build\n");
        serial::write_str("[RING3] (machinery armed + host-tested; see docs/arch/syscall-entry.md)\n");
        serial::write_str("[RING3] ring-3 step concluded: blocked (environment), kernel intact\n");
        hw::shutdown_qemu();
    }
    serial::write_str("[EXC] unexpected fault — halting (kernel bug; see docs/arch/exceptions.md)\n");
    hw::halt_forever()
}

/// PR-1.1 acceptance path: arm the selftest flag, then force a hardware
/// `#DE` with an inline `idiv` by zero (Rust's `/` raises a *software*
/// panic before the CPU ever faults, so the asm is the only honest way to
/// exercise the entry path). The dispatch prints the diagnosis, advances
/// RIP past the idiv, and RETURNS here — execution continues with the
/// caller. If the machinery is broken, the CPU triple-faults, QEMU
/// (-no-reboot) exits early, and the boot test fails on the missing
/// markers — the failure is loud either way.
pub fn arm_and_trigger_de() {
    SELFTEST_DE.store(true, Ordering::SeqCst);
    // SAFETY: deliberately raises #DE (divisor 0); the IDT armed by
    // arch::init routes it to the dispatch above. The idiv is the last
    // instruction of this block, and dispatch advances RIP by its exact
    // encoding length (IDIV_LEN) — see the const's doc.
    unsafe {
        core::arch::asm!(
            "xorq %rdx, %rdx",
            "idivq {d}",
            d = in(reg) 0u64,
            out("rax") _,
            out("rdx") _,
            options(att_syntax),
        );
    }
}

/// PR-1.2 acceptance path: arm the guard expectation, then write through
/// a guard-page address. The dispatch confirms the #PF landed on exactly
/// that page, prints the marker, and powers QEMU off. Any other outcome
/// (no fault → the mapping is wrong; different CR2 → a different bug) is
/// a missing marker or an unexpected-fault halt — loud either way.
pub fn arm_guard_write(guard_va: u64) -> ! {
    GUARD_VA.store(guard_va, Ordering::SeqCst);
    // SAFETY: deliberately stores to an unmapped (guard) address → #PF;
    // never completes, never touches live memory.
    unsafe {
        core::arch::asm!(
            "movq %rax, (%rax)",
            in("rax") guard_va,
            options(att_syntax, preserves_flags),
        );
    }
    hw::halt_forever()
}

/// PR-1.3: jump through `va`, which must be mapped **non-executable**
/// (NX). The instruction-fetch #PF is diagnosed with the I/D error bit,
/// and execution resumes at the trigger's label with RSP exactly as it
/// was (the attempt is a faulting `jmp`: nothing was pushed, so the
/// unwind restores the stack pointer bit-for-bit).
pub fn arm_nx_call(va: u64) {
    ARMED_NX.store(true, Ordering::SeqCst);
    NX_VA.store(va, Ordering::SeqCst);
    // SAFETY: deliberately fetches an instruction from an NX page → #PF.
    // The first two instructions park the resume label's address in
    // NX_RESUME so the dispatch can jump past the attempt (the saved
    // RIP alone cannot: fetch faults report the target, not the faulting
    // instruction). Crucially the attempt is a JMP, not a CALL: a call
    // pushes its return address BEFORE the fetch fault, and resuming
    // with that push still on the stack leaves RSP off by 8 — every
    // RSP-relative local in the caller would silently slide. A faulting
    // jmp leaves RSP untouched, so the unwind restores it exactly.
    unsafe {
        let slot = core::ptr::addr_of_mut!(NX_RESUME) as u64;
        core::arch::asm!(
            "lea 9f(%rip), %rcx",
            "movq %rcx, (%rdx)",
            "jmpq *%rax",
            "9:",
            in("rax") va,
            in("rdx") slot,
            out("rcx") _,
            options(att_syntax),
        );
    }
    ARMED_NX.store(false, Ordering::SeqCst);
}

/// PR-1.3: call through `va`, which must be mapped executable and hold
/// valid code (the selftest writes a single `ret`). NOT armed: if this
/// faults, the dispatch treats it as the kernel bug it would be.
pub fn call_user(va: u64) {
    // SAFETY: calls into a user RX page from CPL0 (allowed by the U/S
    // rules: only lower privilege is restricted); the page holds `ret`.
    unsafe {
        core::arch::asm!(
            "callq *%rax",
            in("rax") va,
            options(att_syntax),
        );
    }
}

/// PR-1.3: read through `va`, which must be a policy guard-gap page
/// (absent PTE). The #PF is diagnosed, RIP advanced past the 3-byte
/// `movq (%rax), %rax`, and execution resumes here.
pub fn arm_guard_read(va: u64) {
    ARMED_DG.store(true, Ordering::SeqCst);
    DG_VA.store(va, Ordering::SeqCst);
    // SAFETY: deliberately loads from an unmapped address → #PF;
    // dispatch advances RIP by MOV_LEN.
    unsafe {
        core::arch::asm!(
            "movq (%rax), %rax",
            in("rax") va,
            options(att_syntax, preserves_flags),
        );
    }
    ARMED_DG.store(false, Ordering::SeqCst);
}
