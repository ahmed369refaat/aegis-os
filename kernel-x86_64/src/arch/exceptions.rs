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
struct IstStack(
    /// Addressed only through `addr_of!`/`addr_of_mut!` (tops are
    /// address arithmetic; the field is never read by name).
    #[allow(dead_code)]
    [u8; 0x4000],
);

// F16 (ADR-0006): `static mut` so these land in `.bss` (writable
// NOBITS). As plain `static` they were immutable data that only worked
// because the image mapping was writable — the exact accident the
// image W^X work (F15) removes. CI asserts the sections
// (scripts/check-ist-sections.sh, wired into boot.sh).
static mut IST_DF: IstStack = IstStack([0; 0x4000]);
static mut IST_NMI: IstStack = IstStack([0; 0x4000]);
static mut IST_MC: IstStack = IstStack([0; 0x4000]);
static mut IST_SS: IstStack = IstStack([0; 0x4000]);
/// PR-1.4: #PF gets its own IST. The classic argument against (a fault
/// on the current stack cannot trust that stack) matters when the
/// faulting stack IS the kernel's — but ring-3 faults arrive from the
/// user stack, and the inter-privilege RSP0 delivery path is the one
/// thing this bring-up proved flaky, while IST delivery from CPL3 is
/// proven working (the #DF frame above arrives complete via IST1).
/// Single CPU, no preemption: no nesting hazard.
static mut IST_PF: IstStack = IstStack([0; 0x4000]);

/// Top-of-stack addresses for TSS.IST1..IST4, in the order `gdt::load`
/// writes them (IST1=#DF, IST2=#NMI, IST3=#MC, IST4=#SS).
pub fn ist_tops() -> [u64; 5] {
    // F16: raw pointers into the `static mut` stacks — no references to
    // mutable statics; the tops are pure address arithmetic.
    let top = |s: *const IstStack| (s as usize + core::mem::size_of::<IstStack>()) as u64;
    [
        top(core::ptr::addr_of!(IST_DF)),
        top(core::ptr::addr_of!(IST_NMI)),
        top(core::ptr::addr_of!(IST_MC)),
        top(core::ptr::addr_of!(IST_SS)),
        top(core::ptr::addr_of!(IST_PF)),
    ]
}

/// Set by `arm_and_trigger_de`: the *next* #DE is the selftest, not a bug.
static SELFTEST_DE: AtomicBool = AtomicBool::new(false);
/// N4 (ADR-0008): armed SMEP selftest — the next instruction-fetch #PF
/// at exactly this user VA is the deliberate CPL0 jump into a user page
/// (SMEP), not a bug.
static ARMED_SMEP: AtomicBool = AtomicBool::new(false);
static SMEP_VA: AtomicU64 = AtomicU64::new(0);
/// The resume label's address, parked by the trigger before the fault
/// (the NX_RESUME pattern: fetch faults report the target as RIP).
static mut SMEP_RESUME: u64 = 0;
/// N4 (ADR-0008): armed SMAP selftest — the next data #PF at exactly
/// this user VA is the deliberate CPL0 read outside the STAC window
/// (SMAP), not a bug.
static ARMED_SMAP: AtomicBool = AtomicBool::new(false);
static SMAP_VA: AtomicU64 = AtomicU64::new(0);
/// F15 (ADR-0006): armed write-permission selftest — the next data #PF
/// at exactly this address is the deliberate CPL0 write to a read-only
/// image page (CR0.WP enforced), not a bug.
static ARMED_WP: AtomicBool = AtomicBool::new(false);
static WP_VA: AtomicU64 = AtomicU64::new(0);
/// F15 (ADR-0006): armed image-exec selftest — the next instruction-
/// fetch #PF at exactly this address is the deliberate CPL0 execution
/// of a non-executable image page (.data NX), not a bug.
static ARMED_IEXEC: AtomicBool = AtomicBool::new(false);
static IEXEC_VA: AtomicU64 = AtomicU64::new(0);
static mut IEXEC_RESUME: u64 = 0;
/// Set by `arm_guard_write`: the next #PF at exactly this address is the
/// (terminal) stack-guard selftest; 0 = unarmed.
static GUARD_VA: AtomicU64 = AtomicU64::new(0);
/// F4: the address alone is not proof of intent — an unarmed
/// `GUARD_VA == cr2` match (both 0) is a kernel NULL dereference, not
/// the selftest. The armed flag makes the distinction; classification
/// lives in `fault_class` (pure, host-tested).
static ARMED_GUARD: AtomicBool = AtomicBool::new(false);
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
    // ── the LAPIC timer (ADR-0012): route to the tick BEFORE anything
    // else. The frame is CPL3 (the kernel runs IF=0 — a tick can only
    // interrupt user code), so the CPL3-fault branch below would
    // otherwise mistake it for the domain's death. The tick either
    // leaves the frame alone (a keep) or rewrites it (a switch to the
    // parked domain the preemptor named); the unwind's iretq then
    // enters whichever domain the frame now describes.
    if f.vector as u8 == super::lapic::TIMER_VECTOR {
        crate::sched::preempt::on_timer_tick(f);
        return;
    }
    // A spurious LAPIC delivery (the SVR vector): a named no-op —
    // notably WITHOUT an EOI (the SDM: acknowledging a spurious vector
    // wedges the APIC's in-service state).
    if f.vector as u8 == super::lapic::SPURIOUS_VECTOR {
        serial::write_str("[IRQ ] lapic spurious vector — ignored (no EOI)\n");
        return;
    }

    // ── broker-owned device vectors (ADR-0019): route to the
    // interrupt broker BEFORE the fault classification. The frame may
    // be CPL3 — a device IRQ that interrupted user code is NOT the
    // domain's death — and it may be CPL0 (the deliberate delivery
    // window); either way the broker owns it: EOI first, then the
    // device's mailbox. An unowned vector is a NAMED halt inside the
    // broker (nothing arms a vector it did not hand out).
    if (crate::irq::DEVICE_VECTOR_BASE..=crate::irq::DEVICE_VECTOR_MAX).contains(&(f.vector as u8))
    {
        crate::irq::deliver(f.vector as u8);
        return;
    }

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

    // #DF forensics: a contribution-#DF in this environment arrives
    // WITHOUT a CPU error code, which shifts the parse by exactly one
    // slot (proven empirically: the err-slot holds the real RIP, the
    // rip-slot the real CS, the cs-slot the real RFLAGS). Dump the raw
    // tail plus CR2/CR3 so the original fault — the one that escalated
    // — can be reconstructed instead of guessed at.
    if f.vector == 8 {
        // SAFETY: CR2/CR3 are register reads; the word reads start at
        // the error_code slot and walk upward through words the stub
        // or the CPU pushed (or the scrubbed IST stack below them) —
        // every read lands on the mapped IST1 stack page.
        let words: [u64; 8] = unsafe {
            let base = core::ptr::addr_of!(f.error_code);
            let mut w = [0u64; 8];
            let mut i = 0;
            while i < 8 {
                w[i] = base.add(i).read();
                i += 1;
            }
            w
        };
        let cr2f = hw::read_cr2();
        let cr3f = hw::read_cr3();
        for (i, w) in words.iter().enumerate() {
            let mut bw = [0u8; 18];
            let mut bi = [0u8; 20];
            serial::write_str("[EXC] #DF raw w");
            serial::write_str(strutil::dec(i as u64, &mut bi));
            serial::write_str("=");
            serial::write_str(strutil::hex(*w, &mut bw));
            serial::write_str("\n");
        }
        let mut bc2 = [0u8; 18];
        let mut bc3 = [0u8; 18];
        serial::write_str("[EXC] #DF cr2=");
        serial::write_str(strutil::hex(cr2f, &mut bc2));
        serial::write_str(" cr3=");
        serial::write_str(strutil::hex(cr3f, &mut bc3));
        serial::write_str("\n");
    }

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
        // ADR-0024 D2: the RECOVERABLE fault — a write to a
        // copy-on-write page (fork demoted it RO on both sides; the
        // region says writable; the frame is shared). The check is the
        // pure truth table; the fix is one private frame, one page
        // copy, one PTE repoint, one invlpg — and this handler simply
        // RETURNS, so the iretq re-executes the faulting instruction.
        if f.vector == 14 && try_cow_recovery(f) {
            return;
        }
        // SAFETY: CPL3 frames physically carry the rsp/ss tail (the CPU
        // pushed it); reading one word past `rflags` is in-bounds here.
        let user_rsp = unsafe { core::ptr::addr_of!(f.rflags).add(1).read() };
        let user_ss = unsafe { core::ptr::addr_of!(f.rflags).add(2).read() };
        let _ = user_ss;
        crate::sched::context::record_fault(f.vector as u8, cr2, f.error_code, f.rip, user_rsp);
        // N2 (ADR-0007 §2): the user's death is an organic fault signal
        // on the LIVE domain, and drives the monitor clock.
        crate::sched::context::note_live_fault();
        serial::write_str("[RING3] user fault: domain terminated, kernel resumes\n");
        // The launch swapped GS to the user view; a CPL3 fault arrives
        // with GS still user-side — swap it back before resuming (the
        // exact pairing the SYS_EXIT path performs).
        hw::swapgs();
        // Resume the launch point: kmain takes the run, reports the
        // fault as the run's exit kind, restores the kernel CR3, and
        // proceeds to the next run. (The user CR3 stays active across
        // the jump — the shared kernel half covers every static the
        // resume path touches, and kmain writes CR3 back on take.)
        crate::sched::context::resume_kernel();
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
    if ARMED_WP.load(Ordering::SeqCst) && f.vector == 14 && cr2 == WP_VA.load(Ordering::SeqCst) {
        // CR0.WP: a supervisor write to a read-only page faults. Data
        // faults report the faulting instruction; advance past it.
        f.rip += MOV_LEN;
        ARMED_WP.store(false, Ordering::SeqCst);
        serial::write_str("[SEC ] image W^X: write to read-only page faulted (CR0.WP)\n");
        return;
    }
    if ARMED_IEXEC.load(Ordering::SeqCst)
        && f.vector == 14
        && cr2 == IEXEC_VA.load(Ordering::SeqCst)
        && (f.error_code & PF_INSTRUCTION_FETCH) != 0
    {
        // NX on an image data page: the fetch never retired; the saved
        // RIP is the target, so resume at the trigger's label.
        // SAFETY: written by arm_image_exec's trigger before the fault;
        // single CPU, read exactly once here.
        f.rip = unsafe { core::ptr::addr_of!(IEXEC_RESUME).read_volatile() };
        ARMED_IEXEC.store(false, Ordering::SeqCst);
        serial::write_str("[SEC ] image W^X: exec from non-executable page faulted (I/D)\n");
        return;
    }
    if ARMED_SMEP.load(Ordering::SeqCst)
        && f.vector == 14
        && cr2 == SMEP_VA.load(Ordering::SeqCst)
        && (f.error_code & PF_INSTRUCTION_FETCH) != 0
    {
        // SMEP: the fetch never retired; the saved RIP is the user
        // target, so resume at the trigger's label (the NX pattern).
        // SAFETY: written by arm_sme_call's trigger before the fault;
        // single CPU, read exactly once here.
        f.rip = unsafe { core::ptr::addr_of!(SMEP_RESUME).read_volatile() };
        ARMED_SMEP.store(false, Ordering::SeqCst);
        serial::write_str("[SEC ] SMEP selftest: kernel exec of user RX page faulted (I/D)\n");
        return;
    }
    if ARMED_SMAP.load(Ordering::SeqCst) && f.vector == 14 && cr2 == SMAP_VA.load(Ordering::SeqCst)
    {
        // SMAP: a CPL0 data access to a user page outside the STAC
        // window. Data faults report the faulting instruction; advance
        // past it (the guard-read pattern).
        f.rip += MOV_LEN;
        ARMED_SMAP.store(false, Ordering::SeqCst);
        serial::write_str("[SEC ] SMAP selftest: kernel read of user page outside STAC faulted\n");
        return;
    }
    if ARMED_DG.load(Ordering::SeqCst) && f.vector == 14 && cr2 == DG_VA.load(Ordering::SeqCst) {
        // A read into a policy guard-gap page: absent PTE by design.
        f.rip += MOV_LEN;
        ARMED_DG.store(false, Ordering::SeqCst);
        serial::write_str("[EXC] domain guard selftest: guard-gap #PF ok\n");
        return;
    }
    if super::fault_class::guard_selftest_hit(
        ARMED_GUARD.load(Ordering::SeqCst),
        GUARD_VA.load(Ordering::SeqCst),
        f.vector as u8,
        cr2,
    ) {
        ARMED_GUARD.store(false, Ordering::SeqCst);
        serial::write_str("[EXC] guard selftest: stack guard #PF ok\n");
        // Terminal by design: the last act of the boot, so the proof ends
        // the run cleanly (mirrors the PR-1.1 pattern). The power-off is
        // FADT-sourced when the ACPI step installed one (arch::pwr),
        // the legacy constants otherwise.
        crate::arch::pwr::power_off()
    }

    // ── a stray device IRQ: named, loud, terminal ────────────────────
    // The PIC is masked and no device is armed; reaching this arm means
    // either a mask regression or an unmodeled source. Halt with the
    // vector number — never a silent #DF with a shifted frame.
    if f.vector >= 32 && f.vector < 48 {
        let mut bv2 = [0u8; 20];
        serial::write_str("[IRQ ] unexpected IRQ vector=");
        serial::write_str(strutil::dec(f.vector, &mut bv2));
        serial::write_str(" — no source is armed (PIC masked); halting loudly\n");
        hw::halt_forever();
    }

    // ── everything else is a kernel bug at this stage ────────────────
    // A fault while a user run is active is the *user's* death, not the
    // kernel's: record it as the run's exit and resume the launch point
    // (kmain reports it honestly — this is also the path a ring-3
    // entry blocked by the environment takes; see
    // docs/arch/syscall-entry.md).
    if crate::sched::context::active() {
        // N1 (ADR-0007 §1): classify BEFORE billing anyone. Only a CPL3
        // frame is the user's death; a CPL0 fault while a run is active
        // is a kernel bug (inside the user-copy routine: a validated-
        // span violation) and must halt loudly — the PR-1.4 code
        // resumed either way, hiding the user-copy over-read crash.
        match super::fault_class::fault_owner(
            (f.cs & 3) as u8,
            crate::syscall::IN_USER_COPY.load(Ordering::SeqCst),
            crate::syscall::SYSCALLS_SERVED.load(Ordering::SeqCst),
        ) {
            super::fault_class::FaultOwner::KernelBugUserCopy => {
                serial::write_str("[SEC ] KERNEL BUG: #PF inside the user-copy routine (copy escaped the validated span)\n");
                serial::write_str(
                    "[EXC] halting: this is unreachable by construction (ADR-0007)\n",
                );
                hw::halt_forever()
            }
            super::fault_class::FaultOwner::KernelBug => {
                serial::write_str("[EXC] KERNEL BUG: CPL0 fault while a user run is active\n");
                hw::halt_forever()
            }
            super::fault_class::FaultOwner::LaunchRelayLimitation => {
                serial::write_str("[RING3] launch fault (CPL0, pre-syscall): the documented entry-relay limitation\n");
            }
            super::fault_class::FaultOwner::User => {}
        }
        // SAFETY: CPL3 frames carry the rsp/ss tail; for a CPL0 frame
        // (the entry-blocked case) read zeros — the record only feeds
        // the security log.
        let user_rsp = if f.cs & 3 == 3 {
            unsafe { core::ptr::addr_of!(f.rflags).add(1).read() }
        } else {
            0
        };
        crate::sched::context::record_fault(f.vector as u8, cr2, f.error_code, f.rip, user_rsp);
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
        serial::write_str(
            "[RING3] (machinery armed + host-tested; see docs/arch/syscall-entry.md)\n",
        );
        serial::write_str("[RING3] ring-3 step concluded: blocked (environment), kernel intact\n");
        hw::shutdown_qemu();
    }
    serial::write_str(
        "[EXC] unexpected fault — halting (kernel bug; see docs/arch/exceptions.md)\n",
    );
    // ADR-0010's lesson: print the FULL frame — every GPR, the iret
    // words, and the raw stack tail — so the next investigation starts
    // from data instead of guesses. `rbp` of a kernel frame is a chain
    // pointer only when built with frame pointers; treat all words as
    // data.
    let names = [
        "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "rbp", "rdi", "rsi", "rdx", "rcx",
        "rbx", "rax",
    ];
    for (i, name) in names.iter().enumerate() {
        let v = crate::sched::context::gpr_at(f, i);
        let mut bv = [0u8; 18];
        serial::write_str("[EXC]   ");
        serial::write_str(name);
        serial::write_str("=");
        serial::write_str(strutil::hex(v, &mut bv));
        serial::write_str("\n");
    }
    {
        let mut b1 = [0u8; 18];
        let mut b2 = [0u8; 18];
        serial::write_str("[EXC]   vector=");
        serial::write_str(strutil::hex(f.vector, &mut b1));
        serial::write_str(" err=");
        serial::write_str(strutil::hex(f.error_code, &mut b2));
        serial::write_str("\n");
    }
    // The caller chain: the frame itself sits on the interrupted
    // stack — the caller's rsp = frame address + 20 words (the whole
    // ExceptionFrame) for a CPL0 fault (no rsp/ss tail).
    {
        let rsp = core::ptr::from_mut(f) as u64 + 20 * 8;
        for i in 0..6u64 {
            let v = crate::memops::read_u64_va(rsp + i * 8);
            let mut bi = [0u8; 18];
            let mut bv = [0u8; 18];
            let idx = strutil::hex(i * 8, &mut bi);
            let val = strutil::hex(v, &mut bv);
            serial::write_str("[EXC]   [rsp+");
            serial::write_str(idx);
            serial::write_str("]=");
            serial::write_str(val);
            serial::write_str("\n");
        }
    }
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
    ARMED_GUARD.store(true, Ordering::SeqCst);
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
/// F15 (ADR-0006): write to a read-only image page (.text/.rodata)
/// from CPL0 — CR0.WP must fault it. Resumable (the guard-read pattern).
pub fn arm_wp_write(va: u64) {
    ARMED_WP.store(true, Ordering::SeqCst);
    WP_VA.store(va, Ordering::SeqCst);
    // SAFETY: deliberately stores to a read-only page → #PF under WP;
    // dispatch advances RIP by MOV_LEN.
    unsafe {
        core::arch::asm!(
            "movq %rax, (%rax)",
            in("rax") va,
            options(att_syntax, preserves_flags),
        );
    }
    ARMED_WP.store(false, Ordering::SeqCst);
}

/// F15 (ADR-0006): execute a non-executable image page (.data, NX)
/// from CPL0 — must fault. A JMP (not a call) so RSP stays exact (the
/// arm_nx_call rationale).
pub fn arm_image_exec(va: u64) {
    ARMED_IEXEC.store(true, Ordering::SeqCst);
    IEXEC_VA.store(va, Ordering::SeqCst);
    // SAFETY: deliberately fetches an instruction from an NX page →
    // #PF; never completes.
    unsafe {
        let slot = core::ptr::addr_of_mut!(IEXEC_RESUME) as u64;
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
    ARMED_IEXEC.store(false, Ordering::SeqCst);
}

/// N4 (ADR-0008): jump into a *user* RX page from CPL0 — SMEP must
/// fault the fetch. A JMP (not a call) so the fault leaves RSP exact
/// (the arm_nx_call rationale).
pub fn arm_sme_call(va: u64) {
    ARMED_SMEP.store(true, Ordering::SeqCst);
    SMEP_VA.store(va, Ordering::SeqCst);
    // SAFETY: deliberately fetches an instruction from a user page at
    // CPL0 → #PF under SMEP. Never completes when SMEP is active.
    unsafe {
        let slot = core::ptr::addr_of_mut!(SMEP_RESUME) as u64;
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
    ARMED_SMEP.store(false, Ordering::SeqCst);
}

/// N4 (ADR-0008): read a *user* page from CPL0 with no STAC window —
/// SMAP must fault the access.
pub fn arm_smap_read(va: u64) {
    ARMED_SMAP.store(true, Ordering::SeqCst);
    SMAP_VA.store(va, Ordering::SeqCst);
    // SAFETY: deliberately loads from a user page at CPL0 outside the
    // STAC window → #PF under SMAP.
    unsafe {
        core::arch::asm!(
            "movq (%rax), %rax",
            in("rax") va,
            options(att_syntax, preserves_flags),
        );
    }
    ARMED_SMAP.store(false, Ordering::SeqCst);
}

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

/// ADR-0024 D2: serve one copy-on-write fault, or answer `false` (the
/// fault is not ours to fix — the fatal path applies). PURE decision
/// over the live state, then the fix: a fresh private frame, the page
/// copy through the direct map, the PTE repointed RW, the old frame's
/// reference released, the TLB entry dropped.
fn try_cow_recovery(f: &ExceptionFrame) -> bool {
    use crate::mm::pte::{self, PTE_P, PTE_U, PTE_W};
    use crate::mm::ADDR_MASK;
    use aegis_os::frame_share::{cow_decision, CowDecision};
    use aegis_os::memory::MemFlags;

    let run = crate::sched::context::current();
    let cr2 = crate::hw::read_cr2();
    // A CPL3 fault in the KERNEL half is a violation by definition —
    // and walking the user tables for a kernel VA would descend into
    // the shared kernel half's HUGE-LEAF entries and read them as
    // page tables (found live: the kernel-VA-read proof faulted into
    // a direct-map walk and panicked in pa_to_va). Never ours.
    if cr2 >= pte::USER_LIMIT {
        return false;
    }
    let is_write = f.error_code & 0x2 != 0;
    let Some(leaf) = run.tables.pte_of(cr2) else {
        return false;
    };
    let pa = leaf & ADDR_MASK;
    let region_writable = run
        .space
        .regions()
        .find(|r| {
            let base = r.base as u64;
            cr2 >= base && cr2 < base + r.len as u64
        })
        .is_some_and(|r| r.flags.0 & MemFlags::WRITE.0 != 0);
    let refs = crate::sched::context::shares_mut().refs(pa);
    match cow_decision(
        leaf & PTE_P != 0,
        leaf & PTE_W != 0,
        leaf & PTE_U != 0,
        region_writable,
        refs,
        is_write,
    ) {
        CowDecision::NotCow => return false,
        // The last holder of a demoted page: no copy, no allocation —
        // re-promote the PTE in place and serve the write.
        CowDecision::Promote => {
            if !run.tables.replace_leaf(cr2, pa, true) {
                return false;
            }
            pte::flush_tlb_page(cr2);
            crate::mm::shares::note_cow_copy();
            return true;
        }
        CowDecision::Copy => {}
    }

    // The fix: one private frame under the faulting domain's tag, the
    // page copied byte-for-byte through the direct map (CR3-
    // independent), the leaf repointed RW at the copy.
    let (Some(pool), Some(k)) = (
        crate::sched::context::pool_mut(),
        crate::sched::context::kernel_mut(),
    ) else {
        return false;
    };
    let Ok(fresh) = pool.alloc_for(&mut k.frames, run.domain) else {
        return false; // OOM on a CoW fix: the fatal path applies
    };
    let mut off = 0u64;
    while off < pte::PAGE_SIZE_U64 {
        let word = crate::memops::read_u64(pa + off);
        crate::memops::write_u64(fresh + off, word);
        off += 8;
    }
    if !run.tables.replace_leaf(cr2, fresh, true) {
        // The walk found no leaf after all (a race the pure check
        // could not see — single CPU makes this unreachable; still,
        // never leave a private frame stranded).
        let _ = pool.free(&mut k.frames, fresh, run.domain);
        return false;
    }
    // The shared frame loses one holder (never the last: refs > 1 is
    // the decision's premise — the release keeps >= 1).
    let _ = crate::sched::context::shares_mut().release(pa);
    pte::flush_tlb_page(cr2);
    crate::mm::shares::note_cow_copy();
    true
}
