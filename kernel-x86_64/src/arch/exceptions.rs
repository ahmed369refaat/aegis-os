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

/// Top-of-stack addresses for TSS.IST1..IST4, in the order `gdt::load`
/// writes them (IST1=#DF, IST2=#NMI, IST3=#MC, IST4=#SS).
pub fn ist_tops() -> [u64; 4] {
    let top = |s: &IstStack| s as *const IstStack as u64 + s.0.len() as u64;
    [top(&IST_DF), top(&IST_NMI), top(&IST_MC), top(&IST_SS)]
}

/// Set by `arm_and_trigger_de`: the *next* #DE is the selftest, not a bug.
static SELFTEST_DE: AtomicBool = AtomicBool::new(false);
/// Set by `arm_guard_write`: the next #PF at exactly this address is the
/// guard selftest; 0 = unarmed.
static GUARD_VA: AtomicU64 = AtomicU64::new(0);

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
    if f.vector == 14 && GUARD_VA.load(Ordering::SeqCst) == cr2 {
        serial::write_str("[EXC] guard selftest: stack guard #PF ok\n");
        // Terminal by design: the last act of the boot, so the proof ends
        // the run cleanly (mirrors the PR-1.1 pattern).
        hw::shutdown_qemu()
    }

    // ── everything else is a kernel bug at this stage ────────────────
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
