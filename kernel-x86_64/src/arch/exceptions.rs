//! Exception dispatch: diagnosis, the PR-1.1 selftest, and the IST stacks
//! (target-only).
//!
//! SAFETY POLICY: allowlisted module (`docs/adr/0005`): the two unsafe
//! items are the frame-pointer deref (valid by construction, see the
//! stub contract) and the deliberate #DE trigger in the selftest.

#![allow(unsafe_code)]

use super::frame::{vector_name, ExceptionFrame};
use crate::{hw, serial, strutil};
use core::sync::atomic::{AtomicBool, Ordering};

/// IST stacks: 16 KiB each, 16-byte aligned, zero-filled in `.bss` by the
/// entry stub. PR-1.2 replaces them with guarded, pool-backed stacks
/// (ADR-0005 documents the interim).
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
static SELFTEST_ARMED: AtomicBool = AtomicBool::new(false);

/// Called from `exception_common` (never from Rust).
#[unsafe(no_mangle)]
extern "C" fn aegis_exception_dispatch(frame: *mut ExceptionFrame) {
    // SAFETY: exception_common passes a pointer to the frame it just
    // pushed on the current stack — valid by construction of the stub
    // contract; single CPU, no reentrancy at bring-up.
    let f = unsafe { &*frame };
    report(f)
}

/// Print the diagnosis, then either finish the selftest (clean poweroff)
/// or halt: in a CPL0-only kernel every unexpected fault is a kernel bug,
/// and halting loudly beats limping on with a corrupted stack.
fn report(f: &ExceptionFrame) -> ! {
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

    if f.vector == 14 {
        let mut bcr2 = [0u8; 18];
        serial::write_str(" cr2=");
        serial::write_str(strutil::hex(hw::read_cr2(), &mut bcr2));
    }
    serial::write_str("\n");

    if SELFTEST_ARMED.load(Ordering::SeqCst) && f.vector == 0 {
        serial::write_str("[EXC] selftest: exception machinery ok\n");
        hw::shutdown_qemu()
    } else {
        serial::write_str("[EXC] unexpected fault — halting (kernel bug; see docs/arch/exceptions.md)\n");
        hw::halt_forever()
    }
}

/// PR-1.1 acceptance path: arm the selftest flag, then force a hardware
/// `#DE` with an inline `idiv` by zero (Rust's `/` raises a *software*
/// panic before the CPU ever faults, so the asm is the only honest way to
/// exercise the entry path). The dispatch prints the diagnosis and the
/// marker line, then powers QEMU off cleanly.
pub fn arm_and_trigger_de() -> ! {
    SELFTEST_ARMED.store(true, Ordering::SeqCst);
    // SAFETY: deliberately raises #DE; the IDT armed by arch::init routes
    // it to the dispatch above. If the machinery is broken, the CPU
    // triple-faults, QEMU (-no-reboot) exits early, and the boot test
    // fails on the missing marker — the failure is loud either way.
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
    hw::halt_forever()
}
