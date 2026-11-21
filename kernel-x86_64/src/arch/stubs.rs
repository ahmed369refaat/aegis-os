//! Naked entry stubs for the 32 CPU exception vectors (target-only).
//!
//! SAFETY POLICY: allowlisted module (`docs/adr/0005`): naked functions
//! whose bodies are raw assembly. They must never be called from Rust —
//! only the IDT points at them.
//!
//! Contract: each stub normalizes the stack to the uniform
//! [`super::frame::ExceptionFrame`] shape (vectors with a CPU error code
//! push only the vector number; the others push a zero error code first),
//! then tail-jumps to `exception_common`.

#![allow(unsafe_code)]

use core::arch::naked_asm;

/// Which vectors take an IST stack (index into TSS.ist). PR-1.4: #PF
/// moves to IST5 — the inter-privilege RSP0 delivery path proved
/// unreliable in this environment while IST delivery from CPL3 is
/// proven working (see `docs/arch/syscall-entry.md`).
const fn ist_for(vector: u8) -> u8 {
    match vector {
        8 => 1,  // #DF: the current stack may be the thing that is broken
        2 => 2,  // #NMI: can interrupt any context, including other ISTs
        18 => 3, // #MC: most severe, its own stack
        12 => 4, // #SS: a stack fault cannot trust that stack
        14 => 5, // #PF: own stack since PR-1.4 (was: none)
        _ => 0,
    }
}

macro_rules! vector_stub {
    ($name:ident, $vector:expr, err) => {
        #[unsafe(no_mangle)] #[unsafe(naked)]
        pub extern "C" fn $name() {
            // The CPU already pushed the error code; add the vector.
            // (`$` is literal in the template; the const operand itself
            // does not get an AT&T prefix, hence the explicit `${v}`.)
            naked_asm!(
                "pushq ${v}",
                "jmp {c}",
                v = const $vector,
                c = sym exception_common,
                options(att_syntax),
            );
        }
    };
    ($name:ident, $vector:expr, noerr) => {
        #[unsafe(no_mangle)] #[unsafe(naked)]
        pub extern "C" fn $name() {
            // No CPU error code: push a zero so every frame is uniform.
            naked_asm!(
                "pushq $0",
                "pushq ${v}",
                "jmp {c}",
                v = const $vector,
                c = sym exception_common,
                options(att_syntax),
            );
        }
    };
}

// 32..=47: the legacy 8259 pair's range. No handler is armed yet (the
// timer arrives with preemption) — these land in the dispatch's
// unexpected-IRQ halt, a NAMED death instead of a #DF with a shifted
// frame. No CPU error code on any of them.
vector_stub!(irq32, 32, noerr);
vector_stub!(irq33, 33, noerr);
vector_stub!(irq34, 34, noerr);
vector_stub!(irq35, 35, noerr);
vector_stub!(irq36, 36, noerr);
vector_stub!(irq37, 37, noerr);
vector_stub!(irq38, 38, noerr);
vector_stub!(irq39, 39, noerr);
vector_stub!(irq40, 40, noerr);
vector_stub!(irq41, 41, noerr);
vector_stub!(irq42, 42, noerr);
vector_stub!(irq43, 43, noerr);
vector_stub!(irq44, 44, noerr);
vector_stub!(irq45, 45, noerr);
vector_stub!(irq46, 46, noerr);
vector_stub!(irq47, 47, noerr);
// 48: the LAPIC timer (ADR-0012) — the preemption entry. No CPU error
// code; the dispatch routes it to the tick before anything else.
vector_stub!(irq48, 48, noerr);
// 49..=112: broker-owned device vectors (ADR-0019). No CPU error code. These land in the dispatch's broker route
// (ADR-0019): an owned vector delivers to its device's mailbox, an
// unowned one is a NAMED halt — the ADR-0010 discipline extended
// from the legacy 8259 range to the device range.
vector_stub!(irq49, 49, noerr);
vector_stub!(irq50, 50, noerr);
vector_stub!(irq51, 51, noerr);
vector_stub!(irq52, 52, noerr);
vector_stub!(irq53, 53, noerr);
vector_stub!(irq54, 54, noerr);
vector_stub!(irq55, 55, noerr);
vector_stub!(irq56, 56, noerr);
vector_stub!(irq57, 57, noerr);
vector_stub!(irq58, 58, noerr);
vector_stub!(irq59, 59, noerr);
vector_stub!(irq60, 60, noerr);
vector_stub!(irq61, 61, noerr);
vector_stub!(irq62, 62, noerr);
vector_stub!(irq63, 63, noerr);
vector_stub!(irq64, 64, noerr);
vector_stub!(irq65, 65, noerr);
vector_stub!(irq66, 66, noerr);
vector_stub!(irq67, 67, noerr);
vector_stub!(irq68, 68, noerr);
vector_stub!(irq69, 69, noerr);
vector_stub!(irq70, 70, noerr);
vector_stub!(irq71, 71, noerr);
vector_stub!(irq72, 72, noerr);
vector_stub!(irq73, 73, noerr);
vector_stub!(irq74, 74, noerr);
vector_stub!(irq75, 75, noerr);
vector_stub!(irq76, 76, noerr);
vector_stub!(irq77, 77, noerr);
vector_stub!(irq78, 78, noerr);
vector_stub!(irq79, 79, noerr);
vector_stub!(irq80, 80, noerr);
vector_stub!(irq81, 81, noerr);
vector_stub!(irq82, 82, noerr);
vector_stub!(irq83, 83, noerr);
vector_stub!(irq84, 84, noerr);
vector_stub!(irq85, 85, noerr);
vector_stub!(irq86, 86, noerr);
vector_stub!(irq87, 87, noerr);
vector_stub!(irq88, 88, noerr);
vector_stub!(irq89, 89, noerr);
vector_stub!(irq90, 90, noerr);
vector_stub!(irq91, 91, noerr);
vector_stub!(irq92, 92, noerr);
vector_stub!(irq93, 93, noerr);
vector_stub!(irq94, 94, noerr);
vector_stub!(irq95, 95, noerr);
vector_stub!(irq96, 96, noerr);
vector_stub!(irq97, 97, noerr);
vector_stub!(irq98, 98, noerr);
vector_stub!(irq99, 99, noerr);
vector_stub!(irq100, 100, noerr);
vector_stub!(irq101, 101, noerr);
vector_stub!(irq102, 102, noerr);
vector_stub!(irq103, 103, noerr);
vector_stub!(irq104, 104, noerr);
vector_stub!(irq105, 105, noerr);
vector_stub!(irq106, 106, noerr);
vector_stub!(irq107, 107, noerr);
vector_stub!(irq108, 108, noerr);
vector_stub!(irq109, 109, noerr);
vector_stub!(irq110, 110, noerr);
vector_stub!(irq111, 111, noerr);
vector_stub!(irq112, 112, noerr);
// 255: the LAPIC spurious vector (from SVR). Wired so a spurious
// delivery is a named no-op in the dispatch instead of an absent-gate
// #GP — the ADR-0010 lesson (absent gates turn surprises into
// frame-shifted #DFs) applied to the first interrupt source.
vector_stub!(v255, 255, noerr);

// 0..=31, with error-code vectors marked (8, 10-14, 17, 21).
vector_stub!(v00, 0, noerr);
vector_stub!(v01, 1, noerr);
vector_stub!(v02, 2, noerr);
vector_stub!(v03, 3, noerr);
vector_stub!(v04, 4, noerr);
vector_stub!(v05, 5, noerr);
vector_stub!(v06, 6, noerr);
vector_stub!(v07, 7, noerr);
vector_stub!(v08, 8, err);
vector_stub!(v09, 9, noerr);
vector_stub!(v10, 10, err);
vector_stub!(v11, 11, err);
vector_stub!(v12, 12, err);
vector_stub!(v13, 13, err);
vector_stub!(v14, 14, err);
vector_stub!(v15, 15, noerr);
vector_stub!(v16, 16, noerr);
vector_stub!(v17, 17, err);
vector_stub!(v18, 18, noerr);
vector_stub!(v19, 19, noerr);
vector_stub!(v20, 20, noerr);
vector_stub!(v21, 21, err);
vector_stub!(v22, 22, noerr);
vector_stub!(v23, 23, noerr);
vector_stub!(v24, 24, noerr);
vector_stub!(v25, 25, noerr);
vector_stub!(v26, 26, noerr);
vector_stub!(v27, 27, noerr);
vector_stub!(v28, 28, noerr);
vector_stub!(v29, 29, noerr);
vector_stub!(v30, 30, noerr);
vector_stub!(v31, 31, noerr);

/// Common entry: push the GPRs (frame order r15..rax), align the stack,
/// call the Rust dispatch, and keep a correct unwind for the day the
/// dispatch starts returning (Ring-3 fault delivery).
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn exception_common() {
    naked_asm!(
        "pushq %rax",
        "pushq %rbx",
        "pushq %rcx",
        "pushq %rdx",
        "pushq %rsi",
        "pushq %rdi",
        "pushq %rbp",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "movq %rsp, %rdi", // frame pointer (SysV first arg)
        "movq %rsp, %rbx", // original rsp; rbx's live copy is in the frame
        "andq $-16, %rsp", // SysV: rsp must be 16-aligned at call
        "call aegis_exception_dispatch",
        "movq %rbx, %rsp", // unwind: reached only if dispatch returns
        "popq %r15",
        "popq %r14",
        "popq %r13",
        "popq %r12",
        "popq %r11",
        "popq %r10",
        "popq %r9",
        "popq %r8",
        "popq %rbp",
        "popq %rdi",
        "popq %rsi",
        "popq %rdx",
        "popq %rcx",
        "popq %rbx",
        "popq %rax",
        "addq $16, %rsp", // drop vector + error code
        "iretq",
        options(att_syntax),
    );
}

/// The broker-owned device-vector stubs (49..=112, ADR-0019) in
/// vector order — the IDT wiring and the broker's slot arithmetic
/// both index this table.
const DEVICE_STUBS: [extern "C" fn(); 64] = [
    irq49, irq50, irq51, irq52,
    irq53, irq54, irq55, irq56,
    irq57, irq58, irq59, irq60,
    irq61, irq62, irq63, irq64,
    irq65, irq66, irq67, irq68,
    irq69, irq70, irq71, irq72,
    irq73, irq74, irq75, irq76,
    irq77, irq78, irq79, irq80,
    irq81, irq82, irq83, irq84,
    irq85, irq86, irq87, irq88,
    irq89, irq90, irq91, irq92,
    irq93, irq94, irq95, irq96,
    irq97, irq98, irq99, irq100,
    irq101, irq102, irq103, irq104,
    irq105, irq106, irq107, irq108,
    irq109, irq110, irq111, irq112,
];

/// The registry the IDT is filled from: (stub address, IST index) for
/// a wired vector. Valid for the exceptions (0..=31), the legacy IRQ
/// catch-alls (32..=47), the LAPIC timer (48), the broker-owned
/// device vectors (49..=112) and the LAPIC spurious vector (255) —
/// see `idt::load` for the wiring policy.
pub fn vector_handler(vector: u8) -> (u64, u8) {
    let stub: extern "C" fn() = match vector {
        0 => v00,
        1 => v01,
        2 => v02,
        3 => v03,
        4 => v04,
        5 => v05,
        6 => v06,
        7 => v07,
        8 => v08,
        9 => v09,
        10 => v10,
        11 => v11,
        12 => v12,
        13 => v13,
        14 => v14,
        15 => v15,
        16 => v16,
        17 => v17,
        18 => v18,
        19 => v19,
        20 => v20,
        21 => v21,
        22 => v22,
        23 => v23,
        24 => v24,
        25 => v25,
        26 => v26,
        27 => v27,
        28 => v28,
        29 => v29,
        30 => v30,
        31 => v31,
        32 => irq32,
        33 => irq33,
        34 => irq34,
        35 => irq35,
        36 => irq36,
        37 => irq37,
        38 => irq38,
        39 => irq39,
        40 => irq40,
        41 => irq41,
        42 => irq42,
        43 => irq43,
        44 => irq44,
        45 => irq45,
        46 => irq46,
        47 => irq47,
        48 => irq48,
        // 49..=112: the broker-owned device vectors (ADR-0019).
        49..=112 => DEVICE_STUBS[(vector - 49) as usize],
        255 => v255,
        _ => panic!("vector_handler: not a wired vector (0..=48, 255)"),
    };
    (stub as usize as u64, ist_for(vector))
}
