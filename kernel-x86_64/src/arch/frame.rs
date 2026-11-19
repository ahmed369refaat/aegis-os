//! The uniform exception frame and vector mnemonics (pure, host-tested).
//!
//! Invariant: every exception stub in [`super::stubs`] leaves the stack in
//! exactly this shape before `exception_common` pushes the GPRs, so the
//! Rust dispatch can read any fault uniformly. Vectors 8/10-14/17/21 push
//! a real CPU error code; all others push a stub zero.

/// Layout (lowest address first; matches the push order in `stubs.rs`).
///
/// The struct describes the CPL0 shape. For faults **from** ring-3 the
/// CPU pushes two extra words above `rflags` (the user `rsp`/`ss`), so a
/// CPL3 frame is this struct plus a 16-byte tail — physically present,
/// consumed automatically by the unwind's `iretq` (RPL-driven), and read
/// only by the user-fault branch via `exceptions::user_rsp/user_ss`.
/// That is why the struct gains no fields: one shape, two tail modes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// Vector number, pushed by the stub (0..=31 for CPU exceptions).
    pub vector: u64,
    /// CPU error code, or the stub's zero for no-error vectors.
    pub error_code: u64,
    /// Faulting instruction pointer (CPU-pushed).
    pub rip: u64,
    /// Code segment selector (CPU-pushed).
    pub cs: u64,
    /// RFLAGS at the fault (CPU-pushed).
    pub rflags: u64,
}

/// Mnemonics for the 32 CPU exception vectors (Intel SDM table 6-1;
/// 19 and 23..=28 have no assigned mnemonic — reported as reserved).
pub fn vector_name(vector: u8) -> &'static str {
    match vector {
        0 => "#DE",
        1 => "#DB",
        2 => "#NMI",
        3 => "#BP",
        4 => "#OF",
        5 => "#BR",
        6 => "#UD",
        7 => "#NM",
        8 => "#DF",
        9 => "#CSO",
        10 => "#TS",
        11 => "#NP",
        12 => "#SS",
        13 => "#GP",
        14 => "#PF",
        15 => "#MF",
        16 => "#XM",
        17 => "#AC",
        18 => "#MC",
        20 => "#VE",
        21 => "#CP",
        _ => "#RSV",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn frame_layout_matches_the_push_order() {
        // 15 GPRs first: r15 is the last push, so it sits lowest.
        assert_eq!(offset_of!(ExceptionFrame, r15), 0);
        assert_eq!(offset_of!(ExceptionFrame, rax), 14 * 8);
        assert_eq!(offset_of!(ExceptionFrame, vector), 15 * 8);
        assert_eq!(offset_of!(ExceptionFrame, error_code), 16 * 8);
        assert_eq!(offset_of!(ExceptionFrame, rip), 17 * 8);
        assert_eq!(offset_of!(ExceptionFrame, cs), 18 * 8);
        assert_eq!(offset_of!(ExceptionFrame, rflags), 19 * 8);
        assert_eq!(size_of::<ExceptionFrame>(), 20 * 8);
    }

    #[test]
    fn vector_names_are_the_sdm_mnemonics() {
        assert_eq!(vector_name(0), "#DE");
        assert_eq!(vector_name(8), "#DF");
        assert_eq!(vector_name(13), "#GP");
        assert_eq!(vector_name(14), "#PF");
        assert_eq!(vector_name(16), "#XM");
        assert_eq!(vector_name(20), "#VE");
        assert_eq!(vector_name(21), "#CP");
        // Unassigned/reserved vectors report as reserved, never garbage.
        assert_eq!(vector_name(19), "#RSV");
        assert_eq!(vector_name(25), "#RSV");
        assert_eq!(vector_name(31), "#RSV");
        assert_eq!(vector_name(200), "#RSV");
    }
}
