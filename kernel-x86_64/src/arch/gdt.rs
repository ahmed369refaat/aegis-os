//! GDT + TSS: descriptor encoding (pure, host-tested) and the one-time
//! kernel-table load (target-only).
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (with `boot`,
//! `hw`, `memops` and the rest of `arch`; see `docs/adr/0005`). The only
//! unsafe here is the `lgdt`/`ltr` pair and the single write of the
//! `.bss`-resident tables before that, at single-CPU bring-up.

#![allow(unsafe_code)]

/// Selector values (byte offsets into the GDT). **The kernel slots
/// mirror the boot stub's layout** (`boot-x86_64/stub.S`): the stub
/// enters the kernel with CS=0x18 / DS=SS=0x10, so the kernel GDT must
/// keep those slots meaning the same thing or the segment registers
/// would describe the wrong descriptors after `lgdt`.
///
/// Everything above 0x20 is ours to place, and PR-1.4 places it by the
/// SYSCALL/SYSRET slot arithmetic (pinned by a host test below):
/// - SYSCALL loads CS ← STAR[47:32] and SS ← STAR[47:32]+8, so the
///   kernel needs a code→data pair at [0x30, 0x38] (the stub's own
///   kernel pair is data-before-code and cannot serve).
/// - SYSRET loads CS ← STAR[63:48]+16 and SS ← STAR[63:48]+8 (RPL 3),
///   so user data must sit at 0x20 and user code at 0x28 (data before
///   code).
pub const CODE32: u16 = 0x08; // stub's 32-bit code, kept for the contract
pub const KERNEL_DATA: u16 = 0x10;
pub const KERNEL_CODE: u16 = 0x18; // 64-bit kernel code (stub's entry CS)
/// User data (DPL 3) — placed for SYSRET's SS = base+8 arithmetic.
pub const USER_DATA: u16 = 0x20;
/// User code (DPL 3, L=1) — placed for SYSRET's CS = base+16 arithmetic.
pub const USER_CODE: u16 = 0x28;
/// Kernel code duplicate the SYSCALL instruction enters on (STAR[47:32]).
pub const SYSCALL_CODE: u16 = 0x30;
/// Kernel data duplicate SYSCALL enters with (SS = STAR[47:32]+8).
pub const SYSCALL_DATA: u16 = 0x38;
pub const TSS_SEL: u16 = 0x40;

/// Encode a segment descriptor (64-bit layout: limit 0..15, base 0..23,
/// access, limit 16..19, flags G/D/L/AVL, base 24..31).
pub const fn segment(base: u64, limit: u32, access: u8, flags: u8) -> u64 {
    let l = limit as u64;
    let b = base & 0xFF_FFFF;
    (l & 0xFFFF)
        | (b << 16)
        | ((access as u64) << 40)
        | (((l >> 16) & 0xF) << 48)
        | (((flags as u64) & 0xF) << 52)
        | (((base >> 24) & 0xFF) << 56)
}

/// Encode the 16-byte (two-slot) TSS descriptor for long mode.
/// Access `0x89` = present, DPL 0, system, available-TSS.
pub const fn tss_descriptor(base: u64, limit: u32) -> [u64; 2] {
    [segment(base, limit, 0x89, 0x0), (base >> 32) as u64]
}

/// The 64-bit task state segment (SDM vol. 3, §7.7).
///
/// `packed(4)`: the hardware layout is *not* u64-aligned (RSP0 sits at
/// byte 4), so plain `repr(C)` would insert padding and desynchronize the
/// whole table.
#[repr(C, packed(4))]
pub struct Tss {
    _reserved0: u32,
    /// RSP0/1/2: stacks switched to on privilege changes into ring 0/1/2.
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// IST1..IST7: unconditional stack switches for their vectors.
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// IOPB offset: `>= sizeof(Tss)` means "no port permissions granted".
    pub iopb_offset: u16,
}

impl Tss {
    pub const fn zeroed() -> Self {
        Tss {
            _reserved0: 0,
            rsp: [0; 3],
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iopb_offset: core::mem::size_of::<Tss>() as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_segment_has_l_set_and_d_clear() {
        // flags 0xA = G(bit55)=1, D(bit54)=0, L(bit53)=1, AVL(bit52)=0.
        let d = segment(0, 0xFFFFF, 0x9A, 0xA);
        assert_eq!((d >> 47) & 1, 1, "present");
        assert_eq!((d >> 44) & 1, 1, "S=1 (code/data)");
        assert_eq!((d >> 43) & 1, 1, "type: executable");
        assert_eq!((d >> 45) & 0b11, 0, "DPL0");
        assert_eq!((d >> 53) & 1, 1, "L=1 (64-bit)");
        assert_eq!((d >> 54) & 1, 0, "D=0 in long mode");
        assert_eq!((d >> 55) & 1, 1, "G=1");
    }

    #[test]
    fn user_segments_carry_dpl3() {
        let c = segment(0, 0xFFFFF, 0xFA, 0xA);
        let d = segment(0, 0xFFFFF, 0xF2, 0xC);
        assert_eq!((c >> 45) & 0b11, 0b11);
        assert_eq!((d >> 45) & 0b11, 0b11);
        assert_eq!((c >> 43) & 1, 1, "user code is executable");
        assert_eq!((d >> 41) & 1, 1, "user data is writable (type W bit)");
        assert_eq!((d >> 43) & 1, 0, "user data is not executable");
    }

    #[test]
    fn tss_descriptor_splits_base_and_is_a_system_descriptor() {
        let base = 0x0000_0000_0200_0000u64;
        let [lo, hi] = tss_descriptor(base, 103);
        assert_eq!((lo >> 40) & 0xFF, 0x89, "present system available-TSS");
        assert_eq!((lo >> 44) & 1, 0, "S=0 (system)");
        assert_eq!(lo & 0xFFFF, 103, "limit low");
        assert_eq!(hi, base >> 32, "base[63:32]");
        // base[23:0] and base[31:24] round-trip through the low word.
        assert_eq!(((lo >> 16) & 0xFF_FFFF) | (((lo >> 56) & 0xFF) << 24), base & 0xFFFF_FFFF);
    }

    #[test]
    fn kernel_descriptors_match_the_boot_stub_literals() {
        // Boot ABI contract (boot-x86_64/stub.S): the stub enters the
        // kernel through these exact descriptors, and the kernel GDT must
        // reproduce them so the live segment registers stay valid.
        assert_eq!(segment(0, 0xFFFFF, 0x9A, 0xC), 0x00CF9A00_0000_FFFF); // 32-bit code
        assert_eq!(segment(0, 0xFFFFF, 0x92, 0xC), 0x00CF9200_0000_FFFF); // data
        assert_eq!(segment(0, 0xFFFFF, 0x9A, 0xA), 0x00AF9A00_0000_FFFF); // 64-bit code
        // Selector layout contract: CS at entry = 0x18, data = 0x10.
        assert_eq!(KERNEL_CODE, 0x18);
        assert_eq!(KERNEL_DATA, 0x10);
        assert_eq!(TSS_SEL, 0x40);
    }

    #[test]
    fn syscall_sysret_slot_arithmetic_is_exact() {
        // The PR-1.4 contract, in one place: given STAR's halves, the CPU
        // computes SYSCALL CS/SS and SYSRET CS/SS by pure addition. Every
        // slot these sums name must exist and mean the right thing.
        let star_cs = SYSCALL_CODE; // STAR[47:32]
        let star_user_base: u16 = 0x18; // STAR[63:48] (== KERNEL_CODE's slot)

        // SYSCALL entry: CS = STAR[47:32], SS = +8 — both must be DPL0.
        assert_eq!(star_cs, 0x30);
        assert_eq!(star_cs + 8, SYSCALL_DATA);
        let c = segment(0, 0xFFFFF, 0x9A, 0xA); // encoding used at 0x30
        let d = segment(0, 0xFFFFF, 0x92, 0xC); // encoding used at 0x38
        assert_eq!((c >> 45) & 0b11, 0, "syscall CS slot is DPL0");
        assert_eq!((c >> 53) & 1, 1, "syscall CS slot is 64-bit (L=1)");
        assert_eq!((d >> 45) & 0b11, 0, "syscall SS slot is DPL0");

        // SYSRET exit: CS = base+16, SS = base+8 — both must be DPL3 and
        // the code slot must be the 64-bit one.
        assert_eq!(star_user_base + 16, USER_CODE);
        assert_eq!(star_user_base + 8, USER_DATA);
        let uc = segment(0, 0xFFFFF, 0xFA, 0xA); // encoding used at 0x28
        let ud = segment(0, 0xFFFFF, 0xF2, 0xC); // encoding used at 0x20
        assert_eq!((uc >> 45) & 0b11, 0b11, "user code is DPL3");
        assert_eq!((uc >> 53) & 1, 1, "user code is 64-bit (L=1)");
        assert_eq!((uc >> 43) & 1, 1, "user code is executable");
        assert_eq!((ud >> 45) & 0b11, 0b11, "user data is DPL3");
        assert_eq!((ud >> 43) & 1, 0, "user data is not executable");

        // No overlaps: all seven used slots are distinct.
        let slots = [KERNEL_CODE, KERNEL_DATA, USER_CODE, USER_DATA, SYSCALL_CODE, SYSCALL_DATA, TSS_SEL];
        for i in 0..slots.len() {
            for j in i + 1..slots.len() {
                assert_ne!(slots[i], slots[j], "selector overlap at {:#x}", slots[i]);
            }
        }
    }

    #[test]
    fn tss_layout_matches_the_architecture_fixed_offsets() {
        use core::mem::{offset_of, size_of};
        assert_eq!(offset_of!(Tss, rsp), 4, "RSP0 at byte 4");
        assert_eq!(offset_of!(Tss, ist), 36, "IST1 at byte 36");
        assert_eq!(offset_of!(Tss, iopb_offset), 102);
        assert_eq!(size_of::<Tss>(), 104);
        // IOPB past the struct end: no I/O permissions granted to anyone.
        assert!(Tss::zeroed().iopb_offset as usize >= size_of::<Tss>());
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only load path (needs the IST stacks from `exceptions`).
// ─────────────────────────────────────────────────────────────────────────
#[cfg(not(test))]
mod load {
    use super::{segment, tss_descriptor, Tss, KERNEL_DATA, TSS_SEL};
    use core::arch::asm;

    // Linker-provided top of the boot kernel stack (linker.ld `stack_top`).
    extern "C" {
        static stack_top: u8;
    }

    #[repr(C, packed)]
    struct PseudoDescriptor {
        limit: u16,
        base: u64,
    }

    struct Gdt {
        entries: [u64; 10],
    }

    static mut GDT: Gdt = Gdt { entries: [0; 10] };
    static mut TSS: Tss = Tss::zeroed();
    static mut GDTR: PseudoDescriptor = PseudoDescriptor { limit: 0, base: 0 };

    /// Fill the GDT/TSS, load them, and set TR. Called exactly once from
    /// `arch::init()` before anything can fault.
    pub fn load() {
        // SAFETY: single-CPU bring-up: the statics are written exactly once
        // here, before lgdt/ltr make them visible to the CPU, and are never
        // written again (read-only by hardware afterwards).
        unsafe {
            let g = &raw mut GDT;
            let t = &raw mut TSS;
            let gdtr = &raw mut GDTR;

            (*g).entries[0] = 0; // required null descriptor
            (*g).entries[1] = segment(0, 0xFFFFF, 0x9A, 0xC); // 32-bit code (stub contract)
            (*g).entries[2] = segment(0, 0xFFFFF, 0x92, 0xC); // kernel data
            (*g).entries[3] = segment(0, 0xFFFFF, 0x9A, 0xA); // 64-bit kernel code
            (*g).entries[4] = segment(0, 0xFFFFF, 0xF2, 0xC); // user data  @0x20 (SYSRET SS)
            (*g).entries[5] = segment(0, 0xFFFFF, 0xFA, 0xA); // user code  @0x28 (SYSRET CS)
            (*g).entries[6] = segment(0, 0xFFFFF, 0x9A, 0xA); // SYSCALL CS @0x30
            (*g).entries[7] = segment(0, 0xFFFFF, 0x92, 0xC); // SYSCALL SS @0x38
            let tss_base = t as u64;
            let [lo, hi] = tss_descriptor(tss_base, core::mem::size_of::<Tss>() as u32 - 1);
            (*g).entries[8] = lo;
            (*g).entries[9] = hi;

            // RSP0: initial value is the boot stack top; `set_rsp0` moves
            // it to a dedicated guarded stack once the frame pool exists
            // (PR-1.4: exceptions from ring-3 land here — the boot stack
            // would clobber kmain's frame). IST1..IST4: exception stacks.
            (*t).rsp[0] = core::ptr::addr_of!(stack_top) as u64;
            let tops = crate::arch::exceptions::ist_tops();
            (*t).ist[0] = tops[0]; // #DF
            (*t).ist[1] = tops[1]; // #NMI
            (*t).ist[2] = tops[2]; // #MC
            (*t).ist[3] = tops[3]; // #SS
            (*t).ist[4] = tops[4]; // #PF (PR-1.4)

            (*gdtr).limit = (8 * 10 - 1) as u16;
            (*gdtr).base = g as u64;
            asm!("lgdt (%rax)", in("rax") gdtr, options(att_syntax, nostack, preserves_flags));
            // Reload the data segments; CS stays valid untouched: the
            // stub entered on 0x18 and slot 3 is still kernel code.
            asm!(
                "movw %ax, %ds\n\tmovw %ax, %es\n\tmovw %ax, %ss",
                in("ax") KERNEL_DATA,
                options(att_syntax, nostack, preserves_flags),
            );
            asm!("ltr %ax", in("ax") TSS_SEL, options(att_syntax, nostack, preserves_flags));
        }
    }

    /// Read back TSS.RSP0 (diagnostics: the ring-3 launch path proves
    /// the exception entry stack is the guarded one before launching).
    pub fn rsp0() -> u64 {
        // SAFETY: single CPU; a plain read of a value only the CPU and
        // `set_rsp0` touch.
        unsafe { (*core::ptr::addr_of!(TSS)).rsp[0] }
    }

    /// Point RSP0 (the CPL3→CPL0 exception stack) at a dedicated guarded
    /// stack. Called from `kmain` after the frame pool exists; the boot
    /// stack value from `load()` was only a bring-up placeholder.
    pub fn set_rsp0(top: u64) {
        // SAFETY: single CPU; the TSS is written before any ring-3
        // context exists (kmain sets this up before the first launch),
        // and the CPU only ever reads RSP0 on a privilege change.
        unsafe {
            (*core::ptr::addr_of_mut!(TSS)).rsp[0] = top;
        }
    }
}

#[cfg(not(test))]
pub use load::{load, rsp0, set_rsp0};
