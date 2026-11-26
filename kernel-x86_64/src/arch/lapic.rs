//! The local APIC timer (M2-W2 / ADR-0012): the first interrupt source
//! in the system, and the only thing that may preempt a running ring-3
//! domain.
//!
//! Design, in one breath: map the LAPIC's MMIO window into the direct
//! map (one extra 1 GiB page-directory entry — every domain inherits
//! it through `install_kernel_entries`, ADR-0002), enable the APIC with
//! a spurious vector that has a wired (no-op) gate, and program the
//! timer in **TSC-deadline mode** when the CPU offers it (the deadline
//! is a plain TSC value — the same clock the monitor windows and the
//! whole boot already use, so tick cadence is deterministic relative to
//! every other measurement in the system), falling back to classic
//! periodic mode otherwise. Each tick ends with an EOI; the deadline is
//! re-armed inside the handler.
//!
//! This module is **unsafe-free by design**: all raw access goes
//! through `memops` (the allowlisted physical-access layer) and the
//! `hw` MSR wrappers. The register map and every encoding are pure and
//! host-tested; only `init`/`arm`/`eoi` touch the device.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only users (driver steps and their helpers), so items only
// they use look dead there — they are used by the boot build.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables, unused_mut))]

#[cfg(not(test))]
use crate::hw;
#[cfg(not(test))]
use crate::memops;
use crate::mm::pte;

/// IA32_APIC_BASE MSR: the MMIO base and the enable/BSP bits.
const MSR_IA32_APIC_BASE: u32 = 0x1B;
/// IA32_TSC_DEADLINE MSR (TSC-deadline mode only): the absolute TSC
/// value at which the next timer interrupt fires.
const MSR_IA32_TSC_DEADLINE: u32 = 0x6E0;
/// Bit 11 of IA32_APIC_BASE: the local APIC is globally enabled.
const APIC_BASE_ENABLE: u64 = 1 << 11;

/// The MMIO base every PC machine uses unless firmware relocates it
/// (we read the MSR and assert it agrees — fail-loud, not guess).
pub const DEFAULT_MMIO_BASE: u64 = 0xFEE0_0000;

// ── register offsets from the MMIO base (Intel SDM vol. 3 §10.4.1) ──
pub const REG_ID: u64 = 0x020;
pub const REG_VERSION: u64 = 0x030;
pub const REG_TPR: u64 = 0x080;
/// End-of-interrupt: a zero write acknowledges the in-service vector.
pub const REG_EOI: u64 = 0x0B0;
pub const REG_SVR: u64 = 0x0F0;
pub const REG_LVT_ERROR: u64 = 0x370;
pub const REG_LVT_LINT0: u64 = 0x350;
pub const REG_LVT_LINT1: u64 = 0x360;
pub const REG_LVT_TIMER: u64 = 0x320;
pub const REG_TIMER_DIVIDE: u64 = 0x3E0;
pub const REG_TIMER_INIT_COUNT: u64 = 0x380;
pub const REG_TIMER_CURRENT_COUNT: u64 = 0x390;

/// The timer's vector: 0x30 (48) — above the legacy 8259 range the IDT
/// already gates as catch-alls (ADR-0010), below anything exotic.
pub const TIMER_VECTOR: u8 = 48;
/// The spurious-interrupt vector from SVR. Must have a wired IDT gate
/// (the LAPIC *can* deliver it); the dispatch treats it as a no-op —
/// notably WITHOUT an EOI, per the SDM.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// SVR: APIC software-enable (bit 8) + the spurious vector number.
pub const fn svr_value() -> u32 {
    (SPURIOUS_VECTOR as u32) | SVR_ENABLE
}
/// SVR bit 8: software enable.
pub const SVR_ENABLE: u32 = 1 << 8;

// ── x2APIC (ADR-0019) ──────────────────────────────────────────────────
// CPUID.01H:ECX bit 21 offers the MSR-mapped APIC ("x2APIC"). When
// present we switch (IA32_APIC_BASE bit 10) and every register
// access — including the EOI — routes through MSR 0x800+off instead
// of the MMIO window. The register FILE offsets (ID 0x02, VER 0x03,
// ..., DIVIDE 0x3E) map straight onto 0x800+off; the one merge is
// ICR (xAPIC's 0x300/0x310 pair becomes the single 64-bit 0x830 —
// unused until SMP's IPIs).

/// IA32_APIC_BASE bit 10: x2APIC enable (only settable alongside bit
/// 11; not clearable once set without disabling the APIC entirely).
pub const APIC_BASE_X2APIC: u64 = 1 << 10;
/// The x2APIC MSR file base: register `off` → MSR 0x800 + off.
pub const MSR_X2APIC_BASE: u32 = 0x800;
/// CPUID.01H:ECX bit 21: the CPU offers x2APIC.
pub const CPUID_ECX_X2APIC: u64 = 1 << 21;

/// The x2APIC EOI MSR (0x80B).
pub const MSR_X2APIC_EOI: u32 = 0x80B;

/// Mode: set once at `init` (before any interrupt can fire — IF=0 at
/// bring-up), read by every accessor. Static atomic, no unsafe.
static X2APIC: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Is the APIC in x2APIC mode? (False = classic xAPIC MMIO.)
#[must_use]
pub fn x2apic_active() -> bool {
    X2APIC.load(core::sync::atomic::Ordering::SeqCst)
}

/// The x2APIC MSR index for a register-file offset (pure — host
/// tests pin the mapping, including the EOI and the LVT timer). The
/// xAPIC MMIO offsets are 16-byte spaced (0x020, 0x030, 0x0B0, ...);
/// the x2APIC MSRs are PACKED — the mapping is 0x800 + (off >> 4):
/// ID 0x020→0x802, VER 0x030→0x803, EOI 0x0B0→0x80B, SVR 0x0F0→0x80F,
/// LVT-timer 0x320→0x832, and ICR's 0x300/0x310 pair merges into the
/// single 64-bit 0x830.
#[must_use]
pub const fn x2apic_msr(off: u64) -> u32 {
    MSR_X2APIC_BASE + (off >> 4) as u32
}

/// LVT timer encodings. The mask bit (16) must stay CLEAR for the
/// timer to fire; the mode field is bits 18:17.
pub const LVT_MASKED: u32 = 1 << 16;
const LVT_MODE_SHIFT: u32 = 17;
/// Mode 0b00: one-shot (INIT_COUNT counts down once).
pub const LVT_MODE_ONESHOT: u32 = 0 << LVT_MODE_SHIFT;
/// Mode 0b01: periodic (INIT_COUNT auto-reloads).
pub const LVT_MODE_PERIODIC: u32 = 1 << LVT_MODE_SHIFT;
/// Mode 0b10: TSC-deadline (the MSR holds the absolute TSC deadline).
pub const LVT_MODE_TSC_DEADLINE: u32 = 2 << LVT_MODE_SHIFT;

/// Divide-config value for divide-by-16 (0b0011, SDM table 10-5).
pub const DIVIDE_BY_16: u32 = 0x3;

/// The periodic-mode fallback initial count. LAPIC bus frequency is
/// machine-dependent (QEMU TCG derives it from the virtual CPU clock),
/// so periodic mode is honest about being approximate: only cadence —
/// never correctness — depends on it. Empirically on this TCG,
/// 12.5M counts ≈ 100M guest loop iterations; 500k keeps the demo's
/// slices a few million iterations apart (the writer's rounds span
/// several ticks while the spinner spans ~100).
pub const PERIODIC_FALLBACK_COUNT: u32 = 500_000;

/// PTE bits for the LAPIC window: present, writable, 1 GiB page size
/// (bit 7), global, no-execute — kernel-only MMIO, same discipline as
/// the direct map (ADR-0002: RW, never X).
/// F5/F12 (review round 4): is `[pa, pa+len)` inside the pre-mapped
/// MMIO window (the 4th GiB, PA 0xC000_0000..0x1_0000_0000)? Every
/// device- or firmware-named physical address is checked against this
/// BEFORE any memops access — a wrong address must refuse, not fault.
#[must_use]
pub fn mmio_in_window(pa: u64, len: u64) -> bool {
    const BASE: u64 = 0xC000_0000;
    const END: u64 = 0x1_0000_0000;
    pa >= BASE && pa.checked_add(len).is_some_and(|e| e <= END)
}

pub const WINDOW_PTE: u64 =
    0xC000_0000 | pte::PTE_P | pte::PTE_W | PTE_PS | pte::PTE_G | pte::PTE_NX;
/// Page-size bit 7: this PDPT entry maps a 1 GiB page (PA base
/// 0xC000_0000 — the fourth GiB, where the default LAPIC lives).
pub const PTE_PS: u64 = 1 << 7;

/// The virtual address of an LAPIC register (direct map + offset).
#[must_use]
pub fn reg(offset: u64) -> u64 {
    crate::mm::direct_map::pa_to_va(DEFAULT_MMIO_BASE) + offset
}

#[cfg(not(test))]
fn read32(offset: u64) -> u32 {
    // x2APIC: the same register file, one MSR read instead of an MMIO
    // window. memops takes the PHYSICAL address and translates
    // through the direct map (the window mapping is what makes this
    // PA reachable); 4-byte accesses: the xAPIC natural MMIO width.
    if x2apic_active() {
        hw::rdmsr(x2apic_msr(offset)) as u32
    } else {
        memops::read_u32(DEFAULT_MMIO_BASE + offset)
    }
}

#[cfg(not(test))]
fn write32(offset: u64, v: u32) {
    if x2apic_active() {
        hw::wrmsr(x2apic_msr(offset), u64::from(v));
    } else {
        memops::write_u32(DEFAULT_MMIO_BASE + offset, v);
    }
}

/// Map the LAPIC's MMIO window into the kernel's direct map: the
/// kernel's own PDPT (PML4[273]'s target) gains entry [3] — a 1 GiB
/// page covering PA 0xC000_0000..0x1_0000_0000, which contains the
/// default LAPIC base. Every per-domain table shares this PDPT through
/// `install_kernel_entries`, so the window is identical in all address
/// spaces. The entry was absent before (nothing cached a translation
/// through it); a CR3 reload makes even that explicit.
///
/// Returns the SVR-ready APIC version (a sanity read proving the window
/// works — the version register must not read as all-ones/all-zeros).
#[cfg(not(test))]
pub fn map_window() -> u32 {
    let pml4 = hw::read_cr3() & crate::mm::ADDR_MASK;
    let pdpt = memops::read_u64(pml4 + 273 * 8) & crate::mm::ADDR_MASK;
    memops::write_u64(pdpt + 3 * 8, WINDOW_PTE);
    // Same-value CR3 reload: flushes non-global translations (the
    // direct map is global, so it survives; the point is discipline,
    // not necessity — the entry was absent before).
    hw::write_cr3(pml4);
    read32(REG_VERSION)
}

/// Bring the LAPIC up: map the window, enable it (SVR), mask every LVT
/// line we do not use, and program the timer — TSC-deadline if the CPU
/// offers it, periodic otherwise. Returns `true` when TSC-deadline mode
/// is active (the caller reports it; both modes are fully supported).
#[cfg(not(test))]
pub fn init() -> bool {
    let version = map_window();
    // Fail loud on a dead window: the version register holds a version
    // number (QEMU: 0x14) and a max-LVT count in bits 23:16 — all-zero
    // or all-ones means the mapping did not land.
    if version == 0 || version == u32::MAX {
        let mut bv = [0u8; 18];
        crate::serial::write_str("[ARCH] lapic: version register reads dead (");
        crate::serial::write_str(crate::strutil::hex(version as u64, &mut bv));
        crate::serial::write_str(") — halting\n");
        hw::halt_forever();
    }

    // IA32_APIC_BASE: keep the firmware base (assert the default), set
    // the global-enable bit; x2APIC mode when the CPU offers it
    // (ADR-0019) — the register file stays, every access after this
    // point routes through MSR 0x800+off.
    let base = hw::rdmsr(MSR_IA32_APIC_BASE);
    if base & !0xFFF_u64 & !APIC_BASE_ENABLE != DEFAULT_MMIO_BASE {
        // A relocated APIC: the window mapping above used the default.
        // QEMU -machine pc never does this; refuse loudly rather than
        // talk to the wrong physical address.
        crate::serial::write_str("[ARCH] lapic: unexpected APIC base MSR — halting\n");
        hw::halt_forever();
    }
    let x2 = crate::arch::features::has_x2apic(hw::cpuid1_ecx());
    let enable = if x2 {
        hw::wrmsr(
            MSR_IA32_APIC_BASE,
            base | APIC_BASE_ENABLE | APIC_BASE_X2APIC,
        );
        X2APIC.store(true, core::sync::atomic::Ordering::SeqCst);
        base | APIC_BASE_ENABLE | APIC_BASE_X2APIC
    } else {
        hw::wrmsr(MSR_IA32_APIC_BASE, base | APIC_BASE_ENABLE);
        base | APIC_BASE_ENABLE
    };
    let _ = enable;

    // Task priority: accept everything (the IDT gates decide).
    write32(REG_TPR, 0);
    // Spurious vector + software enable.
    write32(REG_SVR, svr_value());
    // Mask the lines we never use (error, LINT0, LINT1): an unmasked
    // line with no device behind it is how stray IRQs are born
    // (ADR-0010's root cause 1, in Lapic form).
    write32(REG_LVT_ERROR, LVT_MASKED);
    write32(REG_LVT_LINT0, LVT_MASKED);
    write32(REG_LVT_LINT1, LVT_MASKED);

    let tsc_deadline = crate::arch::features::has_tsc_deadline(hw::cpuid1_ecx());
    if tsc_deadline {
        write32(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_MODE_TSC_DEADLINE);
    } else {
        write32(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_MODE_PERIODIC);
        write32(REG_TIMER_DIVIDE, DIVIDE_BY_16);
        write32(REG_TIMER_INIT_COUNT, PERIODIC_FALLBACK_COUNT);
    }
    tsc_deadline
}

/// Arm the next TSC-deadline tick (one-shot mode: every handler
/// re-arms). In periodic mode this is a no-op.
#[cfg(not(test))]
pub fn arm_deadline(deadline_tsc: u64) {
    hw::wrmsr(MSR_IA32_TSC_DEADLINE, deadline_tsc);
}

/// Acknowledge the current interrupt: without an EOI the LAPIC never
/// delivers the next one. Mode-aware: an MMIO write in xAPIC, the
/// 0x80B MSR in x2APIC (ADR-0019 — the broker's `deliver` calls this
/// FIRST, before any bookkeeping).
#[cfg(not(test))]
pub fn eoi() {
    write32(REG_EOI, 0);
}

/// Mask the timer's LVT entry (pause ticks) — used by ADR-0019's
/// bounded delivery window so a preempt tick cannot land mid-window
/// in CPL0 (the tick path models CPL3 frames only).
#[cfg(not(test))]
pub fn mask_timer() {
    let lvt = read32(REG_LVT_TIMER);
    write32(REG_LVT_TIMER, lvt | LVT_MASKED);
}

/// Is the timer's LVT entry masked right now? ADR-0023: the delivery
/// windows run under this mask; a timer tick delivered at CPL0 while
/// masked is the stale pre-window IRR (an expiry that landed while the
/// kernel ran IF=0 — the mask gates NEW expiries, not an already-set
/// IRR), and the tick path drops it instead of halting.
#[cfg(not(test))]
pub fn timer_masked() -> bool {
    read32(REG_LVT_TIMER) & LVT_MASKED != 0
}

/// Unmask the timer's LVT entry (resume ticks after the window).
#[cfg(not(test))]
pub fn unmask_timer() {
    let lvt = read32(REG_LVT_TIMER);
    write32(REG_LVT_TIMER, lvt & !LVT_MASKED);
}

/// Reload the periodic-mode initial count (a fresh full interval).
/// TSC-deadline mode ignores this and re-arms via `arm_deadline`.
#[cfg(not(test))]
pub fn reload_periodic() {
    write32(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write32(REG_TIMER_INIT_COUNT, PERIODIC_FALLBACK_COUNT);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SVR carries the spurious vector AND the enable bit.
    #[test]
    fn svr_is_spurious_vector_plus_enable() {
        assert_eq!(svr_value(), 0x1FF);
        assert!(svr_value() & SVR_ENABLE != 0);
        assert_eq!((svr_value() & 0xFF) as u8, SPURIOUS_VECTOR);
    }

    /// The timer LVT encodings: vector in the low byte, mode in bits
    /// 18:17, mask bit distinct — pinned so a mode/typo cannot silently
    /// mask the timer (the "why is nothing ticking" class of bug).
    #[test]
    fn lvt_timer_encodings_are_pinned() {
        let tsc = (TIMER_VECTOR as u32) | LVT_MODE_TSC_DEADLINE;
        assert_eq!(tsc, 0x30 | (2 << 17));
        assert_eq!(tsc & 0xFF, TIMER_VECTOR as u32);
        assert_eq!(tsc & LVT_MASKED, 0, "timer must be unmasked");
        let per = (TIMER_VECTOR as u32) | LVT_MODE_PERIODIC;
        assert_eq!(per, 0x30 | (1 << 17));
        assert_eq!(per & LVT_MASKED, 0);
        assert_eq!(LVT_MODE_ONESHOT, 0);
        // The modes are distinct 2-bit values.
        assert_ne!(LVT_MODE_ONESHOT, LVT_MODE_PERIODIC);
        assert_ne!(LVT_MODE_PERIODIC, LVT_MODE_TSC_DEADLINE);
    }

    /// The vectors: the timer sits above the legacy PIC range and the
    /// spurious vector sits at the top — both must stay inside the IDT
    /// wiring (the idt host test pins the wired range).
    #[test]
    fn vectors_are_where_the_idt_expects_them() {
        assert_eq!(TIMER_VECTOR, 48, "above the 32..=47 legacy catch-alls");
        const { assert!(TIMER_VECTOR < SPURIOUS_VECTOR) };
        assert_eq!(SPURIOUS_VECTOR, 0xFF);
    }

    /// The LAPIC window PTE: a 1 GiB page at PA 0xC000_0000, RW, NX,
    /// global — the direct-map discipline (ADR-0002) applied to MMIO.
    #[test]
    fn window_pte_is_the_direct_map_discipline() {
        assert_eq!(WINDOW_PTE & 0x000F_FFFF_FFFF_F000, 0xC000_0000);
        const { assert!(WINDOW_PTE & pte::PTE_P != 0) };
        const { assert!(WINDOW_PTE & pte::PTE_W != 0) };
        const { assert!(WINDOW_PTE & PTE_PS != 0, "page-size bit: 1 GiB page") };
        const { assert!(WINDOW_PTE & pte::PTE_NX != 0, "MMIO is never executable") };
        const {
            assert!(
                WINDOW_PTE & pte::PTE_G != 0,
                "global: survives CR3 switches"
            )
        };
        const { assert!(WINDOW_PTE & pte::PTE_U == 0, "kernel-only") };
    }

    /// Register offsets are the SDM's (a wrong offset writes a
    /// neighboring register — the exact bug class worth pinning).
    #[test]
    fn register_offsets_match_the_sdm() {
        assert_eq!(REG_ID, 0x020);
        assert_eq!(REG_VERSION, 0x030);
        assert_eq!(REG_TPR, 0x080);
        assert_eq!(REG_EOI, 0x0B0);
        assert_eq!(REG_SVR, 0x0F0);
        assert_eq!(REG_LVT_TIMER, 0x320);
        assert_eq!(REG_LVT_LINT0, 0x350);
        assert_eq!(REG_LVT_LINT1, 0x360);
        assert_eq!(REG_LVT_ERROR, 0x370);
        assert_eq!(REG_TIMER_INIT_COUNT, 0x380);
        assert_eq!(REG_TIMER_CURRENT_COUNT, 0x390);
        assert_eq!(REG_TIMER_DIVIDE, 0x3E0);
    }

    /// The LAPIC's VA is direct-map arithmetic over PA 0xFEE00000, and
    /// that PA lands inside the fourth GiB — the exact range the
    /// WINDOW_PTE maps (PDPT[3] of the direct map, PA 0xC0000000..
    /// 0x1_0000_0000). Note this is deliberately NOT va_to_pa: that
    /// helper describes the FIRST GiB only; the LAPIC window is the
    /// second mapping, created on the target by `map_window`.
    #[test]
    fn the_window_pte_range_covers_the_default_lapic_base() {
        use crate::mm::direct_map::{DIRECT_MAP_BASE, DIRECT_MAP_SIZE};
        assert_eq!(DEFAULT_MMIO_BASE, 0xFEE0_0000);
        const { assert!(DEFAULT_MMIO_BASE >= 0xC000_0000, "inside WINDOW_PTE's GiB") };
        const { assert!(DEFAULT_MMIO_BASE < 0x1_0000_0000, "inside WINDOW_PTE's GiB") };
        let va = reg(0);
        assert_eq!(va, DIRECT_MAP_BASE + DEFAULT_MMIO_BASE);
        // And the first-GiB direct map genuinely does NOT cover it —
        // the window mapping is load-bearing, not redundant.
        const { assert!(DEFAULT_MMIO_BASE >= DIRECT_MAP_SIZE) };
    }

    #[test]
    fn divide_by_16_is_the_sdm_encoding() {
        assert_eq!(DIVIDE_BY_16, 0x3);
    }

    /// The x2APIC MSR map (ADR-0019): the register file maps onto
    /// 0x800+off — the EOI, the LVT timer, and the version register
    /// pinned so a wrong offset writes a NEIGHBORING MSR (the exact
    /// bug class worth pinning).
    #[test]
    fn x2apic_msr_map_is_pinned() {
        assert_eq!(x2apic_msr(REG_EOI), 0x80B);
        assert_eq!(x2apic_msr(REG_LVT_TIMER), 0x832);
        assert_eq!(x2apic_msr(REG_VERSION), 0x803);
        assert_eq!(x2apic_msr(REG_ID), 0x802);
        assert_eq!(x2apic_msr(REG_SVR), 0x80F);
        assert_eq!(x2apic_msr(REG_TPR), 0x808);
        assert_eq!(x2apic_msr(REG_TIMER_INIT_COUNT), 0x838);
        assert_eq!(x2apic_msr(REG_TIMER_DIVIDE), 0x83E);
        // The map is a pure shift of the file: distinct offsets stay
        // distinct MSRs (no aliasing).
        for a in [REG_ID, REG_EOI, REG_SVR, REG_LVT_TIMER] {
            for b in [REG_VERSION, REG_TPR, REG_TIMER_DIVIDE] {
                assert_ne!(x2apic_msr(a), x2apic_msr(b));
            }
        }
    }

    /// The x2APIC enable bit and its CPUID feature bit, pinned:
    /// APIC_BASE bit 10 (x2APIC), CPUID.01H:ECX bit 21.
    #[test]
    fn x2apic_bits_are_pinned() {
        assert_eq!(APIC_BASE_X2APIC, 1 << 10);
        assert_eq!(CPUID_ECX_X2APIC, 1 << 21);
        // Distinct from the global-enable bit (11) and from every
        // other flag the base MSR carries.
        assert_ne!(APIC_BASE_X2APIC, APIC_BASE_ENABLE);
        assert!(crate::arch::features::has_x2apic(CPUID_ECX_X2APIC));
        assert!(!crate::arch::features::has_x2apic(0));
        assert!(
            !crate::arch::features::has_x2apic(1 << 20),
            "neighbor bit must not decode"
        );
    }
}
