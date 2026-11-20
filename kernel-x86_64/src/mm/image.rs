//! The kernel image's W^X mapping (F15, ADR-0006).
//!
//! The stub maps the whole image as one 2 MiB RWX leaf (0x83); mm::init
//! replaces that PD entry with a page table built here, one 4 KiB PTE
//! per page: `.text` RX, `.rodata` RO+NX, `.data`/`.bss`/boot stack
//! RW+NX, everything else (inter-section gaps, the boot-stack guard
//! page) ABSENT. CR0.WP makes the R-only pages stick for CPL0 too.
//!
//! The section-to-flags mapping is pure and host-tested; the only
//! target-side work is filling the static PT and swapping the PD entry.

use crate::mm::pte;

/// Linker-exported image boundaries (see linker.ld, F15).
extern "C" {
    pub static __text_start: u8;
    pub static __text_end: u8;
    pub static __rodata_start: u8;
    pub static __rodata_end: u8;
    pub static __data_start: u8;
    pub static __data_end: u8;
    pub static __bss_start: u8;
    pub static __bss_end: u8;
    pub static __stack_guard: u8;
    pub static stack_bottom: u8;
}

/// The image's virtual bounds. `addr_of!` on extern statics is safe
/// (no read happens; only the symbol addresses are taken).
#[must_use]
pub fn image_bounds() -> (u64, u64) {
    (
        core::ptr::addr_of!(__text_start) as u64,
        (core::ptr::addr_of!(__bss_end) as u64 + 4095) & !4095u64,
    )
}

/// All boundary pairs at once: (text, rodata, data, bss, stack_guard).
#[must_use]
pub fn section_bounds() -> ((u64, u64), (u64, u64), (u64, u64), (u64, u64), (u64, u64)) {
    let g = |s: *const u8, e: *const u8| (s as u64, e as u64);
    // SAFETY-free: addr_of on extern statics only takes addresses.
    (
        (g(core::ptr::addr_of!(__text_start), core::ptr::addr_of!(__text_end))),
        (g(core::ptr::addr_of!(__rodata_start), core::ptr::addr_of!(__rodata_end))),
        (g(core::ptr::addr_of!(__data_start), core::ptr::addr_of!(__data_end))),
        (g(core::ptr::addr_of!(__bss_start), core::ptr::addr_of!(__bss_end))),
        (
            core::ptr::addr_of!(__stack_guard) as u64,
            core::ptr::addr_of!(stack_bottom) as u64,
        ),
    )
}

/// The boot-stack guard page's virtual address.
#[must_use]
pub fn boot_stack_guard_va() -> u64 {
    core::ptr::addr_of!(__stack_guard) as u64
}

/// Pure section→PTE-flags mapping (host-tested). Returns the PTE bits
/// for the page containing `va`, or None for a page that must stay
/// ABSENT (gaps between sections, the boot-stack guard). Boundaries
/// are passed in so tests can fabricate layouts.
#[must_use]
pub fn image_pte_flags(
    va: u64,
    text: (u64, u64),
    rodata: (u64, u64),
    data: (u64, u64),
    bss: (u64, u64),
    stack_guard: (u64, u64),
) -> Option<u64> {
    let g = pte::PTE_G;
    let nx = pte::PTE_NX;
    if va >= stack_guard.0 && va < stack_guard.1 {
        return None; // the boot-stack guard page: absent by design
    }
    if va >= text.0 && va < text.1 {
        return Some(pte::PTE_P | g); // RX: present, global, no W, no NX
    }
    if va >= rodata.0 && va < rodata.1 {
        return Some(pte::PTE_P | g | nx); // RO + NX
    }
    if va >= data.0 && va < data.1 {
        return Some(pte::PTE_P | g | pte::PTE_W | nx); // RW + NX
    }
    if va >= bss.0 && va < bss.1 {
        return Some(pte::PTE_P | g | pte::PTE_W | nx); // RW + NX
    }
    None // gap: absent — nothing legitimate lives between sections
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xFFFF_FFFF_8000_0000;
    const P: u64 = 4096;

    fn layout() -> ((u64, u64), (u64, u64), (u64, u64), (u64, u64), (u64, u64)) {
        let text = (BASE, BASE + 3 * P);
        let rodata = (BASE + 3 * P, BASE + 4 * P);
        // one gap page at BASE+4P (linker alignment can leave one)
        let data = (BASE + 5 * P, BASE + 6 * P);
        let bss_start = BASE + 6 * P;
        let guard = bss_start + P;
        let bss = (bss_start, bss_start + 4 * P);
        (text, rodata, data, bss, (guard, guard + P))
    }

    #[test]
    fn text_is_rx_rodata_ro_data_bss_rw_nx() {
        let (text, rodata, data, bss, guard) = layout();
        // .text: present+global, NO write, NO execute-disable.
        let t = image_pte_flags(BASE + P, text, rodata, data, bss, guard).unwrap();
        assert!(t & pte::PTE_P != 0);
        assert!(t & pte::PTE_W == 0, "text must not be writable");
        assert!(t & pte::PTE_NX == 0, "text must be executable");
        // .rodata: present, no write, NX.
        let r = image_pte_flags(BASE + 3 * P, text, rodata, data, bss, guard).unwrap();
        assert!(r & pte::PTE_W == 0);
        assert!(r & pte::PTE_NX != 0, "rodata must never execute");
        // .data/.bss: present, writable, NX.
        for va in [BASE + 5 * P, BASE + 6 * P, BASE + 8 * P] {
            let f = image_pte_flags(va, text, rodata, data, bss, guard).unwrap();
            assert!(f & pte::PTE_W != 0, "data/bss must be writable");
            assert!(f & pte::PTE_NX != 0, "data/bss must never execute");
        }
    }

    #[test]
    fn gaps_and_the_stack_guard_are_absent() {
        let (text, rodata, data, bss, guard) = layout();
        // The alignment gap page: absent.
        assert_eq!(image_pte_flags(BASE + 4 * P, text, rodata, data, bss, guard), None);
        // The boot-stack guard page: absent.
        assert_eq!(image_pte_flags(guard.0, text, rodata, data, bss, guard), None);
        assert_eq!(image_pte_flags(guard.1 - 1, text, rodata, data, bss, guard), None);
        // Outside the image entirely: absent.
        assert_eq!(image_pte_flags(BASE - P, text, rodata, data, bss, guard), None);
    }
}
