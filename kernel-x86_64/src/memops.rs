//! Volatile memory primitives.
//!
//! Two address flavors share one raw layer:
//!
//! - **Kernel target**: the "physical" functions (`read_u32`, `write_u64`,
//!   `scrub_frame`, `frame_is_zero`) take *physical* addresses and reach
//!   RAM through the direct map (ADR-0002): `pa` is translated by
//!   `mm::direct_map::pa_to_va` before the volatile access.
//! - **Host tests**: the same functions run against a real host buffer
//!   whose *virtual* address plays the role of the physical address
//!   (`translate` is the identity there), so the scrub and read-back
//!   paths execute the identical code.
//!
//! The `_va` variants are the raw layer itself: a volatile access at
//! exactly the address given, no translation. The kernel uses them for
//! already-virtual addresses (guarded-stack pages, `mm/stacks.rs`).
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (with `arch`,
//! `boot` and `hw`): volatile raw-pointer access is the one memory-unsafe
//! primitive the kernel needs; every function below is a two-line
//! wrapper.

#![allow(unsafe_code)]

/// Physical→virtual translation. Direct map on the kernel target;
/// identity on the host, where test buffers are handed in as "physical".
#[cfg(not(test))]
fn translate(pa: u64) -> u64 {
    crate::mm::direct_map::pa_to_va(pa)
}

#[cfg(test)]
fn translate(pa: u64) -> u64 {
    pa
}

/// Volatile 32-bit read at physical address `pa` (through the direct map
/// on the kernel).
///
/// SAFETY: `pa` must be 4-byte aligned and point to readable memory
/// (guaranteed by callers: direct-mapped RAM on the kernel, an aligned
/// host buffer in tests).
pub fn read_u32(pa: u64) -> u32 {
    // SAFETY: see function docs; volatile avoids any reordering.
    unsafe { (translate(pa) as *const u32).read_volatile() }
}

/// Volatile 64-bit read at physical address `pa`.
///
/// SAFETY: `pa` must be 8-byte aligned and readable.
pub fn read_u64(pa: u64) -> u64 {
    // SAFETY: see function docs.
    unsafe { (translate(pa) as *const u64).read_volatile() }
}

/// Volatile 64-bit write at physical address `pa`.
///
/// SAFETY: `pa` must be 8-byte aligned and writable.
pub fn write_u64(pa: u64, val: u64) {
    // SAFETY: see function docs.
    unsafe { (translate(pa) as *mut u64).write_volatile(val) }
}

/// Volatile 32-bit write at physical address `pa` — the natural width
/// of MMIO registers (the LAPIC, ADR-0012): devices may reject or split
/// wider accesses, so the 8-byte primitive must not be used on them.
///
/// SAFETY: `pa` must be 4-byte aligned and point to a writable register.
pub fn write_u32(pa: u64, val: u32) {
    // SAFETY: see function docs.
    unsafe { (translate(pa) as *mut u32).write_volatile(val) }
}

/// Read one byte at a user (or kernel) VA — the only volatile reader
/// the user-copy path is allowed to use (N1, ADR-0007 §1): it touches
/// exactly one byte, so a validated `[buf, buf+len)` can never fault.
pub fn read_u8_va(va: u64) -> u8 {
    unsafe { (va as *const u8).read_volatile() }
}

/// Volatile 64-bit read at the *virtual* address `va` (no translation).
///
/// SAFETY: `va` must be 8-byte aligned, mapped and readable. N1
/// (ADR-0007 §1): user-controlled addresses must never reach this
/// primitive — the alignment is asserted, and it touches 8 bytes.
pub fn read_u64_va(va: u64) -> u64 {
    debug_assert!(va.is_multiple_of(8), "read_u64_va on unaligned va {va:#x}");
    // SAFETY: see function docs.
    unsafe { (va as *const u64).read_volatile() }
}

/// Volatile 64-bit write at the *virtual* address `va` (no translation).
///
/// SAFETY: `va` must be 8-byte aligned, mapped and writable.
pub fn write_u64_va(va: u64, val: u64) {
    debug_assert!(va.is_multiple_of(8), "write_u64_va on unaligned va {va:#x}");
    // SAFETY: see function docs.
    unsafe { (va as *mut u64).write_volatile(val) }
}

/// Zero one 4 KiB frame: 512 volatile u64 writes. This is the
/// scrub-on-release primitive — the M1 exit criteria check it by
/// read-back (`frame_is_zero`).
pub fn scrub_frame(pa: u64) {
    for i in 0..512u64 {
        write_u64(pa + i * 8, 0);
    }
}

/// Read a whole 4 KiB frame back and require every word to be zero.
pub fn frame_is_zero(pa: u64) -> bool {
    (0..512u64).all(|i| read_u64(pa + i * 8) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aligned_frame_buffer() -> (Vec<u64>, u64) {
        // 512 u64 = one 4 KiB frame, 8-byte aligned by construction.
        let v = vec![0u64; 512];
        let pa = v.as_ptr() as u64;
        (v, pa)
    }

    #[test]
    fn scrub_frame_zeroes_every_word() {
        let (_keep, pa) = aligned_frame_buffer();
        // Dirty the whole frame first.
        for i in 0..512u64 {
            write_u64(pa + i * 8, 0xDEAD_BEEF_CAFE_F00D);
        }
        assert!(!frame_is_zero(pa));
        scrub_frame(pa);
        assert!(frame_is_zero(pa), "scrub must zero all 512 words");
    }

    #[test]
    fn write_read_roundtrip_is_volatile_consistent() {
        let (_keep, pa) = aligned_frame_buffer();
        write_u64(pa, 0x0123_4567_89AB_CDEF);
        assert_eq!(read_u64(pa), 0x0123_4567_89AB_CDEF);
        write_u64(pa + 8, 42);
        assert_eq!(read_u64(pa + 8), 42);
        // First word untouched by the second write.
        assert_eq!(read_u64(pa), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn read_u32_reads_the_low_half() {
        let (_keep, pa) = aligned_frame_buffer();
        write_u64(pa, 0xFFFF_FFFF_0000_1234);
        assert_eq!(read_u32(pa), 0x0000_1234);
    }
}
