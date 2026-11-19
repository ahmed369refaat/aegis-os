//! Volatile memory primitives over "physical" addresses.
//!
//! On the booted kernel every physical address is identity-mapped, so a
//! physical address IS a dereferenceable virtual address. On the host test
//! builds the same functions run against a real host buffer — the scrub
//! and read-back code path is identical, which is exactly what the tests
//! prove.
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (with `boot` and
//! `hw`): volatile raw-pointer access is the one memory-unsafe primitive
//! the kernel needs; every function below is a two-line wrapper.

#![allow(unsafe_code)]

/// Volatile 32-bit read at `pa`.
///
/// SAFETY: `pa` must be 4-byte aligned and point to readable memory
/// (guaranteed by callers: identity-mapped RAM on the kernel, an aligned
/// host buffer in tests).
pub fn read_u32(pa: u64) -> u32 {
    // SAFETY: see function docs; volatile avoids any reordering.
    unsafe { (pa as *const u32).read_volatile() }
}

/// Volatile 64-bit read at `pa`.
///
/// SAFETY: `pa` must be 8-byte aligned and readable.
pub fn read_u64(pa: u64) -> u64 {
    // SAFETY: see function docs.
    unsafe { (pa as *const u64).read_volatile() }
}

/// Volatile 64-bit write at `pa`.
///
/// SAFETY: `pa` must be 8-byte aligned and writable.
pub fn write_u64(pa: u64, val: u64) {
    // SAFETY: see function docs.
    unsafe { (pa as *mut u64).write_volatile(val) }
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
