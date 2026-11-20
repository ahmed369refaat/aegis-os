//! Pure user-pointer range arithmetic and the user-copy bound (N1,
//! ADR-0007 §1).
//!
//! The PR-1.4 `sys_write` validated the pages covering `[buf, buf+len)`
//! and then copied with 8-byte words: `read_u64_va(buf + off)` touches
//! `[buf+off, buf+off+8)` even when fewer than 8 bytes remained. A
//! `write(1, 0x403FFD, 3)` — ending exactly at the data page's last
//! byte — made the KERNEL read through the absent next page (a CPL0
//! #PF billed to the user). Everything in this module is pure and
//! host-tested; the target adapters in `arch`-adjacent code stay thin.

/// Why a user range is refused before any copy starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// `len` exceeds the syscall's maximum.
    TooLong,
    /// `buf + len` would wrap the address space.
    Overflow,
    /// The range is not inside the user half.
    AboveUserLimit,
}

/// The 8-byte-word copy arithmetic exactly as PR-1.4's `sys_write`
/// performed it (kept as a faithful model of the bug, tested below).
/// Returns the half-open span `[first_touched, last_touched_exclusive)`
/// the word reads actually touch.
#[must_use]
pub fn legacy_word_copy_span(buf: u64, len: u64) -> (u64, u64) {
    let mut off = 0u64;
    let mut touched_end = buf;
    while off < len {
        // memops::read_u64_va(buf + off) reads 8 bytes regardless of
        // how many remain — the N1 bug.
        touched_end = buf + off + 8;
        off += core::cmp::min(8usize, (len - off) as usize) as u64;
    }
    (buf, touched_end)
}

/// The bytes the fixed copy touches: exactly `[buf, buf+len)` —
/// byte-at-a-time, never a byte more (ADR-0007 §1 decision (a)).
#[must_use]
pub fn copy_span(buf: u64, len: u64) -> (u64, u64) {
    (buf, buf.wrapping_add(len))
}

/// Pure span arithmetic: the first and last page VA covering
/// `[buf, buf+len)`, or `None` for an empty range. `Err` for a
/// malformed range (never copied from, never a fault).
pub fn span_pages(
    buf: u64,
    len: u64,
    max_len: u64,
    user_limit: u64,
    page: u64,
) -> Result<Option<(u64, u64)>, RangeError> {
    if len == 0 {
        return Ok(None);
    }
    if len > max_len {
        return Err(RangeError::TooLong);
    }
    let end = match buf.checked_add(len) {
        Some(e) => e,
        None => return Err(RangeError::Overflow),
    };
    if buf >= user_limit || end > user_limit {
        return Err(RangeError::AboveUserLimit);
    }
    let mask = page - 1;
    Ok(Some((buf & !mask, (end - 1) & !mask)))
}

/// Validate a user range: arithmetic first, then every covering page
/// must be a present *user* page (`is_user_page` decides — on target
/// it walks the domain's own tables). Pure: host tests pass a fake map.
pub fn validate_range(
    buf: u64,
    len: u64,
    max_len: u64,
    user_limit: u64,
    page: u64,
    is_user_page: &dyn Fn(u64) -> bool,
) -> bool {
    match span_pages(buf, len, max_len, user_limit, page) {
        Ok(None) => true,
        Ok(Some((first, last))) => {
            let mut va = first;
            loop {
                if !is_user_page(va) {
                    return false;
                }
                if va == last {
                    return true;
                }
                va += page;
            }
        }
        Err(_) => false,
    }
}

/// Copy exactly `[buf, buf+len)` byte-at-a-time. The reader must be
/// `memops::read_u8_va` on target; host tests pass a bounded fake so
/// any byte outside the range is loud.
pub fn copy_user_bytes(
    buf: u64,
    len: u64,
    read: &dyn Fn(u64) -> u8,
    mut sink: impl FnMut(u8),
) -> u64 {
    for off in 0..len {
        sink(read(buf + off));
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: u64 = 0x0000_8000_0000_0000; // pte::USER_LIMIT
    const PAGE: u64 = 4096;
    const MAXW: u64 = 256;

    /// A fake user address space: one mapped page at 0x403000.
    fn one_page(va: u64) -> bool {
        va == 0x403000
    }

    /// N1, the exact report case: `write(1, 0x403FFD, 3)` validates
    /// (the range fits inside the mapped page) — and the PR-1.4 word
    /// copy STILL read past the page end. This documents the bug with
    /// the bug's own arithmetic: the legacy span overshoots.
    #[test]
    fn n1_report_case_word_copy_read_past_the_page() {
        let (lo, hi) = legacy_word_copy_span(0x0040_3FFD, 3);
        assert_eq!(lo, 0x0040_3FFD);
        assert!(
            hi > 0x0040_4000,
            "the legacy word copy must overshoot the page end (got {hi:#x}) — this models the N1 bug"
        );
        // ...while the range itself is perfectly valid:
        assert!(validate_range(0x0040_3FFD, 3, MAXW, LIMIT, PAGE, &one_page));
        // ...and the fixed copy touches exactly the validated bytes:
        let (flo, fhi) = copy_span(0x0040_3FFD, 3);
        assert_eq!((flo, fhi), (0x0040_3FFD, 0x0040_4000));
    }

    /// The fixed copy never reads a byte outside [buf, buf+len).
    #[test]
    fn copy_user_bytes_never_escapes_the_range() {
        let mut touched = [0u64; 8];
        let mut n = 0usize;
        let read = |va: u64| -> u8 {
            assert!(
                (0x100..0x103).contains(&va),
                "copy read outside the range: {va:#x}"
            );
            (va - 0x100) as u8
        };
        let copied = copy_user_bytes(0x100, 3, &read, |b| {
            touched[n] = b as u64;
            n += 1;
        });
        assert_eq!(copied, 3);
        assert_eq!(&touched[..n], &[0, 1, 2]);
    }

    /// G (review round 2): property test — validation NEVER accepts a
    /// range that touches an unmapped page (xorshift64*, fixed seeds;
    /// the page map is fixed: 0x1000..0x9000 present except 0x3000).
    #[test]
    fn property_validation_never_accepts_unmapped_pages() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
        }
        let present = |va: u64| (0x1000..0x9000).contains(&va) && va != 0x3000;
        for seed in [5u64, 0x5EED_5EED, 42] {
            let mut rng = Rng(seed.max(1));
            for _ in 0..2000 {
                let buf = (rng.next() % 0x10) * 0x1000 + rng.next() % 0x1000;
                let len = rng.next() % 600;
                let ok = validate_range(buf, len, MAXW, LIMIT, PAGE, &present);
                // Independent oracle: compute the covering pages and
                // require ALL of them present iff ok.
                if len == 0 {
                    assert!(ok, "empty ranges are always valid");
                    continue;
                }
                if buf.checked_add(len).is_none_or(|e| e <= buf)
                    || buf >= LIMIT
                    || buf.checked_add(len).unwrap() > LIMIT
                    || len > MAXW
                {
                    assert!(!ok, "malformed range accepted: {buf:#x}+{len}");
                    continue;
                }
                let first = buf & !(PAGE - 1);
                let last = (buf + len - 1) & !(PAGE - 1);
                let mut all_present = true;
                let mut va = first;
                while va <= last {
                    if !present(va) {
                        all_present = false;
                        break;
                    }
                    va += PAGE;
                }
                assert_eq!(
                    ok, all_present,
                    "seed {seed}: validation={ok} but oracle={all_present} for {buf:#x}+{len}"
                );
            }
        }
    }

    #[test]
    fn span_arithmetic_edge_cases() {
        // len = 0: no pages, valid.
        assert_eq!(span_pages(0x403000, 0, MAXW, LIMIT, PAGE), Ok(None));
        // len = 1 at the last byte of a page.
        assert_eq!(
            span_pages(0x403FFF, 1, MAXW, LIMIT, PAGE),
            Ok(Some((0x403000, 0x403000)))
        );
        // len = 3 ending exactly at a page end: still one page.
        assert_eq!(
            span_pages(0x403FFD, 3, MAXW, LIMIT, PAGE),
            Ok(Some((0x403000, 0x403000)))
        );
        // Crossing into the next page: two pages.
        assert_eq!(
            span_pages(0x403FFF, 2, MAXW, LIMIT, PAGE),
            Ok(Some((0x403000, 0x404000)))
        );
        // buf + len wraps.
        assert_eq!(
            span_pages(u64::MAX, 2, MAXW, LIMIT, PAGE),
            Err(RangeError::Overflow)
        );
        // buf at/above the user limit.
        assert_eq!(
            span_pages(LIMIT, 1, MAXW, LIMIT, PAGE),
            Err(RangeError::AboveUserLimit)
        );
        assert_eq!(
            span_pages(LIMIT + 5, 1, MAXW, LIMIT, PAGE),
            Err(RangeError::AboveUserLimit)
        );
        // len above the syscall maximum.
        assert_eq!(
            span_pages(0x1000, MAXW + 1, MAXW, LIMIT, PAGE),
            Err(RangeError::TooLong)
        );
    }

    #[test]
    fn validation_against_a_fake_page_map() {
        // Present single page: in-range ok (MAX_WRITE bounds len, so a
        // full-page write is tested at the maximum).
        assert!(validate_range(0x403000, 256, MAXW, LIMIT, PAGE, &one_page));
        assert!(validate_range(0x403F00, 256, MAXW, LIMIT, PAGE, &one_page));
        assert!(validate_range(0x403FFD, 3, MAXW, LIMIT, PAGE, &one_page));
        // Crossing into the absent next page: refused (this is the
        // -EFAULT the edge blob expects).
        assert!(!validate_range(0x404000, 1, MAXW, LIMIT, PAGE, &one_page));
        assert!(!validate_range(0x403FFF, 2, MAXW, LIMIT, PAGE, &one_page));
        // Zero length on an unmapped address: nothing to touch.
        assert!(validate_range(0x999_0000, 0, MAXW, LIMIT, PAGE, &one_page));
        // A kernel-half address is never user memory.
        assert!(!validate_range(
            0xFFFF_8000_0000_0000,
            1,
            MAXW,
            LIMIT,
            PAGE,
            &one_page
        ));
    }
}
