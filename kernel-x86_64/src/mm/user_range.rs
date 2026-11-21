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

/// Round J, SYS_READ: the copy-OUT mirror — write exactly
/// `bytes.len()` bytes to `[buf, buf+bytes.len())`, byte-at-a-time,
/// never a byte more. The writer must be `memops::write_u8_va` on
/// target (the same N1 byte-exactness discipline, now in the outward
/// direction); host tests pass a bounded fake.
pub fn copy_out_bytes(buf: u64, bytes: &[u8], write: &dyn Fn(u64, u8)) -> u64 {
    for (off, b) in bytes.iter().enumerate() {
        write(buf + off as u64, *b);
    }
    bytes.len() as u64
}

/// Why a bounded C-string read from user memory refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CstrError {
    /// No NUL within `max` bytes — the path is not path-shaped.
    TooLong,
    /// The walk touched a page that is not a present user page (or the
    /// address is outside the user half, or would wrap).
    Fault,
}

/// Round J, SYS_OPEN: read a NUL-terminated string from user memory,
/// bounded by `max`, page-checking as the walk goes (a short string
/// before an absent page succeeds; the walk stops at the NUL). Fills
/// `out` with the string bytes (no NUL) and returns their length.
///
/// The page check happens BEFORE the first byte of each page is read —
/// a string ending exactly at a page boundary never touches the next
/// page, and a string whose NUL would land in an absent page faults
/// only if the walk actually reaches past the last good byte... which
/// it must, to see the terminator: a missing NUL inside an absent page
/// is a Fault, never a silent short read.
pub fn read_user_cstr(
    buf: u64,
    max: usize,
    user_limit: u64,
    page: u64,
    is_user_page: &dyn Fn(u64) -> bool,
    read: &dyn Fn(u64) -> u8,
    out: &mut [u8],
) -> Result<usize, CstrError> {
    debug_assert!(out.len() >= max, "out must hold the max bound");
    let mut last_page = u64::MAX;
    for i in 0..max {
        let va = match buf.checked_add(i as u64) {
            Some(va) => va,
            None => return Err(CstrError::Fault),
        };
        if va >= user_limit {
            return Err(CstrError::Fault);
        }
        let va_page = va & !(page - 1);
        if va_page != last_page {
            if !is_user_page(va_page) {
                return Err(CstrError::Fault);
            }
            last_page = va_page;
        }
        let b = read(va);
        if b == 0 {
            return Ok(i);
        }
        out[i] = b;
    }
    Err(CstrError::TooLong)
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

    /// Round J: the copy-out mirror never writes a byte outside
    /// [buf, buf+len).
    #[test]
    fn copy_out_bytes_never_escapes_the_range() {
        use core::cell::RefCell;
        let store = RefCell::new([0xFFu8; 8]);
        let write = |va: u64, b: u8| {
            assert!(
                (0x200..0x204).contains(&va),
                "copy-out wrote outside the range: {va:#x}"
            );
            store.borrow_mut()[(va - 0x200) as usize] = b;
        };
        let n = copy_out_bytes(0x200, &[7, 8, 9], &write);
        assert_eq!(n, 3);
        assert_eq!(&store.borrow()[..4], &[7, 8, 9, 0xFF]);
        // Empty copy touches nothing.
        assert_eq!(copy_out_bytes(0x999_0000, &[], &write), 0);
    }

    /// Round J: the bounded C-string reader — the SYS_OPEN path model.
    #[test]
    fn read_cstr_stops_at_the_terminator_and_bounds_the_walk() {
        let two_pages = |va: u64| va == 0x1000 || va == 0x2000;
        // "/note\0" in the first page.
        let mem = |va: u64| match va {
            0x1000 => b'/',
            0x1001 => b'n',
            0x1002 => b'o',
            0x1003 => b't',
            0x1004 => b'e',
            _ => 0,
        };
        let mut out = [0u8; 32];
        assert_eq!(
            read_user_cstr(0x1000, 16, LIMIT, PAGE, &two_pages, &mem, &mut out),
            Ok(5)
        );
        assert_eq!(&out[..5], b"/note");
        // No NUL within the bound: TooLong, never a silent short read.
        let no_nul = |_va: u64| b'x';
        assert_eq!(
            read_user_cstr(0x1000, 4, LIMIT, PAGE, &two_pages, &no_nul, &mut out),
            Err(CstrError::TooLong)
        );
        // The walk crossing into an absent page faults — the NUL is
        // not there to stop it first (starting near the page end so
        // the bound genuinely crosses).
        let one_page = |va: u64| va == 0x1000;
        assert_eq!(
            read_user_cstr(0x1FF0, 32, LIMIT, PAGE, &one_page, &no_nul, &mut out),
            Err(CstrError::Fault)
        );
        // A kernel-half address faults before any byte is read.
        assert_eq!(
            read_user_cstr(
                0xFFFF_8000_0000_0000,
                4,
                LIMIT,
                PAGE,
                &one_page,
                &no_nul,
                &mut out
            ),
            Err(CstrError::Fault)
        );
        // Wraparound faults.
        assert_eq!(
            read_user_cstr(u64::MAX - 1, 4, LIMIT, PAGE, &one_page, &no_nul, &mut out),
            Err(CstrError::Fault)
        );
    }

    /// Round J: a string ending exactly at a page boundary — the NUL
    /// lands on the last byte of a page, so the next page is never
    /// touched (the boundary walk is exact, not worst-case).
    #[test]
    fn read_cstr_at_page_boundaries_touches_only_what_it_reads() {
        use core::cell::Cell;
        let present = |va: u64| va == 0x1000 || va == 0x2000;
        let checks = Cell::new(0u32);
        let page_seen = |va: u64| {
            checks.set(checks.get() + 1);
            va == 0x1000 || va == 0x2000
        };
        // 0x1FFF is the NUL (last byte of page 0x1000).
        let mem = |va: u64| if va == 0x1FFF { 0 } else { b'a' };
        let mut out = [0u8; 32];
        assert_eq!(
            read_user_cstr(0x1FF0, 16, LIMIT, PAGE, &page_seen, &mem, &mut out),
            Ok(15)
        );
        assert_eq!(out[..15], [b'a'; 15]);
        // Exactly one page check: page 0x1000 — page 0x2000 is never
        // asked about.
        assert_eq!(checks.get(), 1, "the walk must not over-check pages");
        // The empty string (NUL at the first byte) is a legal path of
        // length 0... the VFS will refuse it, but the copy layer
        // reports what is there.
        let nul_first = |_va: u64| 0u8;
        assert_eq!(
            read_user_cstr(0x1000, 16, LIMIT, PAGE, &present, &nul_first, &mut out),
            Ok(0)
        );
    }
}
