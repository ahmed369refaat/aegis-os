//! Tiny integer formatting (decimal/hex) for the boot log.
//!
//! `core::fmt` would work, but the boot log wants zero machinery and the
//! exact same code on host tests — these helpers are pure and tested.

/// Format `v` as decimal into `buf`; returns the digits as a `&str`
/// borrowed from `buf`. A 20-byte buffer always suffices for u64.
pub fn dec(v: u64, buf: &mut [u8; 20]) -> &str {
    let mut n = 0usize;
    let mut val = v;
    // Special case zero (the loop below would emit nothing): a single
    // '0' at the same right-aligned position the loop uses.
    if val == 0 {
        buf[19] = b'0';
        n = 1;
    }
    while val > 0 {
        let digit = (val % 10) as u8;
        buf[19 - n] = b'0' + digit;
        n += 1;
        val /= 10;
    }
    // Digits were written right-aligned at the buffer tail.
    let start = 20 - n;
    let s = &buf[start..20];
    // Digits are ASCII by construction.
    core::str::from_utf8(s).unwrap_or("")
}

/// Format `v` as `0x` + 16 lowercase hex digits (fixed width).
pub fn hex(v: u64, buf: &mut [u8; 18]) -> &str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let shift = 60 - 4 * i;
        buf[2 + i] = HEX[((v >> shift) & 0xF) as usize];
    }
    core::str::from_utf8(&buf[..18]).unwrap_or("")
}

/// Emit a log line as its parts then a newline — the one logging
/// primitive every boot step shares (moved out of `drvstack` so the
/// session module can use it too, ADR-0016).
pub fn line(out: &mut dyn FnMut(&str), parts: &[&str]) {
    for p in parts {
        out(p);
    }
    out("\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_boundaries() {
        let mut buf = [0u8; 20];
        assert_eq!(dec(0, &mut buf), "0");
        assert_eq!(dec(1, &mut buf), "1");
        assert_eq!(dec(9, &mut buf), "9");
        assert_eq!(dec(10, &mut buf), "10");
        assert_eq!(dec(99, &mut buf), "99");
        assert_eq!(dec(100, &mut buf), "100");
        assert_eq!(dec(191, &mut buf), "191");
        assert_eq!(dec(1_000, &mut buf), "1000");
        assert_eq!(dec(u64::MAX, &mut buf), "18446744073709551615");
        assert_eq!(dec(u32::MAX as u64, &mut buf), "4294967295");
    }

    #[test]
    fn decimal_is_exact_not_padded() {
        let mut buf = [0u8; 20];
        // No leading zeros, no leftover tail bytes.
        assert_eq!(dec(42, &mut buf).len(), 2);
        assert_eq!(dec(42, &mut buf), "42");
    }

    #[test]
    fn hex_is_fixed_width_lowercase() {
        let mut buf = [0u8; 18];
        assert_eq!(hex(0, &mut buf), "0x0000000000000000");
        assert_eq!(hex(0xDEAD_BEEF, &mut buf), "0x00000000deadbeef");
        assert_eq!(hex(u64::MAX, &mut buf), "0xffffffffffffffff");
        assert_eq!(hex(0x1000000, &mut buf), "0x0000000001000000");
    }

    #[test]
    fn buffers_do_not_alias_across_calls() {
        let mut buf = [0u8; 20];
        assert_eq!(dec(12345, &mut buf), "12345");
        assert_eq!(dec(7, &mut buf), "7");
    }
}
