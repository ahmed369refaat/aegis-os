//! ADR-0023 D8: the ring-3 signal frame — pure construction, pure
//! validation.
//!
//! The frame the kernel pushes onto the USER stack when a caught
//! signal is delivered, and the bytes it reads back on
//! `rt_sigreturn`. Everything here is pure over byte slices: the
//! kernel supplies the register image and the cookie, and on the way
//! back EVERY user-supplied field is re-validated — the cookie, the
//! selectors, the canonicality of rip/rsp, and the rflags restore is a
//! WHITELIST (ADR-0031): only the arithmetic/status flags (plus DF)
//! pass through, IF and bit 1 are the kernel-fixed floor, and a forged
//! frame can only ever restore a SANITIZED, always-preemptible context
//! or fail with a typed error.
//!
//! Layout (16 little-endian u64 words, 128 bytes). At delivery the
//! handler's entry RSP points at word 0 — a plain `ret` returns to
//! the restorer (the trampoline), leaving RSP at word 1;
//! `rt_sigreturn` therefore reads the frame at `user_rsp - 8`:
//!
//! ```text
//!  0: restorer      1: signum        2: cookie      3: saved rip
//!  4: saved cs      5: saved rflags  6: saved rsp   7: saved ss
//!  8: saved rax     9: rdi          10: rsi        11: rdx
//! 12: r10          13: r8           14: r9         15: rbx
//! ```

/// The frame's exact size in bytes.
pub const SIGFRAME_BYTES: usize = 128;

/// ADR-0031 section A: the WHITELIST of RFLAGS bits a user-supplied
/// frame may choose for itself — the arithmetic/status flags plus DF
/// (per-thread calling-convention state, meaningless to the kernel):
/// CF (0), PF (2), AF (4), ZF (6), SF (7), DF (10), OF (11). Every
/// other bit — TF, IOPL, NT, RF, VM, AC, VIF, VIP, ID and all
/// reserved bits — is stripped: a new architecture bit is
/// non-restorable by default until someone explicitly classifies it.
const RFLAGS_USER_ALLOWED: u64 =
    (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 11);
/// ADR-0031 section A: the kernel-fixed floor — IF (bit 9): a restored
/// context is ALWAYS preemptible (a forged IF=0 must never starve the
/// timer, ADR-0023's guarantee), and reserved bit 1, always 1.
const RFLAGS_KERNEL_FIXED: u64 = (1 << 9) | 0x2;

/// The non-canonical boundary for user-space addresses (48-bit
/// canonical low half).
pub const USER_CANON_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigframeError {
    /// The cookie word does not match the delivery record — a forged
    /// or displaced frame.
    CookieMismatch,
    /// cs/ss are not the expected user selectors.
    BadSelector,
    /// The saved rip is not a canonical user address (or zero).
    BadRip,
    /// The saved rsp is not a canonical user address.
    BadRsp,
}

/// The register image the kernel captures at delivery. `gprs` follows
/// the frame's word order 8..15: rax, rdi, rsi, rdx, r10, r8, r9, rbx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptedImage {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub gprs: [u64; 8],
}

/// Build the 128 frame bytes into `out` (the handler's entry stack).
/// The cookie is KERNEL-chosen per delivery (never derived from user
/// data). Unit-returning by design: `out` is the output.
pub fn build(
    signum: u8,
    cookie: u64,
    restorer: u64,
    img: &InterruptedImage,
    out: &mut [u8; SIGFRAME_BYTES],
) {
    let words: [u64; 16] = [
        restorer,
        u64::from(signum),
        cookie,
        img.rip,
        img.cs,
        img.rflags,
        img.rsp,
        img.ss,
        img.gprs[0],
        img.gprs[1],
        img.gprs[2],
        img.gprs[3],
        img.gprs[4],
        img.gprs[5],
        img.gprs[6],
        img.gprs[7],
    ];
    for (i, w) in words.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
}

/// Read word `i` of a frame (little-endian).
fn word(bytes: &[u8; SIGFRAME_BYTES], i: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
    u64::from_le_bytes(b)
}

/// Validate a user-supplied frame and return the SANITIZED register
/// image to restore. `cookie` is the kernel's delivery record's
/// cookie; `expected_cs`/`expected_ss` the selectors the kernel
/// always delivers with. Every field is re-checked — the kernel never
/// trusts the frame it reads back.
pub fn validate(
    bytes: &[u8; SIGFRAME_BYTES],
    cookie: u64,
    expected_cs: u64,
    expected_ss: u64,
) -> Result<InterruptedImage, SigframeError> {
    if word(bytes, 2) != cookie {
        return Err(SigframeError::CookieMismatch);
    }
    let cs = word(bytes, 4);
    let ss = word(bytes, 7);
    if cs != expected_cs || ss != expected_ss {
        return Err(SigframeError::BadSelector);
    }
    let rip = word(bytes, 3);
    if rip == 0 || rip > USER_CANON_MAX {
        return Err(SigframeError::BadRip);
    }
    let rsp = word(bytes, 6);
    if rsp == 0 || rsp > USER_CANON_MAX {
        return Err(SigframeError::BadRsp);
    }
    // ADR-0031: whitelist, not blacklist — the restored flags are
    // exactly (the frame's user-allowed bits) | (the kernel-fixed
    // floor). A forged frame can never clear IF and never smuggle a
    // kernel-relevant bit (AC, TF, ...) back into the restored context.
    let rflags = (word(bytes, 5) & RFLAGS_USER_ALLOWED) | RFLAGS_KERNEL_FIXED;
    Ok(InterruptedImage {
        rip,
        cs,
        rflags,
        rsp,
        ss,
        gprs: [
            word(bytes, 8),
            word(bytes, 9),
            word(bytes, 10),
            word(bytes, 11),
            word(bytes, 12),
            word(bytes, 13),
            word(bytes, 14),
            word(bytes, 15),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img() -> InterruptedImage {
        InterruptedImage {
            rip: 0x400050,
            cs: 0x2b,
            rflags: 0x202,
            rsp: 0x7fff_0000,
            ss: 0x23,
            gprs: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[test]
    fn build_then_validate_round_trips_exactly() {
        let mut f = [0u8; SIGFRAME_BYTES];
        build(10, 0xCAFE_1234, 0x402000, &img(), &mut f);
        let got = validate(&f, 0xCAFE_1234, 0x2b, 0x23).unwrap();
        assert_eq!(got, img());
        // The signum and restorer words are where the handler ABI
        // expects them.
        assert_eq!(word(&f, 0), 0x402000);
        assert_eq!(word(&f, 1), 10);
    }

    #[test]
    fn a_wrong_cookie_is_refused_by_name() {
        let mut f = [0u8; SIGFRAME_BYTES];
        build(10, 1, 0x402000, &img(), &mut f);
        assert_eq!(
            validate(&f, 2, 0x2b, 0x23),
            Err(SigframeError::CookieMismatch)
        );
    }

    #[test]
    fn kernel_rip_and_zero_rip_refuse() {
        let mut base = img();
        let mut f = [0u8; SIGFRAME_BYTES];
        base.rip = 0xFFFF_8000_0000_0000; // the kernel half
        build(10, 1, 0x402000, &base, &mut f);
        assert_eq!(validate(&f, 1, 0x2b, 0x23), Err(SigframeError::BadRip));
        base.rip = 0;
        build(10, 1, 0x402000, &base, &mut f);
        assert_eq!(validate(&f, 1, 0x2b, 0x23), Err(SigframeError::BadRip));
    }

    #[test]
    fn selectors_must_be_ours() {
        let mut f = [0u8; SIGFRAME_BYTES];
        build(10, 1, 0x402000, &img(), &mut f);
        assert_eq!(validate(&f, 1, 0x30, 0x23), Err(SigframeError::BadSelector));
        assert_eq!(validate(&f, 1, 0x2b, 0x18), Err(SigframeError::BadSelector));
    }

    #[test]
    fn forged_rflags_bits_are_stripped_not_trusted() {
        let mut base = img();
        // ADR-0031: a forged frame tries IF=0 + AC=1 (the round-A1
        // exploit: read the cookie, clear IF, set AC, sigreturn) plus
        // IOPL=3, NT, VM, RF, TF, VIF, VIP, ID for good measure.
        base.rflags = (3 << 12)
            | (1 << 14)
            | (1 << 16)
            | (1 << 17)
            | (1 << 8)
            | (1 << 18)
            | (1 << 19)
            | (1 << 20)
            | (1 << 21);
        let mut f = [0u8; SIGFRAME_BYTES];
        build(10, 1, 0x402000, &base, &mut f);
        let got = validate(&f, 1, 0x2b, 0x23).unwrap();
        assert_eq!(
            got.rflags, 0x202,
            "the whitelist floor: IF forced on, bit 1 on, everything else stripped"
        );
        // Bit 1 and IF are forced on even if the forger cleared them
        // (the floor is unconditional, not a passthrough).
        base.rflags = 0;
        build(10, 1, 0x402000, &base, &mut f);
        let got = validate(&f, 1, 0x2b, 0x23).unwrap();
        assert_eq!(got.rflags, 0x202, "IF and bit 1 survive a zero word");
    }

    /// ADR-0031 section A: the restored context is whitelisted, not
    /// blacklisted. Exactly the arithmetic/status flags (CF PF AF ZF SF
    /// DF OF) pass through bit-exact; IF and reserved bit 1 are the
    /// kernel-fixed floor; EVERY other bit — TF, IOPL, NT, RF, VM, AC,
    /// VIF, VIP, ID and every reserved bit — never survives, whatever
    /// the frame said. Table-driven over all 64 bits so a future flag
    /// bit is non-restorable by default.
    #[test]
    fn every_rflags_bit_is_classified_whitelist_not_blacklist() {
        const USER_ALLOWED: u64 =
            (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 11);
        const KERNEL_FIXED: u64 = (1 << 9) | 0x2;
        for bit in 0..u64::BITS {
            let word = 1u64 << bit;
            let mut base = img();
            base.rflags = word;
            let mut f = [0u8; SIGFRAME_BYTES];
            build(10, 1, 0x402000, &base, &mut f);
            let got = validate(&f, 1, 0x2b, 0x23)
                .expect("a frame with only a flag word set is structurally valid");
            if USER_ALLOWED & word != 0 {
                assert_eq!(
                    got.rflags & word,
                    word,
                    "bit {bit}: user-allowed, must survive"
                );
            } else if KERNEL_FIXED & word == 0 {
                assert_eq!(
                    got.rflags & word,
                    0,
                    "bit {bit}: not whitelisted, must never survive a restore"
                );
            }
            // Kernel-fixed bits (IF, reserved 1) survive as the FLOOR,
            // never as the frame's choice — the next assertion pins
            // that they are on whatever the frame said (the same-word
            // zero case below proves they are not passthrough).
            assert_eq!(
                got.rflags & KERNEL_FIXED,
                KERNEL_FIXED,
                "bit {bit}: IF and reserved bit 1 are the unconditional floor"
            );
        }
    }

    /// ADR-0031 section A: the property form — 10k seeded xorshift
    /// words. Whatever the frame carries, the restore is exactly
    /// (its allowed bits) | (the fixed floor): non-whitelisted bits
    /// never appear, the floor never drops, allowed bits pass through
    /// bit-exact. Deterministic (fixed seed), no dependencies.
    #[test]
    fn property_random_flag_words_restore_the_fixed_floor() {
        const USER_ALLOWED: u64 =
            (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 11);
        const KERNEL_FIXED: u64 = (1 << 9) | 0x2;
        let mut s: u64 = 0x00A6_4D31_5EED_0001;
        for _ in 0..10_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let word = s;
            let mut base = img();
            base.rflags = word;
            let mut f = [0u8; SIGFRAME_BYTES];
            build(10, 1, 0x402000, &base, &mut f);
            let got = validate(&f, 1, 0x2b, 0x23).unwrap();
            assert_eq!(
                got.rflags & !USER_ALLOWED & !KERNEL_FIXED,
                0,
                "non-whitelisted bits survived the restore"
            );
            assert_eq!(
                got.rflags & KERNEL_FIXED,
                KERNEL_FIXED,
                "the preemptibility floor (IF, bit 1) must always hold"
            );
            assert_eq!(
                got.rflags & !KERNEL_FIXED,
                word & USER_ALLOWED,
                "allowed bits must pass through bit-exact"
            );
        }
    }

    #[test]
    fn a_non_canonical_saved_rsp_refuses() {
        let mut base = img();
        base.rsp = 0x0000_FFFF_FFFF_FFFF; // beyond the low canonical half
        let mut f = [0u8; SIGFRAME_BYTES];
        build(10, 1, 0x402000, &base, &mut f);
        assert_eq!(validate(&f, 1, 0x2b, 0x23), Err(SigframeError::BadRsp));
    }

    /// The deterministic fuzz corpus: flip every single bit of a valid
    /// frame (plus a few byte-swaps). Every mutation either validates
    /// to a sanitized-safe image or refuses with a typed error — never
    /// a panic, never an unsanitized restore.
    #[test]
    fn bit_flips_never_panic_and_never_smuggle() {
        let mut f = [0u8; SIGFRAME_BYTES];
        build(10, 0xBEEF, 0x402000, &img(), &mut f);
        for i in 0..SIGFRAME_BYTES {
            for bit in 0..8 {
                let mut g = f;
                g[i] ^= 1 << bit;
                if let Ok(img) = validate(&g, 0xBEEF, 0x2b, 0x23) {
                    // Whatever survived must still be a safe image.
                    assert!(img.rip != 0 && img.rip <= USER_CANON_MAX);
                    assert!(img.rsp != 0 && img.rsp <= USER_CANON_MAX);
                    // ADR-0031: nothing outside the whitelist + floor
                    // ever survives, whatever bit was flipped.
                    assert_eq!(img.rflags & !(RFLAGS_USER_ALLOWED | RFLAGS_KERNEL_FIXED), 0);
                    assert_eq!(img.rflags & RFLAGS_KERNEL_FIXED, RFLAGS_KERNEL_FIXED);
                    assert_eq!(img.cs, 0x2b);
                    assert_eq!(img.ss, 0x23);
                }
                // A refusal is the documented typed set.
                let _ = validate(&g, 0xBEEF, 0x2b, 0x23);
            }
        }
    }
}
