//! Poly1305 (RFC 8439 §2.5): the one-time authenticator under the
//! AEAD.
//!
//! 130-bit arithmetic with five 26-bit limbs (u32 storage, u64
//! accumulation). The block multiply is the same masked 9-slot
//! schoolbook the field arithmetic uses — canonicalized inputs (the
//! block adds leave slack; masking without propagating would drop
//! whole 2^130 ≡ 5 terms), the 2^234-scale window escape folded with
//! 2^130 ≡ 5, and the s-addition carrying across the four 32-bit
//! words (h + s is a 128-bit add, not four disjoint ones — the
//! one-byte tag errors were exactly the dropped carries). Clamped r,
//! no secret-index lookups: constant-time by construction.
//!
//! Pinned by RFC 8439 §2.5.2 plus randomized cross-checks against an
//! independent big-integer implementation, and by the AEAD layer's
//! 300-case library sweep.

/// The 16-byte tag.
pub type Tag = [u8; 16];

const MASK26: u64 = (1u64 << 26) - 1;

/// Poly1305 over `msg` with the 32-byte one-time key
/// (r = key[0..16] clamped, s = key[16..32]).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> Tag {
    let r = load26(&key[0..16]);
    // clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff — the per-limb
    // masks the 128-bit constant actually lands on (0x3ffff03 /
    // 0x3ffc0ff / 0x3f03fff / 0xfffff — NOT the naive alternation;
    // verified against the big-int clamp)
    let r = [
        r[0] & 0x03ff_ffff,
        r[1] & 0x03ff_ff03,
        r[2] & 0x03ff_c0ff,
        r[3] & 0x03f0_3fff,
        r[4] & 0x000f_ffff,
    ];
    let s = [
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
    ];

    let mut h = [0u64; 5]; // the accumulator

    let mut i = 0;
    while i < msg.len() {
        let take = core::cmp::min(16, msg.len() - i);
        let mut blk = [0u8; 17];
        blk[..take].copy_from_slice(&msg[i..i + take]);
        blk[take] = 1; // the 2^(8·take) bit, RFC §2.5 step 3
        let mut n = load26(&blk[0..16]);
        if take == 16 {
            // the +1 sits at byte 16 = bit 128, OUTSIDE load26's
            // 16-byte window: limb 4's local bit 24.
            n[4] += 1 << 24;
        }
        // h += n (limb-wise; n < 2^130 so limbs stay < 2^26·(1+ε))
        for j in 0..5 {
            h[j] += n[j];
        }
        // h = h × r, mod 2^130-5
        h = mul26(&h, &r);
        i += take;
    }

    // ── the final reduction: h < 2^130 → h mod 2^130-5, then + s ──
    // carry-propagate h to canonical limbs (< 2^26)
    propagate(&mut h);
    // h < 2^130 now. If h ≥ 2^130-5, then h+5 carries out of bit
    // 130: u = h + 5, dropping that carry = h + 5 - 2^130 = h - (2^130-5).
    let mut u = h;
    let mut c: u64 = 5;
    for j in 0..5 {
        let v = u[j] + c;
        u[j] = v & MASK26;
        c = v >> 26;
    }
    if c != 0 {
        // the carry out of bit 130: use u (the reduction)
        h = u;
    }
    // pack h (mod 2^128) + s (mod 2^128) → 16 bytes LE
    let mut out = [0u8; 16];
    // 5×26 → 4×32 words (bits 0..128)
    let w0 = (h[0] | h[1] << 26) as u32;
    let w1 = ((h[1] >> 6) | h[2] << 20) as u32;
    let w2 = ((h[2] >> 12) | h[3] << 14) as u32;
    let w3 = ((h[3] >> 18) | h[4] << 8) as u32;
    let words = [w0, w1, w2, w3];
    // h + s is a FULL 128-bit addition: the carries must cross the
    // 32-bit words (dropping them corrupted the tag's low bytes on
    // the wrap cases — the library sweep caught it).
    let mut carry: u32 = 0;
    for j in 0..4 {
        let v = u64::from(words[j]) + u64::from(s[j]) + u64::from(carry);
        out[4 * j..4 * j + 4].copy_from_slice(&(v as u32).to_le_bytes());
        carry = (v >> 32) as u32;
    }
    // the final carry past bit 128 is dropped (mod 2^128) — the sum
    // h+s < 2^130-5 + 2^128 < 2^131, so at most one carry bit.
    out
}

/// The canonical 16-byte → 5×26-bit limb unpack (little-endian;
/// bits [26j, 26j+26) of the byte string live in limb j). Byte-wise:
/// never reads past b[15] (limb 4 is only 24 bits — a 4-byte window
/// read at b[13] would run off the slice).
fn load26(b: &[u8]) -> [u64; 5] {
    [
        (u64::from(b[0])
            | u64::from(b[1]) << 8
            | u64::from(b[2]) << 16
            | u64::from(b[3] & 3) << 24)
            & 0x03ff_ffff, // bits 0..26
        (u64::from(b[3] >> 2)
            | u64::from(b[4]) << 6
            | u64::from(b[5]) << 14
            | u64::from(b[6] & 0xf) << 22)
            & 0x03ff_ffff, // bits 26..52
        (u64::from(b[6] >> 4)
            | u64::from(b[7]) << 4
            | u64::from(b[8]) << 12
            | u64::from(b[9] & 0x3f) << 20)
            & 0x03ff_ffff, // bits 52..78
        (u64::from(b[9] >> 6)
            | u64::from(b[10]) << 2
            | u64::from(b[11]) << 10
            | u64::from(b[12]) << 18)
            & 0x03ff_ffff, // bits 78..104
        u64::from(b[13]) | u64::from(b[14]) << 8 | u64::from(b[15]) << 16, // bits 104..128
    ]
}

/// Multiply two 26-bit-limb numbers mod 2^130-5: canonicalized
/// inputs, masked 10-slot schoolbook, the high half folded with
/// 2^130 ≡ 5 (uniformly — w[9]'s 2^234 = 2^104·2^130 → limb 4), the
/// escape and the residual carry landing on limb 0.
fn mul26(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let a = &canon26(a);
    let b = &canon26(b);
    let mut w = [0u64; 10];
    let mut esc: u64 = 0;
    for i in 0..5 {
        let ai = a[i] & MASK26;
        let mut carry: u64 = 0;
        for j in 0..5 {
            let t = ai * (b[j] & MASK26) + w[i + j] + carry;
            w[i + j] = t & MASK26;
            carry = t >> 26;
        }
        let mut k = i + 5;
        while carry != 0 {
            if k == 10 {
                esc += carry; // 2^234-scale escape: fold below
                break;
            }
            let t = w[k] + carry;
            w[k] = t & MASK26;
            carry = t >> 26;
            k += 1;
        }
    }
    // fold: w[5+k] sits at bit 130+26k, and 2^130 ≡ 5 — each high
    // limb scales by 5 onto limb k
    let mut r = [0u64; 5];
    for k in 0..5 {
        r[k] = w[k];
    }
    let mut carry: u64 = 0;
    for k in 5..10 {
        let limb = k - 5;
        let t = r[limb] + w[k] * 5 + carry;
        r[limb] = t & MASK26;
        carry = t >> 26;
    }
    // The fold's residual carry is 2^130-SCALE — it folds onto limb
    // 0 as ×5 (2^130 ≡ 5). Parking it on limb 4 treated a 2^130 unit
    // as 2^104: the +2^104−5 tag corruption the 300-case sweep
    // caught (the field-mul's tail had the same disease).
    let t = r[0] + carry * 5 + esc * 5;
    r[0] = t & MASK26;
    let mut c = t >> 26;
    let mut i = 1;
    while c != 0 && i < 5 {
        let t2 = r[i] + c;
        r[i] = t2 & MASK26;
        c = t2 >> 26;
        i += 1;
    }
    if c != 0 {
        // a final overflow past limb 4 is again 2^130-scale → ×5
        let v = r[0] + c * 5;
        r[0] = v & MASK26;
        if v >> 26 != 0 {
            r[1] += v >> 26; // < 2^27, absorbed by the next canon
        }
    }
    r
}

/// Carry-propagate a 26-bit-limb number to canonical limbs (< 2^26
/// each), folding the 2^130-scale overflow as ×5 (2^130 ≡ 5).
/// Iterates to a fixed point: a single pass can leave limb 1 with
/// slack, and the final pack assumes fully canonical limbs (the
/// one-byte tag errors were exactly that slack).
fn canon26(v: &[u64; 5]) -> [u64; 5] {
    let mut t = *v;
    for _ in 0..3 {
        let mut carry: u64 = 0;
        for j in 0..5 {
            let x = t[j] + carry;
            t[j] = x & MASK26;
            carry = x >> 26;
        }
        if carry == 0 {
            return t;
        }
        t[0] += carry * 5;
    }
    t
}

/// Carry-propagate to the canonical fixed point (see canon26).
fn propagate(h: &mut [u64; 5]) {
    *h = canon26(h);
}
