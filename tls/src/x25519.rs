//! X25519 (RFC 7748): the Diffie–Hellman function of the TLS 1.3
//! handshake.
//!
//! Field arithmetic over GF(2^255 - 19) with five 51-bit limbs
//! (u64, 13 bits of headroom per limb — additions never overflow,
//! multiplication carries through a u128 accumulator). The scalar
//! multiplication is the RFC's Montgomery ladder: a FIXED 255-step
//! sequence, data-independent control flow, every field operation
//! executed exactly once per step, and the conditional swap is a
//! constant-time mask — the ladder's timing does not depend on the
//! scalar's bits.
//!
//! Inversion uses square-and-multiply over the CONSTANT exponent
//! p-2 = 2^255-21 (every multiply runs unconditionally — the
//! sequence is again data-fixed).
//!
//! Pinned by: RFC 7748 §6.1's two vectors, the §5.2 one-iteration
//! check, and randomized cross-checks against an independent
//! implementation (`tests`).

/// One field element: five 51-bit limbs, little-endian.
#[derive(Clone, Copy, Debug)]
pub struct Fe(pub(crate) [u64; 5]);

const MASK51: u64 = (1u64 << 51) - 1;

impl Fe {
    /// Zero.
    pub(crate) const fn zero() -> Fe {
        Fe([0; 5])
    }

    /// One.
    pub(crate) const fn one() -> Fe {
        Fe([1, 0, 0, 0, 0])
    }

    /// The modulus, p = 2^255-19, in 51-bit limbs.
    const P: Fe = Fe([(1u64 << 51) - 19, MASK51, MASK51, MASK51, MASK51]);

    /// From a 32-byte little-endian u-coordinate (RFC 7748
    /// decodeUCoordinate: the top bit is masked off).
    pub(crate) fn from_bytes_le(b: &[u8; 32]) -> Fe {
        let mut out = [0u64; 5];
        for i in 0..5 {
            // limb i covers bits [51i, 51i+51)
            let lo = i * 51 / 8;
            let sh = (i * 51 % 8) as u32;
            let mut v = u64::from(b[lo]) >> sh;
            for j in 1..8 {
                let idx = lo + j;
                let byte = if idx < 32 { b[idx] } else { 0 };
                v |= u64::from(byte) << (8 * j - sh as usize);
            }
            out[i] = v & MASK51;
        }
        // The packing keeps bits 204..254 (bit 255 never enters —
        // the RFC's mask, by construction).
        Fe(out)
    }

    /// To 32 little-endian bytes, fully reduced mod p.
    pub(crate) fn to_bytes_le(self) -> [u8; 32] {
        let mut t = self.0;
        // Two carry passes: every limb < 2^51, top carry folds as 19.
        for _ in 0..2 {
            let mut c: u64 = 0;
            for i in 0..5 {
                let a = u128::from(t[i]) + u128::from(c);
                t[i] = (a as u64) & MASK51;
                c = (a >> 51) as u64;
            }
            t[0] += c * 19; // 2^255 ≡ 19 (mod p)
                            // absorb a possible limb-0 overflow into limb 1
            let over = t[0] >> 51;
            if over != 0 {
                t[0] &= MASK51;
                t[1] += over;
            }
        }
        // Now t < 2^255 + small; reduce once more if t ≥ p.
        // Compute t - p with a borrow chain; no-borrow ⇒ t ≥ p ⇒ use
        // the difference.
        let mut d = t;
        let mut borrow: i128 = 0;
        for i in 0..5 {
            let v = i128::from(d[i]) - i128::from(Fe::P.0[i]) - borrow;
            if v < 0 {
                d[i] = (v + (1i128 << 51)) as u64;
                borrow = 1;
            } else {
                d[i] = v as u64;
                borrow = 0;
            }
        }
        if borrow == 0 {
            t = d;
        }
        // Serialize: bit i of the value ← bit (i mod 51) of limb
        // (i / 51).
        let mut out = [0u8; 32];
        for i in 0..5 {
            let mut v = t[i];
            let base = i * 51;
            for k in 0..51 {
                let bit = base + k;
                if bit < 256 {
                    out[bit / 8] |= ((v & 1) as u8) << (bit % 8);
                }
                v >>= 1;
            }
        }
        out
    }

    /// Add (limb-wise; one fold pass).
    pub(crate) fn add(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        let mut c: u64 = 0;
        for i in 0..5 {
            let a = u128::from(self.0[i]) + u128::from(o.0[i]) + u128::from(c);
            r[i] = (a as u64) & MASK51;
            c = (a >> 51) as u64;
        }
        r[0] += c * 19;
        let over = r[0] >> 51;
        if over != 0 {
            r[0] &= MASK51;
            r[1] += over;
        }
        Fe(r)
    }

    /// Subtract (self - o) mod p: borrow chain, then a conditional
    /// minus-19 when it underflowed.
    pub(crate) fn sub(&self, o: &Fe) -> Fe {
        // Canonical inputs: slack limbs (≤ ~2^52.5) would push a
        // limb difference below -2^51 and break the +2^51 wrap.
        let a = self.canon();
        let b = o.canon();
        let mut r = [0u64; 5];
        let mut borrow: i128 = 0;
        for i in 0..5 {
            let d = i128::from(a[i]) - i128::from(b[i]) - borrow;
            if d < 0 {
                r[i] = (d + (1i128 << 51)) as u64;
                borrow = 1;
            } else {
                r[i] = d as u64;
                borrow = 0;
            }
        }
        if borrow != 0 {
            // The chain's limbs represent a - b + 2^255 (the wrap);
            // 2^255 ≡ 19 (mod p), so the TRUE value is this minus 19.
            // (a - b ≥ -(p-1) ⇒ the wrapped value ≥ 20 ⇒ this never
            // underflows again.) Adding p back would double-count by
            // 19 — the live vectors caught that one.
            let mut c: i128 = 19;
            for i in 0..5 {
                let v = i128::from(r[i]) - c;
                if v < 0 {
                    r[i] = (v + (1i128 << 51)) as u64;
                    c = 1;
                } else {
                    r[i] = v as u64;
                    c = 0;
                }
            }
            debug_assert!(c == 0, "sub: the wrapped value was ≥ 20");
        }
        Fe(r)
    }

    /// Multiply: 5×5 schoolbook into a 10-limb u128 accumulator, then
    /// fold the high half with 2^255 ≡ 19. The inputs are
    /// canonicalized first: slack limbs (≤ ~2^52.5 out of add/sub)
    /// can carry the schoolbook's propagation past the window's top —
    /// a silent bit loss the full-limb vectors caught; canonical
    /// inputs keep every product inside, and the rare 2^510-scale
    /// escape is folded explicitly (2^510 ≡ 19² = 361).
    pub(crate) fn mul(&self, o: &Fe) -> Fe {
        let a_c = self.canon();
        let b_c = o.canon();
        let a = &a_c;
        let b = &b_c;
        let mut w = [0u128; 10];
        let mut esc: u128 = 0; // the carry that exits the window top
        for i in 0..5 {
            let mut carry: u128 = 0;
            for j in 0..5 {
                let t = u128::from(a[i]) * u128::from(b[j]) + w[i + j] + carry;
                w[i + j] = t & MASK51 as u128;
                carry = t >> 51;
            }
            let mut k = i + 5;
            while carry != 0 {
                if k == 10 {
                    // 2^510-scale: escapes even the widened window
                    // (canonical inputs bound it to a few units).
                    esc += carry;
                    break;
                }
                let t = w[k] + carry;
                w[k] = t & MASK51 as u128;
                carry = t >> 51;
                k += 1;
            }
        }
        // Fold: w[5+i] × 2^(255+51i) → ×19 onto limb i, carried.
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = w[i] as u64;
        }
        let mut c: u128 = 0;
        for i in 5..10 {
            let limb = i - 5;
            let t = u128::from(r[limb]) + w[i] * 19 + c;
            r[limb] = (t as u64) & MASK51;
            c = t >> 51;
        }
        // Both residual carries land on limb 0: the escape at 2^510
        // (≡ 19² = 361) and the fold's last carry c at 2^255 (≡ 19).
        // (The old tail parked c on limb 4 — a 2^255-scale carry does
        // not belong there; the full-limb vectors caught it as a
        // missing 18·19.)
        let t0 = u128::from(r[0]) + esc * 361 + c * 19;
        r[0] = (t0 as u64) & MASK51;
        let mut over = (t0 >> 51) as u64;
        let mut i = 1;
        while over != 0 && i < 5 {
            let t = u128::from(r[i]) + u128::from(over);
            r[i] = (t as u64) & MASK51;
            over = (t >> 51) as u64;
            i += 1;
        }
        // a final overflow past limb 4 is again 2^255-scale → 19
        if over != 0 {
            r[0] += over * 19;
            let v = r[0];
            r[0] = v & MASK51;
            let ov = v >> 51;
            if ov != 0 {
                r[1] += ov;
            }
        }
        Fe(r)
    }

    /// Canonical limbs (< 2^51 each): one carry pass, the top carry
    /// folds as 19 (2^255 ≡ 19).
    fn canon(&self) -> [u64; 5] {
        let mut t = self.0;
        let mut c: u64 = 0;
        for i in 0..5 {
            let a = u128::from(t[i]) + u128::from(c);
            t[i] = (a as u64) & MASK51;
            c = (a >> 51) as u64;
        }
        t[0] += c * 19;
        let over = t[0] >> 51;
        if over != 0 {
            t[0] &= MASK51;
            t[1] += over;
        }
        t
    }

    /// Square.
    pub(crate) fn square(&self) -> Fe {
        self.mul(self)
    }

    /// Invert: self^(p-2) — square-and-multiply over the constant
    /// exponent (data-fixed sequence).
    pub(crate) fn invert(&self) -> Fe {
        let mut result = Fe::one();
        for bit in (0..255).rev() {
            result = result.square();
            if exponent_bit(bit) {
                result = result.mul(self);
            }
        }
        result
    }
}

/// The bits of p-2 = 2^255-21, little-endian bit index. The value is
/// (2^255-1) - 20: all ones with bits 2 and 4 CLEAR (20 = 0b10100);
/// bit 255 is 0.
fn exponent_bit(bit: usize) -> bool {
    match bit {
        2 | 4 => false,
        0..=254 => true,
        _ => false,
    }
}

/// The RFC 7748 scalar clamp: clear bits 0..2 and 255, set bit 254.
pub fn clamp_scalar(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// X25519(k, u) — the raw function (RFC 7748 §5, the Montgomery
/// ladder). 32 bytes in, 32 bytes out.
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = clamp_scalar(*k);
    let x1 = Fe::from_bytes_le(u);
    let mut x2 = Fe::one();
    let mut z2 = Fe::zero();
    let mut x3 = x1;
    let mut z3 = Fe::one();
    let mut swap: u64 = 0;

    for t in (0..255).rev() {
        let k_t = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= k_t;
        // constant-time conditional swap of (x2,x3) and (z2,z3)
        cswap(&mut x2.0, &mut x3.0, swap);
        cswap(&mut z2.0, &mut z3.0, swap);
        swap = k_t;

        // One ladder step (RFC 7748 §5).
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let t0 = da.add(&cb);
        x3 = t0.square();
        let t1 = da.sub(&cb);
        z3 = x1.mul(&t1.square());
        x2 = aa.mul(&bb);
        // a24 = 121665
        let t2 = aa.add(&e.mul(&Fe([121_665, 0, 0, 0, 0])));
        z2 = e.mul(&t2);
    }

    cswap(&mut x2.0, &mut x3.0, swap);
    cswap(&mut z2.0, &mut z3.0, swap);

    // x2 / z2
    let out = x2.mul(&z2.invert());
    out.to_bytes_le()
}

/// Constant-time swap of two 5-limb arrays when `bit` is 1.
fn cswap(a: &mut [u64; 5], b: &mut [u64; 5], bit: u64) {
    let m = bit.wrapping_neg(); // 0 or all-ones
    for i in 0..5 {
        let (x, y) = (a[i], b[i]);
        a[i] = (x & !m) | (y & m);
        b[i] = (y & !m) | (x & m);
    }
}

/// The X25519 base point (u = 9).
pub const BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// The public key for a private scalar (clamped), over the base.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    x25519(sk, &BASE)
}

/// The shared secret (the handshake's ECDHE output).
pub fn shared(sk: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    x25519(sk, peer)
}
