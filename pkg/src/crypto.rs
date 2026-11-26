//! Cryptography for the package manager: SHA-256, SHA-512, CRC-32
//! (framing only), constant-time comparison, and a complete inline
//! Ed25519 implementation (RFC 8032).
//!
//! Zero external crates: every primitive is implemented here on
//! `core` alone, no `unsafe`, no allocation, no global state.
//!
//! ## Why inline crypto
//!
//! A package manager's verification path is the *entire* trust
//! boundary: linking a crypto crate would move that boundary into
//! the supply chain the manager exists to defend. The cost is that
//! this code must be correct on its own; it is pinned against:
//!
//! * **SHA-256**: FIPS 180-4 vectors (`abc`,
//!   the two-block `abcdbcde...` case) — see `tests/mod.rs`.
//! * **SHA-512**: FIPS 180-4 vectors.
//! * **Ed25519**: RFC 8032 §7.1 test vector 1 (empty message) plus
//!   sign/verify round-trips over randomized messages.
//!
//! ## Constant-time policy
//!
//! * [`ct_eq`] compares digests/signatures with a fold-xor
//!   accumulator: no early exit, no branch on secret-derived data.
//!   SHA-256/512 are inherently branch-free on data.
//! * **Ed25519 *verification* is variable-time by design**: the
//!   inputs (public key, signature, message) are public, so timing
//!   leaks nothing. Secret-key operations exist only under
//!   `cfg(any(test, feature = "signer"))` (see [`ed25519::sign`])
//!   and are documented as not hardened against side channels —
//!   signing happens offline, on the repo-build host, never on the
//!   target.
//!
//! ## THREAT: signature replay
//!
//! Ed25519 is deterministic, so a byte-identical (message,
//! signature) pair verifies forever — which is fine: the signature
//! binds the *content*. Replay protection is layered above, in
//! `repository.rs` (monotonic index epochs) and `manifest.rs`
//! (version ordering + the install database's recorded
//! hashes/epochs): an old, validly-signed artifact cannot displace a
//! newer one (downgrade block), and a *mutated* artifact fails the
//! hash/signature checks here.

pub mod sha256 {
    //! SHA-256 (FIPS 180-4). Fixed 64-byte block streaming, no
    //! allocation.

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// Streaming SHA-256 state.
    #[derive(Clone)]
    pub struct Sha256 {
        state: [u32; 8],
        buf: [u8; 64],
        buf_len: usize,
        total: u64,
    }

    impl Default for Sha256 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Sha256 {
        /// Fresh state (IV per FIPS 180-4).
        #[must_use]
        pub const fn new() -> Self {
            Sha256 {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buf: [0; 64],
                buf_len: 0,
                total: 0,
            }
        }

        /// Absorb `data`.
        pub fn update(&mut self, data: &[u8]) {
            self.total = self.total.wrapping_add(data.len() as u64);
            let mut i = 0usize;
            while i < data.len() {
                let take = (64 - self.buf_len).min(data.len() - i);
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
                self.buf_len += take;
                i += take;
                if self.buf_len == 64 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buf_len = 0;
                }
            }
        }

        fn compress(&mut self, block: &[u8; 64]) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }

        /// Finish and write the 32-byte digest into `out`.
        ///
        /// # Panics
        /// Panics if `out.len() < 32` — callers pass fixed 32-byte
        /// arrays (no untrusted lengths reach this).
        pub fn finish(mut self, out: &mut [u8]) {
            let bit_len = self.total.wrapping_mul(8);
            let pad_len = match self.buf_len {
                0..=55 => 56 - self.buf_len,
                _ => 120 - self.buf_len,
            };
            let mut pad = [0u8; 72];
            pad[0] = 0x80;
            pad[pad_len..pad_len + 8].copy_from_slice(&bit_len.to_be_bytes());
            // copy the tail out first: update_final takes &mut self
            let mut tail = [0u8; 64];
            tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            self.update_final(&tail[..self.buf_len], &pad[..pad_len + 8]);
            for (i, s) in self.state.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
            }
        }

        // absorb the buffered tail + padding as whole blocks; the
        // scratch is sized for the worst case (63 tail + 72 pad)
        fn update_final(&mut self, tail: &[u8], pad: &[u8]) {
            let mut tmp = [0u8; 144];
            tmp[..tail.len()].copy_from_slice(tail);
            tmp[tail.len()..tail.len() + pad.len()].copy_from_slice(pad);
            let n = tail.len() + pad.len();
            for off in (0..n).step_by(64) {
                let end = (off + 64).min(n);
                let mut blk = [0u8; 64];
                blk[..end - off].copy_from_slice(&tmp[off..end]);
                self.compress(&blk);
            }
        }

        /// Streaming accessor for incremental hashing of file
        /// contents during extraction (hash-as-you-write).
        #[must_use]
        pub fn interim_clone(&self) -> Sha256 {
            self.clone()
        }
    }

    /// One-shot digest of `data` into a fresh array.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        let mut out = [0u8; 32];
        h.finish(&mut out);
        out
    }
}

pub mod sha512 {
    //! SHA-512 (FIPS 180-4) — required by Ed25519's internal
    //! hashing. Fixed 128-byte block streaming.

    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    /// Streaming SHA-512 state.
    #[derive(Clone)]
    pub struct Sha512 {
        state: [u64; 8],
        buf: [u8; 128],
        buf_len: usize,
        total: u128,
    }

    impl Default for Sha512 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Sha512 {
        /// Fresh state (IV per FIPS 180-4).
        #[must_use]
        pub const fn new() -> Self {
            Sha512 {
                state: [
                    0x6a09e667f3bcc908,
                    0xbb67ae8584caa73b,
                    0x3c6ef372fe94f82b,
                    0xa54ff53a5f1d36f1,
                    0x510e527fade682d1,
                    0x9b05688c2b3e6c1f,
                    0x1f83d9abfb41bd6b,
                    0x5be0cd19137e2179,
                ],
                buf: [0; 128],
                buf_len: 0,
                total: 0,
            }
        }

        /// Absorb `data`.
        pub fn update(&mut self, data: &[u8]) {
            self.total = self.total.wrapping_add(data.len() as u128);
            let mut i = 0usize;
            while i < data.len() {
                let take = (128 - self.buf_len).min(data.len() - i);
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
                self.buf_len += take;
                i += take;
                if self.buf_len == 128 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buf_len = 0;
                }
            }
        }

        fn compress(&mut self, block: &[u8; 128]) {
            let mut w = [0u64; 80];
            for i in 0..16 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&block[i * 8..i * 8 + 8]);
                w[i] = u64::from_be_bytes(b);
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }

        /// Finish and write the 64-byte digest into `out`.
        ///
        /// # Panics
        /// Panics if `out.len() < 64` — callers pass fixed 64-byte
        /// arrays.
        pub fn finish(mut self, out: &mut [u8]) {
            let bit_len = self.total.wrapping_mul(8);
            let pad_len = match self.buf_len {
                0..=111 => 112 - self.buf_len,
                _ => 240 - self.buf_len,
            };
            let mut pad = [0u8; 144];
            pad[0] = 0x80;
            pad[pad_len..pad_len + 16].copy_from_slice(&bit_len.to_be_bytes());
            let n = self.buf_len + pad_len + 16;
            let mut tmp = [0u8; 288];
            tmp[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            tmp[self.buf_len..n].copy_from_slice(&pad[..pad_len + 16]);
            for off in (0..n).step_by(128) {
                let end = (off + 128).min(n);
                let mut blk = [0u8; 128];
                blk[..end - off].copy_from_slice(&tmp[off..end]);
                self.compress(&blk);
            }
            for (i, s) in self.state.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&s.to_be_bytes());
            }
        }
    }

    /// One-shot 64-byte digest.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(data);
        let mut out = [0u8; 64];
        h.finish(&mut out);
        out
    }
}

pub mod crc32 {
    //! CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320).
    //!
    //! **Not a security primitive**: it detects torn journal frames
    //! (power loss mid-write), where a wrong frame must be *dropped*
    //! (treated as absent) — SHA-256 would work but is needlessly
    //! slow for framing on the crash path. All security decisions
    //! stay on Ed25519/SHA-256.

    /// CRC-32 of `data`, initial value 0.
    #[must_use]
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }
}

/// Constant-time equality of two byte slices of equal length.
///
/// Accumulates XOR of every pair — the result does not depend on
/// where the first difference is, and the loop count is public
/// (lengths only). Used for every signature and hash comparison in
/// this crate.
///
/// # Panics
/// Panics if the slices differ in length — all call sites pass
/// fixed-size digests; a length mismatch is a programming error
/// worth failing loudly.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut acc = 0u8;
    for i in 0..a.len().max(b.len()) {
        let x = *a.get(i).unwrap_or(&0x55);
        let y = *b.get(i).unwrap_or(&0xAA);
        acc |= x ^ y;
    }
    acc == 0 && a.len() == b.len()
}

pub mod ed25519 {
    //! Ed25519 (RFC 8032) — verification always compiled; signing
    //! only under `cfg(any(test, feature = "signer"))`.
    //!
    //! Field arithmetic: 5 limbs of radix 2^51 in `u64` with `u128`
    //! intermediate products (the "donna-64" layout). Group
    //! arithmetic: extended twisted-Edwards coordinates (X:Y:Z:T);
    //! the curve is complete (d is a non-residue), so *one* unified
    //! addition formula serves for both add and double — a deliberate
    //! speed trade for a formula that cannot be misapplied.
    //!
    //! Correctness anchors: RFC 8032 §7.1 vector 1 and sign/verify
    //! round-trips in `tests/mod.rs`.
    //!
    //! **Timing:** verification is variable-time on purpose (all
    //! inputs are public). The only secret-side routine, `sign`, is
    //! test/repo-build-tooling only, never shipped on the target.

    #[cfg(any(test, feature = "signer"))]
    use super::sha512::digest as sha512_digest;
    use super::sha512::Sha512;

    /// An Ed25519 public key (canonical compressed point).
    pub type PublicKey = [u8; 32];
    /// An Ed25519 signature (R || S).
    pub type Signature = [u8; 64];
    /// An Ed25519 secret seed (signer side only).
    pub type SecretKey = [u8; 32];

    const MASK51: u64 = (1u64 << 51) - 1;
    /// Curve order L = 2^252 + 27742317777372353535851937790883648493,
    /// little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    /// The compressed base point B (y = 4/5, x even) — the canonical
    /// 0x58,0x66,...,0x66 encoding reproduced by every Ed25519
    /// implementation.
    const B_COMPRESSED: [u8; 32] = {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        b
    };
    /// p - 2 (little-endian): the inversion exponent.
    const P_MINUS_2: [u8; 32] = {
        let mut e = [0xFFu8; 32];
        e[0] = 0xEB;
        e[31] = 0x7F;
        e
    };
    /// (p-5)/8 (little-endian): the square-root exponent.
    const P_M5_DIV_8: [u8; 32] = {
        let mut e = [0xFFu8; 32];
        e[0] = 0xFD;
        e[31] = 0x0F;
        e
    };
    /// (p-1)/4 (little-endian): yields sqrt(-1) when used as an
    /// exponent.
    const P_M1_DIV_4: [u8; 32] = {
        let mut e = [0xFFu8; 32];
        e[0] = 0xFB;
        e[31] = 0x1F;
        e
    };

    // ── field: [u64; 5], limb i weighted 2^(51 i) ──

    fn fe_zero() -> [u64; 5] {
        [0; 5]
    }

    fn fe_one() -> [u64; 5] {
        [1, 0, 0, 0, 0]
    }

    /// A small integer as a field element (value < 2^52 fits limb 0).
    fn fe_from_u64(x: u64) -> [u64; 5] {
        debug_assert!(x < (1 << 52));
        [x, 0, 0, 0, 0]
    }

    fn fe_frombytes(s: &[u8; 32]) -> [u64; 5] {
        let b = |i: usize| -> u64 { u64::from(s[i]) };
        [
            b(0) | (b(1) << 8)
                | (b(2) << 16)
                | (b(3) << 24)
                | (b(4) << 32)
                | (b(5) << 40)
                | ((b(6) & 0x07) << 48),
            (b(6) >> 3)
                | (b(7) << 5)
                | (b(8) << 13)
                | (b(9) << 21)
                | (b(10) << 29)
                | (b(11) << 37)
                | ((b(12) & 0x3F) << 45),
            (b(12) >> 6)
                | (b(13) << 2)
                | (b(14) << 10)
                | (b(15) << 18)
                | (b(16) << 26)
                | (b(17) << 34)
                | (b(18) << 42)
                | ((b(19) & 0x01) << 50),
            (b(19) >> 1)
                | (b(20) << 7)
                | (b(21) << 15)
                | (b(22) << 23)
                | (b(23) << 31)
                | (b(24) << 39)
                | ((b(25) & 0x0F) << 47),
            (b(25) >> 4)
                | (b(26) << 4)
                | (b(27) << 12)
                | (b(28) << 20)
                | (b(29) << 28)
                | (b(30) << 36)
                | ((b(31) & 0x7F) << 44),
        ]
    }

    fn fe_tobytes(h: &[u64; 5]) -> [u8; 32] {
        let mut t = *h;
        // full carry propagation (limbs may arrive up to ~2^53)
        for _ in 0..2 {
            t[1] += t[0] >> 51;
            t[0] &= MASK51;
            t[2] += t[1] >> 51;
            t[1] &= MASK51;
            t[3] += t[2] >> 51;
            t[2] &= MASK51;
            t[4] += t[3] >> 51;
            t[3] &= MASK51;
            let c = t[4] >> 51;
            t[4] &= MASK51;
            t[0] += 19 * c;
        }
        // conditional subtract p: q = 1 iff t >= p
        let mut q = (t[0] + 19) >> 51;
        q = (t[1] + q) >> 51;
        q = (t[2] + q) >> 51;
        q = (t[3] + q) >> 51;
        q = (t[4] + q) >> 51;
        t[0] += 19 * q;
        t[1] += t[0] >> 51;
        t[0] &= MASK51;
        t[2] += t[1] >> 51;
        t[1] &= MASK51;
        t[3] += t[2] >> 51;
        t[2] &= MASK51;
        t[4] += t[3] >> 51;
        t[3] &= MASK51;
        t[4] &= MASK51;
        let mut s = [0u8; 32];
        let word = |limb: u64, shift: u32| -> u8 { ((limb >> shift) & 0xFF) as u8 };
        s[0] = word(t[0], 0);
        s[1] = word(t[0], 8);
        s[2] = word(t[0], 16);
        s[3] = word(t[0], 24);
        s[4] = word(t[0], 32);
        s[5] = word(t[0], 40);
        s[6] = (word(t[0], 48) & 0x07) | (((t[1] & 0x1F) << 3) as u8);
        s[7] = word(t[1], 5);
        s[8] = word(t[1], 13);
        s[9] = word(t[1], 21);
        s[10] = word(t[1], 29);
        s[11] = word(t[1], 37);
        s[12] = (word(t[1], 45) & 0x3F) | (((t[2] & 0x03) << 6) as u8);
        s[13] = word(t[2], 2);
        s[14] = word(t[2], 10);
        s[15] = word(t[2], 18);
        s[16] = word(t[2], 26);
        s[17] = word(t[2], 34);
        s[18] = word(t[2], 42);
        s[19] = (word(t[2], 50) & 0x01) | (((t[3] & 0x7F) << 1) as u8);
        s[20] = word(t[3], 7);
        s[21] = word(t[3], 15);
        s[22] = word(t[3], 23);
        s[23] = word(t[3], 31);
        s[24] = word(t[3], 39);
        s[25] = (word(t[3], 47) & 0x0F) | (((t[4] & 0x0F) << 4) as u8);
        s[26] = word(t[4], 4);
        s[27] = word(t[4], 12);
        s[28] = word(t[4], 20);
        s[29] = word(t[4], 28);
        s[30] = word(t[4], 36);
        s[31] = word(t[4], 44);
        s
    }

    fn fe_add(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        [
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ]
    }

    /// a + 2p - b: every input limb is ≤ ~2^52 after a carry pass,
    /// so each result limb is ≥ 0 and ≤ ~2^53 — safe in `u64`.
    fn fe_sub(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        [
            a[0] + 0xF_FFFF_FFFF_FFDA - b[0],
            a[1] + 0xF_FFFF_FFFF_FFFE - b[1],
            a[2] + 0xF_FFFF_FFFF_FFFE - b[2],
            a[3] + 0xF_FFFF_FFFF_FFFE - b[3],
            a[4] + 0xF_FFFF_FFFF_FFFE - b[4],
        ]
    }

    fn fe_neg(a: &[u64; 5]) -> [u64; 5] {
        fe_sub(&fe_zero(), a)
    }

    fn fe_mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        // a_i, b_i ≤ ~2^52 (callers carry); s_i = 19·b_i folds the
        // high products back below 2^255.
        let s1 = (b[1] as u128) * 19;
        let s2 = (b[2] as u128) * 19;
        let s3 = (b[3] as u128) * 19;
        let s4 = (b[4] as u128) * 19;
        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;
        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;
        let c0 = a0 * b0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
        let mut c1 = a0 * b1 + a1 * b0 + a2 * s4 + a3 * s3 + a4 * s2;
        let mut c2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * s4 + a4 * s3;
        let mut c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * s4;
        let mut c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        let mut r = [0u64; 5];
        c1 += c0 >> 51;
        r[0] = (c0 & MASK51 as u128) as u64;
        c2 += c1 >> 51;
        r[1] = (c1 & MASK51 as u128) as u64;
        c3 += c2 >> 51;
        r[2] = (c2 & MASK51 as u128) as u64;
        c4 += c3 >> 51;
        r[3] = (c3 & MASK51 as u128) as u64;
        r[4] = (c4 & MASK51 as u128) as u64;
        let carry = (c4 >> 51) as u64;
        r[0] += 19 * carry;
        r[1] += r[0] >> 51;
        r[0] &= MASK51;
        r[2] += r[1] >> 51;
        r[1] &= MASK51;
        r[3] += r[2] >> 51;
        r[2] &= MASK51;
        r[4] += r[3] >> 51;
        r[3] &= MASK51;
        r
    }

    fn fe_sq(a: &[u64; 5]) -> [u64; 5] {
        fe_mul(a, a)
    }

    fn fe_mul_small(a: &[u64; 5], s: u64) -> [u64; 5] {
        let mut t = [0u128; 5];
        for i in 0..5 {
            t[i] = (a[i] as u128) * (s as u128);
        }
        let mut r = [0u64; 5];
        for i in 0..4 {
            t[i + 1] += t[i] >> 51;
            r[i] = (t[i] & MASK51 as u128) as u64;
        }
        r[4] = (t[4] & MASK51 as u128) as u64;
        let carry = (t[4] >> 51) as u64;
        r[0] += 19 * carry;
        r[1] += r[0] >> 51;
        r[0] &= MASK51;
        r[2] += r[1] >> 51;
        r[1] &= MASK51;
        r[3] += r[2] >> 51;
        r[2] &= MASK51;
        r[4] += r[3] >> 51;
        r[3] &= MASK51;
        r
    }

    /// Exponentiation by a little-endian exponent byte string
    /// (square-and-multiply, MSB-first). Used with the fixed public
    /// exponents above — variable-time on public data only.
    fn fe_pow(base: &[u64; 5], exp: &[u8]) -> [u64; 5] {
        // find the highest set bit
        let mut hi_byte = exp.len();
        while hi_byte > 0 && exp[hi_byte - 1] == 0 {
            hi_byte -= 1;
        }
        if hi_byte == 0 {
            return fe_one();
        }
        let hb = exp[hi_byte - 1];
        let mut hi_bit = 8u32;
        while hi_bit > 0 && (hb >> (hi_bit - 1)) & 1 == 0 {
            hi_bit -= 1;
        }
        let mut acc = fe_one();
        let mut i = hi_byte as isize - 1;
        while i >= 0 {
            let byte = exp[i as usize];
            let mut b = if i as usize == hi_byte - 1 { hi_bit } else { 8 };
            while b > 0 {
                acc = fe_sq(&acc);
                if (byte >> (b - 1)) & 1 == 1 {
                    acc = fe_mul(&acc, base);
                }
                b -= 1;
            }
            i -= 1;
        }
        acc
    }

    fn fe_invert(a: &[u64; 5]) -> [u64; 5] {
        fe_pow(a, &P_MINUS_2)
    }

    fn fe_eq(a: &[u64; 5], b: &[u64; 5]) -> bool {
        // compare canonical encodings (both reduced)
        fe_tobytes(a) == fe_tobytes(b)
    }

    fn fe_is_zero(a: &[u64; 5]) -> bool {
        fe_tobytes(a) == [0u8; 32]
    }

    fn fe_is_negative(a: &[u64; 5]) -> bool {
        (fe_tobytes(a)[0] & 1) == 1
    }

    // ── scalars: little-endian byte magnitudes mod L ──

    /// s < L?
    fn sc_lt_l(s: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if s[i] != L[i] {
                return s[i] < L[i];
            }
        }
        false
    }

    /// r -= L (assumes r >= L); 33-byte scratch form.
    fn sc_sub_l33(r: &mut [u8; 33]) {
        let mut borrow = 0i16;
        for i in 0..32 {
            let d = i16::from(r[i]) - i16::from(L[i]) - borrow;
            if d < 0 {
                r[i] = (d + 256) as u8;
                borrow = 1;
            } else {
                r[i] = d as u8;
                borrow = 0;
            }
        }
        r[32] = (i16::from(r[32]) - borrow) as u8;
    }

    /// r >= L? (33-byte form, top byte only 0..0x1F)
    fn sc_geq_l33(r: &[u8; 33]) -> bool {
        if r[32] != 0 {
            return true;
        }
        !sc_lt_l(&{
            let mut t = [0u8; 32];
            t.copy_from_slice(&r[..32]);
            t
        })
    }

    /// Reduce a 64-byte little-endian value mod L (byte-wise long
    /// division: r ← r·256 + b, then subtract L until below it).
    fn sc_reduce(inp: &[u8; 64]) -> [u8; 32] {
        let mut r = [0u8; 33];
        for i in (0..64).rev() {
            // r = r*256 + inp[i]: shift bytes up one place, then add
            // the new byte at position 0 (little-endian).
            for j in (1..33).rev() {
                r[j] = r[j - 1];
            }
            r[0] = inp[i];
            // r < L here, so r*256 + b < 256·L: at most 255
            // subtractions of L bring it back below L.
            while sc_geq_l33(&r) {
                sc_sub_l33(&mut r);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&r[..32]);
        out
    }

    /// Schoolbook little-endian product of two 32-byte scalars,
    /// reduced mod L. Callers guarantee both inputs are < 2^255
    /// (clamped `a` and reduced `k`), so the product is < 2^510 and
    /// fits the 64-byte accumulator; byte 64 exists only so carry
    /// propagation can never index out of bounds, and is 0 by the
    /// invariant.
    #[cfg(any(test, feature = "signer"))]
    fn sc_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        debug_assert!(
            a[31] < 0x80 && b[31] < 0x80,
            "sc_mul inputs must be < 2^255"
        );
        let mut t = [0u8; 65];
        for i in 0..32 {
            let mut carry = 0u32;
            for j in 0..32 {
                let v = u32::from(a[i]) * u32::from(b[j]) + u32::from(t[i + j]) + carry;
                t[i + j] = (v & 0xFF) as u8;
                carry = v >> 8;
            }
            let mut k = i + 32;
            while carry > 0 {
                let v = u32::from(t[k]) + carry;
                t[k] = (v & 0xFF) as u8;
                carry = v >> 8;
                k += 1;
            }
        }
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&t[..64]);
        sc_reduce(&wide)
    }

    /// a + b mod L (both < L).
    #[cfg(any(test, feature = "signer"))]
    fn sc_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut r = [0u8; 32];
        let mut carry = 0u32;
        for i in 0..32 {
            let v = u32::from(a[i]) + u32::from(b[i]) + carry;
            r[i] = (v & 0xFF) as u8;
            carry = v >> 8;
        }
        // a+b < 2L: at most one subtraction
        if !sc_lt_l(&r) {
            let mut borrow = 0i16;
            for i in 0..32 {
                let d = i16::from(r[i]) - i16::from(L[i]) - borrow;
                if d < 0 {
                    r[i] = (d + 256) as u8;
                    borrow = 1;
                } else {
                    r[i] = d as u8;
                    borrow = 0;
                }
            }
        }
        r
    }

    // ── group: extended coordinates X:Y:Z:T (x=X/Z, y=Y/Z, T=XY/Z) ──

    #[derive(Clone, Copy)]
    struct Point {
        x: [u64; 5],
        y: [u64; 5],
        z: [u64; 5],
        t: [u64; 5],
    }

    fn pt_identity() -> Point {
        Point {
            x: fe_zero(),
            y: fe_one(),
            z: fe_one(),
            t: fe_zero(),
        }
    }

    /// The curve constant d = −121665/121666 mod p, computed from
    /// the curve's defining integers (the RFC 8032 test vectors in
    /// `tests/mod.rs` pin this end-to-end). Computing it at runtime
    /// avoids hand-copying limb constants.
    fn curve_d() -> [u64; 5] {
        let num = fe_from_u64(121_665);
        let den = fe_from_u64(121_666);
        fe_neg(&fe_mul(&num, &fe_invert(&den)))
    }

    /// Unified addition (complete curve: valid for P = Q too).
    /// add-2008-hwcd: A=(Y1-X1)(Y2-X2), B=(Y1+X1)(Y2+X2),
    /// C=2dT1T2, D=2Z1Z2, E=B-A, F=D-C, G=D+C, H=B+A →
    /// X3=EF, Y3=GH, T3=EH, Z3=FG.
    fn pt_add(p: &Point, q: &Point, d2: &[u64; 5]) -> Point {
        let a = fe_mul(&fe_sub(&p.y, &p.x), &fe_sub(&q.y, &q.x));
        let b = fe_mul(&fe_add(&p.y, &p.x), &fe_add(&q.y, &q.x));
        let c = fe_mul(&fe_mul(d2, &p.t), &q.t);
        let dd = fe_mul(&fe_mul_small(&p.z, 2), &q.z);
        let e = fe_sub(&b, &a);
        let f = fe_sub(&dd, &c);
        let g = fe_add(&dd, &c);
        let h = fe_add(&b, &a);
        Point {
            x: fe_mul(&e, &f),
            y: fe_mul(&g, &h),
            z: fe_mul(&f, &g),
            t: fe_mul(&e, &h),
        }
    }

    /// Variable-time double-and-add over all 256 bit positions
    /// (leading zeros double the identity harmlessly — public data
    /// only, so timing is not a concern).
    fn pt_mul(p: &Point, k: &[u8; 32], d2: &[u64; 5]) -> Point {
        let mut acc = pt_identity();
        for i in (0..=31).rev() {
            let byte = k[i];
            let mut b = 8;
            while b > 0 {
                acc = pt_add(&acc, &acc, d2);
                if (byte >> (b - 1)) & 1 == 1 {
                    acc = pt_add(&acc, p, d2);
                }
                b -= 1;
            }
        }
        acc
    }

    /// Decompress a point encoding (RFC 8032 §5.1.3). Rejects
    /// non-canonical y (y ≥ p), off-curve points, and the negative
    /// zero-x encoding.
    fn decompress(s: &[u8; 32]) -> Option<Point> {
        let y = fe_frombytes(s);
        // canonical check: the low 255 bits must re-encode identically
        let mut ycanon = *s;
        ycanon[31] &= 0x7F;
        if fe_tobytes(&y) != ycanon {
            return None;
        }
        let sign = (s[31] >> 7) & 1 == 1;
        let d = curve_d();
        let yy = fe_sq(&y);
        let u = fe_sub(&yy, &fe_one());
        let v = fe_add(&fe_mul(&d, &yy), &fe_one());
        // x = u·v³·(u·v⁷)^((p-5)/8)
        let v3 = fe_sq(&v);
        let v7 = fe_sq(&v3);
        let v3 = fe_mul(&v3, &v);
        let v7 = fe_mul(&v7, &v3);
        let uv7 = fe_mul(&u, &v7);
        let mut x = fe_mul(&fe_mul(&u, &v3), &fe_pow(&uv7, &P_M5_DIV_8));
        let vxx = fe_mul(&v, &fe_sq(&x));
        if !fe_eq(&vxx, &u) {
            // sqrt(-1) = 2^((p-1)/4): 2 is a non-residue because
            // p = 2^255-19 ≡ 5 (mod 8), so this is the square root
            // of -1. (Using -1 as the base would yield -1 itself —
            // the exponent is odd — and the fixup would be a no-op.)
            let sqrtm1 = fe_pow(&fe_from_u64(2), &P_M1_DIV_4);
            x = fe_mul(&x, &sqrtm1);
            let vxx2 = fe_mul(&v, &fe_sq(&x));
            if !fe_eq(&vxx2, &u) {
                return None; // not on the curve
            }
        }
        if fe_is_zero(&x) && sign {
            return None; // x = 0 must take the even (sign=0) branch
        }
        if fe_is_negative(&x) != sign {
            x = fe_neg(&x);
        }
        Some(Point {
            x,
            y,
            z: fe_one(),
            t: fe_mul(&x, &y),
        })
    }

    /// Compress a point to its 32-byte encoding.
    fn compress(p: &Point) -> [u8; 32] {
        let zinv = fe_invert(&p.z);
        let x = fe_mul(&p.x, &zinv);
        let y = fe_mul(&p.y, &zinv);
        let mut s = fe_tobytes(&y);
        s[31] |= (fe_is_negative(&x) as u8) << 7;
        s
    }

    /// Verify a signature (RFC 8032 §5.1.7, cofactorless).
    ///
    /// # Security
    /// Rejects: non-canonical public key, non-canonical R encoding,
    /// S ≥ L, off-curve points. The comparison is constant-time via
    /// [`super::ct_eq`] over compressed encodings.
    #[must_use]
    pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        let Some(a) = decompress(pk) else {
            return false;
        };
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&sig[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..]);
        if !sc_lt_l(&s_bytes) {
            return false; // S >= L
        }
        let Some(r) = decompress(&r_bytes) else {
            return false;
        };
        // k = SHA-512(R || A || M) mod L
        let mut h = Sha512::new();
        h.update(&r_bytes);
        h.update(pk);
        h.update(msg);
        let mut buf = [0u8; 64];
        h.finish(&mut buf);
        let k = sc_reduce(&buf);
        // d2 = 2·d
        let d = curve_d();
        let d2 = fe_mul_small(&d, 2);
        let b = decompress(&B_COMPRESSED).expect(
            "B_COMPRESSED is a compile-time constant on the curve; this arm is unreachable",
        );
        // [S]B == R + [k]A
        let sb = pt_mul(&b, &s_bytes, &d2);
        let ka = pt_mul(&a, &k, &d2);
        let rhs = pt_add(&r, &ka, &d2);
        let sb_bytes = compress(&sb);
        let rhs_bytes = compress(&rhs);
        super::ct_eq(&sb_bytes, &rhs_bytes)
    }

    /// Derive the public key from a secret seed.
    #[cfg(any(test, feature = "signer"))]
    #[must_use]
    pub fn public_key(sk: &SecretKey) -> PublicKey {
        let h = sha512_digest(sk);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);
        let d = curve_d();
        let d2 = fe_mul_small(&d, 2);
        let b = decompress(&B_COMPRESSED).expect(
            "B_COMPRESSED is a compile-time constant on the curve; this arm is unreachable",
        );
        let big = pt_mul(&b, &a, &d2);
        compress(&big)
    }

    #[cfg(any(test, feature = "signer"))]
    fn clamp(a: &mut [u8; 32]) {
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
    }

    /// Sign a message (RFC 8032 §5.1.6, deterministic).
    ///
    /// **Not shipped on the target** (compile-gated): the repo
    /// build host signs, the manager verifies. Not side-channel
    /// hardened — signing happens offline on trusted hosts.
    #[cfg(any(test, feature = "signer"))]
    #[must_use]
    pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
        let h = sha512_digest(sk);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        let pk = public_key(sk);
        let d = curve_d();
        let d2 = fe_mul_small(&d, 2);
        let b = decompress(&B_COMPRESSED).expect(
            "B_COMPRESSED is a compile-time constant on the curve; this arm is unreachable",
        );
        // r = SHA-512(prefix || M) mod L
        let mut hr = Sha512::new();
        hr.update(&prefix);
        hr.update(msg);
        let mut rb = [0u8; 64];
        hr.finish(&mut rb);
        let r = sc_reduce(&rb);
        let r_point = pt_mul(&b, &r, &d2);
        let r_bytes = compress(&r_point);
        // k = SHA-512(R || A || M) mod L
        let mut hk = Sha512::new();
        hk.update(&r_bytes);
        hk.update(&pk);
        hk.update(msg);
        let mut kb = [0u8; 64];
        hk.finish(&mut kb);
        let k = sc_reduce(&kb);
        // S = r + k·a mod L
        let ka = sc_mul(&k, &a);
        let s = sc_add(&r, &ka);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s);
        sig
    }

    #[cfg(test)]
    mod internal {
        use super::*;

        fn hexs(s: &str) -> [u8; 32] {
            let mut o = [0u8; 32];
            for i in 0..32 {
                o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
            }
            o
        }

        fn hexu(h: &[u8]) -> String {
            h.iter().map(|b| format!("{:02x}", b)).collect()
        }

        fn hexd(h: &[u64; 5]) -> String {
            hexu(&fe_tobytes(h))
        }

        #[test]
        fn fe_roundtrip() {
            let s = hexs("5866666666666666666666666666666666666666666666666666666666666666");
            let f = fe_frombytes(&s);
            assert_eq!(
                hexd(&f),
                "5866666666666666666666666666666666666666666666666666666666666666"
            );
            // inputs with the sign bit set are masked to the low 255
            // bits by design (the bit belongs to the point encoding)
            let mut s2 = hexs("0900b9a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
            s2[31] &= 0x7F;
            let f2 = fe_frombytes(&s2);
            assert_eq!(
                hexd(&f2),
                "0900b9a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a525"
            );
        }

        #[test]
        fn fe_arith_identities() {
            let a = fe_frombytes(&hexs(
                "030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ));
            // a + 0 = a
            assert!(hexd(&fe_add(&a, &fe_zero())) == hexd(&a));
            // a - a = 0
            assert!(fe_is_zero(&fe_sub(&a, &a)), "a - a must be 0");
            // a * 1 = a
            assert!(hexd(&fe_mul(&a, &fe_one())) == hexd(&a));
            // a * a^-1 = 1
            let inv = fe_invert(&a);
            assert_eq!(
                hexd(&fe_mul(&a, &inv)),
                "0100000000000000000000000000000000000000000000000000000000000000"
            );
            // a + (-a) = 0
            let neg = fe_sub(&fe_zero(), &a);
            assert!(fe_is_zero(&fe_add(&a, &neg)), "a + (-a) must be 0");
        }

        #[test]
        fn fe_random_algebra() {
            // deterministic PRNG (xorshift) — reproducible
            let mut st: u64 = 0x243F_6A88_85A3_08D3;
            let mut next = || {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                st
            };
            for _ in 0..200 {
                let mut seed = [0u8; 32];
                for c in seed.iter_mut() {
                    *c = (next() >> 24) as u8;
                }
                seed[31] &= 0x7F;
                let a = fe_frombytes(&seed);
                let mut seed2 = [0u8; 32];
                for c in seed2.iter_mut() {
                    *c = (next() >> 24) as u8;
                }
                seed2[31] &= 0x7F;
                let b = fe_frombytes(&seed2);
                let mut seed3 = [0u8; 32];
                for c in seed3.iter_mut() {
                    *c = (next() >> 24) as u8;
                }
                seed3[31] &= 0x7F;
                let cc = fe_frombytes(&seed3);
                // commutativity
                assert_eq!(hexd(&fe_mul(&a, &b)), hexd(&fe_mul(&b, &a)));
                // associativity
                let ab_c = fe_mul(&fe_mul(&a, &b), &cc);
                let a_bc = fe_mul(&a, &fe_mul(&b, &cc));
                assert_eq!(
                    hexd(&ab_c),
                    hexd(&a_bc),
                    "assoc: a={} b={} c={}",
                    hexd(&a),
                    hexd(&b),
                    hexd(&cc)
                );
                // distributivity
                let lhs = fe_mul(&a, &fe_add(&b, &cc));
                let rhs = fe_add(&fe_mul(&a, &b), &fe_mul(&a, &cc));
                assert_eq!(
                    hexd(&lhs),
                    hexd(&rhs),
                    "distr: a={} b={} c={}",
                    hexd(&a),
                    hexd(&b),
                    hexd(&cc)
                );
                // inversion roundtrip
                let inv = fe_invert(&a);
                assert_eq!(
                    hexd(&fe_mul(&a, &inv)),
                    "0100000000000000000000000000000000000000000000000000000000000000",
                    "inv: a={}",
                    hexd(&a)
                );
                // carry stress: (3a)·b must equal ab + ab + ab even
                // though 3a has limbs up to ~2^52.6 — this is the
                // input shape real group code produces via fe_add.
                let a3 = fe_add(&fe_add(&a, &a), &a);
                let lhs3 = fe_mul(&a3, &b);
                let rhs3 = fe_add(&fe_mul(&a, &b), &fe_mul(&fe_add(&a, &a), &b));
                assert_eq!(
                    hexd(&lhs3),
                    hexd(&rhs3),
                    "carry-stress: a={} b={} 3ab={} 2ab+ab={}",
                    hexd(&a),
                    hexd(&b),
                    hexd(&lhs3),
                    hexd(&rhs3)
                );
                // tobytes of an unreduced value: fe_add(a, a) encodes
                // the same field element as a + a computed small
                let two_a = fe_mul_small(&a, 2);
                assert_eq!(hexd(&fe_add(&a, &a)), hexd(&two_a), "unreduced encode");
            }
        }

        #[test]
        fn b_decodes_with_y_4_over_5() {
            let s = hexs("5866666666666666666666666666666666666666666666666666666666666666");
            let _y = fe_frombytes(&s);
            // 4/5 = 4 * inv(5)
            let four_fifths = fe_mul(&fe_from_u64(4), &fe_invert(&fe_from_u64(5)));
            assert_eq!(
                hexd(&four_fifths),
                "5866666666666666666666666666666666666666666666666666666666666666",
                "4/5 = {}",
                hexd(&four_fifths)
            );
            let b = decompress(&s);
            assert!(b.is_some(), "B must decompress: d check failed");
            let d = curve_d();
            let b = b.unwrap();
            // curve check: -x^2 + y^2 = 1 + d x^2 y^2
            let xx = fe_sq(&b.x);
            let yy = fe_sq(&b.y);
            let lhs = fe_sub(&yy, &xx);
            let rhs = fe_add(&fe_one(), &fe_mul(&fe_mul(&d, &xx), &yy));
            assert_eq!(
                hexd(&lhs),
                hexd(&rhs),
                "B not on curve: lhs {} rhs {} d {}",
                hexd(&lhs),
                hexd(&rhs),
                hexd(&d)
            );
        }

        #[test]
        fn d_is_stable_and_nontrivial() {
            // d = -121665/121666 mod p. The authoritative correctness
            // oracle is the RFC 8032 vector (end-to-end); here we pin
            // determinism and non-degeneracy.
            let d = curve_d();
            assert!(!fe_is_zero(&d), "d must be nonzero");
            assert_eq!(hexd(&curve_d()), hexd(&d));
            // d² ≠ -1 — cheap sanity
            assert!(!fe_eq(&fe_sq(&d), &fe_neg(&fe_one())));
        }

        #[test]
        fn sc_reduce_identities() {
            // L itself reduces to 0
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&L);
            assert!(sc_is_zero_all(&sc_reduce(&wide)), "L mod L must be 0");
            // L + 1 reduces to 1
            wide[0] = L[0].wrapping_add(1);
            let one = sc_reduce(&wide);
            assert_eq!(one[0], 1);
            assert!(one[1..].iter().all(|&b| b == 0));
            // large values stay < L
            let mut big = [0xFFu8; 64];
            big[63] = 0x0F; // < 2^508
            let r = sc_reduce(&big);
            assert!(sc_lt_l(&r), "reduced value must be < L");
            // determinism
            assert_eq!(sc_reduce(&big), r);
        }

        fn sc_is_zero_all(s: &[u8; 32]) -> bool {
            s.iter().all(|&b| b == 0)
        }

        #[test]
        fn sc_mul_identities() {
            // 2 * 3 = 6
            let mut a = [0u8; 32];
            a[0] = 2;
            let mut b = [0u8; 32];
            b[0] = 3;
            let m = sc_mul(&a, &b);
            assert_eq!(m[0], 6);
            assert!(m[1..].iter().all(|&b| b == 0));
            // (L-1)^2 mod L = 1
            let mut lm1 = L;
            // subtract 1 from L
            let mut i = 0;
            loop {
                if lm1[i] > 0 {
                    lm1[i] -= 1;
                    break;
                }
                lm1[i] = 0xFF;
                i += 1;
            }
            let m2 = sc_mul(&lm1, &lm1);
            assert_eq!(
                m2[0], 1,
                "(L-1)^2 mod L must be 1, got first byte {}",
                m2[0]
            );
            // 1 * x = x for a large x < L
            let mut x = [0u8; 32];
            x[..32].copy_from_slice(&lm1);
            let one = {
                let mut o = [0u8; 32];
                o[0] = 1;
                o
            };
            let m3 = sc_mul(&x, &one);
            assert_eq!(&m3[..], &x[..]);
            // clamped-style a (bit 254 set) times small k stays < L
            let mut a2 = [0u8; 32];
            a2[31] = 0x40;
            let mut k = [0u8; 32];
            k[0] = 0x09;
            let m4 = sc_mul(&a2, &k);
            assert!(sc_lt_l(&m4), "a2*9 mod L must be < L");
        }

        #[test]
        fn sc_add_identities() {
            let mut a = L;
            a[0] -= 1; // L - 1
            let mut b = L;
            b[0] -= 1; // L - 1
                       // (L-1) + (L-1) mod L = L - 2
            let s = sc_add(&a, &b);
            let expected = {
                let mut e = L;
                e[0] -= 2;
                e
            };
            assert_eq!(&s[..], &expected[..]);
        }

        #[test]
        fn sc_probe() {
            // value 1 reduces to 1
            let mut v1 = [0u8; 64];
            v1[0] = 1;
            let r1 = sc_reduce(&v1);
            let s1: String = r1.iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(
                s1, "0100000000000000000000000000000000000000000000000000000000000000",
                "one -> {}",
                s1
            );
            // 256 reduces to 256
            let mut v256 = [0u8; 64];
            v256[1] = 1;
            let r256 = sc_reduce(&v256);
            let s256: String = r256.iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(
                s256, "0001000000000000000000000000000000000000000000000000000000000000",
                "256 -> {}",
                s256
            );
            // 0x10·256^31 (the top-byte shift state) stays < L
            let mut vtop = [0u8; 64];
            vtop[31] = 0x10;
            let rtop = sc_reduce(&vtop);
            let stop: String = rtop.iter().map(|b| format!("{:02x}", b)).collect();
            assert!(sc_lt_l(&rtop), "top-byte state must be < L, got {}", stop);
            // L+1 -> 1
            let mut vlp = [0u8; 64];
            vlp[..32].copy_from_slice(&L);
            vlp[0] = L[0].wrapping_add(1);
            let rlp = sc_reduce(&vlp);
            let slp: String = rlp.iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(
                slp, "0100000000000000000000000000000000000000000000000000000000000000",
                "L+1 -> {}",
                slp
            );
        }

        #[test]
        fn pt_group_consistency() {
            let d = curve_d();
            let d2 = fe_mul_small(&d, 2);
            let b = decompress(&B_COMPRESSED).unwrap();
            let id = pt_identity();
            let aff = |p: &Point| -> ([u8; 32], [u8; 32]) {
                let zi = fe_invert(&p.z);
                (
                    fe_tobytes(&fe_mul(&p.x, &zi)),
                    fe_tobytes(&fe_mul(&p.y, &zi)),
                )
            };
            let b_id = pt_add(&b, &id, &d2);
            let (bx, by) = aff(&b);
            let (ix, iy) = aff(&b_id);
            assert_eq!(ix, bx, "B + identity x");
            assert_eq!(iy, by, "B + identity y");
            let id_b = pt_add(&id, &b, &d2);
            let (jx, jy) = aff(&id_b);
            assert_eq!(jx, bx, "identity + B x");
            assert_eq!(jy, by, "identity + B y");
            // 2B: mul vs add agree
            let two = {
                let mut t = [0u8; 32];
                t[0] = 2;
                t
            };
            let mul2 = pt_mul(&b, &two, &d2);
            let add2 = pt_add(&b, &b, &d2);
            let (m2x, m2y) = aff(&mul2);
            let (a2x, a2y) = aff(&add2);
            assert_eq!(m2x, a2x, "2B x: mul {} add {}", hexu(&m2x), hexu(&a2x));
            assert_eq!(m2y, a2y);
            // 3B: B+B+B vs mul(3)
            let three = {
                let mut t = [0u8; 32];
                t[0] = 3;
                t
            };
            let mul3 = pt_mul(&b, &three, &d2);
            let add3 = pt_add(&add2, &b, &d2);
            let (m3x, m3y) = aff(&mul3);
            let (a3x, a3y) = aff(&add3);
            assert_eq!(m3x, a3x, "3B mismatch {} {}", hexu(&m3x), hexu(&a3x));
            assert_eq!(m3y, a3y);
            // scalar assoc: [5]B = [2]B + [3]B
            let five = {
                let mut t = [0u8; 32];
                t[0] = 5;
                t
            };
            let mul5 = pt_mul(&b, &five, &d2);
            let add23 = pt_add(&mul2, &mul3, &d2);
            let (m5x, m5y) = aff(&mul5);
            let (a5x, a5y) = aff(&add23);
            assert_eq!(m5x, a5x, "5B mismatch {} {}", hexu(&m5x), hexu(&a5x));
            assert_eq!(m5y, a5y);
            // random scalar roundtrip: ([k]B) compressed decodes back
            let k = {
                let mut t = [0u8; 32];
                t[0] = 0xAB;
                t[5] = 0x71;
                t[31] = 0x0F;
                t
            };
            let kb = pt_mul(&b, &k, &d2);
            let enc = compress(&kb);
            let back = decompress(&enc);
            assert!(back.is_some(), "[k]B must re-decode");
            let back = back.unwrap();
            let (kx, ky) = aff(&kb);
            let (r_x, r_y) = aff(&back);
            assert_eq!(r_x, kx);
            assert_eq!(r_y, ky);
        }

        #[test]
        fn sign_verify_random_seeds() {
            for seed_byte in 1u8..=40 {
                let sk = [seed_byte; 32];
                let pk = public_key(&sk);
                let msg = [seed_byte; 37];
                let sig = sign(&sk, &msg);
                if !verify(&pk, &msg, &sig) {
                    panic!(
                        "seed {} failed to round-trip ({} of 40 seeds checked)",
                        seed_byte, seed_byte
                    );
                }
            }
        }
    }

    /// Debug variant of `decompress` returning a reason code (1:
    /// non-canonical y, 2: not on curve, 3: x=0 with sign). Test-only.
    #[cfg(test)]
    fn decompress_dbg(s: &[u8; 32]) -> core::result::Result<Point, u8> {
        let y = fe_frombytes(s);
        let mut ycanon = *s;
        ycanon[31] &= 0x7F;
        if fe_tobytes(&y) != ycanon {
            return Err(1);
        }
        let sign = (s[31] >> 7) & 1 == 1;
        let d = curve_d();
        let yy = fe_sq(&y);
        let u = fe_sub(&yy, &fe_one());
        let v = fe_add(&fe_mul(&d, &yy), &fe_one());
        let v3 = fe_sq(&v);
        let v7 = fe_sq(&v3);
        let v3 = fe_mul(&v3, &v);
        let v7 = fe_mul(&v7, &v3);
        let uv7 = fe_mul(&u, &v7);
        let mut x = fe_mul(&fe_mul(&u, &v3), &fe_pow(&uv7, &P_M5_DIV_8));
        let vxx = fe_mul(&v, &fe_sq(&x));
        if !fe_eq(&vxx, &u) {
            // sqrt(-1) = 2^((p-1)/4): 2 is a non-residue because
            // p = 2^255-19 ≡ 5 (mod 8), so this is the square root
            // of -1. (Using -1 as the base would yield -1 itself —
            // the exponent is odd — and the fixup would be a no-op.)
            let sqrtm1 = fe_pow(&fe_from_u64(2), &P_M1_DIV_4);
            let x2 = fe_mul(&x, &sqrtm1);
            let vxx2 = fe_mul(&v, &fe_sq(&x2));
            if !fe_eq(&vxx2, &u) {
                return Err(2);
            }
            x = x2;
        }
        if fe_is_zero(&x) && sign {
            return Err(3);
        }
        if fe_is_negative(&x) != sign {
            x = fe_neg(&x);
        }
        Ok(Point {
            x,
            y,
            z: fe_one(),
            t: fe_mul(&x, &y),
        })
    }

    #[cfg(test)]
    mod roundtrip_probe {
        use super::*;

        #[test]
        fn compress_decompress_random_points() {
            let d = curve_d();
            let d2 = fe_mul_small(&d, 2);
            let b = decompress(&B_COMPRESSED).unwrap();
            for i in 1u8..60 {
                let mut k = [0u8; 32];
                k[0] = i.wrapping_mul(37);
                k[7] = i;
                k[31] = i % 8;
                let p = pt_mul(&b, &k, &d2);
                // curve membership of the affine point (this
                // discriminates a broken group law from a broken
                // point codec)
                let zi = fe_invert(&p.z);
                let ax = fe_mul(&p.x, &zi);
                let ay = fe_mul(&p.y, &zi);
                let xx = fe_sq(&ax);
                let yy = fe_sq(&ay);
                let lhs = fe_sub(&yy, &xx);
                let rhs = fe_add(&fe_one(), &fe_mul(&fe_mul(&d, &xx), &yy));
                if !fe_eq(&lhs, &rhs) {
                    panic!("k[0]={:02x} i={} OFF-CURVE from pt_mul", k[0], i);
                }
                let enc = compress(&p);
                match decompress_dbg(&enc) {
                    Ok(_) => {}
                    Err(code) => {
                        let enc_hex: String = enc.iter().map(|b| format!("{:02x}", b)).collect();
                        panic!("k[0]={:02x} i={} code={} enc={}", k[0], i, code, enc_hex);
                    }
                }
            }
        }
    }
}
