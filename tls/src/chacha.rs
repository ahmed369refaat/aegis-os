//! ChaCha20 (RFC 8439): the stream cipher under TLS 1.3's
//! `TLS_CHACHA20_POLY1305_SHA256`.
//!
//! ARX only — adds, rotates, xors, no table lookups: the timing is
//! data-independent by construction (the right shape for a
//! no-unsafe, constant-time kernel; AES's S-box tables are exactly
//! the wrong shape, which is why this suite exists at all).
//!
//! Pinned by RFC 8439 §2.4.2's block and keystream vectors plus
//! randomized cross-checks against an independent implementation.

/// The "expand 32-byte k" constants (RFC 8439 §2.3).
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The 64-byte ChaCha20 block for (key, 32-bit counter, 96-bit
/// nonce) — RFC 8439 §2.3, 20 rounds (10 double rounds).
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }
    let mut w = s;
    // 10 double rounds
    for _ in 0..10 {
        quarter(&mut w, 0, 4, 8, 12);
        quarter(&mut w, 1, 5, 9, 13);
        quarter(&mut w, 2, 6, 10, 14);
        quarter(&mut w, 3, 7, 11, 15);
        quarter(&mut w, 0, 5, 10, 15);
        quarter(&mut w, 1, 6, 11, 12);
        quarter(&mut w, 2, 7, 8, 13);
        quarter(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = w[i].wrapping_add(s[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// One QUARTERROUND on four state words.
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// XOR `data` with the keystream starting at `counter`, in place.
pub fn xor_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let b = block(key, ctr, nonce);
        for (x, k) in chunk.iter_mut().zip(b.iter()) {
            *x ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
}
