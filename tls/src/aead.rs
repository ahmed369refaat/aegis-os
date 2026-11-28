//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8): TLS 1.3's
//! `TLS_CHACHA20_POLY1305_SHA256` cipher.
//!
//! The seal: ciphertext = plaintext ⊕ ChaCha20(key, counter 1, nonce)
//! keystream; the one-time Poly1305 key is block 0's first 32 bytes;
//! the tag covers aad ‖ pad ‖ ct ‖ pad ‖ le64(len aad) ‖ le64(len ct).
//! The open recomputes and compares through `pkg`'s constant-time
//! `ct_eq` — a forgery is a refusal, never a decryption.
//!
//! No allocation: everything lands in caller-provided slices; the
//! MAC input is assembled in a fixed stack window (the record
//! layer's frames are capped below that — a larger aad+ct is a
//! length refusal, by construction, never a truncation).

use crate::chacha;
use crate::poly1305;
use aegis_pkg::crypto::ct_eq;

/// The MAC window cap (aad + ct + padding + lengths). TLS 1.3
/// records are ≤ 2^14+overhead on the wire; this stack's callers cap
/// frames at RECORD_CAP (2048) — the window covers that with the
/// header, type byte, tag, and length encoding.
pub const MAC_WINDOW: usize = 2084;

/// Seal into `out` (needs pt.len() + 16 bytes): writes the ciphertext
/// then the 16-byte tag. `Err(())` = output too small or the MAC
/// window blown.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    if out.len() < plaintext.len() + 16 {
        return Err(());
    }
    let (ct, rest) = out.split_at_mut(plaintext.len());
    ct.copy_from_slice(plaintext);
    chacha::xor_keystream(key, 1, nonce, ct);
    let t = mac_tag(key, nonce, aad, ct)?;
    // rest is the caller's full remaining buffer; the tag occupies
    // exactly its first 16 bytes (copy_from_slice would panic on the
    // length mismatch — this bit the first client Finished).
    rest[..16].copy_from_slice(&t);
    Ok(plaintext.len() + 16)
}

/// Open `sealed` into `out`: `Ok(len)` of plaintext or `Err(())` (a
/// tag mismatch is a refusal — plaintext never lands).
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    sealed: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, ()> {
    if sealed.len() < 16 || out.len() < sealed.len() - 16 {
        return Err(());
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let want = mac_tag(key, nonce, aad, ct)?;
    if !ct_eq(&want, tag) {
        return Err(());
    }
    out[..ct.len()].copy_from_slice(ct);
    chacha::xor_keystream(key, 1, nonce, &mut out[..ct.len()]);
    Ok(ct.len())
}

/// The Poly1305 tag over the RFC 8439 §2.8 MAC data.
fn mac_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<[u8; 16], ()> {
    let pad_aad = (16 - (aad.len() % 16)) % 16;
    let pad_ct = (16 - (ct.len() % 16)) % 16;
    let total = aad.len() + pad_aad + ct.len() + pad_ct + 16;
    if total > MAC_WINDOW {
        return Err(());
    }
    let mut d = [0u8; MAC_WINDOW];
    let mut o = 0;
    d[..aad.len()].copy_from_slice(aad);
    o += aad.len() + pad_aad;
    d[o..o + ct.len()].copy_from_slice(ct);
    o += ct.len() + pad_ct;
    d[o..o + 8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    d[o + 8..o + 16].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    // the one-time key: block 0's first 32 bytes
    let blk = chacha::block(key, 0, nonce);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&blk[..32]);
    Ok(poly1305::poly1305(&pk, &d[..total]))
}
