//! The TLS record layer (RFC 8446 §5): the outer framing, the 1.3
//! protected record shape, and the per-record nonce.
//!
//! Outer record: `type(1) legacy_version(2) length(2) payload`.
//! Unprotected (the ClientHello, and the compatibility
//! ChangeCipherSpec) carry the payload verbatim. Protected records
//! carry `AEAD(plaintext || inner_type || zeros*)` where `length` on
//! the wire is the ciphertext length INCLUDING the 16-byte tag.
//!
//! The per-record nonce (§5.3): the static IV with the last 8 bytes
//! XORed by the 64-bit big-endian sequence number.
//!
//! The AAD is the record's OWN 5-byte header — sealed records carry
//! 0x0303 (every record after the initial ClientHello; OpenSSL
//! rejects protected records framed with 0x0301 — the live flight
//! caught it), and the seal writes the header BEFORE reading it as
//! AAD, mirroring exactly what the receiver's open sees.
//!
//! No allocation: seal/open write into caller-provided slices; the
//! record cap keeps the AEAD's MAC window honest.

use crate::aead;
use crate::schedule;

/// Record content types (RFC 8446 §5.1 / the handshake types we see).
pub const TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const TYPE_ALERT: u8 = 21;
pub const TYPE_HANDSHAKE: u8 = 22;
pub const TYPE_APPLICATION_DATA: u8 = 23;

/// The legacy version on the WIRE: 0x0301 for a client's initial
/// ClientHello record only; every later record (including ours)
/// carries 0x0303 (RFC 8446 §5.1).
pub const LEGACY_VERSION: [u8; 2] = [0x03, 0x03];

/// The record cap this layer serves: the handshake's Certificate
/// record (an Ed25519 certificate, ~600 B) and the echo payloads must
/// fit whole; 2 KiB covers both with headroom (the AEAD's MAC window
/// is sized to match).
pub const RECORD_CAP: usize = 2048;

/// The per-record nonce: static IV ⊕ seq (low 8 bytes, BE).
pub fn record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let be = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= be[i];
    }
    n
}

/// The per-direction record state (key + IV + sequence).
pub struct RecordCrypto {
    pub key: [u8; 32],
    pub iv: [u8; 12],
    pub seq: u64,
}

impl RecordCrypto {
    /// From a traffic secret.
    pub fn from_secret(secret: &schedule::Secret) -> RecordCrypto {
        RecordCrypto {
            key: schedule::KeySchedule::record_key(secret),
            iv: schedule::KeySchedule::record_iv(secret),
            seq: 0,
        }
    }

    /// Seal `content` (a handshake message or application data) as an
    /// inner-plaintext of `inner_type`, into a full outer record in
    /// `out`. Returns the record's total length. The AAD is THIS
    /// record's own 5-byte header — the same bytes the receiver's
    /// open uses (the header must be written BEFORE the seal reads
    /// it).
    pub fn seal(&mut self, inner_type: u8, content: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        if out.len() < 5 + content.len() + 1 + 16 {
            return Err(());
        }
        // inner plaintext = content || inner_type (no padding — legal
        // per §5.4, and every byte counts in a kernel)
        let mut pt = [0u8; RECORD_CAP];
        if content.len() + 1 > RECORD_CAP {
            return Err(());
        }
        pt[..content.len()].copy_from_slice(content);
        pt[content.len()] = inner_type;
        // outer header: APP_DATA type, length = pt+16
        out[0] = TYPE_APPLICATION_DATA;
        out[1] = LEGACY_VERSION[0];
        out[2] = LEGACY_VERSION[1];
        let ct_len = content.len() + 1 + 16;
        out[3] = (ct_len >> 8) as u8;
        out[4] = ct_len as u8;
        let aad = [out[0], out[1], out[2], out[3], out[4]];
        let nonce = record_nonce(&self.iv, self.seq);
        let n = aead::seal(
            &self.key,
            &nonce,
            &pt[..content.len() + 1],
            &aad,
            &mut out[5..],
        )?;
        self.seq += 1;
        Ok(5 + n)
    }

    /// Open a protected record: `record` (the full outer record),
    /// into `out` (the content). Returns (inner_type, content_len).
    pub fn open(&mut self, record: &[u8], out: &mut [u8]) -> Result<(u8, usize), ()> {
        if record.len() < 5 + 16 || record.len() > 5 + RECORD_CAP {
            return Err(());
        }
        let ct_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        if 5 + ct_len != record.len() {
            return Err(()); // the header must agree with the frame
        }
        let nonce = record_nonce(&self.iv, self.seq);
        let mut pt = [0u8; RECORD_CAP];
        let aad = &record[..5];
        let n = aead::open(&self.key, &nonce, &record[5..], aad, &mut pt)?;
        if n == 0 {
            return Err(());
        }
        let inner_type = pt[n - 1];
        out[..n - 1].copy_from_slice(&pt[..n - 1]);
        self.seq += 1;
        Ok((inner_type, n - 1))
    }
}

/// Build an UNPROTECTED record (the ClientHello): type + version +
/// length + payload. Returns the total length.
pub fn plain_record(rec_type: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, ()> {
    if out.len() < 5 + payload.len() || payload.len() > 0xFFFF {
        return Err(());
    }
    out[0] = rec_type;
    out[1] = 0x03;
    out[2] = 0x01;
    let l = payload.len();
    out[3] = (l >> 8) as u8;
    out[4] = l as u8;
    out[5..5 + l].copy_from_slice(payload);
    Ok(5 + l)
}
