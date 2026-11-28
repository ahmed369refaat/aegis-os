//! The TLS 1.3 key schedule (RFC 8446 §7.1) over the HKDF layer.
//!
//! The full 1-RTT tree, PSK-less (early secret from a zero IKM):
//!
//! ```text
//! early_secret    = Extract(0, 0)
//! derived         = Derive-Secret(early, "derived", "")
//! handshake_sec   = Extract(derived, ECDHE)
//! c_hs / s_hs     = Derive-Secret(hs, "c/s hs traffic", CH..SH)
//! derived2        = Derive-Secret(hs, "derived", "")
//! master          = Extract(derived2, 0)
//! c_ap / s_ap     = Derive-Secret(master, "c/s ap traffic", CH..srvFin)
//! finished keys   = Expand-Label(traffic, "finished", "", 32)
//! record keys/ivs = Expand-Label(traffic, "key"/"iv", "", 32/12)
//! ```
//!
//! No allocation: every secret lands in caller-owned fixed buffers
//! ([u8; 32] secrets, [u8; 32] keys, [u8; 12] IVs).

use crate::hkdf;

/// A 32-byte traffic secret.
pub type Secret = [u8; 32];

/// SHA-256("") — the transcript hash of the EMPTY message stream,
/// which the two "derived" steps of the schedule use (RFC 8446
/// §7.1: Derive-Secret(., "derived", "")). NOT 32 zero bytes — that
/// substitution was the round's key-schedule bug, caught by the live
/// OpenSSL flight refusing to decrypt (the keylog comparison found
/// it).
const HASH_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// HKDF-Extract with the tree's zero shapes: RFC 8446's "(0, 0)"
/// operands are strings of Hash.length ZERO BYTES — not empty
/// slices (an empty IKM hashed differently than 32 zeros: the
/// keylog comparison caught it).
fn extract_zero_ikm() -> Secret {
    hkdf::extract(&[0u8; 32], &[0u8; 32])
}

/// Derive-Secret = HKDF-Expand-Label(secret, label, Hash(transcript),
/// 32) — the transcript hash comes in as `th`.
pub fn derive_secret(secret: &Secret, label: &str, th: &[u8; 32]) -> Secret {
    let mut out = [0u8; 32];
    let _ = hkdf::expand_label(secret, label, th, &mut out);
    out
}

/// The whole 1-RTT secret tree, derived from the ECDHE output.
pub struct KeySchedule {
    pub handshake_secret: Secret,
    pub client_hs_traffic: Secret,
    pub server_hs_traffic: Secret,
    pub master_secret: Secret,
    pub client_ap_traffic: Secret,
    pub server_ap_traffic: Secret,
}

impl KeySchedule {
    /// The pre-ServerHello placeholder: an all-zero tree the client
    /// struct holds before its phase gate opens — its cryptos are
    /// unreachable until `new` derives the real one.
    pub fn from_parts() -> KeySchedule {
        KeySchedule {
            handshake_secret: [0u8; 32],
            client_hs_traffic: [0u8; 32],
            server_hs_traffic: [0u8; 32],
            master_secret: [0u8; 32],
            client_ap_traffic: [0u8; 32],
            server_ap_traffic: [0u8; 32],
        }
    }

    /// Derive the tree from the shared ECDHE secret and the
    /// transcript hash through ServerHello (for the hs secrets) and
    /// through the server Finished (for the application secrets —
    /// supplied by the caller once the flight is verified).
    pub fn new(ecdhe: &[u8; 32], th_through_sh: &[u8; 32]) -> KeySchedule {
        let early = extract_zero_ikm();
        let derived = derive_secret(&early, "derived", &HASH_EMPTY);
        let handshake_secret = hkdf::extract(&derived, ecdhe);
        let client_hs_traffic = derive_secret(&handshake_secret, "c hs traffic", th_through_sh);
        let server_hs_traffic = derive_secret(&handshake_secret, "s hs traffic", th_through_sh);
        // The application half is derived LATER (needs the transcript
        // through the server Finished) — via `finish_application`.
        KeySchedule {
            handshake_secret,
            client_hs_traffic,
            server_hs_traffic,
            master_secret: [0u8; 32],
            client_ap_traffic: [0u8; 32],
            server_ap_traffic: [0u8; 32],
        }
    }

    /// Second half: master + application traffic, from the transcript
    /// hash through the server's Finished.
    pub fn finish_application(&mut self, th_through_server_finished: &[u8; 32]) {
        let derived = derive_secret(&self.handshake_secret, "derived", &HASH_EMPTY);
        self.master_secret = hkdf::extract(&derived, &[0u8; 32]);
        self.client_ap_traffic = derive_secret(
            &self.master_secret,
            "c ap traffic",
            th_through_server_finished,
        );
        self.server_ap_traffic = derive_secret(
            &self.master_secret,
            "s ap traffic",
            th_through_server_finished,
        );
    }

    /// The AEAD key for a traffic secret (32 bytes).
    pub fn record_key(secret: &Secret) -> [u8; 32] {
        let mut k = [0u8; 32];
        let _ = hkdf::expand_label(secret, "key", &[], &mut k);
        k
    }

    /// The per-record static IV (12 bytes; the per-record nonce is
    /// IV ⊕ seq in the low 8 bytes).
    pub fn record_iv(secret: &Secret) -> [u8; 12] {
        let mut iv = [0u8; 12];
        let _ = hkdf::expand_label(secret, "iv", &[], &mut iv);
        iv
    }

    /// The Finished MAC key for a traffic secret.
    pub fn finished_key(secret: &Secret) -> [u8; 32] {
        let mut k = [0u8; 32];
        let _ = hkdf::expand_label(secret, "finished", &[], &mut k);
        k
    }
}
