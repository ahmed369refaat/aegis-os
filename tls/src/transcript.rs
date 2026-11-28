//! The running transcript hash (RFC 8446 §4.4.1): SHA-256 over the
//! concatenated HANDSHAKE messages, each including its 4-byte header
//! (type, 24-bit length). The key schedule's derive-secret calls and
//! both Finished MACs hash snapshots of this.

use aegis_pkg::crypto::sha256::Sha256;

/// The running transcript.
pub struct Transcript {
    h: Sha256,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// A fresh transcript.
    pub fn new() -> Transcript {
        Transcript { h: Sha256::new() }
    }

    /// Append one handshake message (header + body, exactly as on the
    /// wire).
    pub fn message(&mut self, msg: &[u8]) {
        self.h.update(msg);
    }

    /// The current transcript hash — a snapshot; the running state is
    /// preserved through pkg's `interim_clone`.
    pub fn hash(&mut self) -> [u8; 32] {
        let clone = self.h.interim_clone();
        let mut out = [0u8; 32];
        clone.finish(&mut out);
        out
    }
}
