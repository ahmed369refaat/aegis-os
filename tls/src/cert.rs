//! The certificate walk: X.509 DER → the SubjectPublicKeyInfo's raw
//! Ed25519 key (TLS 1.3's Certificate message shape, RFC 8446 §4.4.2).
//!
//! A deliberately MINIMAL, total, length-checked cursor: no
//! allocation, no panics on hostile input — every malformed shape is
//! a `None`, never a crash. The walk: CertificateEntry → the DER
//! Certificate (the entry's own TLV length INCLUDES its SEQUENCE
//! header — the whole certificate, header and all) →
//! TBSCertificate's children → the SEQUENCE whose second child is a
//! BIT STRING (the SPKI; its position shifts with the optional [0]
//! version and [3] extensions, so it is IDENTIFIED, not positionally
//! assumed) → the BIT STRING's raw key bytes, with the Ed25519 OID
//! (1.3.101.112 — `06 03 2B 65 70`) checked on the way.

/// A DER cursor over a byte slice.
struct Der<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Der<'a> {
        Der { b, pos: 0 }
    }

    /// Read one (tag, length) header; `None` on truncation or a
    /// length that escapes the slice.
    fn header(&mut self) -> Option<(u8, usize)> {
        if self.pos + 2 > self.b.len() {
            return None;
        }
        let tag = self.b[self.pos];
        self.pos += 1;
        let first = self.b[self.pos] as usize;
        self.pos += 1;
        let len = if first < 0x80 {
            first
        } else {
            let n = first & 0x7F;
            if n == 0 || n > 4 || self.pos + n > self.b.len() {
                return None;
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | self.b[self.pos + i] as usize;
            }
            self.pos += n;
            v
        };
        if self.pos + len > self.b.len() {
            return None;
        }
        Some((tag, len))
    }

    /// Read one TLV, returning (tag, contents).
    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let (tag, len) = self.header()?;
        let c = &self.b[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, c))
    }

    /// The number of bytes consumed so far (for iteration over a
    /// parent's children).
    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
}

/// Extract the raw 32-byte Ed25519 public key from a DER certificate.
/// Refuses anything that is not an Ed25519 SPKI (the OID is checked:
/// 1.3.101.112 — `06 03 2B 65 70`).
pub fn ed25519_public_key(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Certificate = SEQUENCE { tbs, sigAlg, sig }
    let (tag, cert) = Der::new(cert_der).tlv()?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs) = Der::new(cert).tlv()?;
    if tag != 0x30 {
        return None;
    }
    // Walk the TBS children; the SPKI is the SEQUENCE whose second
    // child is a BIT STRING.
    let mut cur = Der::new(tbs);
    while !cur.done() {
        let (tag, child) = cur.tlv()?;
        if tag != 0x30 {
            continue; // serial, validity, extensions, ...
        }
        let mut inner = Der::new(child);
        let (alg_tag, alg) = inner.tlv()?;
        if alg_tag != 0x30 {
            continue;
        }
        let Some((key_tag, key)) = inner.tlv() else {
            continue;
        };
        if key_tag != 0x03 {
            continue;
        }
        // The SPKI: check the Ed25519 OID inside the
        // AlgorithmIdentifier
        let mut alg_cur = Der::new(alg);
        let Some((oid_tag, oid)) = alg_cur.tlv() else {
            continue;
        };
        if oid_tag != 0x06 || oid != [0x2B, 0x65, 0x70] {
            continue; // not Ed25519 — refuse (RSA/P-256 are not served)
        }
        // The BIT STRING: first byte = unused-bits count (must be 0),
        // then the raw key
        if key.is_empty() || key[0] != 0 || key.len() != 1 + 32 {
            continue;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&key[1..33]);
        return Some(out);
    }
    None
}

/// Parse the Certificate handshake message's FIRST entry's DER
/// (certificate_request_context(1) + list_len(3) + entry_len(3) +
/// DER + ext_len(2)); returns the DER slice.
pub fn first_certificate_entry(cert_msg_body: &[u8]) -> Option<&[u8]> {
    if cert_msg_body.is_empty() {
        return None;
    }
    let ctx_len = cert_msg_body[0] as usize;
    let mut p = 1 + ctx_len;
    if p + 3 > cert_msg_body.len() {
        return None;
    }
    let list_len = (cert_msg_body[p] as usize) << 16
        | (cert_msg_body[p + 1] as usize) << 8
        | cert_msg_body[p + 2] as usize;
    p += 3;
    if list_len == 0 || p + 3 > cert_msg_body.len() {
        return None;
    }
    let entry_len = (cert_msg_body[p] as usize) << 16
        | (cert_msg_body[p + 1] as usize) << 8
        | cert_msg_body[p + 2] as usize;
    p += 3;
    if entry_len == 0 || p + entry_len > cert_msg_body.len() {
        return None;
    }
    // The entry: the DER, then extensions (2-byte len). The DER's
    // own length INCLUDES its SEQUENCE header: 1 + length-bytes +
    // content — return the WHOLE certificate, header and all (the
    // walk truncated without it).
    let der = &cert_msg_body[p..p + entry_len];
    let total = tlv_total(der)?;
    if total == 0 || total > der.len() {
        return None;
    }
    Some(&der[..total])
}

/// The total on-wire size of the first TLV (header + contents).
fn tlv_total(b: &[u8]) -> Option<usize> {
    let mut pos = 1; // the tag
    if b.is_empty() {
        return None;
    }
    let first = b[pos] as usize;
    pos += 1;
    let len = if first < 0x80 {
        first
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 || pos + n > b.len() {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | b[pos + i] as usize;
        }
        pos += n;
        v
    };
    Some(pos + len)
}
