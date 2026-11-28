//! HKDF-SHA-256 (RFC 5869): the KDF under TLS 1.3's whole key
//! schedule.
//!
//! Extract = HMAC-SHA-256(salt, ikm); Expand = the T(i) chain. HMAC
//! itself is built here over `pkg`'s SHA-256 (block 64, output 32):
//! the standard ipad/opad construction, keys hashed when longer
//! than the block, zero-padded otherwise.
//!
//! Pinned by RFC 5869 test cases 1–3 (SHA-256). No allocation: the
//! OKM lands in caller-owned slices; the TLS label wrapper runs in a
//! fixed info window.

use aegis_pkg::crypto::sha256::Sha256;

/// HMAC-SHA-256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = aegis_pkg::crypto::sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    // inner = H(ipad ‖ msg)
    let mut h = Sha256::new();
    h.update(&ipad);
    h.update(msg);
    let mut inner = [0u8; 32];
    h.finish(&mut inner);
    // outer = H(opad ‖ inner)
    let mut h2 = Sha256::new();
    h2.update(&opad);
    h2.update(&inner);
    let mut out = [0u8; 32];
    h2.finish(&mut out);
    out
}

/// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC(salt, IKM).
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3): fills `out` with OKM = T(1) ‖ … ‖
/// T(n), truncated to `out.len()`. `false` = the info exceeds the
/// fixed window or the length exceeds 255×32 (a refusal, never a
/// short fill).
pub fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> bool {
    if info.len() > INFO_CAP || out.len() > 255 * 32 || out.is_empty() {
        return false;
    }
    let mut t: Option<[u8; 32]> = None; // T(0) is the EMPTY string
    let mut filled = 0;
    let mut counter: u8 = 1;
    while filled < out.len() {
        // T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i), T(0) = ""
        let mut data = [0u8; 32 + INFO_CAP + 1];
        let mut n = 0;
        if let Some(t) = &t {
            data[..32].copy_from_slice(t);
            n = 32;
        }
        data[n..n + info.len()].copy_from_slice(info);
        n += info.len();
        data[n] = counter;
        let ti = hmac_sha256(prk, &data[..n + 1]);
        let take = core::cmp::min(32, out.len() - filled);
        out[filled..filled + take].copy_from_slice(&ti[..take]);
        t = Some(ti);
        filled += take;
        counter = counter.wrapping_add(1);
    }
    true
}

/// The info window cap (label ≤ 48 bytes after "tls13 ", context
/// ≤ 64 — the handshake's labels all fit).
pub const INFO_CAP: usize = 262;
const CTX_CAP: usize = 64;

/// HKDF-Expand-Label (RFC 8446 §7.1): the TLS 1.3 label wrapper —
/// HkdfLabel = length(2) + "tls13"+label + context, structured per
/// the spec. Fills `out` (its length IS the requested length);
/// `false` = label/context over the caps (a refusal).
pub fn expand_label(prk: &[u8; 32], label: &str, context: &[u8], out: &mut [u8]) -> bool {
    let lbl = label.as_bytes();
    let full = 6 + lbl.len(); // "tls13 " prefix
    if context.len() > CTX_CAP || full > 253 {
        return false;
    }
    let mut info = [0u8; INFO_CAP];
    let mut o = 0;
    info[o..o + 2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    o += 2;
    info[o] = full as u8;
    o += 1;
    info[o..o + 6].copy_from_slice(b"tls13 ");
    o += 6;
    info[o..o + lbl.len()].copy_from_slice(lbl);
    o += lbl.len();
    info[o] = context.len() as u8;
    o += 1;
    info[o..o + context.len()].copy_from_slice(context);
    o += context.len();
    expand(prk, &info[..o], out)
}
