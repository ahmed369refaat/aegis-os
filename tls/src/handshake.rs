//! The TLS 1.3 CLIENT state machine (RFC 8446, the 1-RTT
//! certificate path, ChaCha20-Poly1305, Ed25519-pinned).
//!
//! One object drives the whole exchange; the caller (the kernel
//! driver or the host test) feeds records and reads events:
//!
//! ```text
//! build_client_hello  →  send
//! on_record(ServerHello)        → keys derive (WaitFlight)
//! on_record(flight records)     → EE (ALPN checked), Certificate
//!                                 (the VERIFY MODE: pin, pin+name,
//!                                 or TOFU), CertificateVerify
//!                                 (Ed25519 over the transcript),
//!                                 Finished (HMAC check)
//!                               → Event::ServerVerified
//! build_finished      →  send (then Established)
//! seal/open app data  →  the encrypted channel
//! ```
//!
//! Every refusal is loud and typed; no panic on hostile input; no
//! allocation (all parsing over caller slices; fixed internal
//! buffers).

use crate::cert;
use crate::hkdf;
use crate::record::{RecordCrypto, TYPE_ALERT, TYPE_CHANGE_CIPHER_SPEC, TYPE_HANDSHAKE};
use crate::schedule::KeySchedule;
use crate::transcript::Transcript;
use crate::x25519;
use aegis_pkg::crypto::ct_eq;
use aegis_pkg::crypto::ed25519;

/// The verification policy — THE security flag of the connection.
///
/// - `Pinned` (the default, the known-hosts model): the presented
///   key must equal `pinned_ed25519` byte-for-byte, in constant
///   time.
/// - `PinnedRequireName`: the pin AND the certificate's CommonName
///   must equal the SNI host — the closest shape to a browser's
///   identity check this trust model gets.
/// - `AcceptAnyKey` (TEST/TOFU shape, off by default): the pin is
///   skipped, but the CertificateVerify signature is STILL verified
///   against the PRESENTED key — an active impostor without the
///   private key still fails; only a pre-known-key check is waived.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VerifyMode {
    Pinned,
    PinnedRequireName,
    AcceptAnyKey,
}

/// The connection FLAGS (`tls::handshake::TlsOptions`) — every knob
/// this client honors, each implemented for real:
///
/// - `sni` — the Server Name Indication host, sent in the
///   ClientHello (and the name `PinnedRequireName` checks against
///   the certificate's CN).
/// - `alpn` — the offered ALPN protocol list, sent in the
///   ClientHello; the server's selection (in EncryptedExtensions)
///   must be one of ours or the connection refuses with
///   `BadAlpn`; the answer is readable via `negotiated_alpn()`.
/// - `verify` — the trust policy (see `VerifyMode`).
/// - `max_record_len` — records (ciphertext included) above this
///   are refused before any decryption (`BadRecord`): the hostile
///   record budget. 64..=RECORD_CAP.
///
/// Not flags, by design: the protocol floor (TLS 1.3 only — a
/// ServerHello without supported_versions 0x0304 refuses with
/// `BadVersion`; there IS no TLS 1.2 path to enable), the cipher
/// (TLS_CHACHA20_POLY1305_SHA256 — the only suite compiled in, so
/// downgrade-to-weak is structurally impossible), and the handshake
/// deadline (the PUMP owns the clock — the kernel step and the host
/// tests bound it themselves; the state machine is clockless and
/// total).
#[derive(Debug, Clone, Copy)]
pub struct TlsOptions<'a> {
    pub sni: Option<&'a str>,
    pub alpn: &'a [&'a str],
    pub verify: VerifyMode,
    pub max_record_len: usize,
}

impl Default for TlsOptions<'_> {
    fn default() -> Self {
        TlsOptions {
            sni: None,
            alpn: &[],
            verify: VerifyMode::Pinned,
            max_record_len: crate::record::RECORD_CAP,
        }
    }
}

/// The client's inputs: the ECDHE private scalar, the two
/// ClientHello randoms, the PINNED server key (the trust anchor for
/// the Pinned modes), and the connection flags.
pub struct ClientConfig<'a> {
    pub client_private: [u8; 32],
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    pub pinned_ed25519: [u8; 32],
    pub options: TlsOptions<'a>,
}

/// The machine's phase.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Phase {
    SendHello,
    WaitServerHello,
    WaitFlight,
    SendFinished,
    Established,
}

/// Refusals, each named.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    BadRecord,
    BadHandshake,
    BadVersion,
    BadCipher,
    BadKeyShare,
    BadAlpn,
    NameMismatch,
    CertMalformed,
    PinMismatch,
    CertVerifyFailed,
    FinishedMismatch,
    UnexpectedMessage,
    TooEarly,
    TooLate,
    Buffer,
}

impl Error {
    /// The one-line description (the driver prints it).
    pub fn describe(&self) -> &'static str {
        match self {
            Error::BadRecord => "malformed record",
            Error::BadHandshake => "malformed handshake message",
            Error::BadVersion => "not TLS 1.3",
            Error::BadCipher => "cipher not negotiated",
            Error::BadKeyShare => "no x25519 key share",
            Error::BadAlpn => "the ALPN answer is not one we offered",
            Error::NameMismatch => "the certificate name is not the host we asked",
            Error::CertMalformed => "certificate walk failed",
            Error::PinMismatch => "the server key is NOT the pinned anchor",
            Error::CertVerifyFailed => "CertificateVerify signature failed",
            Error::FinishedMismatch => "server Finished MAC failed",
            Error::UnexpectedMessage => "message out of order",
            Error::TooEarly => "phase not reached yet",
            Error::TooLate => "phase already past",
            Error::Buffer => "buffer too small",
        }
    }
}

/// What one fed record produced.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Event {
    /// Nothing decisive yet — keep feeding.
    Continue,
    /// The whole server flight verified: keys live, send Finished.
    ServerVerified,
    /// Decrypted application data landed in the caller's buffer.
    AppData(usize),
    /// The server sent an alert (level, description).
    Alert(u8, u8),
}

/// The flight's progress flags.
const F_EE: u8 = 1;
const F_CERT: u8 = 2;
const F_CV: u8 = 4;
const F_FIN: u8 = 8;

/// The handshake message types we consume.
const M_SERVER_HELLO: u8 = 2;
const M_ENCRYPTED_EXTENSIONS: u8 = 8;
const M_CERTIFICATE: u8 = 11;
const M_CERTIFICATE_VERIFY: u8 = 15;
const M_FINISHED: u8 = 20;

/// The negotiated suite: TLS_CHACHA20_POLY1305_SHA256.
const CIPHER_CHACHA20: [u8; 2] = [0x13, 0x03];
/// Ed25519 in the signature schemes registry.
const SIG_ED25519: [u8; 2] = [0x08, 0x07];

/// The ALPN answer buffer (protocol names this client serves).
const ALPN_STORE: usize = 32;

/// The client.
pub struct Client<'a> {
    cfg: ClientConfig<'a>,
    phase: Phase,
    transcript: Transcript,
    schedule: KeySchedule,
    server_hs: RecordCrypto,
    client_hs: RecordCrypto,
    server_ap: RecordCrypto,
    client_ap: RecordCrypto,
    flight_seen: u8,
    client_public: [u8; 32],
    server_random: [u8; 32],
    /// The key the server PRESENTED (extracted at the Certificate
    /// step — the CV signature verifies against THIS, whatever the
    /// verify mode).
    presented_key: Option<[u8; 32]>,
    /// The ALPN protocol the server selected.
    alpn_selected: Option<[u8; ALPN_STORE]>,
    alpn_len: usize,
}

impl<'a> Client<'a> {
    /// A fresh client at `SendHello`.
    pub fn new(cfg: ClientConfig<'a>) -> Client<'a> {
        // The early state is zeroed; the schedule is only valid after
        // ServerHello, but Rust wants every field initialized — the
        // phase gate makes the zeroed cryptos unreachable before
        // their keys derive.
        Client {
            client_public: x25519::public_key(&cfg.client_private),
            cfg,
            phase: Phase::SendHello,
            transcript: Transcript::new(),
            schedule: KeySchedule::from_parts(),
            server_hs: RecordCrypto::from_secret(&[0u8; 32]),
            client_hs: RecordCrypto::from_secret(&[0u8; 32]),
            server_ap: RecordCrypto::from_secret(&[0u8; 32]),
            client_ap: RecordCrypto::from_secret(&[0u8; 32]),
            flight_seen: 0,
            server_random: [0u8; 32],
            presented_key: None,
            alpn_selected: None,
            alpn_len: 0,
        }
    }

    /// The current phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The ALPN protocol the server selected (None if none was
    /// negotiated). Valid after `ServerVerified`. The name lands in
    /// the caller's buffer (bounded to 32 bytes) — the protocol list
    /// this client serves fits by construction.
    pub fn negotiated_alpn(&self, out: &mut [u8]) -> Option<usize> {
        let s = self.alpn_selected?;
        let n = self.alpn_len;
        if out.len() < n {
            return None;
        }
        out[..n].copy_from_slice(&s[..n]);
        Some(n)
    }

    /// Build the ClientHello as a full record into `out`; appends the
    /// handshake message to the transcript. Returns the length.
    ///
    /// The extension set: supported_versions, supported_groups,
    /// signature_algorithms, key_share — plus the FLAGS' own:
    /// server_name (SNI) and ALPN when set.
    pub fn build_client_hello(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.phase != Phase::SendHello {
            return Err(Error::TooLate);
        }
        let host = self.cfg.options.sni;
        let alpn = self.cfg.options.alpn;
        // guards: the SNI host ≤ 200 bytes, ≤ 8 protocols of ≤ 200
        if host.map(|h| h.len() > 200).unwrap_or(false) {
            return Err(Error::Buffer);
        }
        if alpn.len() > 8 || alpn.iter().any(|p| p.len() > 200) {
            return Err(Error::Buffer);
        }
        let sni_ext = host.map(|h| 4 + 5 + h.len()).unwrap_or(0);
        let alpn_list: usize = alpn.iter().map(|p| 1 + p.len()).sum();
        let alpn_ext = if alpn.is_empty() {
            0
        } else {
            4 + 2 + alpn_list
        };
        let ext_total = 7 + 8 + 8 + 42 + sni_ext + alpn_ext;
        // body: version(2) random(32) session_id(1+32) ciphers(2+2)
        //       compression(1+1) extensions(2+…)
        let body_len = 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2 + ext_total;
        let msg_len = 4 + body_len;
        if out.len() < 5 + msg_len || msg_len > 300 {
            return Err(Error::Buffer);
        }
        let mut m = [0u8; 300];
        m[0] = 1; // ClientHello
        m[1] = (body_len >> 16) as u8;
        m[2] = (body_len >> 8) as u8;
        m[3] = body_len as u8;
        let mut p = 4;
        m[p] = 0x03;
        m[p + 1] = 0x03; // legacy_version 0x0303
        p += 2;
        m[p..p + 32].copy_from_slice(&self.cfg.client_random);
        p += 32;
        m[p] = 32; // session id (compat)
        p += 1;
        m[p..p + 32].copy_from_slice(&self.cfg.session_id);
        p += 32;
        m[p] = 0x00;
        m[p + 1] = 0x02; // cipher_suites len
        m[p + 2] = CIPHER_CHACHA20[0];
        m[p + 3] = CIPHER_CHACHA20[1];
        p += 4;
        m[p] = 0x01; // compression methods len
        m[p + 1] = 0x00; // null
        p += 2;
        m[p] = (ext_total >> 8) as u8;
        m[p + 1] = ext_total as u8;
        p += 2;
        // supported_versions
        m[p] = 0x00;
        m[p + 1] = 0x2b;
        m[p + 2] = 0x00;
        m[p + 3] = 0x03;
        m[p + 4] = 0x02;
        m[p + 5] = 0x03;
        m[p + 6] = 0x04;
        p += 7;
        // supported_groups
        m[p] = 0x00;
        m[p + 1] = 0x0a;
        m[p + 2] = 0x00;
        m[p + 3] = 0x04;
        m[p + 4] = 0x00;
        m[p + 5] = 0x02;
        m[p + 6] = 0x00;
        m[p + 7] = 0x1d;
        p += 8;
        // signature_algorithms
        m[p] = 0x00;
        m[p + 1] = 0x0d;
        m[p + 2] = 0x00;
        m[p + 3] = 0x04;
        m[p + 4] = 0x00;
        m[p + 5] = 0x02;
        m[p + 6] = SIG_ED25519[0];
        m[p + 7] = SIG_ED25519[1];
        p += 8;
        // key_share
        m[p] = 0x00;
        m[p + 1] = 0x33;
        m[p + 2] = 0x00;
        m[p + 3] = 0x26; // the extension value: 38
        m[p + 4] = 0x00;
        m[p + 5] = 0x24; // client_shares list: 36
        m[p + 6] = 0x00;
        m[p + 7] = 0x1d; // x25519
        m[p + 8] = 0x00;
        m[p + 9] = 0x20; // 32
        m[p + 10..p + 42].copy_from_slice(&self.client_public);
        p += 42;
        // the FLAGS' extensions
        if let Some(h) = host {
            // server_name: list_len(2) type(1)=host_name namelen(2) name
            m[p] = 0x00;
            m[p + 1] = 0x00;
            m[p + 2] = ((5 + h.len()) >> 8) as u8;
            m[p + 3] = (5 + h.len()) as u8;
            m[p + 4] = ((3 + h.len()) >> 8) as u8;
            m[p + 5] = (3 + h.len()) as u8;
            m[p + 6] = 0x00; // host_name
            m[p + 7] = (h.len() >> 8) as u8;
            m[p + 8] = h.len() as u8;
            m[p + 9..p + 9 + h.len()].copy_from_slice(h.as_bytes());
            p += 4 + 5 + h.len();
        }
        if !alpn.is_empty() {
            // ALPN: list_len(2) then (len(1) proto)*
            m[p] = 0x00;
            m[p + 1] = 0x10;
            m[p + 2] = ((2 + alpn_list) >> 8) as u8;
            m[p + 3] = (2 + alpn_list) as u8;
            m[p + 4] = (alpn_list >> 8) as u8;
            m[p + 5] = alpn_list as u8;
            p += 6;
            for proto in alpn {
                m[p] = proto.len() as u8;
                m[p + 1..p + 1 + proto.len()].copy_from_slice(proto.as_bytes());
                p += 1 + proto.len();
            }
        }
        debug_assert_eq!(p, msg_len);
        self.transcript.message(&m[..msg_len]);
        let n = crate::record::plain_record(TYPE_HANDSHAKE, &m[..msg_len], out)
            .map_err(|_| Error::Buffer)?;
        // The CH is on the wire: the next thing this client accepts
        // is the ServerHello (a second build call refuses with
        // TooLate — the phase is protocol state, not a convenience).
        self.phase = Phase::WaitServerHello;
        Ok(n)
    }

    /// Feed one complete outer record. The phase gates everything.
    /// The `max_record_len` flag is enforced HERE: a record whose
    /// ciphertext exceeds the budget is refused before any
    /// decryption work.
    pub fn on_record(&mut self, rec: &[u8], app_out: &mut [u8]) -> Result<Event, Error> {
        if rec.len() < 5 {
            return Err(Error::BadRecord);
        }
        let ct_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        if 5 + ct_len != rec.len() || ct_len > self.cfg.options.max_record_len {
            return Err(Error::BadRecord);
        }
        // The compat ChangeCipherSpec may appear anywhere pre-key:
        // skip it (never part of the transcript). The SKIP is
        // VALIDATED (RFC 8446 D.4: payload length exactly 1, value
        // exactly 0x01) — an arbitrary type-20 record is not a
        // middlebox artifact, it is hostile framing and refuses
        // (the hostile battery caught the unconditional skip).
        if rec[0] == TYPE_CHANGE_CIPHER_SPEC {
            if ct_len == 1 && rec.len() == 6 && rec[5] == 0x01 {
                return Ok(Event::Continue);
            }
            return Err(Error::BadHandshake);
        }
        match self.phase {
            Phase::SendHello | Phase::WaitServerHello => {
                if rec[0] != TYPE_HANDSHAKE {
                    return Err(Error::UnexpectedMessage);
                }
                self.on_server_hello(&rec[5..])
            }
            Phase::WaitFlight | Phase::SendFinished | Phase::Established => {
                // WaitFlight: server handshake records.
                // SendFinished/Established: app data records (the
                // server's app stream uses the server_ap keys — but
                // during SendFinished no app data may arrive before
                // our Finished? The echo server answers right after
                // its Finished, possibly before receiving ours —
                // accept it in SendFinished too).
                if self.phase == Phase::WaitFlight {
                    let mut content = [0u8; crate::record::RECORD_CAP];
                    let (inner, n) = self
                        .server_hs
                        .open(rec, &mut content)
                        .map_err(|_| Error::BadRecord)?;
                    if inner == TYPE_ALERT {
                        return alert_of(&content[..n]);
                    }
                    if inner != TYPE_HANDSHAKE {
                        return Err(Error::UnexpectedMessage);
                    }
                    self.on_flight_messages(&content[..n])
                } else {
                    if app_out.len() < crate::record::RECORD_CAP {
                        return Err(Error::Buffer);
                    }
                    let (inner, n) = self
                        .server_ap
                        .open(rec, &mut app_out[..crate::record::RECORD_CAP])
                        .map_err(|_| Error::BadRecord)?;
                    match inner {
                        TYPE_ALERT => alert_of(&app_out[..n]),
                        23 => Ok(Event::AppData(n)),
                        // post-handshake messages (NewSessionTicket,
                        // KeyUpdate): not consumed by this client —
                        // skip, keep feeding. Session resumption is
                        // out of scope by name.
                        22 => Ok(Event::Continue),
                        _ => Err(Error::UnexpectedMessage),
                    }
                }
            }
        }
    }

    /// Parse the ServerHello record payload (handshake type 2).
    fn on_server_hello(&mut self, payload: &[u8]) -> Result<Event, Error> {
        if payload.len() < 4 + 2 + 32 + 1 + 2 + 2 + 1 + 2 {
            return Err(Error::BadHandshake);
        }
        if payload[0] != M_SERVER_HELLO {
            // A HelloRetryRequest (type 6) is out of policy for this
            // minimal client — loud refusal.
            return Err(Error::UnexpectedMessage);
        }
        let body = &payload[4..];
        if body[0] != 0x03 || body[1] != 0x03 {
            return Err(Error::BadVersion);
        }
        self.server_random.copy_from_slice(&body[2..34]);
        let sid_len = body[34] as usize;
        let mut p = 35 + sid_len;
        if p + 2 + 1 + 2 > body.len() {
            return Err(Error::BadHandshake);
        }
        if body[p] != CIPHER_CHACHA20[0] || body[p + 1] != CIPHER_CHACHA20[1] {
            return Err(Error::BadCipher);
        }
        p += 2;
        // legacy_compression_methods: a length byte + methods. Real
        // servers send either 1+null or a ZERO-length vector (OpenSSL
        // 3.5 does the latter) — accept both, anything else refuses.
        let comp_len = body[p] as usize;
        if comp_len > 1 {
            return Err(Error::BadHandshake);
        }
        p += 1 + comp_len;
        if p + 2 > body.len() {
            return Err(Error::BadHandshake);
        }
        let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        if p + ext_len > body.len() {
            return Err(Error::BadHandshake);
        }
        // Walk the extensions: need supported_versions (0x0304) and
        // the x25519 key share. NOTE the SERVER's shapes: the
        // selected version is BARE (no list length); the key share is
        // ONE entry directly (group + length + key), no list wrapper.
        let mut version_ok = false;
        let mut server_public: Option<[u8; 32]> = None;
        let exts = &body[p..p + ext_len];
        let mut q = 0;
        while q + 4 <= exts.len() {
            let et = u16::from_be_bytes([exts[q], exts[q + 1]]);
            let el = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
            if q + 4 + el > exts.len() {
                return Err(Error::BadHandshake);
            }
            let ev = &exts[q + 4..q + 4 + el];
            match et {
                // bare 0x0304 (the server's selected version), or the
                // length-prefixed list form — accept both
                0x002b if ev.len() == 2 => {
                    version_ok = ev[0] == 0x03 && ev[1] == 0x04;
                }
                0x002b if ev.len() == 3 && ev[0] == 2 => {
                    version_ok = ev[1] == 0x03 && ev[2] == 0x04;
                }
                // the single server entry: 001d 0020 <32>
                0x0033 if ev.len() == 36 => {
                    if ev[0] != 0x00 || ev[1] != 0x1d || ev[2] != 0x00 || ev[3] != 0x20 {
                        return Err(Error::BadKeyShare);
                    }
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&ev[4..36]);
                    server_public = Some(pk);
                }
                _ => {}
            }
            q += 4 + el;
        }
        if !version_ok {
            return Err(Error::BadVersion);
        }
        let Some(server_public) = server_public else {
            return Err(Error::BadKeyShare);
        };
        // ECDHE + the key schedule + both record cryptos.
        let ecdhe = x25519::shared(&self.cfg.client_private, &server_public);
        // The record's payload IS the whole handshake message.
        let msg_len = 4 + body.len();
        self.transcript.message(&payload[..msg_len]);
        let th = self.transcript.hash();
        self.schedule = KeySchedule::new(&ecdhe, &th);
        self.server_hs = RecordCrypto::from_secret(&self.schedule.server_hs_traffic);
        self.client_hs = RecordCrypto::from_secret(&self.schedule.client_hs_traffic);
        self.phase = Phase::WaitFlight;
        Ok(Event::Continue)
    }

    /// The encrypted flight: a stream of handshake messages in one
    /// record's content.
    fn on_flight_messages(&mut self, content: &[u8]) -> Result<Event, Error> {
        let mut p = 0;
        while p + 4 <= content.len() {
            let mtype = content[p];
            let mlen = (usize::from(content[p + 1]) << 16)
                | (usize::from(content[p + 2]) << 8)
                | usize::from(content[p + 3]);
            if p + 4 + mlen > content.len() {
                return Err(Error::BadHandshake); // a split message: refused, loud
            }
            let msg = &content[p..p + 4 + mlen];
            match mtype {
                M_ENCRYPTED_EXTENSIONS => {
                    self.on_encrypted_extensions(&msg[4..])?;
                    self.transcript.message(msg);
                    self.flight_seen |= F_EE;
                }
                M_CERTIFICATE => {
                    self.transcript.message(msg);
                    let Some(der) = cert::first_certificate_entry(&msg[4..]) else {
                        return Err(Error::CertMalformed);
                    };
                    let Some(pk) = cert::ed25519_public_key(der) else {
                        return Err(Error::CertMalformed);
                    };
                    // THE VERIFY MODE — the trust policy flag
                    match self.cfg.options.verify {
                        VerifyMode::Pinned => {
                            if !ct_eq(&pk, &self.cfg.pinned_ed25519) {
                                return Err(Error::PinMismatch);
                            }
                        }
                        VerifyMode::PinnedRequireName => {
                            if !ct_eq(&pk, &self.cfg.pinned_ed25519) {
                                return Err(Error::PinMismatch);
                            }
                            let Some(host) = self.cfg.options.sni else {
                                return Err(Error::NameMismatch);
                            };
                            let Some(cn) = cert::subject_cn(der) else {
                                return Err(Error::NameMismatch);
                            };
                            if cn != host.as_bytes() {
                                return Err(Error::NameMismatch);
                            }
                        }
                        // TOFU: no pin check — the signature below
                        // still binds the presented key
                        VerifyMode::AcceptAnyKey => {}
                    }
                    self.presented_key = Some(pk);
                    self.flight_seen |= F_CERT;
                }
                M_CERTIFICATE_VERIFY => {
                    if (self.flight_seen & F_CERT) == 0 {
                        return Err(Error::UnexpectedMessage);
                    }
                    let body = &msg[4..];
                    if body.len() != 2 + 2 + 64
                        || body[0] != SIG_ED25519[0]
                        || body[1] != SIG_ED25519[1]
                    {
                        return Err(Error::BadHandshake);
                    }
                    // The signed content: 64 bytes of 0x20, the context
                    // string, a 0x00 separator, then the transcript
                    // hash (through the Certificate) — the RFC's exact
                    // concatenation (a silent zero-fill of the 0x20
                    // padding failed every live signature until the
                    // bytes matched the spec).
                    let th = self.transcript.hash();
                    let mut signed = [0x20u8; 64 + 33 + 1 + 32];
                    signed[64..97].copy_from_slice(b"TLS 1.3, server CertificateVerify");
                    signed[97] = 0x00;
                    signed[98..130].copy_from_slice(&th);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&body[4..68]);
                    // the key the server PRESENTED — not the pin: the
                    // signature must bind the flight's own key
                    let Some(pk) = self.presented_key else {
                        return Err(Error::UnexpectedMessage);
                    };
                    if !ed25519::verify(&pk, &signed, &sig) {
                        return Err(Error::CertVerifyFailed);
                    }
                    self.transcript.message(msg);
                    self.flight_seen |= F_CV;
                }
                M_FINISHED => {
                    if (self.flight_seen & (F_EE | F_CERT | F_CV)) != (F_EE | F_CERT | F_CV) {
                        return Err(Error::UnexpectedMessage);
                    }
                    let body = &msg[4..];
                    if body.len() != 32 {
                        return Err(Error::BadHandshake);
                    }
                    let fk = KeySchedule::finished_key(&self.schedule.server_hs_traffic);
                    let th = self.transcript.hash();
                    let expect = hkdf::hmac_sha256(&fk, &th);
                    if !ct_eq(&expect, body) {
                        return Err(Error::FinishedMismatch);
                    }
                    self.transcript.message(msg);
                    let th_fin = self.transcript.hash();
                    self.schedule.finish_application(&th_fin);
                    self.server_ap = RecordCrypto::from_secret(&self.schedule.server_ap_traffic);
                    self.client_ap = RecordCrypto::from_secret(&self.schedule.client_ap_traffic);
                    self.flight_seen |= F_FIN;
                    self.phase = Phase::SendFinished;
                    return Ok(Event::ServerVerified);
                }
                _ => return Err(Error::UnexpectedMessage),
            }
            p += 4 + mlen;
        }
        Ok(Event::Continue)
    }

    /// EncryptedExtensions: the flags' answer surface — the ALPN
    /// selection. Total and length-checked: an unsolicited ALPN, an
    /// answer we did not offer, or a malformed list all refuse with
    /// `BadAlpn`.
    fn on_encrypted_extensions(&mut self, body: &[u8]) -> Result<(), Error> {
        let offered = self.cfg.options.alpn;
        if body.len() < 2 {
            return Err(Error::BadHandshake);
        }
        let ext_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if 2 + ext_len > body.len() {
            return Err(Error::BadHandshake);
        }
        let exts = &body[2..2 + ext_len];
        let mut q = 0;
        while q + 4 <= exts.len() {
            let et = u16::from_be_bytes([exts[q], exts[q + 1]]);
            let el = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
            if q + 4 + el > exts.len() {
                return Err(Error::BadHandshake);
            }
            if et == 0x0010 {
                // ALPN: list_len(2) (len(1) proto)+
                let ev = &exts[q + 4..q + 4 + el];
                if ev.len() < 2 {
                    return Err(Error::BadAlpn);
                }
                let list_len = u16::from_be_bytes([ev[0], ev[1]]) as usize;
                if 2 + list_len != el || list_len == 0 {
                    return Err(Error::BadAlpn);
                }
                let mut r = 2;
                let mut matched = false;
                while r < ev.len() {
                    let pl = ev[r] as usize;
                    r += 1;
                    if r + pl > ev.len() {
                        return Err(Error::BadAlpn);
                    }
                    let proto = &ev[r..r + pl];
                    if offered.iter().any(|o| o.as_bytes() == proto) {
                        matched = true;
                        // store the answer (bounded)
                        let take = core::cmp::min(pl, ALPN_STORE);
                        let mut store = [0u8; ALPN_STORE];
                        store[..take].copy_from_slice(&proto[..take]);
                        self.alpn_selected = Some(store);
                        self.alpn_len = take;
                    }
                    r += pl;
                }
                if !matched {
                    return Err(Error::BadAlpn);
                }
            }
            q += 4 + el;
        }
        Ok(())
    }

    /// Build the client Finished record (under the CLIENT handshake
    /// keys) into `out`. Marks the session Established.
    pub fn build_finished(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.phase != Phase::SendFinished {
            return Err(Error::TooEarly);
        }
        let fk = KeySchedule::finished_key(&self.schedule.client_hs_traffic);
        let th = self.transcript.hash();
        let mac = hkdf::hmac_sha256(&fk, &th);
        let mut msg = [0u8; 4 + 32];
        msg[0] = M_FINISHED;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        msg[4..36].copy_from_slice(&mac);
        self.transcript.message(&msg);
        let n = self
            .client_hs
            .seal(TYPE_HANDSHAKE, &msg, out)
            .map_err(|_| Error::Buffer)?;
        self.phase = Phase::Established;
        Ok(n)
    }

    /// Seal application data (client → server) into a record.
    pub fn seal_app_data(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.phase != Phase::Established {
            return Err(Error::TooEarly);
        }
        self.client_ap
            .seal(23, data, out)
            .map_err(|_| Error::Buffer)
    }

    /// Which flight messages were seen (diagnostics).
    pub fn flight_seen(&self) -> u8 {
        self.flight_seen
    }
}

/// An alert record's content → the event.
fn alert_of(body: &[u8]) -> Result<Event, Error> {
    if body.len() >= 2 {
        Ok(Event::Alert(body[0], body[1]))
    } else {
        Err(Error::BadRecord)
    }
}
