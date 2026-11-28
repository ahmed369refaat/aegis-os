//! The TLS 1.3 CLIENT state machine (RFC 8446, the 1-RTT
//! certificate path, ChaCha20-Poly1305, Ed25519-pinned).
//!
//! One object drives the whole exchange; the caller (the kernel
//! driver or the host test) feeds records and reads events:
//!
//! ```text
//! build_client_hello  →  send
//! on_record(ServerHello)        → keys derive (WaitFlight)
//! on_record(flight records)     → EE, Certificate (PIN CHECK),
//!                                 CertificateVerify (Ed25519
//!                                 signature over the transcript),
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

/// The client's inputs: the ECDHE private scalar, the two
/// ClientHello randoms, and the PINNED server key (the trust anchor
/// — the SSH known-hosts model; X.509 chain validation is out of
/// scope by name, see THREAT_MODEL.md).
pub struct ClientConfig {
    pub client_private: [u8; 32],
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    pub pinned_ed25519: [u8; 32],
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

/// The client.
pub struct Client {
    cfg: ClientConfig,
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
}

impl Client {
    /// A fresh client at `SendHello`.
    pub fn new(cfg: ClientConfig) -> Client {
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
        }
    }

    /// The current phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Build the ClientHello as a full record into `out`; appends the
    /// handshake message to the transcript. Returns the length.
    pub fn build_client_hello(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.phase != Phase::SendHello {
            return Err(Error::TooLate);
        }
        // The handshake message: type(1) len24 body.
        // body: version(2) random(32) session_id(1+32) ciphers(2+2)
        //       compression(1+1) extensions(2+…)
        // extensions:
        //   supported_versions  002b len 3: 02 0304
        //   supported_groups    000a len 4: 02 001d
        //   signature_algs      000d len 4: 02 0807
        //   key_share           0033: the entry is group(2)+klen(2)+key(32)
        //       = 36 bytes; the list is that entry; the EXTENSION is
        //       the list length field + entry = 38.
        let body_len = 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2
            + 7   // supported_versions: type+len(4) + 3
            + 8   // supported_groups: 4 + 4
            + 8   // signature_algorithms: 4 + 4
            + 42; // key_share: 4 + 2+2+2+32
        let msg_len = 4 + body_len;
        if out.len() < 5 + msg_len {
            return Err(Error::Buffer);
        }
        let mut m = [0u8; 256];
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
        let ext_total = 7 + 8 + 8 + 42;
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
        debug_assert_eq!(p, msg_len);
        self.transcript.message(&m[..msg_len]);
        crate::record::plain_record(TYPE_HANDSHAKE, &m[..msg_len], out).map_err(|_| Error::Buffer)
    }

    /// Feed one complete outer record. The phase gates everything.
    pub fn on_record(&mut self, rec: &[u8], app_out: &mut [u8]) -> Result<Event, Error> {
        if rec.len() < 5 {
            return Err(Error::BadRecord);
        }
        // The compat ChangeCipherSpec may appear anywhere pre-key:
        // skip it (never part of the transcript).
        if rec[0] == TYPE_CHANGE_CIPHER_SPEC {
            return Ok(Event::Continue);
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
                    if !ct_eq(&pk, &self.cfg.pinned_ed25519) {
                        return Err(Error::PinMismatch);
                    }
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
                    let pk = self.cfg.pinned_ed25519;
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
