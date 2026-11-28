//! # aegis-tls — TLS 1.3 for the AegisOS kernel
//!
//! The transport-security layer the stack lacked: raw TCP/IP (K24)
//! could carry bytes but not *secrets*. This crate is a TLS 1.3
//! **client** (RFC 8446) — the record layer, the handshake state
//! machine, the key schedule, and the cryptography it needs — built
//! the way everything in this workspace is built:
//!
//! - `no_std`, **no allocator, zero external crates** (the supply
//!   chain this layer defends is not extended by its own build —
//!   every primitive is inline or comes from the audited `pkg` crate
//!   via a path dependency: SHA-256 streaming, Ed25519 verify,
//!   constant-time comparison)
//! - **zero `unsafe`**: no heap, no raw pointers, no
//!   nightly — all arithmetic on fixed-size arrays
//! - no panics on untrusted input: every parser is length-checked
//!   and total, every refusal is a `Result` (a malformed ServerHello
//!   or a truncated record is a refusal, never a crash)
//! - constant-time where it counts: X25519 is a fixed-sequence
//!   Montgomery ladder (branch-free data flow, constant swaps),
//!   ChaCha20/Poly1305 are ARX (no table lookups), and secret
//!   comparisons go through `pkg::crypto::ct_eq`
//!
//! ## What is implemented (the honest list)
//!
//! - **X25519** (RFC 7748) — the ECDHE of the handshake, 5×51-bit
//!   limbs, pinned by the RFC §6.1 vectors and randomized
//!   cross-checks against an independent implementation
//! - **ChaCha20-Poly1305 AEAD** (RFC 8439) — the TLS 1.3 cipher
//!   suite `TLS_CHACHA20_POLY1305_SHA256`; AES-GCM is NOT implemented
//!   (the table-based AES is the wrong shape for a constant-time,
//!   no-unsafe kernel; ChaCha20-Poly1305 is a MUST in TLS 1.3, so
//!   interop is complete)
//! - **HKDF-SHA-256** (RFC 5869) — extract/expand, the KDF under the
//!   whole key schedule
//! - **The TLS 1.3 key schedule** (RFC 8446 §7.1) — early secret →
//!   handshake secret → master secret, derived secrets, the
//!   traffic keys/IVs, and the finished keys
//! - **The record layer** — the 1-RTT client flight (ClientHello in
//!   the clear, everything after encrypted under the schedule's
//!   keys), the AEAD nonce = static_iv XOR sequence, the
//!   content-type tagging, compatibility ChangeCipherSpec passthrough
//! - **The client state machine** — ClientHello build, ServerHello
//!   parse (key share, version), the encrypted server flight
//!   (EncryptedExtensions, Certificate, CertificateVerify, Finished)
//!   decrypt+parse, the server **Ed25519 CertificateVerify
//!   verification** (pinned-key trust: the X.509 SubjectPublicKeyInfo
//!   is walked, the raw 32-byte key must equal the pinned anchor,
//!   and the signature over the transcript must verify through
//!   `pkg`'s Ed25519), the client Finished, and application-data
//!   seal/open
//! - **What is NOT implemented, by name:** X.509 chain validation
//!   (no CA path building, no expiry/name checks — the trust model
//!   is a pinned key, SSH's known-hosts shape, stated in
//!   THREAT_MODEL.md), AES-GCM, TLS 1.2 and below (protocol
//!   downgrade is refused), session resumption/0-RTT/PSK, client
//!   certificates, and renegotiation (which TLS 1.3 removed)
//!
//! ## The proof discipline
//!
//! Every primitive is pinned by its RFC's own vectors; the AEAD runs
//! a 300-case randomized sweep against the `cryptography` library;
//! the handshake machine is pinned by a RECORDED transcript of a
//! real OpenSSL 3.5.7 server (the fixture is committed under
//! `tls/tests/` with the generation recipe — the test replays the
//! server flight, derives the same keys, decrypts, and verifies the
//! CertificateVerify signature offline); and the whole stack runs
//! LIVE on the boot lane (`drvstack/tls.rs`): a ring-0 step drives
//! the kernel's own TCP/IP stack over the e1000, through QEMU's
//! slirp, to a real OpenSSL server on the host — the handshake, one
//! encrypted request, and the encrypted echo back.

#![cfg_attr(not(test), no_std)]
// The crypto kernels index fixed limb arrays by design (the limb IS
// the data's shape); the unit `Err(())` is deliberate — a refusal
// with no payload to leak (the loud *typing* lives one layer up, in
// `handshake::Error`).
#![allow(clippy::result_unit_err)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::len_without_is_empty)]

pub mod aead;
pub mod cert;
pub mod chacha;
pub mod handshake;
pub mod hkdf;
pub mod poly1305;
pub mod record;
pub mod schedule;
pub mod transcript;
pub mod x25519;

#[cfg(test)]
mod tests;
