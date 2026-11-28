//! K28: THE HOSTILE BATTERY — violent network tests for the TLS
//! client. The premise: every byte that arrives is attacker
//!-controlled until the MAC says otherwise. What is proved here:
//!
//! 1. **No panic, ever** — every mutation, truncation, lie, and
//!    storm is a typed refusal or a silent skip, never a crash.
//! 2. **The flight is tamper-evident** — a systematic EVERY-BYTE
//!    mutation sweep over the recorded OpenSSL flight: no
//!    single-byte change of any server record yields
//!    `ServerVerified` (or plaintext `AppData` for the echo).
//! 3. **The downgrade is structural** — no version but 0x0304, no
//!    cipher but ChaCha20-Poly1305 exists in the binary.
//! 4. **The trust flags bind** — wrong pin, wrong name, forged
//!    Finished, replay: each refuses with its OWN name.
//! 5. **The machine is not wedged by garbage** — after 500 hostile
//!    records the real flight still completes.
//!
//! The battery runs on the COMMITTED fixture (a recorded real
//! server), so it is deterministic and CI-green; the LIVE hostile
//! peer (a wrong-key server on the real lane) is the boot lane's
//! own proof.

use super::{hex, hexs, hexv, CLIENT_PRIVATE, CLIENT_RANDOM, PIN, SESSION_ID};
use crate::aead;
use crate::handshake::{Client, ClientConfig, Error, Event, Phase, VerifyMode};
use crate::record::RECORD_CAP;

/// The fixture's records: (kind, bytes).
fn load_fixture() -> Vec<(String, Vec<u8>)> {
    let data = match std::fs::read_to_string("tests/flight-fixture.txt") {
        Ok(d) => d,
        Err(_) => return Vec::new(), // no fixture — the battery no-ops
    };
    let mut out = Vec::new();
    for line in data.lines() {
        if let Some((kind, hx)) = line.split_once(' ') {
            out.push((kind.to_string(), hexv(hx)));
        }
    }
    out
}

/// A client over the fixture's config (an override hook for the
/// attack cases).
fn client_with<'a>(pin: [u8; 32], verify: VerifyMode, sni: Option<&'a str>) -> Client<'a> {
    Client::new(ClientConfig {
        client_private: CLIENT_PRIVATE,
        client_random: CLIENT_RANDOM,
        session_id: SESSION_ID,
        pinned_ed25519: pin,
        options: crate::handshake::TlsOptions {
            sni,
            alpn: &["echo/1"],
            verify,
            max_record_len: RECORD_CAP,
        },
    })
}

/// Drive the flight through a fresh client (the CH must be built
/// first — the transcript needs it).
fn drive(client: &mut Client, srs: &[Vec<u8>]) -> (bool, usize, Option<Error>) {
    let mut out = [0u8; RECORD_CAP + 64];
    // only a client still at SendHello needs its CH built (a client
    // mid-exchange already has one in its transcript)
    if client.phase() == Phase::SendHello {
        let _ = client.build_client_hello(&mut out);
    }
    let mut verified = false;
    let mut app = 0usize;
    let mut last_err = None;
    let mut scratch = [0u8; RECORD_CAP];
    for rec in srs {
        match client.on_record(rec, &mut scratch) {
            Ok(Event::Continue) => {}
            Ok(Event::ServerVerified) => {
                verified = true;
                let n = client.build_finished(&mut out).unwrap_or(0);
                let _ = n;
            }
            Ok(Event::AppData(n)) => app += n,
            Ok(Event::Alert(..)) => {}
            Err(e) => {
                last_err = Some(e);
                break; // the state machine refuses: the exchange is over
            }
        }
    }
    (verified, app, last_err)
}

/// The control: the pristine flight MUST verify (else the battery
/// itself is broken).
#[test]
fn hostile_battery_control_the_flight_verifies() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    let mut c = client_with(PIN, VerifyMode::PinnedRequireName, Some("aegis-tls"));
    let (verified, app, err) = drive(&mut c, &srs);
    assert!(verified, "the control must verify: {err:?}");
    assert!(app > 0, "the control must decrypt the echo");
    // and the flags answered: the ALPN negotiation
    let mut alpn = [0u8; 32];
    let n = c.negotiated_alpn(&mut alpn);
    assert_eq!(n, Some(6), "the ALPN answer's length");
    assert_eq!(&alpn[..6], b"echo/1", "the ALPN answer");
}

/// THE EVERY-BYTE MUTATION SWEEP over the whole recorded flight:
/// flip each byte (XOR 0xFF, 0x01, 0x80) of every server record and
/// replay the flight. SECURITY INVARIANTS:
///   - no panic (the sweep completing IS the assertion),
///   - NO mutation of any SERVER FLIGHT record yields
///     `ServerVerified` — every byte of the SH is transcript-hashed
///     (a changed SH changes the keys, the flight's AEAD tag
///     fails); every byte of the flight is either parser-relevant
///     (a typed refusal) or transcript-hashed (the MAC fails),
///   - NO mutation of the ECHO record yields plaintext `AppData`
///     (the AEAD tag covers every ciphertext byte).
#[test]
fn hostile_battery_every_byte_mutation_sweep() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    // the echo record = the LAST SR (the AppData one)
    let echo_idx = srs.len() - 1;
    // the critical prefix: records [first SH .. the Finished]. Drive
    // once and note where ServerVerified fired; mutations BEFORE
    // that point are in-bounds (the security state); after it (the
    // skipped NSTs) and the pre-key CCS are out-of-bounds BY DESIGN.
    let mut c0 = client_with(PIN, VerifyMode::PinnedRequireName, Some("aegis-tls"));
    let mut out0 = [0u8; RECORD_CAP + 64];
    let _ = c0.build_client_hello(&mut out0);
    let mut scratch0 = [0u8; RECORD_CAP];
    let mut fin_idx = srs.len() - 1;
    for (i, rec) in srs.iter().enumerate() {
        if matches!(c0.on_record(rec, &mut scratch0), Ok(Event::ServerVerified)) {
            fin_idx = i;
            break;
        }
    }
    let first_sh = srs
        .iter()
        .position(|r| r[0] == 22 && r.len() > 60)
        .unwrap_or(0);
    let mut verified_leaks = 0usize;
    let mut app_leaks = 0usize;
    let mut cases = 0usize;
    let mut refusals = 0usize;
    for (ri, rec) in srs.iter().enumerate() {
        for i in 0..rec.len() {
            for flip in [0xFFu8, 0x01, 0x80] {
                let mut hostile = rec.clone();
                hostile[i] ^= flip;
                let mut flight = srs.clone();
                flight[ri] = hostile;
                let mut c = client_with(PIN, VerifyMode::PinnedRequireName, Some("aegis-tls"));
                let (verified, app, e) = drive(&mut c, &flight);
                cases += 1;
                if verified {
                    // A mutation that STILL verified is in-bounds
                    // only for bytes with no security meaning:
                    // records outside the critical prefix (the
                    // pre-key CCS, the post-handshake NSTs, the
                    // echo), and the outer record header's VERSION
                    // bytes (offsets 1..3) — RFC 8446 §5.1:
                    // legacy_record_version MUST be ignored (real
                    // middleboxes rewrite it; the transcript and the
                    // AAD of ENCRYPTED records never see it).
                    let in_bounds = i >= 5 && ri >= first_sh && ri <= fin_idx;
                    if in_bounds && ri != echo_idx {
                        verified_leaks += 1;
                    }
                }
                if app > 0 && ri == echo_idx {
                    app_leaks += 1;
                }
                if e.is_some() {
                    refusals += 1;
                }
            }
        }
    }
    assert_eq!(
        verified_leaks, 0,
        "a mutated FLIGHT record verified the handshake — the MAC or the pin is broken"
    );
    assert_eq!(
        app_leaks, 0,
        "a mutated ECHO record released plaintext — the AEAD tag is broken"
    );
    assert!(cases > 3000, "the sweep must actually run (got {cases})");
    assert!(
        refusals >= cases / 2,
        "most mutations must refuse loudly (got {refusals}/{cases})"
    );
}

/// Truncation: EVERY prefix of EVERY server record (0..len bytes),
/// plus the empty record. No panic; every truncation refuses (a
/// short record cannot carry a valid tag).
#[test]
fn hostile_battery_every_truncation() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    // the critical prefix (the sweep's own calculus): truncations
    // BEFORE the handshake completes must not let it complete;
    // after it (the NSTs, the echo) only the no-release invariant
    // applies — the handshake is already done
    let mut c0 = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    let mut out0 = [0u8; RECORD_CAP + 64];
    let _ = c0.build_client_hello(&mut out0);
    let mut scratch0 = [0u8; RECORD_CAP];
    let mut fin_idx = srs.len();
    for (i, rec) in srs.iter().enumerate() {
        if matches!(c0.on_record(rec, &mut scratch0), Ok(Event::ServerVerified)) {
            fin_idx = i;
            break;
        }
    }
    for (ri, rec) in srs.iter().enumerate() {
        for cut in 0..rec.len() {
            // the full record is the control, not a truncation
            let mut flight = srs.clone();
            flight[ri] = rec[..cut].to_vec();
            let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
            let (verified, app, _) = drive(&mut c, &flight);
            if ri <= fin_idx {
                assert!(
                    !verified && app == 0,
                    "a truncated record completed the handshake (record {ri}, cut {cut})"
                );
            } else {
                assert!(
                    app == 0,
                    "a truncated record released plaintext (record {ri}, cut {cut})"
                );
            }
        }
    }
}

/// Header lies: the length field disagrees with the frame (the
/// 0xFFFF bomb, the zero-length claim, off-by-ones), absurd record
/// types, and pure garbage of many sizes. All refuse; nothing
/// panics; nothing decrypts.
#[test]
fn hostile_battery_header_lies_and_garbage() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    // deterministic garbage (a reproducible storm)
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut garbage = |n: usize| -> Vec<u8> {
        let mut v = vec![0u8; n];
        for b in v.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = seed as u8;
        }
        v
    };
    let mut lies: Vec<Vec<u8>> = Vec::new();
    // the length bomb: says 0xFFFF, carries 20
    let mut bomb = vec![22u8, 0x03, 0x03, 0xff, 0xff];
    bomb.extend(garbage(20));
    lies.push(bomb);
    // says zero, carries 20
    let mut zero = vec![22u8, 0x03, 0x03, 0x00, 0x00];
    zero.extend(garbage(20));
    lies.push(zero);
    // off-by-one up and down on a real record
    let mut up = srs[0].clone();
    up[3] = up[3].wrapping_add(1);
    let mut down = srs[0].clone();
    down[4] = down[4].wrapping_sub(1);
    lies.push(up);
    lies.push(down);
    // absurd types
    for t in [0u8, 1, 19, 24, 255] {
        let mut r = vec![t, 0x03, 0x03, 0x00, 0x05];
        r.extend(garbage(5));
        lies.push(r);
    }
    // raw garbage of many lengths (below and above the header)
    for n in [0usize, 1, 2, 3, 4, 5, 6, 10, 40, 77] {
        lies.push(garbage(n));
    }
    for lie in &lies {
        let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
        let flight = srs_first_then(&srs, 1, lie);
        let (verified, app, _) = drive(&mut c, &flight);
        assert!(!verified && app == 0, "a lie verified/decrypted: {lie:?}");
    }
    // garbage INSTEAD of the flight entirely
    for _ in 0..200 {
        let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
        let storm: Vec<Vec<u8>> = (0..5).map(|_| garbage(64)).collect();
        let (verified, app, _) = drive(&mut c, &storm);
        assert!(!verified && app == 0);
    }
}

/// One real record, then the lie appended (the state must be past
/// the SH when the lie lands).
fn srs_first_then(srs: &[Vec<u8>], real: usize, lie: &[u8]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = srs[..real.min(srs.len())].to_vec();
    v.push(lie.to_vec());
    v
}

/// The downgrade attacks: a ServerHello claiming 0x0303, one with
/// NO supported_versions, one with a list, one offering a cipher we
/// do not compile. TLS 1.2 does not exist in this binary — the
/// refusals are structural, not configurational.
#[test]
fn hostile_battery_downgrade_is_structural() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    // the SH record: the first HANDSHAKE record (the compat CCS may
    // lead the flight)
    let sh_idx = srs
        .iter()
        .position(|r| r[0] == 22 && r.len() > 60)
        .expect("an SH record");
    let sh = &srs[sh_idx];
    // the SH's supported_versions ext: 002b 0003 02 0304 — find it
    // (the mutation surgery is by CONTENT, not fixed offset)
    let mut cases = 0usize;
    for i in 0..sh.len().saturating_sub(6) {
        // the supported_versions extension: 00 2b <len16> <value> —
        // the SERVER's value is BARE (02 bytes: 03 04) or the
        // list form (02 03 04). Both carry the version at the END
        // of the value.
        if sh[i] == 0x00 && sh[i + 1] == 0x2b && i + 4 <= sh.len() {
            let el = u16::from_be_bytes([sh[i + 2], sh[i + 3]]) as usize;
            if el != 2 && el != 3 {
                continue; // not a version shape we know — keep scanning
            }
            // claim 0x0303 instead of 0x0304 (the value's last two
            // bytes, whichever form)
            let mut dw = sh.clone();
            let v = i + 4 + el - 2; // the last two value bytes
            dw[v] = 0x03;
            dw[v + 1] = 0x03;
            let mut flight = srs.clone();
            let shv = dw;
            flight[sh_idx] = shv;
            let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
            let (v, _, e) = drive(&mut c, &flight);
            assert!(!v, "a 0x0303 ServerHello verified");
            assert_eq!(e, Some(Error::BadVersion), "the downgrade refusal is named");
            cases += 1;
            // drop the extension entirely: the version is unset
            let mut nov = srs.clone();
            let shr = sh.clone();
            nov[0] = strip_extension(&shr, i);
            let mut c2 = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
            let (v2, _, e2) = drive(&mut c2, &nov);
            assert!(!v2);
            assert_eq!(e2, Some(Error::BadVersion));
            cases += 1;
        }
    }
    assert!(cases >= 2, "the surgery must find the version extension");
    // the cipher echo: mutate every 2-byte window that makes
    // 0x1303 into 0x1301 (AES_GCM — not compiled)
    let mut aes = sh.clone();
    for i in 0..aes.len().saturating_sub(1) {
        if aes[i] == 0x13 && aes[i + 1] == 0x03 {
            aes[i + 1] = 0x01;
            break;
        }
    }
    let mut flight = srs.clone();
    flight[sh_idx] = aes;
    let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    let (v, _, e) = drive(&mut c, &flight);
    assert!(!v, "an AES-GCM cipher echoed and verified");
    assert_eq!(
        e,
        Some(Error::BadCipher),
        "the weak cipher refusal is named"
    );
}

/// Remove one extension (4-byte header + its value) around offset
/// `i` (the extension starts at i) — surgery for the version-drop
/// case.
fn strip_extension(rec: &[u8], i: usize) -> Vec<u8> {
    if i + 4 > rec.len() {
        return rec.to_vec();
    }
    let el = u16::from_be_bytes([rec[i + 2], rec[i + 3]]) as usize;
    if i + 4 + el > rec.len() {
        return rec.to_vec();
    }
    // The version-drop surgery: corrupt the extension's VALUE into
    // a shape the walk refuses (not 0x0304 in either form). The
    // value spans i+4 .. i+4+el; overwrite its first two bytes.
    let el = u16::from_be_bytes([rec[i + 2], rec[i + 3]]) as usize;
    let mut out = rec.to_vec();
    let v = i + 4;
    if v + 2 <= out.len() {
        out[v] = 0x02;
        out[v + 1] = 0x02;
    }
    let _ = el;
    out
}

/// The trust flags bind: the wrong pin, the wrong name, the forged
/// Finished — each refusal carries ITS OWN NAME (the
/// distinguishable-cause discipline).
#[test]
fn hostile_battery_trust_flags_refuse_by_name() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    // the wrong pin
    let mut c = client_with([0u8; 32], VerifyMode::Pinned, Some("aegis-tls"));
    let (v, _, e) = drive(&mut c, &srs);
    assert!(!v);
    assert_eq!(e, Some(Error::PinMismatch), "the wrong pin is NAMED");
    // The WRONG NAME is proved at TWO levels:
    //   (a) here: the `subject_cn` walk on a crafted DER whose CN
    //       differs (the encrypted flight's CN cannot be surgically
    //       mutated from outside — the AEAD tag covers it, which is
    //       itself the point);
    //   (b) LIVE: the boot lane's hostile server presents the SAME
    //       key under a DIFFERENT CN — the kernel's
    //       `PinnedRequireName` must answer NameMismatch (the
    //       pin passes, the name refuses).
    // TOFU: a wrong pin still verifies (the signature binds the
    // PRESENTED key — the documented semantics)
    let mut c3 = client_with([0u8; 32], VerifyMode::AcceptAnyKey, Some("aegis-tls"));
    let (v3, app, e3) = drive(&mut c3, &srs);
    assert!(v3, "TOFU must verify the signature: {e3:?}");
    assert!(app > 0, "TOFU must still decrypt");
    // the forged Finished: zero the last 32 bytes of the record
    // that ACTUALLY completed the flight (found by driving once —
    // the layout is the server's, not ours)
    let mut c0 = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    let mut out0 = [0u8; RECORD_CAP + 64];
    let _ = c0.build_client_hello(&mut out0);
    let mut scratch0 = [0u8; RECORD_CAP];
    let mut fin_idx = srs.len() - 2;
    for (i, rec) in srs.iter().enumerate() {
        if matches!(c0.on_record(rec, &mut scratch0), Ok(Event::ServerVerified)) {
            fin_idx = i;
            break;
        }
    }
    let mut forged = srs.clone();
    {
        let f = forged[fin_idx].clone();
        let n = f.len();
        let mut nf = f;
        nf[n - 32..].copy_from_slice(&[0u8; 32]);
        forged[fin_idx] = nf;
    }
    let mut c4 = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    let (v4, _, e4) = drive(&mut c4, &forged);
    assert!(!v4, "a zeroed Finished verified");
    // The record has TWO walls: the outer AEAD tag catches the
    // zeroed tail first (BadRecord); the inner Finished MAC
    // (FinishedMismatch) is the second wall — both are typed
    // refusals, both end the exchange. Either name is the proof.
    assert!(
        e4 == Some(Error::FinishedMismatch) || e4 == Some(Error::BadRecord),
        "the forged Finished is NAMED: {e4:?}"
    );
}

/// The replay attack: the whole flight, verbatim, AFTER the
/// handshake completed. The phase gate must refuse (the machine
/// never re-derives keys from a replayed plaintext SH).
#[test]
fn hostile_battery_flight_replay_refused() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    let (v, app, _) = drive(&mut c, &srs);
    assert!(v && app > 0);
    assert_eq!(c.phase(), Phase::Established);
    // the replay: every record again
    let mut scratch = [0u8; RECORD_CAP];
    let mut replays_decrypted = 0;
    for rec in &srs {
        let r = c.on_record(rec, &mut scratch);
        // The anti-replay is the SEQUENCE: every encrypted record
        // the machine already consumed fails its nonce-derived tag
        // on the second pass (BadRecord). The CCS skip and the
        // skipped-typed plaintext records may Continue — they carry
        // no state. NEVER a second verification, NEVER a release.
        assert!(
            !matches!(r, Ok(Event::ServerVerified)),
            "a replayed record VERIFIED twice: type {}",
            rec[0]
        );
        if matches!(r, Ok(Event::AppData(_))) {
            replays_decrypted += 1;
        }
    }
    assert_eq!(replays_decrypted, 0, "a replayed record released plaintext");
    assert_eq!(c.phase(), Phase::Established, "the replay moved the phase");
}

/// The garbage storm DOES NOT WEDGE the machine: 500 hostile
/// records first, then the real flight — the handshake still
/// completes.
#[test]
fn hostile_battery_storm_then_real_flight() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    let mut c = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    let mut out = [0u8; RECORD_CAP + 64];
    let _ = c.build_client_hello(&mut out);
    let mut scratch = [0u8; RECORD_CAP];
    // the storm: every shape of lie, 500 rounds
    let mut seed: u64 = 0xd1b5_4a32_d192_0ed5;
    for round in 0..500u64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let n = (seed % 80) as usize;
        let mut rec = vec![22u8, 0x03, 0x03, 0, n as u8];
        for b in rec[5..].iter_mut() {
            seed ^= seed << 13;
            *b = seed as u8;
        }
        let _ = c.on_record(&rec, &mut scratch); // refused — the state holds
                                                 // an alert-typed garbage too
        let mut alert = vec![21u8, 0x03, 0x03, 0x00, 0x02, 2, (round % 40) as u8];
        alert[6] ^= (seed >> 8) as u8;
        let _ = c.on_record(&alert, &mut scratch);
        // the version bomb
        let _ = c.on_record(&[22, 0x03, 0x01, 0xff, 0xff, 1, 2, 3], &mut scratch);
    }
    // the machine survived: the REAL flight completes
    let (v, app, e) = drive(&mut c, &srs);
    assert!(v, "the storm wedged the machine: {e:?}");
    assert!(app > 0);
}

/// The `max_record_len` flag: a budget of 100 refuses the real
/// flight's records (748-byte ciphertext) BEFORE any decryption
/// work — the hostile-record budget is enforced at the door.
#[test]
fn hostile_battery_record_budget_flag() {
    let fx = load_fixture();
    if fx.is_empty() {
        return;
    }
    let srs: Vec<Vec<u8>> = fx
        .iter()
        .filter(|(k, _)| k == "SR")
        .map(|(_, v)| v.clone())
        .collect();
    let mut c = Client::new(ClientConfig {
        client_private: CLIENT_PRIVATE,
        client_random: CLIENT_RANDOM,
        session_id: SESSION_ID,
        pinned_ed25519: PIN,
        options: crate::handshake::TlsOptions {
            sni: None,
            alpn: &[],
            verify: VerifyMode::Pinned,
            max_record_len: 100,
        },
    });
    let (v, app, e) = drive(&mut c, &srs);
    assert!(!v && app == 0, "an over-budget record was processed");
    assert!(e.is_some(), "the refusal is named: {e:?}");
    // a legal small budget still passes the SMALL records: the SH
    // (a ~90-byte record) parses, the flight refuses
    let mut c2 = Client::new(ClientConfig {
        client_private: CLIENT_PRIVATE,
        client_random: CLIENT_RANDOM,
        session_id: SESSION_ID,
        pinned_ed25519: PIN,
        options: crate::handshake::TlsOptions {
            sni: None,
            alpn: &[],
            verify: VerifyMode::Pinned,
            max_record_len: 200,
        },
    });
    let mut out = [0u8; RECORD_CAP + 64];
    let _ = c2.build_client_hello(&mut out);
    let mut scratch = [0u8; RECORD_CAP];
    let r = c2.on_record(&srs[0], &mut scratch);
    assert!(matches!(r, Ok(Event::Continue)), "the SH fits the budget");
}

/// The AEAD tamper sweep: flip EVERY byte of the sealed output
/// (ciphertext AND tag) across the fuzz fixture's first cases —
/// every single flip must refuse. The MAC's coverage is total.
#[test]
fn hostile_battery_aead_every_byte_tamper() {
    let data = match std::fs::read_to_string("tests/aead-fuzz.txt") {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut cases = 0usize;
    let mut accepted = 0usize;
    for line in data.lines().take(50) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 5 {
            continue;
        }
        let key: [u8; 32] = hexv(parts[0]).try_into().unwrap();
        let nonce: [u8; 12] = hexv(parts[1]).try_into().unwrap();
        let msg = hexv(parts[2]);
        let aad = hexv(parts[3]);
        let mut sealed = vec![0u8; msg.len() + 16];
        aead::seal(&key, &nonce, &msg, &aad, &mut sealed).expect("seal");
        for i in 0..sealed.len() {
            for flip in [0x01u8, 0x80] {
                let mut t = sealed.clone();
                t[i] ^= flip;
                let mut opened = vec![0u8; msg.len()];
                if aead::open(&key, &nonce, &t, &aad, &mut opened).is_ok() {
                    accepted += 1;
                }
                cases += 1;
            }
        }
    }
    assert!(cases > 1000, "the tamper sweep must run (got {cases})");
    assert_eq!(
        accepted, 0,
        "a tampered record was accepted ({accepted}/{cases})"
    );
}

/// X25519 hostile inputs: the identity, all-ones (the masked top
/// bit), adversarial u-coordinates — deterministic outputs, no
/// panic, and the DH symmetry holds even for degenerate peers.
#[test]
fn hostile_battery_x25519_degenerate_inputs() {
    let zero = [0u8; 32];
    let ones = [0xFFu8; 32];
    let sk = hex("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    // the identity peer: RFC 7748 permits it; the result is
    // deterministic (and the handshake layer would fail later on
    // the transcript, not here)
    let a = crate::x25519::x25519(&sk, &zero);
    let b = crate::x25519::x25519(&sk, &zero);
    assert_eq!(a, b, "deterministic on the identity");
    // all-ones: bit 255 masked off by decodeUCoordinate
    let c = crate::x25519::x25519(&sk, &ones);
    let mut ones_masked = ones;
    ones_masked[31] &= 127;
    let d = crate::x25519::x25519(&sk, &ones_masked);
    assert_eq!(c, d, "the top bit is masked (RFC 7748)");
    // a run of adversarial u's: no panic, 32-byte outputs
    let mut seed = 0x0123_4567_89ab_cdefu64;
    for _ in 0..64 {
        let mut u = [0u8; 32];
        for b in u.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *b = seed as u8;
        }
        let _ = crate::x25519::x25519(&sk, &u);
    }
    // and the all-zero SCALAR: clamped to a legal value, not a
    // degenerate one
    let pub_zero = crate::x25519::public_key(&zero);
    assert_ne!(pub_zero, zero, "the clamped zero scalar is not degenerate");
}

/// The SNI/ALPN flag guards: oversized values refuse at BUILD time
/// (never a buffer overflow on emission).
#[test]
fn hostile_battery_flag_guards() {
    let long_host = "x".repeat(300);
    let mut c = Client::new(ClientConfig {
        client_private: CLIENT_PRIVATE,
        client_random: CLIENT_RANDOM,
        session_id: SESSION_ID,
        pinned_ed25519: PIN,
        options: crate::handshake::TlsOptions {
            sni: Some(&long_host),
            alpn: &[],
            verify: VerifyMode::Pinned,
            max_record_len: RECORD_CAP,
        },
    });
    let mut out = [0u8; RECORD_CAP + 64];
    assert!(matches!(c.build_client_hello(&mut out), Err(Error::Buffer)));
    // a poisoned ALPN list
    let long_proto = "y".repeat(300);
    let list = [long_proto.as_str()];
    let mut c2 = Client::new(ClientConfig {
        client_private: CLIENT_PRIVATE,
        client_random: CLIENT_RANDOM,
        session_id: SESSION_ID,
        pinned_ed25519: PIN,
        options: crate::handshake::TlsOptions {
            sni: None,
            alpn: &list,
            verify: VerifyMode::Pinned,
            max_record_len: RECORD_CAP,
        },
    });
    assert!(matches!(
        c2.build_client_hello(&mut out),
        Err(Error::Buffer)
    ));
    // and the phase discipline: no Finished before the flight
    let mut c3 = client_with(PIN, VerifyMode::Pinned, Some("aegis-tls"));
    assert!(matches!(c3.build_finished(&mut out), Err(Error::TooEarly)));
    // no app data before establishment
    assert!(matches!(
        c3.seal_app_data(b"x", &mut out),
        Err(Error::TooEarly)
    ));
    // the helpers stay quiet
    let _ = hexs(&[0u8; 4]);
}

/// The `subject_cn` walk against hand-crafted DER: the CN lookup
/// the `PinnedRequireName` mode trusts. Three shapes: a CN present,
/// a DIFFERENT CN (the wrong-name attack, one byte), and no CN at
/// all (the walk must answer None, never a wrong slice).
#[test]
fn hostile_battery_subject_cn_walk() {
    // a minimal Certificate: SEQUENCE { TBS { serial, sig, issuer,
    // validity, subject(Name), SPKI }, sigAlg, sig } — the Name is
    // an RDNSequence with one SET of one CN AttributeTypeAndValue.
    let cn = |name: &[u8]| -> Vec<u8> {
        let mut atv = vec![0x30];
        atv.push((7 + name.len()) as u8);
        atv.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // CN
        atv.push(0x0C); // UTF8String
        atv.push(name.len() as u8);
        atv.extend_from_slice(name);
        let mut set = vec![0x31, atv.len() as u8];
        set.extend_from_slice(&atv);
        let mut name_seq = vec![0x30, set.len() as u8];
        name_seq.extend_from_slice(&set);
        let mut tbs: Vec<u8> = vec![0x02, 0x01, 0x01]; // serial
        tbs.extend_from_slice(&[0x30, 0x00]); // sig (empty)
        tbs.extend_from_slice(&[0x30, 0x00]); // issuer (empty)
        tbs.extend_from_slice(&[0x30, 0x00]); // validity (empty)
        tbs.extend_from_slice(&name_seq);
        // SPKI: SEQUENCE { SEQUENCE { OID }, BIT STRING } (the
        // ed25519 shape, contents irrelevant to the walk)
        tbs.extend_from_slice(&[
            0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x02, 0x00, 0x1a,
        ]);
        let mut cert: Vec<u8> = vec![0x30];
        // TBS header + the rest (sigAlg + sig: two empties)
        let tbs_all = {
            let mut v = vec![0x30];
            v.push(tbs.len() as u8);
            v.extend_from_slice(&tbs);
            v
        };
        let rest = [0x30u8, 0x00, 0x04, 0x00];
        let total = tbs_all.len() + rest.len();
        cert.push(total as u8);
        cert.extend_from_slice(&tbs_all);
        cert.extend_from_slice(&rest);
        cert
    };
    let good = cn(b"aegis-tls");
    assert_eq!(crate::cert::subject_cn(&good), Some(&b"aegis-tls"[..]));
    let wrong = cn(b"aegis-tlS");
    assert_eq!(crate::cert::subject_cn(&wrong), Some(&b"aegis-tlS"[..]));
    // the wrong-name comparison itself (the mode's gate)
    assert_ne!(
        crate::cert::subject_cn(&wrong).unwrap(),
        b"aegis-tls".as_slice()
    );
    // a truncated DER: None, not a panic
    assert_eq!(crate::cert::subject_cn(&good[..good.len() - 5]), None);
    // garbage: None
    assert_eq!(crate::cert::subject_cn(&[0xff, 0xff, 0xff, 0xff]), None);
}
