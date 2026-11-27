//! Test module (host builds only — `cfg(test)` pulls in `std` for
//! harness scaffolding; the library itself stays `no_std`).
//!
//! Coverage map (each maps to a THREAT_MODEL.md entry):
//! * [`crypto`]: RFC 8032 Ed25519 vector, FIPS SHA-256/512, CRC-32,
//!   constant-time comparison.
//! * [`manifest`]: semver precedence, canonical roundtrips, hostile
//!   inputs (huge lengths, traversal paths, SUID bits, bare names).
//! * [`solver`]-in-`dbtx`: resolution scenarios (chains, conflicts,
//!   cycles, prefer-latest, keep-installed).
//! * [`pkg`]-in-`dbtx`: LZ4 window decoder, bomb guards, tamper
//!   rejection at the package layer.
//! * [`dbtx`]: the full lifecycle over an in-memory filesystem —
//!   install/verify/remove, downgrade block, disk-full rollback,
//!   crash + journal replay, traversal/symlink refusal, concurrent
//!   lockout, replay defense.

mod crypto {
    use crate::crypto::{crc32, ct_eq, ed25519, sha256, sha512};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn sha256_fips_vectors() {
        let d = sha256::digest(b"abc");
        assert_eq!(
            hex_hex(&d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let d2 = sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex_hex(&d2),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_streaming_matches_oneshot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut h = sha256::Sha256::new();
        for chunk in data.chunks(37) {
            h.update(chunk);
        }
        let mut out = [0u8; 32];
        h.finish(&mut out);
        assert_eq!(out, sha256::digest(&data));
    }

    #[test]
    fn sha512_fips_vectors() {
        let d = sha512::digest(b"abc");
        assert_eq!(
            hex_hex(&d),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32::crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn ct_eq_is_length_safe() {
        assert!(ct_eq(b"same", b"same"));
        assert!(!ct_eq(b"same", b"samf"));
        assert!(!ct_eq(b"a", b"ab"));
    }

    #[test]
    fn ed25519_rfc8032_vector1() {
        // RFC 8032 §7.1, TEST 1 (empty message)
        let sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821\
                      590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let mut s = [0u8; 32];
        s.copy_from_slice(&sk);
        let mut p = [0u8; 32];
        p.copy_from_slice(&pk);
        let mut g = [0u8; 64];
        g.copy_from_slice(&sig);
        assert!(
            ed25519::verify(&p, b"", &g),
            "RFC 8032 vector 1 must verify"
        );
        assert_eq!(ed25519::public_key(&s), p, "key derivation must match RFC");
        assert_eq!(
            ed25519::sign(&s, b""),
            g,
            "deterministic signing must match RFC"
        );
    }

    #[test]
    fn ed25519_rejects_tampering() {
        let sk = [7u8; 32];
        let pk = ed25519::public_key(&sk);
        let msg = b"some package manifest bytes";
        let sig = ed25519::sign(&sk, msg);
        assert!(ed25519::verify(&pk, msg, &sig));
        let mut msg2 = *msg;
        msg2[0] ^= 1;
        assert!(!ed25519::verify(&pk, &msg2, &sig));
        let mut sig2 = sig;
        sig2[10] ^= 1;
        assert!(!ed25519::verify(&pk, msg, &sig2));
        let pk2 = ed25519::public_key(&[8u8; 32]);
        assert!(!ed25519::verify(&pk2, msg, &sig));
    }

    #[test]
    fn ed25519_rejects_high_s() {
        // S >= L must be rejected even if the point equation would
        // hold (malleability defense).
        let sk = [9u8; 32];
        let pk = ed25519::public_key(&sk);
        let msg = b"malleability probe";
        let mut sig = ed25519::sign(&sk, msg);
        sig[63] = 0x7F;
        sig[31] = 0x20; // S >= 2^253 > L
        assert!(!ed25519::verify(&pk, msg, &sig));
    }

    #[test]
    fn ed25519_roundtrip_various_lengths() {
        for len in [0usize, 1, 31, 32, 64, 100, 1000, 4096] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            let sk = [(len as u8) | 1; 32];
            let pk = ed25519::public_key(&sk);
            let sig = ed25519::sign(&sk, &msg);
            assert!(ed25519::verify(&pk, &msg, &sig), "len {len}");
        }
    }
}

mod manifest {
    use crate::error::ErrorKind;
    use crate::manifest::{is_allowed_install_path, FileEntry, Manifest, SemVer, VersionReq};
    use crate::{limits, Path};

    fn v(x: u32, y: u32, z: u32) -> SemVer {
        SemVer::release(x, y, z)
    }

    #[test]
    fn semver_precedence() {
        assert!(v(1, 2, 3).precedes(&v(1, 2, 4)));
        assert!(v(1, 2, 3).precedes(&v(1, 3, 0)));
        assert!(v(1, 2, 3).precedes(&v(2, 0, 0)));
        assert!(!v(1, 2, 3).precedes(&v(1, 2, 3)));
        // prerelease sorts below release
        let pre = v(1, 0, 0).with_pre(b"alpha.1").unwrap();
        assert!(pre.precedes(&v(1, 0, 0)));
        // numeric identifiers compare numerically
        let a = v(1, 0, 0).with_pre(b"alpha.2").unwrap();
        let b = v(1, 0, 0).with_pre(b"alpha.10").unwrap();
        assert!(a.precedes(&b));
        // alphanumeric sorts above numeric
        let n = v(1, 0, 0).with_pre(b"1").unwrap();
        let s = v(1, 0, 0).with_pre(b"alpha").unwrap();
        assert!(n.precedes(&s));
    }

    #[test]
    fn semver_parse_strictness() {
        assert!(SemVer::parse(b"1.2.3").is_ok());
        assert!(SemVer::parse(b"1.2.3-alpha.1").is_ok());
        assert!(SemVer::parse(b"1.2").is_err());
        assert!(SemVer::parse(b"1.2.3.4").is_err());
        assert!(SemVer::parse(b"01.2.3").is_err(), "leading zeros refused");
        assert!(
            SemVer::parse(b"1.2.3+build").is_err(),
            "build metadata refused"
        );
        assert!(
            SemVer::parse(b"1.2.3-").is_err(),
            "empty prerelease refused"
        );
    }

    #[test]
    fn version_req_satisfaction() {
        let r = VersionReq::exact(v(1, 2, 3));
        assert!(r.satisfied_by(&v(1, 2, 3)));
        assert!(!r.satisfied_by(&v(1, 2, 4)));
        let r = VersionReq::min(v(1, 0, 0));
        assert!(r.satisfied_by(&v(1, 0, 0)));
        assert!(r.satisfied_by(&v(2, 0, 0)));
        assert!(!r.satisfied_by(&v(0, 9, 9)));
        let r = VersionReq::max(v(2, 0, 0));
        assert!(r.satisfied_by(&v(1, 9, 9)));
        assert!(!r.satisfied_by(&v(2, 0, 0)));
        let r = VersionReq::range(v(1, 0, 0), v(2, 0, 0));
        assert!(r.satisfied_by(&v(1, 5, 0)));
        assert!(!r.satisfied_by(&v(2, 0, 0)));
        let r = VersionReq::caret(v(1, 2, 3));
        assert!(r.satisfied_by(&v(1, 9, 9)));
        assert!(!r.satisfied_by(&v(2, 0, 0)));
        assert!(!r.satisfied_by(&v(1, 2, 2)));
        let r = VersionReq::caret(v(0, 3, 1));
        assert!(r.satisfied_by(&v(0, 3, 9)));
        assert!(!r.satisfied_by(&v(0, 4, 0)));
        assert!(VersionReq::any().satisfied_by(&v(0, 0, 0)));
        // Debug rendering of a request (kind + boundary)
        assert_eq!(format!("{:?}", VersionReq::caret(v(1, 2, 3))), "^1.2.3");
        assert_eq!(format!("{:?}", VersionReq::exact(v(2, 0, 0))), "=2.0.0");
        assert_eq!(format!("{:?}", VersionReq::any()), "*");
    }

    fn simple_manifest() -> Manifest {
        let mut m = Manifest::new(b"core/hello", v(1, 0, 0)).unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/hello").unwrap(),
            perm: 0o755,
            size: 6,
            sha256: [7; 32],
        })
        .unwrap();
        m
    }

    #[test]
    fn canonical_roundtrip() {
        let m = simple_manifest();
        let mut buf = [0u8; limits::MAX_MANIFEST];
        let n = m.serialize(&mut buf).unwrap();
        let m2 = Manifest::parse(&buf[..n]).unwrap();
        assert!(m == m2, "parse(serialize(x)) must equal x");
        let mut buf2 = [0u8; limits::MAX_MANIFEST];
        let n2 = m2.serialize(&mut buf2).unwrap();
        assert_eq!(&buf[..n], &buf2[..n2]);
        // trailing garbage refused
        let mut bad = buf[..n].to_vec();
        bad.push(0);
        assert!(Manifest::parse(&bad).is_err());
    }

    #[test]
    fn non_canonical_encoding_refused() {
        // duplicate file entries make validate fail (and the parser
        // canonical-checks the serialization)
        let mut m2 = simple_manifest();
        m2.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/hello").unwrap(),
            perm: 0o755,
            size: 6,
            sha256: [7; 32],
        })
        .unwrap();
        let mut b2 = [0u8; limits::MAX_MANIFEST];
        let n2 = m2.serialize(&mut b2).unwrap();
        assert!(Manifest::parse(&b2[..n2]).is_err());
    }

    #[test]
    fn hostile_paths_refused() {
        for bad in [
            &b"../../etc/passwd"[..],
            b"/bin/../etc/passwd",
            b"/bin/./hello",
            b"bin/hello",
            b"/bin//hello",
            b"/bin/h\x00ello",
        ] {
            let e = Path::from_bytes(bad).unwrap_err();
            assert!(
                e.kind() == ErrorKind::PathEscape || e.kind() == ErrorKind::InvalidFormat,
                "{:?} -> {:?}",
                String::from_utf8_lossy(bad),
                e
            );
        }
        // file/dir shadowing refused
        let mut m = Manifest::new(b"core/xx", v(1, 0, 0)).unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/a").unwrap(),
            perm: 0o644,
            size: 1,
            sha256: [0; 32],
        })
        .unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/a/b").unwrap(),
            perm: 0o644,
            size: 1,
            sha256: [0; 32],
        })
        .unwrap();
        assert!(m.validate().is_err());
    }

    #[test]
    fn hostile_fields_refused() {
        // SUID refused
        let mut m = Manifest::new(b"core/xx", v(1, 0, 0)).unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/x").unwrap(),
            perm: 0o4755,
            size: 1,
            sha256: [0; 32],
        })
        .unwrap();
        let e = m.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidFormat);
        // oversize file refused
        let mut m = Manifest::new(b"core/xx", v(1, 0, 0)).unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/x").unwrap(),
            perm: 0o644,
            size: 513 * 1024 * 1024,
            sha256: [0; 32],
        })
        .unwrap();
        let e = m.validate().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TooLarge);
        // bare (non-namespaced) names refused
        assert!(Manifest::new(b"hello", v(1, 0, 0)).is_err());
        assert!(Manifest::new(b"core/hel lo", v(1, 0, 0)).is_err());
        assert!(Manifest::new(b"core/UPPER", v(1, 0, 0)).is_err());
        assert!(Manifest::new(b"core/a/b", v(1, 0, 0)).is_err());
        // the manager's own tree is off-limits
        assert!(!is_allowed_install_path(b"/pkg/db/state"));
        assert!(!is_allowed_install_path(b"/dev/mem"));
        assert!(!is_allowed_install_path(b"/kernel/vm"));
        assert!(is_allowed_install_path(b"/bin/hello"));
        assert!(is_allowed_install_path(b"/etc/core.conf"));
    }

    #[test]
    fn huge_length_claims_refused() {
        // every truncation of a valid manifest must error, never
        // over-read
        let m = simple_manifest();
        let mut buf = [0u8; limits::MAX_MANIFEST];
        let n = m.serialize(&mut buf).unwrap();
        for cut in [n - 1, n / 2, 8, 4] {
            assert!(Manifest::parse(&buf[..cut]).is_err(), "cut {cut}");
        }
        let mut big = vec![0u8; limits::MAX_MANIFEST + 1];
        big[..4].copy_from_slice(b"AMFT");
        assert!(Manifest::parse(&big).is_err());
    }
}

// PART 2: the full package lifecycle over an in-memory filesystem.

mod dbtx {
    use crate::cli;
    use crate::crypto::ed25519;
    use crate::crypto::sha256;
    use crate::database::PkgPaths;
    use crate::error::{Error, ErrorKind};
    use crate::manifest::{Dependency, FileEntry, Manifest, SemVer, VersionReq};
    use crate::package::{self, PkgBuf};
    use crate::solver::{Candidate, Installed, Solver};
    use crate::transaction::{self, Transaction};
    use crate::{FileKind, Fs, OpenFlags, Path, Stat};
    use std::collections::BTreeMap;

    // ── the in-memory filesystem ──

    #[derive(Clone)]
    enum Node {
        File(Vec<u8>, u16),
        Dir,
        Symlink,
    }

    /// In-memory `Fs` with a byte budget (None = unlimited) for the
    /// disk-full scenarios and direct node injection for symlink
    /// planting.
    struct MemFs {
        nodes: BTreeMap<Vec<u8>, Node>,
        fds: BTreeMap<u32, (Vec<u8>, bool, usize)>, // path, writable, cursor
        next_fd: u32,
        quota: Option<u64>,
        written: u64,
    }

    impl MemFs {
        fn new() -> Self {
            let mut nodes = BTreeMap::new();
            nodes.insert(b"/".to_vec(), Node::Dir);
            MemFs {
                nodes,
                fds: BTreeMap::new(),
                next_fd: 3,
                quota: None,
                written: 0,
            }
        }

        fn put_file(&mut self, path: &[u8], data: &[u8], perm: u16) {
            self.nodes
                .insert(path.to_vec(), Node::File(data.to_vec(), perm));
        }

        fn put_symlink(&mut self, path: &[u8], _target: &[u8]) {
            self.nodes.insert(path.to_vec(), Node::Symlink);
        }

        fn mkdirp(&mut self, path: &[u8]) {
            self.nodes.insert(b"/".to_vec(), Node::Dir);
            let mut cur: Vec<u8> = Vec::new();
            for comp in path.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
                cur.push(b'/');
                cur.extend_from_slice(comp);
                self.nodes.entry(cur.clone()).or_insert(Node::Dir);
            }
        }

        fn read_file(&self, path: &[u8]) -> Option<Vec<u8>> {
            match self.nodes.get(path) {
                Some(Node::File(d, _)) => Some(d.clone()),
                _ => None,
            }
        }

        fn exists(&self, path: &[u8]) -> bool {
            self.nodes.contains_key(path)
        }
    }

    fn no_ent() -> Error {
        Error::new(ErrorKind::Io(crate::error::Errno::NoEnt), "noent")
    }

    fn exists_err() -> Error {
        Error::new(ErrorKind::Io(crate::error::Errno::Exists), "exists")
    }

    fn no_space() -> Error {
        Error::new(ErrorKind::Io(crate::error::Errno::NoSpace), "quota")
    }

    impl Fs for MemFs {
        fn open(&mut self, path: &Path, flags: OpenFlags) -> crate::Result<u32> {
            let p = path.as_bytes().to_vec();
            let writable = flags.has(OpenFlags::WRONLY);
            if writable {
                if flags.has(OpenFlags::EXCL) && self.nodes.contains_key(&p) {
                    return Err(exists_err());
                }
                if flags.has(OpenFlags::CREATE) && !self.nodes.contains_key(&p) {
                    // parent must exist and be a dir
                    let parent = parent_of(&p);
                    match self.nodes.get(&parent) {
                        Some(Node::Dir) => {}
                        _ => return Err(no_ent()),
                    }
                    self.nodes.insert(p.clone(), Node::File(Vec::new(), 0o644));
                } else if !self.nodes.contains_key(&p) {
                    return Err(no_ent());
                }
                if !matches!(self.nodes.get(&p), Some(Node::File(..))) {
                    return Err(Error::new(
                        ErrorKind::Io(crate::error::Errno::IsDir),
                        "is dir",
                    ));
                }
            } else if !self.nodes.contains_key(&p) {
                return Err(no_ent());
            }
            let fd = self.next_fd;
            self.next_fd += 1;
            self.fds.insert(fd, (p, writable, 0));
            Ok(fd)
        }

        fn read(&mut self, fd: u32, buf: &mut [u8]) -> crate::Result<usize> {
            let Some((p, false, cur)) = self.fds.get_mut(&fd) else {
                return Err(no_ent());
            };
            let p = p.clone();
            match self.nodes.get(&p) {
                Some(Node::File(d, _)) => {
                    let remaining = d.len().saturating_sub(*cur);
                    let n = remaining.min(buf.len());
                    buf[..n].copy_from_slice(&d[*cur..*cur + n]);
                    *cur += n;
                    Ok(n)
                }
                _ => Err(Error::new(
                    ErrorKind::Io(crate::error::Errno::IsDir),
                    "is dir",
                )),
            }
        }

        fn write(&mut self, fd: u32, buf: &[u8]) -> crate::Result<usize> {
            let Some((p, true, _)) = self.fds.get(&fd) else {
                return Err(no_ent());
            };
            let p = p.clone();
            if let Some(q) = self.quota {
                if self.written + buf.len() as u64 > q {
                    return Err(no_space());
                }
            }
            self.written += buf.len() as u64;
            match self.nodes.get_mut(&p) {
                Some(Node::File(d, _)) => {
                    d.extend_from_slice(buf);
                    Ok(buf.len())
                }
                _ => Err(Error::new(
                    ErrorKind::Io(crate::error::Errno::IsDir),
                    "is dir",
                )),
            }
        }

        fn close(&mut self, fd: u32) -> crate::Result<()> {
            self.fds.remove(&fd);
            Ok(())
        }

        fn sync(&mut self, _fd: u32) -> crate::Result<()> {
            Ok(())
        }

        fn stat(&mut self, path: &Path) -> crate::Result<Stat> {
            match self.nodes.get(path.as_bytes()) {
                Some(Node::File(d, perm)) => Ok(Stat {
                    kind: FileKind::File,
                    size: d.len() as u64,
                    perm: *perm,
                }),
                Some(Node::Dir) => Ok(Stat {
                    kind: FileKind::Dir,
                    size: 0,
                    perm: 0o755,
                }),
                Some(Node::Symlink) => Ok(Stat {
                    kind: FileKind::Symlink,
                    size: 0,
                    perm: 0o777,
                }),
                None => Err(no_ent()),
            }
        }

        fn mkdir(&mut self, path: &Path) -> crate::Result<()> {
            let p = path.as_bytes().to_vec();
            if self.nodes.contains_key(&p) {
                return Err(exists_err());
            }
            let parent = parent_of(&p);
            if !matches!(self.nodes.get(&parent), Some(Node::Dir)) && p != b"/" {
                return Err(no_ent());
            }
            self.nodes.insert(p, Node::Dir);
            Ok(())
        }

        fn unlink(&mut self, path: &Path) -> crate::Result<()> {
            let p = path.as_bytes().to_vec();
            match self.nodes.get(&p) {
                Some(Node::File(..)) | Some(Node::Symlink) => {
                    self.nodes.remove(&p);
                    Ok(())
                }
                Some(Node::Dir) => {
                    let prefix = {
                        let mut s = p.clone();
                        s.push(b'/');
                        s
                    };
                    if self.nodes.range(prefix..).next().is_some() {
                        return Err(Error::new(
                            ErrorKind::Io(crate::error::Errno::NotEmpty),
                            "not empty",
                        ));
                    }
                    self.nodes.remove(&p);
                    Ok(())
                }
                None => Err(no_ent()),
            }
        }

        fn rename(&mut self, from: &Path, to: &Path) -> crate::Result<()> {
            let f = from.as_bytes().to_vec();
            let t = to.as_bytes().to_vec();
            let node = self.nodes.remove(&f).ok_or_else(no_ent)?;
            // replacing a destination file is allowed; dirs not
            if let Some(Node::Dir) = self.nodes.get(&t) {
                self.nodes.insert(f, node);
                return Err(Error::new(
                    ErrorKind::Io(crate::error::Errno::Io),
                    "cannot rename over dir",
                ));
            }
            self.nodes.insert(t, node);
            Ok(())
        }

        fn getdents(&mut self, fd: u32, out: &mut [u8]) -> crate::Result<usize> {
            // list entries once in sorted order, then serve them by
            // the per-fd cursor (like read): a second call continues
            let Some((p, _, cur)) = self.fds.get_mut(&fd) else {
                return Err(no_ent());
            };
            let p = p.clone();
            if !matches!(self.nodes.get(&p), Some(Node::Dir)) {
                return Err(Error::new(
                    ErrorKind::Io(crate::error::Errno::NotDir),
                    "not dir",
                ));
            }
            let prefix = if p == b"/" {
                p.clone()
            } else {
                format!("{}/", String::from_utf8_lossy(&p)).into_bytes()
            };
            let mut names: Vec<Vec<u8>> = Vec::new();
            for (k, _) in self.nodes.range(prefix.clone()..) {
                if !k.starts_with(&prefix) {
                    break;
                }
                let name = &k[prefix.len()..];
                if name.is_empty() || name.contains(&b'/') {
                    continue;
                }
                let mut entry = name.to_vec();
                entry.push(0);
                names.push(entry);
            }
            let mut pos = 0usize;
            let mut served = 0usize;
            for entry in names.iter().skip(*cur) {
                if pos + entry.len() > out.len() {
                    break;
                }
                out[pos..pos + entry.len()].copy_from_slice(entry);
                pos += entry.len();
                served += 1;
            }
            *cur += served;
            Ok(pos)
        }
    }

    fn parent_of(p: &[u8]) -> Vec<u8> {
        match p.iter().rposition(|&c| c == b'/') {
            Some(0) => b"/".to_vec(),
            Some(i) => p[..i].to_vec(),
            None => b"/".to_vec(),
        }
    }

    // ── repo fixtures ──

    /// Build a test repo: MemFs layout at `/r1` with a signed index,
    /// packages, and a config under `/pkg/repos`.
    fn build_repo(fs: &mut MemFs, pkgs: &[BorrowedPkgSpec<'_>]) {
        build_repo_epoch(fs, pkgs, 7);
    }

    fn build_repo_epoch(fs: &mut MemFs, pkgs: &[BorrowedPkgSpec<'_>], epoch: u64) {
        let root = [0x11; 32];
        let repo = [0x22; 32];
        fs.mkdirp(b"/r1");
        fs.mkdirp(b"/pkg/repos");
        let mut entries: Vec<(&[u8], Manifest, [u8; 32], u64)> = Vec::new();
        for (name, ver, files, deps) in pkgs {
            let mut m = Manifest::new(name, *ver).unwrap();
            let mut contents: Vec<&[u8]> = Vec::new();
            for (path, content, perm) in *files {
                m.push_file(FileEntry {
                    path: Path::from_bytes(path).unwrap(),
                    perm: *perm,
                    size: content.len() as u64,
                    sha256: sha256::digest(content),
                })
                .unwrap();
                contents.push(content);
            }
            for (dep, req) in *deps {
                m.push_dep(Dependency::new(dep, *req).unwrap()).unwrap();
            }
            let mut buf: PkgBuf = [0u8; 512 * 1024];
            let n = package::build_package(&m, &contents, &repo, &mut buf).unwrap();
            // package path (K23, version-qualified):
            // /r1/<name with / -> .>-<major.minor.patch>.akp
            let mut pp = b"/r1/".to_vec();
            pp.extend(name.iter().map(|&c| if c == b'/' { b'.' } else { c }));
            pp.push(b'-');
            let mut vb = [0u8; 56];
            let vn = ver.write_bytes(&mut vb);
            pp.extend_from_slice(&vb[..vn]);
            pp.extend_from_slice(b".akp");
            fs.put_file(&pp, &buf[..n], 0o644);
            entries.push((name, m, sha256::digest(&buf[..n]), n as u64));
        }
        // the signed index
        let mut ibuf = [0u8; 96 * 1024];
        let idx_n =
            cli::build_index_with_hashes(b"r1", epoch, &entries, &repo, Some(&root), &mut ibuf)
                .unwrap();
        fs.put_file(b"/r1/index.aki", &ibuf[..idx_n], 0o644);
        // the repo config (pinned local repo)
        let cfg = crate::repository::RepoConfig {
            slug: {
                let mut s = [0u8; crate::limits::MAX_NAME];
                s[..2].copy_from_slice(b"r1");
                s
            },
            slug_len: 2,
            url: {
                let mut u = [0u8; 128];
                u[..3].copy_from_slice(b"/r1");
                u
            },
            url_len: 3,
            key: ed25519::public_key(&repo),
            pinned: true,
            local: true,
        };
        let mut cbuf = [0u8; 300];
        let cn = cfg.serialize(&mut cbuf).unwrap();
        fs.put_file(b"/pkg/repos/r1.repo", &cbuf[..cn], 0o644);
        // trust anchors: the root key
        let anchors = crate::repository::TrustAnchors {
            keys: {
                let mut ks = [[0u8; 32]; 8];
                ks[0] = ed25519::public_key(&root);
                ks
            },
            count: 1,
        };
        let mut abuf = [0u8; 4 + 2 + 1 + 8 * 32];
        let an = anchors.serialize(&mut abuf).unwrap();
        fs.put_file(b"/pkg/trust", &abuf[..an], 0o644);
    }

    fn run(fs: &mut MemFs, args: &[&[u8]]) -> (i32, String) {
        let paths = PkgPaths::new(b"/pkg").unwrap();
        let mut out = String::new();
        // fresh fd namespace per invocation (a new process would
        // have its own): close everything
        fs.fds.clear();
        let code = cli::run_cli(args, fs, &paths, None, &mut out);
        (code, out)
    }

    /// One repo package spec: (name, version, files, deps).
    type PkgSpec = (
        &'static [u8],
        SemVer,
        Vec<(&'static [u8], &'static [u8], u16)>,
        Vec<(&'static [u8], VersionReq)>,
    );

    /// The borrowed shape `build_repo` consumes (callers declare
    /// specs as arrays of tuples; this keeps signatures readable).
    type BorrowedPkgSpec<'a> = (
        &'a [u8],
        SemVer,
        &'a [(&'a [u8], &'a [u8], u16)],
        &'a [(&'a [u8], VersionReq)],
    );

    fn hello_pkg() -> PkgSpec {
        (
            b"r1/hello",
            SemVer::release(1, 0, 0),
            vec![(b"/bin/hello", b"hello world\n", 0o755)],
            vec![],
        )
    }

    // ── the lifecycle tests ──

    #[test]
    fn happy_path_install_verify_remove() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        // install
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 0, "install failed: {out}");
        assert_eq!(
            fs.read_file(b"/bin/hello").unwrap(),
            b"hello world\n".to_vec(),
            "file must land at its destination"
        );
        // list shows it
        let (code, out) = run(&mut fs, &[b"list"]);
        assert_eq!(code, 0);
        assert!(out.contains("r1/hello 1.0.0"), "list: {out}");
        // verify is clean
        let (code, out) = run(&mut fs, &[b"verify"]);
        assert_eq!(code, 0, "verify: {out}");
        // remove
        let (code, out) = run(&mut fs, &[b"remove", b"r1/hello"]);
        assert_eq!(code, 0, "remove: {out}");
        assert!(!fs.exists(b"/bin/hello"), "file must be gone");
        assert!(!fs.exists(b"/pkg/db/r1.hello.rec"), "record must be gone");
        // and re-installable
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 0, "reinstall: {out}");
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        // flip one byte inside the package's manifest (signed zone)
        let mut pkg = fs.read_file(b"/r1/r1.hello-1.0.0.akp").unwrap();
        pkg[8 + 40] ^= 0x40;
        fs.put_file(b"/r1/r1.hello-1.0.0.akp", &pkg, 0o644);
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 1, "tampered package must be refused: {out}");
        assert!(
            !fs.exists(b"/bin/hello"),
            "no file may be installed from a tampered package"
        );
    }

    #[test]
    fn tampered_index_rejected() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        let mut idx = fs.read_file(b"/r1/index.aki").unwrap();
        idx[10] ^= 1; // inside the signed body
        fs.put_file(b"/r1/index.aki", &idx, 0o644);
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 1, "tampered index must be refused: {out}");
        assert!(!fs.exists(b"/bin/hello"));
    }

    #[test]
    fn unknown_repo_rejected() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        let (code, out) = run(&mut fs, &[b"install", b"other/thing"]);
        assert_eq!(code, 1, "unknown repo: {out}");
        assert!(!fs.exists(b"/bin/hello"), "nothing may be installed");
        assert!(!fs.exists(b"/bin/thing"));
    }

    #[test]
    fn downgrade_blocked_and_forced() {
        let mut fs = MemFs::new();
        // repo state 1: v2 only
        let f2: Vec<(&[u8], &[u8], u16)> = vec![(b"/bin/hello", b"hello v2\n", 0o755)];
        let no_deps: &[(&[u8], VersionReq)] = &[];
        build_repo(
            &mut fs,
            &[(b"r1/hello", SemVer::release(2, 0, 0), &f2, no_deps)],
        );
        // install v2
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 0, "install v2: {out}");
        assert_eq!(fs.read_file(b"/bin/hello").unwrap(), b"hello v2\n".to_vec());
        // the repo regresses to offering only v1 (metadata rollback)
        for k in [
            b"/r1/index.aki".to_vec(),
            b"/r1/r1.hello-2.0.0.akp".to_vec(),
        ] {
            fs.nodes.remove(&k);
        }
        let f1: Vec<(&[u8], &[u8], u16)> = vec![(b"/bin/hello", b"hello world\n", 0o755)];
        build_repo_epoch(
            &mut fs,
            &[(b"r1/hello", SemVer::release(1, 0, 0), &f1, no_deps)],
            8,
        );
        // pinning the older version must be refused
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello@1.0.0"]);
        assert_eq!(code, 1, "downgrade must be refused: {out}");
        assert_eq!(
            fs.read_file(b"/bin/hello").unwrap(),
            b"hello v2\n".to_vec(),
            "v2 must still be installed"
        );
        // explicit force succeeds
        let (code, out) = run(
            &mut fs,
            &[b"install", b"r1/hello@1.0.0", b"--force-downgrade"],
        );
        assert_eq!(code, 0, "forced downgrade: {out}");
        assert_eq!(
            fs.read_file(b"/bin/hello").unwrap(),
            b"hello world\n".to_vec()
        );
    }

    #[test]
    fn dependency_chain_resolved() {
        let mut fs = MemFs::new();
        let base_files: Vec<(&[u8], &[u8], u16)> = vec![(b"/lib/base.so", b"BASE", 0o644)];
        let app_files: Vec<(&[u8], &[u8], u16)> = vec![(b"/bin/app", b"APP", 0o755)];
        let no_deps: &[(&[u8], VersionReq)] = &[];
        let app_deps: &[(&[u8], VersionReq)] = &[(b"r1/base", VersionReq::any())];
        build_repo(
            &mut fs,
            &[
                (b"r1/base", SemVer::release(1, 0, 0), &base_files, no_deps),
                (b"r1/app", SemVer::release(1, 0, 0), &app_files, app_deps),
            ],
        );
        let (code, out) = run(&mut fs, &[b"install", b"r1/app"]);
        assert_eq!(code, 0, "dep chain: {out}");
        assert!(fs.exists(b"/bin/app"));
        assert!(fs.exists(b"/lib/base.so"), "the dependency must install");
    }

    #[test]
    fn disk_full_rolls_back() {
        let mut fs = MemFs::new();
        let big1: Vec<u8> = vec![0x41u8; 2048];
        let big2: Vec<u8> = vec![0x42u8; 2048];
        let big_files: Vec<(&[u8], &[u8], u16)> =
            vec![(b"/bin/big1", &big1, 0o755), (b"/bin/big2", &big2, 0o755)];
        let no_deps: &[(&[u8], VersionReq)] = &[];
        build_repo(
            &mut fs,
            &[(b"r1/big", SemVer::release(1, 0, 0), &big_files, no_deps)],
        );
        // now impose a quota that cannot hold the transaction
        fs.quota = Some(900);
        fs.written = 0;
        let (code, out) = run(&mut fs, &[b"install", b"r1/big"]);
        assert_eq!(code, 1, "disk-full must fail the install: {out}");
        assert!(!fs.exists(b"/bin/big1"), "rollback: nothing installed");
        assert!(!fs.exists(b"/bin/big2"));
        assert!(!fs.exists(b"/pkg/db/r1.big.rec"));
        // the lock and journal are released (next attempt works)
        fs.quota = None;
        fs.written = 0;
        let (code, out) = run(&mut fs, &[b"install", b"r1/big"]);
        assert_eq!(code, 0, "retry after rollback: {out}");
        assert!(fs.exists(b"/bin/big1"));
    }

    #[test]
    fn crash_during_commit_recovers() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        // drive a transaction manually and "crash" after the first
        // rename applies
        {
            let paths = PkgPaths::new(b"/pkg").unwrap();
            let mut tx = Transaction::begin(&mut fs, &paths).unwrap();
            let prev = None;
            // K23: repo files are version-qualified (name-1.0.0.akp),
            // so the crash fixture must fetch the same path build_repo
            // wrote — the old name-keyed name now answers ENOENT.
            let _manifest = tx
                .install_package(
                    &Path::from_bytes(b"/r1/r1.hello-1.0.0.akp").unwrap(),
                    &ed25519::public_key(&[0x22; 32]),
                    b"r1",
                    1,
                    prev.as_ref(),
                    false,
                )
                .unwrap();
            // apply the first journaled op (a mkdir or the file
            // move), then vanish like power loss
            transaction::simulate_crash_after_moves(&mut tx, 1).unwrap();
            core::mem::forget(tx); // no Drop cleanup — power loss
        }
        // the system must recover: any next command replays
        let (code, out) = run(&mut fs, &[b"list"]);
        assert_eq!(code, 0, "recovery: {out}");
        // the half-applied install is rolled back
        assert!(
            !fs.exists(b"/pkg/db/r1.hello.rec"),
            "record must be rolled back"
        );
        let state_ok = !fs.read_file(b"/pkg/db/state").is_some()
            || crate::database::DbState::parse(&fs.read_file(b"/pkg/db/state").unwrap())
                .unwrap()
                .count
                == 0;
        assert!(state_ok, "state must not list the crashed package");
        // and a fresh install succeeds (lock was stale-cleared)
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 0, "install after recovery: {out}");
        assert_eq!(
            fs.read_file(b"/bin/hello").unwrap(),
            b"hello world\n".to_vec()
        );
    }

    #[test]
    fn concurrent_invocation_lockout() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        let paths = PkgPaths::new(b"/pkg").unwrap();
        // take the lock, then prove a second begin is refused while
        // it is held
        let mut tx1 = Transaction::begin(&mut fs, &paths).expect("first lock");
        {
            // a second transaction on the same tree while tx1 lives
            let tx2 = Transaction::begin(tx1.fs_field(), &paths);
            match tx2 {
                Err(e) => assert_eq!(e.kind(), ErrorKind::Locked, "second must be Locked"),
                Ok(t2) => {
                    let _ = t2.rollback();
                    panic!("second begin must fail while the lock is held");
                }
            }
        }
        let _ = tx1.rollback();
    }

    #[test]
    fn symlink_parent_escape_refused() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        // plant /bin as a symlink to /pkg (the manager's tree)
        fs.nodes.remove(b"/bin".as_slice());
        fs.put_symlink(b"/bin", b"/pkg");
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 1, "symlink parent must be refused: {out}");
        assert!(
            !fs.exists(b"/pkg/hello") && !fs.exists(b"/pkg/bin"),
            "nothing may land through the symlink"
        );
        assert!(matches!(
            fs.nodes.get(b"/bin".as_slice()),
            Some(crate::tests::dbtx::Node::Symlink)
        ));
        // and the manager's own state is untouched
        assert!(!fs.exists(b"/pkg/db/hello"), "no file inside /pkg");
    }

    #[test]
    fn lz4_roundtrip_with_overlap() {
        // build an lz4 payload (seed + overlapping match) and decode
        // it through the extraction pipeline
        let seed = b"seed-bytes-";
        let mut payload = [0u8; 64];
        let n = package::build_lz4_payload(seed, &mut payload).unwrap();
        // manifest whose file size = seed + 20 repeated bytes
        let mut out_expected = seed.to_vec();
        let last = *seed.last().unwrap();
        out_expected.extend(std::iter::repeat_n(last, 20));
        let mut m = Manifest::new(b"r1/lz", SemVer::release(1, 0, 0)).unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/lz").unwrap(),
            perm: 0o644,
            size: out_expected.len() as u64,
            sha256: sha256::digest(&out_expected),
        })
        .unwrap();
        // hand-build the package: header + the lz4 payload
        let repo = [0x33; 32];
        let mut buf: PkgBuf = [0u8; 512 * 1024];
        // store-mode skeleton, then the payload is spliced in
        let content = out_expected.clone();
        let n2 = package::build_package(&m, &[&content], &repo, &mut buf).unwrap();
        let mut mbuf = [0u8; 4096];
        let mlen = m.serialize(&mut mbuf).unwrap();
        let payload_off = 4 + 4 + mlen + 64;
        for b in buf[payload_off..n2].iter_mut() {
            *b = 0;
        }
        buf[payload_off..payload_off + n].copy_from_slice(&payload[..n]);
        let total = payload_off + n;
        // parse + extract through the real pipeline
        let mut src = package::SliceSource::new(&buf[..total]);
        let hdr = package::read_header(&mut src).unwrap();
        hdr.verify_signature(&ed25519::public_key(&repo)).unwrap();
        // (the signature covers only the manifest — the payload
        // framing is positional and hash-checked)
        let mut ib = package::InBuf::new();
        // feed the payload through a pulling source
        struct PullIo<'x> {
            src: package::SliceSource<'x>,
            sink: Vec<u8>,
        }
        impl package::ExtractIo for PullIo<'_> {
            fn pull(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
                crate::package::DataSource::read(&mut self.src, buf)
            }
            fn push(&mut self, data: &[u8]) -> crate::Result<()> {
                self.sink.extend_from_slice(data);
                Ok(())
            }
        }
        let mut io = PullIo {
            src: package::SliceSource::new(&buf[payload_off..total]),
            sink: Vec::new(),
        };
        package::extract_file(&hdr, 0, &mut ib, &mut io).unwrap();
        assert_eq!(io.sink, out_expected, "lz4 decode must reproduce the data");
    }

    #[test]
    fn decompression_bomb_refused() {
        // three 20-byte LZ4 blocks, each expanding to one 4096-byte
        // window via a long overlapping match: 12288 output from 60
        // input bytes — the ratio cap (100x + slack) fires on the
        // third block, mid-decode
        // token 0x1F: literal count 1, match nibble 15 (extended)
        let mut block = vec![0x1Fu8, 0x41, 0x01, 0x00];
        block.extend(std::iter::repeat_n(0xFFu8, 15));
        block.push(0xFB); // mlen = 4 + 15 + 15*255 + 251 = 4095
        let mut payload = vec![1u8]; // mode = lz4
        for _ in 0..3 {
            let raw: u16 = 4096;
            let comp: u16 = block.len() as u16;
            payload.extend_from_slice(&comp.to_le_bytes());
            payload.extend_from_slice(&raw.to_le_bytes());
            payload.extend_from_slice(&block);
        }
        let claimed = 3u64 * 4096;
        let mut m = Manifest::new(b"r1/bomb", SemVer::release(1, 0, 0)).unwrap();
        m.push_file(FileEntry {
            path: Path::from_bytes(b"/bin/bomb").unwrap(),
            perm: 0o644,
            size: claimed,
            sha256: [0; 32], // never reached: the bomb fires first
        })
        .unwrap();
        let repo = [0x44; 32];
        let mut buf: PkgBuf = [0u8; 512 * 1024];
        // store-mode skeleton, then the payload is spliced in
        let content = vec![0u8; claimed as usize];
        let n2 = package::build_package(&m, &[&content], &repo, &mut buf).unwrap();
        let mut mbuf = [0u8; 4096];
        let mlen = m.serialize(&mut mbuf).unwrap();
        let payload_off = 4 + 4 + mlen + 64;
        for b in buf[payload_off..n2].iter_mut() {
            *b = 0;
        }
        buf[payload_off..payload_off + payload.len()].copy_from_slice(&payload);
        let total = payload_off + payload.len();
        let mut src = package::SliceSource::new(&buf[..total]);
        let hdr = package::read_header(&mut src).unwrap();
        hdr.verify_signature(&ed25519::public_key(&repo)).unwrap();
        let mut ib = package::InBuf::new();
        struct PullIo<'x> {
            src: package::SliceSource<'x>,
            sink: usize,
        }
        impl package::ExtractIo for PullIo<'_> {
            fn pull(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
                crate::package::DataSource::read(&mut self.src, buf)
            }
            fn push(&mut self, data: &[u8]) -> crate::Result<()> {
                self.sink += data.len();
                Ok(())
            }
        }
        let mut io = PullIo {
            src: package::SliceSource::new(&buf[payload_off..total]),
            sink: 0,
        };
        let err = match package::extract_file(&hdr, 0, &mut ib, &mut io) {
            Ok(()) => panic!("a decompression bomb must be refused"),
            Err(e) => e,
        };
        assert!(
            err.kind() == ErrorKind::Bomb,
            "ratio guard must fire, got {err:?}"
        );
        assert!(io.sink < claimed as usize, "emitted far less than claimed");
    }

    #[test]
    fn solver_cycle_detected() {
        // a -> b -> a
        let mk = |name: &[u8], dep: Option<&[u8]>| -> Candidate {
            let mut m = Manifest::new(name, SemVer::release(1, 0, 0)).unwrap();
            if let Some(d) = dep {
                m.push_dep(Dependency::new(d, VersionReq::any()).unwrap())
                    .unwrap();
            }
            Candidate::from_manifest(&m).unwrap()
        };
        let cands = [mk(b"r1/aa", Some(b"r1/bb")), mk(b"r1/bb", Some(b"r1/aa"))];
        let mut solver = Solver::new(&[], &cands, false);
        let err = match solver.resolve_install(b"r1/aa", VersionReq::any()) {
            Ok(_) => panic!("cyclic deps must not resolve"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), ErrorKind::Cycle, "got {err:?}");
        assert!(
            err.detail().windows(5).any(|w| w == b"r1/aa"),
            "chain in detail"
        );
    }

    #[test]
    fn solver_conflict_detected() {
        let mk = |name: &[u8], conflicts: Option<&[u8]>| -> Candidate {
            let mut m = Manifest::new(name, SemVer::release(1, 0, 0)).unwrap();
            if let Some(c) = conflicts {
                m.push_relation(crate::manifest::Relation::Conflict, c)
                    .unwrap();
            }
            Candidate::from_manifest(&m).unwrap()
        };
        // a conflicts with b
        let cands = [mk(b"r1/aa", Some(b"r1/bb")), mk(b"r1/bb", None)];
        let inst = [Installed {
            name: {
                let mut n = [0u8; crate::limits::MAX_NAME];
                n[..5].copy_from_slice(b"r1/bb");
                n
            },
            name_len: 5,
            version: SemVer::release(1, 0, 0),
        }];
        let mut solver = Solver::new(&inst, &cands, false);
        // installing a (which conflicts with the kept b) must fail
        let r = solver.resolve_install(b"r1/aa", VersionReq::any()).err();
        assert!(
            r.is_some(),
            "conflict with an installed package must refuse"
        );
    }

    #[test]
    fn solver_prefers_latest_and_keeps_installed() {
        let mut m1 = Manifest::new(b"r1/xx", SemVer::release(1, 0, 0)).unwrap();
        let _ = &mut m1;
        let mut m2 = Manifest::new(b"r1/xx", SemVer::release(3, 1, 0)).unwrap();
        let _ = &mut m2;
        let cands = [
            Candidate::from_manifest(&m1).unwrap(),
            Candidate::from_manifest(&m2).unwrap(),
        ];
        let mut solver = Solver::new(&[], &cands, false);
        let plan = solver.resolve_install(b"r1/xx", VersionReq::any()).unwrap();
        let mut found_v3 = false;
        for op in plan.ops[..plan.count as usize].iter().copied() {
            if let crate::solver::PlanOp::Install(c) = op {
                if c.version == SemVer::release(3, 1, 0) {
                    found_v3 = true;
                }
            }
        }
        assert!(found_v3, "prefer-latest");
        // keep-installed: already at a satisfying version
        let inst = [Installed {
            name: {
                let mut n = [0u8; crate::limits::MAX_NAME];
                n[..5].copy_from_slice(b"r1/xx");
                n
            },
            name_len: 5,
            version: SemVer::release(3, 1, 0),
        }];
        let mut solver = Solver::new(&inst, &cands, false);
        let plan = solver.resolve_install(b"r1/xx", VersionReq::any()).unwrap();
        let mut kept = false;
        for op in plan.ops[..plan.count as usize].iter().copied() {
            if let crate::solver::PlanOp::Keep(nm, len) = op {
                if &nm[..len as usize] == b"r1/xx" {
                    kept = true;
                }
            }
        }
        assert!(kept, "prefer-keep when installed satisfies");
    }

    #[test]
    fn repo_epoch_replay_defense() {
        use crate::database::RepoEpochs;
        let mut t = RepoEpochs::empty();
        t.observe(b"r1", 7, [1; 32]).unwrap();
        // same epoch, same digest: fine
        assert!(t.check(b"r1", 7, &[1; 32]).is_ok());
        // same epoch, different digest: replay/rollback refused
        assert_eq!(
            t.check(b"r1", 7, &[2; 32]).unwrap_err().kind(),
            ErrorKind::Replay
        );
        // lower epoch refused
        assert_eq!(
            t.check(b"r1", 6, &[1; 32]).unwrap_err().kind(),
            ErrorKind::Replay
        );
        // higher epoch accepted
        assert!(t.check(b"r1", 8, &[3; 32]).is_ok());
        // roundtrip through serialize/parse
        let mut buf = [0u8; 4 + 2 + 1 + 16 * (1 + crate::limits::MAX_NAME + 8 + 32)];
        let n = t.serialize(&mut buf).unwrap();
        let t2 = RepoEpochs::parse(&buf[..n]).unwrap();
        assert_eq!(t2.seen(b"r1"), Some((7, [1; 32])));
    }

    #[test]
    fn audit_detects_tampering() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 0, "{out}");
        // tamper with the installed file
        fs.put_file(b"/bin/hello", b"EVIL\n", 0o755);
        let (code, out) = run(&mut fs, &[b"verify"]);
        assert_eq!(code, 1, "verify must detect the change: {out}");
        assert!(out.contains("CHANGED"), "{out}");
        let (code, out) = run(&mut fs, &[b"audit"]);
        assert_eq!(code, 1, "audit must report it: {out}");
        assert!(out.contains("1 problems"), "{out}");
    }

    #[test]
    fn search_and_info_work() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        let (code, out) = run(&mut fs, &[b"search", b"hell"]);
        assert_eq!(code, 0);
        assert!(out.contains("r1/hello"), "search: {out}");
        let (code, out) = run(&mut fs, &[b"install", b"r1/hello"]);
        assert_eq!(code, 0, "{out}");
        let (code, out) = run(&mut fs, &[b"info", b"r1/hello"]);
        assert_eq!(code, 0);
        assert!(out.contains("installed"), "info: {out}");
        // repo list
        let (code, out) = run(&mut fs, &[b"repo", b"list"]);
        assert_eq!(code, 0);
        assert!(out.contains("r1 /r1 local"), "repo list: {out}");
    }

    #[test]
    fn update_reports_epochs() {
        let mut fs = MemFs::new();
        let (name, ver, files, deps) = hello_pkg();
        build_repo(&mut fs, &[(name, ver, &files, &deps)]);
        let (code, out) = run(&mut fs, &[b"update"]);
        assert_eq!(code, 0, "update: {out}");
        assert!(out.contains("epoch 7"), "{out}");
        // replay defense: the same epoch with the same digest is fine
        let (code, out) = run(&mut fs, &[b"update"]);
        assert_eq!(code, 0, "same-epoch update: {out}");
    }
}
