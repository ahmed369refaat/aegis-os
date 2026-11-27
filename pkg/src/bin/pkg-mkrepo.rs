//! K22/K23: the boot fixture builder — the SIGNED local repo the
//! in-VM package manager installs from.
//!
//! A HOST tool (std, `signer` feature): signing exists for repo
//! BUILDING, never inside the deployed manager. It reproduces the host
//! test suite's `build_repo` recipe with TEST-ONLY fixed seeds — the
//! same `[0x11; 32]` root and `[0x22; 32]` repo seeds the tests use,
//! pinned here so no one mistakes them for production keys — and
//! writes five files into the output directory (embedded by the
//! kernel's K22/K23 boot lanes):
//!
//!   `trust`               the root trust anchors (ATST)
//!   `r1.repo`             the pinned local repo config (ARPS, url `/r1`)
//!   `index.aki`           the root-countersigned index (AKI1, epoch 7,
//!                         TWO entries — both versions of hello)
//!   `r1.hello-1.0.0.akp`  the signed package (AKP1): `r1/hello` 1.0.0,
//!                         one file — `/usr/bin/pkg-hello` =
//!                         "hello world\n" (12 B)
//!   `r1.hello-1.1.0.akp`  the signed package (AKP1): `r1/hello` 1.1.0,
//!                         one file — `/usr/bin/pkg-hello` =
//!                         "hello world v1.1\n" (17 B — a DIFFERENT
//!                         payload at a DIFFERENT size, so the upgrade
//!                         lane proves the bytes and the size moved)
//!
//! K23: the package files are VERSION-QUALIFIED (the repo's layout
//! change that lets one directory serve both versions) — the install
//! lane reads the 1.0.0 file, the upgrade lane's solver picks 1.1.0
//! and the transaction reads the 1.1.0 file.
//!
//! Every file must stay ≤ 8192 B: the kernel ramfs holds files above
//! 1 KiB in 8 KiB side-table windows (`LARGE_FILE_MAX`), so the tool
//! FAILS the build if any output crosses the window — a manifest that
//! grew past it dies here, not at boot.
//!
//! Usage: `pkg-mkrepo <output-dir>`
//! (default `kernel-x86_64/blob/pkg-fixture`, the path boot.sh passes).
use aegis_pkg::cli::build_index_with_hashes;
use aegis_pkg::crypto::{ed25519, sha256};
use aegis_pkg::manifest::{FileEntry, Manifest, SemVer};
use aegis_pkg::package::{build_package, PkgBuf};
use aegis_pkg::repository::{RepoConfig, TrustAnchors};
use aegis_pkg::{limits, Path};

/// TEST-ONLY: the root key seed (the host suite's own fixture seed).
const ROOT_SEED: ed25519::SecretKey = [0x11; 32];
/// TEST-ONLY: the repo signing key seed (the same one the tests sign
/// their fixture packages with).
const REPO_SEED: ed25519::SecretKey = [0x22; 32];
/// The fixture repo's index epoch (mirrors the tests' `build_repo`).
const EPOCH: u64 = 7;
/// The ramfs spill-window bound (the kernel's `LARGE_FILE_MAX`).
const RAMFS_WINDOW: usize = 8192;
/// The package this repo serves — the happy-path test's own spec, with
/// the payload re-aimed at `/usr/bin/pkg-hello` (the test's
/// `/bin/hello` destination is the exec registry's disk slot path).
const PKG_NAME: &[u8] = b"r1/hello";
const PAYLOAD_PATH: &[u8] = b"/usr/bin/pkg-hello";
/// v1.0.0's payload — the K22 install lane's byte-exact target.
const PAYLOAD_V10: &[u8] = b"hello world\n";
/// v1.1.0's payload — different bytes AND a different installed size
/// (the K23 upgrade lane's byte-exact target).
const PAYLOAD_V11: &[u8] = b"hello world v1.1\n";

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "kernel-x86_64/blob/pkg-fixture".to_string());
    std::fs::create_dir_all(&dir).expect("create the fixture dir");

    // Both packages: r1/hello 1.0.0 and 1.1.0, one 0755 file each, no
    // dependencies — same path, different payload bytes and sizes.
    let mut m10 = Manifest::new(PKG_NAME, SemVer::release(1, 0, 0)).expect("manifest 1.0.0");
    m10.push_file(FileEntry {
        path: Path::from_bytes(PAYLOAD_PATH).expect("payload path"),
        perm: 0o755,
        size: PAYLOAD_V10.len() as u64,
        sha256: sha256::digest(PAYLOAD_V10),
    })
    .expect("file entry 1.0.0");
    let mut m11 = Manifest::new(PKG_NAME, SemVer::release(1, 1, 0)).expect("manifest 1.1.0");
    m11.push_file(FileEntry {
        path: Path::from_bytes(PAYLOAD_PATH).expect("payload path"),
        perm: 0o755,
        size: PAYLOAD_V11.len() as u64,
        sha256: sha256::digest(PAYLOAD_V11),
    })
    .expect("file entry 1.1.0");

    let mut pkg10: PkgBuf = [0u8; 512 * 1024];
    let pkg10_len =
        build_package(&m10, &[PAYLOAD_V10], &REPO_SEED, &mut pkg10).expect("package 1.0.0");
    let mut pkg11: PkgBuf = [0u8; 512 * 1024];
    let pkg11_len =
        build_package(&m11, &[PAYLOAD_V11], &REPO_SEED, &mut pkg11).expect("package 1.1.0");

    // The signed index (repo key signs, root countersigns) — BOTH
    // versions are entries; the solver's universe reads one candidate
    // per entry, newest-first at plan time.
    let entries = [
        (
            PKG_NAME,
            m10,
            sha256::digest(&pkg10[..pkg10_len]),
            pkg10_len as u64,
        ),
        (
            PKG_NAME,
            m11,
            sha256::digest(&pkg11[..pkg11_len]),
            pkg11_len as u64,
        ),
    ];
    let mut index = [0u8; 96 * 1024];
    let index_len = build_index_with_hashes(
        b"r1",
        EPOCH,
        &entries,
        &REPO_SEED,
        Some(&ROOT_SEED),
        &mut index,
    )
    .expect("index");

    // The repo config: pinned, local, url /r1 (where the boot lane
    // provisioned the repo files).
    let config = RepoConfig {
        slug: name_buf(b"r1"),
        slug_len: 2,
        url: url_buf(b"/r1"),
        url_len: 3,
        key: ed25519::public_key(&REPO_SEED),
        pinned: true,
        local: true,
    };
    let mut cfg = [0u8; 300];
    let cfg_len = config.serialize(&mut cfg).expect("config");

    // The root trust anchors.
    let anchors = TrustAnchors {
        keys: {
            let mut keys = [[0u8; 32]; 8];
            keys[0] = ed25519::public_key(&ROOT_SEED);
            keys
        },
        count: 1,
    };
    let mut trust = [0u8; 4 + 2 + 1 + 8 * 32];
    let trust_len = anchors.serialize(&mut trust).expect("anchors");

    let files: [(&str, &[u8]); 5] = [
        ("trust", &trust[..trust_len]),
        ("r1.repo", &cfg[..cfg_len]),
        ("index.aki", &index[..index_len]),
        ("r1.hello-1.0.0.akp", &pkg10[..pkg10_len]),
        ("r1.hello-1.1.0.akp", &pkg11[..pkg11_len]),
    ];
    for (name, bytes) in files {
        assert!(
            bytes.len() <= RAMFS_WINDOW,
            "{name} is {} B — over the ramfs 8 KiB spill window",
            bytes.len()
        );
        let path = std::path::Path::new(&dir).join(name);
        std::fs::write(&path, bytes).expect("write the fixture file");
        println!("pkg-mkrepo: {} ({} B)", path.display(), bytes.len());
    }
}

/// The fixed-size slug field (`[u8; limits::MAX_NAME]`).
fn name_buf(slug: &[u8]) -> [u8; limits::MAX_NAME] {
    let mut buf = [0u8; limits::MAX_NAME];
    buf[..slug.len()].copy_from_slice(slug);
    buf
}

/// The fixed-size url field (`[u8; 128]`).
fn url_buf(url: &[u8]) -> [u8; 128] {
    let mut buf = [0u8; 128];
    buf[..url.len()].copy_from_slice(url);
    buf
}
