//! K22: the boot fixture builder — the SIGNED local repo the in-VM
//! package manager installs from.
//!
//! A HOST tool (std, `signer` feature): signing exists for repo
//! BUILDING, never inside the deployed manager. It reproduces the host
//! test suite's `build_repo` recipe with TEST-ONLY fixed seeds — the
//! same `[0x11; 32]` root and `[0x22; 32]` repo seeds the tests use,
//! pinned here so no one mistakes them for production keys — and
//! writes four files into the output directory (embedded by the
//! kernel's K22 boot lane):
//!
//!   `trust`         the root trust anchors (ATST)
//!   `r1.repo`       the pinned local repo config (ARPS, url `/r1`)
//!   `index.aki`     the root-countersigned index (AKI1, epoch 7)
//!   `r1.hello.akp`  the signed package (AKP1): `r1/hello` 1.0.0, one
//!                   file — `/usr/bin/pkg-hello` = "hello world\n"
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
const PAYLOAD: &[u8] = b"hello world\n";

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "kernel-x86_64/blob/pkg-fixture".to_string());
    std::fs::create_dir_all(&dir).expect("create the fixture dir");

    // The package: r1/hello 1.0.0, one 0755 file, no dependencies.
    let mut manifest = Manifest::new(PKG_NAME, SemVer::release(1, 0, 0)).expect("manifest");
    manifest
        .push_file(FileEntry {
            path: Path::from_bytes(PAYLOAD_PATH).expect("payload path"),
            perm: 0o755,
            size: PAYLOAD.len() as u64,
            sha256: sha256::digest(PAYLOAD),
        })
        .expect("file entry");
    let mut pkg: PkgBuf = [0u8; 512 * 1024];
    let pkg_len = build_package(&manifest, &[PAYLOAD], &REPO_SEED, &mut pkg).expect("package");

    // The signed index (repo key signs, root countersigns).
    let entries = [(
        PKG_NAME,
        manifest,
        sha256::digest(&pkg[..pkg_len]),
        pkg_len as u64,
    )];
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
    // provisioned the two repo files).
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

    let files: [(&str, &[u8]); 4] = [
        ("trust", &trust[..trust_len]),
        ("r1.repo", &cfg[..cfg_len]),
        ("index.aki", &index[..index_len]),
        ("r1.hello.akp", &pkg[..pkg_len]),
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
