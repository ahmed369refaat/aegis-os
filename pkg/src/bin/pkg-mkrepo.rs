//! K22/K23/P1-2: the boot fixture builder — the SIGNED local repo
//! the in-VM package manager installs from, now carrying REAL
//! BINARIES.
//!
//! A HOST tool (std, `signer` feature): signing exists for repo
//! BUILDING, never inside the deployed manager. It reproduces the host
//! test suite's `build_repo` recipe with TEST-ONLY fixed seeds — the
//! same `[0x11; 32]` root and `[0x22; 32]` repo seeds the tests use,
//! pinned here so no one mistakes them for production keys — and
//! writes six files into the output directory (embedded by the
//! kernel's K22/K23 boot lanes through the ext2 `/pkgsrc` store):
//!
//!   `trust`               the root trust anchors (ATST)
//!   `r1.repo`             the pinned local repo config (ARPS, url `/r1`)
//!   `index.aki`           the root-countersigned index (AKI1, epoch 7,
//!                         FOUR entries — both versions of hello, the
//!                         netcat client, the rustc citizen)
//!   `r1.hello-1.0.0.akp`  the signed package (AKP1): `r1/hello` 1.0.0,
//!                         one file — `/usr/bin/pkg-hello` =
//!                         "hello world\n" (12 B)
//!   `r1.hello-1.1.0.akp`  the signed package (AKP1): `r1/hello` 1.1.0,
//!                         one file — `/usr/bin/pkg-hello` = the REAL
//!                         STRIPPED gcc userland ELF (`blob/userland-
//!                         hello.elf`, the same bytes the ext2 disk
//!                         serves as /bin/hello — the upgrade round
//!                         now installs a genuine loadable image,
//!                         byte-identical to the exec registry's)
//!   `r1.netcat-1.0.0.akp` the signed package (AKP1): `r1/netcat` 1.0.0,
//!                         one file — `/usr/bin/netcat` = the REAL
//!                         STRIPPED gcc net client (`blob/netcatd.bin`,
//!                         the P1-1 socket citizen) — a third-party
//!                         static binary delivered through the signed
//!                         package path
//!   `r1.rust-hello-1.0.0.akp` the signed package (AKP1): `r1/rust-hello`
//!                         1.0.0, one file — `/usr/bin/rust-hello` = the
//!                         REAL rustc-built ELF (`blob/rust-hello.elf`,
//!                         512 B, `ld -n`-packed segments): the THIRD
//!                         citizen type — a Rust image, not gcc — through
//!                         the same signed path
//!
//! K23: the package files are VERSION-QUALIFIED (the repo's layout
//! change that lets one directory serve both versions) — the install
//! lane reads the 1.0.0 file, the upgrade lane's solver picks 1.1.0
//! and the transaction reads the 1.1.0 file.
//!
//! Every file must stay ≤ 12 KiB: the kernel's pkgsrc store slots
//! mirror the ext2 reader's direct-block ceiling, so the tool FAILS
//! the build if any output crosses it — a manifest that grew past it
//! dies here, not at boot.
//!
//! Usage: `pkg-mkrepo <output-dir>`
//! (default `kernel-x86_64/blob/pkg-fixture`, the path boot.sh passes).
//! The REAL payloads are read from repo-root-relative blob paths
//! (built by boot.sh steps [0c]/[0e] before this step [0g] runs).
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
/// The pkgsrc store's slot bound (the ext2 reader's direct-block
/// ceiling, which the kernel's `SLOT_MAX` mirrors).
const RAMFS_WINDOW: usize = 12 * 1024;
/// The package this repo serves — the happy-path test's own spec, with
/// the payload re-aimed at `/usr/bin/pkg-hello` (the test's
/// `/bin/hello` destination is the exec registry's disk slot path).
const PKG_NAME: &[u8] = b"r1/hello";
const PAYLOAD_PATH: &[u8] = b"/usr/bin/pkg-hello";
/// P1-2's second package: the netcat client (the P1-1 socket citizen),
/// a REAL third-party static binary delivered through the signed path.
const NETCAT_NAME: &[u8] = b"r1/netcat";
const NETCAT_PATH: &[u8] = b"/usr/bin/netcat";
/// P1-2's third package: the RUSTC citizen — the third compiler path
/// through the signed repo (gcc, gcc, rustc).
const RUSTHELLO_NAME: &[u8] = b"r1/rust-hello";
const RUSTHELLO_PATH: &[u8] = b"/usr/bin/rust-hello";
/// v1.0.0's payload — the K22 install lane's byte-exact target.
const PAYLOAD_V10: &[u8] = b"hello world\n";
/// v1.1.0's payload — the REAL stripped gcc userland ELF (read from
/// the blob boot.sh step [0c] builds and strips): the K23 upgrade
/// lane's byte-exact target, byte-identical to the /bin/hello the
/// ext2 disk serves (P1-2: the upgrade installs a genuine image).
fn read_payload(rel: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(rel);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("pkg-mkrepo: cannot read the REAL payload {rel} ({e}) — run boot.sh steps [0c]/[0e] first")
    })
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "kernel-x86_64/blob/pkg-fixture".to_string());
    std::fs::create_dir_all(&dir).expect("create the fixture dir");

    // P1-2: the REAL payloads — the stripped gcc ELFs the earlier
    // boot.sh steps built (and the ext2 disk carries as /bin/hello),
    // plus the packed rustc ELF (step [0b], 512 B).
    let payload_v11 = read_payload("kernel-x86_64/blob/userland-hello.elf");
    let payload_netcat = read_payload("kernel-x86_64/blob/netcatd.bin");
    let payload_rusthello = read_payload("kernel-x86_64/blob/rust-hello.elf");

    // Three packages: r1/hello 1.0.0 (the small string) and 1.1.0 (the
    // REAL gcc ELF — same path, different payload bytes and sizes), plus
    // r1/netcat 1.0.0 (the REAL socket citizen). One 0755 file each, no
    // dependencies.
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
        size: payload_v11.len() as u64,
        sha256: sha256::digest(&payload_v11),
    })
    .expect("file entry 1.1.0");
    let mut mnc = Manifest::new(NETCAT_NAME, SemVer::release(1, 0, 0)).expect("manifest netcat");
    mnc.push_file(FileEntry {
        path: Path::from_bytes(NETCAT_PATH).expect("netcat path"),
        perm: 0o755,
        size: payload_netcat.len() as u64,
        sha256: sha256::digest(&payload_netcat),
    })
    .expect("file entry netcat");

    let mut pkg10: PkgBuf = [0u8; 512 * 1024];
    let pkg10_len =
        build_package(&m10, &[PAYLOAD_V10], &REPO_SEED, &mut pkg10).expect("package 1.0.0");
    let mut pkg11: PkgBuf = [0u8; 512 * 1024];
    let pkg11_len =
        build_package(&m11, &[&payload_v11], &REPO_SEED, &mut pkg11).expect("package 1.1.0");
    let mut pkgnc: PkgBuf = [0u8; 512 * 1024];
    let pkgnc_len =
        build_package(&mnc, &[&payload_netcat], &REPO_SEED, &mut pkgnc).expect("package netcat");
    let mut mrh =
        Manifest::new(RUSTHELLO_NAME, SemVer::release(1, 0, 0)).expect("manifest rust-hello");
    mrh.push_file(FileEntry {
        path: Path::from_bytes(RUSTHELLO_PATH).expect("rust-hello path"),
        perm: 0o755,
        size: payload_rusthello.len() as u64,
        sha256: sha256::digest(&payload_rusthello),
    })
    .expect("file entry rust-hello");
    let mut pkgrh: PkgBuf = [0u8; 512 * 1024];
    let pkgrh_len = build_package(&mrh, &[&payload_rusthello], &REPO_SEED, &mut pkgrh)
        .expect("package rust-hello");

    // The signed index (repo key signs, root countersigns) — ALL FOUR
    // packages are entries; the solver's universe reads one candidate
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
        (
            NETCAT_NAME,
            mnc,
            sha256::digest(&pkgnc[..pkgnc_len]),
            pkgnc_len as u64,
        ),
        (
            RUSTHELLO_NAME,
            mrh,
            sha256::digest(&pkgrh[..pkgrh_len]),
            pkgrh_len as u64,
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

    let files: [(&str, &[u8]); 7] = [
        ("trust", &trust[..trust_len]),
        ("r1.repo", &cfg[..cfg_len]),
        ("index.aki", &index[..index_len]),
        ("r1.hello-1.0.0.akp", &pkg10[..pkg10_len]),
        ("r1.hello-1.1.0.akp", &pkg11[..pkg11_len]),
        ("r1.netcat-1.0.0.akp", &pkgnc[..pkgnc_len]),
        ("r1.rust-hello-1.0.0.akp", &pkgrh[..pkgrh_len]),
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
