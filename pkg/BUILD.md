# BUILD — the AegisOS package manager

## Layout

```text
pkg/                 crate `aegis-pkg` (workspace member)
  src/lib.rs         Fs trait, Path, limits, byte primitives
  src/error.rs       error taxonomy
  src/manifest.rs    AMFT: model, strict parse, canonical serialize
  src/crypto.rs      SHA-256/512, CRC-32, ct_eq, Ed25519 (verify always;
                     sign under cfg(any(test, feature = "signer")))
  src/package.rs     AKP1 container, streaming LZ4, extraction pipeline
  src/database.rs    records, state, repo-epoch table, PkgPaths
  src/repository.rs  signed index, trust anchors, local + broker repos
  src/solver.rs      backtracking resolver
  src/transaction.rs lock, staging, WAL journal, commit/recovery
  src/cli.rs         the eleven commands
  src/main.rs        host binary + x86_64-unknown-none entry
  src/tests/mod.rs   48 host tests (see THREAT_MODEL.md coverage map)
```

## Build & test

```bash
source /home/z/my-project/tools/env.sh      # toolchain PATH

# host: full test suite (RUST_MIN_STACK matters: solver/universe
# buffers are large fixed arrays by design — no allocator)
RUST_MIN_STACK=16777216 cargo test -p aegis-pkg --lib

# host: the real binary (sandboxed to ./pkg-root, or $PKG_ROOT)
cargo run -p aegis-pkg -- install core/hello

# no_std target: the whole binary (no_std, no_main, panic handler,
# syscall adapter) compiles for the freestanding target
cargo build -p aegis-pkg --target x86_64-unknown-none

# lint / format
cargo fmt -p aegis-pkg
cargo clippy -p aegis-pkg --all-targets -- -D warnings
```

Signing (package + index building) is compiled only under
`--features signer` or in tests: **the deployed manager verifies,
it never creates** — there is no signing code in a target build.

## The domain's syscall mask (least privilege)

The manager performs every filesystem operation through the `Fs`
trait (`src/lib.rs`), whose surface *is* the mask. The AegisOS
adapter (`src/main.rs`, `target_os = "none"`) maps each trait
method to exactly one syscall:

| Fs operation | Syscall (aegis-os/src/syscall.rs)      | nr  |
| ------------ | --------------------------------------- | --- |
| `open`       | SYS_OPEN (O_RDONLY/WONLY/CREATE/EXCL)   | 2   |
| `read`       | SYS_READ                                | 0   |
| `write`      | SYS_WRITE                               | 1   |
| `close`      | SYS_CLOSE                               | 3   |
| `mkdir`      | SYS_MKDIR                               | 16  |
| `unlink`     | SYS_UNLINK                              | 17  |
| `exit`       | SYS_EXIT                                | 63  |
| `stat`       | SYS_STAT *(reserved nr 64)*            | 64* |
| `rename`     | SYS_RENAME *(reserved nr 65)*          | 65* |
| `getdents`   | SYS_GETDENTS *(reserved nr 66)*        | 66* |

Network access goes **only through the broker**: the domain's mask
additionally admits `SYS_NET_SEND`/`SYS_NET_RECV` (nr 9/10) — the
broker's token-bucket rate-limited arms — used exclusively by
`BrokerRepository` fetches. `fsync` is currently a documented no-op
(the AegisOS VFS is write-through; the trait contract stays so a
future cached VFS becomes correct without touching this crate).

**Forbidden for this domain, by mask:** `execve`, `mmap` (hence any
`PROT_EXEC`), `spawn`, `ipc_send/recv`, `kill`, `chroot` — and the
mask is attenuation-only, so nothing downstream can widen it.

### Kernel wiring points (K21, honestly stated)

The kernel today exposes `read/write/open/close/mkdir/unlink/exit`
and the broker net arms; `stat`, `rename`, and `getdents` are
reserved numbers in the adapter with the arms still to land in the
VFS (the K21 items). Until they do, the target binary compiles and
boots but install/verify return ENOSYS for those three — the
library, transactions, solver, and all 48 host tests are fully
proven meanwhile (the `Fs` trait is the exact contract the kernel
must implement).

## Wiring into the boot image

1. Build the freestanding binary:
   `cargo build -p aegis-pkg --target x86_64-unknown-none --release`
2. Register `/bin/pkg` on the ext2 disk (`mke2.py`-style
   integration, as `/bin/hello` is today), and add the PM domain to
   the boot's spawn list with the driver-adjacent profile: the mask
   above + `NET_SEND|NET_RECV`, `/pkg` as its writable root (Unix
   perms 0700 root), stack ≥ 2 MiB (the solver/universe buffers are
   fixed arrays — the no-alloc design), and the standard data-page
   boot info.
3. The entry contract: `pkg_main(argc, argv)` with NUL-terminated
   byte-string arguments (the execve argv marshalling is the same
   K21 wiring item as `/bin/hello`'s argument passing).
4. Provision `/pkg/trust` (root anchors) at image build time —
   never through the manager.

## Repository layout (local repos)

```text
/repo-slug/
  index.aki          signed index (AKI1)
  repo-slug.pkg.akp  one package file per namespaced name
/pkg/
  trust              root anchors (ATST)
  repos/<slug>.repo  registered repos (ARPS: url, key, pinned)
  db/...             records, state, journal, repo epochs
  cache/  stage/  lock
```
