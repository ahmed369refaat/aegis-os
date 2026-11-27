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
| `stat`       | SYS_STAT (Linux: newfstatat 262)         | 34  |
| `rename`     | SYS_RENAME (Linux: rename 82/renameat 264) | 35 |
| `getdents`   | SYS_LISTDIR (Linux: getdents64 259)      | 32  |

Network access goes **only through the broker**: the domain's mask
additionally admits `SYS_NET_SEND`/`SYS_NET_RECV` (nr 9/10) — the
broker's token-bucket rate-limited arms — used exclusively by
`BrokerRepository` fetches. `fsync` is currently a documented no-op
(the AegisOS VFS is write-through; the trait contract stays so a
future cached VFS becomes correct without touching this crate).

**Forbidden for this domain, by mask:** `execve`, `mmap` (hence any
`PROT_EXEC`), `spawn`, `ipc_send/recv`, `kill`, `chroot` — and the
mask is attenuation-only, so nothing downstream can widen it.

### Kernel wiring (K21 — landed)

The whole `Fs` surface is live in the kernel now:

- `read/write/open/close/mkdir/unlink/exit` — since Phase 6/K20.
- `stat` — `SYS_STAT` (34): the 24-byte struct contract below, core
  executor gated by an FsNode READ capability, Linux `newfstatat`
  (262) mapped in the v1 whitelist (old stat(4)/fstat(5) stay
  deliberately unmapped). Core-tested
  (`stat_fills_the_24_byte_contract_and_gates`).
- `rename` — `SYS_RENAME` (35): the atomic re-parent with POSIX
  file-destination replacement, identity preservation (same inode
  id + generation), EISDIR refusals for directory destinations and
  subtree cycles, WRITE caps on both parents; Linux `rename`(82) /
  `renameat`(264) mapped. Core-tested
  (`rename_reparents_replaces_and_refuses`).
- `getdents` — the kernel's existing `SYS_LISTDIR` (32): NUL-separated
  names + count (the documented getdents64 subset semantics; Linux
  259 maps there since Phase 7).
- `execve` argv marshalling — live since Phase 6 S3 (`sys_exec` builds
  the `[rsp] = argc, argv pointers` user stack).

The `Fs` trait's 24-byte stat struct: `kind u8 @0` (0 file, 1 dir, 3
other — the kernel VFS has no symlinks), `size u64 LE @8`, `perm
u16 LE @16` (0o777).

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
   byte-string arguments (the execve argv marshalling landed with
   Phase 6 S3; the boot-spawn path is the remaining integration).
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
