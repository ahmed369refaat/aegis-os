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

## K22 — the ring-3 image (built and contract-checked; not yet in the kernel)

`./boot.sh` step `[0d]` links the image and checks it at every build:

```bash
cargo build -p aegis-pkg --bin pkg --profile pkg-image --target x86_64-unknown-none
python3 scripts/check-pkg-image.py target/x86_64-unknown-none/pkg-image/pkg
strip --strip-all target/x86_64-unknown-none/pkg-image/pkg -o kernel-x86_64/blob/pkg.bin
```

- **The link layout** (`pkg/pkg.ld`, `pkg/build.rs`): three PT_LOADs
  under the kernel's `SERVICE` contract (`mm/user_layout.rs`) — text
  R+X at 0x400000, rodata R, data R+W with the bss tail contiguous in
  the SAME phdr — one ABSENT page between neighbours (the kernel's
  ten-check policy refuses adjacent regions). `.eh_frame*`, `.note*`
  and `.comment` are discarded: the loader refuses unknown header
  types.
- **The size recipe** (`[profile.pkg-image]`: opt-level z, one codegen
  unit): text 98,671 B / rodata 10,684 B / data 288 B / no bss; 29
  image pages + 2 guard pages = 31 of the 128-page cage; with the
  64-page stack and the trampoline, 96 of the PM quota's 192 pages.
  The same code at opt-level 3 links 234 KiB of text.
- **The entry**: `_start` reads the SysV initial stack the kernel's
  execve builds (`[rsp] = argc`, then the argv pointers), aligns,
  calls `pkg_main(argc, argv)` and exits with its answer through
  SYS_EXIT (63).
- **The adapter** (`target_abi` in `src/main.rs`) behind a testable
  `Io` port: the crate's `OpenFlags` become the kernel's word
  (`RDONLY`→O_READ, `RDONLY|DIRECTORY`→O_READ,
  `WRONLY`→O_WRITE|O_TRUNC, `+CREATE`→O_WRITE|O_TRUNC|O_CREAT,
  `+EXCL`→O_WRITE|O_CREAT|O_EXCL); `read`/`write`/`getdents` go out
  in 4096-byte pages (the kernel answers `-EINVAL` above one page); a
  short read is asked again and only a 0 ends the fill; the kernel's
  errno words map onto the crate's family (EACCES/EPERM→Access,
  ENOENT→NoEnt, ENOMEM/ENOSPC→NoSpace, EEXIST→Exists,
  ENOTDIR→NotDir, EISDIR→IsDir, ENOTEMPTY→NotEmpty). Output goes
  through a 4096-byte buffer to fd 1. Eleven host tests pin all of it
  (`target_abi_tests`).
- **The stack budget**: the static worst direct-call stack chain is
  58,352 B of the 256 KiB stack (`scripts/pkg-stack-depth.py`; the
  check fails the build above 80 KiB). The solver's recursion
  (~3,448 B a level, depth 48 ≈ 161.6 KiB adversarial) is why the
  chain has to stay under that line.

**Why `/bin/pkg` is not in the kernel's exec registry yet.** The
kernel image lives in ONE 2 MiB huge page (PA 2..4 MiB; the linker
script's ASSERT). The last kernel that links is text 733,184 B +
data 86,016 B + bss 1,204,224 B = 2,023,424 B — 73,728 B of headroom
— while the stripped image is 119,424 B: 45,696 B over, and the link
fails with "kernel image exceeds the single 2 MiB higher-half huge
page". Nothing about the image is wrong; it does not fit beside the
kernel. The two honest ways out:

1. a second huge page (PA 4..6 MiB) in the boot stub's mapping, the
   kernel's own tables, the linker ASSERT, and the frame allocator's
   first free frame (today 0x400000);
2. a disk-sourced slot like `/bin/hello` — which needs a ≥ 128 KiB
   static buffer, i.e. the same bss headroom, so (1) comes first
   either way.

Until then `kernel-x86_64/blob/pkg.bin` is a build output
(gitignored), the registry keeps its two `CANONICAL` citizens, and
the exec arm's `SERVICE` path is proven by host tests only.
