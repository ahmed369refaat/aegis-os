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
| `rename`     | SYS_RENAME (Linux: rename 82/renameat 264) | 36 |
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
  index.aki                      signed index (AKI1)
  <name>-<major.minor.patch>.akp one VERSION-QUALIFIED file per
                                 candidate (K23: two versions of one
                                 package can coexist — a name-keyed
                                 file made the second overwrite the
                                 first, and `upgrade` had nothing
                                 newer to resolve to)
/pkg/
  trust              root anchors (ATST)
  repos/<slug>.repo  registered repos (ARPS: url, key, pinned)
  db/...             records, state, journal, repo epochs
  cache/  stage/  lock
```

`LocalRepository::package_path(name, ver)` (pkg/src/repository.rs)
builds the version-qualified name: `/` in the package name becomes
`.`, then `-`, then the semver, then `.akp` — `r1/hello` 1.1.0 lives
at `r1.hello-1.1.0.akp`. The index lists every version; the solver
walks candidates newest-first, and `package_path_for(&Candidate)`
picks the file matching the PLAN'S chosen version — not the repo's
only one.

## K23/P1-2 — the lifecycle fixture and the four-round boot lane

The boot fixture (`pkg/src/bin/pkg-mkrepo.rs`, `./boot.sh` step
`[0g]`) serves SIX files, each ≤ 12 KiB (the ext2 direct-block
ceiling — the one bound that rules the whole repo path: the disk
walk, the store slot, the ramfs spill window):

```text
trust               root anchors (ATST)
r1.repo             pinned local repo config (ARPS, url /r1)
index.aki           root-countersigned index (AKI1, epoch 7, THREE entries)
r1.hello-1.0.0.akp  r1/hello 1.0.0 → /usr/bin/pkg-hello = "hello world\n" (12 B)
r1.hello-1.1.0.akp  r1/hello 1.1.0 → /usr/bin/pkg-hello = the REAL stripped
                    gcc userland ELF (8,496 B — the same bytes the ext2 disk
                    serves as /bin/hello)
r1.netcat-1.0.0.akp r1/netcat 1.0.0 → /usr/bin/netcat = the REAL stripped
                    gcc socket client (the P1-1 citizen, 8,576 B)
```

P1-2 made the payloads REAL programs: the upgrade round now installs a
genuine loadable image (byte-exact AND parsed by the loader's own
`build_exec_plan` gate), and a fourth round installs the netcat client
— a third-party static binary delivered through the signed path. The
1.0.0 payload stays a 12-B string: different bytes AND sizes is what
separates a real upgrade from the old structural no-op.

ONE caller blob (`examples/ring3-pkg-caller/`) drives the whole
lifecycle: the kernel writes a command selector into byte 0 of the
blob's data page before each launch (0 = install, 1 = upgrade,
2 = remove, 3 = install the netcat package); the blob reads it, builds
the strings and the argv table at `0x40403080 + sel*0x20`, and
execve's (internal nr 19). The install round's argv PINS the version
(`r1/hello@1.0.0`): a bare name resolves newest-first, which would
install 1.1.0 directly and leave the upgrade round nothing to move.

The kmain lane (kernel-x86_64/src/kmain.rs, the K22/K23/P1-2 section)
runs FOUR rounds — spawn → execve → dual drain → verify → destroy —
each verified through a fresh root probe (id 72, never across a
drain):

- **install**: exit 0, `/usr/bin/pkg-hello` == the 12-B 1.0.0
  payload, `/pkg/db/r1.hello` + `/pkg/db/state` written;
- **upgrade**: exit 0, the payload == the REAL stripped gcc ELF,
  byte-exact AND parsed by `build_exec_plan` (the record moved too —
  a real MOVE, not the old no-op);
- **remove**: exit 0, stat `/usr/bin/pkg-hello` = ENOENT, the db
  record gone, no `r1/hello` in a still-valid count-0 ASTT state;
- **install netcat (P1-2)**: exit 0 on the warm, clean tree,
  `/usr/bin/netcat` == the stripped socket client byte-exact, the
  plan gate parses it, `/pkg/db/r1.netcat` written — a signed
  package delivered a genuine third-party program.

The host mirror of the lane is `tests/pkg_lane_cli.rs`
(`cargo test -p aegis-os --test pkg_lane_cli`): the REAL `run_cli`
over the REAL fixture bytes through the kernel's syscall surface —
install, upgrade (plus the up-to-date "nothing to do" answer on the
second run), remove, and a fresh install after the remove.


## K22 — the ring-3 image: built, embedded, and installing inside the VM

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

**The image is IN the kernel now** (the second-leaf round): the
boot stub maps TWO 2 MiB huge pages (PD_hh[0] @ PA 2 MiB, PD_hh[1] @
PA 4 MiB — PA 2..6 MiB), the linker ASSERTs moved to 0x600000, and
`arch::image_map` fills TWO 4 KiB page tables (the F15 W^X rebuild
covers both leaves). The stripped image (119,424 B) rides in
`.rodata`; the registry's third entry is
`service_entry("/bin/pkg", EXEC_PKG_ELF)`.

**The stack is 8 MiB, and that is the design, not a bug.** The first
lane built a 256 KiB stack on a static measure of 57.6 KiB — the
measure was wrong: rustc emits large frames as a probe loop
(`mov %rsp,%r11; sub $frame,%r11`, then 4 KiB steps), and the tool
read the loop's `sub $0x1000` as the frame. The fixed tool
(`scripts/pkg-stack-depth.py`) measures the REAL chain: 7,589,376 B
(run_cli 2.2 MiB + do_solve_and_install 3.8 MiB + load_repos 1.3 MiB
+ ...). `pkg/BUILD.md`'s own "stack ≥ 2 MiB (no_alloc)" was the
number all along. SERVICE.stack_pages = 2048; the PM quota 2112; the
boot lane's caller profile (`pkg_caller_profile`) carries the same
grant — the exec's quota pre-check runs against the CALLER's live
allowance.

**Two found-live adapter bugs the VM exposed** (both now fixed and
documented at their sites): `mkdir` passed mode 0 as the second
syscall word (the kernel takes the mode from a2 — the manager's own
dirs were created 0o000 and the transaction died of EACCES inside
its own staging tree); and `pkg_main` handed `run_cli` the full argv
INCLUDING argv[0], so `/bin/pkg install r1/hello` answered "unknown
command" on its own name.

**SYS_RENAME is 36, not 35.** The entry's internal-mode hybrid
(`linux_to_core`) maps Linux nr 35 — nanosleep(2), which the
ADR-0023 sleeper blobs legitimately call — onto SYS_NANOSLEEP, so an
internal-ABI domain's rename syscall at 35 was ALWAYS translated
into a masked nanosleep: the first in-VM commit answered EPERM
dressed as EACCES. The internal id moved to 36 (35 was unreachable,
so nothing working ever used it); the Linux whitelist's rename(82) /
renameat(264) rows follow the const.

**The in-VM lane** (kmain's `[PKG]` step, asserted by
`boot.sh --verify`): a root supervisor (uid 0, gid 100 — the
manager's group) provisions `/r1` (the pkg-mkrepo fixture: index +
package, root-owned 0644) and `/pkg` 0770 root:100 with
`/pkg/trust` + `/pkg/repos/r1.repo` root-owned 0644 (the manager
reads its anchors, never rewrites them); the `ring3-pkg-caller`
blob execve's `/bin/pkg` with ["/bin/pkg", "install", "r1/hello"]
(internal nr 19); the image runs under its declared 9-syscall mask,
resolves against the Ed25519-verified index, stages, commits
(`/usr/bin/pkg-hello` = "hello world\n" byte-exact + the record +
the state), and exit(0)s; the kernel verifies the tree through a
fresh root probe. The host proofs: `tests/pkg_lane_provision.rs`
(the DAC walk as the manager's exact credentials) and
`tests/pkg_lane_cli.rs` (the REAL `run_cli` over the REAL kernel
through the REAL fixture bytes).
