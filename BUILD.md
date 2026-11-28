# BUILD — the AegisOS toolchain and the userland build path (P1-2)

One `./boot.sh` builds everything: the kernel, every ring-3 image, and
the signed repo fixture. This document is the map — what each image
type is, which compiler builds it, which memory contract it links
under, and where the build refuses loudly instead of failing at boot.

## 1. The toolchain

| Tool | Version | Builds |
|---|---|---|
| `rustc` / `cargo` | 1.100.0, target `x86_64-unknown-none` | the kernel, the policy core (`aegis_os`), the Rust images (`pkg`, `tcpipd`, `/bin/sh`), the flat ring-3 blobs |
| `gcc` | 14.2 (`-ffreestanding -nostdlib`) | the C userland images (`/bin/hello`, the netcat client) |
| `ld` / `objcopy` / `strip` | binutils | the boot stub, the blob flattening, the image strips |

`source /home/z/my-project/tools/env.sh` puts the toolchain on PATH.
No C library, no startup files, no allocator anywhere in a target
build: every image is `no_std`/freestanding and owns its whole program.

## 2. The memory contracts (one gate, three shapes)

Every ring-3 image links under a *contract* the kernel's loader checks
before a frame is spent (`mm/user_layout.rs`; `check-pkg-image.py` /
`check-tcpip-image.py` pin them at build time):

| Contract | Cage | Stack | Who |
|---|---|---|---|
| `CANONICAL` | 7 pages [0x400000,0x407000) | 1 page | flat blobs, the exec target, `/bin/hello`, the netcat client |
| `SERVICE` | 128 pages | 2048 pages | the package manager (`pkg/`) — the no_alloc recursion budget |
| `NETSVC` | 128 pages | 96 pages | the tcpip service (`tcpip/`) — one ~160 KiB frame + nested stack processing |

The rules every link must honor (the ten-check policy enforces them at
load; the checker scripts fail the BUILD first):

- PT_LOADs separated by one ABSENT page (`GuardGap`) — no adjacent
  regions, ever;
- `W^X`: text R+X, data R+W, rodata R — never both on one page range;
- an ELF header + program headers the loader parses (unknown segment
  types are refused);
- **memsz may exceed filesz** (the bss tail): the loader zero-fills it
  — this is also how an image keeps its FILE small (the netcat client
  rides a 12 KiB repo ceiling by putting its pinned blocks and buffers
  in the tail).

## 3. The three citizen types

### (a) A C freestanding ELF — `examples/userland-hello`, `examples/userland-netcat`

```sh
gcc -ffreestanding -nostdlib -nostartfiles -static -O2 -mgeneral-regs-only \
    -T examples/userland-netcat/netcat.ld \
    -o kernel-x86_64/blob/netcatd.bin examples/userland-netcat/netcat.c
strip --strip-all kernel-x86_64/blob/netcatd.bin
```

- `-mgeneral-regs-only` is NOT optional: this kernel's ring 3 has no
  FPU/SSE state, and `-O2` zeroes structs with `pxor/movaps` — the
  image dies on `#UD` at its first vector instruction (found live,
  `rip=0x4001b0`). `boot.sh` greps the disassembly for `%xmm/%st(` and
  fails the build on a hit.
- The linker script pins the data page's blocks (the kernel patches a
  config block before launch, the program writes a report block). Two
  lessons live in `netcat.ld`'s comments: section-internal `.`
  assignments are offsets from the section start, and the pinned
  blocks + bss belong in the NOLOAD tail.
- The stripped ELF is the CANONICAL-cage citizen: spawnable by the
  kernel (`spawn_user_elf`), execve-able from the registry, and — since
  P1-2 — installable from a signed package (below).

### (b) A Rust ELF with a custom linker script — `examples/ring3-sh`, the exec target

```sh
rustc --edition 2021 --crate-type=bin -C panic=abort -C opt-level=z \
      -C codegen-units=1 -C linker=ld -C link-arg=-T<...>/image.ld \
      -C link-arg=--gc-sections -C relocation-model=static \
      --target x86_64-unknown-none src/lib.rs -o blob/image.bin
```

One rustc invocation, no cargo: the shell (`/bin/sh`) is the exemplar.
`--gc-sections` keeps the image flat; the `.ld` carries the contract.

### (c) A Rust lib + bin composition — `pkg/`, `tcpip/`

The shape for real programs: a workspace crate whose **lib** holds all
logic (host-compiled, host-tested, clippy-gated by the workspace lanes)
and whose **bin** is only a `_start`/`panic_handler` shim; the build
script emits the link recipe for the target only:

```toml
# Cargo.toml — a workspace member
[dependencies]
aegis-os = { path = ".." }        # the policy core rlib
[[bin]]
name = "tcpipd"
```

```sh
cargo build -p aegis-tcpip --bin tcpipd --profile pkg-image \
      --target x86_64-unknown-none
python3 scripts/check-tcpip-image.py target/.../tcpipd   # the contract gate
strip --strip-all target/.../tcpipd -o kernel-x86_64/blob/tcpipd.bin
```

`build.rs` emits `-Ttcpipd.ld -no-pie -nostdlib --gc-sections
-z max-page-size=4096` for the target and NOTHING for host builds —
tests and clippy link normally. The `pkg-image` profile (opt-level z,
one codegen unit) is the size recipe every image measures under.

**The LTO lesson (found live):** a kernel-patched config page read
through its static symbol gets constant-folded into the code — the
whole service collapsed to `exit(2)`. Read such bytes through
`read_volatile` at the pinned VA, never through the symbol.

## 4. The flat ring-3 blobs (the demo lane)

`examples/ring3-*` build as `--emit=obj` and `objcopy -O binary
-j .text.ring3` into `blob/*.bin` — position-dependent code the kernel
maps at the CANONICAL code base. `scripts/check-blob-deltas.py` pins
the two hand-pinned handler landings so a layout shift fails the
build, and `scripts/check-no-binaries.sh` keeps the blob set the only
tracked binaries in the tree.

## 5. The signed package path (P1-2: real binaries)

`pkg/src/bin/pkg-mkrepo.rs` builds the signed local repo the in-VM
manager installs from — and since P1-2 the packages carry REAL
programs, not fixture strings:

```text
r1.hello-1.0.0.akp   /usr/bin/pkg-hello = "hello world\n" (12 B)
r1.hello-1.1.0.akp   /usr/bin/pkg-hello = the REAL stripped gcc hello ELF
                     (the SAME bytes the ext2 disk serves as /bin/hello)
r1.netcat-1.0.0.akp  /usr/bin/netcat    = the REAL stripped socket client
```

Two bounds rule the path, both measured, not round: **12 KiB, the
ext2 reader's direct-block ceiling** (the fixture files, `SLOT_MAX`),
and **10 KiB, the ramfs spill window** (`LARGE_FILE_MAX`, sized for
the largest file the repo carries plus margin — and what keeps
`Kernel<4096>` inside its 512-KiB boot-stack budget). The netcat
image fits BECAUSE its pinned blocks and buffers ride the NOLOAD tail
(§3a); a bigger program needs the ext2 indirect-block read, which is
deliberately not built yet.

The in-VM lane (kmain's `[PKG]` section, four rounds now) proves the
whole path per boot: install → upgrade-to-a-real-ELF → remove →
install-the-real-netcat, each round verified byte-exact through a
fresh root probe, the installed files additionally parsed by the
loader's own plan gate (`build_exec_plan`) — a package that delivered
bytes that are not a genuine image cannot pass. The host mirror is
`tests/pkg_lane_cli.rs`.

## 6. The build order (why boot.sh's steps are numbered)

```text
[0/4]  the flat blobs + the delta gate
[0b/4] the exec target (rustc + ld)
[0c/4] /bin/hello (gcc, STRIPPED — the disk and the package carry the same bytes)
[0c/4] /bin/sh (rustc)
[0d/4] /bin/pkg (cargo, pkg-image profile + the contract check)
[0e/4] the netcat client (gcc, STRIPPED — the package payload)
[0f/4] the tcpip service (cargo, the NETSVC contract check)
[0g/4] the signed repo fixture (pkg-mkrepo — LAST: it embeds [0c]/[0e])
[1..3] the kernel (release), objcopy, the multiboot stub
[4/4]  QEMU + the verify greps
```

Every gate in `scripts/gates.sh` runs the same builds first, so a
fresh checkout is green without ceremony.
