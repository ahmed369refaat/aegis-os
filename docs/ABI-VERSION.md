# ABI Version

**Current: `v0.3 (internal)`** — there is no stable userspace ABI yet,
but the ring-3 entry's internal surface is now **specified and
test-pinned** (Round J): the file family's register marshaling lives in
`kernel-x86_64/src/sysabi.rs`, every table in it is host-tested, and
the blob ABI contract below is what `examples/ring3-*` compile against.

**Planned: `v1 (Linux-compatible)`** — lands with Stage 5 per
[ADR-0003](adr/0003-linux-compatible-syscall-abi.md): Linux x86_64
syscall numbers/registers/errno at the entry, translation to internal
ops before the policy gate. aarch64 gets its own Linux number table.
The v0.x surface below already carries Linux's errno numbering so the
v1 translation keeps meanings, not just numbers.

## v0.3 — the ring-3 entry surface (Round J, additive)

Entry: `SYSCALL`/`SYSRET`, nr in RAX, args in RDI, RSI, RDX, R10, R8,
R9 in order (RCX/R11 are destroyed by the instruction — that is why
arg4 rides R10 in general; every call below uses at most RDX). Return: RAX = result, or
**`-errno`** (Linux x86_64 errno numbering — the full `SysError →
errno` table is `sysabi::errno_of`, host-tested variant by variant).

| nr | call | registers | RAX on success |
|----|------|-----------|----------------|
| 0 | read(fd, buf, len) | RDI=fd, RSI=buf VA, RDX=len (≤ 256) | byte count (short reads, 0 at EOF) |
| 1 | write(fd, buf, len) | RDI=fd, RSI=buf VA, RDX=len (≤ 256) | byte count |
| 2 | open(path, flags, mode) | RDI=path VA (NUL-terminated, ≤ 128), RSI=flags, RDX=mode (0o777 honored) | fd |
| 3 | close(fd) | RDI=fd | 0 |
| 12 | pipe() | — | `(write_fd << 8) \| read_fd` |
| 13 | dup2(fd, new_fd) | RDI=fd, RSI=new_fd | new_fd |
| 63 | exit(code) | RDI=code | never returns |

open flags: `O_READ=0x1, O_WRITE=0x2, O_CREAT=0x4, O_TRUNC=0x8` —
unknown bits, and O_TRUNC without O_WRITE, refuse with `-EINVAL`
(`sysabi::open_flags`, host-tested). mode is masked to 0o777.

**The console device alias:** fd 1 is the runtime's console exactly
while the lib's fd table holds the slot `Reserved` (the spawn-time
stdio triplet 0/1/2 — `Kernel::reserve_stdio`). The domain's own
allocations begin at fd 3, Unix-style, so the alias and the fd table
can never collide. A domain that closes fd 1 or replaces it gets
exactly what it asked for.

**User pointers:** every buffer and the open path are validated
page-by-page through the calling domain's own page tables (present, U,
below the split) before any byte moves; copies are byte-exact under
the single blessed SMAP window. The open path walks page-check-as-you-
go (a short string before an absent page succeeds — NUL within 128
bytes or `-ENAMETOOLONG`). `read` fills a kernel buffer once (no
double-fetch) and copies out; `write` copies in once.

## Rules

- Any change to syscall numbers, argument/return conventions, structure
  layouts crossing the user boundary, or errno values **must** bump the
  version here and be called out in the PR + CHANGELOG.
- A version bump in the same major version is additive; removing or
  renumbering an exposed entry is a major bump.
- The full surface is documented in `docs/ABI.md` (created in Stage 5).

## History

- **v0.3 (Round J):** the file family (OPEN/READ/WRITE/CLOSE/PIPE/DUP)
  executes on the live lib kernel; the register table, errno map, pipe
  packing, and open-flag decoding are specified and host-pinned
  (`sysabi.rs`); the stdio triplet (0/1/2) is reserved at spawn.
- **v0.2 (PR-1.4):** SYS_WRITE (console fd 1) + SYS_EXIT, the
  six-register entry, `-errno` returns.
- **v0.1:** kernel-resident only, no ring-3 entry.
