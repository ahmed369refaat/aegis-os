# ABI Version

**Current: `v0.4 (internal, full surface)`** — the ring-3 entry's
internal surface is now **complete and test-pinned**: every syscall
the profiles carry has a documented register contract, an errno map
(`kernel-x86_64/src/sysabi.rs`, host-tested variant by variant), and
a lane proof where execution exists. v0.3 documented only the file
family; v0.4 documents everything the blobs speak, including the
ADR-0029 pipe pair — and records every collision with Linux's x86_64
numbering in one table, so the Phase 5 renumbering to `v1`
(ADR-0003) starts from the truth instead of rediscovering it.

**Planned: `v1 (Linux-compatible)`** — lands with Stage 5 per
[ADR-0003](adr/0003-linux-compatible-syscall-abi.md): Linux x86_64
syscall numbers/registers/errno at the entry, translation to internal
ops before the policy gate. aarch64 gets its own Linux number table.
The v0.x surface already carries Linux's errno numbering so the v1
translation keeps meanings, not just numbers.

## v0.4 — the ring-3 entry surface (complete)

Entry: `SYSCALL`/`SYSRET`, nr in RAX, args in RDI, RSI, RDX, R10, R8,
R9 in order (RCX/R11 are destroyed by the instruction — that is why
arg4 rides R10 in general; every call below uses at most RDX). Return: RAX = result, or
**`-errno`** (Linux x86_64 errno numbering — the full `SysError →
errno` table is `sysabi::errno_of`, host-tested variant by variant).

### The file family (Round J; nr 12 since ADR-0029 creates a channel endpoint)

| nr | call | registers | RAX on success |
|----|------|-----------|----------------|
| 0 | read(fd, buf, len) | RDI=fd, RSI=buf VA, RDX=len (≤ 256) | byte count (short reads, 0 at EOF) |
| 1 | write(fd, buf, len) | RDI=fd, RSI=buf VA, RDX=len (≤ 256) | byte count |
| 2 | open(path, flags, mode) | RDI=path VA (NUL-terminated, ≤ 128), RSI=flags, RDX=mode (0o777 honored) | fd |
| 3 | close(fd) | RDI=fd | 0 |
| 12 | pipe() | — | `(write_fd << 8) \| read_fd` (the two fds address a byte-channel ENDPOINT) |
| 13 | dup2(fd, new_fd) | RDI=fd, RSI=new_fd | new_fd |
| 63 | exit(code) | RDI=code | never returns |

open flags: `O_READ=0x1, O_WRITE=0x2, O_CREAT=0x4, O_TRUNC=0x8` —
unknown bits, and O_TRUNC without O_WRITE, refuse with `-EINVAL`
(`sysabi::open_flags`, host-tested). mode is masked to 0o777.

### The time family (ADR-0023; Linux numbers translate at the entry)

| nr (internal) | call | registers | RAX | Linux nr |
|----|------|-----------|-----|----------|
| 21 | nanosleep(req) | RDI=timespec VA | 0 on wake | 35 |
| 22 | sched_yield() | — | 0 | 24 |
| 23 | clock_gettime(clk, ts) | RDI=clk (0/1), RSI=timespec VA | 0 | 228 |

### Signals (ADR-0023 D8)

| nr (internal) | call | registers | RAX | Linux nr |
|----|------|-----------|-----|----------|
| 25 | rt_sigaction(sig, handler, restorer) | RDI=sig, RSI=handler VA, RDX=restorer VA | 0 | 13 |
| 24 | rt_sigreturn() | — (frame at RSP) | 0 | 15 |
| 14 | kill(pid, sig) | RDI=pid, RSI=sig | 0 | 62 |

`rt_sigreturn` is entry machinery: handled before the policy gate (the
authority was exercised at sigaction/delivery time); every frame field
is validated against the kernel's delivery record. Note kill's Linux
nr 62 and fork's 57 pass through `linux_to_core` unchanged — they
already collide with nothing internal.

### Memory and processes (ADR-0024/0022)

| nr (internal) | call | registers | RAX | Linux nr |
|----|------|-----------|-----|----------|
| 4 | mmap(addr, len, prot) | RDI=addr (0 = pick), RSI=len, RDX=prot (R=1/W=2/X=4) | base VA |
| 5 | munmap(addr, len) | RDI=addr, RSI=len (whole-region) | 0 | 11 |
| 18 | fork() | — | child pid (child sees 0) | 57 |
| 20 | wait4(pid, …) | (host-mode surface; the ABI arm is Phase 5) | — | 61 |

### The IPC family (ADR-0025/0026/0027/0029)

| nr (internal) | call | registers | RAX | Linux nr (collision) |
|----|------|-----------|-----|----------|
| 7 | ipc_send(channel, len) | RDI=endpoint, RSI=len (≤ 64) | free-slot budget | 7 = poll(2) |
| 8 | ipc_recv(channel) | RDI=endpoint | message len | 8 = lseek(2) |
| 26 | ipc_call(channel, len) | RDI=endpoint, RSI=len | the reply len (blocks) | 26 = msync(2) |
| 27 | ipc_recv_wait(channel) | RDI=endpoint | len or avail (blocks) | 27 = mincore(2) |
| 28 | ipc_reply(channel, len) | RDI=endpoint, RSI=len | waiters woken | 28 = madvise(2) |
| 29 | ipc_grant_frames(dst, va, len) | RDI=dst, RSI=va, RDX=len (pages) | VA in dst | 29 = shmget(2) |
| 30 | pipe_read(channel, buf, len) | RDI=endpoint, RSI=buf VA, RDX=len (≤ 256) | byte count (0 = EOF) | 30 = shmat(2) |
| 31 | pipe_write(channel, buf, len) | RDI=endpoint, RSI=buf VA, RDX=len (≤ 256) | byte count (short) | 31 = shmctl(2) |

ADR-0029 pipe semantics at 30/31: short write at the ring's free
space, `-EAGAIN` full, `-EPIPE` after the read end closes; short
read, `0` at EOF; `recv_wait` (27) on a channel answers the waiting
byte count on the fast path or parks until a write's
wake-without-consume rendezvous. Message ops on a channel and pipe
ops on a message endpoint refuse `-EINVAL` (the type discipline).

### The collision ledger (internal → Linux x86_64)

Internal numbers that mean something ELSE in Linux — the reason the
blobs call internal nrs directly and `linux_to_core` translates the
other way. v1 resolves this table by renumbering the internals:

| internal nr | internal meaning | Linux meaning |
|----|------|------|
| 4 | mmap | stat(2) |
| 5 | munmap | fstat(2) |
| 7 | ipc_send | poll(2) |
| 8 | ipc_recv | lseek(2) |
| 12 | pipe | brk(2) |
| 13 | dup2 | rt_sigaction(2) |
| 14 | kill | rt_sigprocmask(2) |
| 15 | chroot | rt_sigreturn(2) |
| 18 | fork | (Linux fork is 57 — no clash) |
| 20 | wait4 | (Linux wait4 is 61 — no clash) |
| 21 | nanosleep | access(2) (Linux nanosleep is 35) |
| 22 | sched_yield | pipe(2) (Linux sched_yield is 24) |
| 24 | rt_sigreturn | sched_yield(2) (Linux rt_sigreturn is 15) |
| 25 | rt_sigaction | mremap(2) (Linux rt_sigaction is 13) |
| 26–28 | ipc_call/recv_wait/reply | msync/mincore/madvise(2) |
| 29 | ipc_grant_frames | shmget(2) |
| 30/31 | pipe_read/write | shmat/shmctl(2) |

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
bytes or `-ENAMETOOLONG`). `read`/`pipe_read` fill a kernel buffer
once (no double-fetch) and copy out; `write`/`pipe_write` copy in
once.

## Rules

- Any change to syscall numbers, argument/return conventions, structure
  layouts crossing the user boundary, or errno values **must** bump the
  version here and be called out in the PR + CHANGELOG.
- A version bump in the same major version is additive; removing or
  renumbering an exposed entry is a major bump.
- The full surface is documented in `docs/ABI.md` (created in Stage 5).

## History

- **v0.4 (ADR-0029, round Q):** the FULL internal surface — time,
  signals, memory/processes, the IPC family, and the pipe pair at
  30/31 — plus the collision ledger above; pipe() at 12 now creates a
  byte-channel endpoint (fds carry the endpoint id).
- **v0.3 (Round J):** the file family (OPEN/READ/WRITE/CLOSE/PIPE/DUP)
  executes on the live lib kernel; the register table, errno map, pipe
  packing, and open-flag decoding are specified and host-pinned
  (`sysabi.rs`); the stdio triplet (0/1/2) is reserved at spawn.
- **v0.2 (PR-1.4):** SYS_WRITE (console fd 1) + SYS_EXIT, the
  six-register entry, `-errno` returns.
- **v0.1:** kernel-resident only, no ring-3 entry.
