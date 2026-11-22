# ABI Version

**Current: `v1 (Linux-compatible entry)`** — a domain can now speak
**Linux x86_64 numbers at the entry** (ADR-0003): a per-domain ABI
flag (`Abi::Linux`, supervisor-declared at spawn, inherited across
fork) switches the entry to a **whitelist** translation table that
runs BEFORE the bounds check and the policy gate. The internal ids
stay the policy space — profiles and masks never see Linux numbers.
v0.4's internal surface (below) is unchanged and remains what the
round-J blobs speak (`Abi::Internal`, the default).

## v1 — the Linux-compatible entry (ADR-0003, round S)

A **per-domain ABI flag** (`Abi::Internal` — the default, v0.4's
hybrid surface; `Abi::Linux` — the whitelist) picks the number
translation at the entry. The flag is numbering ONLY: the policy gate
runs on internal ids after translation either way, so a Linux-mode
domain's rights are exactly its profile's internal ops — translation
changes which NUMBERS reach the gate, never which OPS it allows.

The v1 table is a **WHITELIST, not a pass-through** — the round's
found-live discovery: Linux nrs below 64 collide with internal ops
(Linux 63 is `uname`, internal 63 is EXIT — a pass-through would make
a Linux binary's `uname()` call exit the process). Unmapped nrs,
including every sub-64 collision, answer `-ENOSYS` audited on the
live domain (ADR-0003's refuse rule).

| Linux nr | internal op | notes |
|----|------|-------|
| 0 read / 1 write / 3 close | 0 / 1 / 3 | identical shapes |
| 2 open | 2 | **the O_* word translates at the arm** (slice 2): access mode (bits 0..1: RDONLY=0, WRONLY=1, RDWR=2; 3 is invalid) → the internal O_READ/O_WRITE bits, O_CREAT (0x40) and O_TRUNC (0x200) ride along; every other bit — O_EXCL (0x80), O_APPEND (0x400), O_NONBLOCK (0x800), O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, ... — **refuses -EINVAL**, never silently dropped (a bit whose semantics the internal VFS cannot honor is not a courtesy to approximate; O_EXCL's "only create if absent" would let a caller open an existing file). O_TRUNC without write then dies in the internal decoder with the same -EINVAL a native caller gets. mode is masked to 0o777 as v0.4 |
| 9 mmap | 4 | flags (arg4) must be exactly `MAP_PRIVATE\|MAP_ANONYMOUS` (0x22); MAP_SHARED / file-backed / MAP_FIXED refuse `-EINVAL` |
| 11 munmap | 5 | whole-region, as v0.4 |
| 13 rt_sigaction | 25 | |
| 15 rt_sigreturn | 24 | entry machinery, pre-gate |
| 22 pipe | 12 | **rax = read fd, rdx = write fd** (the x86_64 convention — NOT v0.4's packed word) |
| 24 sched_yield | 21 | |
| 33 dup2 | 13 | |
| 35 nanosleep | 20 | |
| 57 fork | 18 | child speaks the parent's ABI (inherited) |
| 60 exit / 231 exit_group | 63 | the alias |
| 61 wait4 | 20 | **blocks via the rip-2 re-execute park** (slice 3): not-ready parks with rip ON the 2-byte `syscall` instruction and rax = the ORIGINAL nr read from the frame's RAX slot — resume re-runs the very arm (the park machinery stays ABI-blind; found live: parking with the TRANSLATED nr made the re-executed entry answer -ENOSYS for a number the whitelist never maps). The child's completion wakes the parent through the waiter registry (`set_runnable` — the same block/wake primitive nanosleep and the IPC rendezvous use). WNOHANG (0x1) honored: nothing-ready answers 0; every other option bit refuses -EINVAL (WUNTRACED/WCONTINUED report job-control states we do not have — the slice-2 open discipline). rusage is accepted and ignored (no accounting yet — documented, not faked). pid: >0 = that child, -1/0 = any, other negatives -ECHILD; no/not-a child -ECHILD. **The reaped child's completed-mailbox entry is consumed BY the arm** — its teardown runs there (frames via `free_frames_of`, then `exit_process` records the zombie `wait_process` reaps; `destroy_domain` is never used: the supervisor removal erases the meta the zombie needs — found live in the slice-3 hunt), so the spawner's drain never sees it. **The wstatus target must be writable in the caller's OWN tables (P+U+W)**: a fork-CoW-shared page is read-only in both tables and the kernel's direct write answers -EFAULT loudly (ADR-0007: a CPL0 fault is a kernel bug — Linux services the CoW for put_user; we refuse — a careful program passes a private page, as the blob does with a post-fork mmap) |
| 62 kill | 14 | |
| 228 clock_gettime | 23 | |

**Deliberately NOT mapped (slice 3):** `execve` (59) — the internal
`SYS_EXEC` id exists in the policy space but the kernel has no ELF
loading machinery yet; the translation lands with the exec slice, not
as a stub that answers wrong. `dup` (32), `pipe2` (293): no ABI arm
yet. Each answers `-ENOSYS` today. (`open` — nr 2 — lived on this edge
until slice 2: the encoding difference is handled by translating at
the SYS_OPEN arm; `wait4` — nr 61 — until slice 3: the kernel gained
the SYS_WAIT arm the ADR-0022 D7 core was waiting for, with the
rip-2 re-execute park for its blocking path.)

Lane proof: blob mode 13 (`[M3] linux-abi:` marker) — one domain
speaking ONLY Linux nrs: console write, the pipe split, the byte
round-trip, EOF after the write end closes (D7 via Linux nrs), mmap
store/load + the MAP_SHARED refusal, **open(2) with O_RDWR|O_CREAT on
`/pub/s.txt` (the world-writable subtree — the domain's uid is
1000+id), write/close, an O_RDONLY reopen with read-back through an
independent cursor, and the O_EXCL (0xC2) and O_APPEND (0x442)
-EINVAL refusals** (slice 2), the uname(63) and getpid(39)
`-ENOSYS` probes, fork + the CoW child store, **wait4 (61) — slice 3:
the WNOHANG probe (the fork-parked child is not ready -> exactly 0),
the BLOCKING wait on a private scratch page (the syscall parks
rip-2; the dispatcher runs the child, whose exit(7) wakes the parent
through the waiter registry; the re-executed wait reaps: pid == the
fork's child, wstatus == 7 << 8), then -ECHILD after the reap** — the
child exits `exit_group(7)` (a nonzero code on purpose: the wstatus
word is the proof the status crossed the boundary), the parent
`exit_group(0)`. Red: pre-change, nr 22 hit internal SCHED_YIELD and
the boot hung with zero clean exits. Red (slice 2): nr 2 answered
-ENOSYS and the run exited 213 — which the harness swallowed (the
never-parked launch exit sat in USER_RUN; fixed by taking it before
the mailbox drain), so the first red showed as "saw fewer exits" (and
the fix's own first landing went to the IPC section's twin harness —
found live in slice 3 and moved to its true home). Red (slice 3): nr
61 answered -ENOSYS and the run exited 222, read cleanly through the
relocated try_take.

## v0.4 — the ring-3 entry surface (complete, unchanged)

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

- **v1 (ADR-0003, round S):** the Linux-compatible entry — the
  per-domain ABI flag, the whitelist table, pipe's rax/rdx split,
  exit_group's alias, mmap's flags rule, unmapped→-ENOSYS. The
  internal surface below is frozen as v0.4 and remains the default
  (`Abi::Internal`).
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
