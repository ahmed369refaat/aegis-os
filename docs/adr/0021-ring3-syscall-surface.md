# ADR-0021: The ring-3 syscall surface — the marshaling seam and the gate/execute split

- **Status:** Accepted (round J: the file family landed live — OPEN/READ/WRITE/CLOSE/PIPE/DUP proven by the eighth boot run)
- **Stage:** M2 → the usable-core track (GAP-ANALYSIS §2.1's #1 gap)
- **Date:** 2026-11-21

## Context

The ring-3 entry (PR-1.4) speaks a six-register convention but
executed only SYS_WRITE (console) and SYS_EXIT — every other masked
syscall answered `-ENOSYS` "not implemented yet". The policy core's
executor (`Kernel::syscall`) already ran the full Linux-like state
(VFS, fd tables, pipes, signals, sockets) on the host, but nothing
connected the two: ring-3 domains could not open a file, read a pipe,
or dup a descriptor. GAP-ANALYSIS §2.1 said it plainly: until the
profile-allowed surface reaches the same executor the lib tests
exercise, "multi-domain system" means "kernel demo with user-mode
guest actors".

Two structural questions had to be answered before any syscall could
cross:

1. **Where does the gate run?** The ring-3 path already called
   `Kernel::dispatch` (the gate) on the live domain — that is where
   the monitor's used-bits and denial counters must land. Calling the
   lib's `Kernel::syscall` from there would run the gate a second
   time and double every counter.
2. **Who owns fd 1?** The console was a hard-coded `fd == 1` special
   case in the kernel dispatch, invisible to the lib's fd table — a
   Unix-shaped collision waiting for the first `pipe()` (a fresh
   domain's pipe allocates fds 0 and 1 from an empty table).

## Decision

1. **`Kernel::syscall` splits into gate + `execute`.** The existing
   `syscall` (gate, then execute) is unchanged for every lib caller;
   the new `pub fn execute` runs Phase 2 alone, under an explicit
   contract: *the caller has gated*. The ring-3 runtime runs its own
   `dispatch` (accounting lands exactly once) and only an `Allowed`
   reaches `execute`. The contract is host-tested in the negative —
   `execute` hands a parser-profile domain a real fd for a syscall
   its mask forbids — so nobody can "simplify" the runtime path back
   to double-gating without a test going red.

2. **A pure marshaling layer owns the register ABI**
   (`kernel-x86_64/src/sysabi.rs`). Flag decoding (`open_flags`:
   unknown bits and O_TRUNC-without-O_WRITE refuse `-EINVAL`), the
   complete `SysError → errno` table (every lib refusal keeps a
   distinct Linux meaning — nothing collapses into a catch-all), and
   the pipe fd-pair packing (`(write_fd << 8) | read_fd` into the
   single RAX the naked entry returns) are all host-tested without a
   boot. The table is the ABI's source of truth;
   `docs/ABI-VERSION.md` v0.3 documents the register convention.

3. **User pointers are validated once, in both directions.** WRITE
   copies in through the PR-1.4 discipline; the new
   `copy_out_bytes` + `memops::write_u8_va` mirror it byte-exactly
   for READ (validate every covering page, execute into a kernel
   buffer — the user pointer is read once and never again — then copy
   out under the blessed SMAP window). OPEN's path string walks
   `read_user_cstr`: page-check-as-you-go, so a short string before
   an absent page succeeds while a missing NUL within 128 bytes is
   `-ENAMETOOLONG`.

4. **The stdio triplet belongs to the runtime.**
   `Kernel::reserve_stdio` installs `FdTarget::Reserved` at fds
   0/1/2 at spawn, Unix-style: the domain's own allocations begin at
   fd 3, and the console device alias (fd 1) can never collide with a
   real descriptor. Reserved slots refuse I/O through the policy core
   (`SysError::Reserved` → `-EIO`) but close and dup like plain
   entries. The kernel's console path fires only while the lib
   actually holds fd 1 Reserved — a domain that closes or replaces
   fd 1 gets exactly what it asked for.

## Consequences

- The eighth boot run (`examples/ring3-files`) proves the whole seam
  from CPL=3 with in-blob verification: pipe round-trip, a dup
  keeping a pipe end alive past its original's close, file
  create/write/read-back through a duplicate's independent cursor,
  the lowest-free fd recycle (a freed slot is handed back out), and
  the `-EBADF`/`-ENOENT` refusals.
- The remaining surface (MMAP/MUNMAP/SPAWN/IPC/NET/KILL/CHROOT/
  MKDIR/UNLINK) follows the same pattern: a `sysabi` table entry, an
  `execute` arm, a blob. MMAP is the next deep one — its executor
  must also drive the domain's page tables (the lib policy decision
  becoming hardware, PR-1.3's discipline).
- Round J's two entry-path fixes are load-bearing for everything
  above: SYSRET never restored the user RSP (the stub now parks it in
  `USER_RSP_SAVE` and reloads it — hidden since PR-1.4 because no
  blob ever touched its stack), and an outer `#[cfg(not(test))]` had
  compiled the syscall module's tests out of every host run.
- The boot stack grows 256K → 512K: the driver-stack call chain
  measured barely 1.6 KiB above the F15 guard page, and round J's
  first stack-allocated data page proved it by faulting into the
  guard (loudly, as designed).
