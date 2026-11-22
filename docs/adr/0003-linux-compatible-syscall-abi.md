# ADR-0003: Linux-compatible syscall ABI

- **Status:** Accepted (implemented slice 1, round S)
- **Stage:** 5 (POSIX ABI)
- **Date:** 2026-11-19

## Context

The Stage-5 gate is "≥ 80% of the musl libc test suite + busybox `ls,
cat, echo, ps, kill, sleep` work". Both are static Linux binaries: they
issue syscalls by **Linux x86_64 number** (`rax` = nr, args in
`rdi, rsi, rdx, r10, r8, r9`) and read Linux `errno` values. The policy
core's internal syscall ids were designed for clarity, not Linux
compatibility — they partially collide (READ=0, WRITE=1, OPEN=2, CLOSE=3
match Linux) and partially diverge (MMAP=4 vs Linux's 9; SPAWN=6 has no
Linux equivalent; EXIT=63 vs Linux's 60/231). Renumbering the core would
churn 219 tests and the policy layer for no policy gain; ignoring Linux
numbers forfeits every prebuilt userspace binary and both test suites.

## Decision

Keep the policy core's internal ids as the **internal** operation space.
Introduce a Linux-ABI **translation layer** at the syscall entry point
(`kernel/src/sys/posix/dispatch.rs`):

- The Ring-3 entry (SYSCALL/SYSRET) reads the Linux number from `rax`
  and maps it through a compile-time table `LINUX_NR -> InternalOp`
  (read=0, write=1, open=2, … plus the Stage-5 additions: fork=57,
  execve=59, exit=60, wait4=61, kill=62, sigaction=41, mmap=9,
  mprotect=10, brk=12, pipe2=293, …).
- Unmapped numbers return `-ENOSYS` (and are audited, feeding the
  monitor's out-of-profile signal).
- The policy gate (`Kernel::dispatch`) runs **after** translation, before
  execution — the gate stays the single choke point; internal ids keep
  their meaning; profiles are defined against internal ops.
- Errno mapping: internal error enums translate to Linux errno values at
  the boundary; errno semantics documented in `docs/ABI.md`.
- The internal debug surface (e.g. the Stage-1 `SYS_DEBUG_WRITE`) is
  reachable only through a non-Linux-numbered debug range (512+) that
  production profiles never include.

`docs/ABI-VERSION.md` is bumped to v1 when this lands, and every later
change to numbers, structures, or errno behavior requires a bump there.

## Consequences

- Unmodified static musl/busybox binaries run if their syscalls are
  implemented — the whole Stage-5/8 gate becomes meaningful.
- The gate's audit records carry the internal op; the audit trail adds
  the originating Linux number for traceability.
- New syscalls land in both layers with a test asserting the mapping
  exists and is denied outside profiles.
- aarch64 (Track B onward) uses its own Linux number table at its entry
  — translation is per-arch, policy is shared.

## Implementation notes (round S — slice 1 live)

- **The per-domain ABI flag** (`aegis_os::syscall::Abi`): the
  collision ledger's resolution. Nrs below 64 are claimed by BOTH
  surfaces (internal 13 = dup2, Linux 13 = rt_sigaction), so the
  entry cannot know which table applies without being told. The flag
  is supervisor-declared (`Kernel::set_domain_abi` — no syscall
  surface: it changes numbering, never policy) and fork-inherited.
- **The table is a whitelist, not a pass-through** — found while
  designing the edge: Linux 63 is `uname`, internal 63 is EXIT. A
  pass-through would exit a Linux binary on `uname()`. Every unmapped
  nr — including all sub-64 collisions — answers `-ENOSYS`, audited
  on the live domain exactly like an unnormalizable nr.
- **Shape differences honored at the arm, not the table**: pipe(2)
  answers rax = read fd / rdx = write fd (the frame's RDX slot),
  exit_group(231) aliases exit, mmap demands
  MAP_PRIVATE|MAP_ANONYMOUS. open(2) stays unmapped until its O_*
  decoding round — a mistranslated flag bit is worse than -ENOSYS.
- **Proof**: blob mode 13 + the `[M3] linux-abi:` marker, red→green
  on all three lanes (pre-change: nr 22 hit internal SCHED_YIELD,
  zero clean exits). The gate's mask never sees a Linux number.

## Alternatives considered

- Renumber the core to Linux ids — a 219-test churn that buys nothing
  for policy clarity and forever couples policy names to a foreign ABI.
- A fully original ABI + ported libc — maximal churn, zero ecosystem,
  and both test gates become impossible.
