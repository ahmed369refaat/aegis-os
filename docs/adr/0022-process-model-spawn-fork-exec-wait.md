# ADR-0022: The process model — spawn, fork, exec, wait over the domain table

- **Status:** Accepted (Phase 1 of M3 "boot to a shell"; the process table, lifecycle, attenuation and conservation tests land with this round)
- **Stage:** M3 → the process track (the mission's Phase 1)
- **Date:** 2026-11-21

## Context

The system boots, runs ring-3 blobs, opens files and pipes — but it
cannot run a *program*. There is no fork, no exec, no wait, no PID,
no exit status, no parent/child anywhere in the core: `Domain` is a
flat, parentless identity created and destroyed by supervisor calls
(`create_domain_with` / `destroy_domain`), `SYS_SPAWN` (nr 6) answers
`NotImplemented`, and `SYS_EXIT` (nr 63) exists only as a mask bit
the boot kernel interprets. The scheduler, monitor, frame-owner tags,
rate buckets and IPC endpoints all key on the domain id — which is
also the only "process identifier" the system has, chosen by the
supervisor and reused freely after destroy.

Real software (a shell, coreutils, eventually musl/busybox) needs the
Unix lifecycle: a process tree with fork/exec/wait semantics, exit
statuses, orphan reparenting, and resource limits. This ADR decides
how that maps onto the domain table **without weakening the
attenuation-only security model**: every child's authority must be a
subset of its parent's at every step, and no code path may widen a
live domain.

The design constraint that shaped everything below: the policy core
is pure and host-testable (`#![forbid(unsafe_code)]`, no heap, fixed
tables). Image loading (ELF), page-table COW and preemption are
kernel-side concerns owned by later ADRs (0024, 0023); this ADR
defines the *lifecycle logic* they plug into.

## Decision

### D1 — A process IS a domain; the pid is a never-reused monotonic id

`Domain`'s id BECOMES the pid (allocated monotonically, never reused;
no separate field — every id-keyed structure keys the pid directly).
The kernel keeps a `next_pid` counter starting at 100
(ids 1..=99 stay reserved for supervisor-created static domains;
**PID 1 is init** by convention). The pid allocator NEVER reuses a
number within a boot; exhausting the counter is a typed refusal, not
a wraparound.

Why monotonic instead of slot-reuse: every wait/kill handle userspace
can hold is a pid. Reuse would create ABA — a `wait4(child)` landing
on an unrelated successor. Monotonic ids make a stale handle fail
closed *forever* (`UnknownProcess`), which is cheaper and safer than
generation-tagging every handle. The domain table itself stays a
fixed `[Option<Domain>; MAX_DOMAINS]` (slots recycle; pids do not).
All existing id-keyed structures (scheduler, monitor shadow table,
frame owner tags, buckets) keep working unchanged — they key on the
live domain's pid, and a freed slot's state is reset on destroy
(proven since round F7: "a respawned id is born clean" — now it is a
*new* id, born even cleaner).

`MAX_DOMAINS` rises 4 → 32 and `MAX_SCHED_ENTITIES` 8 → 32 (the
"scale reality check" row in the driver-stack ledger): a shell with a
pipeline needs headroom, and the fork-bomb guard needs something to
guard. The raise ships with a capacity self-test (fill all 32, refuse
the 33rd, drain, reuse). `MAX_SOCKETS` stays 4 — only the netd
profile holds NET rights; noted as a toy limit for the network track.

### D2 — The native primitive is `spawn`: explicit inheritance only

`Kernel::spawn_process(parent, profile_request, fd_map) -> pid`:

- **fd_map is the ONLY inheritance.** Each `(parent_fd, child_fd)`
  pair copies that one descriptor (pipe ends acquire a reference;
  file positions snapshot as dup does today). Fds absent from the map
  do NOT exist in the child. No ambient inheritance of any kind.
- **profile_request must be an attenuation of the parent's CURRENT
  state** — syscall surface ⊆ the parent's *live* mask (not the
  parent's original profile: a tightened parent spawns tightened
  children) and quota ≤ the parent's quota. Capability rights are
  enforced BY INTERSECTION, not by validating the request: every cap
  the child receives is `parent_cap ∩ request.base_rights` — a lying
  request still yields a subset. A mask/quota that would widen is
  REFUSED with a typed error (fail closed, never silently clamped)
  and counted as an `escalation_attempt` in the parent's monitor
  stats — the same discipline as the capability gates. A spawned
  child receives NO ambient capabilities: its table starts with only
  its own `Domain(child)` self-cap, plus attenuated copies of the
  parent's caps EXCLUDING any cap aimed at the parent itself (the
  same no-signal-up-the-tree discipline as fork; the F18 ambient
  ROOT/Device minting stays reserved to supervisor
  `create_domain`).
- The child gets `max_children` from the requested profile; its uid,
  gid, cwd and chroot root copy from the parent (a child cannot pick
  a jail escape or new credentials).

This is the security-friendly path: a spawning service states exactly
what the new program gets, and the kernel verifies it is less.

### D3 — fork() is copy-domain: the child is a clone that can only shrink

`Kernel::fork_process(parent) -> pid` exists so real software works
(busybox ash forks). The child is a copy of the parent's CURRENT
state:

- **mask**: a copy of the parent's live mask (a copy of a subset is a
  subset; a tightened parent forks tightened children).
- **capabilities**: the parent's table copied (same resources, same
  rights — ⊆ by construction), MINUS every capability aimed at the
  parent itself (a forked child cannot signal its parent —
  deliberately STRICTER than Unix same-uid rules; SIGCHLD is the
  kernel's job, not a capability), PLUS a fresh `Domain(child)`
  self-cap. The self-signal cap is STRUCTURAL — the capability analog
  of "SYS_EXIT is always reachable" — and is exempt from the
  ancestor-cover requirement; the parent gains `Domain(child) WRITE`
  best-effort so it can signal the child (a full parent table skips
  it: wait needs no capability, only kill(child) is lost).
- **fds**: ALL descriptors copied 1:1 (POSIX keeps fd numbers across
  fork), each pipe end acquiring a reference. The `cloexec` flag
  (D6) rides along untouched.
- **AddressSpace**: region list and quota copied as policy data (the
  physical COW is the page-table layer's business, ADR-0024; the core
  keeps the ledger). Pending signals are cleared (POSIX async
  cancellation of pending delivery to a copied process).
- **limits**: `max_children` copies from the parent's profile.

fork is refused when: the domain table is full, the parent's child
count is at its limit, or the pid counter is exhausted — each a typed
error, each leaving zero side effects (D8).

### D4 — execve() replaces the image and INTERSECTS the surface

`Kernel::exec_replace(pid, declared)` (called by the kernel's loader
after it validates the ELF, ADR-0025):

- The new mask is `live_mask ∩ declared_mask`. Intersection with the
  *current* mask means: a tightened/quarantined-then-reset domain
  cannot exec its way back to its profile's full surface, and a
  program's declared profile only ever narrows. There is no setuid:
  uid/gid never change across exec.
- The declared surface comes from the **exec policy table** (D5).
- `cloexec` fds close (pipe references released) — the flag lands in
  this round (D6) so the semantics exist before fcntl exposes it.
- fds, parent, pid, credentials, cwd and chroot survive exec; the
  address-space regions reset (the new image maps fresh; ADR-0024).

### D5 — Executable profiles come from an init-owned policy table; unlisted = app

`ExecPolicyTable`: a fixed array of `(path, declared_syscall_mask,
monitor_enforce: Option<bool>)`, exact-path lookup, bounded by
NAME_MAX. It is owned by init (PID 1 / uid 0) — writable only through
the supervisor API, never through a syscall a child holds. This is
the "policy table owned by init" option from the mission; a signed
manifest in the initramfs is the M4 hardening path (open item).

Unlisted binaries get the new **`app_profile()`**: the attenuated
default (file + pipe + dup + the process family, no KILL/CHROOT/
MKDIR/UNLINK/NET/IPC), 64-page quota, sensitivity 60, and — per the
mission's usability guard — **AuditOnly monitoring** for the first
release: `Domain.monitor_enforce: Option<bool>` (None = follow the
kernel-global mode) lets the policy table mark a binary Enforce
explicitly. Enforce stays opt-in per-profile until the M3 command
suite runs with zero false positives above Log.

### D6 — `cloexec` becomes real on `FdEntry`

`FdEntry` gains `cloexec: bool` (default false — every existing
constructor and test unchanged in behavior). fork copies it; exec
closes flagged fds; `spawn`'s fd_map cannot carry it (the child is
fresh, the flag starts clear). fcntl(F_SETFD) lands with the Phase-5
ABI; the flag's semantics are pinned NOW by core tests so the ABI
cannot invent them later.

### D7 — exit, zombies, wait, reparenting

- `exit_process(pid, status)` records the `ExitStatus` (code +
  reason: Normal / Killed(sig) / Fault{vector}) in `ProcMeta`, then
  performs exactly what `destroy_domain` performs today (close fds
  dup-aware releasing pipe ends, close the socket, clear the bucket,
  unregister the scheduler, reset monitor state, free the slot). The
  domain is gone; the meta stays as a **zombie** until reaped.
- Kernel-side teardown (physical frames, IOMMU revoke) is the
  CALLER's job BEFORE calling exit — the same contract
  `destroy_user` already implements (`pool.free_all_owned` first).
  The core never touches hardware state.
- Supervisor `create_domain*` entries are PARENTLESS (parent 0):
  kernel-managed domains are not part of init's wait tree — the
  process tree starts at init (PID 1, spawned by the bootstrap). A
  parentless exit is ADOPTED by a living init (the reaper of last
  resort), so a supervisor domain that exits through the process API
  still gets its status reaped instead of leaked.
- `wait_process(parent, pid, nohang)`: a specific child pid or any
  child; reaping frees the zombie's meta slot. No children at all →
  typed `ECHILD`-shaped error (specific or any alike); children exist
  but none exited → typed `WouldBlock`-shaped error (the pure core
  never blocks; the kernel runtime blocks or returns EAGAIN under
  WNOHANG at the ABI).
- A dying process's children (live AND zombie) reparent to **PID 1**.
  If init itself is gone, orphans are auto-reaped at their own exit
  (their status is discarded, slots freed): no zombie can outlive
  every possible reaper. A parent's un-reaped zombies reparent the
  same way, so init's wait loop (Phase 7) drains them.
- `ProcMeta` slots bound live+zombie processes to `MAX_DOMAINS`
  total; a full meta table refuses new children (fork/spawn) rather
  than dropping an exit status on the floor.

### D8 — Failure atomicity is part of the contract, proven per step

Every lifecycle operation is checks-first (all pure validations
before any mutation) with compensating rollback where multi-object
state is touched (the `spawn_user_blob` / pipe-executor pattern).
Injected-failure tests starve each resource (domain slots, meta
slots, cap slots, fd slots, sched entities, pid counter) one at a
time and assert the system returns to its exact baseline: domain
slots, meta slots, fd tables, pipe refcounts, scheduler entries,
capability counts.

### D9 — What is NOT in this round

- No syscall ABI change: FORK/EXEC/WAIT get internal mask bits
  (`SYS_FORK=18, SYS_EXEC=19, SYS_WAIT=20` — sequential after the
  0..=17 family) but their executors and Linux-number mapping are
  Phase 5 (`ABI-VERSION` v0.4). `SYS_SPAWN` stays mask-bit-only
  until init actually uses it (Phase 7).
- Threads/clone, process groups/sessions beyond the minimal
  foreground-group hook Phase 7 needs, setuid/setsid, rlimit
  syscalls: out of scope; recorded in ROADMAP.
- IPC endpoints are NOT released at exit (they are supervisor-managed
  today; the endpoint caps die with the domain, so a dead process's
  endpoint is unreachable garbage until the supervisor reaps it —
  documented, bounded by `MAX_ENDPOINTS`).

### D10 — Threat model

The attacker is a compromised child process (or a hostile executable
an honest parent was tricked into execing). What this design must
make impossible:

1. **Widening via spawn**: a profile_request beyond the parent's
   current surface → typed refusal + escalation counter (D2).
2. **Widening via fork+exec**: fork copies only what the parent has;
   exec intersects (D3/D4). The intersection is with the *live*
   mask, so prior tightenings survive both.
3. **Ambient inheritance**: spawn's fd_map is exhaustive; there is
   no code path that copies an fd outside it.
4. **Pid confusion / ABA**: monotonic pids; stale handles fail
   closed forever (D1).
5. **Zombie flood / fork bomb**: bounded by per-profile
   `max_children`, the meta-table bound, and per-domain quota; the
   monitor's per-domain accounting keeps counting the refusals.
6. **Unwaitable orphan leak**: reparent-to-init + auto-reap when no
   reaper exists (D7).
7. **Kill-up-the-tree**: impossible — fork DROPS the parent's
   self-cap from the child's copy (stricter than Unix same-uid
   parity, recorded as a deliberate divergence); the child holds
   nothing aimed at its ancestors.

What remains possible by design (recorded, not fixed here): a child
holding a copied `Domain(parent)` cap can signal its parent (Unix
parity); `wait` needs no capability (parenthood is the authority —
same as Unix); the exec policy table is only as trustworthy as init
(that is the TCB, as with any init).

## Testing plan (all host-side, pure core)

- Unit: pid monotonicity + exhaustion; explicit-fd spawn (map
  honored, absent fds absent, bad map entries refused); fork copy
  fidelity (mask/caps/fds/pos/creds); exec intersection + cloexec
  close; zombie → wait reap (specific/any/nohang/ECHILD); orphan
  reparent to init; parent-death zombie drain; children limit; the
  capacity self-test at 32 domains.
- Property (deterministic xorshift): random spawn/fork/exec trees —
  at every birth the newborn's mask, quota and non-structural caps
  are ⊆ its parent's live state (asserted at derivation time), and
  every descendant's mask stays ⊆ every ancestor's BIRTH CEILING (the
  ancestor's profile mask — an ancestor narrowing later does not
  retroactively shrink its children; what must never happen is a
  descendant exceeding an ancestor's ceiling). Resource caps
  (FsNode/Device/Endpoint) attenuate down the whole tree; `Domain`
  caps are signal plumbing scoped to the direct parent (a
  parent-minted `Domain(child)` cap is legitimately absent from
  grandparents — Unix sibling-signal parity).
- Lifecycle fuzz (deterministic): random interleaved
  spawn/fork/exec/exit/wait/kill sequences — no panic, and after a
  full teardown the domain slots, meta slots, pipe refcounts,
  scheduler entries and capability counts return to baseline.
- Injected failure at every step of every operation (D8).

## Consequences

- `Kernel` gains a `procs: ProcTable` (32 × small meta) and
  `Domain` gains `pid`, `monitor_enforce`, and a `cloexec` bit on
  its fd entries — all Copy, no heap, forbid(unsafe) intact.
- `MAX_DOMAINS` 4 → 32 grows the static `Kernel` (≈ 32 × Domain);
  host tests construct it on the stack today and keep doing so.
- Profiles grow `max_children`; `app_profile` is new and becomes
  the unlisted-binary default the moment Phase 5 wires execve.
- `SYS_FORK/EXEC/WAIT` occupy internal ids 18..=20 now so Phase 5
  does not renumber anything.

**Open items** (ROADMAP): signed exec manifests (hash-pinned
policy table in initramfs), rlimit syscalls (setrlimit/getrlimit),
process groups/sessions, `clone`-style threads, endpoint reaping at
exit, WUNTRACED/WCONTINUED (no stopped state exists to report).
