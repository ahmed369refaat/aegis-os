# ADR-0029: Pipes over endpoints — the byte channel joins the capability world

- Status: Accepted (round Q, M3 Phase 4 slice 5 / Phase 5 opener)
- Date: 2026-11-22
- Deciders: kernel author
- Relates to: ADR-0004 (endpoints), ADR-0025 (IPC at ring 3, the
  bootstrap pattern), ADR-0026 (the rendezvous and the wake list),
  ROADMAP Stage 2 task 5 ("pipes become a wrapper over endpoints")

## Context

Two byte-paths live in the kernel today, and only one of them is in
the capability world. The IPC round gave domains capability-mediated
messages: endpoints with monotonic ids, WRITE == send, owner drains
with READ, bounded queues, EAGAIN honest, sync rendezvous over the
park machinery. But the message IS the len — no byte payload has ever
moved through an endpoint. Meanwhile `SYS_PIPE` (M1, Round J) runs on
the ambient `PipeTable`: a kernel-global array any fd can address,
sound fd discipline but no capability gate, no cross-domain story —
there is no way for a service to hand an unrelated domain a byte
stream, which is the whole shape of a shell (commands in, bytes out).

The K9 handoff named this round: wire `SYS_PIPE` to the endpoints and
the services story completes — a byte channel riding the same
capability machinery the message channel rides.

## Decision

### D1 — the byte channel endpoint (lib, `ipc.rs`)

An `Endpoint` becomes either a **message endpoint** (the ADR-0004
queue, unchanged) or a **byte channel**: `pipe: Option<Pipe>`, where
`Pipe` is pipe.rs's ring engine lifted out of the table — a 64-byte
ring grown to `CHANNEL_CAPACITY = 256` (the queue-depth × max-message
scale: 4 × 64), short writes at the free space, short reads at the
available bytes, `Ok(0)` at EOF (write end closed and drained),
`BrokenPipe` when the read end is closed, dup-aware per-end refcounts.
The **ring semantics and their tests survive verbatim**; what dies is
the ambient table under them.

New `EndpointTable` surface: `create_channel(owner)`,
`channel_write/read`, `channel_acquire/release_{read,write}`,
`channel_avail` (the recv_wait fast path), `live_ids` (supervisor
hygiene). Two lifetimes, one rule each:

- **fd-scoped channels** (created by `SYS_PIPE`): when both ends'
  refcounts reach zero the slot reclaims itself — Unix pipe lifetime,
  no supervisor needed. The id stays dead forever (the no-ABA rule).
- **supervisor-created channels** (kmain bootstrap): refs start and
  stay at zero; the endpoint lives until a uid-0 destroy — the
  ADR-0025 service-endpoint rule (the table outlives domains).

**Type discipline is a security property**: message ops (push/pop/
call/reply) on a channel refuse `IpcError::WrongKind`, channel ops on
a message endpoint refuse `PipeError::NotAChannel`. No smuggling
bytes through a message queue, no messages past a byte ring.

### D2 — the fd path reroutes onto channels (lib)

`SysRequest::Pipe` becomes `pipe_channel_create(caller)`: a fresh
channel endpoint owned by the caller and the two fds —
`FdTarget::PipeRead(ep)` / `PipeWrite(ep)` now carry the **endpoint
id**. Transactional: a full channel table or fd table rolls the whole
creation back (the `ipc_endpoint_create` discipline).

**No capability is minted — the F18 rule bent the design, not the
invariant.** The first cut self-granted the caller READ|WRITE on the
fresh endpoint and gated the fd reads/writes behind
`require_endpoint_cap`; the F18 test (`a_domain_cannot_mint_
capabilities`: *no syscall grows a domain's capability table*) failed
within minutes — `pipe()` had minted a fourth cap. The invariant is
pinned and correct: the capability table is supervisor-auditable
state, and syscalls do not touch it. So the fd path keeps the M1 fd
discipline exactly — **the fd IS the handle** (per-domain table,
dup-aware, no ambient reach: a domain can only name ids its own
`pipe()`/fork put in *its* table), while the ENDPOINT-addressed path
(`SYS_PIPE_READ`/`WRITE`, D3) is the capability-gated cross-domain
surface. A supervisor can still stop any fd pipe cold —
`ipc_endpoint_destroy` under the fds and every op fails closed
(EBADF, the no-ABA rule) — which the executor tests prove. What is
genuinely lost: mid-flight REVOKE of one end without killing the
endpoint; a later round can add a revoke that targets the fd table if
a caller ever needs it.

Fork children keep working by construction: the fd table copies, the
channel refs acquire — both sides attenuate together, no caps
involved.

`Kernel.pipes`, `PipeTable`, and its table tests are deleted; the
ring engine and its ref/EOF/EPIPE semantics survive inside the
endpoint (`pipe.rs` keeps the engine, `ipc.rs` hosts it). One
byte-path, one table, one id space. The `pub pipes` field's test
exposure narrows to `channel_refs`/`live_endpoint_count` accessors.

### D3 — the endpoint-addressed byte ABI (internal nrs 30/31)

The cross-domain surface, for a domain holding a cap but no fd:

- **`SYS_PIPE_READ(ep, buf, len)` (nr 30)** — READ cap + **owner**,
  the recv rules: short read, `0` at EOF, `-EAGAIN` empty, `-EFAULT`
  on a bad buffer. The kernel fills a kernel buffer once and copies
  out under the blessed SMAP window (the `sys_read` shape, ≤ 256).
- **`SYS_PIPE_WRITE(ep, buf, len)` (nr 31)** — WRITE cap, the send
  rules: short write, `-EPIPE` after the read end closes, `-EAGAIN`
  full. Copy-in once (the `sys_write_file` shape), then
  `drain_ipc_wakes()` — a rendezvous may have woken the owner.

**Wake-without-consume** — the rendezvous rule extended to bytes: a
`channel_write` onto an endpoint whose owner is parked `AwaitingMsg`
wakes the owner with the byte count and leaves the bytes in the ring.
The reader drains them itself with `pipe_read`. No hidden
cross-address-space copy rides the wake (the writer's syscall must
not touch the reader's buffers — the grant round's boundary, kept).
And `IpcRecvWait` on a channel: bytes available → `Count(avail)` now
(no park, no consume); empty → park, exactly the message rule. The
protocol is two steps by design — recv_wait asks "how much arrived?",
pipe_read moves it — and the proof is order-agnostic both ways, the
ADR-0026 shape: reader-first parks and wakes with the count;
writer-first leaves the bytes and recv_wait's fast path answers.

Profiles: bits 30/31 join service, app, and the degraded service
tier (a degraded server must still stream to its clients — the
ADR-0026 rule).

### D4 — supervisor hygiene: `ipc_endpoint_destroy`

uid-0 destroy by id (the create/grant symmetry), plus `live_ids()` so
a supervisor can sweep. Caps on a destroyed id fail closed by the
no-ABA rule — destroying a finished proof's endpoints strands
nothing but dead ids, which is exactly the intent. Needed in
practice: the proofs had left six live endpoints in the eight-slot
table; the mode-12 bootstrap sweeps them before creating its pair.

### D5 — the proof (blob mode 12, the eleventh)

The cross-domain service story, pinned by yields (the mode-9
discipline):

- **WRITER** (holds WRITE only): writes 24 bytes (pattern A) onto F;
  probes G — a channel it holds no cap on — and demands the `-EACCES`
  refusal; yields (the reader wakes and drains); writes 40 bytes
  (pattern B); fills the ring to its brim and demands `-EAGAIN` (the
  bounded truth: a channel is not an unbounded privilege); exits.
- **READER** (the owner): `recv_wait(F)` parks; wakes with exactly
  24; `pipe_read` drains pattern A byte-exact; a further read refuses
  `-EAGAIN` (empty, writer alive); yields; `recv_wait` takes the
  FAST PATH (40 landed while nobody waited); drains pattern B
  byte-exact; then the fd round-trip — `pipe()`, write through the
  write fd, read through the read fd, verify, close both — proving
  the rerouted fd path live at ring 3; exits.

Marker: `[M3] pipe: 64 bytes cross-domain over the channel, caps
enforced (EACCES + EAGAIN), wake and fast-path both proved`.

### D6 — ABI-VERSION v0.4

The internal surface is now the whole story, so the version document
becomes the whole table: the file family plus time, signals, memory,
fork, the IPC family, and the pipe pair — with every Linux x86_64
collision recorded (internal 7 vs poll(2), 8 vs lseek(2), 12 vs
brk(2), 13 vs rt_sigaction(2), 21 vs access(2), 22 vs pipe(2), 25 vs
mremap(2), 26/27/28 vs msync/mincore/madvise(2), 30/31 vs
shmat/shmctl(2)) and the `linux_to_core` translation table that
already bridges the coinciding numbers. Renumbering to the Linux
table stays Phase 5's `v1` work (ADR-0003); v0.4 makes the internal
truth explicit and test-pinned.

## What is explicitly NOT here

- **Writer-death EOF wake**: a reader parked on a channel whose only
  writer domain dies stays parked — the same honest answer as
  ADR-0026's "a stuck server blocks its caller". Waking requires a
  cross-domain WRITE-cap sweep at destroy time; its own small round
  if a caller ever needs it.
- **Blocking pipe_read** (park until bytes, bytes delivered through
  the wake): needs the wake to carry bytes across address spaces.
  The two-step recv_wait + pipe_read protocol is the documented
  answer this round.
- **fd passing between unrelated domains** (Unix SCM_RIGHTS): the
  supervisor-grants-a-WRITE-cap path is the AegisOS answer; a
  pass-fd syscall would be new surface for a later ADR.

## Testing plan

- **Host (red first)**: the channel table suite (roundtrip, short
  write/read, EOF/EPIPE, dup-aware release, fd-scoped reclamation,
  WrongKind both directions, ids never reused); the executor suite
  (Pipe creates a channel and mints NO caps — F18 extended; the M1 fd
  semantics through execute(); cross-domain PipeWrite/PipeRead; the
  no-cap EACCES; the rendezvous wake contents; recv_wait's channel
  fast path; fork fd inheritance over channels; endpoint-death
  closing the fds).
- **Lanes**: the mode-12 pair above; the marker; the refusal probes
  in-blob (a wrong count, a wrong errno, or a wrong byte exits
  nonzero and the marker refuses to print).
