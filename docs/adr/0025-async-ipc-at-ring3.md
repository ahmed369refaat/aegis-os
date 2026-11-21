# ADR-0025: Async IPC at the ring-3 ABI — Stage 2's first M3 slice

- **Status:** Accepted (M3 Phase 4, round "M"; landing in slices)
- **Stage:** M3 → domains talk, capability-mediated
- **Date:** 2026-11-21

## Context

ADR-0004's async half has lived in the policy core since M2 week 1:
`EndpointTable` (never-reused monotonic ids, bounded 4-deep FIFOs,
`MAX_ENDPOINTS=8`), the capability-gated `IpcSend`/`IpcRecv` executors
(WRITE == send, READ == recv, owner-only drains), and the supervisor
grant API (`ipc_endpoint_grant`, uid 0). None of it is reachable from
ring 3: SYS_IPC_SEND/SYS_IPC_RECV answer nothing at the ABI, no blob
has ever sent a message, and the ROADMAP's Stage 2 acceptance (100k
ring-3 ping-pong) has never had a caller.

The memory round (ADR-0024) just closed; the natural next slice is
the one that needs nothing new from the kernel but an arm and a proof.

## Decision

### D1 — The ABI arms (the mmap pattern again)

`SYS_IPC_SEND(channel, len)` and `SYS_IPC_RECV(channel)` at the
INTERNAL nrs 7/8 — marshaled into the core's existing executors
through the same gate-first dispatch (the used-bit and the monitor's
organic fault accounting land in `dispatch`); results and errors
through the existing sysabi table (QueueFull/QueueEmpty → -EAGAIN,
TooLong → -EINVAL, cap denials → -EPERM — audited, the organic
signal). The blob calls the internal nrs directly (Linux 7=poll and
8=lseek are nothing this system's blobs speak — the same collision
note as mmap's nr 9, recorded for Phase 5's ABI-VERSION table).

### D2 — The supervisor bootstrap

Endpoints and caps are SUPERVISOR state: kmain (uid 0) creates the
endpoint (owner = the receiver's domain), grants WRITE to the sender
and READ to the receiver through `ipc_endpoint_grant`, and bakes the
monotonic endpoint id into each blob's data page. A ring-3 domain
never sees an endpoint it was not granted — the ambient-free rule.

### D3 — The proof (async, decoupled, no interleaving required)

The async model's whole point is that the parties do NOT need to
interleave: the sender fills the queue, the receiver drains it later.
Blob mode 8 (two domains, a second data byte picking the role):

- The SENDER: sends 4 fixed-length messages (the queue's full depth),
  verifies the 5th refuses -EAGAIN (the bounded refusal — the queue
  is not an unbounded privilege), yields, sends 4 more after the
  receiver's drain (the second round), verifies a send to an endpoint
  it holds NO cap on refuses -EPERM (the capability gate, live), and
  exits clean.
- The RECEIVER (owner): drains 4 (count and sender verified — the
  message carries the AUTHENTICATED sender id, the kernel's word not
  the peer's), verifies the empty queue refuses -EAGAIN, drains the
  second round, exits clean.

kmain runs them SEQUENTIALLY (sender, then receiver, then sender
again for round 2 — each a plain launch/take): no scheduler
dependency, no interleaving, the proof is about the CONTRACT not the
timing. Marker: `[M3] ipc: N messages each way, caps enforced, EAGAIN
both ends`.

### D4 — What is explicitly NOT here

- The SYNC call/reply fast path (Stage 2 task 2 — a blocking
  rendezvous over the park machinery; its own round).
- Page-grant IPC (task 4 — now easy over ADR-0024's refcounts; its
  own round).
- Pipes-over-endpoints (task 5) and the 100k ping-pong bench (task
  6): the acceptance number was written for real hardware; in QEMU
  TCG a syscall costs microseconds and 100k round trips is minutes —
  the bench round will measure HONESTLY (a smaller N with the stub's
  per-syscall ROUNDTRIP cycles, the acceptance re-stated per-host).
- Blocking recv (a parked receiver woken by a send — the K2 sleep
  machinery could do it; deferred with the sync path).

## Testing plan

- Host: the executor suites already exist (ADR-0004's tests); the new
  kernel arms add no policy — no new host tests beyond the arm
  marshal being compile-checked.
- Lanes: the mode-8 pair above; the marker; the EAGAIN/EPERM probes
  in-blob (a wrong count or a wrong errno exits nonzero and the
  marker refuses to print).

## Consequences

- The service/app profiles already carry the IPC bits (since round
  J's recalibration); the degraded tier has neither, unchanged.
- `ipc_endpoint_grant` gets its first live caller (kmain's proof
  bootstrap) — the API is exercised end-to-end for the first time.
- The endpoint table is kernel-global state in the core; teardown of
  a domain does NOT destroy its endpoints (the supervisor's table
  outlives domains — documented; revoke-on-exit is Stage 2's later
  business).
