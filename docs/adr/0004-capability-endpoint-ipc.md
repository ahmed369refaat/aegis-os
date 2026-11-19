# ADR-0004: Capability-endpoint IPC

- **Status:** Proposed
- **Stage:** 2 (IPC)
- **Date:** 2026-11-19

## Context

Stage 2 must give domains a way to cooperate without any ambient shared
state — no global channels, no "send to pid", no shared memory by
convention. The project invariant (attenuation-only privileges) demands
that communication rights be granted explicitly and be revocable, and
the Stage-2 gate (100k Ring-3 ping-pong < 1 s, zero leaks) demands a
fast path with zero allocation.

## Decision

All IPC flows through **endpoints**, and an endpoint is only usable via a
**capability** from the existing generation-based capability table
(`cap = {index, generation, rights}`):

1. **Sync call/reply (fast path):** `call(dst_cap, &Msg) -> Reply` with
   fixed-size (≤ 64-byte) messages copied through a per-endpoint slot;
   the sender blocks; zero allocation; measured in cycles at boot and in
   `bench/ipc.rs`.
2. **Async endpoints:** bounded per-domain queues; `send_async` never
   blocks (fails `EAGAIN`-style when full); delivery order FIFO.
3. **Shared memory as page grants:** `grant_frames(dst_cap, frames)`
   maps the granted frames RW-only (never executable) into the grantee's
   tables; revocation unmaps and scrubs — reusing the Stage-1 page-table
   and scrub machinery.
4. **Rights:** `SEND`, `RECV`, `GRANT` — derivation via the existing
   `try_narrow_to` (subset-only); revocation via the existing generation
   mechanism; both feed the monitor as before.
5. **Pipes become wrappers** over a pair of async endpoints; the lib's
   pipe semantics (EOF/EPIPE/dup-aware ends) are preserved and its tests
   ported unchanged in spirit.

## Consequences

- No message can be sent without a valid cap; a revoked or stale handle
  is rejected (`InvalidHandle`) and audited.
- The fast path is the only place where a domain blocks on another
  domain; deadlock is bounded by the scheduler (Stage 4 preemption
  breaks any cycle; until then, the bootstrap demo uses well-nested
  call/reply only).
- Page grants can never widen a domain's syscall surface; memory rights
  and syscall rights remain orthogonal.
- Invariant tests: zero caps/frames leaked across the 100k ping-pong;
  revoked-mid-flight calls fail with audit; granted pages are RX-free.

## Alternatives considered

- Mach-style ports with a central receiver thread — extra scheduling
  hops on the fast path.
- L4-style synchronous-only IPC — fastest, but async queues avoid
  priority-inversion pain for drivers (Stage 6) at negligible cost.
- SysV-style global keys ( queues/shmget) — ambient authority by
  construction; rejected outright.
