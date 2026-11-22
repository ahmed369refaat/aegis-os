# ADR-0026: Sync call/reply over the park machinery

- Status: Accepted (round N, M3 Phase 4 slice 2)
- Date: 2026-11-22
- Deciders: kernel author
- Relates to: ADR-0004 (async endpoints), ADR-0023 (park/nanosleep),
  ADR-0025 (IPC at the ring-3 ABI, the nested-dispatcher rules)

## Context

ADR-0025 closed the async half: domains send and poll from ring 3,
capability-gated, bounded queues, EAGAIN honest. Stage 2's task 2 is
the synchronous half — the call/reply rendezvous a service protocol
actually speaks: `call(dst, msg)` blocks the caller until the callee
replies; a blocking `recv` parks the server until a request arrives.
The machinery to ride already exists and is lane-proven: the park
table (ADR-0012), the syscall-path park (`park_current_from_syscall`,
ADR-0023), the scheduler's `set_runnable` block/wake with the F12
vruntime floor, and the round-M dispatcher rules (the tolerant
`try_take`, the chain stack).

## Decision

Three syscalls at the internal nrs 26/27/28 (the ABI-VERSION note of
ADR-0025 applies: internal numbering, the Linux renumbering is Phase
5's table):

1. **`ipc_call(channel, len)`** — WRITE cap, the same bounded push as
   `ipc_send` (a full queue refuses -EAGAIN: sync is not a privilege
   around capacity), then the caller registers as awaiting-reply on
   that endpoint and blocks. The kernel side parks the run
   (`park_current_from_syscall`). When the reply lands, the parked
   image's RAX is patched to the reply's len — `call` RETURNS the
   reply.
2. **`ipc_recv_wait(channel)`** — READ cap + owner (the recv rules).
   Queue non-empty → pop now, return the len, no park (the fast path
   is the async recv verbatim). Queue empty → register as
   awaiting-message on the endpoint and block; the kernel parks.
3. **`ipc_reply(channel, len)`** — READ cap + owner. Finds the OLDEST
   awaiting-reply caller on the endpoint (FIFO by a monotone
   sequence), records `len` as its wake value, clears the waiter,
   wakes the domain (`set_runnable(true)` — the F12 floor applies, a
   blocked domain cannot bank vruntime). No waiter → -EAGAIN (the
   transient truth: nobody is asking).

**The rendezvous rule** — one clause that unifies sync and async: a
push (send OR call) onto an endpoint whose owner is parked in
`recv_wait` does not leave the message in the queue. The executor
pops what it pushed, records the len as the owner's wake value, and
wakes the owner. The queue only ever holds the async backlog —
messages that arrived with nobody waiting.

**The wake-value plumbing** (the layering rule): the CORE decides and
records — a small wake list of `(domain, value)` pairs filled by the
reply/send executors; the KERNEL applies — after a waking syscall
returns, the syscall layer drains the list and patches each parked
image's RAX (`patch_parked_rax`, the `gprs[14]` slot
`parked_from_syscall` built from the syscall's `result`). The core
stays host-testable (no register imagery in it); the register truth
stays in the kernel where the park table lives.

**Exit cleanup**: a dying domain's waiter entry dies with it (the
ADR-0023 sleepers precedent). A reply to a dead endpoint's caller
finds no waiter → -EAGAIN.

## The proof (blob mode 9, the eighth kmain marker)

A caller and a callee (the endpoint owner), TWO round-trips, and the
order is deliberately the scheduler's business — the contract is
order-agnostic:

- If the caller runs first: the call queues the message and blocks;
  the callee's `recv_wait` pops it (no block), computes, `reply`s; the
  caller wakes with the reply len in RAX.
- If the callee runs first: its `recv_wait` blocks; the caller's
  `call` rendezvouses (the push pops itself, the callee wakes with
  the request len); the caller blocks on the reply; the callee
  replies; the caller wakes.

Both orders must yield: `call` returns exactly the reply len the
callee sent, `recv_wait` returns exactly the request len, `reply`
returns 1 (one waiter woken). The marker:
`[M3] sync: 2 round-trips, call blocked and returned both replies, recv_wait returned both requests` —
order-agnostic by construction, on every lane.

## Consequences

- The service and app profiles gain the three bits (sync IPC is
  service-surface; degraded service keeps them too — a degraded
  server must still answer its clients).
- Host tests cover the core semantics: block registration, FIFO
  among callers, the recv_wait fast path, the rendezvous
  self-consume, the exit cleanup, the wake list contents.
- NOT here (each its own round if ever): reply channels as separate
  endpoints (the reply rides the caller's endpoint — one cap, one
  gate), timeouts on call (a stuck server blocks its caller; the
  honest answer today, same as Unix read on a pipe), and any
  multi-word payload (the len IS the message this round, as in
  ADR-0025).
- The scheduler's run queue and the park table stay untouched: a
  blocked domain is simply non-runnable, exactly like a sleeper
  before its deadline — one blocking mechanism, three users.
