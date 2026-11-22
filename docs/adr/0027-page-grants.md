# ADR-0027: Page grants — memory capability transfer over the ADR-0024 accounting

- Status: Accepted (round O, M3 Phase 4 slice 3)
- Date: 2026-11-22
- Deciders: kernel author
- Relates to: ADR-0024 (frames, refcounts, mmap/fork), ADR-0004
  (capabilities), ADR-0025/0026 (the IPC surface the grant rides)

## Context

ADR-0024 closed anonymous mmap, CoW fork, and the frame-refcount
table — but explicitly deferred "refcounted SHARED mappings between
live processes" (D4). Stage 2's task 4 is the bounded first slice of
exactly that: one domain CONFERING a page on another, explicitly,
capability-gated — not ambient shm. The K7 handoff named it the
easiest remaining Stage-2 item because every piece exists: the
refcount table (`frame_share`), the ten-check mapper
(`map_region`), the window allocator (`find_free_window`), the
domain-capability gate (`require_domain_cap`), and the sync IPC
(ADR-0026) to tell the receiver where the page landed.

While designing the exit path this round found a LIVE ADR-0024 D2
bug, visible in every boot log since the fork round:
`[MM] teardown domain 27: freed 5 of 9 owned frames`. A dying domain
releases the refcounts of frames it POOL-OWNS (the reclaim path),
but never the refcounts of frames it MAPS BUT DOES NOT OWN — the
fork child's side of every still-shared page. Four pages per fork
proof leaked (stuck at refs=1 after the parent's death, never
returned to the pool). The grant would multiply the leak; the fix is
a precondition.

## Decision

1. **The exit-release rule (the D2 fix)**: on SYS_EXIT, before the
   run dies, walk its user PTEs and RELEASE every frame whose shares
   entry names another owner (`owner_of(pa) != me`) — the borrowed
   mappings (fork-shared-from-parent, granted-in). Release-to-zero
   frees under the ORIGINAL owner's tag, exactly as the reclaim path
   does. Frames the domain pool-owns stay the reclaim path's
   business (the two rules are disjoint: `owner_of(pa) == me` vs
   `!= me`). The fix's observable: the loud teardown line disappears
   — `freed 9 of 9` — and boot.sh gates on its ABSENCE (any
   accounting bug, anywhere, fails the boot).

2. **The shares-aware unmap source (`SharesSource`)**: one
   `FrameSource` whose `free_frame` consults the shares table — a
   shared frame is RELEASED (freed only on the last release, under
   the original owner's tag); a private frame frees through the pool
   as today. `sys_munmap` switches to it, closing a second latent
   hole (munmapping a fork-shared or granted page used to pool-free
   a frame another space still maps). `grant_map`'s rollback uses it
   for the same reason.

3. **`ipc_grant_frames(dst, va, len)`** (internal nr 29, the
   ABI-VERSION note of ADR-0025 applies):
   - **The gate** (core, host-tested): the caller holds a Domain
     capability on `dst` with WRITE (the kill pattern — the right to
     operate on that domain); `dst` must be live (a dead grantee is
     `UnknownDomain`, not a silent drop). The arm validates and
     returns Unit — the kernel side maps (the mmap precedent: the
     core owns policy identity, the kernel owns PTEs).
   - **The kernel side**: walk the GRANTER's tables over
     `[va, va+len)` — every PTE present + user, else -EFAULT (no
     grant of unmapped or kernel memory). Take the receiver's parked
     run (`take_parked`), pick its window
     (`space.find_free_window`, the same floor as mmap), and
     `grant_map`: the SAME ten-check policy gate (the receiver's
     quota and overlap rules apply to grants — a grant cannot
     smuggle memory past a quota), with every leaf PTE pointing at
     the granter's frame, refcount acquired per page immediately
     before its PTE write (rollback releases exactly the mapped
     ones). The receiver's run is stashed back untouched except for
     its tables and space — a blocked run (parked in recv_wait) is
     as grantable as a runnable one: the PARKED table holds it
     either way.
   - **RW-only, hardwired**: a granted page never arrives executable
     (READ|WRITE in the PTE, no caller choice).
   - **The bound**: a grant is 1..=64 pages — the refcount table's
     own `MAX_SHARED` (a bigger ask is -EAGAIN, the honest
     transient; growing the table is its own round).
   - **The return**: the VA where the frames landed in the
     RECEIVER's space. The sender passes it on through the sync IPC
     of ADR-0026 — `call(ep, granted_va)` — the two rounds compose:
     the grant confers the page, the call tells the receiver where
     it is, and the reply confirms the read.
   - **The lifetime invariant**: the refcount counts every
     reference including the owner's implicit one (the fork
     accounting, unchanged). Either side may munmap (its release
     drops one ref); either side may exit (the exit rule above);
     the grant OUTLIVES the granter (the granter's death releases
     its side; the grantee maps a live frame until it lets go).
   - **No revocation this round** (a revoke is a forced unmap +
     TLB shootdown protocol — its own ADR when a caller needs it);
   **no grant-in-grant chains** (a grantee may grant onward — the
   accounting allows it — but no round tests it; documented, not
   faked).

## The proof (blob mode 10, the ninth marker)

The granter mmaps a page, writes a pattern into it, grants it, and
calls the receiver's endpoint with the granted VA as the message
(the rendezvous of ADR-0026 delivers it). The receiver wakes from
`recv_wait` with the VA, READS the pattern through the grant (the
granter's write, visible in another address space), writes its own
mark at the next offset, and replies. The granter's `call` returns
the reply, then reads its OWN page and must find the receiver's mark
(the bidirectional proof — the grant is real shared memory, not a
copy). Both exit 0. The marker:
`[M3] grants: 1 page RW, the grantee read the pattern and the granter saw the reply-write`.
And the D2 fix's own gate: no `[MM] teardown` line in any boot log
(the count line prints only on a mismatch).

## Consequences

- The service profile (and its degraded tier) gains the grant bit.
- Host tests cover the core gate (no cap → PermissionDenied with the
  escalation counted; dead dst → UnknownDomain; cap present → Unit).
  The page-table mechanics (walk, grant_map, the exit rule) are
  target-side, lane-proven — the fork precedent (clone_for_fork has
  no host tests either; the boot proofs carry it).
- The teardown-noise gate makes every future accounting bug a boot
  failure, not a log line.
