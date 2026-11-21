# ADR-0024: The memory round — anonymous mmap at ring 3, copy-on-write fork, and the physical-access story

- **Status:** Accepted (M3 Phase 3; landing in slices, each with its own red-then-green proof)
- **Stage:** M3 → processes get memory of their own
- **Date:** 2026-11-21

## Context

The policy core has had a memory half since round F13: `AddressSpace`
regions behind a ten-check policy (W^X, quota, overlap, guard gaps,
kernel half), and `SysRequest::Mmap/Munmap` executors that enforce it —
but they are metadata-only. From ring 3, SYS_MMAP/SYS_MUNMAP answer
`-ENOSYS` (the ring3-rogue's mode-3 audit line is literally that).
Nothing allocates a frame; nothing fills a PTE; no page a process did
not get at spawn exists.

Fork is the same story one layer up: `fork_process` (ADR-0022) copies
masks, caps, fds, credentials — everything except memory, because
there is no memory story to copy. And on the physical side, the
mission asks for "the 16 MiB identity map of all physical memory"
to be gone — it already is (PML4[0] is zeroed at `mm::init` and the
boot asserts the read-back); what remains is the 1 GiB kernel direct
map, which is the memory manager's own translation window (every
page-table walk, scrub and copy goes through it) and is NOT
device-facing: devices DMA through the broker on IOMMU lanes
(ADR-0013 D6) and through pool-owned identity frames on the
no-IOMMU lane (the documented degradation).

This ADR decides how the memory round closes those gaps.

## Decision

### D1 — Anonymous mmap/munmap at the ring-3 ABI: real frames, owned, reclaimed

`SYS_MMAP(addr, len, flags)` marshals into the core's existing
executor (the policy gate lands where the monitor reads it), then —
only on `Allowed` — the kernel side makes it REAL:

- A pool-backed `FrameSource` allocates every page with
  `owner = run.domain`: the mmap'd memory is the DOMAIN'S, and exit
  reclaims it through the existing `free_all_owned`.
- `run.tables.map_region(&mut space, base, len, flags, src)` — the
  SAME ten-check-gated mapper spawn uses, with its rollback-on-failure
  (a mid-mmap exhaustion unwinds cleanly; the policy `unmap` rides the
  rollback too).
- ANON only: no file-backed mappings this round (no fd-into-PTE path
  exists; documented, not faked). Flags: READ/WRITE/EXEC pass to the
  policy (W^X enforced there); unknown bits refuse `-EINVAL`.
- Address choice: the caller's `addr` is a HINT honored only if the
  policy accepts it (gaps, overlap, kernel half — the fixed spawn
  layout's guard gaps refuse adjacency by construction). `addr=0`
  picks the next free window above the trampoline page, page-aligned,
  from a pure, host-tested allocator (deterministic, gap-respecting).
- `SYS_MUNMAP(addr, len)`: policy unmap + PTE teardown + the frames
  FREE (owner-scoped; a frame the domain no longer maps is not the
  domain's).
- The fixed layout (code/data/stack/trampoline) is spawn-time state
  and stays outside the mmap ABI's reach — the policy's overlap and
  guard-gap checks make that structural, not conventional.

### D2 — Copy-on-write fork: the page-table half, and its first consumer

- **Frame reference counts** (`src/frame_share.rs`, pure,
  host-tested): a fixed table `[(pa, refs)]` with
  acquire/release/unique, overflow-checked, release-to-zero returning
  the frame to the caller (the kernel frees it through the pool).
  One refcount per physical frame — the root of every CoW decision.
- **fork's memory half** (kernel): clone the parent run's page tables
  with EVERY writable user PTE demoted to read-only, and every mapped
  frame's refcount +1 — both sides then share every page. The child
  run enters the world parked (the K2 machinery hands it the CPU);
  the parent continues from the syscall.
- **The write fault is the copy**: the CPL3 #PF path gains a CoW
  check BEFORE the terminate — the decision is PURE
  (`should_cow(pte, region_flags, refs, write_access)`, host-tested
  with the full truth table): PTE present ∧ user ∧ read-only ∧ the
  region says writable ∧ refs > 1 ∧ the fault is a WRITE → allocate a
  fresh frame, copy the page through the direct map, remap the
  faulting PTE RW to the copy, release one refcount, and RETURN from
  the exception — the faulting instruction re-executes and succeeds.
  Anything else keeps today's semantics (the monitor's fault record
  and the domain's death — an RO-region write is a violation, not a
  CoW).
- **SYS_FORK at the ABI** (Linux nr 57 → the core's `SYS_FORK`):
  gate (the bit exists on service+app since round K), core
  `fork_process` (masks/caps/fds/creds), then the page-table clone
  above; the parent's RAX is the child's domain id, the child's RAX
  is 0. The child's id is a DOMAIN id — the pid mapping is the
  Phase-5 ABI's business.
- Refcount-one pages skip the demote+share dance (a private page
  stays private-RW — the common case costs nothing).

### D3 — The physical-access story: pin what is already true

- The identity map's death gets a NAMED pin (a boot-time assertion
  with its own marker) so a regression cannot hide behind the
  existing assertion's prose.
- The direct map is DOCUMENTED as the kernel-internal translation
  window (memory-manager privilege, not a device path): its doc
  header says so, and the device rules are restated in one place —
  devices reach memory ONLY through the broker (IOMMU lanes) or
  pool-owned identity frames (the no-IOMMU lane's documented
  degradation), never through an ambient physical window.
- No attempt is made this round to window the direct map per-owner:
  the kernel's own page-table machinery legitimately addresses all of
  RAM, and a per-owner windowing of THAT is a multi-round project
  with no current threat model behind it (there is exactly one
  kernel, and it is the memory manager). If untrusted kernel modules
  ever arrive (ROADMAP: driver isolation), this decision reopens.

### D4 — What is explicitly NOT here

- File-backed mmap (needs the fd→PTE path; Phase 5+).
- `mprotect`, `madvise`, `brk`/`sbrk` heaps, MAP_FIXED semantics
  beyond "the hint is honored or refused".
- Swap, huge pages, NUMA, page cache.
- Refcounted SHARED mappings between live processes (`MAP_SHARED`
  between fork relatives IS the refcount path; arbitrary
  `shm` is not).
- The pid/ABI fork semantics beyond the memory half (wait, exit
  codes through the ABI) — Phase 5.

## Testing plan

- Pure (host): the frame-refcount table (acquire/release/unique,
  overflow, zero-release); the CoW decision truth table (every
  (pte-present, user, rw, region-writable, refs, write) combination —
  exactly one "copy" outcome, everything else "violate" or "pass");
  the free-window allocator (deterministic, gap-respecting, exhausts
  honestly); the mmap flag decoding.
- Kernel host tests: the pool-backed FrameSource's accounting (every
  alloc attributed to the owner, rollback returns everything).
- Lanes: a `ring3-mmap` blob — mmap two pages, write patterns through
  them, munmap one, touch the freed one (must #PF → the organic
  signal), exit clean; a `ring3-fork` blob — mmap a page, write a
  pattern, fork, the CHILD writes a different pattern (the CoW
  fault), the PARENT's pattern must survive (the copy happened), both
  exit clean — the marker names the CoW count; and the mission's
  randomized stress: a deterministic fork/kill/exit churn replayed on
  the HOST against the core + refcount model, ending with every
  frame, slot and scheduler entry home (`free_all_owned` == 0
  leftovers).

## Consequences

- A run's `tables`/`space` are no longer spawn-immutable: the mmap
  path mutates them at syscall time (the run's CR3 is live; the
  kernel edits through the direct map as always).
- `UserRun` gains nothing; the refcount table is kernel-global
  (single CPU, one pool). Domains' frames remain pool-owned; CoW
  copies allocate owner-tagged like any mmap page.
- The fault path gains its first RECOVERABLE user fault — the
  terminate branch stays the default, and the CoW branch is one
  checked decision, not a policy.
- `boot.sh` greps grow (same-commit rule): `[M3] mmap:`,
  `[M3] cow:`.

**Open items** (ROADMAP): file-backed mmap, mprotect, shm, the
per-owner direct-map windowing (reopens with driver isolation),
swap.
