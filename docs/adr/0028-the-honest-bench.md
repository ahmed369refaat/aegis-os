# ADR-0028: The honest bench — measured, not guessed (and the two bugs the measurement round found)

- Status: Accepted (round P, M3 Phase 4 slice 4)
- Date: 2026-11-22
- Deciders: kernel author
- Relates to: ADR-0012 (the park machinery), ADR-0023 (ticks,
  signals), ADR-0024 (frames, CoW), ADR-0026 (sync call/reply),
  ADR-0027 (grants, whose round's K8 handoff named this one)

## Context

M2-PLAN's standing rule is "measured, not guessed", yet every
performance claim about the IPC/memory machinery so far was a
guess: nothing ever timed a park, a rendezvous, a grant, or a CoW
copy. The K8 handoff made the bench the next round's first
priority. The design constraint that shaped everything: the timing
must be END-TO-END from ring 3 — rdtsc inside the blob, around the
whole syscall (entry, gate, park, wake, resume) — because a
kernel-side timestamp would flatter the paths by exactly the
context-switch cost a real caller pays.

## Decision

### D1 — The bench (blob mode 11, the tenth proof)

Two domains: a MEASURER (mmaps three windows: the metrics buffer,
the grant source, the CoW subject) and a RESPONDER (recv_wait →
reply on an endpoint, exits on a 63 sentinel — a bounded message,
the IPC bound being 64). The measurer, in order: 16 yields (the
park+dispatch floor — nobody else runnable, the responder is
BLOCKED not runnable), 32 call/reply round-trips (every call
rendezvouses with the parked responder: park, wake it, it runs and
replies, we wake — the full cycle), one grant (walk + refcounts +
map through the receiver's own policy, the receiver parked
throughout), 4 CoW samples (fork demotes everything, one write
faults+copies inside a single instruction's wall time, the yield
reaps the child whose D2 exit-release drops the shared refs).

The report is SELF-REPORTED: raw TSC deltas formatted as hex by a
tiny in-blob formatter (16 nibbles/word) and written through
SYS_WRITE — the kernel cannot read the metrics page after the run
dies (its frames are reclaimed), and the blob has no other output
channel. The kernel prints the CALIBRATION beside it: the
ACPI-measured `tsc_hz`. `scripts/bench-decode.py` converts. The
boot gate greps all three lines.

### D2 — The numbers (pc lane, QEMU, tsc_hz = 2.5 GHz)

| metric | cycles | time |
| --- | ---: | ---: |
| park+dispatch floor (yield, avg of 16) | ~5,000 | **2.0 µs** |
| call/reply RTT (avg of 32, min 41.2 µs) | ~116,000 | **46.2 µs** |
| grant syscall (one page, whole path) | ~105,000 | **42.1 µs** |
| CoW fault+copy (avg of 4, min 130.9 µs) | ~430,000 | **171.6 µs** |

Reading: the RTT and the grant cost the same order — both are
dominated by the park/wake machinery crossing the scheduler, not
by their own work (the grant maps ONE page through a ten-check
policy and still lands within one RTT). The CoW copy is ~4 RTTs:
the exception path (two page walks, the frame alloc, the refcount
release, the TLB flush) plus a 4 KiB WORD-wise copy through the
direct map (512 u64 volatile pairs — never byte-wise; the round-R
re-read of the code corrected this attribution) plus the remap,
all under a fault-and-resume. The floor (2 µs)
shows the park machinery itself is cheap; everything above it is
the fair scheduler's pick + the wake chain. These are
QEMU-TCG-accurate relative numbers — hardware absolute numbers
need the aegislane; the RATIOS are the transferable truth.

### D3 — Fix 1: a dying run must never be preempt-parked (ExitKind::Running)

The exit arm sets `run.exit`, ticks the window clock, then resumes
the kernel — and the tick between those lines could PREEMPT-PARK
the run: parked as not-runnable with its exit already written, its
user RIP resumed past its own exit syscall, and the completion
mailbox never sees it. The structural hole: `ExitKind` had no
"alive" variant — every run's default was `Exited(0)`, so no
machine could tell a live run from a finished one. Now:
`ExitKind::Running` is the spawn default; the tick's Switch path
reads the active run's exit and KEEPS it (no park, no switch) when
it is not `Running` — a dying run finishes dying.

### D4 — Fix 2: the park-unwind rule (bounded dispatch nesting)

`park_current_from_syscall` called `dispatch_next()` — nesting a
FULL dispatcher per park. A run resumed by a dispatcher and parking
again (every blocking syscall in a loop) added a level each time:
the chain stack (depth 8, then a panic) and the kernel stack below
it. A server that parks once per request could not survive its own
load; the bench's 32-call RTT found it live (a corrupted resume
slot stranded both runs mid-flow). The rule: an INNER park (a
dispatcher level is live — `park_chain_depth() > 0`) does not nest
— it jumps `resume_kernel()` straight back to the CURRENT level's
loop (the resume slot already holds its resume_parked label; the
loop's post-return `try_take` sees None and just loops). Only the
OUTERMOST park — a flat-launched run parking for the first time —
starts a dispatcher. Depth is ~1 forever; the frames unwind through
the RSP restore; a request loop of any length runs in one level.

### D5 — The hunt's lessons (kept, because they will recur)

The bench boot failed for fifteen boots before it passed, and the
failure was almost never what it looked like. Three lessons worth
their cost:

1. **The missing dispatch line.** The bench domains ran the
   MODE-1 WRITER (the dispatch fallthrough) with mode-11's data —
   the `cmp al, 11 / je 17f` line was never written (an earlier
   edit's anchor fix silently dropped it). Fifteen boots of
   "register corruption" were mode-1 code running with the wrong
   data page. When a system behaves as if a completely different
   code ran, CHECK THAT YOUR CODE IS REACHABLE BEFORE hunting
   register-level ghosts.
2. **The self-inflicted probe.** A debug probe read a user VA from
   CPL0 without STAC — the probe itself faulted the kernel. A
   diagnostic that breaks the thing it measures is worse than
   none; the SMAP discipline applies to debug code too.
3. **The constant typo.** The "[BENCH] " prefix qword was
   byte-swapped into "[BNECH] " — the metrics were perfect for two
   boots while the gate refused the label. Verify constants
   against their bytes, not their intent.

The fixes D3/D4 were found by the hunt and are real regardless of
the blob bug (both reproduce under synthetic storms); they stay,
with the proof suite green on all three lanes.

## Consequences

- boot.sh gates the `[BENCH]` line, the `6 clean exits` marker, and
  the `tsc_hz` line — a regression in any timed path's ability to
  COMPLETE is now a boot failure.
- `scripts/bench-decode.py` is the conversion tool; the ADR table
  is the baseline future rounds compare against.
- Host tests: the bench itself is target-side (the lanes prove it);
  D3/D4's logic is structural (the tick guard reads a kind the
  proofs now exercise every boot).
- The aegislane (hardware absolute numbers) remains future work;
  the ratios are documented as the transferable result.
