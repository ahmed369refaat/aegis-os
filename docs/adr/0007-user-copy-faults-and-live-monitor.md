# ADR-0007: Kernel faults while servicing user syscalls; ring-3 under the live monitor

- Status: Accepted
- Date: 2026-11-20 (second deep review, Phases A-B)
- Deciders: kernel maintainers
- Related: ADR-0005 (exception machinery), ADR-0006 (image W^X / IST)

## 1. Kernel faults while servicing user syscalls (N1)

### Context

`sys_write` validated the pages covering `[buf, buf+len)` and then copied
with `memops::read_u64_va(buf + off)` — 8 bytes at a time, even when fewer
remained. A user `write(1, 0x403FFD, 3)` (tail of the data page at
0x403000) made the *kernel* read through the absent next page: a CPL0 #PF
that the dispatch billed to the user and, on other paths, halted the
machine. `read_u64_va` also documents "8-byte aligned" while `buf` is
attacker-controlled and unaligned (UB).

### Decision — option (a): validate-then-copy, provably fault-free

We keep the validate-then-copy model and make the copy **provably unable
to fault** by construction:

1. **The copy touches exactly the validated bytes.** A new allowlisted
   `memops::read_u8_va` reads one byte at a time inside `[buf, buf+len)`.
   No user-controlled address ever reaches an alignment-requiring
   primitive: `read_u64_va`/`write_u64_va` gain `debug_assert!` on
   alignment, and the user-copy path simply does not use them.
2. **The range arithmetic is pure and host-tested** (`mm/user_range.rs`):
   zero length, single byte at a page's last byte, a range ending exactly
   at a page end, a range crossing into an absent page, `buf + len`
   wraparound, `buf >= USER_LIMIT`, `len > MAX_WRITE`. The target's
   `validate_user_range` is a thin adapter that walks the domain's tables
   over the pure function's span.
3. **The dispatch distinguishes fault origins.** A #PF whose frame's
   `CS & 3 == 3` while a user run is active is the *user's* death (the
   existing path). A **CPL0** fault while a user run is active is a
   **kernel bug** — it halts loudly with a distinct marker, never the
   user's, never silent. An `IN_USER_COPY` armed flag narrows it further:
   a CPL0 fault inside the user-copy routine prints
   `[SEC ] kernel fault inside user copy (copy escaped the validated span)`
   — unreachable after (1), present so any future escape is loud.
   One documented carve-out: a CPL0 fault *before the run's first
   syscall* is the known launch-relay limitation of this QEMU build
   (`docs/arch/syscall-entry.md`) — it is recorded and resumed, and
   kmain reports the run as environment-blocked. The copy routine can
   only run after the first syscall, so the carve-out can never mask a
   copy-span violation.

**Why not (b) exception tables / fixups:** a fixup mechanism would *mask*
real bugs — any stray kernel fault inside the copy window would silently
become `-EFAULT`, including faults that corrupt state. In a no_std kernel
without unwinding, fixup tables are also a second, parallel control-flow
path to audit. A copy that cannot fault needs no recovery: the invariant
"copy span == validated span" is checkable by review and by the host
tests, and the armed flag turns any violation into the loudest possible
failure instead of a recoverable one.

## 2. Ring-3 domains under the live behavior monitor (N2)

### Context

The ring-3 path gated on a *snapshot* (`UserRun.mask`,
`UserRun.quarantined`) copied at spawn; denied syscalls were counted in
`run.denied`, never in the lib `Domain` the monitor reads;
`syscall_dispatch` had no access to the `Kernel`. So Tighten, Quarantine,
`Kernel::tick` and AuditOnly (the F6-F9 machinery) never reached any
domain actually executing in ring 3.

### Decision

1. **The snapshot is not a source of truth.** The ring-3 gate runs
   through the live lib domain: `Kernel::dispatch(domain_id, nr)` —
   which updates stats, used-bits, denied counts and out-of-profile bits
   and honors Tighten/Quarantine immediately (the mask can only shrink —
   attenuation-only holds). `UserRun.mask/quarantined` remain only as
   fast-path caches of the last observed live state and are re-read
   after every audit window.
2. **The Kernel is reachable from the syscall path via an allowlisted,
   documented singleton**: `runtime::kernel_ptr()` — a `static mut`
   pointer set once in kmain before the first ring-3 launch, never
   aliased concurrently (single CPU, dispatch runs with interrupts off
   on the kernel stack) and guarded by a re-entrancy flag that halts
   loudly on nested entry. The unsafe is confined to the existing
   `runtime` allowlist entry (see `scripts/check_unsafe.sh`).
3. **Organic signals from ring 3**: user #PF/#GP/NX faults record
   `record_fault` on the live domain (fault entry path); unknown syscall
   numbers count as out-of-profile; failed user-pointer validation
   counts as a fault.
4. **`Kernel::tick(now)` is driven from the kernel**: TSC-derived time
   at syscall entry/exit and at fault entry (until a timer exists). The
   window length is the lib default (`MonitorConfig` / `set_monitor_window`;
   100 TSC-derived "ticks" per window, printed at boot). Audit results
   apply to the *running* domain: after Tighten the next syscall sees
   the reduced mask; after Quarantine only SYS_EXIT works.

### Consequences

- A rogue ring-3 domain is quarantined by its own behavior — observable
  in QEMU with a CI-grepped marker — and a healthy domain keeps running
  through the same windows.
- The `denied`/`bad_syscalls` counters on `UserRun` become advisory
  (display/audit replay); the lib `Domain` is the accounting truth.
- `unsafe` count may rise by the singleton accessor; that requires this
  ADR's reference in `scripts/unsafe-count.txt`.
