# Changelog

## [Unreleased] — Phase 6 S1: the boot root grows — mkdir/unlink/chroot reach ring 3

The tmpfs core gets its first M3-sized window: 64 inodes (was 32),
1 KiB per file — a full ext2 block, the persistence round's unit (was
128 bytes). Sizing note pinned in the source: the VFS is inline in
`Kernel<P>` and every host test builds one on its stack; a 4 KiB
window measurably overflowed the deep-park host tests' stacks, 1 KiB
keeps the struct ~68 KiB. The boot tree grows from the lone /pub to
the M3 tree: /pub, /tmp (world-writable), /dev, /proc (S2's homes),
/bin — prepared by the same uid-0-then-dies supervisor pattern.

Three ring-3 arms arrive: SYS_MKDIR(16), SYS_UNLINK(17) (the
unlink+rmdir fold, `-ENOTEMPTY` on a non-empty directory), and
SYS_CHROOT(15) — all reading paths through the SAME bounded,
page-checked copy-in as SYS_OPEN. The Linux whitelist gains
mkdir(83), unlink(87), chroot(161). **The collision hunt, live**: the
first blob probe of internal chroot(15) died silently after every
answer checked correct — internal slot 15 is rt_sigreturn's legacy
home in the frozen v0.4 hybrid table (the signal trampolines in the
field call it), so the kernel translated chroot(15) into a sigreturn
refusal. Resolution, documented in ABI-VERSION: ring-3 chroot is
Linux-entry-only (nr 161); the internal files blob keeps the
mkdir/unlink dance (EEXIST, rmdir fold, ENOENT, ENOTEMPTY — with the
ENOTEMPTY probe moved INSIDE /pub after /'s 0o755 answered EACCES
first, POSIX order); the Linux-ABI blob (mode 13) gains the full
path-family probe — mkdir(83), unlink(87), chroot(161), then inside
the jail the escaped absolute path answers ENOENT.

Gates: red->green (the 1 KiB absolute pin went red on the 128-byte
cap; the translate table went red on 83/87/161), fmt clean, clippy
`-D warnings` clean, host tests 426/0, all three boot lanes PASS with
the files blob's new Phase M and mode-13's S1 probes live.


## [Unreleased] — ADR-0030 round Y: the fragile handler delta found, relocated and pinned

### The correction that mattered

Round X shipped a dossier claiming the ~1-in-5 lane flake was
"reproducible on demand" at 8x tick density. Round Y disproved it:
every failing round-X boot ran the hunt's own amplifier blob, whose
50-iteration loop (inserted in mode 7) moved `sig_handler` +0xC
while the blob's hand-measured `0x947` delta stayed stale — the
kernel delivered SIGUSR1 twelve bytes short, into the hex helper's
tail, and the victim died writing through rdi=0xA. The pristine tree
at 8x density is green (4/4), as are 18 consecutive pristine boots
at 10 ms. The dying register file's "context struct fields" were
launch-stub scratch leftovers (harmless — mode 3 never reads a
callee-saved register). ADR-0030 is rewritten to say all of this
out loud, including the methodological lesson: **per-BUILD
determinism misread as per-boot randomness** — every future hunt
must pin the blob identity before claiming a reproduction.

### The fix that the artifact exposed (a real bug)

`ring3-preempt` mode 3 registers its SIGUSR1 handler as
`next_instr + 0x947` — hand-measured, because the global_asm
pre-parser rejects rip-relative forms. The handler sat ~770 lines
later, so the delta spanned every mode from 4 to 13: ANY code
insertion there silently delivered SIGUSR1 into arbitrary code.
Now: `sig_handler` lives IMMEDIATELY before mode 3 (the delta is
`next_instr - 0x1f`, spanning only mode 3's own prologue), and
`scripts/check-blob-deltas.py` objdumps every built blob and fails
the build unless the landing is exactly the flag-writer
(`mov $0x51515151,%rax; mov %rax,0x403060`). Wired into boot.sh
right after the blob rebuild; every boot log now carries
"CHECK-BLOB-DELTA OK".

### Gates

3/3 verify boots green with the pin in the build (signal demo green
in all three), `cargo fmt --check` clean, clippy `-D warnings`
clean, host tests 425/0.

### Still open

The original flake — two pristine-tree occurrences (round X's CoW
`parent_ok=0 child_ok=0 copies=1` and round W's mode-13 wait4
loss) — is unexplained, NOT tick-density-correlated, and remains
the next hunt's target (the plan is in ADR-0030's closing section).


## [Unreleased] — ADR-0003 v1 slice 4: execve(59) lands — the image replacement, ELF loader and all

### The slice

`execve(2)` — nr 59 — joins the Linux entry, mapped in the core
whitelist and implemented in the kernel arm in ONE atomic commit
(the slice-3 edge's own rule: never half-map a number to answer a
wrong thing first). What the whole chain does now, live on all three
boot lanes:

- **The registry**: `exec_registry.rs` — the kernel's compiled-in
  executable images, keyed by absolute path (no filesystem until
  Phase 6; a miss answers `-ENOENT` exactly as Linux answers a path
  no filesystem resolves). The first entry is `ring3-exec-target`: a
  REAL linked ELF64 — PT_LOADs at declared vaddrs (text RX at
  0x400000, data RW at 0x403000 with a bss tail at 0x403800), entry
  `_start` from `e_entry` — built by boot.sh (rustc --emit=obj + ld -T
  exec.ld), embedded as ELF bytes, planned at runtime by the host-tested
  core loader (11 elf tests + a registry test that plans the EMBEDDED
  bytes exactly as the kernel will).
- **The arm** (`sys_exec`): read_user_path -> registry resolve ->
  `build_exec_plan` (-ENOEXEC with a typed refusal for every header
  the loader cannot honor) -> `exec_replace` (ADR-0022 D4: mask
  INTERSECTION with the path's declared profile, unlisted = the app
  default; cloexec closes; handlers and regions reset) -> build the
  new image's tables under a SCRATCH OWNERSHIP TAG (`FramePool::retag_owner`,
  host-tested, moves the finished image's frames to the domain so
  every later teardown reclaims them) -> on failure -ENOMEM and the
  OLD IMAGE CONTINUES (Linux parity; the mask stays honestly
  narrowed, documented) -> the new tables ACTIVATE, the old image's
  frames free -> park with a SYNTHETIC image (rip = e_entry, rsp =
  the fresh stack, EVERY GP REGISTER ZERO — a fresh image cannot read
  the old image's registers) -> the dispatcher resumes the exec'd
  image. argv/envp validated canonical, accepted, NOT materialized
  (the wait4-rusage discipline).
- **The lane proof**: the mode-13 linux-abi run now forks a second
  child that execve("/bin/exec-target"); the exec'd image prints its
  own serial marker through fd 1 (which SURVIVES exec), probes its
  own bss byte (zero-filled = the loader's contract, live), and
  exit_group(11); the parent's blocking wait4 reaps it with
  wstatus == 11 << 8. Red pre-change: nr 59 answered -ENOSYS
  (whitelist flip-off), the child died exit(59), the parent's wait
  went wrong (exit 228), the lane halted at the ERROR line.

### Found live, fixed in the hunt

1. **The CR3 order** (the first green boot died SILENTLY): the arm
   runs ON the old tables' CR3 (the SYSCALL entry never switches CR3
   — the kernel half lives inside the user PML4), so freeing the old
   image's frames before the new tables are live scrubs the very
   PML4 the next instruction fetch walks — a triple fault, an
   instant QEMU exit, no diagnosis line, wall-clock varying with
   host load to hide it. The fix swaps + ACTIVATES the new tables
   first, then tears the old image down from the safety of the new
   ones. The instrumented zone prints that found it are stripped;
   the order's comment in the arm carries the story.
2. **The probe's CoW blind spot**: slice 4's probe first reused
   slice-3's wstatus scratch page (r14) — but the SECOND fork marked
   it CoW read-only in the PARENT's own tables, and the wait arm's
   write-range validation refused -EFAULT (exactly the guard slice 3's
   own comment pinned: "a fresh mmap after fork is parent-private").
   The probe now mmaps its own page after its fork (the same rule,
   this time followed by its author).
3. **The parked-swapped image was never re-picked**: exec parks the
   CURRENT run — and pick_next removes the entity it returned from
   the ready set, so the swapped-in image sat parked-runnable-never:
   silence after the child's CoW store. The park re-arms the domain
   runnable itself (nanosleep pins the same rule in the opposite
   direction: set_runnable(false) before ITS park because its wake
   is the timer's).

### Open item (measured, honest — NOT claimed fixed)

**A ~1-in-5 lane flake in the slice-3/preempt interplay, exposed by
slice-4's timing shift** (the +9KB registry blob moved the mode-13
stage's tick phase). Five post-fix pc boots: 4 green, 1 failed at
slice-3's OWN first-fork reap (the child's exit code 7 surfaced
unconsumed by kmain's drain — the parent's wait4 never reaped it;
the failure shape fits a lost wake or a lost completion record in a
rare tick interleaving, NOT any slice-4 code path: every slice-4
step printed green in the failing boot up to the halt). The ADR-0012
ABI note rules out the corrupt-RAX theory (SYSRET costs only the
RCX/R11 pair); the exact interleaving needs its own instrumented
hunt round — the three formal lane logs in the session archive are
green runs; the flake stays on the books until that hunt closes it.

### Gates

fmt/clippy x2 clean; 9 host suites green (346 lib + 11 elf + the new
registry + retag pool test — 368 kernel-side); unsafe 125/125; the
kernel lane boots green on pc, q35, and q35-noiommu with the exec
marker asserted by boot.sh --verify (a new VERIFY gate line).

## [Unreleased] — ADR-0003 v1 slice 4, part 1: the ELF64 loader the kernel arm was waiting for

### Why

ABI-VERSION's slice-3 edge names execve(59) as deliberately unmapped:
"the kernel has no ELF loading machinery yet; the translation lands
with the exec slice, not as a stub that answers wrong." The arm needs
something that does not exist in this kernel: validation of a real
ELF64 static image into an executable mapping plan. The validation is
POLICY, not mechanics — which headers an image may present, which
program headers carry mapping semantics, where every byte must sit —
so it lives in the host-tested core where every refusal gets a test,
and the kernel's arm (next part) only executes the plan.

### The design (src/elf.rs — 11 host tests)

`build_exec_plan(image) -> ExecPlan | ElfError` — pure, no_std, no
allocation, fixed-capacity plans. The open(2) slice-2 discipline: a
feature this loader cannot honor is REFUSED with a typed error, never
silently dropped.

- Accepted: `ET_EXEC` + `EM_X86_64` + 64-bit + LSB; `PT_LOAD`
  segments with page-congruent (vaddr ≡ offset mod PAGE) extents;
  `PT_NULL`/`PT_PHDR`/`PT_NOTE`/`PT_GNU_*` ignored as carrying no
  mapping semantics for a static image.
- Refused, each with its own variant: PIE (`ET_DYN` — the loader
  does not compute relocation bases, and "it would work at the right
  base" is the most tempting wrong answer); `PT_INTERP`/
  `PT_DYNAMIC` (dynamic linkage we do not perform); unknown program
  header types AND unknown p_flag bits (the O_EXCL rule — a future
  ELF feature is not silently dropped); `p_filesz > p_memsz`; segments
  past EOF; zero-memsz loads (reservation is mmap's job, not exec's);
  W+X (the kernel's W^X invariant, refused at load time); zero-perm;
  vaddr 0 and the kernel half; entry outside every PT_LOAD; two
  segments sharing a page (x86 cannot hold two permission sets in one
  page — no correctly-linked static ELF64 asks it); more than
  MAX_SEGMENTS=8 loads (refused, not truncated).
- `ExecPlan.map_bytes` sums the PAGE-ROUNDED extents, not memsz — the
  kernel checks quota before touching a frame, so ENOMEM lands at the
  gate, not mid-copy.

### What is NOT in this part (on purpose)

The Linux whitelist entry (59 -> SYS_EXEC) lands ATOMICALLY with the
kernel arm — mapping the number while the arm answers -ENOSYS would be
exactly the half-ABI the slice-3 note refuses. The arm's chosen route:
the proven parked handover (park the in-flight run with a SYNTHETIC
image — rip = e_entry, rsp = STACK_TOP, every GP register ZERO so the
fresh image cannot read the old image's registers), teardown of the
old image's frames, fresh tables mapped from the plan, and
`Kernel::exec_replace` (ADR-0022 D4: mask intersection, cloexec
closes, regions reset — in the core since round K) for the policy
half.

## [Unreleased] — Phase 0 (round V): the toolchain doctor — three recycles, three truncation modes, one diagnosis command

### Why

The build sandbox is recycled between work sessions, and each recycle
has truncated a DIFFERENT subset of the toolchain: (1) the cargo
binary vanished while clippy stayed; (2) cargo AND the extracted
QEMU root vanished; (3) cargo LOOKED intact but every host-std rlib
was a metadata stub — the first `cargo test` on a CLEAN checkout
failed with 2956 errors. Each hunt cost real time before a single
line of kernel work; the failure never announces which piece broke.

### The fix

- **`scripts/toolchain-doctor.sh`** — the baseline ritual as one
  command. It SELF-DISCOVERS the toolchain (sources the tools env,
  falls back to the rustup toolchain bin, prefers the QEMU wrapper
  — a recycled sandbox starts with a bare PATH, and a doctor that
  needs the env pre-set reports a healthy environment as broken),
  then probes: the four rust binaries answer --version; the HOST
  std actually compiles, LINKS, and runs a Vec-using hello (the
  metadata-stub mode passes any file-existence check — the probe
  that would have named failure #3 in seconds); a #![no_std]
  staticlib for the kernel target links (the lanes' first hard
  stop); QEMU answers --version and both seabios blobs exist.
  `--fix` attempts the proven repairs from the dist components and
  the cached debs. Exit 0 iff every probe is green — wire it ahead
  of any gate in CI or on any fresh sandbox.

### Doc truth, verified

- `wait4` consistency after slice 3: zero stale "not mapped / no
  arm" claims left in ABI-VERSION; README/ROADMAP/CHANGELOG all
  describe slice 3 as landed. (The lane logs and the bundle for
  round U already sit in the session archive.)

## [Unreleased] — ADR-0003 slice 3 (v1): wait4(2) joins the Linux entry — the blocking syscall lands (rip-2 re-execute), on the ADR-0022 D7 core

### The feature

- **nr 61 → SYS_WAIT** — the kernel's first BLOCKING Linux syscall.
  The ADR-0022 D7 core (`wait_process`/`exit_process`, host-tested
  since round K) finally has the arm that reaches it. Linux shape:
  wait4(pid, wstatus*, rusage*, options); rusage accepted and ignored
  (no accounting yet — documented, not faked).
- **The rip-2 re-execute park** (`park_current_reexec`): a not-ready
  wait parks with rip ON the 2-byte `syscall` instruction and rax =
  the ORIGINAL nr read from the frame's own RAX slot — resume re-runs
  the very arm against the completed world it waited for. The
  argument registers ride the image; no wake-time image patching
  anywhere; the park machinery stays ABI-blind (found live: passing
  the TRANSLATED nr parked the image with the internal number, and
  the re-executed entry answered -ENOSYS for a number the whitelist
  never maps).
- **The waiter registry** (park.rs): the blocked parent registers
  BEFORE leaving the ready queue (a preemption window must find it);
  the dispatcher's completion site wakes the exited run's parent via
  `set_runnable` — nanosleep's own block/wake primitive, applied to
  wait.
- **The consume contract**: the re-executed arm consumes the reaped
  child's completed-mailbox entry and runs its full teardown — frames
  via `free_frames_of` (the frame half of `destroy_user`, extracted),
  THEN `exit_process` records the zombie `wait_process` reaps. The
  spawner's drain never sees a consumed child; the mode-13 harness
  expects exactly ONE clean exit (the parent) — the child's honesty
  is the blob's wstatus check.
- **wstatus, byte for byte Linux**: exit → (code & 0xff) << 8
  (WIFEXITED/WEXITSTATUS), kill/fault → the signal in the low 7 bits
  (the fault vector maps: #DE→SIGFPE, #UD→SIGILL, #GP/#PF→SIGSEGV,
  else SIGKILL). WNOHANG honored (nothing-ready answers 0); every
  other option bit refuses -EINVAL (WUNTRACED/WCONTINUED report
  job-control states this kernel does not have — the slice-2 open
  discipline). wait.rs is the pure, host-tested half (+4 tests:
  options/wstatus/ExitKind→ExitStatus/fault-table).

### Found live (the hunt's dividends — four, all fixed in-slice)

1. **Round T's try_take fix landed in the wrong harness**: the edit
   matched the IPC section's textual twin first — benign there (the
   IPC sender always parks before exiting) but MISSING in §24; the
   wait4 parent, which exits without parking when the arm is absent,
   exposed the gap as an identity-less "different count". Moved to
   its true home (with a comment naming the trap).
2. **The translated-nr park**: as above — the re-execute image now
   reads the frame's own RAX (the number the user spoke).
3. **`destroy_user` kills the zombie**: its `destroy_domain` tail
   erases the proc meta, so the arm's `exit_process` after it found
   no meta and no zombie was ever recorded — the parent answered
   -ECHILD forever. `free_frames_of` extracted; the arm composes
   frames → exit_process (the contract's order).
4. **The kernel's direct user-write cannot service a CoW**: the
   blob's wstatus sat on the fork-shared data page — read-only in
   BOTH tables after fork — and the write faulted at CPL0, caught
   by the ADR-0007 guard ("copy escaped the validated span").
   Linux services the CoW for put_user; our discipline is the loud
   refusal: the arm write-validates P+U+W and answers -EFAULT; a
   careful program passes a private page (the blob mmaps its
   wstatus scratch post-fork). Documented in ABI-VERSION.

### Proof

- Red (saved): nr 61 → -ENOSYS → exit 222, read cleanly through the
  relocated try_take.
- Green: **all three lanes** (pc, q35 with intel-iommu, q35-noiommu)
  `BOOT VERIFY: PASS` with the extended
  `[M3] linux-abi: v1 entry live — … wait4(61) WNOHANG/block/reap
  (wstatus 7<<8, then ECHILD) …` marker — the blocking path driven
  end-to-end: park → dispatcher runs the child (CoW + write +
  exit(7)) → waiter-registry wake → re-execute → consume → reap →
  wstatus == 0x0700 → -ECHILD after.
- Gates: fmt, both clippy lanes, unsafe 125/125 (+4, ADR-noted in
  unsafe-count.txt — all in park.rs, the module that owns it; wait.rs
  and the arm are unsafe-free), asm-patterns, no-binaries, IST,
  history-clean; 9 suites (kernel 279: +4 wait tests; lib 346: the
  whitelist table + edge updated — nr 61 moved from the edge to the
  mapped set).

## [Unreleased] — ADR-0003 slice 2 (v1): open(2) joins the Linux entry — the O_* word translates, never passes through

### The feature

- **nr 2 → SYS_OPEN** — the whitelist grows its first syscall whose
  ARGUMENT word needs translation (round S handled shape differences;
  this is a different ENCODING). Linux's O_RDONLY is 0 — the internal
  0 is "no access at all" — so the word must never reach
  `open_flags` raw. `sysabi::linux_open_flags` (host-tested) maps the
  access mode (bits 0..1) to O_READ/O_WRITE, rides O_CREAT (0x40) and
  O_TRUNC (0x200) along, and **refuses -EINVAL on every other bit**
  (O_EXCL, O_APPEND, O_NONBLOCK, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC,
  acc==3): a bit whose semantics the internal VFS cannot honor is
  never silently dropped — O_EXCL's "only create if absent" would let
  a caller open an existing file. O_TRUNC|O_RDONLY dies in the
  internal decoder with the same EINVAL a native caller gets.
- Blob mode 13 grows the probes: create `/pub/s.txt` (O_RDWR|O_CREAT,
  0o644), write the 16-byte pattern, close, **reopen O_RDONLY and read
  it back through an independent cursor**, then the O_EXCL (0xC2) and
  O_APPEND (0x442) refusal probes. Error stubs 213-221 exit_group with
  the probe's identity.
- `wait4`(61)/`execve`(59) stay UNMAPPED, now for the honest reason:
  SYS_WAIT/SYS_EXEC exist in the policy space but the kernel has no
  dispatch arm — they land with the process-model slice, not as stubs
  that answer wrong.

### Found live (the red's dividend): the launch-exit gap

- **A run that exits straight out of launch (never parks) leaves its
  exit in USER_RUN, and kmain's mailbox-only drain never sees it** —
  dispatch_next records only the runs IT resumes. Round S never
  tripped this: the mode-13 parent always parked (sched_yield) before
  exiting. The slice-2 red did: open refused -EACCES (uid 1045 cannot
  create under the root-owned "/"), the blob exited 213 straight out
  of launch, and the harness reported "saw fewer exits" while the
  exit sat in the slot. Fix: the mode-13 harness takes USER_RUN first
  (try_take, the ADR-0026 tolerant twin — the parked flow returns
  with the slot empty) and applies the same verdict/teardown as the
  mailbox drain.
- The blob's path is `/pub/s.txt` — the world-writable subtree, the
  round-J convention (the domain's deterministic uid is 1000+id).

### Proof

- Red: nr 2 → -ENOSYS → exit 213 swallowed by the harness gap
  (saved as boot-pc-open2-RED.txt); after the harness fix the same
  -EACCES exit printed its identity — the gap closed before the
  feature could prove itself.
- Green: **all three lanes** (pc, q35 with intel-iommu, q35-noiommu)
  `BOOT VERIFY: PASS` with the extended
  `[M3] linux-abi: v1 entry live — … open(2) O_* translated
  (O_EXCL/O_APPEND refused) …` marker.
- Gates: fmt, both clippy lanes, unsafe 121/121 (unchanged),
  asm-patterns, no-binaries, IST, history-clean; 9 test suites
  (kernel 275: +2 linux_open_flags decoder tests; lib 346: the
  whitelist table + edge updated — nr 2 moved from the edge to the
  mapped set).

## [Unreleased] — Phase 0 hygiene (round S follow-up): hw.rs unified, docs synced

### The kernel's only mixed-syntax asm file is gone

- **hw.rs: the six port-I/O blocks rewritten Intel → AT&T** — the
  repo convention is att_syntax (every other multi-operand asm! site
  in the kernel already is); the port wrappers were the lone Intel
  holdouts (`out dx, al` → `outb %al, %dx`, `in al, dx` → `inb %dx,
  %al`, ...). Semantics byte-identical; the full pc-lane boot (every
  driver path — serial, PCI config, ACPI, IOMMU, LAPIC — rides port
  I/O) passes with all markers.
- **`hw::rdtsc` DELETED** — a byte-identical twin of `hw::read_tsc`
  (one caller, kmain's boot timing; the monitor/park/preempt/irq/
  clock/ACPI paths all read read_tsc). The unsafe baseline drops
  122 → 121 (shrinking is always allowed; history entry in
  `scripts/unsafe-count.txt`).
- **Two misplaced doc blocks re-homed**: read_cr3's doc had been
  glued into cpuid7_ebx's block (with the N2 monitor-clock paragraph
  that belongs to read_tsc); read_cr4's doc had been glued into
  pic_mask_all's. Each function now carries its own.

### Docs synced to round S

- **ROADMAP** Stage 5 gains the slice-1 status line (the per-domain
  ABI flag, the whitelist, the shape honors, blob mode 13, and what
  is still ahead: open's O_* decoding, execve/wait4, the musl/busybox
  acceptance runs).
- **README** gains the round-S status bullet (the Linux-compatible
  entry) and the stale "v0.3 register table" pointer now names v0.4
  and v1.
- **SECURITY.md**'s in-scope list now covers the v1 entry translation
  itself: a mapped nr that changes meaning, an unmapped nr that
  passes through (Linux 63 = uname vs internal EXIT), or a shape
  mistranslation is a vulnerability, not a bug.

Gates: fmt, both clippy lanes, unsafe 121/121 (ratcheted down),
asm-patterns, no-binaries, history-clean; workspace 9 suites; pc-lane
`BOOT VERIFY: PASS` with every M3 marker.

## [Unreleased] — round S (ADR-0003 slice 1 / ABI-VERSION v1): the Linux-compatible entry

### Added — a domain can speak Linux x86_64 numbers

- **The per-domain ABI flag** (`Abi::Internal` default | `Abi::Linux`,
  supervisor-declared, fork-inherited): resolves the collision ledger's
  ambiguity — nrs below 64 are claimed by both surfaces (internal 13 =
  dup2, Linux 13 = rt_sigaction); the entry now knows which table
  applies. Numbering only: the policy gate runs on internal ids after
  translation either way.
- **The v1 whitelist table** (`linux_nr_to_core`, host-tested entry by
  entry): read/write/close, mmap/munmap, rt_sigaction/rt_sigreturn,
  pipe, sched_yield, dup2, nanosleep, fork, exit + exit_group, kill,
  clock_gettime. **A whitelist, not a pass-through** — the found-live
  edge: Linux 63 is uname, internal 63 is EXIT; unmapped nrs
  (including every sub-64 collision) answer -ENOSYS audited.
- **Shape differences honored**: pipe(2) answers rax=read/rdx=write
  (the x86_64 convention; the internal packed word unchanged); mmap
  demands MAP_PRIVATE|MAP_ANONYMOUS (0x22) — MAP_SHARED/file-backed/
  MAP_FIXED refuse -EINVAL; open stays unmapped (Linux O_* encoding
  differs — the filesystem round, not a mistranslation).
- **Blob mode 13** (`[M3] linux-abi:` marker, all three lanes PASS):
  one domain speaking ONLY Linux nrs — console write, the pipe split,
  the byte round-trip, EOF after the write end closes (D7 via Linux
  nrs), mmap store/load + the MAP_SHARED refusal, the uname(63)/
  getpid(39) -ENOSYS probes, fork + the CoW child store, both sides
  exit_group(0). Red: pre-change nr 22 hit internal SCHED_YIELD —
  the boot hung with zero clean exits.
- Tests: 4 lib (the table, the edge, the targets, the flag's
  default/set/fork-carry) + 2 kernel (the per-ABI selector); lib 346,
  kernel 273, workspace 9 suites; fmt, both clippy lanes, unsafe
  122/122, pc/pi400/q35 PASS.

## [Unreleased] — round R (ADR-0029 D7): the EOF wake

### Added — a parked reader can no longer outlive its writers

- **D7**: two paths end a byte channel's write end and both now
  signal EOF — a parked `AwaitingMsg` owner wakes with **0**, its
  recv_wait returns 0, its next pipe_read reads 0. The capability
  sweep at domain death (the reachable path: the dying domain's last
  channel WRITE cap, no fd refs, no other live writer — the owner's
  own bootstrap WRITE does not count, found live) and the fd-release
  terminal close (one helper behind every close/dup/cloexec/teardown
  site; a no-op by construction until fd-attachment lands — recv_wait
  is cap-gated and pipe() mints no caps, F18).
- Red→green: 3 new tests (writer-death EOF, second-writer negative,
  fd terminal-close no-spurious-wake + read-fd EOF); workspace 410
  green, all gates, pc lane PASS.

### Fixed — the record

- ADR-0028 D2's CoW attribution said "a 4 KiB byte-copy loop" — the
  copy was already WORD-wise (512 u64 volatile pairs); the K9
  handoff's "8× word-copy" optimization candidate was investigated
  and REJECTED with the correction recorded (the ~430k cycles are the
  exception path itself: two page walks, frame alloc, refcount
  release, TLB flush). The stale "byte-for-byte" comment in the CoW
  fix path is corrected too.

## [Unreleased] — round Q (ADR-0029): pipes over endpoints

### Added — the byte channel joins the capability world (ADR-0029)

- `EndpointTable` byte channels: an `Endpoint` is now a message queue
  OR a byte channel (`pipe::Pipe` engine at `CHANNEL_CAPACITY` = 256
  inside it); one monotonic id space, kind fixed at creation, every
  operation checks it (message ops on a channel → `WrongKind`, pipe
  ops on a message endpoint → `NotAChannel` — the type discipline is
  a security property). Two lifetimes: fd-scoped channels reclaim
  their slot when both ends' refs hit zero (Unix pipe lifetime, id
  dead forever); supervisor-created channels live until
  `ipc_endpoint_destroy` (uid 0).
- `SYS_PIPE_READ`/`SYS_PIPE_WRITE` at the internal nrs 30/31 — the
  cross-domain byte path: READ cap + owner to drain, WRITE cap to
  send; short write/read, 0 at EOF, -EPIPE, -EAGAIN; the
  wake-without-consume rendezvous (a parked `recv_wait` owner wakes
  with the byte count, the bytes stay for its own `pipe_read`);
  `recv_wait` on a channel answers the waiting count on the fast
  path. Profiles: bits 30/31 in service, degraded service, and app.
- `ipc_channel_create` (the supervisor bootstrap, owner gets
  READ|WRITE|GRANT) and `live_endpoint_ids` (the hygiene sweep).
- ABI-VERSION **v0.4**: the COMPLETE internal surface (file family,
  time, signals, memory/processes, the IPC family with the pipe pair)
  plus the Linux x86_64 collision ledger (internal 7 vs poll, 12 vs
  brk, 22 vs pipe, 30/31 vs shmat/shmctl, ...) — Phase 5's v1
  renumbering starts from the recorded truth.
- The proof (blob mode 12, the eleventh; the twelfth M3 marker):
  64 bytes cross-domain byte-exact, the no-cap EACCES and full-ring
  EAGAIN live, the rendezvous wake, and the fd round-trip —
  **order-agnostic by construction**, on all three lanes.

### Changed

- `SYS_PIPE`'s two fds now carry the ENDPOINT id; the ambient
  `PipeTable` and `Kernel.pipes` are DELETED (one ring engine, one
  table, one id space; the `pub pipes` test exposure narrows to
  `channel_refs`/`live_endpoint_count`). **No capability is minted**
  — the F18 invariant ("no syscall grows a domain's capability
  table") bent the design, not the invariant: the fd path keeps the
  M1 fd discipline, the endpoint-addressed path is the cap-gated
  cross-domain surface.
- The user code region is TWO pages (`CODE_PAGES` 1 → 2; the proof
  blob crossed 4096 bytes at 3372 → 4484) — the code→data guard gap
  is still a full absent page, layout-test-pinned.

### Fixed — two real bugs the blob's growth flushed out

- `copy_into_frame` assumed the region is physically contiguous (true
  for one page, false for two): the blob's tail ran off the first
  frame into whatever the pool held next — the writer domain died at
  its entry with a P=0 fetch fault (its page-table frame was the
  overflow target). Now page-by-page translate-and-copy.
- The first mode-12 proof pinned its interleaving with yields; a q35
  tick preempted the reader between drain and the EAGAIN probe and
  the writer's next write landed (exit 193). Redesigned
  order-agnostic: wake-value determinism, exact-size FIFO reads,
  bounded polling, program-order no-more-writes, local-only fills
  (the five shapes that survive a tick — ADR-0029 D5's hunt record).

All notable changes to AegisOS. Format: [Keep a Changelog](https://keepachangelog.com/), versions: [SemVer](https://semver.org/).

## [Unreleased] — Stage 1: Ring-3 isolation (in progress)

### Added — M3 Phase 4, slice 4 (round "P", ADR-0028): the honest bench — "measured, not guessed" finally has numbers

The blob itself (mode 11, the tenth proof) times every operation END-TO-END with rdtsc — syscall entry, park, wake, resume: exactly what a real caller pays. A measurer domain runs 16 yields (the park+dispatch floor), 32 call/reply round-trips against a parked responder, one grant through the receiver's own policy, and 4 CoW fault+copy samples; a 63-sentinel retires the responder. The report is SELF-REPORTED: raw TSC deltas in hex through SYS_WRITE (a tiny in-blob formatter; the kernel cannot read the page after the run dies), with the kernel's ACPI-calibrated tsc_hz printed beside. `scripts/bench-decode.py` converts; boot.sh gates all three lines.

**The numbers (QEMU, 2.5 GHz calibrated; ratios are the transferable truth):** park+dispatch floor **2.0 µs**; call/reply RTT **46 µs** avg; grant (whole path, one page) **42 µs** — the same order as a full RTT, both dominated by the park/wake machinery rather than their own work; CoW fault+copy **172 µs** avg — ~4 RTTs: the exception path plus a 4 KiB copy under a fault-and-resume.

### Fixed — M3 Phase 4, slice 4 (round "P", ADR-0028): two architectural holes the bench's call storm found live

- **A dying run must never be preempt-parked.** The exit arm sets `run.exit`, ticks the window clock, then resumes the kernel — and a tick in that window could park the half-dead run as not-runnable and resume its user RIP past its own exit syscall; the completion mailbox never saw it. The structural hole: `ExitKind` had no "alive" variant (the default was `Exited(0)`). Now `ExitKind::Running` is the spawn default and the tick's Switch path KEEPS a run whose exit is written — it finishes dying.
- **The park-unwind rule (bounded dispatch nesting).** Every park nested a full `dispatch_next()` — a server parking once per request added a dispatcher level per request (chain stack depth 8, then the kernel stack). An inner park now returns to the CURRENT level's loop through the resume slot (its label is already there; the loop's try_take sees None and just loops); only a flat-launched run's first park starts a dispatcher. Depth ~1 forever; request loops of any length run in one level.
- Three hunt lessons kept in the ADR: check your code is REACHABLE before hunting register ghosts (the bench domains ran mode-1's writer for fifteen boots — a dispatch line an edit silently dropped); debug probes owe the same SMAP discipline as production code (a probe's unguarded user read faulted the kernel); verify constants against their bytes ("[BNECH]" — the metrics were perfect while the gate refused the label).

### Fixed — M3 Phase 4, slice 3 (round "O", ADR-0027): the ADR-0024 D2 exit leak — found live, closed loudly

Every boot since the fork round printed `[MM] teardown domain 27: freed 5 of 9 owned frames` and nobody asked why. A dying domain released the refcounts of frames it POOL-OWNS (the reclaim path) but never the refcounts of frames it MAPS BUT DOES NOT OWN — the fork child's side of every still-shared page: four pages per fork proof leaked (stuck at refs=1 after the parent's death, never returned to the pool). Designing the grant's exit path found it; the fix is the grant's precondition. **The rule**: on SYS_EXIT, walk the dying run's user PTEs and release every frame whose shares entry names another owner (`owner_of(pa) != me` — the borrowed mappings: fork-shared-from-parent, granted-in); release-to-zero frees under the ORIGINAL owner's tag, exactly as reclaim does. The two rules are disjoint (`== me` is reclaim's). **The gate**: boot.sh now FAILS any boot with a `[MM] teardown` line — every future accounting bug is a boot failure, not a log line. A second latent hole closed with it: munmapping a shared page used to pool-free a frame another space still maps — `sys_munmap` now comes through the shares-aware source.

### Added — M3 Phase 4, slice 3 (round "O", ADR-0027): page grants — memory capability transfer over the ADR-0024 accounting

One domain can now CONFER a page on another, explicitly, capability-gated — the bounded first slice of ADR-0024 D4's deferred "shared mappings between live processes".

- **`ipc_grant_frames(dst, va, len)`** (internal nr 29): the caller's `[va, va+len)` mapped RW into the receiver's space through the RECEIVER'S OWN ten-check policy (quota and overlap apply — a grant cannot smuggle memory past a quota), every leaf PTE pointing at the granter's frame, refcount acquired per page immediately before its PTE write (rollback releases exactly the mapped ones). RW-only is HARDWIRED — a granted page never arrives executable. The bound: 1..=64 pages, the refcount table's own `MAX_SHARED`. The return: the VA where the frames landed in the receiver.
- **The gate** (core, host-tested): a Domain capability with WRITE on dst — the kill pattern — plus a supervisor conferral API `cap_grant_domain_to(sup, holder, target)` (the `ipc_endpoint_grant` shape for domain caps: a privileged, auditable bootstrap; spawned domains have derived non-root uids, so the self-grant API is not their path).
- **The grant composes with the sync IPC**: the granted VA travels to the receiver as two 6-bit messages (the IPC bound is 64 — a raw address half refuses; the page number fits 12 bits), and the reply confirms the read — grant + call/reply in one proof.
- **The proof** (blob mode 10, the ninth marker): the granter mmaps a page, writes a pattern, grants it; the grantee — woken by the rendezvous — reads the pattern THROUGH the grant, writes its mark, replies (with a bounded EAGAIN retry: the tick may run the grantee ahead of the caller's park — the transient truth, not an error). The granter's `call` returns the reply and its OWN page carries the mark: bidirectional shared memory, both directions verified. Marker: `[M3] grants: 1 page RW, the grantee read the pattern and the granter saw the reply-write`.
- **The lifetime invariant** (the fork accounting, unchanged): the refcount counts every reference including the owner's implicit one. Either side may munmap (its release drops one ref); either side may exit (the D2 rule above); the grant OUTLIVES the granter. No revocation, no grant chains tested — documented, not faked.
- Host tests: the gate (no cap → PermissionDenied with the escalation counted; the conferral passes it), the dead-grantee ESRCH, the length bound (0, unaligned, 1-past-capacity refuse; exactly 64 pages pass).

### Added — M3 Phase 4, slice 2 (round "N", ADR-0026): sync call/reply over the park machinery — the rendezvous, ring 3 to ring 3

Domains BLOCK on each other now: `call` parks the caller until the owner replies, a blocking `recv` parks the server until a request arrives. One blocking mechanism, three users (sleep, yield, IPC rendezvous) — all through the same `set_runnable` F12-floor path and the same park table.

- **The three arms** (internal nrs 26/27/28, the ADR-0025 ABI-VERSION note): `ipc_call(channel, len)` — the WRITE gate, the same bounded push as send (sync is not a privilege around capacity), then the caller registers awaiting-reply and blocks; the reply patches the parked image's RAX so `call` RETURNS the reply len. `ipc_recv_wait(channel)` — the owner's blocking recv: a waiting message pops NOW (the async recv verbatim, no park), an empty queue parks until a push rendezvouses. `ipc_reply(channel, len)` — READ+owner; answers the OLDEST waiting caller (FIFO by a monotone seq); no waiter → -EAGAIN (the transient truth). All three keep the cap gates and the owner checks of the async pair.
- **The rendezvous rule** — one clause unifying sync and async: a push (send OR call) onto an endpoint whose owner is parked in recv_wait consumes the message the moment it lands (pop-what-you-pushed; the queue only ever holds the async backlog). FIFO-safe by invariant: an AwaitingMsg waiter implies the queue was empty at park time and every push since rendezvoused.
- **The wake-value plumbing** (the layering rule): the core decides — a small wake list of (domain, value) pairs filled by the reply/rendezvous executors, host-tested; the kernel applies — after every waking syscall (send/call/reply), the syscall layer drains the list and patches each parked image's RAX (`patch_parked_rax`, the `gprs[14]` slot `parked_from_syscall` built from the syscall's `result`). The drain runs BEFORE any park in the same arm: the woken owner's image must be patched before the dispatcher can resume it. Unsafe baseline 118→119 (the ADR-referenced raise).
- **The proof** (blob mode 9, the eighth marker, every lane): a caller and a callee trade TWO round-trips, and BOTH halves of the unified contract fire DETERMINISTICALLY — the blob's yields pin the order, no luck: exchange 1 through the RENDEZVOUS (the callee parks in recv_wait before the caller's call; the push self-consumes; the callee wakes with the request len), exchange 2 through the QUEUED fast path (the callee yields between reply and the next recv_wait; the caller's call lands while nobody waits — the message queues; the callee's recv_wait pops it, no park). The caller's call returns exactly the reply len; the callee's reply wakes exactly one waiter. Marker: `[M3] sync: 2 round-trips, call blocked and returned both replies, recv_wait returned both requests` — green on the FIRST boot.
- **Host tests** (8 new, the M2 discipline — core semantics tested host-side): call blocks + FIFO among two callers; the recv_wait fast path; the empty-queue park + the send rendezvous (the message self-consumes, the queue stays empty); the CALL message rendezvousing too; reply-with-no-waiter EAGAIN; destroy clears the wait; a second call replaces the first (one wait per domain); the sync arms keep the READ/WRITE/owner gates.
- Profiles: service (and its degraded tier) gain the three bits — a degraded server must still answer its clients.
- **Not this round**: reply channels as separate endpoints (the reply rides the caller's endpoint — one cap, one gate), call timeouts (a stuck server blocks its caller; the honest answer today, same as Unix read on a pipe), multi-word payloads (the len IS the message this round, as in ADR-0025).

### Added — M3 Phase 4, slice 1 (round "M", ADR-0025): async IPC at the ring-3 ABI — the proof green, and three machinery finds with it

Domains talk, capability-mediated, from ring 3 for the first time — the M2-era async endpoint core (ADR-0004) was never reachable before this round.

- **The proof** (blob mode 8, three domains, every lane): a uid-0 supervisor (created, grants, then UNREGISTERED — a never-running domain must leave the scheduler) creates three endpoints — A owned by rx1, B by rx2, C never granted to the sender — and grants the sender WRITE on A and B. The sender opens with a YIELD (the resume chain must be set by a real resume_parked before any receiver can exit through the tick path), fills both 4-deep queues until -EAGAIN, proves the no-cap send to C refuses -EACCES, and parks; the receivers — stashed parked-runnable, resumed by the nested dispatcher — drain with bounded poll loops (yield on empty; the EAGAIN counts only after ≥4). Every exit lands in the completed mailbox; kmain drains, verifies, tears down. Marker: `[M3] ipc: 8+ messages over 2 channels, caps enforced (EAGAIN + the no-cap EACCES), both ends verified`. The interleaving is the scheduler's business — the proof pins the CONTRACT (caps, bounded queues, lengths, refusals).
- **The ABI arms**: `SYS_IPC_SEND(channel, len)`/`SYS_IPC_RECV(channel)` at the INTERNAL nrs 7/8 (Linux 7=poll/8=lseek never spoken by blobs — the mmap-style collision note, recorded for Phase 5's ABI-VERSION table), marshaled into the core's existing capability-gated executors; EAGAIN/EINVAL/EACCES through the existing sysabi table. The errno contract pinned live: PermissionDenied → -EACCES (EPERM is the mask/quarantine errno) — the blob expected the Unix mnemonic and exited 136 until the probe printed the actual refusal.
- **The three machinery finds** (each tripped by the kernel's own loud guards, each fixed structurally — the hunt is recorded in ADR-0025):
  1. `try_take` (context.rs): `dispatch_next` assumed `resume_parked` returns only on EXIT. A run the dispatcher ITSELF resumed can YIELD (the receivers' poll loops) — the nested `park_current` takes USER_RUN on its way out, and the outer loop came back to an empty slot ("user run state missing on take"). The tolerant twin reads the slot without panicking: an exit records, an empty slot continues. Unsafe baseline 117→118 (the ADR-referenced raise).
  2. The park-chain STACK (context.rs): the nested dispatcher's saved outer chain was ONE Option — correct while only flat-launched runs ever yielded (the cow proof's shape), but a dispatcher-resumed run that yields nests a SECOND dispatcher whose entry save overwrote the outer chain; the inner unwind consumed the only copy and the outer unwind found nothing ("unwind with no saved chain"). Now a depth-8 stack beside the proven slots; overflow is a boot bug, caught loudly.
  3. The supervisor unregister: a never-running domain (the endpoint bootstrap) sits runnable in the scheduler, and the next yield/tick picks an unparked domain ("yield/sleep picked unparked domain 31").
- **Not this round** (ADR-0025 D4, each its own): the sync call/reply fast path (a blocking rendezvous over the park machinery), page-grant IPC (now easy over ADR-0024's refcounts), pipes-over-endpoints, and the 100k ping-pong bench (the acceptance number was written for real hardware; the bench round will measure honestly per-host).
- Tests: no new host suites — the executors were host-tested in M2; the round's work is the ABI wiring and the lane proof (the proof IS the test). 661 total unchanged. ABI notes: IPC at the internal nrs 7/8; the blob's mode-8 data page carries the role byte + the three channel qwords, baked by the bootstrap through the direct map.

### Added — M3 Phase 3 (round "L", ADR-0024): the memory round — mmap at ring 3, copy-on-write fork, and the physical-access rules

Processes get memory of their own, fork gets its memory half, and the kernel's physical window gets its rules written down. Five commits (the first three landed in round K4's session; this round closed the proof); every marker runs on all three boot lanes.

- **The pure root** (`src/frame_share.rs`, `AddressSpace::find_free_window`): per-frame reference counts carrying the frame's ORIGINAL pool owner (the pool validates ownership on free — a fork's child frees an inherited frame under the ancestor's tag), with the insertion semantics the fork/reclaim model test caught before any kernel run: a private frame becoming shared starts at TWO references (the original holder + the new sharer); inserting at one would let a single release free a frame another address space still maps. `cow_decision` — the pure truth table, pinned by EQUIVALENCE over all 384 combinations: the Copy family fires exactly when (present ∧ user ∧ PTE-read-only ∧ region-writable ∧ write) and a refcount exists, splitting by the count: refs>1 → **Copy** (another address space still maps the original), refs==1 → **Promote** (found live: the first sibling's copy drops refs to one, and the second writer's identical fault was refused by the refs>1 premise — the last holder re-enables write IN PLACE, no copy, no allocation). The window allocator: the lowest policy-acceptable window at/above a floor, allocation-free (a hop loop), deliberately quota-BLIND (the allocator proposes VA, the ten-check policy refuses budget — the layering is pinned by its test).
- **Anonymous mmap/munmap at the ring-3 ABI**: the gate ran since round F13 while SYS_MMAP answered -ENOSYS; now the execution is REAL — PROT bits decoded (unknown bits -EINVAL, page-rounded length), addr==0 picks the lowest window at/above the trampoline, a nonzero hint is honored or refused (never relocated), the mapping goes through the SAME ten-check-gated rollback-on-failure mapper spawn uses, every frame pool-allocated with `owner = run.domain` (exit reclaims through the reclaim walker, munmap through the owner-scoped free). munmap is WHOLE-REGION (exact base, exact length; splitting is Phase 5+); the spawn-time layout lives below the window floor and refuses at the ABI (teardown frees it, not the syscall). Marker on every lane: `[M3] mmap: 2 windows mapped+verified, munmap freed, the freed read faulted at cr2=0x412000`.
- **fork's memory half**: `PageTables::clone_for_fork` — the whole user-half tree cloned top-down (writable pages copied READ-ONLY into the child: the demote marker; every shared frame acquired; the SHARED KERNEL HALF PML4[256..512] copied verbatim — found live: without it the child's CR3 has no kernel half and the first kernel access under it faults at a half-present address; huge leaves in the user half refuse), rollback by walking the partial tree (the parent is untouched until the allocation-free demote pass), then the parent's writable PTEs demoted with per-page invlpg. `sys_fork` (Linux nr 57 → the core's SYS_FORK): round K's fork_process (masks/caps/fds/creds) + the clone + the child stashed parked with the parent's syscall image and RAX=0. The fault path's first RECOVERABLE user fault: `try_cow_recovery` — the pure decision, then one private frame + one page copy + one PTE repoint + one release + one invlpg (Copy), or one PTE re-promotion (Promote), and the handler simply RETURNS (the iretq re-executes the faulting instruction). A CPL3 fault in the kernel half is never ours (walking user tables for a kernel VA would descend into the direct map's huge leaves and read them as page tables — found live, panicked in pa_to_va; guarded at the top). Shares-aware teardown: destroy_user's blind `free_all_owned` becomes `reclaim_domain_frames` (per frame: shared → release, freeing on the last under the ORIGINAL owner; private → free) with a loud mismatch line if anything leaks; `SharedSource` makes munmap's frees consult the table. The proof (blob mode 7): mmap a page, write the parent pattern, fork, the PARENT YIELDS (deterministic — a tick stealing the child mid-run races the exits), both sides write through the demotion (the child's Copy + the parent's Promote), both exit clean into the completed mailbox, kmain drains and reclaims. Marker on every lane: `[M3] cow: fork shared, 2 CoW copies served, both exits clean, frames reclaimed`.
- **THE SYSCALL LESSON** (the one this round will be remembered for, two commits' worth of hunt): reading the user's callee-saved registers LIVE at dispatch depth reads the COMPILER'S SCRATCH — SysV makes every callee preserve rbp/r12-15, which means the user's values live in the callees' stack frames, not in the registers; the yield path's parked images carried compiler scratch as user state and the resumed parent wrote through r12=3. The stub now parks the five AT ENTRY (`USER_RBP/R12-R15`, the USER_RSP_SAVE discipline; SYSRET needs no restore), both park paths read the slots, and `live_callee_saved` is DELETED — wrong by principle, gone so nobody can reach for it again (unsafe baseline 120→117). The syscall stack grew 2 → 8 pages in the same hunt (the fork path's dispatch depth — Domain::forked's ~3.5 KiB frame — measured past 8 KiB and the GUARD caught it exactly as F15 built it to). The nested dispatcher's saved outer chain moved from a park-module static to the proven context-entry slot (beside RESUME_RIP/PARK_*).
- **The physical-access rules, restated in one place** (`mm/direct_map.rs`, ADR-0024 D3): the 1 GiB direct map is the MEMORY MANAGER's window — the kernel itself (page-table walks, scrubs, copies), nobody else: the identity map is DEAD (PML4[0]=0, asserted by read-back, the `identity=pml4[0]:0` boot line), devices reach memory only through the DMA broker's cookies (IOMMU lanes) or pool-owned identity frames (the no-IOMMU degradation), ring-3 only through the ten-check policy's PTEs. The per-owner windowing question reopens with driver isolation, and the doc says so.
- Tests: +3 suites this round — `tests/frame_share.rs` (the refcount lifecycle with owner provenance, the underflow/overflow/table-full refusals, the truth-table family including the Promote split, both allocator suites), `tests/fork_reclaim.rs` (the 600-op deterministic fork/exit churn against the real core + the real refcount table, ending with every frame reclaimed and the table empty; the original-owner free pin), and the kernel's +0 host (the page-table/fault paths are lane-proven). 661 total (390 lib + 271 kernel). ABI notes: mmap/munmap at the INTERNAL nrs 4/5 (Linux 9 collides with NET_SEND), fork at Linux 57; the full renumbering is Phase 5's ABI-VERSION v0.4 table.

### Added — M3 Phase 2 (round "K2", ADR-0023): preemptive ring-3 multitasking — sleep, the calibrated clock, and signal frames

The scheduler becomes a real one, and ring-3 learns to wait, tell time, and receive signals. Four commits, each with its red-then-green proof; every marker runs on all three boot lanes (pc / q35 / q35-noiommu).

- **Sleep, wake, and yield in the policy core** (`Kernel::sleep_until/wake_due/sleepers_due/sleeping`, `Preemptor::on_yield`): a bounded `[(domain, wake_at)]` table in the SAME unit-agnostic time base `tick()` speaks (the core never learns what a TSC is); a second sleep REPLACES the first, zero cycles is a plain yield, an overflowing span refuses with a typed `InvalidArgument` (a deadline that can never be reached would be a lost wakeup); wakes go through the scheduler's wake path so the min_vruntime floor holds — a long sleep buys no priority. `tick()` now runs the wake pass on EVERY tick (audits stay window-gated, wakes are not), teardown cancels a dying domain's sleep, and yield charges the slice IN FULL — volunteering must not buy priority; a yield-loops-forever domain earns nothing but its own spin. `SYS_NANOSLEEP=21`/`SYS_SCHED_YIELD=22` gate bits on service+app (the degraded tier gets neither: starting nothing new is its philosophy).
- **The ADR-0012 starvation-freedom proof left its feature gate**: the two-run proof (spinner 20 vs writer 21) runs in the DEFAULT boot on every lane — `[M3] preempt: 2 runs interleaved (switches=N), hog starved nobody` (measured: 9/9/9 switches across the three lanes; the release+LTO named-static workaround held everywhere). `PARKED` grows to `MAX_DOMAINS` (32): the parked table IS the run queue's storage. The ungating surfaced a real race on q35 — a timer expiry that lands while the kernel runs IF=0 sets IRR=48, and a delivery window's LVT mask gates NEW expiries but cannot retract an already-set IRR; the window's sti delivered it as a CPL0 timer frame and the tick guard halted. The guard gained exactly one carve-out: a CPL0 frame while the timer is MASKED is the stale pre-window tick — EOI'd and dropped, never switched; an UNMASKED CPL0 tick remains the loud halt.
- **The calibrated clock, nanosleep/yield/clock_gettime at the ABI, and the guarded idle state**: `clock.rs` holds ONE frequency for the whole kernel (the HPET measurement from the ACPI walk via `set_calibrated`, or the documented 2.5 GHz fallback — q35 lanes print the true measured 2445 MHz, the pc lane honestly prints "fallback cadence", and the sleep proof still verifies there because sleep and clock read the same number). The ABI translation seam (Phase 5's table, first three entries): sched_yield(24)→22, nanosleep(35)→21, clock_gettime(228)→23, translation BEFORE normalization so 228 survives the bounds check; the timespec is read ONCE page-checked under the SMAP window, unrepresentable spans refuse, CLOCK_MONOTONIC == CLOCK_REALTIME (no RTC wiring — documented, not faked). `sched/park.rs` parks a run from INSIDE a syscall: the entry publishes the in-flight frame's address; the park path rebuilds the user image through the OFF_* table. The idle state (`preempt::idle_hlt`: flag, sti, hlt, cli) with the tick handler's second CPL0 carve-out — the idle hlt is the one legal CPL0 tick, wakes landing inside `Kernel::tick`. Markers: `[M3] sleep: idle engaged (hlt cycles=11), 100ms wake landed on time, exit 0` and `[M3] clock:` on every lane.
- **Ring-3 signal frames** (`src/sigframe.rs` pure + host-fuzzed, `Delivered` on the run, the trampoline page): `rt_sigaction` installs a disposition (signum 1..=63, KILL/STOP never catchable; the restorer must be THE trampoline — a fixed RX page mapped into every user space carrying `mov eax,15; syscall; ud2`); `fork` copies the handler table, `execve` CLEARS it (POSIX). Delivery at BOTH kernel→user boundaries — the syscall tail (the stub frame rewritten in place; the interrupted image, syscall result included, rides the pushed 128-byte frame) and the unpark path (the `ParkedContext` rewritten before `resume_parked`); a tick-switch wake defers delivery to the woken run's next syscall. `rt_sigreturn` is ENTRY MACHINERY, handled before the policy gate (the authority was exercised at sigaction/delivery; documented) and re-validates EVERY user-supplied field against the kernel's own delivery record — the cookie, the exact frame address, the selectors, canonical rip/rsp, and the rflags a user frame may never choose (IOPL/NT/VM/RF/TF stripped): a forged or displaced frame refuses -EINVAL, never a panic, never an unsanitized restore. The pure module's bit-flip fuzz pins that every mutation of a valid frame either validates to a sanitized image or refuses typed. `kill(62)→SYS_KILL` marshals into the core executor (capability gate first, Unix rules second — unchanged). Marker: `[M3] signal: handler ran, sigreturn resumed, forged frame refused` — the victim installs a handler and sleeps 200 ms, the killer (granted `Domain(victim)` WRITE + uid 0 by the bootstrap; the capability gate still applies) strikes mid-sleep, the victim wakes through the IDLE path, the handler runs, sigreturn resumes the interrupted code, the in-blob flag check passes; a separate forger calls rt_sigreturn with a garbage stack and its clean exit certifies the refusal.
- **The nested dispatcher learns to unwind** (`sched/park.rs` + `ResumeChain` save/restore in `sched/context.rs`): `resume_parked` RETURNS when the resumed run exits (the kmain-handover shape, one level deeper); exited runs land in a completed mailbox (resource teardown stays the SPAWNER's contract — kmain drains on regaining control; the scheduler settles immediately), and when nothing is runnable and nothing sleeps, the saved chain restores kmain's launch point so `resume_kernel` unwinds home. Two hard lessons, both found live and both in the commit messages: the `SyscallFrame` STRUCT is the mirror image of the push order (field i sits at 88−8i from the post-push RSP — a `&`-cast onto the base pointer reads every field from the wrong slot; the first boot resumed a parked run at the nanosleep `rem` pointer, an NX data address, until the reads moved to the OFF_* table), and the kernel stack is SHARED (the stub reloads `SYSCALL_RSP` on every syscall), so state that must survive excursions lives in .bss statics — a frame-local resume chain was overwritten by the resumed runs' own syscalls and the unwind jumped through packed domain ids (caught via `qemu -d int` reading the corrupted SP).
- Tests: +16 host this round (9 in `tests/sleep_wake.rs` including the deterministic 600-op random sleep/tick/exit simulation — no lost wakeup, idempotent double ticks, full-teardown conservation — plus the yield-loops-earn-no-priority alternation; 7 in `src/sigframe.rs` including the bit-flip fuzz) and +8 kernel (clock's pure-math/parse suites, the frame-to-parked mapping pin, the fallback mirror, the trampoline layout rows) — 385 lib + 271 kernel = **656 total**. unsafe baseline 101→114 across the round, every raise ADR-0023-referenced (the park path's register reads and frame deref, `hw::hlt_once`, the ResumeChain save/restore, the SAVED_CHAIN static borrows).

### Fixed — round "K2"

- **The cutoff commit shipped past clippy**: `sigframe::build` is unit-returning by design (the out-param is the output) — the `#[must_use]` was wrong; `pop_catchable_signal`'s pending-but-uncaught early return collapses into an `as_ref()?`. Plus three kernel-side lints in `park.rs` (a needless paren pair, a block-wrapped scrutinee) and one test NAME containing the literal token "unsafe" that tripped the policy-core scanner — renamed, not allowed.

### Added — M3 Phase 1 (round "K", ADR-0022): the process model — spawn, fork, exec, wait over the domain table

- **The process table** (`src/proc.rs`): pids that never repeat within a boot (a monotonic counter from 100; supervisor static ids keep 1..=99, PID 1 is init) so every stale wait/kill handle fails closed forever instead of hitting an unrelated successor; a meta slot for every process living or zombie (zombies hold their slot until reaped — the budget a fork bomb feels); `ExitStatus` with Normal/Killed/Fault reasons; and the init-owned `ExecPolicyTable` (exact-path declared surfaces, unlisted binaries get the new `app_profile` under AuditOnly monitoring — Enforce is opt-in per binary, the usability guard).
- **The lifecycle, in the policy core** (`Kernel::spawn_process/fork_process/exec_replace/exit_process/wait_process`): spawn with EXPLICIT-only inheritance (the fd_map is everything the child receives — no ambient fds, no ambient caps; the child's caps are attenuated copies `parent ∩ request.base_rights`, excluding anything aimed at the parent) and fail-closed profile validation against the parent's CURRENT surface (wider requests are refused and counted as escalation attempts — live mask, so a tightened parent spawns tightened children); fork as a copy that can only shrink (live mask, caps minus the parent-aimed ones, fd table with positions and cloexec flags, credentials, jail; pending signals and behavioral accounting start clean; the self-signal cap is structural like SYS_EXIT); exec as INTERSECTION (the live mask ∩ the declared surface, EXIT unalienable, cloexec fds close with their pipe references, the region ledger resets while the quota survives); exit as teardown-plus-zombie with orphan reparenting to init — a living init is the reaper of last resort even for parentless exits, and with no reaper anywhere the status is discarded, never leaked.
- **`cloexec` is real on `FdEntry`** (round K's forward-pinning): the flag lands now with fork-copies/exec-closes/dup-clears semantics host-tested, so the Phase-5 fcntl ABI cannot invent them later.
- **Capacity**: `MAX_DOMAINS` 4 → 32 and `MAX_SCHED_ENTITIES` 8 → 32 (the driver-stack ledger's scale-reality row) with the fill/refuse/drain/reuse capacity self-test; the process meta table rides the same bound.
- **Proof**: 31 new host tests (26 in `tests/proc_model.rs` + 5 unit in proc.rs): pid monotonicity and typed exhaustion, explicit-fd inheritance, spawn/fork/exec attenuation refusals with the escalation counter, fork copy fidelity, zombie→wait (specific/any/ECHILD), orphan reparenting and the no-reaper discard, the children limit (zombies included in the budget until reaped), meta-table exhaustion, the random-tree property (every birth ⊆ parent; every mask ⊆ every ancestor's birth ceiling — an ancestor narrowing later is not a violation, exceeding a ceiling is), and a 400-op deterministic lifecycle fuzz that ends with every domain slot, meta slot, pipe and scheduler entry home. 362 lib + 265 kernel = 627 total.

### Fixed — round "K"

- **The irq test suite raced itself** (`kernel-x86_64/src/irq.rs`): the SLOTS table is a process-wide static and cargo runs tests in parallel — a sibling's `reset()` released slots mid-assert. Latent forever (lucky scheduling) until ADR-0022 grew the Kernel struct enough to shift thread timing; pinned with a module test lock, verified across three consecutive full runs.
- **The ring3-rogue audit-only spam recalibrated** (`examples/ring3-rogue`): MMAP left the mode-3 forbidden list because ADR-0022 moved MMAP/MUNMAP/FORK/EXEC/WAIT INTO the service surface — an allowed-but-ENOSYS syscall halves the denied-ratio signal (measured: the audit-only score fell to 64 against the 65 quarantine threshold, one point short, and the audit-only lane caught it exactly as designed).

### Added — review round 10 ("J"): the ring-3 file lifecycle — the syscall surface crosses the fd line

- **The file family executes on the LIVE lib kernel** (`kernel-x86_64/src/syscall.rs` + the new `sysabi.rs`): OPEN, READ, WRITE, CLOSE, PIPE and DUP are marshaled from the six-register SYSCALL convention into the lib's `SysRequest` values and run through `Kernel::execute` — the same domains, fd tables, pipes and VFS the behavior monitor reads. The runtime gates first (`dispatch`, where the used-bits/denial accounting lands exactly once) and only an Allowed reaches the executor: the lib's `syscall` was split into gate + `execute` for exactly this seam, and the split's contract (execute NEVER gates; the caller must) is host-tested by watching the parser profile's masked OPEN both ways.
- **The ABI layer** (`kernel-x86_64/src/sysabi.rs`, pure + host-tested): the open-flag decoding (O_READ/WRITE/CREAT/TRUNC; unknown bits and O_TRUNC-without-O_WRITE refuse -EINVAL), the complete `SysError → errno` table (every lib refusal keeps a distinct Linux meaning — 40+ variants pinned one by one), the pipe fd-pair packing into the single RAX the naked entry returns (`(w << 8) | r`), and the file-family number table pinned against the lib's constants. `docs/ABI-VERSION.md` now carries the full v0.3 register table.
- **The copy-OUT primitive** (`mm::user_range::copy_out_bytes` + `memops::write_u8_va`): SYS_READ's byte-exact mirror of the PR-1.4 copy-in — validate every covering page through the domain's own tables first, execute into a KERNEL buffer (the user pointer is read once for validation and never again — no double-fetch), then write the bytes out under the single blessed SMAP window. `read_user_cstr` reads SYS_OPEN's path page-check-as-you-go: a short string before an absent page succeeds, a missing NUL within 128 bytes is -ENAMETOOLONG, and the walk's page checks are exact (a string ending at a page boundary never asks about the next page — host-tested with a counting map).
- **The stdio triplet** (`Kernel::reserve_stdio` + `FdTarget::Reserved`): a spawned domain's fds 0/1/2 belong to the runtime, Unix-style, so the domain's own pipe()/open() allocations begin at fd 3 and the console device alias behind fd 1 can never collide with a real fd-table entry. Reserved slots refuse I/O through the policy core (`SysError::Reserved` → -EIO) but close and dup like plain entries — closing one frees it for allocation again (all host-tested, including the reservation refusing to shadow a real target).
- **The proof blob** (`examples/ring3-files`): the full Unix dance from CPL=3, every answer checked IN the blob — pipe() → (3,4); a pipe round-trip with byte-verified read-back; dup keeping the read end alive past its original's close (the second message arrives through the survivor); open(O_CREAT)/write/read-back through the duplicate's independent cursor (the snapshot-pos semantics the lib documents); close of the original with the dup reading EOF; and the three errno refusals (-EBADF on a never-open fd, -ENOENT on a missing path, -EBADF on the closed pipe end). Exit 42 only when every step verified; the boot asserts it plus write_bytes=101 (every byte the run contributed), and the J:pipe/J:dup/J:file/J:neg console markers are grepped by `boot.sh --verify`. kmain prepares /pub world-writable through a kernel-resident uid-0 supervisor first — the init-prepares-/tmp pattern.
- Host tests: +5 lib (stdio reservation, Reserved I/O refusals, the gate/execute split contract, and the files blob's phase-F sequence replayed on the host — the same supervisor//pub/domain shape the boot runs) and +9 kernel (sysabi's five tables, the copy-out bounds, the cstr reader's three behaviors) — plus the three resurrected syscall-module tests below — 331 lib + 265 kernel = 596 total.

### Fixed — review round 10 ("J"): two hidden debts of the ring-3 path, found the way they always are

- **SYSRET never restored the user RSP** (`arch/syscall_entry.rs`): SYSRET restores only RIP/RFLAGS (from RCX/R11), and the stub switches RSP to the kernel stack on entry — so every sysret since PR-1.4 returned to ring-3 code running on the KERNEL's stack pointer. Invisible for the whole seven-run sequence because every earlier blob is pure register code that never touches its stack; the files blob's verify subroutine (the first `call` in ring-3 history) pushed its return address through a kernel-half RSP and faulted with the full record printing `rsp=0xffffffff40002ff8`-shaped values. The stub now parks the user RSP before the stack switch (`USER_RSP_SAVE`, the same single-CPU/no-nesting lifetime as `SYSCALL_RSP`) and reloads it as the only RSP restore before SYSRETQ. The saved-register contract in the module docs now says so explicitly.
- **The syscall module never ran its own tests** (`kernel-x86_64/src/main.rs`): an outer `#[cfg(not(test))]` sat on `pub mod syscall`, compiling the whole module — its three host tests included — out of every `cargo test` run ever taken. The tests' missing `SyscallMask` import had been invisible for exactly that long; removing the outer gate (the module's target-only `mod exec` is internally gated, as designed) put all three back on the host, and the import was fixed. The kernel host count jumped 253 → 262 before round J's own tests even landed — the count had been quietly lying by three.
- **The boot stack was 1.6 KiB from its own guard page** (`kernel-x86_64/linker.ld`): the driver-stack call chain (kmain → driver_stack_step → the per-driver steps, with their multi-KiB inventory frames) bottoms out barely 1.6 KiB above `stack_bottom` — measured, not guessed, when round J's first draft put the files blob's 4 KiB data page on kmain's stack and the very next deep call (#PF err=2: supervisor write to the not-present guard page) caught it. The F15 guard page did exactly what it was built to do — the overflow faulted loudly instead of corrupting .bss. The data page is now a compile-time `static` (zero stack cost, and `const fn`-built into .rodata), and the boot stack grows 256K → 512K so the margin is honest rather than lucky; image + bss + stack stay inside the single 2 MiB page (kernel end ≈ 1.01 MiB).

### Added — review round 7 ("I"): read-only FAT32 — the EFI System Partition

- **The FAT32 policy core** (`src/fat32.rs`): BPB validation with the
  spec's own type determination (a cluster count below 65525 is
  FAT12/FAT16-shaped and REFUSED as `NotFat32`, never misread),
  FAT-entry classification (free/reserved/bad/past-the-volume values
  refuse; a legal follow and end-of-chain are distinct outcomes), 8.3
  dirent parsing (long-name, deleted, and volume-label records are
  skipped per the format; a size>0 record with no cluster behind it
  refuses), and the cluster-chain walk with a structural termination
  proof — each iteration covers exactly one cluster, so the walk ends
  after ceil(len/cluster_bytes) steps; a loop-back entry re-reads a
  bounded cluster and still terminates; a chain shorter than the
  dirent's length refuses with `ChainTooShort`, a length the volume
  cannot hold refuses up front with `ChainTooLong`. Seven host tests
  including a 2000-image fuzz corpus; the walk itself lives in the
  core (the kernel supplies only the sector loader), so every bound
  above is host-proven, not boot-hoped.
- **`scripts/mkfat32.py`**: grows the mkext2 disk with GPT partition 2
  — an ESP (type GUID C12A7328-…) holding an honest FAT32 volume:
  65600 clusters (≥ the 65525 minimum), two 516-sector FAT copies, the
  FSInfo sector with true free-cluster accounting, the backup boot
  sector, and HELLO.ESP — 1200 bytes across clusters 3→4→5, so the
  chain has real hops to walk. The GPT backup moves to the new tail;
  the stale copy is zeroed; the protective MBR is resized.
- **The transport** (`drvstack/fat32.rs`): mounts on the LIVE AHCI
  port right after ext2 (same frames, no restart), walks the GPT again
  for partition 2, and reads HELLO.ESP through the policy core's walk
  — the marker prints the head (cluster 3) AND the tail (cluster 5),
  so every hop between them is proven. Live on BOTH lanes (IOMMU and
  no-IOMMU), grepped by the CI lanes.

### Fixed — review round 7 ("I"): the hidden lane debt of rounds 6–H

- **The TSC calibration that never calibrated** (`drvstack/acpi.rs`):
  `tsc_delta.checked_mul(10^15)` overflows u64 for ANY real window —
  a 2M-spin calibration is millions of TSC ticks and the product
  exceeds 2^64 ten times over — so the "[TSC ] calibrated" marker
  had never printed (hidden behind the round-6 lane crash). The
  arithmetic moved to u128; the quotient bounds (1 MHz..16 GHz)
  stay.
- **The virtio-console chain that never chained**
  (`drvstack/vcon.rs`): the header descriptor was written with
  `flags = 0` — without `DESC_F_NEXT` the next-index field is
  ignored, the device treated the 4-byte port header as the whole
  request, and the host file received exactly those 4 bytes while
  the guest-side completion reported success. One flag; the host
  file now holds the full round-trip payload.
- **The CPUID RBX destruction** (`hw::cpuid7_ebx` / `hw::cpuid1_ecx`):
  the "bulletproof" push/cpuid/store/pop pattern was inverted — the
  `mov %rbx,(%rsp)` overwrote the SAVED original RBX with CPUID's
  output and the `pop` handed that to the output operand, so the
  caller's callee-saved RBX never came back. CPUID destroys RBX and
  the block never declared it; whether anything broke was allocation
  luck (a release build kept the driver stack's inventory pointer in
  RBX across `cpuid7_ebx()` — the q35 lane #PF'd at a garbage
  pointer, deterministically, while a marker-instrumented build with
  different register allocation ran clean). `cpuid7_ebx` now shuttles
  the word out with `xchg` (the original RBX lands back in the
  register, the wanted EBX in the slot); `cpuid1_ecx` stores ECX to
  its operand directly and pops the original RBX. The other push-RBX
  sites (the naked entry stubs) are self-balanced and untouched.
- **The unclaimed-virtio DMA failure** (`drvstack/pci.rs` +
  `pci::Inventory::set_dom_dev`, host-tested): the round-G/H steps
  drove virtio-rng, virtio-console, and virtio-balloon WITHOUT
  walking the claim gate — their sessions ran with `dev.dom = 0`
  (the kernel's own domain), and an unclaimed device's DMA fails
  closed at the IOMMU, so every device completion honestly timed
  out ("DID NOT COMPLETE (budget)") the moment the ECAM fix let the
  q35 lane reach them. Claimed devices beside them (vblk dom 1,
  vnet dom 2) completed everything — the differential that pinned
  it. The three devices now walk the same claim gate as the rest
  (matched by virtio device id, legacy and modern both; the family's
  class codes are ambiguous), recorded through the new id-matched
  `set_dom_dev`. The domain budget that made the fix visible —
  `MAX_VTD_DOMAINS` 8 → 16, with the derived `TABLE_BUDGET` scaling
  along (the q35 lane now claims nine devices; dom 7 was the last
  handout, so rng/balloon were refused on budget before the raise) —
  and console's device round trip completing on its own domain
  ("TX complete … the HOST file holds the other half") is the
  end-to-end proof.
- **The idle-queue MSI-X kick** (`drvstack/vnet.rs`): the ADR-0019
  delivery proof kicked the TX queue AFTER the DHCP exchange drained
  it — a notify with no pending buffer never produces a used-ring
  update, so the device never fired and the 400M-TSC-cycle delivery
  window ground the whole lane into its timeout (under QEMU TCG the
  emulated TSC makes 400M cycles ten-plus wall-clock minutes). The
  step now queues one fresh TX before the kick (the used-ring update
  itself — not the network — is the event that fires entry 2), and
  the window's budget drops to 40M cycles (~13 ms on real iron at
  3 GHz, under a minute under TCG).

### Known-open (round I, honestly recorded — not claimed)

- **MSI message delivery (both formats)**: the arming, read-back,
  fresh-work kick, bounded window, and teardown are proven live, but
  the message never lands (compat on the base lane, remapped on IR).
  The delivery window's own honesty is what exposed it: the old
  mwait window slept through its deadline (a silent device = a
  hung boot), the new `wait_for_delivery_spin` says "NOT delivered"
  loudly and the boot continues. The DELIVERED greps moved off both
  lanes; the line-interrupt chain (IOAPIC → vector → mailbox) is
  delivered and stays grepped.
- **The balloon inflate**: the deflate round trip is live (the page
  returns home); the inflate's host-side discard never completes the
  queue entry under this QEMU. Round H's "real inflate/deflate"
  claim was never exercised (the lane crashed at ECAM first) — the
  checklist now says what actually happens.
- **The ECAM direct-map hole** (`mm::map_gib_windows` + `gib_span`):
  round 6's ADR-0020 shipped the ECAM seam without mapping the GiB the
  MCFG window lives in — on q35 the third GiB (PCIEXBAR 0xB000_0000),
  which nothing else maps — so the FIRST config read through the
  direct map #PF'd and the kernel halted ("unexpected fault"). The q35
  lane never got that far (see below), so the crash hid. The fix
  generalizes the fourth-GiB LAPIC/VT-d window trick: the spanned
  1-GiB PDPT entries are mapped as RW+NX huge pages, idempotently,
  only-if-absent; the span math is pure and host-tested. The lane now
  greps the mapping marker.
- **The GPT lane marker** (`drvstack/ext2.rs`): the lane greps
  expected `LBA 34..=289` while the kernel printed `LBA 34..289` —
  every lane ran red on that grep since round 6, which is exactly how
  the ECAM crash above stayed hidden. The kernel now prints the
  inclusive range (the GPT span is first..=last); the FAT32 marker
  matches the same convention.
- **The fmt debt**: rounds G/H shipped 25 files without a fmt pass —
  `cargo fmt --all --check` (the CI job) reported 1407 diff lines on a
  tree that was clean at 15d9441. Reformatted, zero semantic change,
  full suite green.
- **The lane timeouts**: q35/IR lanes raised 240s → 600s. The M2
  syscall audit phase alone emits ~390k serial lines before the driver
  stack starts, and q35 + intel-iommu under TCG on a loaded host needs
  more than 240s just to reach `[PCI ]` — the timeout kill looked like
  a boot failure while it was really a budget failure.
- **A dead comparison in `pci::ecam_addr`** (flagged by the compiler):
  `bus.wrapping_sub(start_bus) > 255` on u8s is always false; the
  window's end is the caller's bound (`CfgAccess::resolve` checks
  `end_bus`). Removed with the responsibility stated.
- unsafe ratchet: unchanged at 100/100 — the round adds ZERO unsafe
  (the transport reuses the proven AHCI read path; the GiB-window
  writes go through the memops wrappers).

### Changed — review round 6, part 2 ("H"): the watchdogs, AMD-Vi's IVRS, and two more virtio devices

- **The watchdogs** (`drvstack/wdt.rs`, register maps pinned against
  QEMU's ich9_tco.h / ich9.h / wdt_i6300esb.c): **iTCO_wdt** — the
  ICH9 LPC's TCO block probed through PMBASE (config 0x40, bits
  15:7), its registers read live, and the timer reprogrammed with a
  read-back proof — but ONLY after the chipset's NO_REBOOT gate (GCS
  bit 5, read through the RCBA) says a timeout is inert (QEMU's
  default; a clear gate refuses to reprogram, CI-safety stated).
  **i6300esb** — the unlock×3 / max-preload / ping sequence on the
  write-only MMIO registers, with reboot-on-timeout masked in config.
  New `hw::inw` (the 16-bit I/O read TCO needs); unsafe ratchet
  99 → 100.
- **AMD-Vi's IVRS parsed** (`src/ivrs.rs`, policy core, layouts
  pinned against Linux's actbl2.h): IVHD blocks (the IOMMU MMIO
  bases, ids, flags) and the device-entry topology (selects, ranges,
  aliases, specials — including the 8-byte types whose values EMBED
  their length bits, a trap the tests pin), IVMD unity-map blocks
  counted. Typed hostile refusals. The boot probe prints the honest
  absence on QEMU (no AMD-Vi emulation); the register-engine slice
  follows on real AMD machines.
- **virtio-console** (`drvstack/vcon.rs`, 0x1043): port 0's transmit
  queue driven — the [port-id header + payload] chain sent through
  the broker, completion validated, and the HOST half of the round
  trip asserted by the lane (the chardev file must contain the proof
  string; the guest marker alone is not the claim).
- **virtio-balloon** (`drvstack/vballoon.rs`, 0x1045): a REAL
  one-page cycle — a fresh pool frame offered on the inflate queue,
  the config's `actual` watched advancing to the checked target, the
  SAME page deflated home, the frame returned to the pool. The stats
  vq is not negotiated (stated scope).


### Changed — review round 6 ("G"): the interrupt chain, multi-bus PCI, and the platform slice (ADR-0019 + ADR-0020)

- **The interrupt broker (ADR-0019)** — `kernel-x86_64/src/irq.rs`:
  vectors 49..=112 are broker-owned from boot (64 stubs + gates in
  `idt::load`, the dispatch route); `alloc` is the only way a vector
  gets an owner (one per device, duplicate tags refuse); `deliver`
  EOIs FIRST then lands the delivery in a per-device mailbox
  (served/lost/pending, cap 1024 — surplus counted, never wrapped);
  an unowned vector is a named halt. The bounded delivery window
  (`wait_for_delivery`) pauses the tick, opens IF, and sleeps in
  **MWAIT on the LAST_DELIVERED word** when the CPU offers MONITOR
  (armed-late re-check included), spinning otherwise.
- **IOAPIC + x2APIC**: the MADT's interrupt view parsed pure
  (IOAPIC entries + ISA-IRQ→GSI overrides, hostile truncations
  stop the walk); the IOAPIC's RTE encoded field-by-field,
  programmed masked-first, bounds-checked against the probed max;
  the LAPIC switches to x2APIC when CPUID offers it (MSR
  0x800+(off>>4), mode-aware EOI). **The lane's proof**: the QMP
  key arrives MID-WINDOW and delivers ISA IRQ1 → GSI1 → vector →
  EOI → mailbox — the first line interrupt in the tree that is not
  a poll.
- **MSI/MSI-X + VT-d IRTE**: the MSI-X table (BIR/offset decode,
  BAR-size bounds, masked-first entry writes, read-back) points
  virtio-net at a broker vector — the TX kick's completion arrives
  as a MESSAGE. When the DMAR declares interrupt remapping, IR
  enables (IRTA + SIRTP + IRE on the accumulated GCMD word, 256
  IRTEs on a scrubbed frame) and the NIC's messages switch to the
  REMAPPED format through IRTE n = broker slot n (layouts pinned
  against QEMU's decoder; reserved fields zero by construction).
  New lane `--verify-q35-ir` (`intremap=on`) proves the remapped
  path end to end in CI.
- **Multi-bus PCI (ADR-0020)**: the config seam
  (`CfgAccess::LegacyPorts | Ecam`) with bounds-checked ECAM
  address math; `enumerate_multi` walks THROUGH type-1 bridges
  (visited-set loop protection, depth cap 8, the same
  BAR/capability code now bus-parameterized); the F9 bus-0-only
  refusal is LIFTED — devices behind bridges claim their own
  ADR-0018 domains. The q35 lane gains a pcie-root-port with a
  virtio-blk behind it; the ECAM marker, the traversed marker, and
  the bus-1 device line are asserted. Inventory cap 32 → 48.
- **The platform slice**: power paths read the FADT
  (`arch/pwr.rs` — PM1a + the reset register, offsets pinned
  against Linux's actbl.h; power-off and reboot go through the
  firmware's addresses with loud legacy fallbacks); the TSC is
  calibrated against the live HPET counter (the preempt tick stops
  riding a guessed constant); entropy exists (RDRAND/RDSEED +
  virtio-rng harvested through the broker into a splitmix64-mixed
  pool with honest counters — a mixer, not yet a CSPRNG, stated);
  and the storage stack reads a REAL partition table
  (`src/part.rs`: protective MBR + GPT with both CRC-32s enforced,
  typed hostile refusals — the ext2 mount rides the 'aegis-root'
  partition base, raw-LBA-0 fallback marked).
- **Unsafe ratchet 93 → 99** (six single-instruction `hw` wrappers,
  ADR-0019 referenced in `scripts/unsafe-count.txt`); ~60 new host
  tests across the kernel and policy crates; every marker the new
  lanes assert is listed in the ADRs.


### Changed — review round 5, Phase E: ADR-0017's first slice — the IpcMmio channel

- **`kernel-x86_64/src/ipc_mmio.rs`**: a driver's register access as
  a MESSAGE, not a volatile load. `IpcMmio` implements the `MmioBus`
  trait (ADR-0016's seam) by forwarding every accessor through an
  `MmioChannel` to a ring-0 **DeviceCore** that checks offset AND
  width against the same validated window before anything volatile
  happens — a ring-3 driver domain cannot even NAME a register
  outside its grant. The core counts served/refused (the organic
  monitor feed a domain cannot forge or suppress). The first slice's
  channel runs in-process (the core is the far end); the ring-3
  slice swaps the transport for a capability-gated IPC endpoint
  without touching the message types or the discipline.
- **Host proofs**: the headline ADR-0017 test — the SAME driver code
  (a register sequence written only against the trait) runs unchanged
  against the direct ring-0 bus and the channel, with identical
  answers; out-of-window requests never reach the register page (a
  poison guard proves it) and are counted; hostile widths (0/1/3/255)
  are refused by the core; and the rogue-driver suite walks the six
  forbidden operations (MMIO outside the window, quota overrun,
  another domain's cookie, in-flight unmap, the absent-verdict DMA
  gate, descriptor bounds via the channel + virtio's tests) — every
  one refused, typed, side-effect-free, and a healthy driver keeps
  working after each.
- **What is NOT in this slice** (the next one, per ADR-0017's own
  sequencing): the ring-3 transport itself (a launched driver domain
  whose channel is an IPC endpoint), the syscall-mask + capability
  gating on the domain's driver-facing calls, the monitor wiring of
  the core counters, and the boot-lane marker for a live ring-3
  driver. The broker/channel refusal proofs here are host-level; the
  ring-3 rogue demo stays the ADR-0010 one until then.

### Changed — review round 5, Phase D: leftovers made loud

- **MAX_SESSION_FRAMES is proven, and outgrowing it is LOUD**: the
  per-driver frame sets are enumerated in the constant's doc (vblk 5,
  vnet 8, e1k 4, nvme 6, ahci 4, xhci 2+4 — largest is 8 of 16);
  `DriverSession::frame()` now returns a typed `FrameError::{Pool,
  Budget}` instead of a bare Option, and a budget violation prints
  "[SESSION] BUDGET EXCEEDED..." at close — never again a silent
  "pool exhausted" for a driver bug. Host test
  `frame_budget_exceeded_is_loud_and_conserving` pins it (16 frames
  in, the 17th refused, everything conserved). Writing that test
  caught a REAL harness hazard: world()'s 9-frame FakePhys buffer
  corrupts the host heap when a test allocates past it — the budget
  test uses a dedicated 192 KiB backing (documented in the test).
- **Bridge topology**: already a loud refusal (the "[PCI ] bridge at
  this slot — devices behind it are NOT driven (isolation boundary,
  F9)" marker) with the claim gate host-tested (ClaimError::
  BridgeClass/NotEndpoint, pci.rs's fake-config tests); the bus-0-only
  limitation stays documented in the module header and the checklist
  row. No code change needed — verified, not reimplemented.
- Test counts regenerated (497 -> 498).

### Changed — review round 5, Phase C: history, secrets and repo guards (NO history changes)

- **`scripts/check-history-clean.sh`**: scans every blob reachable
  from any ref — not just the tree at HEAD — for the incident classes
  (ELF cores via the 20-byte header's e_type, oversize blobs outside
  the known allowlist, assignment-shaped credential patterns shared
  with check-no-binaries.sh, with the same self-literal exclusions).
  Measured today: exactly the three historical `kernel-x86_64/core`
  blobs (8,167,424 / 8,183,808 / 2,805,760 bytes) and nothing else —
  zero false positives. Wired into CI as REPORT-ONLY: its failure is
  the standing reminder that the human purge is pending; the flip to
  `--strict` (build-fatal) is documented in the script, the runbook,
  and the CI step.
- **The incident runbook grows the verification step**: after the
  purge, both `git log --all --oneline -- kernel-x86_64/core` and
  `git rev-list --all --objects | grep -E '(^|/)core$'` must print
  NOTHING — checked on the purged clone before pushing and on a fresh
  clone after.
- **`check-ist-sections.sh` fails honestly**: a missing kernel ELF now
  prints "kernel ELF not found: build first or pass a path" instead of
  the misleading "IST symbols missing" (hit twice in practice during
  this round — the raw kernel ELF, not the packaged boot image, is
  the expected argument; CI already invokes it argument-less after the
  build).
- NO history was rewritten, no refs deleted, no force used — the
  purge and rotation remain human steps per the runbook.

### Changed — review round 5, Phase B: hostile-device tests for every driver

The drvstack tree compiled OUT of test builds entirely
(`#[cfg(not(test))] mod drvstack`) — every driver module had ZERO
tests and nothing exercised a lying device. Phase B opens the tree to
host builds (the step functions stay cfg'd; the pure logic does not)
and drives the REAL driver code — memops is identity on host, so the
actual submit/encode/parse functions run against the new fakes:

- **`drvstack/testharness.rs`**: one shared, deterministic harness —
  a scriptable fake `MmioBus` (constant / cycling-sequence /
  flipping-garbage registers, a write log), a budget-capped fake
  `DmaProt`, the host-"physical" `FakePhys` buffer pattern, and the
  repo's xorshift. The harness has its own self-test (which caught a
  real mixing bug: xorshift's three shifts do not propagate low-bit
  differences into the high half — folded with a finalizer).
- **Per-module hostile tests** (19 in drvstack, every driver module
  covered): nvme's SQE encoder + CQE poll (the F11 pin: the data
  pointer at BOTH +16/+24, the phase bit at 16; a never-completing
  device cannot hang the poll — budget-bounded by test; 1000-garbage
  CQEs, every accepted status within bounds); e1k's TX descriptor +
  the RX DD bit (garbage in neighboring fields cannot flip it); ahci's
  READ-DMA-EXT command table (every ADR-0014 offset pinned — each was
  once wrong; a 1000-LBA fuzz roundtrips the 48-bit field); xhci's
  No-Op TRB + event-type extraction (bounded to 6 bits under garbage);
  netutil's DHCP DISCOVER (checksum VERIFIES over the built packet;
  1000 hostile MACs all build checksum-valid frames); vblk's
  3-descriptor chain (IN/OUT flag polarity, avail publish + wrap
  semantics); vnet's avail publish; legacy's BCD decode (hostile
  nibbles decode to face value, never panic).
- **Extractions** (the trait-seam move the round asked for):
  e1k::build_tx_desc/rx_desc_done, xhci::build_noop_trb/
  event_trb_type, ahci::build_read_dma_cmdtable/
  build_identify_cmdtable (module-scope, host-testable; the boot steps
  call them — single source of truth), netutil un-cfg'd, vblk::submit
  and vnet::net_publish un-cfg'd, legacy::bcd_decode extracted.
- The step-orchestration modules without their own #[test]
  (drvstack/pci.rs, vtd.rs, broker.rs, ext2.rs, acpi.rs) are thin
  sequencing over layers that ARE tested (crate pci.rs, arch/vtd.rs,
  arch/acpi.rs, the ext2 policy core) — noted in the report.
- Boot markers byte-identical (all three lanes PASS unchanged).

### Changed — review round 5, Phase A (ADR-0018): one IOMMU domain per device

The main remaining isolation gap: every device sat in IOMMU domain 0
(one shared second-level table — any device could DMA into any
other's buffers; one driver's revoke_all(0) tore down every driver's
mappings; ADR-0015's domain-scoped cookies had no second domain to
be wrong in). Red test first: `device_tables_are_isolated_per_domain`
FAILED on the old claim shape (both devices in dom 0 share one SLPT).

- **ADR-0018**: domain 0 is the kernel's own (the hw-proof + broker
  demo); every claimed device draws its own id from the kernel-side
  `DomainIds` allocator (never device-supplied; exhaustion = typed
  None; release is explicit and double-release refused). The hardware
  proof now UNASSIGNS its probe device (context clear + QI
  context-cache invalidation — the only way a device changes
  domains); `assign_device` refuses an already-assigned device.
- **DriverSession carries the domain** (from PciDev.dom, set at
  claim time): map/complete/unmap/revoke_all all scoped — one
  session's teardown provably leaves every other's mappings alone.
- **The table budget is derived, not guessed**: a pure
  `worst_case_tables(domains)` (shared root+IQ+ctx + per-domain
  root+PDPT+PD+9 PT spans) sizes TABLE_BUDGET to 99 (was 64 — 6-8
  devices × per-domain trees would have exhausted it). The exhaustion
  test drives the new sizing to its edge: typed refusal, cursor
  consistent, no table aliasing.
- **Live negative probe on the q35 lane**: the e1000 (its own domain)
  DMAs at a page mapped ONLY in the virtio-net's domain — it MUST
  fault; the lane grep requires "cross-device DMA FAULTED
  (FSTS.PPF set)" and --verify-q35 FAILS without it. Measured: it
  faults.
- **Truthful teardown markers**: `revoke_or_quarantine` now reports
  revoked/freed/quarantined/poisoned counts per domain and never
  claims "frames return scrubbed" when any region was poisoned. The
  claim markers carry the real domain id ("→ dom 3 ok"); the lane
  greps were updated in the same commit (dom-number-agnostic
  prefixes).
- Host tests: per-domain isolation (A's page absent in B's walk; the
  same frame in both domains only via separate map_runs; unmap
  scoping), reassign-until-unassigned, budget math, multi-domain
  exhaustion, a 3000-step xorshift property test over random
  assign/map/unmap/unassign sequences (no aliasing, per-domain
  presence matches the model after every sampled step), and the
  DomainIds allocator (kernel-domain reservation, exhaustion,
  release rules).

### Docs — review round 4, Phase 6: ADR-0017 — ring-3 driver domains

The architecture ADR-0016 built its seams for: drivers become ring-3
monitored domains with exactly four grants — an `IpcMmio` channel
(the device core checks every offset against the same validated
window), broker-only DMA (domain-scoped cookies), an organic monitor
feed the domain cannot forge, and a `Device` capability for its own
device. A driver bug becomes a quarantined domain event, not a
kernel compromise. The first implementation slice is the `IpcMmio`
channel; polling stays (no IRQ routing in this phase), one domain
per device, the domain image built with the kernel like today's
ring-3 examples.

### Changed — driver-stack review round 4, Phase 5 (F13): ext2 parsing moves to the policy core

- **`src/ext2.rs` — the on-disk parser, pure and validated.** Every
  structure the boot walk consumed (superblock, inode, dirent) moves
  from the kernel's raw field reads into the policy lib as pure
  functions over byte slices: magic/inode-size sanity, inode-number
  and block-range geometry math (every step checked against the
  superblock's own counts), inode extents bounded by the slice, and
  a directory walk where a hostile record (rec_len < 8 + name_len,
  not 4-aligned, zero, running past the block, or a name crossing
  the caller's slice edge) is a typed refusal — never a skipped
  record, never a panic.
- **The kernel keeps the transport and the markers**: sector reads
  through AHCI, the boot markers byte-identical (the lane grep pins
  hello.txt's line verbatim), and explicit refusal markers naming
  the policy verdict on hostile images.
- **Host tests pin the parser from every side**: the real
  `mkext2.py` image (mirrored by a test builder) parses end-to-end
  to "HELLO-AEGIS-EXT2."; hostile superblocks (bad magic, inode
  sizes 0/999/130, truncation) refuse; hostile inode numbers and
  blocks refuse; hostile dirents refuse-never-skip; the exact
  512-byte-sector shape the kernel hands the parser (a last record
  padding its rec_len to the 1 KiB block end, past the slice) is
  pinned as its own test; and a deterministic 2000-iteration fuzz
  (seeded corruptions biased at the format's structures) runs the
  full parse chain with zero panics.

### Fixed — driver-stack review round 4, Phase 5 (F12): ACPI firmware-table validation

- **`read_table` (the DMAR/RSDT path) now verifies the ACPI
  checksum** — every byte of the declared length must sum to zero. A
  bit-flipped table was previously a parsed table (length was the
  only check). Red-proven by `read_table_rejects_checksum_corruption`
  on the pre-fix code.
- **`table_ok(pa, sig, scratch)` — the validation gate for the
  directory walk's target tables**: signature, declared length
  (36..=scratch), and checksum before the HPET/MADT/MCFG walks trust
  a pointer they found in the RSDT/XSDT. The directory itself is
  validated first (sig + length + checksum — the old walk trusted a
  raw header length), and each target table is gated before any
  field read; a corrupted table prints an explicit refusal marker
  instead of walking hostile bytes. Host tests pin the gate from
  every side: valid table accepted with its length, broken checksum
  refused, wrong signature refused, hostile lengths (0, 35, 1025,
  u32::MAX) refused, and the minimum legal 36-byte table accepted.
- The lane markers are unchanged on healthy firmware (all three
  lanes PASS); the q35 lane caught a byte-1 sig heuristic bug
  (R**S**DT vs X**S**DT share byte 1) before it shipped.

### Fixed — driver-stack review round 4, Phase 5 (F11): the NVMe data path — SOLVED

Two compounding layout quirks of this QEMU's nvme plus one lane
device property, each masking the others for two sessions:

- **The command data pointer is read from SQE bytes 24-31** (the
  spec's PRP2 slot), not 16-23 — measured by planting a distinct
  page in every PRP-candidate slot and watching the identify DMA
  fault at exactly the +24 plant (1,024 IOMMU write faults on its
  page) while ignoring the +16 plant. The historical "data lands at
  PA 0" was this bug writing at pointer 0 in the pass-through era.
  The driver now writes the pointer at BOTH slots — spec hardware
  ignores PRP2 for single-page aligned buffers, so both worlds work.
- **CC's entry-size fields sit at bits 19:16 (IOSQES) / 23:20
  (IOCQES)** here, not the spec's 23:20 / 27:24 — measured by
  QEMU's own `pci_nvme_err_invalid_create_cq_entry_size iosqes 4
  iocqes 6` after a spec-layout write. CC returns to 0x0046_0001
  (the value the 2026-11-20 session had and "fixed" into the spec
  layout while chasing the PRP symptom).
- **The lane's nvme device needs `num_queues=2`** — the property
  defaults to 0 (zero I/O queue pairs; `max_ioqpairs` is only a
  cap). The q35 lane now passes it.

After all three, the FIRST complete NVMe run: the Identify data
page arrives (serial "AEGISN1", VID 0x1b36, NN=256), CreateIoCq +
CreateIoSq pass, and a 512-byte LBA-0 read completes through the
IOMMU. The lane greps pin all of it. docs/arch/drivers.md's anomaly
note is rewritten as the resolution (the AHCI-retraction pattern).

### Changed — driver-stack review round 4, Phase 4-B (ADR-0016): MmioBus windows

- **`kernel-x86_64/src/mmio.rs` — every device register access goes
  through a bounds-checked window** (ADR-0016). A `MmioWindow` is
  established once per device — `BarMmio` from an enumerated BAR
  (base + the size the scanner measured), `FixedMmio` for
  firmware-named blocks (the HPET) — refusing zero-length and
  wrapping ranges. The `MmioBus` trait's accessors (`read8/16/32/64`,
  `write32/64`) take window-relative offsets and refuse out-of-window
  access with `None`/`false` — a device-supplied number (or our own
  arithmetic bug) can never steer the kernel outside the claimed
  registers; refusals are verdicts the caller handles, never panics
  and never a silent 0. The window math is pure and host-tested at
  the edges (zero/wrap refusal, `off+len` overflow, the last valid
  byte, a 16-bit access straddling the end, byte reads needing their
  whole containing dword, and a fake-bus test proving out-of-window
  offsets never reach the volatile core). The volatile core delegates
  to `memops` — no new `unsafe` enters the tree (check_unsafe 93/93).
- **Five drivers converted** (e1k, nvme, ahci+ext2, xHCI ×2 steps,
  HPET): raw `memops::*(bar_base + off)` register accesses are gone;
  the device-derived offsets that remained raw — NVMe doorbells
  (stride from CAP.DSTRD), xHCI's caplen/dboff/rtsoff — are now
  door-checked once then window-checked per access, and every
  refusal prints an explicit marker. The virtio drivers keep their
  F5 `MmioVirtio` (already windowed at `resolve()`); the arch layer's
  own registers (LAPIC, VT-d programming in `arch/vtd.rs`) stay in
  the tested arch module.

### Changed — driver-stack review round 4, Phase 4-C (ADR-0016): one-close() DriverSession (F10)

- **`kernel-x86_64/src/session.rs` — the mid-flight refusal leak dies
  by construction.** Every driver run (vblk, vnet, e1k, nvme, ahci,
  both xHCI steps) now acquires pool frames and broker regions
  through a `DriverSession` that records them as they are acquired;
  ONE `close(out)` runs the ordered teardown (BME off →
  revoke_or_quarantine → frames home) with the lane markers verbatim,
  and `Drop` is the silent safety net — a driver that returns early
  for ANY reason still cannot strand a frame, leave a region mapped,
  or leave a device with bus mastering past its owner's lifetime.
  Pinned by four host tests (a fake `DmaProt` + the real
  `FramePool`/`Kernel`): `no_frame_stranded_on_early_refusal` (alloc
  three, map two, refuse the third, drop — everything home),
  `close_frees_and_revokes_everything` (marker verbatim),
  `drop_alone_is_the_safety_net`, `identity_close_prints_and_frees`.
- The session is generic over `DmaProt` (the fake in tests today;
  ADR-0017's brokered channels next) and carries the teardown core
  (`revoke_or_quarantine` moved in from drvstack/mod.rs — it was only
  ever the session's engine). `strutil::line` is the shared logging
  primitive (moved out of drvstack for the same reason).
- The identity lanes close correctly for the first time: bus
  mastering is cut BEFORE the frames go home (the old hand-rolled
  identity teardowns freed first — a real device-reach window on the
  no-IOMMU lane).
- vblk's enforcement probe runs through the session
  (`complete_unmap` + `with_prot` + `hand_back` — the unmapped data
  page returns home exactly once).

### Changed — driver-stack review round 4, Phase 4-A (ADR-0016): the module split

- `kernel-x86_64/src/drvstack.rs` (4,389 lines, twelve subsystems
  accreted across ADR-0013/0014/0015 and F4–F9) is now
  `src/drvstack/` — one module per subsystem (`vtd`, `broker`, `pci`,
  `vblk`, `vnet`, `netutil`, `e1k`, `nvme`, `ahci`, `xhci`, `acpi`,
  `ext2`, `legacy`) with `mod.rs` keeping the shared teardown
  discipline, the pool-owner tags, and the step sequencing. A **pure
  move**: signatures, boot markers, and lane greps stay
  byte-identical — all three boot lanes PASS on the split alone (the
  pc lane's M1 exit criteria, the q35 lane's VT-d trace assertions +
  7/7 screen check, the q35-neg fail-closed control).
- The ADR index rows for 0014/0015 (missing since their landing) are
  restored; ADR-0016 documents the split and the two commits that
  follow in-phase (MmioBus windows, one-close() DriverSession).
- One source typo fixed in the move: AHCI_OWNER's doc comment had a
  `//` line where `///` was meant.

### Fixed — driver-stack review round 4, Phase 2 (ADR-0015): IOMMU integrity

- **F1 — `map_run` is atomic** (a `DmaProt` contract guarantee now):
  the table demand is precomputed by a pure read-only walk and checked
  against the budget BEFORE anything is written; the table cursor
  commits every linked frame on every exit path (a table frame is
  never handed to two parents); residual errors roll back every page
  the call wrote. Pinned by `map_run_is_atomic_on_budget_exhaustion`
  (red on the pre-fix code), a 300-step xorshift property test, the
  pure `check_no_table_aliasing` walk, and a reusable
  `dma::contract` harness run against BOTH the fake and the real Vtd.
- **F2 — revoke fails closed**: `revoke_all` returns
  `{revoked, poisoned}`; a region whose hardware unmap failed is
  poisoned (still live in hardware, still holding its quota,
  enumerable for kernel quarantine), its frames are re-tagged under a
  `QUARANTINE_OWNER` in the FramePool and never freed, the device's
  bus mastering is cut (new `pci::disable_bus_master`, a 16-bit
  command write that never echoes the RW1C Status half), and
  `retry_poisoned()` is the only release path. All 19 drvstack
  teardown/refusal sites route through one `revoke_or_quarantine`
  helper (this also fixes the VBLK teardown frame leak and its lying
  "frames return scrubbed" marker).
- **F3 — cookies are domain-scoped**:
  `region_complete(dom, cookie)` / `unmap_region(dom, cookie)`; a
  foreign cookie returns the same `InvalidHandle` as an unknown one
  (no oracle), and the domain id always comes from the kernel.
- Typed `DmaError::OutOfTables` (+ wire refusal 11) for the atomic
  budget refusal.

### Fixed — driver-stack review round 4, Phase 0 + Phase 1 (ADR-0014)

- **P0.1**: the 8 MiB ELF core dump committed as `kernel-x86_64/core`
  (environment block included) is untracked; `.gitignore` covers core
  files; `scripts/check-no-binaries.sh` (self-tested, CI-wired) fails
  on tracked ELF cores, oversize files, and credential patterns;
  `docs/incident-core-dump.md` is the maintainer runbook (token
  rotation + history purge are human steps).
- **P0.2**: clippy clean on the pinned toolchain for BOTH profiles
  (host: 5 errors; kernel target: 43 more behind `cfg(not(test))`),
  plus the asm-pattern guard generalized off its %rbx-only heuristic
  (false positive on `cpuid1_ecx`).
- **ADR-0014**: context entries carried TT=0b10 — pass-through — so no
  device ever walked the second-level tables (`vtd_pt_enable_fast_path`
  ×8, six devices; enforcement probe completed against an unmapped
  page). TT=0b00 + non-leaf entries now carry W (VT-d checks R/W at
  every level). The q35 lane boots with `-trace enable=vtd_*` and
  FAILS on any fast-path event or a missing `PPF=yes`.
- Cascades solved by real translation: virtio-net and e1000 full DHCP
  round trips through the IOMMU; AHCI's "stale FIS" was three driver
  bugs (PRDT DBC offset, FIS LBA offsets, missing sector count) — the
  ext2 mount now reads hello.txt on BOTH the IOMMU and no-IOMMU lanes.
- Boot-lane hygiene: the q35/q35-neg lanes now generate all their disk
  images (previously they existed only on one dev machine — a latent
  CI break), and the no-IOMMU control lane carries the AHCI control
  experiment.

### Added — PR-1.1: exception machinery (`kernel-x86_64/src/arch/`, ADR-0005)

- Kernel-owned GDT/TSS/IDT mirroring the boot stub's selector map (the
  boot ABI — pinned by a host test against the stub's literal GDT
  values), a uniform exception frame from 32 naked stubs generated by
  one macro, IST stacks for `#DF/#NMI/#MC/#SS` (`#PF` deliberately not),
  and a Rust dispatch printing full diagnoses (vector/rip/cs/err/cr2).
- Live selftest: the boot forces a hardware `#DE`; `boot.sh --verify`
  greps the diagnosis and marker lines.

### Added — PR-1.2: higher-half kernel + direct map (`kernel-x86_64/src/mm/`, ADR-0002)

- The kernel links at `0xFFFFFFFF80000000`, loaded at PA 2 MiB (linker
  `AT()`; objcopy places by LMA), and the stub maps three windows before
  entry: kernel image, direct map (`0xFFFF888000000000`+PA, RW, never
  executable), and a bring-up identity window that `mm::init` **tears
  down and proves dead** (PML4[0]=0 + CR3 reload + read-back assert).
- `memops` becomes the one physical-memory door (translate-through-
  direct-map; host tests unchanged by an identity `translate`); `mm`
  itself is unsafe-free.
- Guarded kernel stacks (`mm/stacks.rs`): one 2 MiB slot per stack,
  absent-PTE guard page, PD/PT/frames from the pool with owner 0,
  scrub-on-free, per-page `invlpg`.
- Per-CPU state at the GS base (`arch/percpu.rs`).
- The `#DE` selftest now **returns** (dispatch advances RIP past the
  `idiv`; `exception_common`'s unwind is live — the seed of Ring-3
  fault→signal delivery), and the boot ends with a terminal guard-page
  `#PF` proof (`cr2` names the exact guard page).

### Added — PR-1.4: SYSCALL/SYSRET entry + ring-3 machinery (ADR-0005; status: environment-blocked, see below)

- `arch/gdt.rs`: STAR slot arithmetic made real — user data @0x20 /
  user code @0x28 (SYSRET SS=base+8 / CS=base+16), a dedicated
  SYSCALL pair @0x30/0x38, TSS at 0x40, `set_rsp0`/`rsp0`; pinned by a
  new host test.
- `arch/syscall_entry.rs` (new): STAR/LSTAR/FMASK/SCE MSRs,
  KERNEL_GS_BASE = user value (swapgs partner), naked entry: swapgs,
  stack from a static, 12-quadword SysV-aligned frame, RDTSC-bracketed
  dispatch, restore-all-but-RAX/RCX/R11, swapgs, sysretq.
- `syscall.rs` (kernel, new): the shared gate first
  (`aegis_os::syscall::gate`, extracted from `request_syscall`), a
  full-width syscall-number bounds check (nr=256 must not truncate
  into SYS_READ — host-tested), SYS_WRITE with per-page user-buffer
  validation, -ENOSYS + audit counters for unknown numbers.
- `sched/context.rs` (new): UserContext / launch (explicit RSP+RIP
  resume point — immune to the LTO tail-jump on `-> !` entry points,
  a real bug this PR found and fixed) / resume_kernel / user-run state.
- `mm/user_layout.rs` + `mm/user.rs` (new): canonical user layout
  (host-tested against the real ten-check gate) and spawn_user_blob.
- `examples/ring3-hello` + `examples/ring3-rogue` (new): flat-asm user
  blobs built by boot.sh; rogue performs one hostile act per run.
- #PF moved to a dedicated IST; a CPL3 fault during an active run is
  the user's death, not the kernel's (recorded + honest verdict).
- `Makefile` with `test-qemu-pr14`; unsafe ratchet 39 to 61 (all in
  allowlisted arch/sched modules, each with a SAFETY note).
- Status (documented in `docs/arch/syscall-entry.md`): in this
  sandbox's QEMU (10.0.13 TCG, no KVM) the first user-context fault
  cannot be relayed by the inter-privilege delivery path; one build
  did reach ring-3 executing real gated syscalls. The boot ends the
  chapter with `[RING3] launch blocked` + a clean poweroff; the full
  marker set is required the moment the environment allows it. Real
  bugs fixed along the way: nr-truncation smuggling, KERNEL_GS_BASE
  initial value, missing user-CR3 activation, LTO
  tail-jump/unreachable-deletion on `-> !` entry points, an
  indirect-`jmp *sym` misuse.

### Added — PR-1.3: per-domain page tables (`kernel-x86_64/src/mm/{pte,page_table}.rs`, ADR-0002)

- `mm/page_table.rs`: the lib's ten-check `AddressSpace::map` runs
  first and is the only gate; accepted regions become live PTEs (U set,
  NX unless executable, fresh scrubbed pool frames, guard gaps as
  absent PTEs). Walk/unmap/translate are allocation-free and
  **unsafe-free**; host tests cover the walk, policy gating
  (GuardGap/W^X/NULL/kernel-half), disjoint same-VA tables, unmap, and
  pool-exhaustion rollback.
- `mm/pte.rs`: `PteFlags` → PTE bits (XD for `!x`), `USER_LIMIT`
  enforcement, per-page TLB flush. EFER.NXE + CR4.PGE enabled in
  `mm::init`; kernel leaves marked global; the direct map's 1 GiB leaf
  becomes RW+NX (never executable, now hardware-enforced).
- QEMU selftest (CI-grepped): two domains, the same VA resolving to
  different frames; an NX instruction-fetch fault (`err` P+I/D) that
  **resumes execution**; an RX page executing `ret`; the policy
  guard-gap page faulting on read with CR2 naming it.
- Generic pool: `BuddyAllocator<const N>`, `Kernel<const N>`,
  `FramePool<const N>` (defaults keep every existing call site green);
  the kernel boots a 4096-frame pool (physical 16..32 MiB).
- Fixed a real fault-resume bug found by the selftest: the NX trigger
  must be a faulting `jmp`, not `call` — a faulting `call` pushes its
  return address before the fetch fault and silently slides every
  RSP-relative local in the caller.

### Changed

- Unsafe ratchet 23 → 33 (PR-1.2), then 33 → 39 (PR-1.3: two `hw` CR4 wrappers, four exceptions selftest items) (five `hw` wrappers: cr3 r/w, invlpg, wrmsr,
  rdmsr; two `memops` `_va` variants; two percpu derefs; one fault
  trigger) — referenced to ADR-0002.
- CI: kernel-build greps the higher-half entry point
  (`0xffffffff80000000`); boot-test greps the new `[MM ]`/`[EXC]`
  markers.

## [0.2.0] — 2026-11-19 — "It boots" (M1)

The project is no longer just a library: AegisOS now **boots on QEMU** and
runs its M1 exit-criteria sequence on real physical memory, with CI
proving it on every push.

### Added — bootable kernel (`kernel-x86_64/`, new workspace member)

- Two-stage multiboot v1 bring-up (QEMU's `-kernel` loader rejects
  ELF64 — discovered on the first CI boot run and fixed with this
  design): a pure-asm ELF32 stub (`boot-x86_64/stub.S`) — own GDT,
  identity page tables (1 GiB, 2 MiB pages), PAE → EFER.LME → CR0.PG
  long-mode transition, relocation-free 64-bit handoff — embeds the
  flattened ELF64 kernel at its 2 MiB link base and jumps to its entry
  with the boot TSC stamped at the stub's first instruction.
- Real frame pool: 256 × 4 KiB at physical 16 MiB, claimed only after
  multiboot `mem_upper` validation, managed by the **existing** policy-core
  buddy allocator (the `Kernel.frames` instance), with per-frame ownership
  tracking and **scrub-on-free verified by read-back**.
- The M1 boot sequence: hello domain (guard-gap policy rejecting an
  adjacent mapping live, 3 real backed frames, CFS slices), the proven
  five-window monitor escalation (55 → 50 → 37 → 80 → 80, quarantine,
  healthy neighbor unaffected), supervised cleanup, and a 1000-cycle
  create/destroy stress asserting zero frame leaks. Verdict printed as a
  single `M1-EXIT-CRITERIA` line; clean QEMU poweroff.
- `boot.sh` (one command to build+boot; `--verify` asserts the exit
  criteria and is what CI runs).
- Unsafe policy, machine-enforced: kernel is `deny(unsafe_code)` with a
  documented allowlist (`arch/`, `boot/`, `hw.rs`, `memops.rs`, `sched/`), each
  item carrying a `SAFETY` note; `scripts/check_unsafe.sh` fails CI on
  violations.

### Added — policy core

- `Kernel::destroy_domain`: releases pipe ends (dup-aware), brokered
  socket, rate bucket, scheduler registration, and the table slot; works
  on quarantined domains (the supervised-respawn removal path). Files it
  created persist (Unix semantics).
- Public `Kernel::domain_mut` accessor for supervisors and the kernel
  runtime (all Domain fields were already public).

### Changed

- Repository is now a Cargo workspace (`kernel-x86_64/` member;
  `default-members = ["."]` keeps root `cargo test` scoped to the core).
- CI expanded from 3 to 7 jobs: core tests, kernel host tests (the same
  M1 sequence logic without an emulator), ARM no_std build, kernel ELF
  build with ELF sanity checks, **QEMU boot test**, dependency audit
  (workspace-wide), and the unsafe-policy allowlist check.
- Docs: README rewritten around the real boot status; new
  `docs/SECURITY-MODEL.md` one-pager; `docs/M1-PLAN.md` (assessment,
  design, exit-criteria mapping); ARCHITECTURE/ROADMAP updated.

### Numbers

- Tests: 196 (policy core) + 23 (kernel host) = **219**, all green.
- Kernel ELF: ~53 KiB release; kernel image + bss + stack end ≈ 0x14F010,
  far below the 8 MiB safety line and the 16 MiB pool.
- Boot time target (< 300 ms in QEMU) is measured and reported by the CI
  boot job (wall-clock of the full QEMU run, startup included).

## [0.1.0] — 2026-11-19 — Policy kernel M0 + Linux semantics

- Attenuation-only syscall masks, capability generations, ten-check memory
  policy, VFS with Unix DAC + chroot, fd tables, refcounted pipes,
  POSIX signals, CFS scheduling (real Linux weight table), buddy
  allocator, brokered rate-limited sockets, executing syscall layer
  (gate → execute), behavior monitor with graduated response, SPSC
  telemetry rings.
- 191 tests; zero dependencies; `forbid(unsafe_code)`; no_std proven on
  thumbv7em-none-eabihf.
