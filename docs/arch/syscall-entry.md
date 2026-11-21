# arch: SYSCALL/SYSRET entry + ring-3 (PR-1.4)

> The MSR contract, the register-save invariants, the GDT slot
> arithmetic, and — with full honesty — the open environment issue this
> PR ended on. Read `docs/STAGE1-PR-PLAN.md` for the PR spec and
> `docs/adr/0005` for the unsafe-allowlist policy.

## The machinery (all built, host-tested, armed at boot)

- **`arch/gdt.rs`** — the GDT now carries seven used slots with the
  SYSCALL/SYSRET arithmetic pinned by a host test: SYSCALL enters on
  CS=0x30/SS=0x38 (a dedicated kernel pair — the stub's own kernel
  pair is data-before-code and cannot serve the `SS = CS+8` rule),
  SYSRET leaves on CS=0x2b/SS=0x23 (user data at 0x20, user code at
  0x28). `set_rsp0` points TSS.RSP0 at a dedicated guarded stack.
- **`arch/syscall_entry.rs`** — `init()` writes
  STAR=`(0x18<<48)|(0x30<<32)`, LSTAR=entry, FMASK=IF|TF|DF (`0x700`),
  enables EFER.SCE, and parks `0` in KERNEL_GS_BASE (the swapgs
  partner: launch swaps GS→user/KGS→percpu, every entry/exit pair
  balances). The naked entry: `swapgs` → park the USER RSP into
  `USER_RSP_SAVE` (SYSRET restores only RIP/RFLAGS — round J found the
  stub had never carried the user's stack pointer back, so every sysret
  returned to ring-3 running on the kernel's stack; invisible while
  every blob was pure register code, exposed by the first `call` in
  ring-3 history) → RSP from a static (SYSCALL switches no stack
  itself) → park 12 quadwords (SysV-aligned) → RDTSC t0 → call the
  dispatch with the 6-register ABI → RDTSC t1 → restore everything
  except RAX/RCX/R11 → reload the user RSP → `swapgs` → `sysretq`.
- **`syscall.rs` (kernel)** — the gate runs first through the *same*
  lib code as kernel-resident domains (`aegis_os::syscall::gate`,
  extracted verbatim in this PR), the syscall number is bounds-checked
  on the full u64 **before any cast** (nr=256 must not truncate into
  SYS_READ — host-tested), SYS_WRITE validates every buffer page
  through the domain's own tables (present + U + below the split)
  before copying a byte, unknown numbers return `-ENOSYS` and are
  audited (counter + log line, replayed into the lib telemetry from
  PR-1.5 on).
- **`sched/context.rs`** — `UserContext`, `launch()` (records the
  resume point as an explicit RSP+RIP pair and tail-jumps into the
  naked `enter_ring3`), `resume_kernel()` (restores RSP, jumps to the
  recorded RIP). The explicit pair exists because `enter_ring3` used
  to be `-> !`, which let LTO tail-jump the call site — no return
  address on the stack — and delete the post-resume code as
  unreachable (both are real bugs found live; `launch` is a plain
  `()` function now, and nothing after it is unreachable).
- **`mm/user_layout.rs` + `mm/user.rs`** — the canonical user layout
  (code RX at 0x400000, data RW at 0x403000, stack RW below 0x409000,
  guard gaps policy-enforced — host-tested against the real gate) and
  `spawn_user_blob` (lib domain + PR-1.3 tables + blob copy through
  the direct map; frames pool-owned by the domain id).
- **`arch/exceptions.rs`** — a fault with `cs & 3 == 3` while a user
  run is active is the *user's* death: recorded as the run's exit
  kind, the kernel resumes. #PF also moved to a dedicated IST (IST5):
  IST delivery from CPL3 is proven working in this environment while
  the inter-privilege RSP0 delivery path is the one thing that is not
  (see below).

## The examples

`examples/ring3-hello` (write "hello from ring 3 (CPL=3)" via
SYS_WRITE, then SYS_EXIT(0)) and `examples/ring3-rogue` (one hostile
act per run, chosen by a kernel-written mode byte: NX-exec / kernel-VA
read / forged syscall with a self-checking exit code) — pure
`global_asm` blobs, built to flat `.bin` by boot.sh
(rustc --emit=obj + objcopy) and embedded with `include_bytes!`.

## The reopened case: closed (ADR-0010, M2-W2)

The investigation below was honest about its evidence but wrong in its
verdict: nothing here was the environment's fault. M2-W2 added #DF
forensics (raw frame words + CR2/CR3), the full fault record in the
blocked path, and a QEMU-monitor probe of the post-resume hang, and the
chain resolved into **four local bugs** (all in ADR-0010, each with its
regression guard):

1. **A stray legacy IRQ at the IF boundary.** The kernel runs IF=0 but
   user code runs IF=1 (USER_RFLAGS) — the first instant an interrupt
   can fire is the SYSRET boundary itself. The IDT covered 0..=31 only
   and nothing masked the PIC, so a stray line (the PIT runs) hit an
   absent gate, faulted mid-delivery, and escalated to #DF carrying the
   *pending user frame* — the "shifted frame" of the original hunt
   (QEMU's contribution-#DF also pushes no error code, which shifted
   the stub's parse by one slot: the printed `err` was the real RIP).
   Fixed: `pic_mask_all()` first thing in `arch::init()`, plus named
   catch-all gates for 32..=47 that halt loudly with the vector.
2. **Mirror-inverted stub offsets.** The last push lands at `[rsp+0]`,
   but the stub read `nr` from offset 8 — the RBX slot. Every user
   syscall was a garbage-nr `-ENOSYS`; the "gate refusals" recorded
   during the original investigation were this bug. Fixed: named
   `OFF_*` consts in the host-visible `arch::syscall_frame` module, read
   by the asm via const operands, pinned by a host test.
3. **The launch/resume register hole.** Both run-exit paths jump to the
   resume label from mid-Rust, so kmain's callee-saved registers crossed
   the user excursion unpreserved — `kernel_cr3` arrived as a live
   `&mut Kernel` and `write_cr3` spun in a #GP loop (the monitor probe
   caught RIP parked on `mov %rax,%cr3`). Fixed: `launch` parks
   RBX/RBP/R12–R15; the resume label restores them.
4. **An `iretq` regression.** The code contradicted its own doc
   comment: the documented SYSRET entry performs no descriptor-
   validation cycle and cannot fault mid-switch. Restored.

Two more finds in the same pass: the telemetry ring (16 slots, refuses
on overflow — never overwrites by design) was never drained, so run 6's
AuditOnly verdicts dropped (2076 dropped events at the first drain);
kmain now drains as the supervisor will (M2-PLAN R5). And `boot.sh`'s
success marker still said "4 runs" against a kernel printing "7" — it
had never fired because the full path had never run.

**Status quo:** the full seven-run sequence (hello / NX / kernel-VA /
forged syscall / edge writes / live-monitor quarantine / audit-only)
passes in this very QEMU build; `boot.sh --verify` accepts only that
outcome — the blocked line is a CI failure if it ever returns.

The original investigation notes follow, kept verbatim for the record —
the bit-for-bit verifications below were all correct and all beside the
point:

## Why the gate runs before anything else

The kernel's whole thesis is one policy for every execution site:
`gate(mask, quarantined, nr)` is the only door, and the ring-3 entry
reaches it before a single argument register is examined — the same
order `Kernel::dispatch` enforces for kernel-resident domains.
Everything else (copy validation, execution, audit) happens strictly
after the decision.
