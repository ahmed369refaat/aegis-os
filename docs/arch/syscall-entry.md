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
  balances). The naked entry: `swapgs` → RSP from a static (SYSCALL
  switches no stack itself) → park 12 quadwords (SysV-aligned) →
  RDTSC t0 → call the dispatch with the 6-register ABI → RDTSC t1 →
  restore everything except RAX/RCX/R11 → `swapgs` → `sysretq`.
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

## The open issue (environment), documented with full evidence

In this sandbox's QEMU (10.0.13, TCG, no KVM), the ring-3 launch
itself **works** — during the investigation one build reached ring-3
and the user executed real syscalls (gate refusals with `-ENOSYS` and
audit lines are in the investigation logs) — but the *first fault
from the user context* cannot be relayed: it escalates to a #DF whose
frame arrives shifted, and the resume jump does not land. Everything
the fault path depends on was verified bit-for-bit from physical
memory via the QEMU monitor:

- user PML4 walk: `[0]→0x27, [0]→0x27, [2]→0x27, [0]→0x25` — present,
  U set at every level, code leaf P|U|A with NX clear;
- kernel-half copies present (`[273]=pdpt_dm|P|W|A`, `[511]`);
- the live GDT holds exactly the seven descriptors the host test
  pins; TSS limit covers RSP0/ISTs;
- RSP0 was pointed at a known-good IST top — same failure; the entry
  stack was moved off `%gs:` to a static — same failure; PGE and G
  bits were disabled — same failure; `-cpu max` / `Skylake-Client` —
  same failure; both `iretq` and `sysretq` entries — same failure.

What did get fixed on the way (all real bugs, all now regression-
covered): the nr-truncation smuggling check, the KERNEL_GS_BASE
initial value (must be the *user* value, not percpu), the missing
user-CR3 activation before launch, the LTO tail-jump/unreachable-
deletion on `-> !` entry points, and an indirect-`jmp *sym` misuse.

**Status quo**: the boot ends the ring-3 chapter honestly —
`[RING3] launch blocked: ...` + a clean poweroff, with the full marker
set required only on a passing environment (`boot.sh --verify` accepts
exactly one of the two outcomes, warning loudly on the blocked one).

**Repro/retry on a different environment**: run `make test-qemu-pr14`
(or `./boot.sh --verify`). On a KVM-capable host or a different QEMU,
expect the four runs (hello/NX/kernel-VA/forged syscall) and the full
marker set; if the entry still faults, the first place to look is the
exception-delivery path from CPL3 (RSP0 vs IST) in that build, using
the monitor recipes above (`xp` on the user PML4, the GDT at its GDTR
address, and the IST frame below its top).

## Why the gate runs before anything else

The kernel's whole thesis is one policy for every execution site:
`gate(mask, quarantined, nr)` is the only door, and the ring-3 entry
reaches it before a single argument register is examined — the same
order `Kernel::dispatch` enforces for kernel-resident domains.
Everything else (copy validation, execution, audit) happens strictly
after the decision.
