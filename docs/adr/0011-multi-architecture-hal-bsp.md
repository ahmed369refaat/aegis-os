# ADR-0011: Multi-Architecture Strategy — the HAL/BSP Seam

- **Status:** Accepted (design; enforcement starts with the CI target
  jobs in the same commit; the crate restructure is Phase 2 of
  `GAP-ANALYSIS-v2.md`).
- **Date:** 2026-11-20
- **Supersedes:** the "Track B restructure" note in ROADMAP v2 Stage 1
  (same intent, now with a concrete contract and a deadline rationale).

## Context

The brief makes multi-architecture a first-class requirement: x86_64,
aarch64, RISC-V (RV64) as primary targets, everything else through a
strict HAL/BSP layer, policy core completely architecture-agnostic, CI
on at least x86_64 and aarch64.

Today only `src/` (the policy core) is arch-agnostic, proven by the
CI `no-std` build for `thumbv7em-none-eabihf`. The boot kernel lives in
`kernel-x86_64/`, which mixes two very different kinds of code:

1. **Genuinely arch-specific** (correctly allowlisted today):
   `arch/` (GDT/TSS/IDT, stubs, syscall entry, exceptions, percpu,
   features), `hw.rs` (port I/O, MSRs, CRs), `boot/`, `memops.rs`
   (raw physical access), and the naked launch/resume pair in
   `sched/context.rs`.
2. **Arch-agnostic kernel services that happen to live in the x86_64
   crate**: the policy→PTE *gating* half of `mm/page_table.rs` (the
   ten-check policy call, rollback discipline, frame-source trait),
   the run-queue and dispatch glue, `runtime.rs` (the demo sequence is
   arch-independent policy choreography), kmain's reporting.

The next features (preemption, ELF loader, COW, block layer, driver
model) all straddle that line. If they land as more arch-flavored
monolith inside `kernel-x86_64/`, each is written again — differently
and worse — for aarch64. The seam must be cut **before** the feature
wave, and the next features must demonstrate the discipline.

## Decision

### D1 — The layering (target state, Phase 2 restructure)

```text
src/                    policy core (UNCHANGED, forbid(unsafe), zero deps)
                        syscall masks · capabilities · memory policy ·
                        VFS/DAC/chroot · pipes · signals · CFS · monitor ·
                        IPC · profiles · preempt policy (new, see D3)
kernel/                 arch-agnostic kernel core (the crate named `aegis-kernel`)
                        run-queue & parked runs · syscall dispatch table ·
                        ELF loader core · block/page-cache core ·
                        domain-supervisor loop · demo choreography (runtime.rs)
                        depends only on: src/ + the `hal` trait crate
hal/                    the contract crate (no bodies, no unsafe):
                        traits every arch must implement (D2)
arch/x86_64/            implements hal: boot, IDT/GDT/TSS, PTE format,
                        SYSCALL/SYSRET, LAPIC, context switch, IOMMU (VT-d)
arch/aarch64/           implements hal: EL1/EL0, stage-1 MMU, SVC, GIC,
                        generic timer, PAN, context switch, SMMU
arch/riscv64/           implements hal: M/S/U, satp, SBI, CLINT/PLIC
boot-<arch>/            per-arch bring-up stubs (multiboot stub today)
```

Rules:

- `src/` and `kernel/` may never import an arch crate directly; they
  see hardware only through `hal::` traits (already the letter of
  CONTRIBUTING.md; now it becomes structure).
- `hal/` contains **traits, types, and constants only** — no `unsafe`,
  no inline asm, no device code. Every trait method documents its
  contract, its invariants, and who may call it.
- Per-arch crates contain all `unsafe` (joining the allowlist with
  their own ratchet baselines); the unsafe *count* is reported per arch.
- Boot stubs are per-arch and may not be imported by anything.

### D2 — The trait surface (minimal, added-to only via ADR)

The seam abstracts exactly what the kernel core needs, nothing more:

| Trait | What it hides | x86_64 today |
|---|---|---|
| `Console` | byte output (boot log) | `serial.rs` |
| `Timer` | periodic tick, deadline arm, monotonic clock read | LAPIC timer (new, ADR-0012) + TSC |
| `IntCtrl` | mask/unmask, EOI, per-vector wiring | LAPIC + IDT |
| `FrameAlloc` | physical frame source, scrub-on-free | `FramePool` (mostly portable already; owner tagging stays) |
| `PageTableFmt` | PTE encode/decode, walk, activate, per-page flush | `mm/pte.rs`, `mm/page_table.rs` walk |
| `UserContextT` | build/enter/exit a user context, park/resume | `sched/context.rs` naked pair |
| `Entry` | user→kernel entry (syscall/exception), frame shape | SYSCALL/SYSRET + IDT frames |
| `MmuFeat` | W^X/SMEP/SMAP-or-PAN equivalents, feature detect | `arch/features.rs` |
| `DmaProt` | IOMMU: per-domain DMA windows (Phase 3, design-first) | VT-d (not yet present) |

Deliberately **not** abstracted: the security policy itself (masks,
capabilities, monitor, memory checks), the scheduler math, the VFS,
IPC, and the audit trail. Policy is identical on every arch; that is
the point.

### D3 — The discipline starts now, not at the restructure

Until Phase 2 moves the crates, every new feature applies the seam
*within* the current tree:

- the **policy/decision half** lands in `src/` (host-tested, portable);
- the **hardware half** lands in `kernel-x86_64/` behind a module
  boundary that a Phase-2 move can lift verbatim.

Preemption (this commit) is the first demonstration:
`src/preempt.rs` owns the switch decisions (tick → charge → pick;
exit → hand over), host-tested against the real `Scheduler`; the x86_64
crate owns only the LAPIC, the IDT wiring, and the frame rewrite.

### D4 — CI enforcement, from today

- New CI job: `cargo build` of the policy core for
  `aarch64-unknown-none-softfloat` **and**
  `riscv64imac-unknown-none-elf`. Any arch assumption in `src/` fails
  the compiler, not a future porting project.
- Phase 2 adds `qemu-system-aarch64 -M virt` to the boot-test matrix
  with the *same* acceptance markers as x86_64.
- RISC-V is a build-only target until its full port (Phase 6); we say
  so honestly in README rather than implying parity.

### D5 — What "supports an architecture" means (honesty ladder)

1. **Builds**: policy core compiles for the target (CI job).
2. **Boots**: kernel reaches the console, runs kernel-resident domains.
3. **Isolates**: the ring-3 acceptance markers pass (user domains,
   W^X, faults, monitor feeds).
4. **Schedules**: preemption + the starvation-freedom markers pass.
5. **Full**: drivers/storage/net/userland parity on that arch.

A release states, per arch, the highest rung it has *proven in CI*.
x86_64 is at rung 4 as of this ADR's preemption commit; aarch64 and
RISC-V are at rung 1.

## Consequences

- The Phase-2 restructure becomes mostly `git mv` + wiring: the seam
  already exists where new code was written against it.
- Unsafe accounting gets per-arch baselines; the total ratchet keeps
  its ADR requirement to grow.
- An adopting company auditing the system has a crisp boundary: above
  the HAL, one implementation, arch-independent; below it, small,
  documented, per-arch surfaces.
- Cost: one restructure PR series (~1 week) and slightly more trait
  indirection in the kernel core. The alternative — re-deriving the
  memory, scheduling, and monitor integration per arch — is the
  classic route to per-arch policy divergence, the exact failure mode
  this project cannot afford.
