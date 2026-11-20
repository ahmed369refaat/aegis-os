# Stage 1 — Ring-3 Isolation: Track A PR Plan (first 5 PRs)

> Concrete, reviewable units of work for Stage 1 Track A (x86_64). Each
> PR: < 500 lines, ships host tests for its logic, a QEMU-verifiable
> marker, and a `docs/arch/*.md` file. Order is dependency order — do not
> reorder. Track B (aarch64) is outlined at the end and starts only after
> PR-1.5's acceptance is green in CI.
>
> Signatures below are the intended public surface; minor adjustments
> during review are fine, the invariants are not.

## PR-1.1 — `arch: exception machinery (IDT, GDT/TSS, IST stacks)`

The foundation every later PR depends on: without a working IDT, a bug in
Ring-3 work is a silent hang instead of a diagnosed fault.

**New files**

- `kernel-x86_64/src/arch/mod.rs` — module wiring; `arch::init()` called
  from `kmain` before anything else.
- `kernel-x86_64/src/arch/gdt.rs`
  - `pub struct Gdt([u64; 8])`, `pub struct Tss`
  - `Gdt::new()` → kernel code/data + user code/data + tss slots
  - `Tss::new()`, `Tss::set_rsp0(vaddr: usize)`, `Tss::set_ist(slot: usize, vaddr: usize)`
  - `Gdt::load(&'static self)`, `load_tr(selector: u16)`
- `kernel-x86_64/src/arch/idt.rs`
  - `pub struct Idt { entries: [Entry; 256] }`
  - `Idt::new()`, `Idt::set_exception(&mut self, vec: u8, handler: usize, ist: u8, dpl: u8)`
  - `Idt::load(&'static self)`; `Entry` encoding as pure functions
    (`Entry::encode(handler, ist, dpl) -> u64` — host-testable).
- `kernel-x86_64/src/arch/frame.rs`
  - `#[repr(C)] pub struct ExceptionFrame { regs: [u64; 15], vector: u64, error_code: u64, rip: u64, cs: u64, rflags: u64, rsp: u64, ss: u64 }`
- `kernel-x86_64/src/arch/stubs.rs` — `global_asm!` stubs: push regs →
  `exception_common(frame)` for the CPU-exception vectors.
- `kernel-x86_64/src/arch/exceptions.rs`
  - `extern "C" fn exception_common(frame: &ExceptionFrame)`
  - `pub fn handle_divide_error`, `handle_general_protection`,
    `handle_page_fault(frame, cr2)`, `handle_double_fault -> !`,
    `handle_stack_segment`, `handle_invalid_tss`…
- `docs/arch/exceptions.md` — design, IST/stack invariants, threat model
  (why #DF and #SS must be IST, why handlers are `unsafe`-allowlisted).

**Tests:** host — IDT entry encoding (present/DPL/IST/selectors), TSS
layout offsets against the SDM; QEMU — a `#[cfg(feature = "selftest")]`
divide-by-zero in the kernel prints `[EXC] #DE vector=0 rip=…` and halts
cleanly (proves entry → Rust handler → serial works).

**Acceptance marker:** `[EXC] selftest: exception machinery ok`.

## PR-1.2 — `mm: higher-half kernel, direct map, per-CPU, guarded stacks`

**New / modified files**

- `kernel-x86_64/linker.ld` — base `0xFFFFFFFF80000000`; keep the
  `_kernel_end` ASSERT.
- `boot-x86_64/stub.S` / `stub.ld` — stub maps *both* the low identity
  window and the higher-half kernel window before entry; entry address
  passed via `--defsym` as today.
- `kernel-x86_64/src/mm/mod.rs` — `pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;`
- `mm/direct_map.rs`
  - `pub const DIRECT_MAP_BASE: u64 = 0xFFFF_8880_0000_0000;`
  - `pub fn pa_to_va(pa: u64) -> u64`, `pub fn va_to_pa(va: u64) -> Option<u64>`
- `mm/stacks.rs`
  - `pub struct KernelStacks { … }`, `alloc(pages: usize) -> KernelStack`
    (guard page below, zeroed on free — scrub path reused)
- `arch/percpu.rs`
  - `pub struct PerCpu { pub cpu_id: u32, pub current: u32, pub kstack_top: u64 }`
  - `pub fn init()`, `pub fn get() -> &'static PerCpu` (GS-relative)
- `docs/arch/memory-layout.md` — the full map diagram + invariants + the
  threat model (user space low half only; kernel never maps user pages
  executable; direct map is RW, X-only-via-alias forbidden).

**Tests:** host — pa/va translation round-trips and range rejects;
QEMU — boot with symbols at the high base, the existing M1 sequence
still passes (frame pool now accessed via the direct map); a selftest
write to a guard page → `[EXC] #PF guard` panic.

**Acceptance markers:** M1 markers still green + `[MM ] higher-half ok`.

## PR-1.3 — `mm: per-domain page tables (policy → real PTEs)`

The heart of Stage 1: the lib's ten-check memory policy stays the gate;
what changes is that its decisions become hardware.

**New / modified files**

- `src/buddy.rs` (core lib) — `pub struct BuddyAllocator<const N: usize = 256>`
  with `pub type Buddy256 = BuddyAllocator<256>;` (existing call sites and
  tests unchanged via the default; kernel uses `BuddyAllocator<4096>` =
  16 MiB pool).
- `kernel-x86_64/src/mm/page_table.rs`
  - `pub struct PageTables { pml4: usize }`
  - `PageTables::new() -> Result<Self, FrameError>`
  - `map_user_page(&mut self, va: u64, pa: u64, flags: PteFlags) -> Result<(), MapError>`
  - `map_region(&mut self, base: u64, len: usize, flags: PteFlags) -> Result<Region, MapError>`
    *(runs the core `AddressSpace::map` policy first, then writes PTEs)*
  - `unmap_region(&mut self, base: u64) -> Result<Region, MapError>`
    *(PTEs removed + scrub + TLB flush, then policy unmap)*
  - `cr3(&self) -> u64`, `activate(&self)`
  - table-walk helpers against the direct map (no recursive mapping).
- `mm/pte.rs` — `pub struct PteFlags { pub r: bool, pub w: bool, pub x: bool, pub user: bool }`
  → PTE bit translation (XD for !x), `flush_tlb_page(va: u64)`.
- `docs/mm/page-tables.md` — invariants (every user PTE has U set and
  comes from the policy gate; guard-gap pages are *absent* PTEs; kernel
  entries are global), threat model (aliasing, TLB, direct-map leakage).

**Tests:** host — pure table-bookkeeping parts against a fake frame
source; policy-rejection cases (adjacent map → GuardGap) still enforced
before any PTE write; QEMU — two domains with disjoint tables: kernel
probe of A's page succeeds via direct map, the same *virtual* address in
B is a different frame, and the guard page between regions faults.

**Acceptance marker:** `[MM ] per-domain tables: 2 domains, W^X + guards live`.

## PR-1.4 — `arch: SYSCALL/SYSRET entry + the first Ring-3 domain`

**New files**

- `kernel-x86_64/src/arch/syscall_entry.rs`
  - `pub fn init(entry: u64)` — writes IA32_STAR/LSTAR/FMASK MSRs
  - `global_asm!` stub: `swapgs` → save regs → `syscall_dispatch(frame)`
    → restore → `sysretq`
  - `#[repr(C)] pub struct SyscallFrame { rax, rdi, rsi, rdx, r10, r8, r9, … }`
  - `fn syscall_dispatch(frame: &mut SyscallFrame) ` — runs the policy
    gate (`Kernel::dispatch`), executes, records the round-trip TSC delta
    (boot-time measurement of the fast path).
- `kernel-x86_64/src/mm/user.rs`
  - `pub fn spawn_user_blob(&mut Kernel, code: &[u8], entry_off: u64, stack_pages: usize) -> Result<u32, M1Error>`
    — code mapped RX, stack RW with a guard page below, `UserContext` built.
- `kernel-x86_64/src/sched/context.rs`
  - `pub struct UserContext { rip, rsp, rflags, … }`
  - `pub fn enter_ring3(ctx: &UserContext) -> !` (sysretq path, RPL3)
- `examples/ring3-hello/` — a new workspace crate: `#![no_std]`
  `#![no_main]` static user blob (asm entry + one syscall), built to a
  flat binary by `boot.sh` and embedded in the kernel with
  `include_bytes!`.
- `docs/arch/syscall-entry.md` — MSR contract, register save/restore
  invariants, why the gate runs before anything else.

**Tests:** host — dispatch-table routing (allow/deny/quarantine) over the
core; QEMU — the marker from Ring-3 itself.

**Acceptance marker:** `hello from ring 3 (CPL=3)` + a printed
`syscall round-trip: N cycles`.

## PR-1.5 — `arch: faults → SIGSEGV + audit trail (Stage-1 gate)`

**New files**

- `kernel-x86_64/src/arch/fault.rs`
  - `pub enum FaultKind { GuardPage, WxViolation, UserWrite, UserRead, KernelBug }`
  - `pub fn classify_page_fault(frame: &ExceptionFrame, cr2: u64) -> FaultKind`
  - `pub fn deliver_signal_default(domain: u32, kind: FaultKind) -> !`
    (SIGSEGV default action: terminate → `destroy_domain` supervised path)
- `kernel-x86_64/src/audit/audit.rs`
  - `pub struct AuditRecord { pub domain: u32, pub kind: AuditKind, pub detail: u64, pub tsc: u64 }`
  - `pub fn audit_event(kind: AuditKind, detail: u64)` — SPSC ring over
    the core `RingBuffer`, drained to serial at boot and later by `auditd`
  - `AuditKind::{SyscallDenied, Sigsegv, WxViolation, Quarantine, CapRevoked}`
- Boot demo extension (`kmain.rs`): after the hello domain, spawn a second
  user blob that (a) issues a syscall outside its mask and (b) writes to
  a guard page — both must end in SIGSEGV + audit lines while domain 1
  keeps running.
- `docs/arch/faults-signals.md` + threat-model section (fault side
  channels, fault-storm rate limiting via the existing monitor counters).

**Tests:** host — fault classification table; QEMU — the Stage-1
acceptance markers.

**Acceptance markers (the Stage-1 Track A gate):**
`[AUDIT] domain N SIGSEGV (syscall denied)`, `[AUDIT] domain N SIGSEGV (guard page)`,
`healthy domain still running: yes`, and `STAGE1-EXIT: PASS` with all
components (hello CPL=3, deny→SIGSEGV, audit, W^X/guards, boot ≤ 400 ms).

---

## Track B outline (aarch64 parity, PRs B1–B5, after 1.5)

- **B1** `boot-aarch64/` + `kernel/src/arch/aarch64/`: QEMU `-M virt`
  boot (raw Image header, PL011 serial, EL2→EL1), linker at a fixed
  DRAM base; kernel crate restructured into `kernel/src/arch/{x86_64,aarch64}`.
- **B2** stage-1 MMU tables (block + page granularity), direct map, per-CPU (TPIDR).
- **B3** SVC entry + `eret` to EL0; the same `SyscallFrame` contract.
- **B4** synchronous/translation exceptions → the same `FaultKind`/audit
  path; PAN enable + fallback.
- **B5** CI matrix: aarch64 build + QEMU boot job running the same
  Stage-1 markers.

## Sequencing rules

- PR-1.1 must merge before any Ring-3 work; PR-1.3 before 1.4; 1.5 closes
  the gate. No stage-2 work in these PRs (pipes stay the lib version —
  no premature IPC).
- Every PR keeps the M1 exit-criteria boot test green; a red boot test
  blocks merge regardless of unit tests.
