//! SYSCALL/SYSRET entry (PR-1.4): the MSR contract and the naked
//! fast-path stub.
//!
//! SAFETY POLICY: allowlisted module (naked assembly + MSR programming,
//! same class as the rest of `arch`; see `docs/adr/0005` and
//! `docs/arch/syscall-entry.md`).
//!
//! Invariants:
//! - **STAR slot arithmetic** is pinned by `gdt`'s host test: SYSCALL
//!   enters on CS=0x30/SS=0x38, SYSRET leaves on CS=0x2b/SS=0x23
//!   (RPL 3 added by the instruction itself).
//! - **SFMASK = IF|TF|DF**: the kernel always starts a syscall with
//!   interrupts off, no trap flag, no direction flag — SYSRET restores
//!   the user RFLAGS from R11 untouched. Since ADR-0012 the stub also
//!   executes an explicit `cli` right after `swapgs`: in this
//!   environment (QEMU 10.0.13 TCG, `-cpu max`) SYSCALL demonstrably
//!   does NOT apply FMASK.IF — the dispatch was measured running with
//!   IF=1 — so the no-nesting invariant is self-enforced, not trusted
//!   to the MSR.
//! - **SYSCALL does not switch stacks.** The stub loads RSP from the
//!   per-CPU `kstack_top` via `%gs:` right after `swapgs`; the TSS
//!   RSP0 (same stack) only serves the *interrupt/exception* path.
//! - **GS pairing**: entry `swapgs` ↔ exit `swapgs`; SYS_EXIT never
//!   reaches the exit path (the dispatch longjmps) and does its own
//!   swap before that jump.
//! - **The saved-register contract** (the ABI user code may rely on):
//!   a syscall clobbers exactly RAX (result), RCX and R11 (the
//!   architecture's syscall rip/rflags carriers). Everything else —
//!   including RBX, which the stub borrows for the TSC measurement —
//!   is restored bit-for-bit — including the **user RSP** (Round J):
//!   SYSRET restores only RIP/RFLAGS, and the stub has switched RSP
//!   to the kernel stack on entry, so the stub itself carries the
//!   user's stack pointer across (USER_RSP_SAVE) and reloads it right
//!   before SYSRETQ. Before round J every sysret silently returned to
//!   ring-3 running on the kernel's stack pointer — invisible because
//!   no earlier blob ever touched its stack.
//! - **Round-trip measurement**: RDTSC brackets the dispatch call; the
//!   delta lands in `ROUNDTRIP` (plain store; single CPU) and kmain
//!   prints it as the acceptance number.

#![allow(unsafe_code)]

use super::syscall_frame::{
    OFF_R10, OFF_R11, OFF_R8, OFF_R9, OFF_RAX, OFF_RBX, OFF_RCX, OFF_RDI, OFF_RDX, OFF_RSI,
};
use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::gdt;
use crate::hw;

// ── MSR indices ──────────────────────────────────────────────────────
const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_FMASK: u32 = 0xC000_0083;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// RFLAGS bits the kernel clears on entry: IF (9), TF (8), DF (10).
const FMASK_IF_TF_DF: u64 = 1 << 9 | 1 << 8 | 1 << 10;

/// Last measured SYSCALL→SYSRET round-trip (TSC cycles). Written by the
/// stub (plain store — single CPU), read by kmain after the run.
static ROUNDTRIP: AtomicU64 = AtomicU64::new(0);

/// The syscall-entry stack top (RIP-relative read; the GS path arrives
/// with Stage 4's SMP work — see docs/arch/syscall-entry.md).
static SYSCALL_RSP: AtomicU64 = AtomicU64::new(0);

/// Round J: the user RSP of the in-flight syscall. SYSRET restores
/// RIP/RFLAGS (from RCX/R11) but NOT RSP — and the stub switches RSP
/// to the kernel stack on entry — so the user's stack pointer must be
/// carried across the excursion explicitly or every sysret returns to
/// ring-3 running on the KERNEL's stack pointer. Hidden since PR-1.4:
/// every ring-3 blob before round J was pure register code that never
/// touched its stack, so the first `call`/`push` in ring-3 history
/// (the files blob's verify subroutine) was the first to expose it —
/// a #PF pushing a return address through a kernel-half RSP. Written
/// by the stub BEFORE the stack switch (the only moment the value
/// exists in a register), read back right before SYSRETQ. Single CPU
/// + IF=0 through the whole kernel side: exactly one excursion is ever
///   in flight, the same lifetime discipline as SYSCALL_RSP itself.
static USER_RSP_SAVE: AtomicU64 = AtomicU64::new(0);

/// ADR-0023: the in-flight syscall's frame address (the post-push
/// RSP), published right before `call dispatch` so the park paths
/// (nanosleep/yield, sched/park.rs) can rebuild the user image from
/// it. Same lifetime discipline as USER_RSP_SAVE: single CPU, IF=0,
/// exactly one excursion in flight.
static SYSCALL_FRAME: AtomicU64 = AtomicU64::new(0);

/// The published address of the in-flight syscall's frame.
pub fn syscall_frame_addr() -> u64 {
    SYSCALL_FRAME.load(Ordering::Relaxed)
}

/// Read one word of the in-flight frame at an OFF_* offset (ADR-0023:
/// the signal paths rebuild/rewrite the user image through the SAME
/// table the stub's own loads use — the struct is mirror-imaged and
/// must never be cast onto the base pointer).
///
/// SAFETY: the entry published the address; single CPU, IF=0.
pub fn frame_word(off: u64) -> u64 {
    let base = SYSCALL_FRAME.load(Ordering::Relaxed);
    unsafe { *((base + off) as *const u64) }
}

/// Write one word of the in-flight frame at an OFF_* offset.
///
/// SAFETY: the entry published the address; single CPU, IF=0; the
/// write is 8-byte aligned inside the frame.
pub fn write_frame_word(off: u64, val: u64) {
    let base = SYSCALL_FRAME.load(Ordering::Relaxed);
    unsafe { *((base + off) as *mut u64) = val };
}

/// ADR-0024 D2: the user's callee-saved registers (rbp, r12, r13,
/// r14, r15), parked by the stub AT ENTRY — the same lifetime
/// discipline as USER_RSP_SAVE. They CANNOT be read live at dispatch
/// depth: past the stub's `call`, rbp/r12-15 are the RUST COMPILER'S
/// scratch (SysV makes every callee preserve them, which means the
/// user's values live in the callees' stack frames, not in the
/// registers — found live when the fork path's parked images carried
/// compiler scratch as user state and both runs died writing through
/// garbage r12). The stub stores them before anything can clobber;
/// SYSRET needs no restore (the whole kernel path preserved them).
static mut USER_RBP: u64 = 0;
static mut USER_R12: u64 = 0;
static mut USER_R13: u64 = 0;
static mut USER_R14: u64 = 0;
static mut USER_R15: u64 = 0;

/// The user's callee-saved register values parked at syscall entry,
/// in `[rbp, r12, r13, r14, r15]` order.
pub fn user_callee_saved() -> [u64; 5] {
    // SAFETY: single CPU, one in-flight excursion; the stub wrote
    // these before `call dispatch` and nothing else touches them.
    unsafe { [USER_RBP, USER_R12, USER_R13, USER_R14, USER_R15] }
}

/// Round J's parked user RSP, read by the park paths.
pub fn user_rsp_save() -> u64 {
    USER_RSP_SAVE.load(Ordering::Relaxed)
}

/// ADR-0023 D8: rewrite the in-flight user RSP (the signal delivery
/// paths: the frame push moves the stack; sigreturn restores it).
pub fn set_user_rsp_save(rsp: u64) {
    USER_RSP_SAVE.store(rsp, Ordering::Relaxed);
}

fn percpu_kstack_top() -> u64 {
    crate::arch::percpu::get().kstack_top
}

/// Refresh the syscall entry stack (kmain, after allocating the guarded
/// stack for ring-3).
pub fn set_entry_stack(top: u64) {
    SYSCALL_RSP.store(top, Ordering::Relaxed);
}

/// The measured round-trip of the most recent completed syscall.
pub fn roundtrip() -> u64 {
    ROUNDTRIP.load(Ordering::Relaxed)
}

/// Arm SYSCALL/SYSRET: STAR/LSTAR/FMASK MSRs, EFER.SCE, and the swapgs
/// partner (KERNEL_GS_BASE = percpu). Must run in the kernel GS state
/// (before the first ring-3 launch).
pub fn init() {
    // STAR: SYSCALL CS ← [47:32] (our 0x30 slot), SYSRET CS ← [63:48]+16
    // and SS ← [63:48]+8 — the gdt host test pins the whole arithmetic.
    let star = ((gdt::KERNEL_CODE as u64) << 48) | ((gdt::SYSCALL_CODE as u64) << 32);
    hw::wrmsr(MSR_STAR, star);
    let entry: extern "C" fn() = syscall_entry;
    hw::wrmsr(MSR_LSTAR, entry as usize as u64);
    hw::wrmsr(MSR_FMASK, FMASK_IF_TF_DF);
    // EFER.SCE (bit 0): the instructions exist at all.
    let efer = hw::rdmsr(MSR_EFER);
    hw::wrmsr(MSR_EFER, efer | 1);
    // Publish the entry stack (kmain refreshes it when it allocates the
    // dedicated guarded stack).
    SYSCALL_RSP.store(percpu_kstack_top(), Ordering::Relaxed);
    // swapgs partner: KERNEL_GS_BASE holds the *user* value (0). The
    // launch's swapgs then lands GS=user / KGS=percpu — and every
    // entry (swapgs → percpu) / exit (swapgs → user) pair balances.
    // (Writing percpu here instead would be a no-op swap: GS already
    // holds percpu in kernel mode.)
    hw::wrmsr(MSR_KERNEL_GS_BASE, 0);
    crate::serial::write_str("[ARCH] syscall entry armed: STAR/LSTAR/FMASK, SCE on\n");
}

/// The fast path. Stack discipline: RSP lands on `kstack_top` (16-byte
/// aligned); the stub pushes exactly 12 quadwords (96 bytes) so the
/// `call` meets the SysV ABI alignment, and the pad slots exist purely
/// for that arithmetic.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn syscall_entry() {
    naked_asm!(
        "swapgs",                      // GS ← percpu (KERNEL_GS_BASE ↔ user)
        "cli",                         // self-enforcing: interrupts OFF for
                                       // the whole kernel side of the syscall
                                       // (ADR-0012: SYSCALL's FMASK path does
                                       // NOT clear IF in this environment —
                                       // observed QEMU 10.0.13 TCG, -cpu max —
                                       // so the stub enforces the no-nesting
                                       // invariant itself; SYSRET restores the
                                       // user's IF from R11)
        "movq %rbp, {ubp}(%rip)",       // ADR-0024: park the user's
        "movq %r12, {ur12}(%rip)",      // callee-saved five BEFORE
        "movq %r13, {ur13}(%rip)",      // anything can clobber them
        "movq %r14, {ur14}(%rip)",      // (SYSRET needs no restore:
        "movq %r15, {ur15}(%rip)",      // the kernel path preserves)
        "movq %rsp, {ursp}(%rip)",     // Round J: park the USER RSP —
                                       // SYSRET will not restore it, and
                                       // the switch below destroys it
        "movq {srsp}(%rip), %rsp",     // SYSCALL switches no stack; we do
        // ── park the user registers (SyscallFrame order) ──
        "pushq $0",                    // pad (alignment)
        "pushq %rax",                  // nr → result slot
        "pushq %rdi",
        "pushq %rsi",
        "pushq %rdx",
        "pushq %r10",
        "pushq %r8",
        "pushq %r9",
        "pushq %rcx",                  // user rip
        "pushq %r11",                  // user rflags
        "pushq %rbx",                  // borrowed below, restored
        "pushq $0",                    // pad (alignment)
        // ── measure t0 ──
        "rdtsc",
        "shlq $32, %rdx",
        "orq %rdx, %rax",
        "movq %rax, %rbx",             // t0 (dispatch preserves RBX)
        // ── dispatch(nr, a1..a5): SysV arg registers from the frame ──
        // Every slot reference goes through the OFF_* consts — the same
        // table the host test pins against SyscallFrame (see the OFF_*
        // docs for the M2-W2 mirror-inversion this prevents).
        "movq {off_rax}(%rsp), %rdi",  // nr   (user RAX)
        "movq {off_rdi}(%rsp), %rsi",  // a1   (user RDI)
        "movq {off_rsi}(%rsp), %rdx",  // a2   (user RSI)
        "movq {off_rdx}(%rsp), %rcx",  // a3   (user RDX)
        "movq {off_r10}(%rsp), %r8",   // a4   (user R10)
        "movq {off_r8}(%rsp), %r9",    // a5   (user R8)
        "movq %rsp, {sfrm}(%rip)",     // ADR-0023: publish the frame
                                       // address for the park paths
        "call {dispatch}",
        // ── result + t1 ──
        "movq %rax, {off_rax}(%rsp)",  // result into the user-RAX slot
        "rdtsc",
        "shlq $32, %rdx",
        "orq %rdx, %rax",
        "subq %rbx, %rax",             // delta = t1 - t0
        "movq %rax, {rt}(%rip)",       // ROUNDTRIP (single CPU)
        // ── restore: clobber exactly RAX, RCX, R11 ──
        "movq {off_rcx}(%rsp), %rcx",  // user rip   (SYSRET uses RCX)
        "movq {off_r11}(%rsp), %r11",  // user rflags (SYSRET uses R11)
        "movq {off_rbx}(%rsp), %rbx",  // the borrowed callee-saved
        "movq {off_rax}(%rsp), %rax",  // result
        "movq {off_rdi}(%rsp), %rdi",
        "movq {off_rsi}(%rsp), %rsi",
        "movq {off_rdx}(%rsp), %rdx",
        "movq {off_r10}(%rsp), %r10",
        "movq {off_r8}(%rsp), %r8",
        "movq {off_r9}(%rsp), %r9",
        "movq {ursp}(%rip), %rsp",     // Round J: the user's RSP back —
                                       // SYSRET restores RIP/RFLAGS only,
                                       // so this is the ONLY RSP restore
        "swapgs",                      // GS ← user value
        "sysretq",                     // CPL=3, RFLAGS from R11
        srsp = sym SYSCALL_RSP,
        ursp = sym USER_RSP_SAVE,
        ubp = sym USER_RBP,
        ur12 = sym USER_R12,
        ur13 = sym USER_R13,
        ur14 = sym USER_R14,
        ur15 = sym USER_R15,
        sfrm = sym SYSCALL_FRAME,
        dispatch = sym crate::syscall::syscall_dispatch,
        rt = sym ROUNDTRIP,
        off_rax = const OFF_RAX,
        off_rdi = const OFF_RDI,
        off_rsi = const OFF_RSI,
        off_rdx = const OFF_RDX,
        off_r10 = const OFF_R10,
        off_r8 = const OFF_R8,
        off_r9 = const OFF_R9,
        off_rcx = const OFF_RCX,
        off_r11 = const OFF_R11,
        off_rbx = const OFF_RBX,
        options(att_syntax),
    );
}
