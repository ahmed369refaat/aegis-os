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
//!   the user RFLAGS from R11 untouched.
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
//!   is restored bit-for-bit.
//! - **Round-trip measurement**: RDTSC brackets the dispatch call; the
//!   delta lands in `ROUNDTRIP` (plain store; single CPU) and kmain
//!   prints it as the acceptance number.

#![allow(unsafe_code)]

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

/// The register image the stub parks on the syscall stack (lowest
/// address first — the stub's push order). Documentation of the asm
/// below; the offsets must match exactly.
#[repr(C)]
pub struct SyscallFrame {
    _pad0: u64,   // stack alignment (12 slots = 96 bytes)
    pub rax: u64, // syscall number in; result out
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rcx: u64, // user rip (SYSRET target)
    pub r11: u64, // user rflags (SYSRET restores)
    pub rbx: u64, // borrowed for the TSC measurement, restored
    _pad1: u64,   // alignment
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
        "movq 8(%rsp), %rdi",          // nr   (user RAX)
        "movq 16(%rsp), %rsi",         // a1   (user RDI)
        "movq 24(%rsp), %rdx",         // a2   (user RSI)
        "movq 32(%rsp), %rcx",         // a3   (user RDX)
        "movq 40(%rsp), %r8",          // a4   (user R10)
        "movq 48(%rsp), %r9",          // a5   (user R8)
        "call {dispatch}",
        // ── result + t1 ──
        "movq %rax, 8(%rsp)",          // result into the user-RAX slot
        "rdtsc",
        "shlq $32, %rdx",
        "orq %rdx, %rax",
        "subq %rbx, %rax",             // delta = t1 - t0
        "movq %rax, {rt}(%rip)",       // ROUNDTRIP (single CPU)
        // ── restore: clobber exactly RAX, RCX, R11 ──
        "movq 64(%rsp), %rcx",         // user rip   (SYSRET uses RCX)
        "movq 72(%rsp), %r11",         // user rflags (SYSRET uses R11)
        "movq 80(%rsp), %rbx",         // the borrowed callee-saved
        "movq 8(%rsp),  %rax",         // result
        "movq 16(%rsp), %rdi",
        "movq 24(%rsp), %rsi",
        "movq 32(%rsp), %rdx",
        "movq 40(%rsp), %r10",
        "movq 48(%rsp), %r8",
        "movq 56(%rsp), %r9",
        "addq $96, %rsp",
        "swapgs",                      // GS ← user value
        "sysretq",                     // CPL=3, RFLAGS from R11
        srsp = sym SYSCALL_RSP,
        dispatch = sym crate::syscall::syscall_dispatch,
        rt = sym ROUNDTRIP,
        options(att_syntax),
    );
}
