//! Ring-3 scheduling context: the user run state, and the launch /
//! resume pair that crosses the privilege boundary (PR-1.4).
//!
//! SAFETY POLICY: allowlisted module (same class as `arch`: naked
//! assembly entries + the single-CPU run state; see `docs/adr/0005`
//! and `docs/arch/syscall-entry.md`). Everything unsafe here is a
//! static read/write under the single-CPU, single-run-at-a-time
//! invariant, or the naked launch/resume pair below.
//!
//! Invariants:
//! - **Stack discipline**: `enter_ring3` is a naked function — it saves
//!   the caller's RSP (pointing at its return address) *before* the
//!   `iretq` and never touches any callee-saved register, so
//!   `resume_kernel` can `mov rsp, saved; ret` and the kernel continues
//!   as if the launch had simply returned. No frame is left half-built.
//! - **GS pairing**: `enter_ring3` executes one `swapgs` on the way in
//!   (GS: user value, KERNEL_GS_BASE: percpu). Every path back to the
//!   kernel — SYSRET in the syscall entry, SYS_EXIT in the dispatch,
//!   the user-fault branch in the exception dispatch — executes exactly
//!   one `swapgs` of its own. Unbalanced pairs are a kernel bug by
//!   construction.
//! - **One run at a time**: `USER_RUN` holds the single active user
//!   domain (single CPU, no preemption until Stage 4). `begin` before
//!   `enter_ring3`, `take` after `resume_kernel` reaches kmain.

#![allow(unsafe_code)]

use aegis_os::memory::AddressSpace;
use aegis_os::syscall::SyscallMask;

use crate::arch::frame::ExceptionFrame;
use crate::mm::page_table::PageTables;

/// RFLAGS for a freshly launched user context: interrupts on (IF, bit 1
/// in this encoding), reserved bit 1 set as the architecture requires,
/// everything else clear — no FPU carry-over, no trap flag.
pub const USER_RFLAGS: u64 = 0x202;

/// The register image `iretq` needs to enter ring-3 (CPL=3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserContext {
    pub rip: u64,
    /// Full selector including RPL 3 (0x2b with the PR-1.4 GDT layout).
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    /// Full selector including RPL 3 (0x23).
    pub ss: u64,
}

impl UserContext {
    /// A context entering `rip` with the stack pointer at `rsp`, on the
    /// user segments from `arch::gdt` (which SYSRET's arithmetic also
    /// targets — the two entry paths agree by construction).
    pub fn new(rip: u64, rsp: u64) -> Self {
        UserContext {
            rip,
            cs: (crate::arch::gdt::USER_CODE | 3) as u64,
            rflags: USER_RFLAGS,
            rsp,
            ss: (crate::arch::gdt::USER_DATA | 3) as u64,
        }
    }
}

/// How a user run ended. `Fault` carries everything the security log
/// prints: what faulted, where, and under which error-code bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// The domain called SYS_EXIT(code).
    Exited(u64),
    /// A CPU fault at CPL3 (the domain is terminated; the kernel lives).
    Fault {
        vector: u8,
        cr2: u64,
        error_code: u64,
        rip: u64,
        user_rsp: u64,
    },
}

/// The single active user run: hardware context + gate snapshot +
/// the run's telemetry. Plain data, no pointers — safe to park in a
/// static between the launch and the resume.
pub struct UserRun {
    /// The domain's page tables (PR-1.3) — the dispatch validates user
    /// pointers by walking these.
    pub tables: PageTables,
    /// The policy space that gated every mapped region.
    pub space: AddressSpace,
    /// Lib domain id (audit/accounting identity; frames are pool-owned
    /// by this id).
    pub domain: u32,
    /// Gate snapshot (checked by the same `aegis_os::syscall::gate` the
    /// kernel-resident path uses).
    pub mask: SyscallMask,
    pub quarantined: bool,
    /// How the run ended (written by SYS_EXIT or the fault branch).
    pub exit: ExitKind,
    /// SYS_WRITE byte count (the run's positive contribution).
    pub write_bytes: u64,
    /// Unknown-syscall attempts (audit signal, replayed into the lib
    /// telemetry after the resume).
    pub bad_syscalls: u32,
    /// Policy-denied syscall attempts (masked or quarantined).
    pub denied: u32,
    /// Measured SYSCALL→SYSRET round-trip of the first write (TSC).
    pub roundtrip_tsc: u64,
    /// ADR-0023 D8: the in-flight DELIVERED signal (set at delivery,
    /// consumed by rt_sigreturn) — the kernel's own frame record; the
    /// user-side frame is never trusted without it.
    pub delivered: Option<Delivered>,
}

/// ADR-0023 D8: the delivery record — what the kernel knows about the
/// signal frame it pushed (the user-visible copy can be forged; this
/// cannot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivered {
    pub sig: u8,
    /// The kernel-chosen cookie (TSC-mixed; embedded in the frame and
    /// matched at sigreturn).
    pub cookie: u64,
    /// The frame's exact user address (a displaced frame refuses).
    pub frame_rsp: u64,
}

impl UserRun {
    pub fn new(
        tables: PageTables,
        space: AddressSpace,
        domain: u32,
        mask: SyscallMask,
        quarantined: bool,
    ) -> Self {
        UserRun {
            tables,
            space,
            domain,
            mask,
            quarantined,
            exit: ExitKind::Exited(0),
            write_bytes: 0,
            bad_syscalls: 0,
            denied: 0,
            roundtrip_tsc: 0,
            delivered: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Parked contexts (M2-W2 / ADR-0012): the register image of a ring-3 run
// that is runnable but NOT the one on the CPU — preempted by the timer,
// or freshly spawned and not yet entered. Pure data + pure mapping
// helpers, host-tested; the table and the naked entry live in `entry`.
// ─────────────────────────────────────────────────────────────────────────

/// The complete register image of a parked run: the 15 GPRs in
/// `ExceptionFrame` order, then the iret-frame words. `from_user_context`
/// builds the not-yet-started image (GPRs zeroed — blobs are written not
/// to depend on entry register state); the timer tick builds it from a
/// live interrupt frame.
///
/// The naked resume entry reads this struct at FIXED OFFSETS — pinned by
/// the host test below (the M2-W2 mirror-inversion lesson: an asm offset
/// table is only trustworthy when a test pins it against the struct).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ParkedContext {
    /// r15,r14,r13,r12,r11,r10,r9,r8,rbp,rdi,rsi,rdx,rcx,rbx,rax —
    /// exactly `ExceptionFrame`'s field order.
    pub gprs: [u64; 15],
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    /// The user stack pointer (the CPL3 iret tail, word 1).
    pub rsp: u64,
    /// The user stack selector (the CPL3 iret tail, word 2).
    pub ss: u64,
}

impl ParkedContext {
    /// The not-yet-started image of a freshly spawned domain.
    #[must_use]
    pub fn from_user_context(ctx: &UserContext) -> Self {
        ParkedContext {
            gprs: [0; 15],
            rip: ctx.rip,
            cs: ctx.cs,
            rflags: ctx.rflags,
            rsp: ctx.rsp,
            ss: ctx.ss,
        }
    }
}

/// Read GPR `i` of a frame (0=r15 … 14=rax) — the one place the
/// frame-order mapping is spelled out, host-tested against the struct.
#[must_use]
pub fn gpr_at(frame: &ExceptionFrame, i: usize) -> u64 {
    match i {
        0 => frame.r15,
        1 => frame.r14,
        2 => frame.r13,
        3 => frame.r12,
        4 => frame.r11,
        5 => frame.r10,
        6 => frame.r9,
        7 => frame.r8,
        8 => frame.rbp,
        9 => frame.rdi,
        10 => frame.rsi,
        11 => frame.rdx,
        12 => frame.rcx,
        13 => frame.rbx,
        14 => frame.rax,
        _ => panic!("gpr_at: not a frame GPR index"),
    }
}

/// Write GPR `i` of a frame (the park/unpark pair of `gpr_at`).
pub fn set_gpr_at(frame: &mut ExceptionFrame, i: usize, v: u64) {
    match i {
        0 => frame.r15 = v,
        1 => frame.r14 = v,
        2 => frame.r13 = v,
        3 => frame.r12 = v,
        4 => frame.r11 = v,
        5 => frame.r10 = v,
        6 => frame.r9 = v,
        7 => frame.r8 = v,
        8 => frame.rbp = v,
        9 => frame.rdi = v,
        10 => frame.rsi = v,
        11 => frame.rdx = v,
        12 => frame.rcx = v,
        13 => frame.rbx = v,
        14 => frame.rax = v,
        _ => panic!("set_gpr_at: not a frame GPR index"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_targets_ring3_with_interrupts_on() {
        let c = UserContext::new(0x40_0000, 0x40_9000);
        assert_eq!(c.cs & 0b11, 3, "RPL 3");
        assert_eq!(c.ss & 0b11, 3, "RPL 3");
        assert_eq!(c.cs, crate::arch::gdt::USER_CODE as u64 + 3);
        assert_eq!(c.ss, crate::arch::gdt::USER_DATA as u64 + 3);
        assert_eq!(c.rflags, 0x202);
        assert!(
            c.rflags & (1 << 9) != 0,
            "IF=1: user code runs interruptible"
        );
        assert_eq!(c.rflags & (1 << 8), 0, "TF clear");
        assert_eq!(c.rflags & (1 << 10), 0, "DF clear");
    }

    /// The naked resume entry (`enter_ring3_parked`) reads ParkedContext
    /// at literal offsets — pin them against the struct (the M2-W2
    /// mirror-inversion lesson, applied before the bug can exist).
    #[test]
    fn parked_context_offsets_match_the_asm_table() {
        use core::mem::{offset_of, size_of};
        assert_eq!(offset_of!(ParkedContext, gprs), 0);
        assert_eq!(offset_of!(ParkedContext, rip), 15 * 8, "asm reads 120");
        assert_eq!(offset_of!(ParkedContext, rflags), 17 * 8, "asm reads 136");
        assert_eq!(offset_of!(ParkedContext, rsp), 18 * 8, "asm reads 144");
        assert_eq!(size_of::<ParkedContext>(), 20 * 8);
        // The gprs array and the frame's 15 GPR fields are layout-identical.
        assert_eq!(
            core::mem::offset_of!(ExceptionFrame, vector),
            15 * 8,
            "the frame's GPR block is 15 words — gprs mirrors it"
        );
    }

    #[test]
    fn fresh_parked_context_zeroes_gprs_and_carries_the_iret_frame() {
        let uc = UserContext::new(0x40_0000, 0x40_9000);
        let pc = ParkedContext::from_user_context(&uc);
        assert_eq!(pc.gprs, [0; 15]);
        assert_eq!(pc.rip, 0x40_0000);
        assert_eq!(pc.rsp, 0x40_9000);
        assert_eq!(pc.cs & 3, 3);
        assert_eq!(pc.ss & 3, 3);
        assert_eq!(pc.rflags, USER_RFLAGS);
    }

    /// gpr_at/set_gpr_at must agree with the frame field order exactly —
    /// a park/unpark round-trip through every index preserves every
    /// register (a swapped pair here is a silently corrupted domain).
    #[test]
    fn gpr_indexing_round_trips_every_frame_register() {
        let mut f = ExceptionFrame {
            r15: 1,
            r14: 2,
            r13: 3,
            r12: 4,
            r11: 5,
            r10: 6,
            r9: 7,
            r8: 8,
            rbp: 9,
            rdi: 10,
            rsi: 11,
            rdx: 12,
            rcx: 13,
            rbx: 14,
            rax: 15,
            vector: 48,
            error_code: 0,
            rip: 0x40_0000,
            cs: 0x2b,
            rflags: 0x202,
        };
        let snapshot: [u64; 15] = core::array::from_fn(|i| gpr_at(&f, i));
        assert_eq!(
            snapshot,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        // Write a distinct pattern through the mapping, read it back by field.
        for i in 0..15 {
            set_gpr_at(&mut f, i, 0x1000 + i as u64);
        }
        assert_eq!(f.r15, 0x1000);
        assert_eq!(f.r14, 0x1001);
        assert_eq!(f.r13, 0x1002);
        assert_eq!(f.r12, 0x1003);
        assert_eq!(f.r11, 0x1004);
        assert_eq!(f.r10, 0x1005);
        assert_eq!(f.r9, 0x1006);
        assert_eq!(f.r8, 0x1007);
        assert_eq!(f.rbp, 0x1008);
        assert_eq!(f.rdi, 0x1009);
        assert_eq!(f.rsi, 0x100a);
        assert_eq!(f.rdx, 0x100b);
        assert_eq!(f.rcx, 0x100c);
        assert_eq!(f.rbx, 0x100d);
        assert_eq!(f.rax, 0x100e);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only: the run state and the naked launch/resume pair.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(not(test))]
mod entry {
    use super::{ExitKind, ParkedContext, UserContext, UserRun};
    use crate::arch::frame::ExceptionFrame;
    use core::arch::naked_asm;

    /// Where `enter_ring3` parked the kernel's resume point (RSP holding
    /// its return address). Written once per launch, consumed once per
    /// resume — single CPU, single run.
    /// The kernel resume point, as an explicit (RSP, RIP) pair — immune
    /// to calling-convention games: `enter_ring3` is `-> !`, so the
    /// optimizer may legally turn its call site into a tail jump with
    /// no return address on the stack. `set_resume_point` records both
    /// values from a *returning* function; `resume_kernel` restores the
    /// stack and jumps to the label. Single CPU, single run at a time.
    static mut RESUME_RSP: u64 = 0;
    static mut RESUME_RIP: u64 = 0;
    /// The kernel caller's callee-saved registers, parked at launch and
    /// restored at the resume label. The user excursion crosses code
    /// (the syscall stub, the IST fault handlers) that has no ABI
    /// contract to preserve them, and BOTH run-exit paths jump to the
    /// resume label from mid-Rust (SYS_EXIT in the dispatch, the
    /// user-fault branch in the exception dispatch) — without this
    /// park/restore, kmain's locals kept in callee-saved registers
    /// arrive as the last handler's scratch (M2-W2: `kernel_cr3` landed
    /// as a live `&mut Kernel` and `write_cr3` spun the CPU in a #GP
    /// loop). Single CPU, single run: one slot per register.
    static mut PARK_RBX: u64 = 0;
    static mut PARK_RBP: u64 = 0;
    static mut PARK_R12: u64 = 0;
    static mut PARK_R13: u64 = 0;
    static mut PARK_R14: u64 = 0;
    static mut PARK_R15: u64 = 0;

    /// The active run, or `None` between runs.
    static mut USER_RUN: Option<UserRun> = None;

    /// ADR-0023: a snapshot of the kernel resume chain — the resume
    /// point plus the parked callee-saved registers. A NESTED
    /// dispatcher (sched/park.rs: the yield/sleep paths) overwrites
    /// all eight slots with every `resume_parked`; when its run set
    /// empties it restores the chain so `resume_kernel` lands back in
    /// the OUTER launch (kmain), exactly as a flat kmain-only boot
    /// would. Single CPU, no nesting beyond one level (the park paths
    /// run only from the one in-flight syscall).
    #[derive(Clone, Copy)]
    pub struct ResumeChain {
        rsp: u64,
        rip: u64,
        rbx: u64,
        rbp: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
    }

    /// ADR-0024 D2: the NESTED dispatcher's saved outer chain — the
    /// same storage discipline as RESUME_RIP/PARK_* (one slot, single
    /// CPU, written before the first nested resume, consumed at the
    /// unwind). A plain Option beside its proven neighbors: the
    /// array-of-one shape at the park module level came out of the
    /// linker EIGHT TIMES (SAVED_CHAIN.1-.8 — each CGU its own copy,
    /// state divergence and all); this shape has been single since
    /// M2-W2.
    static mut PARK_CHAIN: Option<ResumeChain> = None;

    /// Save the current chain as the nested dispatcher's outer point.
    ///
    /// SAFETY: single CPU, IF=0 on the caller's path.
    pub fn park_chain_save(chain: ResumeChain) {
        // SAFETY: see the static's doc.
        unsafe { PARK_CHAIN = Some(chain) }
    }

    /// Take the saved outer chain (the unwind consumes it).
    ///
    /// SAFETY: single CPU, IF=0 on the caller's path.
    pub fn park_chain_take() -> Option<ResumeChain> {
        // SAFETY: see the static's doc.
        unsafe { PARK_CHAIN.take() }
    }

    /// Snapshot the current resume chain (see `ResumeChain`).
    ///
    /// SAFETY: single CPU; plain reads of the eight statics.
    pub fn save_resume_chain() -> ResumeChain {
        // SAFETY: no concurrent writer (single CPU, IF=0 on this path).
        unsafe {
            ResumeChain {
                rsp: RESUME_RSP,
                rip: RESUME_RIP,
                rbx: PARK_RBX,
                rbp: PARK_RBP,
                r12: PARK_R12,
                r13: PARK_R13,
                r14: PARK_R14,
                r15: PARK_R15,
            }
        }
    }

    /// Restore a saved resume chain (see `ResumeChain`).
    ///
    /// SAFETY: single CPU; plain writes of the eight statics.
    pub fn restore_resume_chain(chain: &ResumeChain) {
        // SAFETY: no concurrent writer (single CPU, IF=0 on this path).
        unsafe {
            RESUME_RSP = chain.rsp;
            RESUME_RIP = chain.rip;
            PARK_RBX = chain.rbx;
            PARK_RBP = chain.rbp;
            PARK_R12 = chain.r12;
            PARK_R13 = chain.r13;
            PARK_R14 = chain.r14;
            PARK_R15 = chain.r15;
        }
    }

    /// N2 (ADR-0007 §2): the live lib Kernel, set once by kmain before
    /// the first ring-3 launch. The ring-3 syscall path gates through
    /// it (stats, denials, Tighten/Quarantine apply to the very next
    /// syscall) and drives its monitor windows from the TSC.
    /// SAFETY POLICY: part of the documented unsafe allowlist (sched/),
    /// same single-CPU static-mut pattern as USER_RUN above: set once
    /// during bring-up, read-only afterwards, never aliased
    /// concurrently (the dispatch runs on the kernel stack of the only
    /// CPU; nested entry is impossible — SYSCALL never re-enters the
    /// kernel — and the fault path runs after the dispatch returned).
    static mut KERNEL: Option<*mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>> = None;

    /// Install the run state. Called from kmain just before
    /// `enter_ring3`.
    pub fn begin(run: UserRun) {
        // SAFETY: single CPU; written before the launch, and nothing
        // reads it until the dispatch runs (which is after the launch).
        unsafe { USER_RUN = Some(run) }
    }

    /// A mutable handle to the active run. Only valid while a user
    /// context is launched (between `begin` and `take`).
    pub fn current() -> &'static mut UserRun {
        // SAFETY: single CPU; called only from the syscall/exception
        // dispatch paths, which run strictly inside a launched run.
        // SAFETY: single CPU; USER_RUN is written only by begin/take
        // around a launched run (no concurrent access exists).
        unsafe { (*core::ptr::addr_of_mut!(USER_RUN)).as_mut() }
            .unwrap_or_else(|| panic!("user run state missing"))
    }

    /// Is a user run launched right now? (Exception path: a CPL3 fault
    /// with no active run would be a kernel bug, reported loudly.)
    pub fn active() -> bool {
        // SAFETY: single CPU; a plain read of the Option's discriminant.
        unsafe { (*core::ptr::addr_of!(USER_RUN)).is_some() }
    }

    /// Record a ring-3 fault as the run's exit reason (exception path).
    /// N2: install the live kernel pointer (kmain, once, before the
    /// first ring-3 launch).
    pub fn set_kernel(k: *mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>) {
        // SAFETY: single CPU, bring-up phase, before any ring-3 launch.
        unsafe {
            KERNEL = Some(k);
        }
    }

    /// ADR-0024 D1: kmain's frame pool, installed once beside the
    /// kernel — the mmap/munmap syscall paths need it at dispatch
    /// time, where no kmain frame is on the stack. The buddy arena
    /// rides inside the Kernel (`k.frames`) and needs no slot.
    static mut POOL: Option<*mut crate::frames::FramePool<{ crate::frames::KERNEL_POOL_FRAMES }>> =
        None;

    /// Install the pool pointer (kmain, once, right after creation).
    pub fn set_pool(p: *mut crate::frames::FramePool<{ crate::frames::KERNEL_POOL_FRAMES }>) {
        // SAFETY: single CPU, bring-up phase, before any ring-3 launch.
        unsafe {
            POOL = Some(p);
        }
    }

    /// The live pool, when installed (host tests never install one).
    pub fn pool_mut(
    ) -> Option<&'static mut crate::frames::FramePool<{ crate::frames::KERNEL_POOL_FRAMES }>> {
        // SAFETY: the pointer was set once from a live `&mut FramePool`
        // that outlives every ring-3 run (kmain owns it for the whole
        // boot); single CPU, no concurrent access.
        unsafe { POOL.map(|p| &mut *p) }
    }

    /// ADR-0024 D2: the frame-share table — kernel-global (single
    /// CPU, one pool), born empty, never reset. Holds a refcount per
    /// frame mapped by more than one address space; private frames
    /// never enter it.
    static mut SHARES: aegis_os::frame_share::FrameShares =
        aegis_os::frame_share::FrameShares::new();

    /// The live share table (fork, munmap, teardown, the CoW fault).
    pub fn shares_mut() -> &'static mut aegis_os::frame_share::FrameShares {
        // SAFETY: single CPU; every caller runs at IF=0 on the one
        // kernel stack (syscall/fault paths) or from kmain between
        // runs — no concurrent access exists to exclude.
        unsafe { &mut *core::ptr::addr_of_mut!(SHARES) }
    }

    /// N2: the live kernel, when installed (host tests never install
    /// one — callers fall back to the snapshot).
    pub fn kernel_mut(
    ) -> Option<&'static mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>> {
        // SAFETY: the pointer was set once from a live `&mut Kernel`
        // that outlives every ring-3 run (kmain owns it for the whole
        // boot); single CPU, no nesting (see the static's comment).
        unsafe { KERNEL.map(|p| &mut *p) }
    }

    /// N2: the active run's domain id (for the fault-path live feeds).
    pub fn active_domain() -> Option<u32> {
        // addr_of on a static mut is safe (no reference is formed).
        let run = core::ptr::addr_of!(USER_RUN);
        // SAFETY: single CPU; a read-only peek at the installed run —
        // the raw pointer was just taken, no aliasing reference exists.
        unsafe { (*run).as_ref().map(|r| r.domain) }
    }

    /// N2 (ADR-0007 §2): feed a user-context fault to the LIVE domain
    /// (organic fault signal) and drive the monitor clock. Called from
    /// the exception dispatch's user-death branch, after the run's
    /// exit was recorded.
    #[cfg(not(test))]
    pub fn note_live_fault() {
        let Some(id) = active_domain() else { return };
        if let Some(k) = kernel_mut() {
            let _ = k.report_fault(id);
            k.tick(crate::hw::read_tsc());
        }
    }

    #[cfg(test)]
    pub fn note_live_fault() {}

    // ── parked runs (M2-W2 / ADR-0012) ────────────────────────────────
    // Every runnable ring-3 run that is NOT the one on the CPU: parked
    // by the timer tick (preempted mid-execution) or stashed by kmain
    // (spawned, not yet entered). Single CPU, one active run: the table
    // is touched only from the tick path (interrupts masked) or kmain
    // between runs — never concurrently, never nested.

    /// How many ring-3 runs may be parked at once. Small, fixed, and
    /// fail-loud: a full table is a bookkeeping bug, never something to
    /// paper over (the F14 discipline).
    /// ADR-0023 D6: the parked table grows with the process table —
    /// MAX_DOMAINS runs may be parked-runnable at once (the run queue's
    /// storage; every runnable-but-not-running domain has exactly one
    /// entry, the running one is USER_RUN).
    pub const MAX_PARKED_RUNS: usize = aegis_os::MAX_DOMAINS;

    static mut PARKED: [Option<(UserRun, ParkedContext)>; MAX_PARKED_RUNS] =
        [const { None }; MAX_PARKED_RUNS];

    /// Store a run + its register image. Panics on a full table.
    pub fn stash_parked(run: UserRun, ctx: ParkedContext) {
        // SAFETY: single CPU; touched only from the tick path (IF=0)
        // or kmain between runs — see the table's doc.
        let table = core::ptr::addr_of_mut!(PARKED);
        unsafe {
            for slot in (*table).iter_mut() {
                if slot.is_none() {
                    *slot = Some((run, ctx));
                    return;
                }
            }
        }
        panic!("stash_parked: the parked-run table is full (bookkeeping bug)");
    }

    /// Withdraw the parked run of `domain`, if it is parked.
    pub fn take_parked(domain: u32) -> Option<(UserRun, ParkedContext)> {
        // SAFETY: as stash_parked.
        let table = core::ptr::addr_of_mut!(PARKED);
        unsafe {
            for slot in (*table).iter_mut() {
                if matches!(&*slot, Some((r, _)) if r.domain == domain) {
                    return (*slot).take();
                }
            }
        }
        None
    }

    /// Is `domain` parked right now? (kmain's starvation-freedom
    /// assertion reads this: the writer finishing while the spinner is
    /// still parked IS the proof.)
    pub fn is_parked(domain: u32) -> bool {
        // SAFETY: a read-only peek under the same single-CPU contract.
        let table = core::ptr::addr_of!(PARKED);
        unsafe { (*table).iter().flatten().any(|(r, _)| r.domain == domain) }
    }

    /// How many runs are parked (diagnostics).
    pub fn parked_count() -> usize {
        // SAFETY: as is_parked.
        let table = core::ptr::addr_of!(PARKED);
        unsafe { (*table).iter().flatten().count() }
    }

    /// Park the CURRENT run: withdraw USER_RUN and capture the
    /// interrupted register image from the timer's interrupt frame —
    /// the 15 frame GPRs, the iret words, and the CPL3 tail (user
    /// rsp/ss) the CPU pushed above rflags. Called from the tick path,
    /// which has verified a run is active and the frame is CPL3.
    pub fn park_from_frame(frame: &mut ExceptionFrame) -> (UserRun, ParkedContext) {
        // Withdraw the active run FIRST (single CPU; take() panics if
        // missing — the tick checked active() before calling).
        let run = take();
        let mut ctx = ParkedContext {
            gprs: [0; 15],
            rip: frame.rip,
            cs: frame.cs,
            rflags: frame.rflags,
            rsp: 0,
            ss: 0,
        };
        for (i, gpr) in ctx.gprs.iter_mut().enumerate() {
            *gpr = super::gpr_at(frame, i);
        }
        // SAFETY: the frame is CPL3 (the tick asserted it before
        // calling): the CPU physically pushed the user rsp/ss two and
        // three words above rflags — in-bounds reads of the frame tail.
        unsafe {
            let tail = core::ptr::addr_of!(frame.rflags);
            ctx.rsp = tail.add(1).read();
            ctx.ss = tail.add(2).read();
        }
        (run, ctx)
    }

    /// Install a parked image into the interrupt frame: the unwind's
    /// pop-registers + iretq will enter THAT domain instead of
    /// returning to the interrupted one. The frame rewrite IS the
    /// context switch; CR3 and USER_RUN are the caller's half.
    pub fn unpark_into_frame(frame: &mut ExceptionFrame, ctx: &ParkedContext) {
        for (i, gpr) in ctx.gprs.iter().enumerate() {
            super::set_gpr_at(frame, i, *gpr);
        }
        frame.rip = ctx.rip;
        frame.cs = ctx.cs;
        frame.rflags = ctx.rflags;
        // SAFETY: the frame carries the CPL3 tail (it arrived from
        // CPL3); the writes land exactly on those two words.
        unsafe {
            let tail = core::ptr::addr_of_mut!(frame.rflags);
            tail.add(1).write(ctx.rsp);
            tail.add(2).write(ctx.ss);
        }
    }

    pub fn record_fault(vector: u8, cr2: u64, error_code: u64, rip: u64, user_rsp: u64) {
        // SAFETY: single CPU; called only from the exception dispatch,
        // which runs strictly inside a launched run (checked by the
        // caller via `active()`).
        let run = core::ptr::addr_of_mut!(USER_RUN);
        // SAFETY: single CPU; the raw pointer was just taken.
        unsafe {
            if let Some(r) = (*run).as_mut() {
                r.exit = ExitKind::Fault {
                    vector,
                    cr2,
                    error_code,
                    rip,
                    user_rsp,
                };
            }
        }
    }

    /// The parked kernel resume RIP (diagnostics).
    pub fn saved_rip() -> u64 {
        // SAFETY: single CPU; plain read of what set_resume_point wrote.
        unsafe { RESUME_RIP }
    }

    /// The parked kernel resume point (diagnostics).
    pub fn saved_rsp() -> u64 {
        // SAFETY: single CPU; plain read of the value `enter_ring3` wrote.
        unsafe { RESUME_RSP }
    }

    /// Withdraw the run state (kmain, after `resume_kernel`).
    pub fn take() -> UserRun {
        // SAFETY: single CPU; called exactly once after the resume,
        // before the next `begin`.
        match unsafe { (*core::ptr::addr_of_mut!(USER_RUN)).take() } {
            Some(r) => r,
            None => panic!("user run state missing on take"),
        }
    }

    /// Record the resume point (RSP + the label below, inside this very
    /// function) and tail-jump into `enter_ring3`. The launch itself
    /// never returns; when the user run ends (SYS_EXIT or a fault), the
    /// dispatch calls `resume_kernel`, which restores the saved RSP and
    /// jumps to the label — and this function then returns to kmain
    /// normally, exactly once per run. Being a plain `()` function (not
    /// `-> !`), nothing after the call site is unreachable and the
    /// optimizer cannot delete the post-run code.
    pub fn launch(ctx: &UserContext) {
        // SAFETY: writes the two statics once per run (single CPU); the
        // asm stores addresses and tail-jumps to the naked entry. The
        // label is reached only via resume_kernel's jump, on the saved
        // stack — the ordinary epilogue then returns to the caller.
        unsafe {
            core::arch::asm!(
                "lea 9f(%rip), %rax",
                "movq %rax, {rip_slot}(%rip)",
                "movq %rsp, {rsp_slot}(%rip)",
                // Park the caller's callee-saved registers (see the
                // PARK_* doc): the only registers the kernel caller has
                // a right to find intact after this call returns.
                "movq %rbx, {rbx_slot}(%rip)",
                "movq %rbp, {rbp_slot}(%rip)",
                "movq %r12, {r12_slot}(%rip)",
                "movq %r13, {r13_slot}(%rip)",
                "movq %r14, {r14_slot}(%rip)",
                "movq %r15, {r15_slot}(%rip)",
                "jmp {enter}",
                // resume_kernel lands here (RSP restored to the value
                // recorded above); restore the parked registers, then
                // fall into launch's ordinary epilogue: the caller sees
                // a plain function call that just... returned.
                "9:",
                "movq {rbx_slot}(%rip), %rbx",
                "movq {rbp_slot}(%rip), %rbp",
                "movq {r12_slot}(%rip), %r12",
                "movq {r13_slot}(%rip), %r13",
                "movq {r14_slot}(%rip), %r14",
                "movq {r15_slot}(%rip), %r15",
                enter = sym enter_ring3,
                rip_slot = sym RESUME_RIP,
                rsp_slot = sym RESUME_RSP,
                rbx_slot = sym PARK_RBX,
                rbp_slot = sym PARK_RBP,
                r12_slot = sym PARK_R12,
                r13_slot = sym PARK_R13,
                r14_slot = sym PARK_R14,
                r15_slot = sym PARK_R15,
                options(att_syntax),
                in("rdi") ctx,
            );
        }
    }

    /// Enter ring-3 via `sysretq`. Naked; the kernel resume point is
    /// the (RSP, RIP) pair `launch` recorded just before the tail jump.
    ///
    /// Why SYSRET and not IRETQ for the initial entry: SYSRET loads
    /// CS/SS from the STAR slot arithmetic (no descriptor-validation
    /// stack-switch cycle — the exact cycle IRETQ performs on a
    /// privilege change), so the entry cannot fault mid-switch. The
    /// context's `cs`/`ss` fields stay documentation: what runs is the
    /// STAR contract (same selectors — pinned by gdt's host test).
    ///
    /// PR-1.4 reopen (M2-W2): the code had regressed to `iretq`, whose
    /// privilege-switch cycle is exactly where the launch died in this
    /// environment — the #DF frame carried the *pristine launch
    /// context* (rip=CODE_BASE, rsp=STACK_TOP, rflags=0x202, cs=0x2b,
    /// ss=0x23, CR2 stale from an earlier selftest), i.e. the user
    /// context never started. SYSRET, as the design above specifies,
    /// performs no such validation cycle.
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    /// NOTE: declared as returning `()` on purpose — it never returns
    /// (the `iretq` leaves for ring-3 and the kernel resumes through
    /// `resume_kernel`'s jump), but a `-> !` signature lets the
    /// optimizer tail-jump the call site *and delete everything after
    /// it as unreachable*, which would erase the post-resume code.
    pub extern "C" fn enter_ring3(ctx: &UserContext) {
        naked_asm!(
            // rdi = ctx (SysV first arg). SYSRET's contract: RIP comes
            // from RCX, RFLAGS from R11, RSP from RSP; CS/SS come from
            // the STAR user arithmetic (0x2b / 0x23 — the exact
            // selectors UserContext carries, pinned by gdt's host test).
            "movq 0x00(%rdi), %rcx", // rip → RCX
            "movq 0x10(%rdi), %r11", // rflags → R11
            "movq 0x18(%rdi), %rsp", // user rsp
            "swapgs",                // GS: user / KERNEL_GS_BASE: percpu
            "sysretq",               // CPL=3, IF from R11 — no mid-switch
            // descriptor-validation cycle
            options(att_syntax),
        );
    }

    /// Jump back to the kernel point `set_resume_point` recorded:
    /// restore RSP, jump to the label. Never returns (the label is the
    /// resume point; execution continues from there normally).
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub extern "C" fn resume_kernel() -> ! {
        naked_asm!(
            "movq {rsp_slot}(%rip), %rsp",
            "jmpq *{rip_slot}(%rip)",
            rsp_slot = sym RESUME_RSP,
            rip_slot = sym RESUME_RIP,
            options(att_syntax),
        );
    }

    /// Resume a PARKED run from kmain (the handover path: another domain
    /// exited, the preemptor named the next one). Same discipline as
    /// `launch`: park the kernel caller's resume point + callee-saved
    /// registers into the shared slots (only one excursion is ever
    /// active), then tail-jump into the parked entry. When the resumed
    /// domain later exits (SYS_EXIT or a fault), `resume_kernel` lands
    /// on the label below and this call returns to kmain exactly once.
    ///
    /// ABI note (ADR-0012): the SYSRET-based entry cannot restore the
    /// target's RCX/R11 — the instruction loads them with RIP/RFLAGS.
    /// The interrupt-frame switch (the tick path) preserves every
    /// register; only this handover path costs the SYSCALL-ABI pair,
    /// the same two registers every syscall already clobbers.
    pub fn resume_parked(ctx: &ParkedContext) {
        // SAFETY: writes the shared park slots once per excursion
        // (single CPU, single excursion — see PARK_*'s doc), then
        // tail-jumps to the naked parked entry. The label is reached
        // only via resume_kernel's jump, on the saved stack.
        unsafe {
            core::arch::asm!(
                "lea 9f(%rip), %rax",
                "movq %rax, {rip_slot}(%rip)",
                "movq %rsp, {rsp_slot}(%rip)",
                "movq %rbx, {rbx_slot}(%rip)",
                "movq %rbp, {rbp_slot}(%rip)",
                "movq %r12, {r12_slot}(%rip)",
                "movq %r13, {r13_slot}(%rip)",
                "movq %r14, {r14_slot}(%rip)",
                "movq %r15, {r15_slot}(%rip)",
                "jmp {enter}",
                "9:",
                "movq {rbx_slot}(%rip), %rbx",
                "movq {rbp_slot}(%rip), %rbp",
                "movq {r12_slot}(%rip), %r12",
                "movq {r13_slot}(%rip), %r13",
                "movq {r14_slot}(%rip), %r14",
                "movq {r15_slot}(%rip), %r15",
                enter = sym enter_ring3_parked,
                rip_slot = sym RESUME_RIP,
                rsp_slot = sym RESUME_RSP,
                rbx_slot = sym PARK_RBX,
                rbp_slot = sym PARK_RBP,
                r12_slot = sym PARK_R12,
                r13_slot = sym PARK_R13,
                r14_slot = sym PARK_R14,
                r15_slot = sym PARK_R15,
                options(att_syntax),
                in("rdi") ctx,
            );
        }
    }

    /// Enter a parked ring-3 context via `sysretq`, restoring every GPR
    /// the frame carries. Naked; offsets are the ParkedContext struct's,
    /// pinned by the host test (`parked_context_offsets_match_the_asm_table`).
    ///
    /// Why SYSRET (like `enter_ring3`, unlike the tick path's iretq):
    /// SYSRET performs no descriptor-validation stack-switch cycle, so
    /// the entry cannot fault mid-switch (ADR-0010 root cause 4). The
    /// price: RCX/R11 carry RIP/RFLAGS, not the parked values.
    #[unsafe(no_mangle)]
    #[unsafe(naked)]
    pub extern "C" fn enter_ring3_parked(ctx: &ParkedContext) {
        naked_asm!(
            // rdi = ctx. Load the SYSRET carriers and the user stack
            // first (they live outside the gprs array), then every GPR;
            // rdi itself last. gprs: r15(0) r14(8) r13(16) r12(24)
            // r11(32) r10(40) r9(48) r8(56) rbp(64) rdi(72) rsi(80)
            // rdx(88) rcx(96) rbx(104) rax(112); rip(120) rflags(136)
            // rsp(144).
            "movq 120(%rdi), %rcx", // rip → RCX (SYSRET target)
            "movq 136(%rdi), %r11", // rflags → R11 (SYSRET restores)
            "movq 144(%rdi), %rsp", // user rsp
            "movq 0(%rdi), %r15",
            "movq 8(%rdi), %r14",
            "movq 16(%rdi), %r13",
            "movq 24(%rdi), %r12",
            "movq 40(%rdi), %r10",
            "movq 48(%rdi), %r9",
            "movq 56(%rdi), %r8",
            "movq 64(%rdi), %rbp",
            "movq 80(%rdi), %rsi",
            "movq 88(%rdi), %rdx",
            "movq 104(%rdi), %rbx",
            "movq 112(%rdi), %rax",
            "movq 72(%rdi), %rdi", // user rdi — the pointer's last use
            "swapgs",              // GS ← user / KERNEL_GS_BASE ← percpu
            "sysretq",             // CPL=3, IF from R11
            options(att_syntax),
        );
    }
}

/// ADR-0023: re-export of the entry-mod resume-chain API (the
/// nested dispatcher in sched/park.rs saves/restores the launch
/// point around its resume_parked calls). Boot-only like the module
/// it re-exports.
#[cfg(not(test))]
pub use entry::{
    park_chain_save, park_chain_take, pool_mut, restore_resume_chain, save_resume_chain, set_pool,
    shares_mut, ResumeChain,
};

#[cfg(not(test))]
pub use entry::{
    active, active_domain, begin, current, enter_ring3, enter_ring3_parked, is_parked, kernel_mut,
    launch, note_live_fault, park_from_frame, parked_count, record_fault, resume_kernel,
    resume_parked, saved_rip, saved_rsp, set_kernel, stash_parked, take, take_parked,
    unpark_into_frame,
};
