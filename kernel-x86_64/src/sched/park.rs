//! ADR-0023: parking from INSIDE a syscall — the `sched_yield` and
//! `nanosleep` paths.
//!
//! The SYSCALL entry parks the user's image in a `SyscallFrame` on
//! the kernel stack and publishes its address; this module rebuilds a
//! `ParkedContext` from it (plus the user RSP the entry carried and
//! the LIVE callee-saved registers — the SysV ABI preserved their
//! user values across the dispatch call), stashes the run, and hands
//! the CPU to the next runnable domain — or idles (sti+hlt under the
//! tick's IDLE carve-out) until a sleeper's deadline wakes one. Like
//! SYS_EXIT's `resume_kernel`, none of these paths return: the parked
//! copy resumes later through the parked handover, with the syscall's
//! result already in its RAX slot.
//!
//! SAFETY POLICY: part of the `sched/` allowlist. The two unsafe acts
//! are (1) reading the entry-published frame pointer — valid for the
//! whole dispatch call by the same single-CPU, IF=0, one-excursion
//! discipline as `USER_RSP_SAVE` — and (2) five pure register reads.
//! The PURE half (the image builder) is host-tested; the never-return
//! machinery is boot-only.

#![allow(unsafe_code)]

use crate::sched::context::ParkedContext;

/// The live callee-saved registers `[rbp, r12, r13, r14, r15]` —
/// their USER values, preserved through the dispatch call by the SysV
/// ABI (the stub's frame does not carry them; nothing else can).
///
/// SAFETY: pure register reads; no memory access, no side effects.
unsafe fn live_callee_saved() -> [u64; 5] {
    let (rbp, r12, r13, r14, r15);
    unsafe {
        core::arch::asm!(
            "movq %rbp, {rbp}",
            "movq %r12, {r12}",
            "movq %r13, {r13}",
            "movq %r14, {r14}",
            "movq %r15, {r15}",
            rbp = out(reg) rbp,
            r12 = out(reg) r12,
            r13 = out(reg) r13,
            r14 = out(reg) r14,
            r15 = out(reg) r15,
            options(att_syntax, nostack, preserves_flags)
        );
    }
    [rbp, r12, r13, r14, r15]
}

/// Build the parked image of an in-flight syscall: every user GPR
/// from the entry's frame (RAX replaced by `result`), the user
/// rip/rflags from the frame's RCX/R11 slots (the SYSCALL convention),
/// the user RSP as the entry carried it across, and the callee-saved
/// user values (`live = [rbp, r12, r13, r14, r15]`). PURE — the boot
/// caller feeds the live register reads, the host test a fixed array.
/// The syscall-frame half of a parked image: the values the entry
/// parks on the kernel stack, in the shape the builder wants them.
#[derive(Clone, Copy)]
pub(crate) struct SyscallImage {
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    /// The user rip (the frame's RCX slot — SYSRET's carrier).
    pub user_rip: u64,
    /// The user rflags (the frame's R11 slot — SYSRET's carrier).
    pub user_rflags: u64,
    pub rbx: u64,
    /// The user RSP the entry carried across (USER_RSP_SAVE).
    pub user_rsp: u64,
    /// The syscall's result — it lands in the parked RAX slot.
    pub result: u64,
    /// The live callee-saved registers `[rbp, r12, r13, r14, r15]`.
    pub live: [u64; 5],
}

fn parked_from_syscall(img: SyscallImage) -> ParkedContext {
    let SyscallImage {
        rdi,
        rsi,
        rdx,
        r10,
        r8,
        r9,
        user_rip,
        user_rflags,
        rbx,
        user_rsp,
        result,
        live,
    } = img;
    let [rbp, r12, r13, r14, r15] = live;
    ParkedContext {
        // The ExceptionFrame order: r15,r14,r13,r12,r11,r10,r9,r8,
        // rbp,rdi,rsi,rdx,rcx,rbx,rax.
        gprs: [
            r15,
            r14,
            r13,
            r12,
            user_rflags, // r11 held the user rflags
            r10,
            r9,
            r8,
            rbp,
            rdi,
            rsi,
            rdx,
            user_rip, // rcx held the user rip
            rbx,
            result,
        ],
        rip: user_rip,
        cs: (crate::arch::gdt::USER_CODE | 3) as u64,
        rflags: user_rflags,
        rsp: user_rsp,
        ss: (crate::arch::gdt::USER_DATA | 3) as u64,
    }
}

/// ADR-0023: the completed-run mailbox — the nested dispatcher parks
/// exited runs here (domain + exit kind; the RUN's resource teardown
/// stays the SPAWNER's contract, so kmain drains this on regaining
/// control). Bounded; overflow refuses loudly (a boot that parks more
/// than MAX_COMPLETED exits without draining is a boot bug, not a
/// leak to hide).
#[cfg(not(test))]
const MAX_COMPLETED: usize = 16;

#[cfg(not(test))]
static mut COMPLETED: [Option<(u32, crate::sched::context::ExitKind)>; MAX_COMPLETED] =
    [const { None }; MAX_COMPLETED];

/// Record a completed run (the nested dispatcher, on resume return).
#[cfg(not(test))]
fn record_completed(domain: u32, exit: crate::sched::context::ExitKind) -> bool {
    // SAFETY: single CPU, IF=0 through the dispatcher; the only writers
    // are the nested dispatcher and kmain's drain, never concurrent.
    let completed = unsafe { &mut *core::ptr::addr_of_mut!(COMPLETED) };
    for slot in completed.iter_mut() {
        if slot.is_none() {
            *slot = Some((domain, exit));
            return true;
        }
    }
    false
}

/// Drain one completed run (kmain, after the nested dispatcher
/// returned control): (domain, exit kind). None when empty.
#[cfg(not(test))]
pub fn completed_drain() -> Option<(u32, crate::sched::context::ExitKind)> {
    // SAFETY: see record_completed.
    let completed = unsafe { &mut *core::ptr::addr_of_mut!(COMPLETED) };
    for slot in completed.iter_mut() {
        if let Some(x) = slot.take() {
            return Some(x);
        }
    }
    None
}

#[cfg(not(test))]
mod boot {
    use super::{live_callee_saved, parked_from_syscall, record_completed, SyscallImage};
    use crate::arch::syscall_entry;
    use crate::arch::syscall_frame::{
        OFF_R10, OFF_R11, OFF_R8, OFF_R9, OFF_RBX, OFF_RCX, OFF_RDI, OFF_RDX, OFF_RSI,
    };
    use crate::hw;
    use crate::sched::context::{self};
    use crate::sched::preempt;
    use crate::serial;
    use crate::strutil;

    /// Park the in-flight syscall's run (its result already baked into
    /// the parked image) and hand the CPU onward: the fair pick if one
    /// is runnable, the idle state otherwise. Never returns — the
    /// parked copy resumes later through the parked handover.
    pub fn park_current_from_syscall(result: u64) -> ! {
        // The frame is read through the OFF_* RSP-relative offsets —
        // the SAME table the stub's argument loads use, pinned by the
        // host test. The `SyscallFrame` STRUCT is the mirror image of
        // the push order (field i sits at 88-8*i from the post-push
        // RSP), so casting the base pointer to `&SyscallFrame` reads
        // every field from the WRONG slot — the exact bug the first
        // boot of this path shipped (rip read from the RSI slot: the
        // parked run resumed at the nanosleep `rem` pointer, an NX
        // data address).
        let base = syscall_entry::syscall_frame_addr();
        let read = |off: u64| {
            // SAFETY: the entry published this address right before
            // `call dispatch`; the frame lives at the top of the
            // kernel stack for the whole dispatch (single CPU, IF=0,
            // one excursion — the USER_RSP_SAVE discipline). Every
            // read is 8-byte aligned inside it.
            unsafe { *((base + off) as *const u64) }
        };
        // SAFETY: pure register reads of this context's callee-saved
        // values — their user values, preserved across dispatch by the
        // SysV ABI.
        let live = unsafe { live_callee_saved() };
        let ctx = parked_from_syscall(SyscallImage {
            rdi: read(OFF_RDI),
            rsi: read(OFF_RSI),
            rdx: read(OFF_RDX),
            r10: read(OFF_R10),
            r8: read(OFF_R8),
            r9: read(OFF_R9),
            user_rip: read(OFF_RCX),    // SYSRET's RCX carrier
            user_rflags: read(OFF_R11), // SYSRET's R11 carrier
            rbx: read(OFF_RBX),
            user_rsp: syscall_entry::user_rsp_save(),
            result,
            live,
        });
        let run = context::take();
        context::stash_parked(run, ctx);
        dispatch_next()
    }

    /// Hand the CPU to the next runnable domain — or idle until one
    /// is — until the run set empties, then UNWIND to the outer
    /// launch point (kmain). The shape mirrors kmain's own handover
    /// loop exactly: `resume_parked` RETURNS when the resumed run
    /// exits (the exit path jumps to the resume point with the exited
    /// run still in USER_RUN); the exit is recorded in the completed
    /// mailbox (teardown stays the spawner's contract) and the loop
    /// re-picks. When nothing is runnable AND nothing sleeps, the
    /// saved resume chain (kmain's launch point) is restored and
    /// `resume_kernel` lands in kmain — the same control flow a flat
    /// kmain-only boot has, one nesting level deeper.
    fn dispatch_next() -> ! {
        // kmain's launch point, before any resume_parked of ours
        // overwrites the eight slots.
        let chain = context::save_resume_chain();
        loop {
            let now = hw::read_tsc();
            if let Some(k) = context::kernel_mut() {
                k.tick(now);
                if let Some(next) = k.sched.pick_next() {
                    match context::take_parked(next) {
                        Some((run, ctx)) => {
                            run.tables.activate();
                            context::begin(run);
                            context::resume_parked(&ctx);
                            // Returned: the resumed run EXITED; USER_RUN
                            // holds it (both exit paths leave it there).
                            let exited = context::take();
                            if !record_completed(exited.domain, exited.exit) {
                                serial::write_str(
                                    "[SCHD] KERNEL BUG: completed mailbox overflow\n",
                                );
                                hw::halt_forever();
                            }
                            // The SCHEDULER question settles NOW (the
                            // exited entity must never be picked
                            // again); the RESOURCE teardown stays the
                            // spawner's drain (kmain).
                            if let Some(k) = context::kernel_mut() {
                                let _ = preempt::on_exit(&mut k.sched, exited.domain);
                            }
                            continue;
                        }
                        None => {
                            // Registered-but-not-parked: the ADR-0012
                            // bookkeeping invariant, held to here too.
                            let mut b = [0u8; 20];
                            serial::write_str(
                                "[SCHD] KERNEL BUG: yield/sleep picked unparked domain ",
                            );
                            serial::write_str(strutil::dec(next as u64, &mut b));
                            serial::write_str(" — halting\n");
                            hw::halt_forever();
                        }
                    }
                }
                // Nothing runnable. A sleeper still parked in the core
                // means a future wake: the guarded idle state.
                if k.sleepers_due(now).is_some() {
                    preempt::idle_hlt();
                    continue;
                }
            }
            // Nothing runnable, nothing sleeping: the run set is empty
            // — unwind to the outer launch point.
            context::restore_resume_chain(&chain);
            context::resume_kernel();
        }
    }
}

#[cfg(not(test))]
pub use boot::park_current_from_syscall;

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping is pure given a frame's values and the live
    /// registers — the test pins the slot-to-slot correspondence (the
    /// M2-W2 mirror-inversion lesson applied to the syscall path).
    #[test]
    fn syscall_frame_values_map_into_the_parked_order() {
        // A FIXED live array: the mapping is pure, so the test pins
        // positions against known values (re-reading the registers
        // here would race the test's own code using them).
        let ctx = parked_from_syscall(SyscallImage {
            rdi: 501,
            rsi: 502,
            rdx: 503,
            r10: 504,
            r8: 505,
            r9: 506,
            user_rip: 0x1111_2222, // the frame's RCX slot
            user_rflags: 0x0202,   // the frame's R11 slot
            rbx: 507,
            user_rsp: 0x7000,                // USER_RSP_SAVE
            result: 42,                      // the syscall result -> RAX
            live: [601, 602, 603, 604, 605], // rbp, r12, r13, r14, r15
        });
        // The result replaces the syscall number in RAX; the user
        // rip/rflags ride the RCX/R11 slots into their iret places.
        assert_eq!(ctx.gprs[14], 42);
        assert_eq!(ctx.rip, 0x1111_2222);
        assert_eq!(ctx.rflags, 0x0202);
        assert_eq!(ctx.gprs[12], 0x1111_2222);
        assert_eq!(ctx.gprs[4], 0x0202);
        assert_eq!(ctx.gprs[9], 501);
        assert_eq!(ctx.gprs[10], 502);
        assert_eq!(ctx.gprs[11], 503);
        assert_eq!(ctx.gprs[5], 504);
        assert_eq!(ctx.gprs[7], 505);
        assert_eq!(ctx.gprs[6], 506);
        assert_eq!(ctx.gprs[13], 507);
        assert_eq!(ctx.rsp, 0x7000);
        assert_eq!(ctx.cs & 3, 3);
        assert_eq!(ctx.ss & 3, 3);
        // The callee-saved slots land at their pinned positions.
        assert_eq!(ctx.gprs[8], 601); // rbp
        assert_eq!(ctx.gprs[3], 602); // r12
        assert_eq!(ctx.gprs[2], 603); // r13
        assert_eq!(ctx.gprs[1], 604); // r14
        assert_eq!(ctx.gprs[0], 605); // r15
    }
}
