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

/// The current R12 (diagnostics/profiling; pure register read).
///
/// SAFETY: one register read, no memory access, no side effects.
pub fn current_r12() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("movq %r12, %rax", lateout("rax") v, options(att_syntax, nostack, preserves_flags));
    }
    v
}

/// The current RSP (diagnostics/profiling; pure register read).
///
/// SAFETY: one register read, no memory access, no side effects.
pub fn current_rsp() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("movq %rsp, {rsp}", rsp = out(reg) rsp, options(att_syntax, nostack, preserves_flags));
    }
    rsp
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

pub(crate) fn parked_from_syscall(img: SyscallImage) -> ParkedContext {
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
    use super::{parked_from_syscall, record_completed, SyscallImage};
    use crate::arch::syscall_entry;
    use crate::arch::syscall_frame::{
        OFF_R10, OFF_R11, OFF_R8, OFF_R9, OFF_RBX, OFF_RCX, OFF_RDI, OFF_RDX, OFF_RSI,
    };
    use crate::hw;
    use crate::sched::context::{self};
    use crate::sched::preempt;
    use crate::serial;
    use crate::strutil;

    /// ADR-0024 D2: build the parked image of the IN-FLIGHT syscall
    /// (the fork path's child image) — the frame reads, the live
    /// callee-saved reads, and the mapping, all owned here where the
    /// unsafe lives (syscall.rs is unsafe-free by policy).
    pub fn parked_from_current_syscall(result: u64) -> crate::sched::context::ParkedContext {
        use crate::arch::syscall_entry::{frame_word, user_rsp_save};
        use crate::arch::syscall_frame::{
            OFF_R10, OFF_R11, OFF_R8, OFF_R9, OFF_RBX, OFF_RCX, OFF_RDI, OFF_RDX, OFF_RSI,
        };
        // The user's callee-saved five, parked by the stub AT ENTRY
        // (reading them live here would read the compiler's scratch —
        // SysV preserves them in the CALLEES' frames, not in the
        // registers; see user_callee_saved's doc).
        let live = crate::arch::syscall_entry::user_callee_saved();
        parked_from_syscall(SyscallImage {
            rdi: frame_word(OFF_RDI),
            rsi: frame_word(OFF_RSI),
            rdx: frame_word(OFF_RDX),
            r10: frame_word(OFF_R10),
            r8: frame_word(OFF_R8),
            r9: frame_word(OFF_R9),
            user_rip: frame_word(OFF_RCX),
            user_rflags: frame_word(OFF_R11),
            rbx: frame_word(OFF_RBX),
            user_rsp: user_rsp_save(),
            result,
            live,
        })
    }

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
        // The user's callee-saved five from the STUB SLOTS — the
        // parked-from-current twin's fix applies here too: a live read
        // at this depth reads the compiler's scratch (SysV preserves
        // the user's values in the CALLEES' frames, not in the
        // registers; found live — the yield path's parked images
        // carried garbage r12 and the resumed parent wrote through 3).
        let live = crate::arch::syscall_entry::user_callee_saved();
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
        // ADR-0028's park-unwind rule: an INNER park (a run resumed by
        // a live dispatcher level) RETURNS to that level's loop — the
        // resume slot already holds its resume_parked label, and its
        // post-return try_take sees None ("the parked case just
        // loops"). Nesting a fresh dispatch_next per park used to
        // grow the chain stack (depth 8) and then the kernel stack —
        // a server parking once per request could not survive its own
        // load; the bench round's 32-call RTT found it live (the
        // corrupted resume slot stranded both runs). Only the
        // OUTERMOST park — a flat-launched run parking for the first
        // time, no level below — starts the dispatcher.
        if context::park_chain_depth() > 0 {
            context::resume_kernel();
        }
        dispatch_next()
    }

    /// ADR-0023 D8: deliver one pending caught signal to a run being
    /// resumed from parked — the twin of the syscall-path delivery in
    /// syscall.rs, rewriting the ParkedContext instead of the stub
    /// frame. The interrupted image comes from the parked context;
    /// the frame lands on ITS user stack (the caller activated the
    /// target's tables first — the byte writes need its CR3).
    fn deliver_to_parked(
        run: &mut crate::sched::context::UserRun,
        ctx: &mut crate::sched::context::ParkedContext,
    ) {
        use crate::mm::user_range::copy_out_bytes;
        use aegis_os::sigframe::{self, InterruptedImage};

        // ParkedContext gprs order: r15,r14,r13,r12,r11,r10,r9,r8,
        // rbp,rdi,rsi,rdx,rcx,rbx,rax — indices 9..11,5..7,13,14.
        let new_rsp = (ctx.rsp.saturating_sub(136)) & !0xF;
        // The stack span must be a present user page in THIS run's
        // tables (page-walk validation, CR3-independent).
        let stack_ok = {
            let page = new_rsp & !(crate::mm::pte::PAGE_SIZE_U64 - 1);
            let end_page = (new_rsp + sigframe::SIGFRAME_BYTES as u64 - 1)
                & !(crate::mm::pte::PAGE_SIZE_U64 - 1);
            let mut ok = true;
            let mut p = page;
            while p <= end_page {
                ok = ok
                    && matches!(run.tables.pte_of(p),
                        Some(e) if e & crate::mm::pte::PTE_U != 0 && e & crate::mm::pte::PTE_P != 0);
                p += crate::mm::pte::PAGE_SIZE_U64;
            }
            ok
        };
        if !stack_ok {
            return;
        }
        let Some(k) = context::kernel_mut() else {
            return;
        };
        let Some((sig, handler, restorer)) = k.pop_catchable_signal(run.domain) else {
            return;
        };
        let img = InterruptedImage {
            rip: ctx.rip,
            cs: ctx.cs,
            rflags: ctx.rflags,
            rsp: ctx.rsp,
            ss: ctx.ss,
            gprs: [
                ctx.gprs[14], // rax
                ctx.gprs[9],  // rdi
                ctx.gprs[10], // rsi
                ctx.gprs[11], // rdx
                ctx.gprs[5],  // r10
                ctx.gprs[7],  // r8
                ctx.gprs[6],  // r9
                ctx.gprs[13], // rbx
            ],
        };
        let t = hw::read_tsc();
        let cookie = t ^ (t.rotate_left(32)) ^ (u64::from(run.domain) << 48) ^ u64::from(sig);
        let mut frame = [0u8; sigframe::SIGFRAME_BYTES];
        sigframe::build(sig, cookie, restorer, &img, &mut frame);
        crate::syscall::IN_USER_COPY.store(true, core::sync::atomic::Ordering::SeqCst);
        if hw::smap_active() {
            hw::stac();
        }
        let _ = copy_out_bytes(new_rsp, &frame, &|va, b| crate::memops::write_u8_va(va, b));
        if hw::smap_active() {
            hw::clac();
        }
        crate::syscall::IN_USER_COPY.store(false, core::sync::atomic::Ordering::SeqCst);
        // Rewrite the parked image: the resume enters the handler with
        // RDI = signum; the interrupted image lives on in the frame.
        ctx.rip = handler;
        ctx.gprs[9] = u64::from(sig); // rdi
        ctx.gprs[14] = 0; // rax (undefined at entry)
        ctx.rsp = new_rsp;
        // The delivery record rides the run (sigreturn matches the
        // cookie and the exact frame address against it).
        run.delivered = Some(crate::sched::context::Delivered {
            sig,
            cookie,
            frame_rsp: new_rsp,
        });
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
        // overwrites the eight slots — in a .bss STATIC (see
        // The outer chain lives in the context entry slot (beside
        // RESUME_RIP/PARK_* — the proven storage; a module-local
        // static here came out of the linker EIGHT times over, one
        // copy per CGU, states diverging — see PARK_CHAIN's doc).
        context::park_chain_save(context::save_resume_chain());
        loop {
            let now = hw::read_tsc();
            if let Some(k) = context::kernel_mut() {
                k.tick(now);
                if let Some(next) = k.sched.pick_next() {
                    match context::take_parked(next) {
                        Some((mut run, mut ctx)) => {
                            run.tables.activate();
                            // ADR-0023 D8: a signal may have arrived
                            // while this run was parked — deliver it
                            // by rewriting the parked image (the
                            // target's CR3 is active, so the user-stack
                            // write lands in ITS tables).
                            deliver_to_parked(&mut run, &mut ctx);
                            context::begin(run);
                            context::resume_parked(&ctx);
                            // Returned: EITHER the resumed run EXITED
                            // (USER_RUN holds it — both exit paths
                            // leave it there) OR it PARKED — a yield
                            // from a dispatcher-resumed run nests a
                            // second dispatch_next whose unwind returns
                            // here with the slot EMPTY (the nested
                            // park_current took it; found live: the
                            // IPC receivers' poll loops tripped the
                            // strict take). The parked case just loops.
                            if let Some(exited) = context::try_take() {
                                if !record_completed(exited.domain, exited.exit) {
                                    serial::write_str(
                                        "[SCHD] KERNEL BUG: completed mailbox overflow\n",
                                    );
                                    hw::halt_forever();
                                }
                                // The SCHEDULER question settles NOW
                                // (the exited entity must never be
                                // picked again); the RESOURCE teardown
                                // stays the spawner's drain (kmain).
                                if let Some(k) = context::kernel_mut() {
                                    let _ = preempt::on_exit(&mut k.sched, exited.domain);
                                }
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
            if let Some(chain) = context::park_chain_take() {
                context::restore_resume_chain(&chain);
                context::resume_kernel();
            }
            // No chain saved (a bookkeeping bug): loud, never silent.
            serial::write_str("[SCHD] KERNEL BUG: unwind with no saved chain\n");
            hw::halt_forever();
        }
    }
}

#[cfg(not(test))]
pub use boot::{park_current_from_syscall, parked_from_current_syscall};

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
