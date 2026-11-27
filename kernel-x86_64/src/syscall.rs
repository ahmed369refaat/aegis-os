//! The ring-3 syscall layer (PR-1.4 + Round J): the real syscall
//! surface.
//!
//! Invariants:
//! - **The gate runs before anything else.** Every entry calls the
//!   lib's `aegis_os::syscall::gate` — the *same* decision code the
//!   kernel-resident path uses — before any argument is even looked at.
//! - **No nr truncation before the bounds check**: a caller passing
//!   nr=256 must get -ENOSYS, not "SYS_READ" (`256 as u8 == 0` would
//!   smuggle a masked syscall through the gate). Host-tested.
//! - **User pointers are never trusted**: every buffer (write in,
//!   read out, open's path) is validated page-by-page through the
//!   *domain's own* page tables (present + U bit + below the split)
//!   before a single byte moves, and the copies are byte-exact through
//!   `memops` reads/writes at the user VA under the single blessed
//!   SMAP window (N4, ADR-0008).
//! - **The executor is the LIVE lib kernel** (Round J): the file
//!   family — OPEN/READ/WRITE/CLOSE/PIPE/DUP — marshals into
//!   `SysRequest` values and runs `Kernel::execute` on the same state
//!   the monitor reads. The runtime gates first (`dispatch`, where the
//!   accounting lands exactly once) and only an Allowed reaches the
//!   executor — the split's contract is host-tested in the lib.
//! - **SYS_EXIT never returns to ring-3**: it records the exit, swaps
//!   GS back to the kernel view, and longjmps to the launch point.
//!
//! SAFETY POLICY: this module is unsafe-free; the raw entry lives in
//! `arch::syscall_entry` (allowlisted), the resume longjmp in
//! `sched::context` (allowlisted).

use aegis_os::domain::Decision;
use core::sync::atomic::AtomicBool;

/// N1 (ADR-0007 §1): armed around the user-copy routine. The copy is
/// provably fault-free (it touches exactly the validated bytes), so a
/// CPL0 fault while this is set can only mean the invariant broke —
/// the exception path reports it as loudly as possible.
pub static IN_USER_COPY: AtomicBool = AtomicBool::new(false);

/// N1 (ADR-0007 §1): set by the first successful dispatch for the
/// active run — a CPL0 fault *before* this is the documented
/// launch-relay limitation; after it, a CPL0 fault is a kernel bug.
pub static SYSCALLS_SERVED: AtomicBool = AtomicBool::new(false);
// The dispatch arms below are boot-only (cfg(not(test))); only the
// constants the host tests pin stay unconditionally imported.
#[cfg(not(test))]
use aegis_os::sys::{SysRequest, SysValue};
use aegis_os::syscall::gate;
#[cfg(not(test))]
use aegis_os::syscall::Abi;
#[cfg(not(test))]
use aegis_os::syscall::{
    SYSCALL_COUNT, SYS_CHROOT, SYS_CLOCK_GETTIME, SYS_DEVREG, SYS_EXEC, SYS_EXIT, SYS_FORK,
    SYS_IPC_CALL, SYS_IPC_GRANT, SYS_IPC_RECV, SYS_IPC_RECV_WAIT, SYS_IPC_REPLY, SYS_IPC_SEND,
    SYS_KILL, SYS_LISTDIR, SYS_MKDIR, SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP, SYS_NET_RECV,
    SYS_NET_SEND, SYS_PIPE_READ, SYS_PIPE_WRITE, SYS_RENAME, SYS_SCHED_YIELD, SYS_SIGACTION,
    SYS_SIGRETURN, SYS_STAT, SYS_UNLINK, SYS_WAIT, SYS_WRITE,
};
#[cfg(test)]
use aegis_os::syscall::{
    SYSCALL_COUNT, SYS_CLOCK_GETTIME, SYS_EXEC, SYS_EXIT, SYS_FORK, SYS_KILL, SYS_LISTDIR,
    SYS_NANOSLEEP, SYS_RENAME, SYS_SCHED_YIELD, SYS_SIGRETURN, SYS_STAT, SYS_WAIT, SYS_WRITE,
};

/// errno values this layer returns (negated, Linux-style, in RAX).
pub const EPERM: i64 = 1;
pub const E2BIG: i64 = 7;
pub const EBADF: i64 = 9;
pub const EFAULT: i64 = 14;
pub const ENOEXEC: i64 = 8;
pub const EINVAL: i64 = 22;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;
/// ADR-0024: the frame source or the address space refused — out of
/// memory (budget, pool, or window).
pub const ENOMEM: i64 = 12;
/// K20 (P0-2): the send is longer than `MAX_NET_FRAME_BYTES` — a
/// value error (Linux send(2)'s EMSGSIZE), never a throttle: it can
/// not fit any token window.
pub const EMSGSIZE: i64 = 90;
/// K20 (P0-2): no live NIC session behind the brokered socket (the
/// arms answer this honestly on machines/lane phases without one).
pub const ENODEV: i64 = 19;

/// Longest SYS_WRITE the kernel will service in one call (bounds the
/// copy loop; user code wanting more loops itself). K20 (P0-1):
/// 256 -> 4096, one page — the read-side mirror (sysabi::MAX_READ)
/// carries the full sizing note (the copy buffer rides the guarded
/// syscall stack).
pub const MAX_WRITE: usize = 4096;

/// ADR-0023: the Linux-ABI numbers of the time family map onto the
/// core's internal ids (the numbers below 64 that coincide with Linux
/// — read/write/open/close — pass through unchanged; the full
/// renumbering table is Phase 5's ABI-VERSION v0.4). Translation
/// BEFORE normalization: clock_gettime's 228 must not die in the
/// bounds check.
pub fn linux_to_core(nr: u64) -> u64 {
    match nr {
        24 => SYS_SCHED_YIELD as u64,    // sched_yield(2)
        35 => SYS_NANOSLEEP as u64,      // nanosleep(2)
        228 => SYS_CLOCK_GETTIME as u64, // clock_gettime(2)
        // (rt_sigaction's Linux nr 13 is NOT translated: it collides
        // with the internal SYS_DUP the round-J blobs already speak —
        // the victim blob calls the internal 25 directly; the full
        // Linux renumbering is Phase 5's ABI-VERSION v0.4 table.)
        15 => SYS_SIGRETURN as u64, // rt_sigreturn(2)
        62 => SYS_KILL as u64,      // kill(2)
        57 => SYS_FORK as u64,      // fork(2)
        n => n,
    }
}

/// ADR-0003 (v1): the per-ABI entry translation. Linux mode is the
/// WHITELIST — unmapped nrs answer `None` (including sub-64 nrs that
/// collide with internal ops: Linux 63 is uname, internal 63 is
/// EXIT); Internal mode keeps the v0.4 hybrid, where everything
/// maps (legacy translations + raw internal pass-through).
pub fn translate_nr(nr: u64, linux_abi: bool) -> Option<u64> {
    if linux_abi {
        aegis_os::syscall::linux_nr_to_core(nr)
    } else {
        Some(linux_to_core(nr))
    }
}

/// Normalize the raw RAX syscall number: `None` for anything outside
/// `0..SYSCALL_COUNT` — **checked on the full u64 before any cast**, so
/// nr=256 cannot truncate into SYS_READ.
pub fn normalize_nr(nr: u64) -> Option<u8> {
    if nr < SYSCALL_COUNT as u64 {
        Some(nr as u8)
    } else {
        None
    }
}

/// The pure routing table: gate decision → errno-or-zero (host-tested;
/// the target dispatch layer prints and accounts around exactly this).
pub fn errno_for(decision: &Decision) -> i64 {
    match decision {
        Decision::Allowed => 0,
        Decision::BadSyscall(_) => -ENOSYS,
        Decision::DeniedByMask(_) | Decision::DeniedQuarantined(_) => -EPERM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Round J: this import was missing all along — the module's outer
    // `#[cfg(not(test))]` (removed this round) meant these tests never
    // compiled, so the gap stayed invisible.
    use aegis_os::syscall::SyscallMask;

    fn mask() -> SyscallMask {
        SyscallMask::from_bits((1 << SYS_WRITE) | (1 << SYS_EXIT))
    }

    #[test]
    fn syscall_number_normalization_blocks_truncation_smuggling() {
        // nr=256 truncates to 0 (SYS_READ) if cast carelessly — the
        // exact attack the full-width check exists to stop.
        assert_eq!(normalize_nr(0), Some(0));
        assert_eq!(normalize_nr(SYS_WRITE as u64), Some(SYS_WRITE));
        assert_eq!(normalize_nr(63), Some(63));
        assert_eq!(normalize_nr(64), None);
        assert_eq!(normalize_nr(256), None, "must not become SYS_READ");
        assert_eq!(normalize_nr(u64::MAX), None);
    }

    #[test]
    fn v1_translation_is_a_whitelist_linux_mode() {
        // The mapped set (Linux nr -> internal op).
        assert_eq!(translate_nr(22, true), Some(12)); // pipe(2)
        assert_eq!(translate_nr(231, true), Some(63)); // exit_group -> EXIT
        assert_eq!(translate_nr(60, true), Some(63)); // exit -> EXIT
        assert_eq!(translate_nr(9, true), Some(4)); // mmap
        assert_eq!(translate_nr(13, true), Some(25)); // rt_sigaction
        assert_eq!(translate_nr(0, true), Some(0)); // read: identity
                                                    // Slice 2: open(2) joins the mapped set — its O_* word is
                                                    // translated at the SYS_OPEN arm (Linux's O_RDONLY is 0,
                                                    // the internal 0 is "no access": the encodings are NOT the
                                                    // same word-shape, so the arm translates instead of passing).
        assert_eq!(translate_nr(2, true), Some(2)); // open(2) -> SYS_OPEN
                                                    // The edge: sub-64 collisions must NOT pass (uname vs EXIT is
                                                    // the sharp one), nor unmapped Linux nrs.
                                                    // Slice 3: wait4(61) joins the mapped set — its arm parks
                                                    // with the re-execute image (rip-2) and reaps through the
                                                    // ADR-0022 D7 core.
        assert_eq!(translate_nr(61, true), Some(SYS_WAIT as u64)); // wait4 -> SYS_WAIT
                                                                   // Slice 4: execve(59) joined the mapped set with
                                                                   // the image-replacement arm — the stale "must be
                                                                   // None" entry below was the slice-4 miss.
        assert_eq!(translate_nr(59, true), Some(SYS_EXEC as u64)); // execve -> SYS_EXEC
                                                                   // Phase 7: getdents64(259) joins — the
                                                                   // shell's ls over the internal ListDir.
        assert_eq!(translate_nr(259, true), Some(SYS_LISTDIR as u64)); // getdents64 -> SYS_LISTDIR
                                                                       // K21: the package manager's arms join the whitelist —
                                                                       // newfstatat(262) -> STAT, rename(82)/renameat(264) ->
                                                                       // RENAME; old stat(4) and fstat(5) stay unmapped (the
                                                                       // subset speaks the modern arm only).
        assert_eq!(translate_nr(262, true), Some(SYS_STAT as u64));
        assert_eq!(translate_nr(82, true), Some(SYS_RENAME as u64));
        assert_eq!(translate_nr(264, true), Some(SYS_RENAME as u64));
        assert_eq!(translate_nr(4, true), None, "old stat stays unmapped");
        assert_eq!(translate_nr(5, true), None, "fstat stays unmapped");
        for nr in [4u64, 12, 32, 39, 63, 64, 293] {
            assert_eq!(translate_nr(nr, true), None, "nr {nr}");
        }
    }

    #[test]
    fn internal_mode_keeps_the_v04_hybrid() {
        assert_eq!(translate_nr(24, false), Some(SYS_SCHED_YIELD as u64));
        assert_eq!(translate_nr(35, false), Some(SYS_NANOSLEEP as u64));
        assert_eq!(translate_nr(228, false), Some(SYS_CLOCK_GETTIME as u64));
        // The pass-throughs the round-J blobs speak: raw internal nrs
        // (13 = DUP, 63 = EXIT) and the unnormalized large nr.
        assert_eq!(translate_nr(13, false), Some(13));
        assert_eq!(translate_nr(63, false), Some(63));
        assert_eq!(translate_nr(256, false), Some(256)); // dies in normalize, not here
    }

    #[test]
    fn gate_results_route_to_errnos() {
        let m = mask();
        assert_eq!(errno_for(&gate(&m, false, SYS_WRITE)), 0);
        assert_eq!(errno_for(&gate(&m, false, 200)), -ENOSYS);
        assert_eq!(errno_for(&gate(&m, false, 9)), -EPERM); // SYS_NET_SEND: not in mask
        assert_eq!(errno_for(&gate(&m, true, SYS_WRITE)), -EPERM); // quarantined
        assert_eq!(errno_for(&gate(&m, true, SYS_EXIT)), 0);
    }

    #[test]
    fn write_bounds_are_sane() {
        const { assert!(MAX_WRITE >= 64, "a hello fits comfortably") };
        assert!(MAX_WRITE.is_power_of_two() || MAX_WRITE.is_multiple_of(8));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only execution (console, user-run state, resume path).
// ─────────────────────────────────────────────────────────────────────────
#[cfg(not(test))]
mod exec {
    use super::*;
    use crate::sched::context::{self, ExitKind};
    use crate::{hw, memops, mm::pte, serial, strutil, sysabi};
    use core::sync::atomic::Ordering;

    /// The SYSCALL/SYSRET dispatch: called by the naked entry with the
    /// six-register ABI (nr in RAX, args in RDI, RSI, RDX, R10, R8, R9 —
    /// arg4 rides R10 per the syscall convention, not RCX). Returns the
    /// value RAX carries back to ring-3.
    pub fn syscall_dispatch(nr: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64) -> u64 {
        SYSCALLS_SERVED.store(true, Ordering::SeqCst);
        let run = context::current();
        // ADR-0003 (v1): the per-domain entry ABI picks the table —
        // Linux mode is the whitelist (None = -ENOSYS below), Internal
        // mode keeps the v0.4 hybrid. Either way the translation runs
        // BEFORE the bounds check (231 -> 63) and BEFORE the policy
        // gate (the gate sees internal ids, always).
        let linux_abi = context::kernel_mut()
            .map(|k| k.domain(run.domain).is_some_and(|d| d.abi == Abi::Linux))
            .unwrap_or(false);
        let Some(nr) = translate_nr(nr, linux_abi) else {
            // The ADR-0003 refuse: an unmapped Linux nr — audited on
            // the live domain exactly like an unnormalizable one.
            run.bad_syscalls = run.bad_syscalls.saturating_add(1);
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_unknown_syscall(run.domain);
                k.tick(crate::hw::read_tsc());
            }
            log_denied(run.domain, nr, "unmapped linux nr", -ENOSYS);
            return (-ENOSYS) as u64;
        };
        // Full-width bounds check first (see `normalize_nr`), then the
        // shared policy gate — before any argument is examined.
        let Some(nr8) = normalize_nr(nr) else {
            run.bad_syscalls = run.bad_syscalls.saturating_add(1);
            // N2 (ADR-0007 §2): an unnormalizable nr is a denial on the
            // LIVE domain (out-of-profile by definition) and drives the
            // monitor clock.
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_unknown_syscall(run.domain);
                k.tick(crate::hw::read_tsc());
            }
            log_denied(run.domain, nr, "unknown syscall", -ENOSYS);
            return (-ENOSYS) as u64;
        };

        // ADR-0023 D8: rt_sigreturn is ENTRY MACHINERY, like SYSRET
        // itself — the kernel invoked it (via the trampoline it
        // installed); the policy authority was exercised at sigaction
        // and delivery time, so it is handled BEFORE the gate. The
        // frame it carries is validated against the kernel's own
        // delivery record; a forged or displaced frame refuses.
        if nr8 == SYS_SIGRETURN {
            return sys_sigreturn(run);
        }
        // N2 (ADR-0007 §2): the LIVE lib domain is the gate — stats,
        // used-bits and denials land where the monitor reads them, and
        // Tighten/Quarantine apply to the very next syscall. The
        // snapshot fields remain only as a no-kernel fallback (host
        // tests) and for display.
        let decision = match context::kernel_mut() {
            Some(k) => {
                k.tick(crate::hw::read_tsc());
                match k.dispatch(run.domain, nr8) {
                    Ok(d) => d,
                    // Unreachable: the run's domain was spawned by kmain.
                    Err(_) => Decision::BadSyscall(nr8),
                }
            }
            None => gate(&run.mask, run.quarantined, nr8),
        };
        let result = match decision {
            Decision::Allowed if nr8 == SYS_EXIT => {
                run.exit = ExitKind::Exited(a1);
                // N2: close the window bookkeeping on the way out.
                if let Some(k) = context::kernel_mut() {
                    k.tick(crate::hw::read_tsc());
                }
                // ADR-0027 (the ADR-0024 D2 fix): release every frame
                // this domain MAPS BUT DOES NOT OWN — the fork child's
                // and the grantee's side of each share. Without this,
                // the dying side's reference leaks and the owner's
                // later teardown finds refs stuck at 1 (found live:
                // "teardown domain 27: freed 5 of 9"). The frames the
                // domain DOES own stay the reclaim path's business.
                if let (Some(pool), Some(k)) = (context::pool_mut(), context::kernel_mut()) {
                    let _ = crate::mm::shares::release_borrowed_frames(
                        &run.tables,
                        pool,
                        &mut k.frames,
                        run.domain,
                    );
                }
                // GS back to the kernel view, then jump to the launch
                // point — SYSRET never happens for EXIT.
                hw::swapgs();
                context::resume_kernel();
            }
            Decision::Allowed if nr8 == SYS_WRITE => sys_write(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_SCHED_YIELD => sys_sched_yield(run),
            Decision::Allowed if nr8 == SYS_NANOSLEEP => sys_nanosleep(run, a1),
            Decision::Allowed if nr8 == SYS_CLOCK_GETTIME => sys_clock_gettime(run, a1, a2),
            Decision::Allowed if nr8 == SYS_SIGACTION => sys_sigaction(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_KILL => sys_kill(run, a1, a2),
            // Phase 6 S1: the path family — mkdir/unlink/chroot from
            // ring 3 (the core executors were live since round F11;
            // the arms arrive with the boot root).
            Decision::Allowed if nr8 == SYS_MKDIR => sys_mkdir(run, a1, a2),
            // K20 (P0-2): the network data path — the brokered socket's
            // send/receive arms, gated by the core policy (Device cap +
            // token bucket) and driven against the live virtio-net
            // session the driver-stack proof armed.
            Decision::Allowed if nr8 == SYS_NET_SEND => sys_net_send(run, a1, a2),
            Decision::Allowed if nr8 == SYS_NET_RECV => sys_net_recv(run, a1, a2),
            Decision::Allowed if nr8 == SYS_UNLINK => sys_unlink(run, a1),
            // K21: the package manager's remaining arms — stat for
            // the destination-parent walks, rename for the journaled
            // commit. (getdents already ran as SYS_LISTDIR; execve
            // marshals argv since Phase 6 S3.)
            Decision::Allowed if nr8 == SYS_STAT => sys_stat(run, a1, a2),
            Decision::Allowed if nr8 == SYS_RENAME => sys_rename(run, a1, a2),
            Decision::Allowed if nr8 == SYS_LISTDIR => sys_listdir(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_CHROOT => sys_chroot(run, a1),
            Decision::Allowed if nr8 == SYS_MMAP => sys_mmap(run, a1, a2, a3, _a4, linux_abi),
            Decision::Allowed if nr8 == SYS_MUNMAP => sys_munmap(run, a1, a2),
            Decision::Allowed if nr8 == SYS_FORK => sys_fork(run),
            Decision::Allowed if nr8 == SYS_EXEC => sys_exec(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_WAIT => sys_wait(run, a1, a2, a3, _a4),
            Decision::Allowed if nr8 == SYS_IPC_SEND => sys_ipc_send(run, a1, a2),
            Decision::Allowed if nr8 == SYS_IPC_RECV => sys_ipc_recv(run, a1),
            Decision::Allowed if nr8 == SYS_IPC_CALL => sys_ipc_call(run, a1, a2),
            Decision::Allowed if nr8 == SYS_IPC_RECV_WAIT => sys_ipc_recv_wait(run, a1),
            Decision::Allowed if nr8 == SYS_IPC_REPLY => sys_ipc_reply(run, a1, a2),
            // ADR-0017 round two: the ring-3 driver's register channel.
            // One message, one window-checked access, routed to the
            // CALLING domain's core — the routing is the capability.
            Decision::Allowed if nr8 == SYS_DEVREG => sys_devreg(run, a1, a2, a3, _a4, _a5),
            Decision::Allowed if nr8 == SYS_IPC_GRANT => sys_grant_frames(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_PIPE_READ => sys_pipe_read(run, a1, a2, a3),
            Decision::Allowed if nr8 == SYS_PIPE_WRITE => sys_pipe_write(run, a1, a2, a3),
            // Round J: the file family runs on the LIVE lib kernel —
            // marshaled through sysabi, executed by `Kernel::execute`.
            Decision::Allowed if sysabi::FILE_FAMILY.contains(&nr8) => {
                sys_file(run, nr8, a1, a2, a3, linux_abi)
            }
            Decision::Allowed => {
                // In the mask, but not implemented (MMAP, SPAWN, IPC,
                // NET, ...). Not an attack signal — just unimplemented.
                log_denied(run.domain, nr, "not implemented yet", -ENOSYS);
                (-ENOSYS) as u64
            }
            Decision::BadSyscall(_) => {
                run.bad_syscalls = run.bad_syscalls.saturating_add(1);
                log_denied(run.domain, nr, "unknown syscall", -ENOSYS);
                (-ENOSYS) as u64
            }
            Decision::DeniedByMask(_) | Decision::DeniedQuarantined(_) => {
                run.denied = run.denied.saturating_add(1);
                log_denied(run.domain, nr, "denied by policy", -EPERM);
                (-EPERM) as u64
            }
        };
        // ADR-0023 D8: the kernel→user boundary — deliver one pending
        // caught signal on the way out (the frame rewrite IS the
        // delivery; SYS_EXIT and the park paths never reach here).
        maybe_deliver_signal(run, result);
        result
    }

    /// ADR-0023 D8: deliver one pending caught signal by rewriting the
    /// in-flight syscall frame and pushing the signal frame onto the
    /// user stack. The interrupted image (including THIS syscall's
    /// result in RAX) is captured into the frame; the handler enters
    /// with RSP at the frame (a plain `ret` reaches the trampoline)
    /// and RDI = signum. The kernel's own delivery record (cookie +
    /// exact frame address) rides the run; sigreturn refuses anything
    /// that does not match it.
    fn maybe_deliver_signal(run: &mut crate::sched::context::UserRun, result: u64) {
        use crate::arch::syscall_entry::{frame_word, write_frame_word};
        use crate::arch::syscall_frame::{
            OFF_R10, OFF_R11, OFF_R8, OFF_R9, OFF_RAX, OFF_RBX, OFF_RCX, OFF_RDI, OFF_RDX, OFF_RSI,
        };
        use crate::mm::user_range::copy_out_bytes;
        use aegis_os::sigframe::{self, InterruptedImage};

        let user_rsp = crate::arch::syscall_entry::user_rsp_save();
        // 16-byte-aligned, 136 bytes below the interrupted stack (the
        // frame plus the trampoline's popped restorer word).
        let new_rsp = (user_rsp.saturating_sub(136)) & !0xF;
        // The stack span must be a present user stack page — a blown
        // stack skips delivery (the signal stays pending; the domain's
        // own next fault is the loud answer).
        if !validate_user_range(run, new_rsp, sigframe::SIGFRAME_BYTES as u64, 136) {
            return;
        }
        let Some(k) = context::kernel_mut() else {
            return;
        };
        let Some((sig, handler, restorer)) = k.pop_catchable_signal(run.domain) else {
            return;
        };
        let img = InterruptedImage {
            rip: frame_word(OFF_RCX),
            cs: (crate::arch::gdt::USER_CODE | 3) as u64,
            rflags: frame_word(OFF_R11),
            rsp: user_rsp,
            ss: (crate::arch::gdt::USER_DATA | 3) as u64,
            gprs: [
                result,
                frame_word(OFF_RDI),
                frame_word(OFF_RSI),
                frame_word(OFF_RDX),
                frame_word(OFF_R10),
                frame_word(OFF_R8),
                frame_word(OFF_R9),
                frame_word(OFF_RBX),
            ],
        };
        // The cookie: TSC-mixed, kernel-chosen, recorded only here and
        // in the frame itself.
        let t = crate::hw::read_tsc();
        let cookie = t ^ (t.rotate_left(32)) ^ (u64::from(run.domain) << 48) ^ u64::from(sig);
        let mut frame = [0u8; sigframe::SIGFRAME_BYTES];
        sigframe::build(sig, cookie, restorer, &img, &mut frame);
        // Write the frame onto the user stack under the blessed window
        // (the span was validated above; the current CR3 is the run's).
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let _ = copy_out_bytes(new_rsp, &frame, &|va, b| memops::write_u8_va(va, b));
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        // Rewrite the in-flight frame: the stub SYSRETs into the
        // handler with RDI = signum; the interrupted RAX (this
        // syscall's result) lives on in the signal frame.
        write_frame_word(OFF_RCX, handler);
        write_frame_word(OFF_RDI, u64::from(sig));
        write_frame_word(OFF_RAX, 0);
        crate::arch::syscall_entry::set_user_rsp_save(new_rsp);
        run.delivered = Some(crate::sched::context::Delivered {
            sig,
            cookie,
            frame_rsp: new_rsp,
        });
    }

    /// rt_sigaction(signum, handler, restorer) — ADR-0023 D8. The
    /// handler must be a canonical user address; the restorer must be
    /// THE trampoline (custom restorers are not supported — the
    /// trampoline page is the only rt_sigreturn entry the kernel
    /// honors, and it is mapped into every user address space).
    fn sys_sigaction(
        run: &mut crate::sched::context::UserRun,
        signum: u64,
        handler: u64,
        restorer: u64,
    ) -> u64 {
        // K22: THE trampoline is this run's (its layout's) — a service
        // image's restorer lives at its own contract's address.
        let trampoline = run.layout.trampoline_base;
        if handler == 0 || handler > aegis_os::sigframe::USER_CANON_MAX {
            return (-EINVAL) as u64;
        }
        if restorer != 0 && restorer != trampoline {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let Ok(signum8) = u8::try_from(signum) else {
            return (-EINVAL) as u64;
        };
        match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::SigAction {
                signum: signum8,
                handler,
                restorer: if restorer == 0 { trampoline } else { restorer },
            },
        ) {
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// kill(pid, sig) — Linux's nr 62 marshaled into the core's Kill
    /// executor (the capability + Unix-uid rules + no-enumeration
    /// properties all live there).
    fn sys_kill(run: &mut crate::sched::context::UserRun, pid: u64, sig: u64) -> u64 {
        if sig > 63 || pid > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::Kill {
                target: pid as u32,
                sig: sig as u8,
            },
        ) {
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// rt_sigreturn() — ADR-0023 D8: read the frame the trampoline
    /// points at (user memory — untrusted), validate EVERY field
    /// against the kernel's delivery record (the cookie, the exact
    /// frame address) and the pure validator (selectors, canonical
    /// rip/rsp, sanitized rflags), then rebuild the interrupted
    /// context through the same frame the stub SYSRETs from. A forged
    /// or displaced frame refuses with -EINVAL; nothing user-supplied
    /// is ever restored unsanitized.
    fn sys_sigreturn(run: &mut crate::sched::context::UserRun) -> u64 {
        use crate::arch::syscall_entry::{frame_word, write_frame_word};
        use crate::arch::syscall_frame::{
            OFF_R10, OFF_R11, OFF_R8, OFF_R9, OFF_RAX, OFF_RBX, OFF_RCX, OFF_RDI, OFF_RDX, OFF_RSI,
        };
        use aegis_os::sigframe::{self, SIGFRAME_BYTES};

        // The trampoline entered with RSP = frame + 8 (the handler's
        // `ret` popped the restorer word); the entry parked that RSP.
        let user_rsp = crate::arch::syscall_entry::user_rsp_save();
        let Some(frame_rsp) = user_rsp.checked_sub(8) else {
            return (-EINVAL) as u64;
        };
        // The delivery record must exist and match the frame address.
        let Some(rec) = run.delivered else {
            return (-EINVAL) as u64;
        };
        if rec.frame_rsp != frame_rsp {
            return (-EINVAL) as u64;
        }
        let mut bytes = [0u8; SIGFRAME_BYTES];
        if !validate_user_range(run, frame_rsp, SIGFRAME_BYTES as u64, SIGFRAME_BYTES as u64) {
            return (-EFAULT) as u64;
        }
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        for (off, b) in bytes.iter_mut().enumerate() {
            *b = memops::read_u8_va(frame_rsp + off as u64);
        }
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        let img = match sigframe::validate(
            &bytes,
            rec.cookie,
            (crate::arch::gdt::USER_CODE | 3) as u64,
            (crate::arch::gdt::USER_DATA | 3) as u64,
        ) {
            Ok(img) => img,
            Err(_) => {
                // Forged or displaced: refused, counted. The record
                // stays — the next genuine sigreturn (or the domain's
                // exit) settles it.
                return (-EINVAL) as u64;
            }
        };
        // Rebuild the interrupted context: the stub SYSRETs with the
        // frame's slots, and the user RSP rides USER_RSP_SAVE.
        write_frame_word(OFF_RCX, img.rip);
        write_frame_word(OFF_R11, img.rflags);
        write_frame_word(OFF_RAX, img.gprs[0]);
        write_frame_word(OFF_RDI, img.gprs[1]);
        write_frame_word(OFF_RSI, img.gprs[2]);
        write_frame_word(OFF_RDX, img.gprs[3]);
        write_frame_word(OFF_R10, img.gprs[4]);
        write_frame_word(OFF_R8, img.gprs[5]);
        write_frame_word(OFF_R9, img.gprs[6]);
        write_frame_word(OFF_RBX, img.gprs[7]);
        crate::arch::syscall_entry::set_user_rsp_save(img.rsp);
        run.delivered = None;
        let _ = frame_word; // (diagnostics anchor)
        0
    }

    /// The file-family executor (Round J): marshal the six-register ABI
    /// into `SysRequest` values and run them on the LIVE lib kernel —
    /// the same domains, fd tables, pipes and VFS the monitor reads.
    /// The gate already allowed the nr; every argument below is still
    /// untrusted and re-validated.
    fn sys_file(
        run: &mut crate::sched::context::UserRun,
        nr: u8,
        a1: u64,
        a2: u64,
        a3: u64,
        linux_abi: bool,
    ) -> u64 {
        use aegis_os::sys::SysRequest;
        use aegis_os::syscall::{SYS_CLOSE, SYS_DUP, SYS_OPEN, SYS_PIPE, SYS_READ};
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        match nr {
            SYS_OPEN => sys_open(run, k, a1, a2, a3, linux_abi),
            SYS_READ => sys_read(run, k, a1, a2, a3),
            SYS_CLOSE => match fd_arg(a1) {
                Ok(fd) => match k.execute(run.domain, SysRequest::Close { fd }) {
                    Ok(_) => 0,
                    Err(e) => sysabi::errno_of(&e) as u64,
                },
                Err(e) => e as u64,
            },
            SYS_PIPE => match k.execute(run.domain, SysRequest::Pipe) {
                Ok(SysValue::FdPair(r, w))
                    if k.domain(run.domain).is_some_and(|d| d.abi == Abi::Linux) =>
                {
                    // ADR-0003 (v1): Linux pipe(2) on x86_64 answers
                    // rax = read fd, rdx = write fd — the frame's RDX
                    // slot is what the SYSRET stub pops.
                    use crate::arch::syscall_entry::write_frame_word;
                    use crate::arch::syscall_frame::OFF_RDX;
                    write_frame_word(OFF_RDX, u64::from(w));
                    u64::from(r)
                }
                Ok(v) => sysabi::rax_of(v), // the packed internal ABI
                Err(e) => sysabi::errno_of(&e) as u64,
            },
            SYS_DUP => match (fd_arg(a1), fd_arg(a2)) {
                (Ok(fd), Ok(new_fd)) => match k.execute(run.domain, SysRequest::Dup { fd, new_fd })
                {
                    Ok(v) => sysabi::rax_of(v),
                    Err(e) => sysabi::errno_of(&e) as u64,
                },
                (_, Err(e)) | (Err(e), _) => e as u64,
            },
            _ => (-ENOSYS) as u64,
        }
    }

    /// An fd argument: no truncation smuggling (fd = 0x100 must be
    /// EBADF, not fd 0 — the same full-width discipline as the nr).
    fn fd_arg(a: u64) -> Result<u8, i64> {
        if a > u8::MAX as u64 {
            Err(-EBADF)
        } else {
            Ok(a as u8)
        }
    }

    /// SYS_OPEN(path, flags, mode): the path is a NUL-terminated
    /// string in user memory, read page-check-as-you-go (a short path
    /// before an absent page succeeds); flags decode through
    /// `sysabi::open_flags` (unknown bits refuse); mode is masked to
    /// 0o777 like Linux's O_CREAT mode argument.
    fn sys_open(
        run: &mut crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        path_va: u64,
        flags: u64,
        mode: u64,
        linux_abi: bool,
    ) -> u64 {
        use aegis_os::sys::SysRequest;
        use aegis_os::vfs::Mode;
        // ADR-0003 (v1 slice 2): a Linux-mode caller passes a Linux
        // O_* word — the encoding is NOT the internal one (Linux's
        // O_RDONLY is 0, the internal 0 is "no access at all"), so
        // the word is translated at the entry and every bit whose
        // semantics the internal VFS cannot honor (O_APPEND,
        // O_NONBLOCK, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, ...) is
        // refused -EINVAL — never silently dropped. O_TRUNC|O_RDONLY
        // then dies in `open_flags` with the same EINVAL a native
        // caller gets (POSIX-undefined, kernel-refused).
        let flags = if linux_abi {
            match sysabi::linux_open_flags(flags) {
                Ok(f) => f,
                Err(e) => return e as u64,
            }
        } else {
            flags
        };
        let (read, write, create, truncate, excl) = match sysabi::open_flags(flags) {
            Ok(f) => f,
            Err(e) => return e as u64,
        };
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        let mode = Mode((mode & 0o777) as u16);
        match k.execute(
            run.domain,
            SysRequest::Open {
                path,
                mode,
                create,
                read,
                write,
                truncate,
                excl,
            },
        ) {
            Ok(v) => sysabi::rax_of(v),
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// The bounded, page-checked path copy-in (the SYS_OPEN reader).
    /// SMAP is armed around the whole walk: the page-table reads it
    /// interleaves are kernel accesses (unaffected by AC), the byte
    /// reads are user accesses (permitted only under the blessed
    /// window, N4/ADR-0008).
    fn read_user_path(
        run: &crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        va: u64,
        out: &mut [u8; sysabi::MAX_PATH],
    ) -> Result<usize, i64> {
        use crate::mm::user_range::{read_user_cstr, CstrError};
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let r = read_user_cstr(
            va,
            sysabi::MAX_PATH,
            pte::USER_LIMIT,
            pte::PAGE_SIZE_U64,
            &|page| match run.tables.pte_of(page) {
                Some(e) => e & pte::PTE_U != 0 && e & pte::PTE_P != 0,
                None => false,
            },
            &|va| memops::read_u8_va(va),
            out,
        );
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        match r {
            Ok(len) => Ok(len),
            // No NUL within MAX_PATH: the string is not path-shaped.
            Err(CstrError::TooLong) => Err(-ENAMETOOLONG),
            // A page the walk reached is not a present user page — an
            // organic fault signal on the live domain (N2).
            Err(CstrError::Fault) => {
                let _ = k.report_fault(run.domain);
                Err(-EFAULT)
            }
        }
    }

    // ── Phase 6 S1: the path family — mkdir/unlink/chroot from
    // ring 3. The core executors (round F11, host-tested) were
    // waiting for arms; the boot root is what makes them real.
    // All three read the path through the SAME bounded, page-checked
    // copy-in as SYS_OPEN (read_user_path) — no second path reader
    // exists to get wrong. ──

    /// SYS_MKDIR(path, mode): mode is masked to 0o777 exactly like
    /// SYS_OPEN's O_CREAT mode argument.
    fn sys_mkdir(run: &mut crate::sched::context::UserRun, path_va: u64, mode: u64) -> u64 {
        use aegis_os::sys::SysRequest;
        use aegis_os::vfs::Mode;
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        match k.execute(
            run.domain,
            SysRequest::Mkdir {
                path,
                mode: Mode((mode & 0o777) as u16),
            },
        ) {
            Ok(v) => sysabi::rax_of(v),
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// SYS_UNLINK(path): unlink(2) and rmdir(2) folded — the core's
    /// unlink refuses a non-empty directory with ENOTEMPTY and
    /// unlinks an empty directory, which is exactly the rmdir(2)
    /// contract (the internal ABI documents the fold; the Linux
    /// entry maps both nrs 87 and 84's story through this arm).
    fn sys_unlink(run: &mut crate::sched::context::UserRun, path_va: u64) -> u64 {
        use aegis_os::sys::SysRequest;
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        match k.execute(run.domain, SysRequest::Unlink { path }) {
            Ok(v) => sysabi::rax_of(v),
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// SYS_STAT(path, out) — K21: the 24-byte metadata struct. The
    /// core fills a kernel buffer once (no double-fetch); the copy
    /// out rides the blessed SMAP window like every byte-out arm.
    /// The out-buffer bound is fixed (24) — the manager's adapter
    /// sizes it exactly (BUILD.md); anything shorter is EINVAL
    /// before the core runs.
    fn sys_stat(run: &mut crate::sched::context::UserRun, path_va: u64, out_va: u64) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        use aegis_os::sys::SysRequest;
        const STAT_OUT: u64 = 24;
        if !validate_user_range(run, out_va, STAT_OUT, STAT_OUT) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        let mut kbuf = [0u8; 24];
        match k.execute(
            run.domain,
            SysRequest::Stat {
                path,
                out: &mut kbuf,
            },
        ) {
            Ok(SysValue::Count(24)) => {
                IN_USER_COPY.store(true, Ordering::SeqCst);
                if crate::hw::smap_active() {
                    crate::hw::stac();
                }
                let wrote = copy_out_bytes(out_va, &kbuf, &|va, b| memops::write_u8_va(va, b));
                if crate::hw::smap_active() {
                    crate::hw::clac();
                }
                IN_USER_COPY.store(false, Ordering::SeqCst);
                wrote
            }
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// SYS_RENAME(from, to) — K21: the atomic re-parent. Both paths
    /// ride the SAME bounded, page-checked copy-in as every path arm
    /// (no second path reader exists to get wrong); the core
    /// re-resolves both parents and gates the WRITE caps itself.
    fn sys_rename(run: &mut crate::sched::context::UserRun, from_va: u64, to_va: u64) -> u64 {
        use aegis_os::sys::SysRequest;
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        let mut frombuf = [0u8; sysabi::MAX_PATH];
        let flen = match read_user_path(run, k, from_va, &mut frombuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(from) = core::str::from_utf8(&frombuf[..flen]) else {
            return (-EINVAL) as u64;
        };
        let mut tobuf = [0u8; sysabi::MAX_PATH];
        let tlen = match read_user_path(run, k, to_va, &mut tobuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(to) = core::str::from_utf8(&tobuf[..tlen]) else {
            return (-EINVAL) as u64;
        };
        match k.execute(run.domain, SysRequest::Rename { from, to }) {
            Ok(v) => sysabi::rax_of(v),
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// The console-in device path (Phase 7): drain the UART
    /// opportunistically — the service-time half of the TTY; the IRQ
    /// bottom half may already have taken everything — then move up
    /// to `len` bytes from the ring out under the blessed SMAP
    /// window. 0 = nothing typed yet (the shell's poll signal; this
    /// TTY has no EOF — the idle shell exits on its own timer).
    fn sys_read_console(run: &mut crate::sched::context::UserRun, buf: u64, len: u64) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        if len as usize > sysabi::MAX_READ {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len, sysabi::MAX_READ as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        crate::tty::drain_uart();
        let mut kbuf = [0u8; sysabi::MAX_READ];
        let n = crate::tty::drain(&mut kbuf[..len as usize]);
        if n == 0 {
            return 0;
        }
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let _ = copy_out_bytes(buf, &kbuf[..n], &|va, b| memops::write_u8_va(va, b));
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        n as u64
    }

    /// SYS_LISTDIR(fd, buf, len) — Phase 7: the shell's `ls`. The
    /// executor fills a kernel buffer once (no double-fetch), the
    /// names copy out byte-exact under the blessed SMAP window — the
    /// `sys_pipe_read` shape over the VFS's directory walk.
    fn sys_listdir(run: &mut crate::sched::context::UserRun, fd: u64, buf: u64, len: u64) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        if len as usize > sysabi::MAX_READ {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len, sysabi::MAX_READ as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let fd = match fd_arg(fd) {
            Ok(fd) => fd,
            Err(e) => return e as u64,
        };
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let mut kbuf = [0u8; sysabi::MAX_READ];
        match k.execute(
            run.domain,
            SysRequest::ListDir {
                fd,
                buf: &mut kbuf[..len as usize],
            },
        ) {
            Ok(SysValue::Count(n)) => {
                IN_USER_COPY.store(true, Ordering::SeqCst);
                if crate::hw::smap_active() {
                    crate::hw::stac();
                }
                let wrote = copy_out_bytes(buf, &kbuf[..n], &|va, b| memops::write_u8_va(va, b));
                if crate::hw::smap_active() {
                    crate::hw::clac();
                }
                IN_USER_COPY.store(false, Ordering::SeqCst);
                wrote
            }
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// SYS_CHROOT(path): the confinement change — resolve against the
    /// CURRENT root, then re-root (the cwd moves with the root, the
    /// ADR-0023 close of the historical chroot+cwd escape). One-way
    /// for every caller: no arm widens a root.
    fn sys_chroot(run: &mut crate::sched::context::UserRun, path_va: u64) -> u64 {
        use aegis_os::sys::SysRequest;
        let Some(k) = context::kernel_mut() else {
            return (-ENOSYS) as u64;
        };
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(l) => l,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        match k.execute(run.domain, SysRequest::Chroot { path }) {
            Ok(v) => sysabi::rax_of(v),
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// sched_yield(2) — ADR-0023 D3: charge the slice, then either
    /// park-and-switch (the fair pick exists) or return 0 (solo).
    fn sys_sched_yield(run: &mut crate::sched::context::UserRun) -> u64 {
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match crate::sched::preempt::yield_decision(&mut k.sched, run.domain) {
            Some(_) => crate::sched::park::park_current_from_syscall(0),
            None => 0,
        }
    }

    /// nanosleep(2) — ADR-0023: read the timespec ONCE (page-checked,
    /// under the SMAP window), convert through THE calibrated clock
    /// (the same number the tick rides), register the sleep in the
    /// core, then park the run; the idle state covers the
    /// nothing-else-runnable case. The parked copy resumes with RAX=0
    /// — the syscall "returns" when the sleeper wakes.
    fn sys_nanosleep(run: &mut crate::sched::context::UserRun, req: u64) -> u64 {
        if !validate_user_range(run, req, 16, 16) {
            let _ = context::kernel_mut().map(|k| k.report_fault(run.domain));
            return (-EFAULT) as u64;
        }
        let mut ts = [0u8; 16];
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        for (off, b) in ts.iter_mut().enumerate() {
            *b = memops::read_u8_va(req + off as u64);
        }
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        let Some((sec, nsec)) = crate::clock::parse_timespec(&ts) else {
            return (-EINVAL) as u64;
        };
        let Some(ns) = crate::clock::timespec_to_ns(sec, nsec) else {
            return (-EINVAL) as u64;
        };
        if ns == 0 {
            // A zero sleep is a plain yield without the queue dance.
            return 0;
        }
        let Some(cycles) = crate::clock::ns_to_cycles(ns) else {
            return (-EINVAL) as u64;
        };
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            SysRequest::Nanosleep {
                now: crate::hw::read_tsc(),
                cycles,
            },
        ) {
            Ok(SysValue::Count(_)) => crate::sched::park::park_current_from_syscall(0),
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// clock_gettime(2) — ADR-0023 D4: CLOCK_MONOTONIC and
    /// CLOCK_REALTIME (equal: no RTC wiring yet — documented, not
    /// faked), computed from the calibrated TSC, copied out
    /// byte-exact through the page-checked write window.
    fn sys_clock_gettime(run: &mut crate::sched::context::UserRun, clk: u64, ts: u64) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        if clk > 1 {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, ts, 16, 16) {
            let _ = context::kernel_mut().map(|k| k.report_fault(run.domain));
            return (-EFAULT) as u64;
        }
        let ns = crate::clock::now_ns();
        let sec = (ns / 1_000_000_000u128) as u64;
        let nsec = (ns % 1_000_000_000u128) as u64;
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&sec.to_le_bytes());
        out[8..].copy_from_slice(&nsec.to_le_bytes());
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let _ = copy_out_bytes(ts, &out, &|va, b| memops::write_u8_va(va, b));
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        0
    }

    /// mmap(addr, len, prot) — ADR-0024 D1: the gate ran (the used-bit
    /// and monitor accounting land in `dispatch`); the EXECUTION makes
    /// the mapping REAL — the same ten-check policy and the same
    /// rollback-on-failure mapper spawn uses, over the RUN's own
    /// tables and space, every frame pool-allocated with
    /// `owner = run.domain` (exit reclaims through `free_all_owned`).
    /// ANON only. `addr == 0` picks the lowest policy-acceptable
    /// window at/above the trampoline; a nonzero hint is honored or
    /// refused (never relocated — no MAP_FIXED guessing).
    fn sys_mmap(
        run: &mut crate::sched::context::UserRun,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        linux_abi: bool,
    ) -> u64 {
        use crate::mm::page_table::{MapError, PoolSource};
        use aegis_os::memory::MemFlags;

        // K22: the window floor is the RUN's — one page above its own
        // trampoline (a service image's floor sits far above the
        // canonical one).
        let window_floor = run.layout.window_floor();
        /// The per-call ceiling (matches the policy's own quota scale;
        /// a bigger ask is a program error, not an OOM).
        const MAX_MMAP: u64 = 16 << 20;

        if len == 0 || len > MAX_MMAP {
            return (-EINVAL) as u64;
        }
        // ADR-0003 (v1): a Linux-mode caller passes mmap(2) flags in
        // arg4 — this ABI is ANON|PRIVATE only (0x22); MAP_SHARED, a
        // file mapping, or MAP_FIXED (which also unmaps overlapping
        // pages in Linux) refuses rather than mistranslating.
        const MAP_PRIVATE: u64 = 0x02;
        const MAP_ANONYMOUS: u64 = 0x20;
        if linux_abi && flags != (MAP_PRIVATE | MAP_ANONYMOUS) {
            return (-EINVAL) as u64;
        }
        // Linux PROT bits only: READ=1 WRITE=2 EXEC=4.
        if prot & !0b111 != 0 {
            return (-EINVAL) as u64;
        }
        let mut flags = MemFlags(0);
        if prot & 1 != 0 {
            flags = MemFlags(flags.0 | MemFlags::READ.0);
        }
        if prot & 2 != 0 {
            flags = MemFlags(flags.0 | MemFlags::WRITE.0);
        }
        if prot & 4 != 0 {
            flags = MemFlags(flags.0 | MemFlags::EXEC.0);
        }
        // Round the length up to the page (Linux behavior; the policy
        // is page-granular anyway).
        let len_r = ((len as usize) + 4095) & !4095;
        let base = if addr == 0 {
            match run.space.find_free_window(len_r, window_floor as usize) {
                Some(b) => b as u64,
                None => return (-ENOMEM) as u64,
            }
        } else {
            if !addr.is_multiple_of(4096) || addr < window_floor {
                return (-EINVAL) as u64;
            }
            addr
        };
        let (Some(pool), Some(k)) = (context::pool_mut(), context::kernel_mut()) else {
            return (-ENOMEM) as u64;
        };
        let mut src = PoolSource::new(pool, &mut k.frames, run.domain);
        match run
            .tables
            .map_region(&mut run.space, base, len_r, flags, &mut src)
        {
            Ok(_) => base,
            Err(MapError::Policy(aegis_os::memory::MemError::QuotaExceeded)) => (-ENOMEM) as u64,
            Err(MapError::Policy(_)) => (-EINVAL) as u64,
            Err(_) => (-ENOMEM) as u64,
        }
    }

    /// munmap(addr, len) — ADR-0024 D1: WHOLE-REGION semantics (the
    /// addr must name a region's exact base and len its exact length;
    /// splitting is Phase 5+). The spawn-time layout is below the
    /// window floor and refuses here — it is freed by teardown, not by
    /// the ABI. Frames return through the pool (owner-scoped, scrubbed
    /// on free).
    fn sys_munmap(run: &mut crate::sched::context::UserRun, addr: u64, len: u64) -> u64 {
        let window_floor = run.layout.window_floor();
        if !addr.is_multiple_of(4096) || addr < window_floor || len == 0 {
            return (-EINVAL) as u64;
        }
        // Whole-region: exact base AND exact length.
        let exact = run
            .space
            .regions()
            .any(|r| r.base == addr as usize && r.len == len as usize);
        if !exact {
            return (-EINVAL) as u64;
        }
        let (Some(pool), Some(k)) = (context::pool_mut(), context::kernel_mut()) else {
            return (-ENOMEM) as u64;
        };
        // ADR-0027: the shares-aware source — unmapping a SHARED page
        // (fork-shared, granted) releases its refcount instead of
        // pool-freeing a frame another space still maps (a latent
        // double-free in the fork round, closed with the grant's
        // accounting).
        let mut src = crate::mm::page_table::SharesSource {
            pool,
            buddy: &mut k.frames,
            owner: run.domain,
            shares: context::shares_mut(),
        };
        match run.tables.unmap_region(&mut run.space, addr, &mut src) {
            Ok(_) => 0,
            Err(_) => (-EINVAL) as u64,
        }
    }

    /// fork() — ADR-0024 D2: the core's fork_process (masks ∩, caps ∩
    /// minus parent-aimed, fds, creds — round K's semantics) followed
    /// by the memory half this round adds: the page-table tree cloned
    /// with every shared user frame refcounted and every WRITABLE page
    /// demoted read-only on BOTH sides. The child enters the world
    /// parked with the parent's syscall image and RAX=0; the parent
    /// returns the child's id. The first write on either side faults,
    /// and the fault path's CoW branch copies the frame privately.
    fn sys_fork(run: &mut crate::sched::context::UserRun) -> u64 {
        use crate::mm::page_table::PoolSource;

        let parent = run.domain;
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let child = match k.fork_process(parent) {
            Ok(c) => c,
            Err(aegis_os::proc::ProcError::UnknownProcess(_)) => {
                return (-sysabi::ESRCH) as u64;
            }
            Err(aegis_os::proc::ProcError::Quarantined(_)) => {
                return (-sysabi::EPERM) as u64;
            }
            // The capacity family (children limit, table/meta
            // exhaustion): the Unix "try again".
            Err(_) => return (-sysabi::EAGAIN) as u64,
        };
        // The child's table frames allocate under the CHILD's tag;
        // shared data frames keep their provenance in the table.
        let Some(pool) = context::pool_mut() else {
            let _ = k.destroy_domain(child);
            return (-ENOMEM) as u64;
        };
        let tables = {
            let mut src = PoolSource::new(pool, &mut k.frames, child);
            let shares = context::shares_mut();
            match run.tables.clone_for_fork(&mut src, shares, parent) {
                Ok(t) => t,
                Err(_) => {
                    // The clone rolled itself back; undo the core fork.
                    let _ = k.destroy_domain(child);
                    return (-ENOMEM) as u64;
                }
            }
        };
        // The child's run: a fresh accounting shell over the shared
        // memory (the snapshot mask is the parent's — the LIVE gate
        // reads the child's own domain record). The memory contract is
        // the parent's too: the clone maps the same addresses (K22).
        let mut child_run = crate::sched::context::UserRun::new(
            tables,
            run.space.clone(),
            child,
            run.mask,
            run.quarantined,
        );
        child_run.layout = run.layout;
        // The child's register image: the parent's in-flight syscall
        // with RAX=0 (the fork convention), stashed parked (the unsafe
        // lives in park.rs's wrapper — this module is unsafe-free).
        let ctx = crate::sched::park::parked_from_current_syscall(0);
        crate::sched::context::stash_parked(child_run, ctx);
        child as u64
    }

    /// execve(2) — ADR-0003 v1 slice 4: the image replacement.
    /// The Linux shape is execve(path, argv, envp); the internal ABI
    /// serves the same positions. Phase 6 S3: argv/envp are now
    /// MATERIALIZED — the kernel reads the caller's strings (bounded:
    /// 8 args / 8 env entries, MAX_PATH bytes each; anything past is
    /// -E2BIG exactly like Linux), and builds the SysV initial stack
    /// before the synthetic park: [rsp] = argc, the argv pointers,
    /// NULL, the envp pointers, NULL, a minimal AT_NULL auxv, the
    /// strings above. Every GP register still enters ZERO — the
    /// stack is the only thing a fresh image may read.
    ///
    /// The path resolves against the kernel's exec registry (the
    /// compiled-in ELF images — no filesystem yet; a path with no
    /// image is -ENOENT, exactly what Linux answers for a path no
    /// filesystem resolves). The image is parsed by the slice-4
    /// loader (`aegis_os::elf`), mapped at its DECLARED vaddrs
    /// inside the exec cage, and entered at `e_entry`.
    ///
    /// The frame story (the order is load-bearing):
    /// 1. parse/resolve/plan — pure refusals, zero side effects;
    /// 2. `exec_replace` (ADR-0022 D4): mask INTERSECTION with the
    ///    path's declared profile (unlisted = app default, D5),
    ///    cloexec fds close, caught handlers reset (D8), the region
    ///    ledger clears — the point of no return;
    /// 3. the new image builds UNDER THE EXEC SCRATCH TAG while the
    ///    old image's frames are still live — a build failure answers
    ///    -ENOMEM and the OLD IMAGE CONTINUES (Linux parity), with
    ///    the mask honestly narrowed (never widened — a tightened
    ///    exec caller stays tightened; documented ABI divergence);
    /// 4. on success the old image's borrowed frames release, its
    ///    owned frames free (the scratch tag splits the two images'
    ///    ownership apart — free-by-owner-id cannot reach the new
    ///    one), and the finished image's frames re-tag to the domain
    ///    so every later teardown (wait4's reap, the drain) reclaims
    ///    them exactly like a spawned image's;
    /// 5. the run swaps to the new tables and parks with a SYNTHETIC
    ///    image: rip = e_entry, rsp = the fresh stack top, every GP
    ///    register ZERO (a fresh image reading a stale register
    ///    would read the old image's data across the exec boundary —
    ///    the register contents at process start are unspecified by
    ///    Unix; we specify zero). The park never returns.
    fn sys_exec(
        run: &mut crate::sched::context::UserRun,
        path_va: u64,
        argv: u64,
        envp: u64,
    ) -> u64 {
        use crate::sched::context::ParkedContext;
        use aegis_os::syscall::SyscallMask;

        // argv must be a canonical user pointer (Linux answers EFAULT
        // for a NULL argv — there is no argv-less exec); envp may be
        // NULL (an empty environment is legal), non-NULL must be
        // canonical.
        let user_top = 1u64 << 47;
        if argv == 0 || argv >= user_top || (envp != 0 && envp >= user_top) {
            return (-EFAULT) as u64;
        }
        // Phase 6 S3: read the caller's argv/envp NOW — the strings
        // live in the OLD image's pages, which are only guaranteed
        // while this arm runs on the old CR3 (steps 2..4 below are
        // the point of no return; the materialized copy must precede
        // them).
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let args = match read_exec_args(run, k, argv, envp) {
            Ok(a) => a,
            Err(e) => return e as u64,
        };
        // 1. The path: bounded, page-checked, SMAP-blessed copy-in.
        let mut pathbuf = [0u8; sysabi::MAX_PATH];
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let len = match read_user_path(run, k, path_va, &mut pathbuf) {
            Ok(n) => n,
            Err(e) => return e as u64,
        };
        let Ok(path) = core::str::from_utf8(&pathbuf[..len]) else {
            return (-EINVAL) as u64;
        };
        // ADR-0032 section B: canonicalize BEFORE the registry lookup —
        // `//bin/x`, `/bin/./x`, and `/bin/../bin/x` are ONE entry, so
        // no path spelling can dodge a declared policy.
        let mut canon = [0u8; sysabi::MAX_PATH];
        let Some(clen) = aegis_os::proc::canonicalize_path(path, &mut canon) else {
            return (-sysabi::ENOENT) as u64;
        };
        let Ok(cpath) = core::str::from_utf8(&canon[..clen]) else {
            return (-sysabi::EINVAL) as u64;
        };
        // K22: the registry names the image AND the memory contract it
        // was linked for — the stack, the trampoline and the cage come
        // from the entry, never from a constant.
        let Some(resolved) = crate::exec_registry::resolve_image(cpath) else {
            return (-sysabi::ENOENT) as u64;
        };
        let (image, layout) = (resolved.image, resolved.layout);
        let Ok(plan) = aegis_os::elf::build_exec_plan(image) else {
            return (-ENOEXEC) as u64;
        };
        // 1a. The CAGE pre-check — pure, same stage as the quota: an
        // image linked outside its declared contract is a plain
        // refusal (the old image keeps running, its mask untouched).
        if crate::mm::user::exec_cage_check(&plan, layout).is_err() {
            return (-sysabi::ENOMEM) as u64;
        }
        // 1b. (round N2) The QUOTA pre-check — pure, BEFORE the point
        // of no return: the image's mapped pages + stack + trampoline
        // must fit the caller's LIVE quota. A refusal is a plain
        // syscall answer: the old image keeps running, its mask
        // untouched, no frame spent. (Before this, an over-quota image
        // was caught only AFTER exec_replace had already narrowed the
        // caller — the failure path documented itself as "narrowed".)
        let live_quota = k
            .domain(run.domain)
            .map(|d| d.space.quota_pages())
            .unwrap_or(0);
        if crate::exec_registry::exec_quota_check(
            plan.map_bytes,
            layout.stack_pages,
            crate::mm::user_layout::TRAMPOLINE_PAGES,
            live_quota,
        )
        .is_err()
        {
            return (-sysabi::ENOMEM) as u64;
        }
        // 2. The point of no return: the declared profile, keyed by
        // the IMAGE IDENTITY (the content hash of the registry bytes —
        // never the path). An unlisted image inherits the caller's
        // monitor mode (None) and the app-default surface (intersected
        // with the live mask inside exec_replace); the monitor ratchet
        // there keeps an enforcing domain enforcing. cloexec fds
        // close; handlers and regions reset.
        let (declared, monitor) = match k.exec_policy_declared_for(aegis_os::proc::image_id(image))
        {
            Some((m, e)) => (m, e),
            None => (aegis_os::profile::app_profile().syscalls, None),
        };
        if let Err(aegis_os::proc::ProcError::UnknownProcess(_)) =
            k.exec_replace(run.domain, &declared, monitor)
        {
            return (-sysabi::ESRCH) as u64;
        }
        // 3. The new image builds under the scratch tag — the old
        // image's frames are untouched, so a failure here is a
        // plain refusal the old image survives.
        let build = {
            let Some(pool) = context::pool_mut() else {
                return (-ENOMEM) as u64;
            };
            crate::mm::user::exec_tables(
                k,
                pool,
                crate::exec_registry::EXEC_SCRATCH_OWNER,
                &plan,
                image,
                layout,
                live_quota,
            )
        };
        let (tables, space) = match build {
            Ok(b) => b,
            Err(_) => {
                // Roll the partial build back (scrubbed on free) and
                // continue the old image — narrowed, documented.
                if let Some(pool) = context::pool_mut() {
                    let _ = pool
                        .free_all_owned(&mut k.frames, crate::exec_registry::EXEC_SCRATCH_OWNER);
                }
                return (-ENOMEM) as u64;
            }
        };
        // 4. THE ORDER THE FIRST GREEN BOOT TAUGHT: the arm runs ON
        // THE OLD TABLES' CR3 (the SYSCALL entry never switches CR3 —
        // the kernel half lives inside the user PML4), so freeing the
        // old image's frames before the new tables are LIVE scrubs
        // the very PML4 the next instruction fetch walks — a silent
        // triple fault, an instant QEMU exit, no diagnosis line.
        // Swap first, ACTIVATE the new tables (the same
        // `run.tables.activate()` take_parked does — its kernel half
        // was installed by exec_tables), and only then tear the old
        // image down, from the safety of the new one.
        let old_tables = core::mem::replace(&mut run.tables, tables);
        run.space = space;
        run.layout = layout;
        run.tables.activate();
        // ── Phase 6 S3: materialize the initial stack — BETWEEN the
        // activation and the teardown, so every possible failure is
        // answered while the old image is still alive: a refusal
        // landing after the old frames free answers into a destroyed
        // image (found live: a post-teardown validate answered -EFAULT
        // and the child's next instruction fetch faulted through the
        // new tables at its own exit path). The fresh stack page is
        // mapped by exec_tables; validate's 4th argument is the
        // LENGTH BOUND (the sigframe/nanosleep calls pin the idiom) —
        // the whole image, never an alignment. ──
        let entry_rsp = {
            let mut stack_img = [0u8; EXEC_STACK_IMG];
            let (total, entry_rsp) = build_initial_stack(&args, layout.stack_top(), &mut stack_img);
            debug_assert!(total <= EXEC_STACK_IMG);
            if !validate_user_range(run, entry_rsp, total as u64, EXEC_STACK_IMG as u64) {
                // Unreachable by construction (exec_tables maps the
                // stack; the image is bounded) — but if it ever fires,
                // the old image below is still ALIVE, so returning is
                // honest: the caller survives with -EFAULT.
                return (-EFAULT) as u64;
            }
            IN_USER_COPY.store(true, Ordering::SeqCst);
            if crate::hw::smap_active() {
                crate::hw::stac();
            }
            let _ =
                crate::mm::user_range::copy_out_bytes(entry_rsp, &stack_img[..total], &|va, b| {
                    memops::write_u8_va(va, b)
                });
            if crate::hw::smap_active() {
                crate::hw::clac();
            }
            IN_USER_COPY.store(false, Ordering::SeqCst);
            entry_rsp
        };
        if let Some(pool) = context::pool_mut() {
            let _ = crate::mm::shares::release_borrowed_frames(
                &old_tables,
                pool,
                &mut k.frames,
                run.domain,
            );
            crate::mm::user::free_frames_of(k, pool, run.domain);
            let moved = pool.retag_owner(crate::exec_registry::EXEC_SCRATCH_OWNER, run.domain);
            debug_assert!(moved > 0, "the built image must own its frames");
        }
        // 5. The narrowed mask and the synthetic park: fresh ledger,
        // a zeroed register file — and the one thing a fresh image
        // may read: the materialized argc/argv/envp stack.
        run.mask = SyscallMask::from_bits(run.mask.bits() & declared.bits());
        let entry_ctx = crate::sched::context::UserContext::new(plan.entry, entry_rsp);
        let parked = ParkedContext::from_user_context(&entry_ctx);
        crate::sched::park::park_current_exec_image(parked)
    }

    /// ── Phase 6 S3: the exec argument block ── bounded like Linux
    /// answers E2BIG: at most 8 argv entries and 8 envp entries, each
    /// a NUL-terminated string of at most MAX_PATH bytes.
    const MAX_EXEC_ARGS: usize = 8;
    const EXEC_STACK_IMG: usize = 2560;

    #[derive(Clone, Copy)]
    struct ExecArgs {
        argv: [[u8; sysabi::MAX_PATH]; MAX_EXEC_ARGS],
        argv_len: [usize; MAX_EXEC_ARGS],
        argc: usize,
        envp: [[u8; sysabi::MAX_PATH]; MAX_EXEC_ARGS],
        envp_len: [usize; MAX_EXEC_ARGS],
        envc: usize,
    }

    impl ExecArgs {
        const fn zeroed() -> Self {
            ExecArgs {
                argv: [[0; sysabi::MAX_PATH]; MAX_EXEC_ARGS],
                argv_len: [0; MAX_EXEC_ARGS],
                argc: 0,
                envp: [[0; sysabi::MAX_PATH]; MAX_EXEC_ARGS],
                envp_len: [0; MAX_EXEC_ARGS],
                envc: 0,
            }
        }
    }

    /// Read one page-checked u64 from user memory (the argv/envp
    /// array slots) — the nanosleep idiom, eight bytes wide.
    fn read_user_slot(run: &crate::sched::context::UserRun, va: u64) -> Result<u64, i64> {
        if !validate_user_range(run, va, 8, 8) {
            return Err(-EFAULT);
        }
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let mut v = 0u64;
        for off in 0..8 {
            v |= u64::from(memops::read_u8_va(va + off)) << (8 * off);
        }
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        Ok(v)
    }

    /// The bounded argv/envp read (Phase 6 S3). `argv` must name a
    /// NULL-terminated pointer array; `envp` may be NULL (an empty
    /// environment is legal). Every string rides the SAME page-
    /// checked copy-in as SYS_OPEN's path.
    fn read_exec_args(
        run: &crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        argv: u64,
        envp: u64,
    ) -> Result<ExecArgs, i64> {
        let user_top = 1u64 << 47;
        let mut blk = ExecArgs::zeroed();
        let mut read_table = |base: u64,
                              strs: &mut [[u8; sysabi::MAX_PATH]; MAX_EXEC_ARGS],
                              lens: &mut [usize; MAX_EXEC_ARGS],
                              count: &mut usize|
         -> Result<(), i64> {
            for i in 0..=MAX_EXEC_ARGS {
                let slot = read_user_slot(run, base + 8 * i as u64)?;
                if slot == 0 {
                    *count = i;
                    return Ok(());
                }
                if i == MAX_EXEC_ARGS {
                    return Err(-E2BIG); // the table is not NUL-terminated
                }
                if slot >= user_top {
                    return Err(-EFAULT);
                }
                let len = read_user_path(run, k, slot, &mut strs[i])?;
                lens[i] = len;
            }
            unreachable!("the loop returns at the NULL or the bound")
        };
        read_table(argv, &mut blk.argv, &mut blk.argv_len, &mut blk.argc)?;
        if envp != 0 {
            read_table(envp, &mut blk.envp, &mut blk.envp_len, &mut blk.envc)?;
        }
        Ok(blk)
    }

    /// Build the SysV x86-64 initial stack image (Phase 6 S3): the
    /// VECTOR (argc, argv pointers, NULL, envp pointers, NULL, the
    /// AT_NULL auxv) at the BOTTOM — argc sits at the entry RSP —
    /// then the strings, then padding so the image's last byte lands
    /// at `stack_top - 1` and the entry RSP (the image's base) is
    /// 16-byte aligned. The first draft put the vector at the TOP;
    /// the exec-target's probe caught it live (argc read the pad).
    fn build_initial_stack(
        args: &ExecArgs,
        stack_top: u64,
        img: &mut [u8; EXEC_STACK_IMG],
    ) -> (usize, u64) {
        let mut strings = 0usize;
        for &len in args.argv_len.iter().take(args.argc) {
            strings += len + 1;
        }
        for &len in args.envp_len.iter().take(args.envc) {
            strings += len + 1;
        }
        // argc + argv + NULL + envp + NULL + auxv (AT_NULL alone)
        let vec_len = 8 * (1 + args.argc + 1 + args.envc + 1 + 2);
        let pad = (16 - ((strings + vec_len) % 16)) % 16;
        let total = pad + strings + vec_len;
        debug_assert!(total <= img.len());
        let base = stack_top - total as u64; // the entry rsp: argc here
        let mut off = vec_len;
        let mut argv_ptrs = [0u64; MAX_EXEC_ARGS];
        for (slot, (buf, len)) in argv_ptrs
            .iter_mut()
            .zip(args.argv.iter().zip(args.argv_len.iter()))
            .take(args.argc)
        {
            *slot = base + off as u64;
            img[off..off + *len].copy_from_slice(&buf[..*len]);
            img[off + *len] = 0;
            off += len + 1;
        }
        let mut envp_ptrs = [0u64; MAX_EXEC_ARGS];
        for (slot, (buf, len)) in envp_ptrs
            .iter_mut()
            .zip(args.envp.iter().zip(args.envp_len.iter()))
            .take(args.envc)
        {
            *slot = base + off as u64;
            img[off..off + *len].copy_from_slice(&buf[..*len]);
            img[off + *len] = 0;
            off += len + 1;
        }
        debug_assert_eq!(off, vec_len + strings);
        let mut vec = 0usize;
        fn push_word(img: &mut [u8; EXEC_STACK_IMG], vec: &mut usize, w: u64) {
            img[*vec..*vec + 8].copy_from_slice(&w.to_le_bytes());
            *vec += 8;
        }
        push_word(img, &mut vec, args.argc as u64);
        for &p in argv_ptrs.iter().take(args.argc) {
            push_word(img, &mut vec, p);
        }
        push_word(img, &mut vec, 0); // argv NULL
        for &p in envp_ptrs.iter().take(args.envc) {
            push_word(img, &mut vec, p);
        }
        push_word(img, &mut vec, 0); // envp NULL
        push_word(img, &mut vec, 0); // auxv AT_NULL
        push_word(img, &mut vec, 0);
        debug_assert_eq!(vec, vec_len);
        (total, base)
    }

    /// wait4(2) — ADR-0003 v1 slice 3: the Linux wait lands on the
    /// ADR-0022 D7 core (`wait_process`/`exit_process` were waiting
    /// in the lib since round K; this is the arm that reaches them).
    /// Linux shape: wait4(pid, wstatus*, rusage*, options); the
    /// internal ABI serves the same positions. rusage is accepted
    /// and IGNORED (no accounting yet — documented, not faked). The
    /// blocking path parks with the RE-EXECUTE image (rip-2, rax =
    /// the raw nr): the dispatcher runs the fork-parked child, its
    /// exit wakes the parent through the waiter registry, and the
    /// re-executed arm reaps. Every completed child whose mailbox
    /// entry is consumed HERE gets its full teardown in the arm
    /// (destroy_user FIRST — the exit_process order contract — then
    /// the zombie record), so the spawner's drain never sees it.
    fn sys_wait(
        run: &mut crate::sched::context::UserRun,
        pid: u64,
        wstatus: u64,
        _rusage: u64,
        options: u64,
    ) -> u64 {
        use aegis_os::proc::ProcError as PE;
        let nohang = match crate::wait::decode_options(options) {
            Ok(n) => n,
            Err(e) => return e as u64,
        };
        if wstatus != 0 && !validate_user_write_range(run, wstatus, 4, 4) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        // Reap-ready: consume every completed entry of one of MY
        // children (ids collected first — the children_of borrow ends
        // before the teardown mutates the kernel).
        const MAX_REAPED: usize = 16;
        let mut kids = [None; MAX_REAPED];
        for (slot, m) in kids.iter_mut().zip(k.procs.children_of(run.domain)) {
            *slot = Some(m.pid);
        }
        for child in kids.into_iter().flatten() {
            if let Some(kind) = crate::sched::park::completed_take(child) {
                // The full teardown, in the exit_process contract's
                // order: FRAMES first (the free half of destroy_user —
                // never destroy_domain: the supervisor removal erases
                // the meta the zombie record needs, found live in the
                // slice-3 hunt), then the lib's exit path (teardown +
                // the zombie wait_process reaps). The kernel-side
                // sched bookkeeping already ran at the completion site
                // (every mailbox entry passes dispatch_next).
                if let Some(pool) = context::pool_mut() {
                    crate::mm::user::free_frames_of(k, pool, child);
                }
                let _ = k.exit_process(child, crate::wait::exit_status_of(&kind));
            }
        }
        match k.wait_process(run.domain, pid as i64, nohang) {
            Ok((reaped, st)) => {
                if wstatus != 0 {
                    let word = crate::wait::wstatus_word(&st).to_le_bytes();
                    IN_USER_COPY.store(true, Ordering::SeqCst);
                    if crate::hw::smap_active() {
                        crate::hw::stac();
                    }
                    for (off, b) in word.iter().enumerate() {
                        memops::write_u8_va(wstatus + off as u64, *b);
                    }
                    if crate::hw::smap_active() {
                        crate::hw::clac();
                    }
                    IN_USER_COPY.store(false, Ordering::SeqCst);
                }
                u64::from(reaped)
            }
            // WNOHANG: nothing ready answers 0 — the pid comes later.
            Err(PE::WouldBlock) if nohang => 0,
            Err(PE::WouldBlock) => {
                // The block: register FIRST (a preemption window before
                // the park must find the waiter), leave the ready
                // queue, then park with the re-execute image. A full
                // registry answers EAGAIN — the honest try-again, the
                // same refusal shape as fork's capacity family.
                if !crate::sched::park::waiter_register(run.domain) {
                    return (-sysabi::EAGAIN) as u64;
                }
                let _ = k.sched.set_runnable(run.domain, false);
                crate::sched::park::park_current_reexec()
            }
            Err(PE::NoChildren) | Err(PE::NotAChild(_)) => (-sysabi::ECHILD) as u64,
            Err(PE::UnknownProcess(_)) => (-sysabi::ESRCH) as u64,
            Err(_) => (-EINVAL) as u64,
        }
    }

    /// ipc_send(channel, len) — ADR-0025 D1: the core's capability-
    /// gated async executor (WRITE == send), reached at last from
    /// ring 3. The gate and the organic monitor accounting land in
    /// `dispatch`; the queue's bounded EAGAIN and the cap denial's
    /// -EPERM surface through the sysabi table.
    /// devreg(op, off, len, val, region) — ADR-0017 round two: the
    /// driver domain's register channel, routed to the CALLING
    /// domain's registered core by `run.domain` (the routing IS the
    /// capability — no domain can name another's device). All
    /// device-side validation — width, window, the refusal ladder —
    /// lives in the core (ipc_mmio), where every refusal is counted
    /// for the monitor. The arm's own guard exists so a wide `len`
    /// cannot launder through the u8 cast. Returns the read value, 0
    /// for a served write, u64::MAX for every refusal.
    fn sys_devreg(
        run: &mut crate::sched::context::UserRun,
        op: u64,
        off: u64,
        len: u64,
        val: u64,
        region: u64,
    ) -> u64 {
        if op > 1 || len > 8 || region > 3 {
            return u64::MAX;
        }
        crate::ipc_mmio::devreg_serve(run.domain, region as u8, op as u8, off, len as u8, val)
    }

    fn sys_ipc_send(run: &mut crate::sched::context::UserRun, channel: u64, len: u64) -> u64 {
        if channel > u32::MAX as u64 || len > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let r = match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::IpcSend {
                channel: channel as u32,
                len: len as u32,
            },
        ) {
            Ok(aegis_os::sys::SysValue::Count(n)) => n as u64,
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        };
        // ADR-0026: the push may have rendezvoused with a parked
        // recv_wait owner — patch its image before returning.
        drain_ipc_wakes();
        r
    }

    /// ipc_recv(channel) — ADR-0025 D1: the owner-only drain (READ ==
    /// recv). Returns the popped message's LENGTH (the authenticated
    /// sender rides the endpoint's record, not the return — the
    /// receiver's proof checks the count and the kernel's sender id
    /// through the second data word).
    fn sys_ipc_recv(run: &mut crate::sched::context::UserRun, channel: u64) -> u64 {
        if channel > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::IpcRecv {
                channel: channel as u32,
            },
        ) {
            Ok(aegis_os::sys::SysValue::Count(n)) => n as u64,
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// ADR-0026: apply the core's wake list — each (domain, value)
    /// lands in the parked image's RAX (the layering rule: the core
    /// decides, the kernel applies). Runs after every syscall that
    /// can wake (send, call, reply), BEFORE any park: the woken
    /// owner's image must be patched before the dispatcher can
    /// resume it.
    fn drain_ipc_wakes() {
        while let Some(k) = context::kernel_mut() {
            match k.pop_ipc_wake() {
                Some((dom, val)) => {
                    context::patch_parked_rax(dom, val);
                }
                None => break,
            }
        }
    }

    /// ipc_call(channel, len) — ADR-0026: the sync rendezvous. The
    /// core pushed the message (a parked recv_wait owner takes it
    /// THIS instant — the wake drain runs before the park) and
    /// blocked the caller; the run parks here and the parked image's
    /// RAX is patched when the owner replies. `call` RETURNS the
    /// reply's len.
    fn sys_ipc_call(run: &mut crate::sched::context::UserRun, channel: u64, len: u64) -> u64 {
        if channel > u32::MAX as u64 || len > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::IpcCall {
                channel: channel as u32,
                len: len as u32,
            },
        ) {
            // Unit = "the caller parked; the reply's len arrives via
            // the wake path" (the ADR-0026 contract).
            Ok(aegis_os::sys::SysValue::Unit) => {
                drain_ipc_wakes();
                crate::sched::park::park_current_from_syscall(0)
            }
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// ipc_recv_wait(channel) — ADR-0026: the blocking recv. A
    /// waiting message pops NOW (Count(len), no park — the async
    /// recv verbatim); an empty queue parks the owner until a push
    /// rendezvouses (the push's wake patches the RAX with the len).
    fn sys_ipc_recv_wait(run: &mut crate::sched::context::UserRun, channel: u64) -> u64 {
        if channel > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::IpcRecvWait {
                channel: channel as u32,
            },
        ) {
            Ok(aegis_os::sys::SysValue::Count(n)) => n as u64,
            // Unit = "the queue was empty; parked until a rendezvous".
            Ok(aegis_os::sys::SysValue::Unit) => crate::sched::park::park_current_from_syscall(0),
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// ipc_reply(channel, len) — ADR-0026: the owner answers its
    /// OLDEST waiting caller. The core cleared the waiter and woke
    /// the domain; the drain patches the caller's parked RAX with the
    /// reply len BEFORE this arm returns (the caller could be resumed
    /// on the very next tick).
    fn sys_ipc_reply(run: &mut crate::sched::context::UserRun, channel: u64, len: u64) -> u64 {
        if channel > u32::MAX as u64 || len > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let r = match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::IpcReply {
                channel: channel as u32,
                len: len as u32,
            },
        ) {
            Ok(aegis_os::sys::SysValue::Count(n)) => n as u64,
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        };
        // The reply woke a caller: patch its image now.
        drain_ipc_wakes();
        r
    }

    /// ipc_grant_frames(dst, va, len) — ADR-0027: confer
    /// `[va, va+len)` of the caller's mapped memory on dst, RW-only.
    /// The core validated (the Domain-capability gate, liveness, the
    /// page-granular bound); THIS side walks the granter's tables,
    /// takes the receiver's parked run, maps the frames through the
    /// receiver's OWN policy (quota and overlap apply), and returns
    /// the VA where they landed in the receiver — the address the
    /// caller then passes on through the sync IPC (ADR-0026).
    fn sys_grant_frames(
        run: &mut crate::sched::context::UserRun,
        dst: u64,
        va: u64,
        len: u64,
    ) -> u64 {
        use crate::mm::page_table::{MapError, SharesSource};

        if dst > u32::MAX as u64 || va > u32::MAX as u64 || len > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        // The whole range must live in the user half (a kernel-half
        // grant is nonsense; the granter's tables never map it, but
        // the check is cheap and the refusal explicit).
        if !va.is_multiple_of(4096) || va + len > crate::mm::pte::USER_LIMIT {
            return (-EINVAL) as u64;
        }
        // The core gate: cap + liveness + the bound (host-tested).
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        match k.execute(
            run.domain,
            aegis_os::sys::SysRequest::IpcGrantFrames {
                dst: dst as u32,
                va: va as u32,
                len: len as u32,
            },
        ) {
            Ok(aegis_os::sys::SysValue::Unit) => {}
            Ok(_) => return 0,
            Err(e) => return sysabi::errno_of(&e) as u64,
        }
        // The source walk: every page in the granter's range must be
        // present (a grant of unmapped memory is -EFAULT, mapped
        // nothing, touched nothing).
        let mut pas = [0u64; aegis_os::frame_share::MAX_GRANT_PAGES];
        let pages = (len / 4096) as usize;
        for (i, slot) in pas.iter_mut().enumerate().take(pages) {
            match run.tables.translate(va + (i as u64) * 4096) {
                Some(pa) => *slot = pa,
                None => return (-EFAULT) as u64,
            }
        }
        // The receiver's parked run: take it, map through ITS policy,
        // stash it back — the parked image untouched (a run blocked in
        // recv_wait is as grantable as a runnable one; the PARKED
        // table holds it either way).
        let Some((mut brun, bctx)) = context::take_parked(dst as u32) else {
            // The grantee never entered the world (or already exited):
            // ESRCH — the same truth the core's liveness check speaks.
            return (-sysabi::ESRCH) as u64;
        };
        // K22: the RECEIVER's window floor — its layout, not the
        // granter's (a grant into a service image lands above ITS
        // trampoline).
        let base = match brun
            .space
            .find_free_window(pages * 4096, brun.layout.window_floor() as usize)
        {
            Some(b) => b as u64,
            None => {
                context::stash_parked(brun, bctx);
                return (-ENOMEM) as u64;
            }
        };
        let (Some(pool), Some(k)) = (context::pool_mut(), context::kernel_mut()) else {
            context::stash_parked(brun, bctx);
            return (-ENOMEM) as u64;
        };
        {
            let mut src = SharesSource {
                pool,
                buddy: &mut k.frames,
                owner: dst as u32,
                shares: context::shares_mut(),
            };
            let mut grant = crate::mm::page_table::GrantFrames {
                pas: &pas[..pages],
                owner: run.domain,
                shares: context::shares_mut(),
            };
            let r =
                brun.tables
                    .grant_map(&mut brun.space, base, pages * 4096, &mut grant, &mut src);
            if let Err(e) = r {
                context::stash_parked(brun, bctx);
                return match e {
                    MapError::Policy(_) => (-EINVAL) as u64,
                    MapError::ShareLimit => (-sysabi::EAGAIN) as u64,
                    _ => (-ENOMEM) as u64,
                };
            }
        }
        // The receiver's run goes back EXACTLY as it came — the same
        // image, one more region in its tables and space.
        context::stash_parked(brun, bctx);
        base
    }

    /// pipe_read(channel, buf, len) — ADR-0029: the owner drains its
    /// byte channel by ENDPOINT ID (the cross-domain path: a cap but
    /// no fd). The `sys_read` shape: the executor fills a kernel
    /// buffer once (no double-fetch), the bytes copy out byte-exact
    /// under the blessed SMAP window.
    fn sys_pipe_read(
        run: &mut crate::sched::context::UserRun,
        channel: u64,
        buf: u64,
        len: u64,
    ) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        if channel > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        if len as usize > sysabi::MAX_READ {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len, sysabi::MAX_READ as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let mut kbuf = [0u8; sysabi::MAX_READ];
        match k.execute(
            run.domain,
            SysRequest::PipeRead {
                channel: channel as u32,
                buf: &mut kbuf[..len as usize],
            },
        ) {
            Ok(SysValue::Count(n)) => {
                IN_USER_COPY.store(true, Ordering::SeqCst);
                if crate::hw::smap_active() {
                    crate::hw::stac();
                }
                let wrote = copy_out_bytes(buf, &kbuf[..n], &|va, b| memops::write_u8_va(va, b));
                if crate::hw::smap_active() {
                    crate::hw::clac();
                }
                IN_USER_COPY.store(false, Ordering::SeqCst);
                wrote
            }
            // READ answers Count (short reads, 0 at EOF).
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// pipe_write(channel, buf, len) — ADR-0029: write bytes onto a
    /// byte channel by endpoint id (WRITE cap, the send rules). The
    /// `sys_write_file` shape: copy-in once under the blessed SMAP
    /// window, then the executor; a rendezvous may have woken the
    /// parked owner — patch its image before returning (the
    /// sys_ipc_send rule).
    fn sys_pipe_write(
        run: &mut crate::sched::context::UserRun,
        channel: u64,
        buf: u64,
        len: u64,
    ) -> u64 {
        if channel > u32::MAX as u64 {
            return (-EINVAL) as u64;
        }
        if len as usize > MAX_WRITE {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len, MAX_WRITE as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        let mut kbuf = [0u8; MAX_WRITE];
        let mut pos = 0usize;
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        crate::mm::user_range::copy_user_bytes(buf, len, &memops::read_u8_va, |b| {
            kbuf[pos] = b;
            pos += 1;
        });
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        let r = match k.execute(
            run.domain,
            SysRequest::PipeWrite {
                channel: channel as u32,
                bytes: &kbuf[..len as usize],
            },
        ) {
            Ok(SysValue::Count(n)) => n as u64,
            // WRITE answers Count.
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        };
        // The write may have rendezvoused with a parked owner — the
        // wake must land in its image before this arm returns.
        drain_ipc_wakes();
        r
    }

    /// SYS_NET_SEND(buf, len) — K20 (P0-2), the brokered socket's
    /// data path. The order is the discipline:
    /// 1. the frame bound (EMSGSIZE — a request that can never fit
    ///    any token window is a value error, and burns nothing),
    /// 2. the live session (ENODEV — no NIC behind the broker; checked
    ///    BEFORE the policy gate so a doomed send consumes no tokens),
    /// 3. the user range (EFAULT, fault-reported like every arm),
    /// 4. the POLICY gate on the live kernel (Device cap WRITE + the
    ///    caller's socket + the token bucket — audit, Tighten and
    ///    Quarantine all apply, EACCES/EAGAIN out of `errno_of`),
    /// 5. the data (copy-in once under the blessed SMAP window),
    /// 6. the wire (the netdata session's publish/kick/completion).
    ///
    /// RAX answers the byte count, Linux send(2)-style — the core's
    /// internal `Count` (remaining tokens) is the policy layer's own.
    fn sys_net_send(run: &mut crate::sched::context::UserRun, buf: u64, len: u64) -> u64 {
        use aegis_os::net::MAX_NET_FRAME_BYTES;
        if len > MAX_NET_FRAME_BYTES as u64 {
            return (-EMSGSIZE) as u64;
        }
        if len == 0 {
            return 0; // nothing to move, nothing to charge
        }
        if !crate::drvstack::netdata::armed() {
            return (-ENODEV) as u64;
        }
        if !validate_user_range(run, buf, len, MAX_NET_FRAME_BYTES as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        if let Err(e) = k.execute(run.domain, SysRequest::NetSend { len: len as u32 }) {
            return sysabi::errno_of(&e) as u64;
        }
        // The data: read the user bytes ONCE into a kernel buffer.
        let mut kbuf = [0u8; MAX_NET_FRAME_BYTES as usize];
        let mut pos = 0usize;
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        crate::mm::user_range::copy_user_bytes(buf, len, &memops::read_u8_va, |b| {
            kbuf[pos] = b;
            pos += 1;
        });
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        match crate::drvstack::netdata::send(&kbuf[..len as usize]) {
            Some(n) => n as u64,
            // Armed but the completion stalled: loud, never silent.
            None => (-sysabi::EIO) as u64,
        }
    }

    /// SYS_NET_RECV(buf, len) — the receive half. Same order: the
    /// session (ENODEV), the user range (EFAULT), the POLICY gate
    /// (Device cap READ + the caller's socket — EACCES/EBADF), then
    /// the data: a bounded poll of the RX used ring; nothing ready is
    /// EAGAIN (the module's non-blocking flavor, never a park), a
    /// completed frame copies out byte-exact and the buffer re-arms
    /// for the next packet. The actual byte count is accounted on the
    /// socket through the supervisor callback (`net_recv_account`) —
    /// the policy gate admitted the REQUEST, this is the truth.
    /// RAX answers the copied count; a frame longer than the buffer
    /// truncates like read(2) on a datagram (min semantics).
    fn sys_net_recv(run: &mut crate::sched::context::UserRun, buf: u64, len: u64) -> u64 {
        use aegis_os::net::MAX_NET_FRAME_BYTES;
        if len == 0 {
            return (-EINVAL) as u64;
        }
        if !crate::drvstack::netdata::armed() {
            return (-ENODEV) as u64;
        }
        if !validate_user_range(run, buf, len, MAX_NET_FRAME_BYTES as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let Some(k) = context::kernel_mut() else {
            return (-EPERM) as u64;
        };
        if let Err(e) = k.execute(run.domain, SysRequest::NetRecv { len: len as u32 }) {
            return sysabi::errno_of(&e) as u64;
        }
        let mut kbuf = [0u8; MAX_NET_FRAME_BYTES as usize];
        let Some(n) = crate::drvstack::netdata::recv(&mut kbuf) else {
            return (-sysabi::EAGAIN) as u64;
        };
        // The policy half's honest accounting: the ACTUAL count.
        k.net_recv_account(run.domain, n as u32);
        // K20 (P0-2): the copy-out rides the page's PHYSICAL mapping,
        // translated through the CALLER's own tables — the same frame
        // the VA store would reach (the range was validated above; the
        // bytes are read ONCE, from kbuf — no double-fetch). The
        // direct VA-store path measurably loses whole-frame writes in
        // the driver-stack phase while working in the M3/TTY context —
        // the arm-time snapshot plus the verifier's page read pin the
        // divergence; the AC-flag/SMAP interaction is the documented
        // open question (vnet.rs).
        let page = buf & !0xFFF;
        let in_page = buf & 0xFFF;
        let Some(pa) = run.tables.translate(page) else {
            return (-EFAULT) as u64;
        };
        for (off, b) in kbuf.iter().enumerate().take(n) {
            crate::virtio::write_u8_pa(pa + in_page + off as u64, *b);
        }
        // K20 debug: the copy target + the immediate read-back — if
        // the read-back sees the byte but the verifier later does
        // not, the page was rewritten in between; if the read-back is
        // already wrong, the translate or the write is.
        let readback = if n > 42 {
            crate::virtio::read_u8_pa(pa + in_page + 42)
        } else {
            0
        };
        // K20 debug: the SAME byte through the USER VA, under the
        // blessed SMAP window, at arm time.
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        let va_readback = if n > 42 {
            memops::read_u8_va(buf + 42)
        } else {
            0
        };
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        crate::drvstack::netdata::snapshot_target(pa, readback, va_readback);
        // K20 (P0-2): the arm-time truth — the frame as received.
        crate::drvstack::netdata::snapshot(&kbuf[..n]);
        n as u64
    }

    /// SYS_READ(fd, buf, len): the executor fills a KERNEL buffer
    /// (no double-fetch: the user pointer is read once, for the
    /// validation, and never again), then the bytes copy OUT
    /// byte-exact under the blessed SMAP window.
    fn sys_read(
        run: &mut crate::sched::context::UserRun,
        k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
        fd: u64,
        buf: u64,
        len: u64,
    ) -> u64 {
        use crate::mm::user_range::copy_out_bytes;
        use aegis_os::sys::SysRequest;
        if len as usize > sysabi::MAX_READ {
            return (-EINVAL) as u64;
        }
        if !validate_user_range(run, buf, len, sysabi::MAX_READ as u64) {
            let _ = k.report_fault(run.domain);
            return (-EFAULT) as u64;
        }
        // Phase 7: fd 0 is the TTY's console-in alias exactly while
        // the fd table holds it Reserved (the spawn-time stdio
        // triplet) — the read-side twin of SYS_WRITE's fd-1 alias. A
        // closed or replaced fd 0 routes into the live lib executor.
        let console_in = fd == 0
            && match k.domain_mut(run.domain) {
                Ok(d) => {
                    matches!(d.fds.get(0), Some(e) if e.target == aegis_os::fd::FdTarget::Reserved)
                }
                Err(_) => false,
            };
        if console_in {
            return sys_read_console(run, buf, len);
        }
        let fd = match fd_arg(fd) {
            Ok(fd) => fd,
            Err(e) => return e as u64,
        };
        let mut kbuf = [0u8; sysabi::MAX_READ];
        match k.execute(
            run.domain,
            SysRequest::Read {
                fd,
                buf: &mut kbuf[..len as usize],
            },
        ) {
            Ok(aegis_os::sys::SysValue::Count(n)) => {
                IN_USER_COPY.store(true, Ordering::SeqCst);
                if crate::hw::smap_active() {
                    crate::hw::stac();
                }
                let wrote = copy_out_bytes(buf, &kbuf[..n], &|va, b| memops::write_u8_va(va, b));
                if crate::hw::smap_active() {
                    crate::hw::clac();
                }
                IN_USER_COPY.store(false, Ordering::SeqCst);
                wrote
            }
            // READ always answers Count (short reads, 0 at EOF).
            Ok(_) => 0,
            Err(e) => sysabi::errno_of(&e) as u64,
        }
    }

    /// SYS_WRITE(fd, buf, len) — Round J: the full target set. fd 1 is
    /// the runtime's CONSOLE device alias exactly while the lib's fd
    /// table holds that slot Reserved (the spawn-time stdio triplet):
    /// the device path serves it without the fd table. Any other fd —
    /// or a fd 1 the domain closed/replaced — routes into the LIVE lib
    /// executor (files, pipe write ends), the same path a Unix write
    /// takes.
    fn sys_write(run: &mut crate::sched::context::UserRun, fd: u64, buf: u64, len: u64) -> u64 {
        use aegis_os::fd::FdTarget;
        if len as usize > MAX_WRITE {
            return (-EINVAL) as u64;
        }
        let console_alias = fd == 1
            && match context::kernel_mut() {
                Some(k) => match k.domain_mut(run.domain) {
                    Ok(d) => matches!(d.fds.get(1), Some(e) if e.target == FdTarget::Reserved),
                    Err(_) => false,
                },
                None => true, // no lib kernel: the PR-1.4 behavior
            };
        if console_alias {
            return sys_write_console(run, buf, len);
        }
        sys_write_file(run, fd, buf, len)
    }

    /// The console device path (PR-1.4's sys_write, unchanged): every
    /// page of the buffer must be a *user* page of this domain; the
    /// copy is byte-exact to the serial console under the blessed SMAP
    /// window.
    fn sys_write_console(run: &mut crate::sched::context::UserRun, buf: u64, len: u64) -> u64 {
        if !validate_user_range(run, buf, len, MAX_WRITE as u64) {
            // N2: a failed user-pointer validation is an organic fault
            // signal on the live domain (the exact feed the rogue
            // blob's crossing writes exercise).
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        // copy_from_user (N1, ADR-0007 §1): byte-exact — the copy span
        // equals the validated span by construction, so it cannot
        // fault. IN_USER_COPY is armed so that if this invariant ever
        // breaks, the fault is named, not billed to the user.
        IN_USER_COPY.store(true, Ordering::SeqCst);
        // N4 (ADR-0008): the single blessed SMAP window — the copy
        // reads user pages from CPL0, so it runs under STAC/CLAC when
        // (and only when) the CPU has SMAP.
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        // Phase 4 (the text console): the USER's console output
        // mirrors to the framebuffer text plane (the user's screen)
        // alongside the serial — a no-op before console::init named
        // the plane. The kernel's own log stays serial-only (the
        // console is the user's screen, not a second copy of the
        // boot log — and mirroring the log would add hundreds of
        // scrolls to every boot).
        let sink = |b: u8| {
            serial::write_byte(b);
            crate::drvstack::console::write_byte(b);
        };
        let written = crate::mm::user_range::copy_user_bytes(buf, len, &memops::read_u8_va, sink);
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        run.write_bytes += written;
        written
    }

    /// The file/pipe path (Round J): copy-IN byte-exact to a kernel
    /// buffer, then the LIVE lib executor — files write at the fd's
    /// cursor, pipes through the bounded ring, refusals keep their
    /// errno identities.
    fn sys_write_file(
        run: &mut crate::sched::context::UserRun,
        fd: u64,
        buf: u64,
        len: u64,
    ) -> u64 {
        use aegis_os::sys::{SysRequest, SysValue};
        if !validate_user_range(run, buf, len, MAX_WRITE as u64) {
            if let Some(k) = context::kernel_mut() {
                let _ = k.report_fault(run.domain);
            }
            return (-EFAULT) as u64;
        }
        let fd = match fd_arg(fd) {
            Ok(fd) => fd,
            Err(e) => return e as u64,
        };
        let mut kbuf = [0u8; MAX_WRITE];
        let mut pos = 0usize;
        IN_USER_COPY.store(true, Ordering::SeqCst);
        if crate::hw::smap_active() {
            crate::hw::stac();
        }
        crate::mm::user_range::copy_user_bytes(buf, len, &memops::read_u8_va, |b| {
            kbuf[pos] = b;
            pos += 1;
        });
        if crate::hw::smap_active() {
            crate::hw::clac();
        }
        IN_USER_COPY.store(false, Ordering::SeqCst);
        match context::kernel_mut() {
            Some(k) => match k.execute(
                run.domain,
                SysRequest::Write {
                    fd,
                    bytes: &kbuf[..len as usize],
                },
            ) {
                Ok(SysValue::Count(n)) => {
                    run.write_bytes += n as u64;
                    n as u64
                }
                // WRITE answers Count.
                Ok(_) => 0,
                Err(e) => sysabi::errno_of(&e) as u64,
            },
            None => (-ENOSYS) as u64,
        }
    }

    /// Every page overlapping [buf, buf+len): present, U set, and the
    /// whole range inside the user half. The walk uses the domain's own
    /// tables — the same tables its CR3 points at. `max` is the
    /// syscall's own bound (MAX_WRITE / MAX_READ — both 256 today, but
    /// the seam is explicit).
    /// The write-target twin: present, U, AND W — a write through
    /// the kernel's direct window cannot take the CoW path the user's
    /// own store would (a fork-shared page is read-only in BOTH
    /// tables until the fault services the copy; a CPL0 fault on it
    /// is a kernel bug by ADR-0007, so the ARM refuses -EFAULT
    /// instead — found live by the wait4 slice: the blob's wstatus
    /// sat on the CoW-shared data page and the write faulted loudly).
    /// A careful program passes a private page (the blob mmaps one
    /// post-fork); Linux would service the CoW for put_user — our
    /// discipline is the loud refusal, documented in ABI-VERSION.
    fn validate_user_write_range(
        run: &crate::sched::context::UserRun,
        buf: u64,
        len: u64,
        max: u64,
    ) -> bool {
        crate::mm::user_range::validate_range(
            buf,
            len,
            max,
            pte::USER_LIMIT,
            pte::PAGE_SIZE_U64,
            &|va| match run.tables.pte_of(va) {
                Some(e) => e & pte::PTE_U != 0 && e & pte::PTE_P != 0 && e & pte::PTE_W != 0,
                None => false,
            },
        )
    }

    fn validate_user_range(
        run: &crate::sched::context::UserRun,
        buf: u64,
        len: u64,
        max: u64,
    ) -> bool {
        // N1 (ADR-0007 §1): the arithmetic lives in the pure, host-
        // tested mm::user_range; this adapter only walks the domain's
        // own tables (the same tables its CR3 points at).
        crate::mm::user_range::validate_range(
            buf,
            len,
            max,
            pte::USER_LIMIT,
            pte::PAGE_SIZE_U64,
            &|va| match run.tables.pte_of(va) {
                Some(e) => e & pte::PTE_U != 0 && e & pte::PTE_P != 0,
                None => false,
            },
        )
    }

    fn log_denied(domain: u32, nr: u64, why: &str, errno: i64) {
        let mut bd = [0u8; 20];
        let mut bn = [0u8; 20];
        let mut be = [0u8; 20];
        serial::write_str("[SYSC] domain ");
        serial::write_str(strutil::dec(domain as u64, &mut bd));
        serial::write_str(" nr=");
        serial::write_str(strutil::dec(nr, &mut bn));
        serial::write_str(" ");
        serial::write_str(why);
        serial::write_str(" -> ");
        serial::write_str(strutil::dec(errno as u64, &mut be));
        serial::write_str(" (audited)\n");
    }
}

#[cfg(not(test))]
pub use exec::syscall_dispatch;
