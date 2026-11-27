//! Syscall numbering and the attenuation-only syscall mask.
//!
//! Design rules:
//! - The fast-path membership test (`is_allowed`) is a single AND + bit test:
//!   O(1), branch-free, no allocation. This is the deterministic fast path
//!   every syscall entry point hits before any analysis runs.
//! - Masks can only ever *shrink* at runtime (`attenuate` = intersection,
//!   `try_narrow_to` rejects any derivation that would add a bit). There is
//!   no code path in the kernel that widens a live domain's mask.

use crate::domain::Decision;

/// ADR-0003 (v1): which ABI a domain speaks AT THE ENTRY. The
/// internal ids stay the policy space; the flag only picks the
/// NUMBER TRANSLATION — `Internal` keeps the v0.4 hybrid surface
/// (the six legacy Linux nrs translate, everything else is the raw
/// internal number), `Linux` is the v1 whitelist below.
///
/// The flag is not a security boundary: translation changes which
/// NUMBERS reach the gate, never which OPS the mask allows — the
/// gate runs on internal ids after translation either way.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Abi {
    /// v0.4: the blobs' internal surface (legacy translations + raw
    /// internal nrs).
    #[default]
    Internal,
    /// v1: Linux x86_64 numbers, translated through the whitelist
    /// before the bounds check and the policy gate.
    Linux,
}

/// ADR-0003 (v1): the Linux x86_64 number table — a WHITELIST, not a
/// pass-through. Every nr below maps to an internal op with an
/// IDENTICAL register/return shape; every OTHER nr — including nrs
/// < 64 that collide with internal ops — answers `-ENOSYS` at the
/// entry (Linux 63 is uname, internal 63 is EXIT: a pass-through
/// would make a Linux binary's uname() call exit the process).
///
/// Deliberately NOT mapped (slice 1):
/// - `open` (2): Linux's O_* encoding (O_RDONLY=0, O_CREAT=0x40)
///   differs from the internal O_READ=0x1 family — it lands with the
///   filesystem round, not mistranslated today.
/// - `wait4` (61), `execve` (59), `dup` (32), `pipe2` (293): no ABI
///   arm yet.
pub fn linux_nr_to_core(nr: u64) -> Option<u64> {
    match nr {
        0 => Some(SYS_READ as u64),            // read(2)
        2 => Some(SYS_OPEN as u64),            // open(2) — O_* translated, not passed through
        1 => Some(SYS_WRITE as u64),           // write(2)
        3 => Some(SYS_CLOSE as u64),           // close(2)
        9 => Some(SYS_MMAP as u64),            // mmap(2) — ANON|PRIVATE only
        11 => Some(SYS_MUNMAP as u64),         // munmap(2)
        13 => Some(SYS_SIGACTION as u64),      // rt_sigaction(2)
        15 => Some(SYS_SIGRETURN as u64),      // rt_sigreturn(2)
        22 => Some(SYS_PIPE as u64),           // pipe(2) — rax/rdx split
        24 => Some(SYS_SCHED_YIELD as u64),    // sched_yield(2)
        33 => Some(SYS_DUP as u64),            // dup2(2)
        35 => Some(SYS_NANOSLEEP as u64),      // nanosleep(2)
        57 => Some(SYS_FORK as u64),           // fork(2)
        59 => Some(SYS_EXEC as u64),           // execve(2) — replaces the image (slice 4)
        61 => Some(SYS_WAIT as u64),           // wait4(2) — blocks via the rip-2 re-execute park
        60 => Some(SYS_EXIT as u64),           // exit(2)
        62 => Some(SYS_KILL as u64),           // kill(2)
        228 => Some(SYS_CLOCK_GETTIME as u64), // clock_gettime(2)
        231 => Some(SYS_EXIT as u64),          // exit_group(2) — the alias
        83 => Some(SYS_MKDIR as u64),          // mkdir(2) — the Phase-6 ring-3 arm
        87 => Some(SYS_UNLINK as u64),         // unlink(2) — unlink+rmdir folded, errno-exact
        82 => Some(SYS_RENAME as u64),         // rename(2) — K21: the PM's commit primitive
        264 => Some(SYS_RENAME as u64),        // renameat(2) — the dirfd-prefixed alias
        262 => Some(SYS_STAT as u64),          // newfstatat(2) — K21; old stat(4)/fstat(5) stay
        // unmapped (the subset speaks the modern arm)
        161 => Some(SYS_CHROOT as u64), // chroot(2) — the cwd moves with the root
        259 => Some(SYS_LISTDIR as u64), // getdents64(2) — names NUL-separated, count returned
        _ => None,                      // the whitelist's edge
    }
}

/// Read from a file/object.
pub const SYS_READ: u8 = 0;
/// Write to a file/object.
pub const SYS_WRITE: u8 = 1;
/// Open a path (mediated by capabilities in a real kernel).
pub const SYS_OPEN: u8 = 2;
/// Close an open handle.
pub const SYS_CLOSE: u8 = 3;
/// Map memory into the domain's address space.
pub const SYS_MMAP: u8 = 4;
/// Unmap memory.
pub const SYS_MUNMAP: u8 = 5;
/// Spawn a child domain.
pub const SYS_SPAWN: u8 = 6;
/// Send an IPC message.
pub const SYS_IPC_SEND: u8 = 7;
/// Receive an IPC message.
pub const SYS_IPC_RECV: u8 = 8;
/// Send network data (brokered).
pub const SYS_NET_SEND: u8 = 9;
/// Receive network data (brokered).
pub const SYS_NET_RECV: u8 = 10;
/// Device control.
pub const SYS_IOCTL: u8 = 11;
/// Create an anonymous pipe (Linux-like extension).
pub const SYS_PIPE: u8 = 12;
/// Duplicate a file descriptor onto a target index (dup2 semantics).
pub const SYS_DUP: u8 = 13;
/// Send a signal to another domain (kill(2)-like).
pub const SYS_KILL: u8 = 14;
/// Change the root directory of this domain (chroot(2)-like).
pub const SYS_CHROOT: u8 = 15;
/// Create a directory (mkdir(2)).
pub const SYS_MKDIR: u8 = 16;
/// Remove a file / empty directory (unlink(2) + rmdir(2)).
pub const SYS_UNLINK: u8 = 17;
/// Create a child process as a copy of the caller (fork(2)-like;
/// ADR-0022 — the child is born a subset of the parent's live state).
pub const SYS_FORK: u8 = 18;
/// Replace the caller's image (execve(2)-like; ADR-0022 — the live
/// surface only ever INTERSECTS with the declared one).
pub const SYS_EXEC: u8 = 19;
/// Wait for a child and reap its exit status (wait4(2)-like).
pub const SYS_WAIT: u8 = 20;
/// Sleep for a span of core time units (nanosleep(2)-like; ADR-0023 —
/// the ABI layer converts ns to the kernel's time base).
pub const SYS_NANOSLEEP: u8 = 21;
/// Volunteer the rest of the current slice (sched_yield(2)-like).
pub const SYS_SCHED_YIELD: u8 = 22;
/// Read a clock (clock_gettime(2)-like; ADR-0023 — the GATE lives in
/// the core, the execution is kernel-side math over the calibrated
/// TSC: the core has no clock of its own).
pub const SYS_CLOCK_GETTIME: u8 = 23;
/// Install a caught-signal disposition (rt_sigaction(2)-like;
/// ADR-0023 D8).
pub const SYS_SIGACTION: u8 = 25;
/// Return from a signal handler (rt_sigreturn(2)-like; ADR-0023 D8).
/// NOT gate-masked: like SYSRET itself, it is entry machinery the
/// kernel invoked (the authority was exercised at sigaction and
/// delivery time); the kernel-side ABI layer handles it before the
/// policy gate and re-validates every frame field against its own
/// delivery record.
pub const SYS_SIGRETURN: u8 = 24;
/// ADR-0026: the sync IPC rendezvous (internal nrs; the Linux
/// renumbering lands with Phase 5's ABI-VERSION table, like the
/// async pair at 7/8).
pub const SYS_IPC_CALL: u8 = 26;
/// ipc_recv_wait(2): the blocking recv — pop now if a message waits,
/// park the owner until one arrives.
pub const SYS_IPC_RECV_WAIT: u8 = 27;
/// ipc_reply(2): the owner answers its oldest waiting caller; the
/// caller's blocked call returns the reply len.
pub const SYS_IPC_REPLY: u8 = 28;
/// ADR-0027: ipc_grant_frames(dst, va, len) — confer MY mapped pages
/// on dst, RW-only, through the receiver's own policy (quota and
/// overlap apply); the return is the VA where they landed in dst.
pub const SYS_IPC_GRANT: u8 = 29;
/// ADR-0029: pipe_read(channel, buf, len) — the OWNER drains its byte
/// channel by endpoint id (READ cap + owner, the recv rules). Short
/// read; 0 at EOF; -EAGAIN empty. Internal nr (Linux 30 is shmat —
/// the ABI-VERSION v0.4 collision table).
pub const SYS_PIPE_READ: u8 = 30;
/// ADR-0029: pipe_write(channel, buf, len) — write bytes onto a byte
/// channel by endpoint id (WRITE cap, the send rules). Short write;
/// -EPIPE after the read end closes; -EAGAIN full. Internal nr
/// (Linux 31 is shmctl).
pub const SYS_PIPE_WRITE: u8 = 31;
/// Reserved: domain exit. Always reachable; a mask without it is rejected
/// by convention (see `profile` tests).
/// list_dir(fd, buf): a directory's children as NUL-separated names.
/// v1 maps getdents64(259) here — the documented subset semantics:
/// names + count, not dirent64 structs.
pub const SYS_LISTDIR: u8 = 32;

/// devreg(op, off, len, val, region) — ADR-0017's ring-3 driver
/// channel: ONE device-register access as a message, routed to the
/// CALLING domain's registered core (the routing is the capability —
/// no domain can name another's device). `op`: 0=read, 1=write;
/// `region` 0..3 selects one of the domain's registered windows
/// (common/notify/isr/device-config for virtio); the core
/// window-checks the offset and width itself, counts what it serves
/// and refuses, and after enough refusals stops serving the channel
/// (the quarantine). The read returns the register value; a served
/// write returns 0; every refusal is `u64::MAX` (no plausible
/// register value on this bus family). Internal nr only — not a
/// Linux ABI number.
pub const SYS_DEVREG: u8 = 33;

/// stat(2)-like: metadata of a path without opening it. The executor
/// fills a 24-byte user struct — kind u8 @0 (0 file, 1 dir, 3 other;
/// this VFS has no symlinks), size u64 LE @8, perm u16 LE @16
/// (0o777). K21: the package manager's destination-parent walks.
pub const SYS_STAT: u8 = 34;
/// rename(2)-like: the atomic re-parent (the package manager's
/// commit step). WRITE caps on BOTH parents; a file destination is
/// replaced; a directory destination is refused; the inode keeps its
/// identity (same id + generation). K21.
///
/// K22: 35 was unreachable from ring 3 — the entry's internal-mode
/// hybrid table maps Linux nr 35 (nanosleep(2), which the ADR-0023
/// sleeper blobs legitimately call) onto SYS_NANOSLEEP, so an
/// internal-ABI domain's `SYS_RENAME` call was ALWAYS hijacked into a
/// masked nanosleep (found live: the in-VM manager's commit rename
/// answered EPERM dressed as EACCES). 36 has no collision; the
/// rename(2)/renameat(2) Linux whitelist entries follow this const.
pub const SYS_RENAME: u8 = 36;

pub const SYS_EXIT: u8 = 63;

/// Number of syscall slots (mask width).
pub const SYSCALL_COUNT: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskError {
    /// Syscall id outside `0..SYSCALL_COUNT`.
    UnknownSyscall(u8),
    /// Attempted to derive a mask that adds bits (forbidden: attenuation only).
    WidenForbidden,
}

/// Bitset over the 64 syscall slots. `Copy`, no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyscallMask {
    bits: u64,
}

impl SyscallMask {
    /// Mask that permits nothing.
    pub const NONE: SyscallMask = SyscallMask { bits: 0 };
    /// Mask that permits everything (profile-construction time only).
    pub const ALL: SyscallMask = SyscallMask { bits: u64::MAX };

    /// Wrap a raw bitset (const-constructible for profile definitions).
    pub const fn from_bits(bits: u64) -> Self {
        SyscallMask { bits }
    }

    /// Union of two masks. Only used when *building* profiles; never on live masks.
    pub const fn union(self, other: SyscallMask) -> SyscallMask {
        SyscallMask {
            bits: self.bits | other.bits,
        }
    }

    /// Build from syscall ids. Fails on any id >= `SYSCALL_COUNT`.
    pub fn from_ids(ids: &[u8]) -> Result<Self, MaskError> {
        let mut m = Self::NONE;
        for &id in ids {
            m.allow(id)?;
        }
        Ok(m)
    }

    /// Set one bit (profile construction only; not exposed to live domains).
    pub fn allow(&mut self, id: u8) -> Result<(), MaskError> {
        if id >= SYSCALL_COUNT {
            return Err(MaskError::UnknownSyscall(id));
        }
        self.bits |= 1u64 << id;
        Ok(())
    }

    /// Fast-path check: O(1) AND + bit test. Errors on unknown ids.
    pub fn is_allowed(&self, id: u8) -> Result<bool, MaskError> {
        if id >= SYSCALL_COUNT {
            return Err(MaskError::UnknownSyscall(id));
        }
        Ok(self.bits & (1u64 << id) != 0)
    }

    /// Attenuation: intersection with a tighter mask. The *only* mutation
    /// applied to live domain masks. Monotonic by construction.
    #[must_use]
    pub fn attenuate(&self, tighter: &SyscallMask) -> SyscallMask {
        SyscallMask {
            bits: self.bits & tighter.bits,
        }
    }

    /// Derive `other` from `self`; succeeds only if `other` adds no bits.
    /// This is the capability-style derivation check used at grant time.
    pub fn try_narrow_to(&self, other: &SyscallMask) -> Result<SyscallMask, MaskError> {
        if other.bits & !self.bits != 0 {
            return Err(MaskError::WidenForbidden);
        }
        Ok(*other)
    }

    #[must_use]
    pub fn is_subset_of(&self, other: &SyscallMask) -> bool {
        self.bits & !other.bits == 0
    }

    /// Number of permitted syscalls (popcount).
    #[must_use]
    pub fn count(&self) -> u32 {
        self.bits.count_ones()
    }

    /// Raw bitset (for hashing/telemetry).
    #[must_use]
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// K23 (observability): the permitted syscall ids as a
    /// comma-separated decimal list, written into `buf` — the mask as
    /// a SET, the shape the completed-exit markers print (a live mask
    /// is accounting state; this only READS it, no bit ever moves).
    /// Ascending id order; an empty mask writes the empty string.
    /// PURE, no allocation: the caller owns the buffer. Ids are
    /// `< SYSCALL_COUNT = 64`, so two digits bound every id and
    /// `64×2 + 63` commas = 191 bytes bound every mask; a short
    /// buffer truncates (never panics — telemetry must not kill the
    /// boot).
    pub fn arm_ids_csv<'a>(&self, buf: &'a mut [u8]) -> &'a str {
        /// Write one id (0..64 — at most two digits) as decimal into
        /// `out`; the byte count written (0 when `out` is too short).
        fn write_id(id: u8, out: &mut [u8]) -> usize {
            let len = if id >= 10 { 2 } else { 1 };
            if out.len() < len {
                return 0;
            }
            out[0] = b'0' + id % 10;
            if len == 2 {
                out[1] = out[0];
                out[0] = b'0' + id / 10;
            }
            len
        }
        let mut n = 0usize;
        for id in 0..SYSCALL_COUNT {
            if self.bits & (1u64 << id) == 0 {
                continue;
            }
            if n > 0 {
                if n >= buf.len() {
                    break;
                }
                buf[n] = b',';
                n += 1;
            }
            let w = write_id(id, &mut buf[n..]);
            if w == 0 {
                break;
            }
            n += w;
        }
        // Every byte above is ASCII by construction; the unwrap_or
        // only guards a buffer that shrank between the write and the
        // read (impossible — same borrow).
        core::str::from_utf8(&buf[..n]).unwrap_or("")
    }
}

/// The pure syscall gate (PR-1.4): the decision every caller gets, with
/// no accounting. Extracted verbatim from `Domain::request_syscall` so
/// kernel-resident domains and Ring-3 domains (whose hardware context
/// lives outside the lib) run **the same gate code** — one policy, two
/// execution sites.
///
/// Order matters and is load-bearing: unknown ids are bad before any
/// state check; a quarantined domain may only ever EXIT; the mask is
/// consulted last. `Domain::request_syscall` layers its behavioral
/// accounting on top of exactly this decision.
pub fn gate(mask: &SyscallMask, quarantined: bool, id: u8) -> Decision {
    if id >= SYSCALL_COUNT {
        return Decision::BadSyscall(id);
    }
    if quarantined {
        if id == SYS_EXIT {
            return Decision::Allowed;
        }
        return Decision::DeniedQuarantined(id);
    }
    if !mask.is_allowed(id).unwrap_or(false) {
        return Decision::DeniedByMask(id);
    }
    Decision::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_allows_nothing_and_all_counts_64() {
        let none = SyscallMask::NONE;
        for id in 0u8..SYSCALL_COUNT {
            assert_eq!(none.is_allowed(id), Ok(false));
        }
        assert_eq!(SyscallMask::ALL.count(), 64);
        assert_eq!(SyscallMask::NONE.count(), 0);
    }

    #[test]
    fn boundary_id_63_is_addressable() {
        let mut m = SyscallMask::NONE;
        m.allow(63).unwrap();
        assert_eq!(m.is_allowed(63), Ok(true));
        assert_eq!(m.is_allowed(62), Ok(false));
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn from_ids_rejects_out_of_range_ids() {
        assert!(SyscallMask::from_ids(&[SYS_READ, SYS_WRITE]).is_ok());
        assert_eq!(
            SyscallMask::from_ids(&[64]),
            Err(MaskError::UnknownSyscall(64))
        );
        assert_eq!(
            SyscallMask::from_ids(&[SYS_READ, 255]),
            Err(MaskError::UnknownSyscall(255))
        );
    }

    #[test]
    fn is_allowed_rejects_out_of_range_ids() {
        assert_eq!(
            SyscallMask::ALL.is_allowed(64),
            Err(MaskError::UnknownSyscall(64))
        );
        assert_eq!(
            SyscallMask::ALL.is_allowed(200),
            Err(MaskError::UnknownSyscall(200))
        );
    }

    #[test]
    fn attenuate_only_shrinks_and_is_idempotent() {
        let service = SyscallMask::from_ids(&[SYS_READ, SYS_WRITE, SYS_OPEN, SYS_CLOSE]).unwrap();
        let tighter = SyscallMask::from_ids(&[SYS_READ]).unwrap();

        let once = service.attenuate(&tighter);
        assert!(once.is_subset_of(&service));
        assert_eq!(once.count(), 1);

        let twice = once.attenuate(&tighter);
        assert_eq!(twice, once, "attenuation must be idempotent");
    }

    #[test]
    fn attenuate_to_none_is_sticky() {
        let m = SyscallMask::from_ids(&[SYS_READ, SYS_WRITE]).unwrap();
        let dead = m.attenuate(&SyscallMask::NONE);
        assert_eq!(dead, SyscallMask::NONE);
        // Any further attenuation stays empty.
        assert_eq!(dead.attenuate(&SyscallMask::ALL), SyscallMask::NONE);
    }

    #[test]
    fn try_narrow_to_rejects_any_widening() {
        let small = SyscallMask::from_ids(&[SYS_READ]).unwrap();
        let bigger = SyscallMask::from_ids(&[SYS_READ, SYS_WRITE]).unwrap();

        assert_eq!(small.try_narrow_to(&bigger), Err(MaskError::WidenForbidden));
        assert_eq!(small.try_narrow_to(&small), Ok(small));
        assert_eq!(
            small.try_narrow_to(&SyscallMask::NONE),
            Ok(SyscallMask::NONE)
        );
        assert_eq!(
            SyscallMask::NONE.try_narrow_to(&SyscallMask::ALL),
            Err(MaskError::WidenForbidden)
        );
    }

    #[test]
    fn subset_lattice_behaves() {
        let none = SyscallMask::NONE;
        let a = SyscallMask::from_ids(&[SYS_READ]).unwrap();
        let ab = SyscallMask::from_ids(&[SYS_READ, SYS_WRITE]).unwrap();
        let all = SyscallMask::ALL;

        assert!(none.is_subset_of(&a) && a.is_subset_of(&ab) && ab.is_subset_of(&all));
        assert!(!ab.is_subset_of(&a));
        assert!(!all.is_subset_of(&ab));
    }

    #[test]
    fn union_is_construction_only_commutative() {
        let a = SyscallMask::from_ids(&[SYS_READ]).unwrap();
        let b = SyscallMask::from_ids(&[SYS_WRITE]).unwrap();
        assert_eq!(a.union(b), b.union(a));
        assert_eq!(a.union(b).count(), 2);
    }

    #[test]
    fn raw_bits_roundtrip() {
        let m = SyscallMask::from_ids(&[SYS_EXIT]).unwrap();
        assert_eq!(m.bits(), 1u64 << SYS_EXIT);
        assert_eq!(SyscallMask::from_bits(m.bits()), m);
    }

    #[test]
    fn arm_ids_csv_lists_the_set_in_id_order() {
        // Empty mask: empty string, not a stray comma.
        let mut buf = [0u8; 192];
        assert_eq!(SyscallMask::NONE.arm_ids_csv(&mut buf), "");
        // One id, two-digit ids, and non-contiguous ids all round-trip.
        let one = SyscallMask::from_ids(&[SYS_MKDIR]).unwrap();
        assert_eq!(one.arm_ids_csv(&mut buf), "16");
        let two_digit = SyscallMask::from_ids(&[SYS_RENAME, SYS_EXIT]).unwrap();
        assert_eq!(two_digit.arm_ids_csv(&mut buf), "36,63");
        let wide = SyscallMask::from_ids(&[SYS_READ, SYS_WRITE, SYS_OPEN, SYS_CLOSE]).unwrap();
        assert_eq!(wide.arm_ids_csv(&mut buf), "0,1,2,3");
        // The csv must agree with the bits: re-derive the mask from the
        // text and compare — the SET and the BITSET are one mask.
        for m in [one, two_digit, wide] {
            let text = m.arm_ids_csv(&mut buf);
            let ids: Vec<u8> = text
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<u8>().unwrap())
                .collect();
            assert_eq!(SyscallMask::from_ids(&ids).unwrap(), m);
            assert_eq!(ids.len(), m.count() as usize);
        }
        // A short buffer truncates instead of panicking (telemetry
        // must never kill the boot); what IS written stays ASCII.
        let mut tiny = [0u8; 3];
        assert_eq!(wide.arm_ids_csv(&mut tiny), "0,1");
        assert!(SyscallMask::NONE.arm_ids_csv(&mut tiny).is_ascii());
    }

    #[test]
    fn package_manager_profile_arms_are_pinned() {
        // K23: the completed-exit markers print this mask's bits and
        // arm set — pin BOTH so a profile edit that silently moves an
        // arm fails here, not in the VM lane.
        use crate::profile::package_manager_profile;
        let pm = package_manager_profile().syscalls;
        assert_eq!(pm.count(), 10);
        assert_eq!(pm.bits(), 0x8000_0015_0003_000f);
        let mut buf = [0u8; 192];
        assert_eq!(
            pm.arm_ids_csv(&mut buf),
            "0,1,2,3,16,17,32,34,36,63",
            "read/write/open/close/mkdir/unlink/listdir/stat/rename/exit"
        );
        // The profile stays attenuated by the service surface it
        // derives from (the lane's MISMATCH guard reads the same
        // relation on the live mask).
        assert!(pm.is_subset_of(&crate::profile::service_profile().syscalls));
    }

    #[test]
    fn gate_matches_the_domain_semantics() {
        use super::*;
        let m = SyscallMask::from_ids(&[SYS_READ, SYS_WRITE, SYS_EXIT]).unwrap();
        // Unknown id: bad before any state check.
        assert_eq!(gate(&m, false, 200), Decision::BadSyscall(200));
        assert_eq!(gate(&m, true, 200), Decision::BadSyscall(200));
        // Quarantine: only EXIT passes.
        assert_eq!(
            gate(&m, true, SYS_READ),
            Decision::DeniedQuarantined(SYS_READ)
        );
        assert_eq!(gate(&m, true, SYS_EXIT), Decision::Allowed);
        // Mask decides the rest.
        assert_eq!(gate(&m, false, SYS_WRITE), Decision::Allowed);
        assert_eq!(gate(&m, false, SYS_KILL), Decision::DeniedByMask(SYS_KILL));
        // Empty mask denies everything except (unquarantined) nothing.
        assert_eq!(
            gate(&SyscallMask::NONE, false, SYS_EXIT),
            Decision::DeniedByMask(SYS_EXIT)
        );
    }
}

#[cfg(test)]
mod adr0003_tests {
    use super::*;

    /// v1: the whitelist, entry by entry (Linux nr -> internal op).
    #[test]
    fn linux_table_maps_every_entry() {
        let cases: &[(u64, u8)] = &[
            (0, SYS_READ),            // read(2)
            (1, SYS_WRITE),           // write(2)
            (2, SYS_OPEN),            // open(2) — O_* translated at the entry
            (3, SYS_CLOSE),           // close(2)
            (9, SYS_MMAP),            // mmap(2)
            (11, SYS_MUNMAP),         // munmap(2)
            (13, SYS_SIGACTION),      // rt_sigaction(2)
            (15, SYS_SIGRETURN),      // rt_sigreturn(2)
            (22, SYS_PIPE),           // pipe(2)
            (24, SYS_SCHED_YIELD),    // sched_yield(2)
            (33, SYS_DUP),            // dup2(2)
            (35, SYS_NANOSLEEP),      // nanosleep(2)
            (57, SYS_FORK),           // fork(2)
            (59, SYS_EXEC),           // execve(2) — the image replacement
            (61, SYS_WAIT),           // wait4(2) — the blocking wait parks rip-2
            (60, SYS_EXIT),           // exit(2)
            (62, SYS_KILL),           // kill(2)
            (228, SYS_CLOCK_GETTIME), // clock_gettime(2)
            (231, SYS_EXIT),          // exit_group(2) — the alias
            (83, SYS_MKDIR),          // mkdir(2) — the Phase-6 ring-3 arm
            (87, SYS_UNLINK),         // unlink(2) — unlink+rmdir folded
            (161, SYS_CHROOT),        // chroot(2) — confinement, cwd moves with the root
            (82, SYS_RENAME),         // rename(2) — K21: the PM's commit primitive
            (264, SYS_RENAME),        // renameat(2) — the dirfd-prefixed alias
            (262, SYS_STAT),          // newfstatat(2) — K21: the PM's parent walks
        ];
        for &(nr, op) in cases {
            assert_eq!(linux_nr_to_core(nr), Some(u64::from(op)), "nr {nr}");
        }
    }

    /// v1: the whitelist's EDGE — the collisions that must NOT pass
    /// through. Linux 63 is uname; internal 63 is EXIT (a
    /// pass-through would exit a Linux binary on uname). Linux 39 is
    /// getpid, 32/293 have no ABI arm. (open — nr 2 — lived on
    /// this edge until slice 2: its O_* word is TRANSLATED now, the
    /// encoding difference handled at the SYS_OPEN arm; wait4 — nr
    /// 61 — until slice 3: the kernel gained the SYS_WAIT arm the
    /// ADR-0022 D7 core was waiting for; execve — nr 59 — until
    /// slice 4: the ELF loader and the SYS_EXEC arm landed as one
    /// atomic change.)
    #[test]
    fn linux_table_refuses_the_collisions() {
        for nr in [4u64, 5, 12, 14, 32, 39, 63, 64, 293, 1000, u64::MAX] {
            assert_eq!(linux_nr_to_core(nr), None, "nr {nr} must not pass");
        }
    }

    /// v1: every mapped target is a real internal op id (< 64 — the
    /// mask's width) — the gate could never index out of its mask.
    #[test]
    fn linux_table_targets_are_internal_ops() {
        for nr in 0..=300u64 {
            if let Some(op) = linux_nr_to_core(nr) {
                assert!(op < u64::from(SYSCALL_COUNT), "nr {nr} -> {op}");
            }
        }
    }

    /// v1: the ABI flag — default Internal, the setter flips it, fork
    /// carries it (the Linux-mode parent's child speaks Linux too).
    #[test]
    fn abi_flag_defaults_sets_and_forks() {
        use crate::profile::service_profile;
        let mut k = crate::Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        assert_eq!(k.domain(1).unwrap().abi, Abi::Internal, "the default");
        k.set_domain_abi(1, Abi::Linux).unwrap();
        assert_eq!(k.domain(1).unwrap().abi, Abi::Linux);
        let child = k.fork_process(1).unwrap();
        assert_eq!(
            k.domain(child).unwrap().abi,
            Abi::Linux,
            "the fork child inherits the parent's entry ABI"
        );
        assert!(k.set_domain_abi(99, Abi::Linux).is_err(), "unknown id");
    }
}
