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
/// Reserved: domain exit. Always reachable; a mask without it is rejected
/// by convention (see `profile` tests).
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
