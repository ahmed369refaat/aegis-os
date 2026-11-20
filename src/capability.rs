//! Capability table: unforgeable handles with generation counters.
//!
//! A `CapHandle` is an (index, generation) pair. Slots are kernel-owned;
//! user code never sees a `Capability` directly. Revoking a slot bumps the
//! generation, so stale handles (use-after-revoke, ABA) fail closed.
//!
//! Derivation rule (`attenuate`): the parent must hold `GRANT` and the
//! requested rights must be a subset of the parent's rights. There is no
//! operation that adds rights — escalation attempts return `CapError::Escalation`.

pub const MAX_CAPABILITIES: usize = 16;

/// Rights bitset over a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rights(pub u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const EXEC: Rights = Rights(1 << 2);
    /// Required to derive child capabilities.
    pub const GRANT: Rights = Rights(1 << 3);
    /// Query metadata/stats of a resource.
    pub const STATS: Rights = Rights(1 << 4);

    /// Keep only the defined right bits.
    pub const fn from_bits(bits: u8) -> Rights {
        Rights(bits & 0b0001_1111)
    }

    #[must_use]
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    #[must_use]
    pub const fn is_subset_of(self, other: Rights) -> bool {
        self.0 & !other.0 == 0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        Rights(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Rights {
    fn bitor_assign(&mut self, rhs: Rights) {
        self.0 |= rhs.0;
    }
}

/// What a capability points at (F18, ADR-0009): the full resource
/// model the syscall layer enforces. `FsNode` carries the inode
/// reference (id + generation, F10) so a stale capability fails closed
/// exactly like a stale fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    FsNode(crate::vfs::InodeRef),
    Device(u32),
    Domain(u32),
    /// IPC endpoints — reserved for the IPC executor slices (ADR-0009
    /// TODO); nothing enforces them yet.
    Endpoint(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub resource: Resource,
    pub rights: Rights,
    /// Assigned by the table on insert; 0 means "not yet inserted".
    pub generation: u32,
}

/// Kernel-side handle handed to domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapHandle {
    pub index: usize,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    TableFull,
    /// Revoked, never-used, or stale-generation handle.
    InvalidHandle,
    /// Handle index outside the table.
    OutOfRange,
    /// Parent lacks the GRANT right.
    MissingGrantRight,
    /// Requested rights are not a subset of the parent's rights.
    Escalation,
}

pub struct CapabilityTable {
    slots: [Option<Capability>; MAX_CAPABILITIES],
    gens: [u32; MAX_CAPABILITIES],
}

impl CapabilityTable {
    pub fn new() -> Self {
        CapabilityTable {
            slots: [None; MAX_CAPABILITIES],
            gens: [0; MAX_CAPABILITIES],
        }
    }

    /// Insert a capability; returns the handle that must be used to refer to it.
    /// Generation bump on slot reuse makes previously handed-out handles stale.
    pub fn insert(&mut self, cap: Capability) -> Result<CapHandle, CapError> {
        for i in 0..MAX_CAPABILITIES {
            if self.slots[i].is_none() {
                self.gens[i] = self.gens[i].wrapping_add(1);
                if self.gens[i] == 0 {
                    self.gens[i] = 1; // generation 0 is reserved ("not inserted")
                }
                let stored = Capability { generation: self.gens[i], ..cap };
                self.slots[i] = Some(stored);
                return Ok(CapHandle { index: i, generation: self.gens[i] });
            }
        }
        Err(CapError::TableFull)
    }

    #[must_use]
    pub fn lookup(&self, handle: CapHandle) -> Result<Capability, CapError> {
        if handle.index >= MAX_CAPABILITIES {
            return Err(CapError::OutOfRange);
        }
        match self.slots[handle.index] {
            Some(c) if c.generation == handle.generation => Ok(c),
            _ => Err(CapError::InvalidHandle),
        }
    }

    /// Remove a capability. The slot's generation survives, so any handle
    /// minted before revocation is permanently invalid.
    pub fn revoke(&mut self, handle: CapHandle) -> Result<Capability, CapError> {
        if handle.index >= MAX_CAPABILITIES {
            return Err(CapError::OutOfRange);
        }
        match self.slots[handle.index] {
            Some(c) if c.generation == handle.generation => {
                self.slots[handle.index] = None;
                Ok(c)
            }
            _ => Err(CapError::InvalidHandle),
        }
    }

    /// Derive a child capability: requires GRANT on the parent and a subset
    /// of the parent's rights. Never widens.
    pub fn attenuate(
        &self,
        parent: CapHandle,
        rights: Rights,
    ) -> Result<Capability, CapError> {
        let p = self.lookup(parent)?;
        if !p.rights.contains(Rights::GRANT) {
            return Err(CapError::MissingGrantRight);
        }
        if !rights.is_subset_of(p.rights) {
            return Err(CapError::Escalation);
        }
        Ok(Capability { resource: p.resource, rights, generation: 0 })
    }

    /// F18: iterate live capabilities (the syscall gates scan for a
    /// covering capability).
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.slots.iter().flatten()
    }

    /// F18: live handles with their true generations (tests and
    /// supervisors enumerate to revoke; generation 0 is reserved, so
    /// guessing handles never works).
    pub fn handles(&self) -> impl Iterator<Item = CapHandle> + use<'_> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|c| CapHandle { index: i, generation: c.generation }))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CapabilityTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_cap(rights: Rights) -> Capability {
        Capability { resource: Resource::FsNode(crate::vfs::InodeRef { id: 7, generation: 1 }), rights, generation: 0 }
    }

    #[test]
    fn insert_lookup_roundtrip() {
        let mut t = CapabilityTable::new();
        assert!(t.is_empty());
        let h = t.insert(file_cap(Rights::READ | Rights::GRANT)).unwrap();
        let c = t.lookup(h).unwrap();
        assert_eq!(c.resource, Resource::FsNode(crate::vfs::InodeRef { id: 7, generation: 1 }));
        assert!(c.rights.contains(Rights::READ));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn table_full_at_max_capabilities() {
        let mut t = CapabilityTable::new();
        for i in 0..MAX_CAPABILITIES {
            t.insert(Capability {
                resource: Resource::FsNode(crate::vfs::InodeRef { id: i as u32, generation: 1 }),
                rights: Rights::READ,
                generation: 0,
            })
            .unwrap();
        }
        assert_eq!(t.len(), MAX_CAPABILITIES);
        assert_eq!(t.insert(file_cap(Rights::READ)), Err(CapError::TableFull));
    }

    #[test]
    fn revoke_then_lookup_fails_closed() {
        let mut t = CapabilityTable::new();
        let h = t.insert(file_cap(Rights::READ)).unwrap();
        let revoked = t.revoke(h).unwrap();
        assert_eq!(revoked.resource, Resource::FsNode(crate::vfs::InodeRef { id: 7, generation: 1 }));
        assert_eq!(t.lookup(h), Err(CapError::InvalidHandle));
    }

    #[test]
    fn double_revoke_is_an_error() {
        let mut t = CapabilityTable::new();
        let h = t.insert(file_cap(Rights::READ)).unwrap();
        t.revoke(h).unwrap();
        assert_eq!(t.revoke(h), Err(CapError::InvalidHandle));
    }

    #[test]
    fn stale_generation_rejected_after_slot_reuse() {
        let mut t = CapabilityTable::new();
        let h1 = t.insert(file_cap(Rights::READ)).unwrap();
        t.revoke(h1).unwrap();
        // Same slot gets reused with a bumped generation.
        let h2 = t.insert(file_cap(Rights::WRITE)).unwrap();
        assert_eq!(h1.index, h2.index);
        assert_ne!(h1.generation, h2.generation);
        // The old handle must NOT reach the new capability.
        assert_eq!(t.lookup(h1), Err(CapError::InvalidHandle));
        assert!(t.lookup(h2).is_ok());
    }

    #[test]
    fn attenuate_requires_grant_right() {
        let mut t = CapabilityTable::new();
        let h = t.insert(file_cap(Rights::READ | Rights::WRITE)).unwrap();
        assert_eq!(
            t.attenuate(h, Rights::READ),
            Err(CapError::MissingGrantRight)
        );
    }

    #[test]
    fn attenuate_rejects_escalation() {
        let mut t = CapabilityTable::new();
        let h = t
            .insert(file_cap(Rights::READ | Rights::EXEC | Rights::GRANT))
            .unwrap();
        // WRITE is not held by the parent: escalation attempt.
        assert_eq!(
            t.attenuate(h, Rights::READ | Rights::WRITE),
            Err(CapError::Escalation)
        );
        // Superset rights are rejected too.
        assert_eq!(t.attenuate(h, Rights::from_bits(0xFF)), Err(CapError::Escalation));
    }

    #[test]
    fn attenuate_to_empty_rights_is_allowed() {
        // A "null capability": proves knowledge of the resource, grants nothing.
        let mut t = CapabilityTable::new();
        let h = t.insert(file_cap(Rights::READ | Rights::GRANT)).unwrap();
        let child = t.attenuate(h, Rights::NONE).unwrap();
        assert!(child.rights.is_empty());
        assert_eq!(child.resource, Resource::FsNode(crate::vfs::InodeRef { id: 7, generation: 1 }));
    }

    #[test]
    fn attenuate_derives_subset_rights_same_resource() {
        let mut t = CapabilityTable::new();
        let h = t
            .insert(file_cap(Rights::READ | Rights::WRITE | Rights::GRANT))
            .unwrap();
        // Child carries GRANT too, so it can further delegate.
        let child = t
            .attenuate(h, Rights::READ | Rights::WRITE | Rights::GRANT)
            .unwrap();
        assert!(child.rights.is_subset_of(h_lookup(&t, h).rights));
        assert_eq!(child.resource, Resource::FsNode(crate::vfs::InodeRef { id: 7, generation: 1 }));
        // Attenuation of an attenuation still cannot exceed the parent.
        let h2 = t.insert(child).unwrap();
        let grandchild = t.attenuate(h2, Rights::READ).unwrap();
        assert!(grandchild.rights.is_subset_of(Rights::READ | Rights::WRITE));
    }

    fn h_lookup(t: &CapabilityTable, h: CapHandle) -> Capability {
        t.lookup(h).unwrap()
    }

    #[test]
    fn out_of_range_handles_rejected() {
        let t = CapabilityTable::new();
        assert_eq!(
            t.lookup(CapHandle { index: MAX_CAPABILITIES, generation: 1 }),
            Err(CapError::OutOfRange)
        );
        assert_eq!(
            t.lookup(CapHandle { index: 255, generation: 1 }),
            Err(CapError::OutOfRange)
        );
    }

    #[test]
    fn rights_lattice_and_bit_truncation() {
        assert!(Rights::READ.is_subset_of(Rights::READ | Rights::WRITE));
        assert!(!Rights::GRANT.is_subset_of(Rights::READ));
        assert!(Rights::NONE.is_subset_of(Rights::NONE));
        // from_bits drops undefined high bits.
        assert_eq!(Rights::from_bits(0xFF).0, 0b0001_1111);
        assert_eq!(Rights::from_bits(0b0010_0000), Rights::NONE);
        let r = Rights::READ.union(Rights::WRITE).intersect(Rights::WRITE);
        assert_eq!(r, Rights::WRITE);
    }
}
