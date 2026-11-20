//! Dependency-free deterministic property tests (G, review round 2).
//!
//! A tiny xorshift64* generator: no proptest, no dependency — the
//! properties are checked over fixed seeds, so failures reproduce
//! bit-for-bit and the counts feed scripts/count-tests.sh.

use aegis_os::capability::{CapError, Capability, Resource, Rights};
use aegis_os::profile::service_profile;
use aegis_os::syscall::SyscallMask;
use aegis_os::vfs::InodeRef;
use aegis_os::Kernel;

/// xorshift64* — deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn bit(&mut self) -> bool {
        self.next() & 1 == 0
    }
}

/// Property (the attenuation-only invariant): under ANY random
/// sequence of tighten / quarantine / audit-window operations, a live
/// domain's mask NEVER gains a bit outside its initial surface.
#[test]
fn property_masks_never_gain_bits() {
    for seed in [1u64, 0xDEAD_BEEF, 0xC0FF_EE01, 12345] {
        let mut rng = Rng::new(seed);
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        k.set_monitor_window(10);
        let initial = k.domain_mut(1).unwrap().mask();
        let mut clock = 0u64;
        for step in 0..500u32 {
            // Random degraded masks (some wider than the surface — the
            // intersection must still never widen).
            let mut bits = 0u64;
            for _ in 0..8 {
                bits |= 1 << rng.below(64);
            }
            let probe = SyscallMask::from_bits(bits);
            let d = k.domain_mut(1).unwrap();
            match rng.below(3) {
                0 => {
                    d.tighten(&probe);
                }
                1 => d.quarantine(),
                _ => {}
            }
            let after = k.domain_mut(1).unwrap().mask();
            assert!(
                after.is_subset_of(&initial),
                "seed {seed} step {step}: mask widened — attenuation-only violated"
            );
            // Drive windows across the sequence so audits interleave.
            clock += 10;
            k.tick(clock);
        }
    }
}

/// Property: capability derivation NEVER gains rights — a request that
/// is a subset succeeds and stays inside the parent; anything wider is
/// Escalation and inserts nothing.
#[test]
fn property_capability_derivation_never_gains_rights() {
    for seed in [7u64, 0xABCD_EF01, 99] {
        let mut rng = Rng::new(seed);
        let mut k = Kernel::new();
        k.create_domain(1, service_profile()).unwrap();
        // A root capability with GRANT plus a random subset of rights.
        let mut root = Rights::GRANT;
        for b in 0..5 {
            if rng.bit() {
                root = root.union(Rights(1 << b));
            }
        }
        let h_root = k
            .domain_mut(1)
            .unwrap()
            .caps
            .insert(Capability {
                resource: Resource::FsNode(InodeRef {
                    id: 1,
                    generation: 1,
                }),
                rights: root,
                generation: 0,
            })
            .unwrap();
        let mut parent = h_root;
        let mut parent_rights = root;
        for step in 0..200u32 {
            // A random request: sometimes a subset, sometimes wider.
            let mut req = Rights::NONE;
            for b in 0..5 {
                if rng.bit() {
                    req = req.union(Rights(1 << b));
                }
            }
            if rng.bit() {
                // Widen: add a random bit possibly outside the parent.
                req = req.union(Rights(1 << rng.below(6)));
            }
            let before = k.domain_mut(1).unwrap().caps.len();
            match k.cap_attenuate(1, parent, req) {
                Ok(child) => {
                    let c = k.cap_lookup(1, child).unwrap();
                    assert!(
                        c.rights.is_subset_of(parent_rights),
                        "seed {seed} step {step}: derived rights exceed the parent"
                    );
                    parent = child;
                    parent_rights = c.rights;
                }
                Err(CapError::MissingGrantRight) => {
                    // A derived capability without GRANT cannot derive
                    // further — refused, nothing inserted.
                    assert!(
                        !parent_rights.contains(Rights::GRANT),
                        "seed {seed} step {step}: GRANT-holding parent refused"
                    );
                }
                Err(CapError::Escalation) => {
                    assert!(
                        !req.is_subset_of(parent_rights),
                        "seed {seed} step {step}: a subset request was refused"
                    );
                    assert_eq!(
                        k.domain_mut(1).unwrap().caps.len(),
                        before,
                        "a failed derivation inserted nothing"
                    );
                }
                Err(e) => panic!("seed {seed} step {step}: unexpected {e:?}"),
            }
        }
    }
}
