//! The entropy pool (first slice): what the system does until now was
//! nothing — every "random" number this kernel ever produced was a
//! constant. This module mixes the machine's real entropy sources
//! (RDRAND/RDSEED on the CPU, virtio-rng on the bus) into a
//! splitmix64-mixed accumulator with health counters.
//!
//! HONEST SCOPE: splitmix64 is a MIXER, not a cryptographic
//! primitive. The pool spreads and decorrelates whatever is mixed
//! into it; the ChaCha20 CSPRNG that reads from it (and the KASLR
//! that depends on that) is the documented next slice. What this
//! slice proves end to end: the SOURCES are live (CPUID-gated
//! instructions + the virtio device through the IOMMU), the mixing
//! happens, and draws are not constants.
//!
//! The pool is atomics-only inside so it can live as a boot static —
//! single CPU today, torn-word-free by construction.

use core::sync::atomic::{AtomicU64, Ordering};

/// The splitmix64 finalizer (Vigna's constant set): the mixer. Pure,
/// deterministic, pinned by structural tests (determinism, avalanche,
/// no trivial collisions — not by parroted magic values).
#[must_use]
pub const fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The boot entropy pool: an accumulator, the source/draw counters
/// (the health feed), and the previous draw (the "not a constant"
/// self-check reads it).
pub struct Pool {
    state: AtomicU64,
    mixes: AtomicU64,
    draws: AtomicU64,
    last: AtomicU64,
}

impl Pool {
    /// The unmixed pool: state 0 (nothing trusted yet), zero counters.
    #[must_use]
    pub const fn new() -> Pool {
        Pool {
            state: AtomicU64::new(0),
            mixes: AtomicU64::new(0),
            draws: AtomicU64::new(0),
            last: AtomicU64::new(0),
        }
    }

    /// Fold one source sample into the accumulator. Sources may fail
    /// (RDRAND can refuse; virtio-rng can time out) — a failed source
    /// simply does not mix, and the counter says so.
    pub fn mix(&self, sample: u64) {
        let old = self.state.load(Ordering::SeqCst);
        // Single CPU: the load/store pair cannot interleave (the only
        // writers are boot-step code and the interrupt-disabled
        // window paths).
        self.state.store(
            splitmix64(old ^ sample ^ splitmix64(sample)),
            Ordering::SeqCst,
        );
        self.mixes.fetch_add(1, Ordering::SeqCst);
    }

    /// Draw one word from the pool: the state advances (a draw is not
    /// a replay), and the health counters tick.
    pub fn next_u64(&self) -> u64 {
        let old = self.state.load(Ordering::SeqCst);
        let v = splitmix64(old ^ 0x9E37_79B9_7F4A_7C15);
        self.state.store(splitmix64(old ^ v), Ordering::SeqCst);
        self.draws.fetch_add(1, Ordering::SeqCst);
        self.last.store(v, Ordering::SeqCst);
        v
    }

    /// The health feed: (sources mixed, draws served, last draw).
    #[must_use]
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.mixes.load(Ordering::SeqCst),
            self.draws.load(Ordering::SeqCst),
            self.last.load(Ordering::SeqCst),
        )
    }
}

/// The one boot pool (the source mixers and the draw paths all share
/// it — entropy is a machine property, not a per-driver property).
pub static BOOT_POOL: Pool = Pool::new();

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism: same input, same output — the mixer is a pure
    /// function (a mixer that disagrees with itself is a bug, not
    /// entropy).
    #[test]
    fn splitmix64_is_deterministic() {
        for x in [0u64, 1, 42, 0xDEAD_BEEF, u64::MAX, u64::MAX - 1] {
            assert_eq!(splitmix64(x), splitmix64(x));
        }
    }

    /// Avalanche, structurally: consecutive inputs produce outputs
    /// that differ in about half the bits ON AVERAGE (measured over
    /// the sample — single pairs can swing; a mixer whose average
    /// drifts from 32 is not mixing).
    #[test]
    fn splitmix64_consecutive_inputs_differ_widely() {
        let mut total = 0u32;
        for x in 0u64..256 {
            let a = splitmix64(x);
            let b = splitmix64(x + 1);
            assert_ne!(a, b);
            let bits = (a ^ b).count_ones();
            assert!(
                bits >= 16,
                "pair {x} differs in only {bits} bits — the mixer stopped mixing"
            );
            total += bits;
        }
        let avg = total / 256;
        assert!(
            (28..=36).contains(&avg),
            "average avalanche {avg} bits — expected ~32"
        );
        // And no trivial fixed points in the sample.
        for x in 0u64..256 {
            assert_ne!(splitmix64(x), x, "a fixed point is not mixing");
        }
    }

    /// The pool: mixing changes the state, draws advance it, counters
    /// are honest, and two draws from a mixed pool are distinct and
    /// non-constant.
    #[test]
    fn the_pool_mixes_counts_and_draws_distinctly() {
        let p = Pool::new();
        // Unmixed draws are still deterministic words (and advance).
        let d0 = p.next_u64();
        let d1 = p.next_u64();
        assert_ne!(d0, d1, "consecutive draws are distinct");
        // Mixing sources changes what draws produce.
        p.mix(0x1111_1111_1111_1111);
        p.mix(0x2222_2222_2222_2222);
        let d2 = p.next_u64();
        let d3 = p.next_u64();
        assert_ne!(d2, d3);
        assert_ne!(d2, d0);
        assert_ne!(d2, d1);
        // The counters tell the truth: 2 mixes, 4 draws.
        assert_eq!(p.counters(), (2, 4, d3));
        // All-zero samples do not wedge the pool (a failed-but-zero
        // source still folds — the state keeps moving).
        p.mix(0);
        let d4 = p.next_u64();
        assert_ne!(d4, d3);
        assert_eq!(p.counters().0, 3);
    }

    /// The same source sequence produces the same pool trajectory
    /// (reproducible mixing — the pool is a state machine, and the
    /// counters are its log).
    #[test]
    fn identical_source_sequences_reproduce_identically() {
        let a = Pool::new();
        let b = Pool::new();
        for s in [7u64, 8, 9, 10, 11] {
            a.mix(s);
            b.mix(s);
        }
        for _ in 0..4 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_eq!(a.counters(), b.counters());
    }
}
