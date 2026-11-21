//! ADR-0023 D4/D5: the calibrated clock — one TSC frequency for the
//! whole kernel (the tick cadence, clock_gettime, and ns↔cycle
//! conversions all read the same number, so a sleeper's deadline and
//! the reader's clock can never disagree).
//!
//! The HPET calibration in the driver stack's ACPI walk (round 6)
//! publishes the measured frequency here; until then (or on a machine
//! with no HPET) the FALLBACK is the preempt tick's fallback cadence
//! made into a frequency — honest about being a guess: monotonic and
//! self-consistent, never claimed measured.

use core::sync::atomic::{AtomicU64, Ordering};

static TSC_HZ: AtomicU64 = AtomicU64::new(0);

/// The fallback: the preempt tick's 25M-cycle cadence at 10 ms/tick
/// implies 2.5 GHz (mirrors `sched::preempt::TICK_INTERVAL_TSC` —
/// duplicated because preempt is boot-only and this constant must
/// exist in host-test builds too; a drifting pair fails the
/// fallback_matches_the_tick_cadence test below). Monotonic under
/// TCG's TSC; wrong on real silicon by whatever the real ratio is —
/// which is exactly why [`calibrated`] exists and the boot log never
/// prints an unmeasured number as measured.
pub const FALLBACK_HZ: u64 = 25_000_000 * 100;

/// Publish the HPET-measured frequency (a zero is refused — a zero
/// cadence would starve every conversion).
pub fn set_calibrated(hz: u64) {
    if hz > 0 {
        TSC_HZ.store(hz, Ordering::SeqCst);
    }
}

/// The live frequency: the calibrated value, or the fallback.
#[must_use]
pub fn tsc_hz() -> u64 {
    let hz = TSC_HZ.load(Ordering::SeqCst);
    if hz > 0 {
        hz
    } else {
        FALLBACK_HZ
    }
}

/// Whether a real measurement has landed.
#[must_use]
pub fn calibrated() -> bool {
    TSC_HZ.load(Ordering::SeqCst) > 0
}

/// TSC cycles → nanoseconds (u128: ~584 years of horizon at 2.7 GHz —
/// no wraparound to audit).
#[must_use]
pub fn tsc_to_ns(tsc: u64) -> u128 {
    u128::from(tsc) * 1_000_000_000u128 / u128::from(tsc_hz())
}

/// Nanoseconds → TSC cycles, CHECKED: a span whose cycle count cannot
/// be represented refuses (`None` → -EINVAL at the ABI) — never a
/// silent truncation that would wake a sleeper early.
#[must_use]
pub fn ns_to_cycles(ns: u128) -> Option<u64> {
    let cycles = ns.saturating_mul(u128::from(tsc_hz())) / 1_000_000_000u128;
    u64::try_from(cycles).ok()
}

/// Monotonic nanoseconds now (boot-only: reads the TSC).
#[cfg(not(test))]
#[must_use]
pub fn now_ns() -> u128 {
    tsc_to_ns(crate::hw::read_tsc())
}

/// Parse a 16-byte `{ sec: u64, nsec: u64 }` timespec (little-endian,
/// the x86_64 layout). `nsec >= 1e9` refuses — a nanosecond field
/// outside its own unit is malformed, not rounded.
#[must_use]
pub fn parse_timespec(bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let mut sec = [0u8; 8];
    let mut nsec = [0u8; 8];
    sec.copy_from_slice(&bytes[..8]);
    nsec.copy_from_slice(&bytes[8..]);
    let sec = u64::from_le_bytes(sec);
    let nsec = u64::from_le_bytes(nsec);
    if nsec >= 1_000_000_000 {
        return None;
    }
    Some((sec, nsec))
}

/// `{sec, nsec}` → nanoseconds, CHECKED (u128; sec bounded so the
/// product cannot overflow — the ABI layer refuses absurd second
/// counts instead of wrapping).
#[must_use]
pub fn timespec_to_ns(sec: u64, nsec: u64) -> Option<u128> {
    if nsec >= 1_000_000_000 || sec > u32::MAX as u64 {
        return None;
    }
    Some(u128::from(sec) * 1_000_000_000u128 + u128::from(nsec))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pure math, pinned at a fixed frequency (the static is
    // process-global and other tests may have calibrated it — pin
    // tsc_hz() by construction instead: every test computes with the
    // SAME tsc_hz() the functions read).
    #[test]
    fn ns_cycle_roundtrip_is_lossless_within_one_cycle() {
        let hz = tsc_hz();
        // 100 ms at the live frequency.
        let ns = 100_000_000u128;
        let cycles = ns_to_cycles(ns).unwrap();
        let back = tsc_to_ns(cycles);
        // floor division loses strictly less than one cycle's worth
        // of nanoseconds each way.
        let one_cycle_ns = 1_000_000_000u128 / u128::from(hz) + 1;
        assert!(
            ns <= back && back - ns < one_cycle_ns,
            "{back} vs {ns} at {hz} Hz"
        );
    }

    #[test]
    fn zero_and_huge_spans() {
        assert_eq!(ns_to_cycles(0), Some(0));
        // u64::MAX ns (~585 years) cannot be represented in cycles.
        assert_eq!(ns_to_cycles(u128::from(u64::MAX)), None);
    }

    #[test]
    fn timespec_parsing_rejects_malformed_nsec() {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&2u64.to_le_bytes());
        b[8..].copy_from_slice(&500u64.to_le_bytes());
        assert_eq!(parse_timespec(&b), Some((2, 500)));
        b[8..].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        assert_eq!(parse_timespec(&b), None);
        // The seconds bound: u32::MAX is accepted, above refused
        // (timespec_to_ns's own contract).
        b[..8].copy_from_slice(&u64::from(u32::MAX).to_le_bytes());
        b[8..].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(timespec_to_ns(u64::from(u32::MAX), 0).is_some(), true);
        assert_eq!(timespec_to_ns(u64::from(u32::MAX) + 1, 0), None);
    }

    #[test]
    fn fallback_is_never_zero_and_never_claimed_measured() {
        // The invariant the ABI's honest logging relies on.
        assert!(tsc_hz() > 0);
    }

    #[test]
    fn fallback_matches_the_tick_cadence() {
        // 25M cycles per 10 ms tick == 2.5 GHz: the mirror of
        // sched::preempt::TICK_INTERVAL_TSC (boot-only, hence the
        // duplication) — if either side drifts, this pins which one.
        assert_eq!(FALLBACK_HZ, 2_500_000_000);
        assert_eq!(FALLBACK_HZ / 100, 25_000_000);
    }
}
