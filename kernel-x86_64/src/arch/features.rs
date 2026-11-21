//! Pure CPU-feature decoding and CR4 images (N4, ADR-0008).
//!
//! Everything here is host-tested arithmetic over raw register values;
//! the target wrappers that actually execute CPUID/STAC/CLAC live in
//! `hw`.

/// CPUID leaf 7 sub-leaf 0, EBX bit 7: Supervisor Mode Execution
/// Prevention.
#[must_use]
pub const fn has_smep(leaf7_ebx: u64) -> bool {
    leaf7_ebx & (1 << 7) != 0
}

/// CPUID leaf 7 sub-leaf 0, EBX bit 20: Supervisor Mode Access
/// Prevention.
#[must_use]
pub const fn has_smap(leaf7_ebx: u64) -> bool {
    leaf7_ebx & (1 << 20) != 0
}

/// CPUID leaf 1, ECX bit 24: TSC-deadline timer mode (the LAPIC timer
/// can take an absolute TSC deadline via MSR 0x6E0 — the deterministic
/// mode, same clock as every other measurement in the kernel).
#[must_use]
pub const fn has_tsc_deadline(leaf1_ecx: u64) -> bool {
    leaf1_ecx & (1 << 24) != 0
}

/// CR4.SMEP is bit 20, CR4.SMAP is bit 21.
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;

/// CPUID leaf 1, ECX bit 21: x2APIC (ADR-0019's MSR-mapped APIC).
#[must_use]
pub const fn has_x2apic(leaf1_ecx: u64) -> bool {
    leaf1_ecx & (1 << 21) != 0
}

/// CPUID leaf 1, ECX bit 3: MONITOR/MWAIT (the idle pair).
#[must_use]
pub const fn has_monitor(leaf1_ecx: u64) -> bool {
    leaf1_ecx & (1 << 3) != 0
}

/// CPUID leaf 1, ECX bit 30: RDRAND (the on-CPU entropy source).
#[must_use]
pub const fn has_rdrand(leaf1_ecx: u64) -> bool {
    leaf1_ecx & (1 << 30) != 0
}

/// CPUID leaf 7 sub-leaf 0, EBX bit 18: RDSEED (seed-quality entropy).
#[must_use]
pub const fn has_rdseed(leaf7_ebx: u64) -> bool {
    leaf7_ebx & (1 << 18) != 0
}

/// The CR4 image after (possibly) setting SMEP/SMAP. Setting a bit for
/// an unsupported feature is a #UD at the next privilege change — so
/// the image only ever sets what CPUID reported.
#[must_use]
pub const fn cr4_image(current: u64, smep: bool, smap: bool) -> u64 {
    let mut cr4 = current;
    if smep {
        cr4 |= CR4_SMEP;
    }
    if smap {
        cr4 |= CR4_SMAP;
    }
    cr4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuid_bits_decode() {
        // QEMU -cpu max (TCG) reports both; qemu64 reports neither.
        assert!(has_smep(1 << 7));
        assert!(has_smap(1 << 20));
        assert!(has_smep((1 << 7) | (1 << 20)));
        assert!(!has_smep(0));
        assert!(!has_smap(0));
        assert!(!has_smep(1 << 20), "SMAP's bit is not SMEP's");
        assert!(!has_smap(1 << 7), "SMEP's bit is not SMAP's");
    }

    #[test]
    fn tsc_deadline_bit_decodes() {
        // CPUID.01H:ECX bit 24 (QEMU -cpu max reports it).
        assert!(has_tsc_deadline(1 << 24));
        assert!(has_tsc_deadline(1 << 24 | 1 << 7));
        assert!(!has_tsc_deadline(0));
        assert!(!has_tsc_deadline(1 << 23), "neighbor bit must not decode");
    }

    #[test]
    fn aegis19_feature_bits_decode() {
        // x2APIC: ECX bit 21 (QEMU -cpu max reports it).
        assert!(has_x2apic(1 << 21));
        assert!(!has_x2apic(0));
        assert!(!has_x2apic(1 << 20), "neighbor bit must not decode");
        // MONITOR/MWAIT: ECX bit 3.
        assert!(has_monitor(1 << 3));
        assert!(!has_monitor(0));
        assert!(!has_monitor(1 << 4), "neighbor bit must not decode");
        // RDRAND: ECX bit 30.
        assert!(has_rdrand(1 << 30));
        assert!(!has_rdrand(0));
        assert!(!has_rdrand(1 << 29), "neighbor bit must not decode");
        // RDSEED: leaf-7 EBX bit 18.
        assert!(has_rdseed(1 << 18));
        assert!(!has_rdseed(0));
        assert!(!has_rdseed(1 << 17), "neighbor bit must not decode");
    }

    #[test]
    fn cr4_image_sets_only_supported_bits() {
        let base = 0x1_0000; // some existing CR4 bits (e.g. PSE)
        assert_eq!(cr4_image(base, false, false), base);
        assert_eq!(cr4_image(base, true, false), base | CR4_SMEP);
        assert_eq!(cr4_image(base, false, true), base | CR4_SMAP);
        assert_eq!(cr4_image(base, true, true), base | CR4_SMEP | CR4_SMAP);
        // Idempotent on already-set bits.
        assert_eq!(cr4_image(base | CR4_SMEP, true, false), base | CR4_SMEP);
    }
}
