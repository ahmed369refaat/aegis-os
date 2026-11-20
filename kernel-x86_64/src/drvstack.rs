//! Driver-stack boot steps (ADR-0013): the per-PR bring-up sequence
//! between the M1/M2 demonstrations and the terminal guard-page proof
//! (kmain step 13 stays the last act — every step here runs BEFORE it).
//!
//! Discipline, same as the rest of the boot: each step prints
//! CI-greppable markers (`[IOMMU] …`, later `[PCI ]`/`[VBLK]`) and
//! **fails closed** — an absent or malformed device is a verdict that
//! gets reported and remembered, never an invented capability and
//! never a crash of the boot itself.
//!
//! Step map (one PR each, ADR-0013's Phase 0 + the driver phases):
//! - PR 0.3 `acpi_step` — RSDP/RSDT/DMAR discovery + markers
//! - PR 0.4/0.5 add the VT-d bring-up and the broker wiring here.

use crate::arch;
use crate::strutil;
use aegis_os::dmar::{self, DmarStruct};

fn line(out: &mut dyn FnMut(&str), parts: &[&str]) {
    for p in parts {
        out(p);
    }
    out("\n");
}

/// PR 0.3: discover the firmware's DMA-remapping description and print
/// the ADR-0013 marker set. Outcomes, all CI-grepped on the q35 lanes:
///
/// - `[IOMMU] dmar: …` — found: `pa`, host address width, unit count,
///   interrupt-remapping flag, one line per DRHD (segment, register
///   base, include-all, scope count) and per RMRR (refused devices).
/// - `[IOMMU] dmar: absent` — the no-intel-iommu lane: DMA-capable
///   device claims will be refused later (fail-closed, D2).
/// - `[IOMMU] discovery: FAILED …` — broken firmware tables; same
///   fail-closed treatment, stated loudly instead of guessed around.
pub fn acpi_step(out: &mut dyn FnMut(&str)) {
    let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
    match arch::acpi::discover_boot(&mut buf) {
        arch::acpi::Discovery::Found {
            rsdp_pa,
            rsdp,
            dir_pa,
            dir_entries,
            dmar_pa,
            dmar,
        } => {
            let mut h1 = [0u8; 18];
            let mut h2 = [0u8; 18];
            let mut h3 = [0u8; 18];
            let mut n1 = [0u8; 20];
            let mut n2 = [0u8; 20];
            let mut n3 = [0u8; 20];
            let mut oem = [0u8; 6];
            oem.copy_from_slice(&rsdp.oem_id);
            let oem_len = oem.iter().position(|b| *b == 0).unwrap_or(oem.len());
            line(
                out,
                &[
                    "[IOMMU] rsdp: pa=",
                    strutil::hex(rsdp_pa, &mut h1),
                    " rev=",
                    strutil::dec(u64::from(rsdp.revision), &mut n1),
                    " oem=",
                    core::str::from_utf8(&oem[..oem_len]).unwrap_or("?"),
                ],
            );
            let mut n4 = [0u8; 20];
            line(
                out,
                &[
                    "[IOMMU] rsdt: pa=",
                    strutil::hex(dir_pa, &mut h1),
                    " entries=",
                    strutil::dec(dir_entries as u64, &mut n4),
                ],
            );
            let mut n5 = [0u8; 20];
            let mut n6 = [0u8; 20];
            line(
                out,
                &[
                    "[IOMMU] dmar: pa=",
                    strutil::hex(dmar_pa, &mut h2),
                    " haw=",
                    strutil::dec(u64::from(dmar.haw_bits), &mut n2),
                    " units=",
                    strutil::dec(dmar.structure_count as u64, &mut n5),
                    " ir=",
                    if dmar.intr_remap { "on" } else { "off" },
                ],
            );
            // One line per remapping structure: DRHDs describe the
            // units we will program (PR 0.4); RMRRs describe devices
            // that are unusable by policy (fail-closed, D2).
            let mut idx = 0usize;
            for s in dmar.structures[..dmar.structure_count].iter() {
                match s {
                    DmarStruct::Drhd(drhd) => {
                        let mut hb = [0u8; 18];
                        let mut nb = [0u8; 20];
                        line(
                            out,
                            &[
                                "[IOMMU] drhd[",
                                strutil::dec(idx as u64, &mut n3),
                                "]: seg=",
                                strutil::dec(u64::from(drhd.segment), &mut n6),
                                " base=",
                                strutil::hex(drhd.reg_base, &mut hb),
                                " include_all=",
                                if drhd.include_all { "yes" } else { "no" },
                                " scopes=",
                                strutil::dec(drhd.scope_count as u64, &mut nb),
                            ],
                        );
                    }
                    DmarStruct::Rmrr(rmrr) => {
                        let mut hb = [0u8; 18];
                        let mut hl = [0u8; 18];
                        let mut nb = [0u8; 20];
                        line(
                            out,
                            &[
                                "[IOMMU] rmrr[",
                                strutil::dec(idx as u64, &mut n3),
                                "]: base=",
                                strutil::hex(rmrr.base, &mut hb),
                                " limit=",
                                strutil::hex(rmrr.limit, &mut hl),
                                " scopes=",
                                strutil::dec(rmrr.scope_count as u64, &mut nb),
                                " — devices under it are unusable (D2)",
                            ],
                        );
                    }
                    DmarStruct::Unknown { kind, len } => {
                        let mut nk = [0u8; 20];
                        let mut nl = [0u8; 20];
                        line(
                            out,
                            &[
                                "[IOMMU] struct[",
                                strutil::dec(idx as u64, &mut n3),
                                "]: unknown kind=",
                                strutil::dec(u64::from(*kind), &mut nk),
                                " len=",
                                strutil::dec(u64::from(*len), &mut nl),
                                " (skipped)",
                            ],
                        );
                    }
                }
                idx += 1;
            }
        }
        arch::acpi::Discovery::NoDmar { rsdp_pa, .. } => {
            let mut h = [0u8; 18];
            line(
                out,
                &[
                    "[IOMMU] dmar: absent (rsdp @ ",
                    strutil::hex(rsdp_pa, &mut h),
                    ", no DMAR in the directory) — DMA device claims will be refused",
                ],
            );
        }
        arch::acpi::Discovery::Failed(err) => {
            line(
                out,
                &[
                    "[IOMMU] discovery: FAILED (",
                    describe_error(err),
                    ") — fail-closed, DMA device claims will be refused",
                ],
            );
        }
    }
}

/// One honest line per failure class (details live in the parser's
/// typed errors; the marker stays stable for CI).
fn describe_error(err: arch::acpi::DiscoveryError) -> &'static str {
    match err {
        arch::acpi::DiscoveryError::NoRsdp => "no RSDP in the EBDA or ROM windows",
        arch::acpi::DiscoveryError::BadRsdp(_) => "RSDP present but invalid",
        arch::acpi::DiscoveryError::BadDir(_) => "RSDT/XSDT invalid",
        arch::acpi::DiscoveryError::BadDmar(_) => "DMAR present but malformed",
    }
}
