//! The driver-stack boot orchestration (ADR-0013/0016): discovery,
//! the shared teardown discipline, and the step sequencing. The
//! per-subsystem steps live in the sibling modules.

// Host-test builds compile this module without its boot-only step
// functions; their imports stay (used by the boot build).
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::arch;
use crate::arch::acpi::Discovery;
use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;
use aegis_os::dmar::{self, Dmar, DmarStruct};

// ADR-0016: one module per subsystem — the split is a pure move; the
// step sequencing below is the only thing that knows them all.
#[cfg(test)]
pub(crate) mod testharness;

mod acpi;
mod ahci;
mod broker;
mod e1k;
mod ext2;
mod legacy;
mod netutil;
mod nvme;
mod pci;
mod vblk;
mod vnet;
mod vtd;
mod xhci;

// The pool owner tags stay reachable at `crate::drvstack::*` (their
// documented home in the frames ledger); the modules define them.
pub use ahci::AHCI_OWNER;
pub use e1k::E1K_OWNER;
pub use ext2::EXT2_OWNER;
pub use nvme::NVME_OWNER;
pub use vblk::VBLK_OWNER;
pub use vnet::VNET_OWNER;
pub use xhci::XHCI_OWNER;

/// The arch layer's opaque `Hardware(n)` codes, decoded for markers.
fn hw_code(e: &aegis_os::dma::DmaError) -> &'static str {
    match e {
        aegis_os::dma::DmaError::Hardware(1) => "wrong segment",
        aegis_os::dma::DmaError::Hardware(2) => "table budget exhausted",
        aegis_os::dma::DmaError::Hardware(3) => "map walk failed",
        aegis_os::dma::DmaError::Hardware(4) => "invalidation failed",
        aegis_os::dma::DmaError::Hardware(5) => "domain not assigned",
        aegis_os::dma::DmaError::Hardware(6) => "domain out of range",
        aegis_os::dma::DmaError::Hardware(7) => {
            "device already assigned (ADR-0018: unassign first)"
        }
        aegis_os::dma::DmaError::Hardware(_) => "arch refusal",
        _ => "policy refusal",
    }
}

/// The pool owner tag for VT-d translation tables (root, context,
/// SLPT, the IQ frame) and the proof pages — distinct so the M1
/// zero-leak accounting can name them (they are intentionally still
/// held at the end of boot: the IOMMU is live infrastructure, not a
/// leak; the ledger says so).
pub const VTD_TABLE_OWNER: u32 = 42;

/// The driver-stack entry point (kmain step 14): discover the
/// firmware's DMA-remapping description, print the ADR-0013 marker
/// set, and — when a DMAR exists — bring the real VT-d unit up
/// (PR 0.4). Absence and failure are verdicts, not crashes: the boot
/// continues and later claim paths fail closed on them.
#[cfg(not(test))]
pub fn driver_stack_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
) {
    let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
    match arch::acpi::discover_boot(&mut buf) {
        Discovery::Found {
            rsdp_pa,
            rsdp,
            dir_pa,
            dir_entries,
            dmar_pa,
            dmar,
        } => {
            print_found(out, rsdp_pa, &rsdp, dir_pa, dir_entries, dmar_pa, &dmar);
            // F9c: every endpoint goes quiet (IO/MEM/BME off) BEFORE
            // the VT-d unit is enabled — no device decodes or DMAs
            // while the IOMMU's own tables are being built, and the
            // later BAR sizing runs with decoding disabled.
            let quiesced = crate::pci::quiesce_all();
            let mut nq = [0u8; 20];
            line(
                out,
                &[
                    "[PCI ] quiesce_all before VT-d: ",
                    strutil::dec(quiesced as u64, &mut nq),
                    " endpoint(s) IO/MEM/BME off",
                ],
            );
            if let Some(mut unit) = vtd::vtd_step(k, pool, out, &dmar) {
                vtd::proof_step(k, pool, out, &dmar, &mut unit);
                let mut broker = broker::broker_step(k, pool, out, unit);
                // ADR-0018: kernel-allocated, one IOMMU domain per
                // device (domain 0 stays the kernel's own).
                let mut domains = crate::session::DomainIds::new();
                let inv = pci::pci_step(out, &dmar, &mut broker, &mut domains);
                vblk::virtio_step(k, pool, out, &mut broker, &inv);
                vnet::net_step(k, pool, out, &mut broker, &inv);
                e1k::e1k_step(k, pool, out, &mut broker, &inv);
                e1k::e1k_cross_device_probe_step(k, pool, out, &mut broker, &inv);
                nvme::nvme_step(k, pool, out, &mut broker, &inv);
                ahci::ahci_step(k, pool, out, &mut broker, &inv);
                xhci::xhci_step(k, pool, out, &mut broker, &inv);
                xhci::xhci_cmdring_step(k, pool, out, &mut broker, &inv);
                acpi::acpi_hpet_step(out, dir_pa);
                legacy::gfx_step(out, &inv);
                legacy::ps2_step(out);
                legacy::rtc_step(out);
            } else {
                line(out, &["[IOMMU] dma-drivers=0 (fail-closed: no broker)"]);
            }
        }
        Discovery::NoDmar { rsdp_pa, .. } => {
            let mut h = [0u8; 18];
            line(
                out,
                &[
                    "[IOMMU] dmar: absent (rsdp @ ",
                    strutil::hex(rsdp_pa, &mut h),
                    ", no DMAR in the directory) — DMA device claims will be refused",
                ],
            );
            line(out, &["[IOMMU] dma-drivers=0 (fail-closed: no broker)"]);

            // The q35-neg control lane: a placeholder broker whose
            // verdict is Absent lets the driver steps run anyway —
            // every claim refuses, and identity-mode drivers (the
            // e1000 control for the device-DMA investigation) run
            // their full flow against plain RAM.
            // Drivers reach device MMIO through the 4th-GiB direct-
            // map window; on the IOMMU lane vtd_step maps it — map it
            // here too or every BAR read faults (measured: #PF at
            // cr2=direct_map+0xfebc5400, the e1000's RAL).
            crate::arch::vtd::map_mmio_window();
            let broker = aegis_os::dma::DmaBroker::new(
                crate::arch::vtd::Vtd::absent(),
                aegis_os::dma::DmaQuotas {
                    max_regions: 16,
                    max_bytes: 64 * 1024,
                },
            );
            let mut broker = broker;
            let mut domains = crate::session::DomainIds::new();
            let inv = pci::pci_step(
                out,
                &aegis_os::dmar::Dmar::absent_stub(),
                &mut broker,
                &mut domains,
            );
            e1k::e1k_step(k, pool, out, &mut broker, &inv);
            // ADR-0014 step 5: the stale-FIS control lane — the SAME
            // AHCI two-command sequence without the vIOMMU.
            ahci::ahci_step(k, pool, out, &mut broker, &inv);
        }
        Discovery::Failed(err) => {
            line(
                out,
                &[
                    "[IOMMU] discovery: FAILED (",
                    describe_discovery_error(err),
                    ") — fail-closed, DMA device claims will be refused",
                ],
            );
            line(out, &["[IOMMU] dma-drivers=0 (fail-closed: no broker)"]);
        }
    }
}

/// The found-path markers (PR 0.3): the tables, the HAW, one line per
/// remapping structure (DRHDs we will program; RMRRs whose devices
/// are unusable by policy, D2).
fn print_found(
    out: &mut dyn FnMut(&str),
    rsdp_pa: u64,
    rsdp: &dmar::Rsdp,
    dir_pa: u64,
    dir_entries: usize,
    dmar_pa: u64,
    dmar: &Dmar,
) {
    let mut h1 = [0u8; 18];
    let mut n1 = [0u8; 20];
    let mut n2 = [0u8; 20];
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
    line(
        out,
        &[
            "[IOMMU] rsdt: pa=",
            strutil::hex(dir_pa, &mut h1),
            " entries=",
            strutil::dec(dir_entries as u64, &mut n2),
        ],
    );
    let mut h2 = [0u8; 18];
    let mut n3 = [0u8; 20];
    let mut n4 = [0u8; 20];
    line(
        out,
        &[
            "[IOMMU] dmar: pa=",
            strutil::hex(dmar_pa, &mut h2),
            " haw=",
            strutil::dec(u64::from(dmar.haw_bits), &mut n3),
            " units=",
            strutil::dec(dmar.structure_count as u64, &mut n4),
            " ir=",
            if dmar.intr_remap { "on" } else { "off" },
        ],
    );
    for (idx, s) in dmar.structures[..dmar.structure_count].iter().enumerate() {
        let mut hb = [0u8; 18];
        let mut hl = [0u8; 18];
        let mut nb = [0u8; 20];
        match s {
            DmarStruct::Drhd(drhd) => {
                line(
                    out,
                    &[
                        "[IOMMU] drhd[",
                        strutil::dec(idx as u64, &mut n1),
                        "]: seg=",
                        strutil::dec(u64::from(drhd.segment), &mut n2),
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
                line(
                    out,
                    &[
                        "[IOMMU] rmrr[",
                        strutil::dec(idx as u64, &mut n1),
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
                line(
                    out,
                    &[
                        "[IOMMU] struct[",
                        strutil::dec(idx as u64, &mut n1),
                        "]: unknown kind=",
                        strutil::dec(u64::from(*kind), &mut n2),
                        " len=",
                        strutil::dec(u64::from(*len), &mut nb),
                        " (skipped)",
                    ],
                );
            }
        }
    }
}

/// One honest line per discovery failure class (details live in the
/// parser's typed errors; the marker stays stable for CI).
fn describe_discovery_error(err: arch::acpi::DiscoveryError) -> &'static str {
    match err {
        arch::acpi::DiscoveryError::NoRsdp => "no RSDP in the EBDA or ROM windows",
        arch::acpi::DiscoveryError::BadRsdp(_) => "RSDP present but invalid",
        arch::acpi::DiscoveryError::BadDir(_) => "RSDT/XSDT invalid",
        arch::acpi::DiscoveryError::BadDmar(_) => "DMAR present but malformed",
    }
}
