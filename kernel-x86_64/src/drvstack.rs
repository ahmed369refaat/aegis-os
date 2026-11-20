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
//! - PR 0.3 `driver_stack_step` — RSDP/RSDT/DMAR discovery + markers
//! - PR 0.4 `vtd_step` — VT-d caps/program/TE + hardware proofs
//! - PR 0.5+ (the broker, PCI, virtio) stack after it.
//!
//! This module is target-only (the whole `drvstack` mod is
//! `cfg(not(test))`; its logic lives in `arch::acpi`/`arch::vtd`,
//! which carry the host tests).

use crate::arch;
use crate::arch::acpi::Discovery;
use crate::frames::FramePool;
use crate::strutil;
use aegis_os::dmar::{self, Dmar, DmarStruct};

fn line(out: &mut dyn FnMut(&str), parts: &[&str]) {
    for p in parts {
        out(p);
    }
    out("\n");
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
            vtd_step(k, pool, out, &dmar);
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
    let mut idx = 0usize;
    for s in &dmar.structures[..dmar.structure_count] {
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
        idx += 1;
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

/// PR 0.4: bring the VT-d unit up on a machine whose DMAR parsed —
/// caps validated, root table + invalidation queue programmed,
/// SRTP/QIE/TE sequenced with bounded spins, then the hardware
/// proofs (`proof_step`). Every refusal is a marker + verdict line,
/// never a halting guess.
fn vtd_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    dmar: &Dmar,
) {
    use crate::arch::vtd;

    // The MMIO window first: caps are read before a Vtd exists.
    vtd::map_mmio_window();

    let Some(DmarStruct::Drhd(drhd)) = dmar.structures[..dmar.structure_count]
        .iter()
        .find(|s| matches!(s, DmarStruct::Drhd(_)))
    else {
        // plan() would refuse the same thing; discovery found a DMAR
        // with no DRHD — state it and stop here (fail closed).
        line(out, &["[IOMMU] vtd: no DRHD to program — verdict: absent"]);
        return;
    };
    let ver = crate::memops::read_u32(drhd.reg_base + vtd::REG_VER);
    let cap = crate::memops::read_u64(drhd.reg_base + vtd::REG_CAP);
    let ecap = crate::memops::read_u64(drhd.reg_base + vtd::REG_ECAP);

    // The bounded table budget, straight from the (scrubbed) pool.
    let mut tables = [0u64; vtd::TABLE_BUDGET];
    for (i, slot) in tables.iter_mut().enumerate() {
        match pool.alloc_for(&mut k.frames, VTD_TABLE_OWNER) {
            Ok(pa) => *slot = pa,
            Err(_) => {
                let mut b = [0u8; 20];
                line(
                    out,
                    &[
                        "[IOMMU] vtd: table-budget allocation failed at frame ",
                        strutil::dec(i as u64, &mut b),
                        " — verdict: absent (fail-closed)",
                    ],
                );
                return;
            }
        }
    }

    match vtd::Vtd::plan(dmar, ver, cap, ecap, &tables) {
        Err(e) => {
            line(
                out,
                &[
                    "[IOMMU] vtd: plan FAILED (",
                    describe_vtd_error(&e),
                    ") — verdict: absent",
                ],
            );
        }
        Ok(mut unit) => match unit.program_and_enable() {
            Err(e) => {
                line(
                    out,
                    &[
                        "[IOMMU] vtd: enable FAILED (",
                        describe_vtd_error(&e),
                        ") — verdict: absent",
                    ],
                );
            }
            Ok((srtp, qie, te)) => {
                let mut h1 = [0u8; 18];
                let mut h2 = [0u8; 18];
                let mut s1 = [0u8; 20];
                let mut s2 = [0u8; 20];
                let mut s3 = [0u8; 20];
                line(
                    out,
                    &[
                        "[IOMMU] vtd: caps ver=",
                        strutil::hex(u64::from(ver), &mut h1),
                        " sagaw4=yes qi=yes c=",
                        if unit.caps.coherent { "yes" } else { "NO" },
                    ],
                );
                line(
                    out,
                    &[
                        "[IOMMU] vtd: root=",
                        strutil::hex(unit.root_pa(), &mut h1),
                        " iq=",
                        strutil::hex(unit.iq_pa(), &mut h2),
                        " — RTPS/QIES/TES on (spins ",
                        strutil::dec(srtp, &mut s1),
                        "/",
                        strutil::dec(qie, &mut s2),
                        "/",
                        strutil::dec(te, &mut s3),
                        ")",
                    ],
                );
                let mut n = [0u8; 20];
                line(
                    out,
                    &[
                        "[IOMMU] vtd: verdict: available haw=",
                        strutil::dec(u64::from(unit.haw_bits()), &mut n),
                        " — translation enabled (unmapped device DMA now faults)",
                    ],
                );
                proof_step(k, pool, out, dmar, &mut unit);
            }
        },
    }
}

/// The three hardware proofs (PR 0.4): assign a real device from the
/// DRHD's endpoint scopes to domain 0, map one pool page, unmap it —
/// each verified by reading the structures back, all through the
/// `DmaProt` surface the broker (PR 0.5) will sit on. The device
/// comes from the DRHD's own scopes; the real claim path arrives with
/// Phase 1's PCI model (the marker says so).
fn proof_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    dmar: &Dmar,
    unit: &mut crate::arch::vtd::Vtd,
) {
    use crate::arch::vtd;
    use aegis_os::dma::{DmaDir, DmaProt};

    // The proof device: the LAST PCI-endpoint scope the DRHD names —
    // on the q35+virtio lane that is the virtio-blk itself (00:03.0),
    // the device Phase 2 will actually drive through the broker.
    let mut proof: Option<(u8, u8, u8)> = None; // (bus, dev, fn)
    for s in &dmar.structures[..dmar.structure_count] {
        if let DmarStruct::Drhd(drhd) = s {
            for sc in &drhd.scopes[..drhd.scope_count] {
                if sc.kind == dmar::ScopeType::PciEndpoint && sc.path_len >= 1 {
                    proof = Some((sc.start_bus, sc.path[0].0, sc.path[0].1));
                }
            }
        }
    }
    let Some((bus, dev, func)) = proof else {
        line(
            out,
            &["[IOMMU] vtd: hw-proof: skipped (no endpoint scope names a device; the claim path arrives in Phase 1)"],
        );
        return;
    };
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];
    let mut b3 = [0u8; 20];
    line(
        out,
        &[
            "[IOMMU] vtd: hw-proof: assigning bus=",
            strutil::dec(u64::from(bus), &mut b1),
            " dev=",
            strutil::dec(u64::from(dev), &mut b2),
            " fn=",
            strutil::dec(u64::from(func), &mut b3),
            " → dom 0",
        ],
    );
    match unit.assign_device(0, 0, bus, (dev, func)) {
        Err(e) => {
            line(
                out,
                &["[IOMMU] vtd: hw-proof: assign refused (", hw_code(&e), ")"],
            );
            return;
        }
        Ok(()) => {}
    }
    let (lo, hi) = unit.context_entry_of(bus, (dev, func));
    let mut h1 = [0u8; 18];
    line(
        out,
        &[
            "[IOMMU] vtd: hw-proof: ctx entry present=",
            if lo & 1 != 0 { "yes" } else { "NO" },
            " did=",
            strutil::dec(hi & 0xFFFF, &mut b1),
            " slpt=",
            strutil::hex(lo & vtd::ADDR_MASK, &mut h1),
        ],
    );

    // One fresh, scrubbed pool page as the mapped region.
    let Ok(page_pa) = pool.alloc_for(&mut k.frames, VTD_TABLE_OWNER) else {
        line(
            out,
            &["[IOMMU] vtd: hw-proof: pool exhausted before the map proof"],
        );
        return;
    };
    let Some(slpt) = unit.dom_slpt(0) else {
        line(out, &["[IOMMU] vtd: hw-proof: no SLPT root for dom 0"]);
        return;
    };
    if unit
        .map_run(0, page_pa, 4096, DmaDir::Bidirectional)
        .is_err()
    {
        line(out, &["[IOMMU] vtd: hw-proof: map refused"]);
        return;
    }
    let pte = unit.slpte_of(slpt, page_pa);
    line(
        out,
        &[
            "[IOMMU] vtd: hw-proof: mapped 1 page (pte ",
            if pte.map(|p| p & 3 == 3).unwrap_or(false) {
                "present+rw"
            } else {
                "BAD"
            },
            ", identity)",
        ],
    );
    if unit.unmap_run(0, page_pa, 4096).is_err() {
        line(out, &["[IOMMU] vtd: hw-proof: unmap refused"]);
        return;
    }
    let cleared = unit.slpte_of(slpt, page_pa).is_none();
    let fsts = unit.fsts();
    let mut h2 = [0u8; 18];
    line(
        out,
        &[
            "[IOMMU] vtd: hw-proof: unmapped + iotlb invalidated (pte ",
            if cleared { "absent" } else { "STILL PRESENT" },
            ", fsts=",
            strutil::hex(u64::from(fsts), &mut h2),
            ")",
        ],
    );
    // The proof page goes back to the pool (scrubbed on free).
    let _ = pool.free(&mut k.frames, page_pa, VTD_TABLE_OWNER);
}

/// One honest line per VT-d failure class.
fn describe_vtd_error(e: &crate::arch::vtd::VtdError) -> &'static str {
    use crate::arch::vtd::VtdError;
    match e {
        VtdError::NoDrhd => "no DRHD",
        VtdError::UnsupportedMultiDrhd(_) => "multi-DRHD machines out of Phase-0 scope",
        VtdError::BadVer(_) => "VER reads dead",
        VtdError::UnsupportedAgaw { .. } => "SAGAW lacks the 4-level width",
        VtdError::UnsupportedLevels(_) => "only the 48-bit/4-level width is walked in Phase 0",
        VtdError::NoQi(_) => "no queued invalidation (ECAP.QI)",
        VtdError::OutOfTables => "table budget exhausted",
        VtdError::SpinTimeout(w) => w,
        VtdError::InvalidationError(_) => "invalidation queue error (FSTS)",
    }
}

/// The arch layer's opaque `Hardware(n)` codes, decoded for markers.
fn hw_code(e: &aegis_os::dma::DmaError) -> &'static str {
    match e {
        aegis_os::dma::DmaError::Hardware(1) => "wrong segment",
        aegis_os::dma::DmaError::Hardware(2) => "table budget exhausted",
        aegis_os::dma::DmaError::Hardware(3) => "map walk failed",
        aegis_os::dma::DmaError::Hardware(4) => "invalidation failed",
        aegis_os::dma::DmaError::Hardware(5) => "domain not assigned",
        aegis_os::dma::DmaError::Hardware(6) => "domain out of range",
        aegis_os::dma::DmaError::Hardware(_) => "arch refusal",
        _ => "policy refusal",
    }
}
