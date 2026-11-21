//! VT-d bring-up + the hardware proofs + the broker demo (PR 0.4/0.5).

use super::hw_code;
use super::line;
use super::VTD_TABLE_OWNER;
use crate::frames::FramePool;
use crate::strutil;
use aegis_os::dmar::{self, Dmar, DmarStruct};

/// PR 0.4: bring the VT-d unit up on a machine whose DMAR parsed —
/// caps validated, root table + invalidation queue programmed,
/// SRTP/QIE/TE sequenced with bounded spins. Every refusal is a
/// marker + verdict line, never a halting guess. Returns the live
/// unit for the hardware proofs and the broker (PR 0.5) to sit on.
pub(crate) fn vtd_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    dmar: &Dmar,
) -> Option<crate::arch::vtd::Vtd> {
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
        return None;
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
                return None;
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
            None
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
                None
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
                Some(unit)
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
pub(crate) fn proof_step<const N: usize>(
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
    if let Err(e) = unit.assign_device(0, 0, bus, (dev, func)) {
        line(
            out,
            &["[IOMMU] vtd: hw-proof: assign refused (", hw_code(&e), ")"],
        );
        return;
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
    // ADR-0018: the probe assignment is released — the context entry
    // is cleared and the context cache invalidated, so the per-device
    // claims that follow start from a clean table (a device owns
    // exactly one domain, and this one was only ever the proof's).
    if let Err(e) = unit.unassign_device(0, bus, (dev, func)) {
        line(
            out,
            &[
                "[IOMMU] vtd: hw-proof: unassign refused (",
                hw_code(&e),
                ")",
            ],
        );
        return;
    }
    line(
        out,
        &["[IOMMU] vtd: hw-proof: probe assignment released (ctx cleared + cache invalidated, ADR-0018)"],
    );
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
