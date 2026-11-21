//! PCI enumeration, BAR sizing, capability walk, and the claim gate.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use super::hw_code;
use super::line;
use crate::strutil;
use aegis_os::dmar::Dmar;

/// Phase 1 (checklist item 2 + item 4's first slice): enumerate bus 0
/// over CF8/CFC, print the inventory (one line per function: ids,
/// class, the driver stack's honest name for it, sized BARs, the
/// capability list), then exercise the REAL claim gate on the first
/// virtio-blk: endpoint + not-bridge-class + IOMMU verdict + not
/// RMRR-covered, then the broker's `assign_device`. On machines
/// without the IOMMU the claim refuses — the negative proof.
#[cfg(not(test))]
pub(crate) fn pci_step(
    out: &mut dyn FnMut(&str),
    dmar: &Dmar,
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    domains: &mut crate::session::DomainIds,
) -> crate::pci::Inventory {
    use crate::pci;

    let mut inv = pci::enumerate_bus0();
    let mut n = [0u8; 20];
    line(
        out,
        &[
            "[PCI ] scan bus 0: ",
            strutil::dec(inv.count as u64, &mut n),
            " device(s)",
        ],
    );
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];
    for d in &inv.devices[..inv.count] {
        let mut h = [0u8; 6];
        let mut parts: [&str; 8] = [""; 8];
        parts[0] = "[PCI ] ";
        parts[1] = strutil::dec(u64::from(d.dev), &mut b1);
        parts[2] = ".";
        parts[3] = strutil::dec(u64::from(d.func), &mut b2);
        parts[4] = " ";
        parts[5] = hex4(d.vendor, &mut h);
        parts[6] = ":";
        // vendor:device + class + name, then BARs and caps on their
        // own lines (the array is fixed-size: no formatting crutches).
        line(out, &parts[..7]);
        let mut h2 = [0u8; 6];
        let mut c = [0u8; 6];
        line(
            out,
            &[
                "       ",
                hex4(d.device, &mut h2),
                " class=",
                hex4(d.class, &mut c),
                " ",
                pci::describe(d.vendor, d.device),
            ],
        );
        if !pci::is_endpoint_header(d.header) {
            // F9: a bridge topology this driver stack cannot isolate
            // (single-domain Phase-2 model; devices behind bridges are
            // not enumerated, not claimed, and their DMA fails closed
            // on missing context entries). Say so loudly.
            line(
                out,
                &["[PCI ] bridge at this slot — devices behind it are NOT driven (isolation boundary, F9)"],
            );
        }
        for b in d.bars[..d.bar_count].iter().flatten() {
            let mut hb = [0u8; 18];
            let mut hs = [0u8; 18];
            line(
                out,
                &[
                    "       BAR[",
                    match b.kind {
                        pci::BarKind::Mem64 => "mem64",
                        pci::BarKind::Mem32 => "mem32",
                        pci::BarKind::Io => "io  ",
                    },
                    "] base=",
                    strutil::hex(b.base, &mut hb),
                    " size=",
                    strutil::hex(b.size, &mut hs),
                    if b.prefetchable {
                        " (prefetchable)"
                    } else {
                        ""
                    },
                ],
            );
        }
        if d.cap_count > 0 {
            for i in 0..d.cap_count {
                let mut hc = [0u8; 6];
                line(
                    out,
                    &[
                        "       cap[",
                        strutil::dec(u64::from(d.cap_ptrs[i]), &mut b1),
                        "] ",
                        cap_name(d.cap_ids[i]),
                        " (id=",
                        hex4(u16::from(d.cap_ids[i]), &mut hc),
                        ")",
                    ],
                );
            }
        }
    }

    // The claim gate, live: virtio-blk (vendor 0x1AF4, class 01xx).
    match inv.find_by(0x1AF4, 0x01) {
        None => {
            line(
                out,
                &["[PCI ] claim: no virtio-blk on this machine (nothing to claim)"],
            );
        }
        Some(dev) => {
            let mut bd = [0u8; 20];
            let mut bf = [0u8; 20];
            let rmrr = dmar.rmrr_covers(0, dev.bus, dev.dev, dev.func);
            let claim = pci::check_claim(dev, broker.verdict(), rmrr);
            match claim {
                Err(e) => {
                    line(
                        out,
                        &[
                            "[PCI ] claim: ",
                            strutil::dec(u64::from(dev.dev), &mut bd),
                            ".",
                            strutil::dec(u64::from(dev.func), &mut bf),
                            " REFUSED (",
                            describe_claim_error(e),
                            ")",
                        ],
                    );
                }
                Ok(()) => {
                    let (bus, d, f) = (dev.bus, dev.dev, dev.func);
                    match domains
                        .alloc()
                        .map(|dom| (dom, broker.assign_device(dom, 0, bus, (d, f))))
                    {
                        None => {
                            line(
                                out,
                                &["[PCI ] claim: virtio-blk REFUSED (no free IOMMU domain — ADR-0018)"],
                            );
                        }
                        Some((dom, Ok(()))) => {
                            inv.set_dom(0x1AF4, 0x01, dom);
                            let mut db = [0u8; 20];
                            line(
                                out,
                                &[
                                    "[PCI ] claim: bus=0 dev=",
                                    strutil::dec(u64::from(d), &mut bd),
                                    " fn=",
                                    strutil::dec(u64::from(f), &mut bf),
                                    " (virtio-blk) → dom ",
                                    strutil::dec(u64::from(dom), &mut db),
                                    " ok (broker assigned, ADR-0018)",
                                ],
                            );
                        }
                        Some((dom, Err(e))) => {
                            domains.release(dom);
                            line(
                                out,
                                &[
                                    "[PCI ] claim: broker refused the assignment (",
                                    hw_code(&e),
                                    ")",
                                ],
                            );
                        }
                    }
                }
            }
        }
    };

    // The same claim gate for the network device (vendor 0x1AF4,
    // class 02xx) — Phase 2's net driver runs right after this.
    match inv.find_by(0x1AF4, 0x02) {
        None => {
            line(out, &["[PCI ] claim: no virtio-net on this machine"]);
        }
        Some(dev) => {
            let rmrr = dmar.rmrr_covers(0, dev.bus, dev.dev, dev.func);
            match pci::check_claim(dev, broker.verdict(), rmrr) {
                Err(e) => {
                    line(
                        out,
                        &[
                            "[PCI ] claim: virtio-net REFUSED (",
                            describe_claim_error(e),
                            ")",
                        ],
                    );
                }
                Ok(()) => {
                    let (bus, d, f) = (dev.bus, dev.dev, dev.func);
                    match domains
                        .alloc()
                        .map(|dom| (dom, broker.assign_device(dom, 0, bus, (d, f))))
                    {
                        None => {
                            line(
                                out,
                                &["[PCI ] claim: virtio-net REFUSED (no free IOMMU domain — ADR-0018)"],
                            );
                        }
                        Some((dom, Ok(()))) => {
                            inv.set_dom(0x1AF4, 0x02, dom);
                            let mut db = [0u8; 20];
                            line(
                                out,
                                &[
                                    "[PCI ] claim: virtio-net → dom ",
                                    strutil::dec(u64::from(dom), &mut db),
                                    " ok (broker assigned, ADR-0018)",
                                ],
                            );
                        }
                        Some((dom, Err(e))) => {
                            domains.release(dom);
                            line(
                                out,
                                &[
                                    "[PCI ] claim: broker refused the net assignment (",
                                    hw_code(&e),
                                    ")",
                                ],
                            );
                        }
                    }
                }
            }
        }
    };

    // The claim gate for the e1000 NIC (vendor 0x8086, class 02xx).
    if let Some(dev) = inv.find_by(0x8086, 0x02) {
        let rmrr = dmar.rmrr_covers(0, dev.bus, dev.dev, dev.func);
        match pci::check_claim(dev, broker.verdict(), rmrr) {
            Err(e) => {
                line(
                    out,
                    &[
                        "[PCI ] claim: e1000 REFUSED (",
                        describe_claim_error(e),
                        ")",
                    ],
                );
            }
            Ok(()) => {
                let (bus, d, f) = (dev.bus, dev.dev, dev.func);
                match domains
                    .alloc()
                    .map(|dom| (dom, broker.assign_device(dom, 0, bus, (d, f))))
                {
                    None => {
                        line(
                            out,
                            &["[PCI ] claim: e1000 REFUSED (no free IOMMU domain — ADR-0018)"],
                        );
                    }
                    Some((dom, Ok(()))) => {
                        inv.set_dom(0x8086, 0x02, dom);
                        let mut db = [0u8; 20];
                        line(
                            out,
                            &[
                                "[PCI ] claim: e1000 → dom ",
                                strutil::dec(u64::from(dom), &mut db),
                                " ok (broker assigned, ADR-0018)",
                            ],
                        );
                    }
                    Some((dom, Err(e))) => {
                        domains.release(dom);
                        line(
                            out,
                            &[
                                "[PCI ] claim: broker refused the e1000 assignment (",
                                hw_code(&e),
                                ")",
                            ],
                        );
                    }
                }
            }
        }
    }

    // The claim gate for the NVMe controller (vendor 0x1B36, class
    // 01xx — Red Hat's qemu-nvme).
    if let Some(dev) = inv.find_by(0x1B36, 0x01) {
        let rmrr = dmar.rmrr_covers(0, dev.bus, dev.dev, dev.func);
        match pci::check_claim(dev, broker.verdict(), rmrr) {
            Err(e) => {
                line(
                    out,
                    &["[PCI ] claim: nvme REFUSED (", describe_claim_error(e), ")"],
                );
            }
            Ok(()) => {
                let (bus, d, f) = (dev.bus, dev.dev, dev.func);
                match domains
                    .alloc()
                    .map(|dom| (dom, broker.assign_device(dom, 0, bus, (d, f))))
                {
                    None => {
                        line(
                            out,
                            &["[PCI ] claim: nvme REFUSED (no free IOMMU domain — ADR-0018)"],
                        );
                    }
                    Some((dom, Ok(()))) => {
                        inv.set_dom(0x1B36, 0x01, dom);
                        let mut db = [0u8; 20];
                        line(
                            out,
                            &[
                                "[PCI ] claim: nvme → dom ",
                                strutil::dec(u64::from(dom), &mut db),
                                " ok (broker assigned, ADR-0018)",
                            ],
                        );
                    }
                    Some((dom, Err(e))) => {
                        domains.release(dom);
                        line(
                            out,
                            &[
                                "[PCI ] claim: broker refused the nvme assignment (",
                                hw_code(&e),
                                ")",
                            ],
                        );
                    }
                }
            }
        }
    }

    // The claim gates for AHCI (Intel, class 01xx) and xHCI (Red
    // Hat qemu-xhci, class 0Cxx).
    for (vendor, class_hi, label) in [(0x8086u16, 0x01u8, "ahci"), (0x1B36u16, 0x0Cu8, "xhci")] {
        if let Some(dev) = inv.find_by(vendor, class_hi) {
            let rmrr = dmar.rmrr_covers(0, dev.bus, dev.dev, dev.func);
            match pci::check_claim(dev, broker.verdict(), rmrr) {
                Err(e) => {
                    line(
                        out,
                        &[
                            "[PCI ] claim: ",
                            label,
                            " REFUSED (",
                            describe_claim_error(e),
                            ")",
                        ],
                    );
                }
                Ok(()) => {
                    let (bus, d, f) = (dev.bus, dev.dev, dev.func);
                    match domains
                        .alloc()
                        .map(|dom| (dom, broker.assign_device(dom, 0, bus, (d, f))))
                    {
                        None => {
                            line(
                                out,
                                &[
                                    "[PCI ] claim: ",
                                    label,
                                    " REFUSED (no free IOMMU domain — ADR-0018)",
                                ],
                            );
                        }
                        Some((dom, Ok(()))) => {
                            inv.set_dom(vendor, class_hi, dom);
                            let mut db = [0u8; 20];
                            line(
                                out,
                                &[
                                    "[PCI ] claim: ",
                                    label,
                                    " → dom ",
                                    strutil::dec(u64::from(dom), &mut db),
                                    " ok (broker assigned, ADR-0018)",
                                ],
                            );
                        }
                        Some((dom, Err(e))) => {
                            domains.release(dom);
                            line(
                                out,
                                &[
                                    "[PCI ] claim: broker refused the ",
                                    label,
                                    " assignment (",
                                    hw_code(&e),
                                    ")",
                                ],
                            );
                        }
                    }
                }
            }
        }
    }

    // Dump the context table as the hardware sees it (guest-side
    // ground truth for the device-DMA investigation). No-op without a
    // real unit: the absent broker's root_pa is 0 (guarded — reading
    // through the direct map at unmapped PAs panics by design).
    {
        let root_pa = broker.prot().root_pa();
        if root_pa == 0 {
            return inv;
        }
        let root = crate::memops::read_u64(root_pa);
        if root & 1 != 0 {
            let ct = root & 0x000F_FFFF_FFFF_F000;
            let dfns: [u64; 6] = [0x10, 0x18, 0x20, 0x28, 0x30, 0xF8];
            let v0 = crate::memops::read_u64(ct + dfns[0] * 16 + 8);
            let v1 = crate::memops::read_u64(ct + dfns[1] * 16 + 8);
            let v2 = crate::memops::read_u64(ct + dfns[2] * 16 + 8);
            let v3 = crate::memops::read_u64(ct + dfns[3] * 16 + 8);
            let v4 = crate::memops::read_u64(ct + dfns[4] * 16 + 8);
            let v5 = crate::memops::read_u64(ct + dfns[5] * 16 + 8);
            let mut b0 = [0u8; 18];
            let mut b1 = [0u8; 18];
            let mut b2 = [0u8; 18];
            let mut b3 = [0u8; 18];
            let mut b4 = [0u8; 18];
            let mut b5 = [0u8; 18];
            line(
                out,
                &[
                    "[CTX ] dump: 0x10 hi=0x",
                    strutil::hex(v0, &mut b0),
                    " 0x18 hi=0x",
                    strutil::hex(v1, &mut b1),
                    " 0x20 hi=0x",
                    strutil::hex(v2, &mut b2),
                    " 0x28 hi=0x",
                    strutil::hex(v3, &mut b3),
                    " 0x30 hi=0x",
                    strutil::hex(v4, &mut b4),
                    " 0xF8 hi=0x",
                    strutil::hex(v5, &mut b5),
                ],
            );
        }
    }

    inv
}

/// Capability names for the inventory (diagnostics; unknown = "?").
fn cap_name(id: u8) -> &'static str {
    match id {
        0x05 => "msi",
        0x11 => "msix",
        0x09 => "virtio",
        _ => "?",
    }
}

fn describe_claim_error(e: crate::pci::ClaimError) -> &'static str {
    match e {
        crate::pci::ClaimError::NotEndpoint => "bridge header",
        crate::pci::ClaimError::BridgeClass => "bridge class",
        crate::pci::ClaimError::NoIommu => "no IOMMU (fail-closed)",
        crate::pci::ClaimError::RmrrCovered => "RMRR-covered (unusable, D2)",
    }
}

/// 0x-prefixed 4-digit hex (the marker-friendly form for ids).
fn hex4(v: u16, buf: &mut [u8; 6]) -> &str {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..4 {
        let shift = 12 - 4 * i as u32;
        buf[2 + i] = DIGITS[((v >> shift) & 0xF) as usize];
    }
    core::str::from_utf8(&buf[..6]).unwrap_or("0x????")
}

// ── Phase 2: the virtio-blk driver over the broker (checklist item 5) ──
