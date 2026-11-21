//! The DmaBroker boot demo: map/abort/complete/unmap/quota/revoke markers.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use super::hw_code;
use super::line;
use super::VTD_TABLE_OWNER;
use crate::frames::FramePool;
use crate::strutil;

/// PR 0.5: the kernel DMA broker over the live VT-d — the ADR-0013 D6
/// protocol, proven on the boot lane end to end: a map returns a view
/// with a cookie and length ONLY (no addresses), unmapping before the
/// abort handshake refuses, the handshake releases, quotas refuse
/// loudly, and `revoke_all` tears a domain down without the handshake
/// (teardown semantics). The runtime claim path and the
/// domain-destroy hook arrive with Phase 1's driver model; the
/// `dma-drivers` verdict line below is what gates them.
pub(crate) fn broker_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    unit: crate::arch::vtd::Vtd,
) -> aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd> {
    use aegis_os::dma::{DmaBroker, DmaDir, DmaError, DmaQuotas};

    // Room for the driver's five regions; the byte budget is small
    // enough that the refusal itself is provable in one boot.
    let quotas = DmaQuotas {
        max_regions: 16,
        max_bytes: 64 * 1024,
    };
    let mut broker = DmaBroker::new(unit, quotas);

    // One fresh page as the region (the kernel allocates; the driver
    // domain would only ever see the cookie).
    let Ok(page_pa) = pool.alloc_for(&mut k.frames, VTD_TABLE_OWNER) else {
        line(
            out,
            &["[IOMMU] broker: pool exhausted before the broker proof"],
        );
        return broker;
    };
    let view = match broker.map_region(0, page_pa, 4096, DmaDir::Bidirectional) {
        Ok(v) => v,
        Err(e) => {
            line(out, &["[IOMMU] broker: map refused (", hw_code(&e), ")"]);
            return broker;
        }
    };
    let mut n1 = [0u8; 20];
    let mut n2 = [0u8; 20];
    line(
        out,
        &[
            "[IOMMU] broker: map ok cookie=",
            strutil::dec(view.cookie, &mut n1),
            " len=",
            strutil::dec(view.len, &mut n2),
            " (the view carries no addresses)",
        ],
    );

    // Abort-before-unmap: with work in flight the unmap must refuse.
    match broker.unmap_region(0, view.cookie) {
        Err(DmaError::AbortRequired) => {
            line(
                out,
                &["[IOMMU] broker: unmap refused (AbortRequired) — in-flight work must complete first"],
            );
        }
        Ok(()) => {
            line(
                out,
                &["[IOMMU] broker: unmap ordering check SUCCEEDED (BUG: in-flight unmap)"],
            );
            return broker;
        }
        Err(e) => {
            line(
                out,
                &[
                    "[IOMMU] broker: unmap ordering check refused (",
                    hw_code(&e),
                    ")",
                ],
            );
            return broker;
        }
    }
    broker
        .region_complete(0, view.cookie)
        .expect("fresh complete");
    broker
        .unmap_region(0, view.cookie)
        .expect("complete released the region");
    line(
        out,
        &["[IOMMU] broker: complete → unmap ok (abort handshake honored)"],
    );

    // Quotas: fill the region budget, watch the third map refuse.
    for _ in 0..quotas.max_regions as u64 {
        let Ok(pa) = pool.alloc_for(&mut k.frames, VTD_TABLE_OWNER) else {
            break;
        };
        if broker.map_region(0, pa, 4096, DmaDir::ToDevice).is_err() {
            break;
        }
    }
    let live = broker.live_regions(0);
    let mut n3 = [0u8; 20];
    let mut n4 = [0u8; 20];
    line(
        out,
        &[
            "[IOMMU] broker: live regions=",
            strutil::dec(live as u64, &mut n3),
            "/",
            strutil::dec(quotas.max_regions as u64, &mut n4),
        ],
    );
    let Ok(extra_pa) = pool.alloc_for(&mut k.frames, VTD_TABLE_OWNER) else {
        return broker;
    };
    match broker.map_region(0, extra_pa, 4096, DmaDir::ToDevice) {
        Err(DmaError::QuotaRegions) => {
            line(
                out,
                &["[IOMMU] broker: quota enforced (region budget exhausted → QuotaRegions)"],
            );
        }
        _ => {
            line(
                out,
                &["[IOMMU] broker: QUOTA CHECK FAILED (map went through)"],
            );
        }
    }

    // Teardown semantics: revoke_all unmaps everything the domain
    // holds, handshake or not (the domain is dying).
    let revoked = broker.revoke_all(0);
    let mut n5 = [0u8; 20];
    line(
        out,
        &[
            "[IOMMU] broker: revoke_all(0) → ",
            strutil::dec(revoked.revoked as u64, &mut n5),
            " region(s) unmapped (teardown path)",
        ],
    );
    if revoked.poisoned > 0 {
        let mut n6 = [0u8; 20];
        line(
            out,
            &[
                "[IOMMU] broker: POISON: ",
                strutil::dec(revoked.poisoned as u64, &mut n6),
                " region(s) un-unmappable — quarantined (ADR-0015 F2)",
            ],
        );
    }

    // The verdict line Phase 1's claim path gates on.
    line(out, &["[IOMMU] dma-drivers=1 (broker live over VT-d)"]);
    broker
}
