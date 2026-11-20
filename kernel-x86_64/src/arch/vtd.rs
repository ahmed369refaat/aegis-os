//! VT-d DMA-remapping bring-up + `DmaProt` (ADR-0013, PR 0.4).
//!
//! This is the module that programs the real remapping hardware
//! QEMU's `intel-iommu` exposes through the DRHD at 0xFED9_0000 (found
//! by `arch::acpi`, parsed by `aegis_os::dmar`, both PR 0.3/0.2). The
//! discipline is the LAPIC's (ADR-0012): register map and every entry
//! encoding pure and host-tested; only bring-up touches MMIO, through
//! `memops` (the allowlisted aligned-access layer) and the 4th-GiB
//! window the LAPIC window PTE already maps.
//!
//! ## What bring-up does (and refuses)
//!
//! 1. validate caps: VER must be nonzero, CAP.SAGAW must offer the
//!    4-level/48-bit adjusted guest width our HAW needs, ECAP.QI must
//!    exist (queued invalidation is the invalidation discipline of
//!    record — D3). ECAP.C (coherency) is reported, not gated: QEMU is
//!    trivially coherent; real non-coherent hardware gets a cache
//!    maintenance layer before it gets support (open item, ledger).
//! 2. program: RTADDR ← root table (one pool frame), GCMD.SRTP + spin
//!    RTPS; IQA ← invalidation queue (one pool frame, 256 descriptors),
//!    GCMD.QIE + spin QIES; GCMD.TE + spin TES. Every spin is bounded
//!    (the ADR's no-infinite-spin rule) and its iteration count is
//!    reported in the marker.
//! 3. From then on the type is a `DmaProt` (the ADR-0011 D2 row): root
//!    entries → context tables on demand, context entries → per-domain
//!    4-level second-level tables on demand, identity IOVA per D4, and
//!    a queued IOTLB invalidation after every unmap. All table frames
//!    come from a caller-provided bounded budget — loud exhaustion,
//!    never a guess.
//!
//! ## Unsafe policy: zero
//!
//! Every MMIO access is `memops::read_u32`/`write_u32` at the aligned
//! register offsets (VT-d registers are 4-byte naturally aligned), and
//! every table write is `memops::write_u64` into pool frames. Host
//! tests drive the identical walker code over plain buffers (memops'
//! identity-translate test discipline).
//!
//! ## What is deliberately NOT here
//!
//! - Fault-record parsing (FRO walk): Phase 2's enforcement proof
//!   reads the fault records; for now FSTS lands in a marker so a
//!   remapping fault is visible in every boot log.
//! - Interrupt remapping: `intremap=off` on the lane until the
//!   interrupt-broker ADR owns the IRTE decision (checklist item 3).
//! - Multi-DRHD machines: refused loudly (`UnsupportedMultiDrhd`) —
//!   this machine class (QEMU q35) has exactly one unit (measured).

use aegis_os::dma::{DmaAbsentReason, DmaDir, DmaError, DmaProt, DmaVerdict};
use aegis_os::dmar::{Dmar, DmarStruct, Drhd};
use aegis_os::memory::PAGE_SIZE;

// ── register offsets (VT-d spec; pinned against Linux's DMAR_* map) ──
pub const REG_VER: u64 = 0x00; // 32-bit
pub const REG_CAP: u64 = 0x08; // 64-bit
pub const REG_ECAP: u64 = 0x10; // 64-bit
pub const REG_GCMD: u64 = 0x18; // 32-bit
pub const REG_GSTS: u64 = 0x1C; // 32-bit
pub const REG_RTADDR: u64 = 0x20; // 64-bit
pub const REG_FSTS: u64 = 0x34; // 32-bit
pub const REG_IQH: u64 = 0x80; // 32-bit, read-only
pub const REG_IQT: u64 = 0x88; // 32-bit
pub const REG_IQA: u64 = 0x90; // 64-bit

/// GCMD bit 31: translation enable.
pub const GCMD_TE: u32 = 1 << 31;
/// GCMD bit 30: set root-table pointer.
pub const GCMD_SRTP: u32 = 1 << 30;
/// GCMD bit 26: queued-invalidation enable.
pub const GCMD_QIE: u32 = 1 << 26;
/// GSTS bit 31: translation enabled.
pub const GSTS_TES: u32 = 1 << 31;
/// GSTS bit 30: root-table pointer set.
pub const GSTS_RTPS: u32 = 1 << 30;
/// GSTS bit 26: queued invalidations enabled.
pub const GSTS_QIES: u32 = 1 << 26;

/// FSTS bits that mean "the invalidation machinery is broken": IQE(4)
/// invalidation-queue error, ICE(5) completion error, ITE(6) timeout.
pub const FSTS_INV_ERRORS: u32 = (1 << 4) | (1 << 5) | (1 << 6);
/// FSTS bit 1: primary fault pending — a device hit a remapping fault.
pub const FSTS_PPF: u32 = 1 << 1;

/// CAP bits 7..11: supported AGAWs (bit set per width: 7=32-bit/2L,
/// 8=39/3L, 9=48/4L, 10=57/5L, 11=64/6L).
pub const CAP_SAGAW_4_LEVEL: u64 = 1 << 9;
/// ECAP bit 1: queued invalidation supported.
pub const ECAP_QI: u64 = 1 << 1;
/// ECAP bit 0: page-request coherency (reported, not gated).
pub const ECAP_C: u64 = 1 << 0;

// ── entry encodings (pure, host-pinned below) ──

/// Present bit, shared by root/context/second-level entries.
pub const ENTRY_P: u64 = 1;
/// Second-level leaf: read/write (device may write).
pub const SLPT_W: u64 = 1 << 1;
/// Physical-address mask for table pointers (4 KiB granularity).
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Root entry for `bus`: present + the context-table pointer.
#[must_use]
pub const fn root_entry(ctx_table_pa: u64) -> u64 {
    ENTRY_P | (ctx_table_pa & ADDR_MASK)
}

/// Context entry for a device: present, translation-type 0 (multi-
/// level), **AW = 2** (the 4-level/48-bit page walk — bits 11:8;
/// Linux's `context_set_address_width(ctx, agaw)`. Without it the
/// walk runs TWO levels and reads PML4 slots at the wrong shift:
/// measured "slpte permission error level=2" on the first device
/// DMA), the domain's second-level root. (DID rides the high word —
/// `context_entry_hi`.)
#[must_use]
pub const fn context_entry(slpt_root_pa: u64, _did: u16) -> u64 {
    // TT bits 3:2 = 0b10: QEMU decodes the walk depth as 2+TT (TT=00
    // walks two levels and mis-reads my 4-level tables — measured
    // "slpte permission error level=2" on the first device DMA; bits
    // 11:8 are reserved and rejected outright).
    ENTRY_P | (0b10 << 2) | (slpt_root_pa & ADDR_MASK)
}

/// High word of a context entry: DID at bits 8-23 and **AW = 2 at
/// bits 0-2**. QEMU decodes the walk depth as `2 + (hi & 7)` (and
/// DID as `(hi >> 8) & 0xffff`): with DID riding the low bits QEMU
/// read AW = DID & 7 — a three-level walk over our four-level tree,
/// the measured `slpte permission error (level=0x2, slpte=0x0)` on
/// virtio-net/e1000/NVMe — while virtio-blk/AHCI survived on their
/// context-cache entries from the init proof, whose hand-written
/// context entry carried a correct AW. The mis-placed DID also made
/// every domain-selective IOTLB invalidation match nothing (QEMU
/// saw DID 0), so unmapped pages could stay cached. Both fixed here.
#[must_use]
pub const fn context_entry_hi(did: u16) -> u64 {
    ((did as u64) << 8) | 2
}

/// Second-level leaf PTE for a 4 KiB page.
#[must_use]
pub const fn slpte_leaf(phys: u64, write: bool) -> u64 {
    ENTRY_P | (if write { SLPT_W } else { 0 }) | (phys & ADDR_MASK)
}

/// Second-level non-leaf entry: present, nothing else.
#[must_use]
pub const fn slpte_table(child_pa: u64) -> u64 {
    ENTRY_P | (child_pa & ADDR_MASK)
}

// ── queued-invalidation descriptors (128-bit: 4 words) ──

/// IOTLB invalidation, domain-wide (IG=0b10, no drain bits): the one
/// descriptor Phase 0 needs (after every unmap). Type 0x2.
#[must_use]
pub fn qi_desc_iotlb_domain(did: u16) -> [u64; 4] {
    [0x2 | (0b10 << 4) | ((did as u64) << 16), 0, 0, 0]
}

/// Context-entry invalidation for (bus, devfn) in `did` (type 0x1,
/// GRAN set, DID@16, SID@32 = bus<<8|devfn). Kept for the replace-
/// entry path (Phase 1); fresh entries architecturally need no
/// invalidation — nothing cached an absent entry.
#[must_use]
pub fn qi_desc_context(did: u16, bus: u8, devfn: (u8, u8)) -> [u64; 4] {
    let sid = ((bus as u64) << 8) | (((devfn.0) as u64) << 3) | ((devfn.1) as u64);
    [0x1 | (1 << 4) | ((did as u64) << 16) | (sid << 32), 0, 0, 0]
}

/// Second-level levels for a host address width: 4 for 39 < haw ≤ 48
/// (the QEMU q35 case, HAW=48).
#[must_use]
pub const fn levels_for_haw(haw_bits: u8) -> u8 {
    match haw_bits {
        0..=32 => 2,
        33..=39 => 3,
        40..=48 => 4,
        49..=57 => 5,
        _ => 6,
    }
}

/// CAP.SAGAW bit for a level count (2..=6 → bits 7..=11).
#[must_use]
pub const fn sagaw_bit(levels: u8) -> u64 {
    1 << (levels - 2 + 7)
}

/// Why bring-up refused. Every variant is fail-closed: the caller
/// reports it and the DMA device claim path stays shut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtdError {
    /// No DRHD in the parsed DMAR (the discovery layer already says
    /// absent; defensive here).
    NoDrhd,
    /// This machine class is single-unit; more is out of scope.
    UnsupportedMultiDrhd(usize),
    /// VER register reads zero (dead MMIO window or missing unit).
    BadVer(u32),
    /// CAP.SAGAW lacks the width our HAW needs (carries CAP).
    UnsupportedAgaw { cap: u64, need_bit: u64 },
    /// Phase 0 walks 4-level tables only (the 48-bit width this
    /// machine class has); other widths refuse rather than mis-walk.
    UnsupportedLevels(u8),
    /// ECAP.QI missing: no queued invalidation, no support.
    NoQi(u64),
    /// The bounded table-frame budget ran out (map-time `Hardware`
    /// refusal; the unit itself stays available).
    OutOfTables,
    /// A spin budget expired (GCMD never reported the status bit).
    SpinTimeout(&'static str),
    /// The invalidation queue errored (FSTS carried the detail).
    InvalidationError(u32),
}

/// The caps the validation accepted (marker material).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub ver: u32,
    pub cap: u64,
    pub ecap: u64,
    pub levels: u8,
    pub coherent: bool,
}

/// Validate the raw register reads against the D4/D3 requirements.
#[must_use]
pub fn validate_caps(ver: u32, cap: u64, ecap: u64, haw_bits: u8) -> Result<Caps, VtdError> {
    if ver == 0 {
        return Err(VtdError::BadVer(ver));
    }
    let levels = levels_for_haw(haw_bits);
    let need = sagaw_bit(levels);
    if cap & need == 0 {
        return Err(VtdError::UnsupportedAgaw {
            cap,
            need_bit: need,
        });
    }
    if ecap & ECAP_QI == 0 {
        return Err(VtdError::NoQi(ecap));
    }
    Ok(Caps {
        ver,
        cap,
        ecap,
        levels,
        coherent: ecap & ECAP_C != 0,
    })
}

/// Domains the Phase-0 Vtd tracks (the kernel broker is domain 0;
/// driver domains arrive with the Phase-1 model).
pub const MAX_VTD_DOMAINS: usize = 8;
/// Bounded table-frame budget: root + IQ + context tables + SLPT
/// tables. Loud exhaustion (`OutOfTables`), never a guess.
pub const TABLE_BUDGET: usize = 64;
/// Invalidation-queue descriptors: 256 × 16 B = one pool frame.
pub const IQ_ENTRIES: u32 = 256;
/// IQA.QS encoding for `IQ_ENTRIES` (2^(QS+1) descriptors).
pub const IQ_QS: u64 = 7;

/// The programmed unit. Constructed only through `plan` (caps
/// validated) + `program_and_enable` (hardware sequenced) — a `Vtd`
/// that exists is a unit whose verdict is `Available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vtd {
    reg_base: u64,
    segment: u16,
    haw_bits: u8,
    levels: u8,
    /// MMIO-visible state markers (for the boot log).
    pub caps: Caps,
    root_pa: u64,
    iq_pa: u64,
    /// Descriptor index of the next submission (monotonic; the
    /// hardware head chases it modulo IQ_ENTRIES).
    iq_tail: u32,
    tables: [u64; TABLE_BUDGET],
    table_cursor: usize,
    /// SLPT root per domain (None until `assign_device`).
    dom_slpt: [Option<u64>; MAX_VTD_DOMAINS],
    assigned: u32,
    mapped_pages: u64,
    unmapped_pages: u64,
    /// True only for `Vtd::absent()` — a placeholder that exists so
    /// the fail-closed arm can still hand the driver steps a broker
    /// (whose every operation refuses; verdict Absent). Real units
    /// are only constructed through `plan`.
    disabled: bool,
}

impl Vtd {
    /// The no-hardware placeholder for machines without a DMAR: the
    /// driver steps can still run against a broker whose verdict is
    /// `Absent` (the q35-neg control lane) — every operation refuses.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            reg_base: 0,
            segment: 0,
            haw_bits: 39,
            levels: 4,
            caps: Caps {
                ver: 0,
                cap: 0,
                ecap: 0,
                levels: 4,
                coherent: false,
            },
            root_pa: 0,
            iq_pa: 0,
            iq_tail: 0,
            tables: [0; TABLE_BUDGET],
            table_cursor: 0,
            dom_slpt: [None; MAX_VTD_DOMAINS],
            assigned: 0,
            mapped_pages: 0,
            unmapped_pages: 0,
            disabled: true,
        }
    }

    /// Pure planning: validate caps, consume the first two table
    /// frames (root table, invalidation queue). No MMIO — host tests
    /// construct units this way and drive the whole `DmaProt` surface
    /// over plain buffers.
    #[must_use]
    pub fn plan(
        dmar: &Dmar,
        ver: u32,
        cap: u64,
        ecap: u64,
        tables: &[u64; TABLE_BUDGET],
    ) -> Result<Self, VtdError> {
        // Exactly one DRHD on this machine class; more is out of scope
        // and stated loudly (the multi-unit cluster story is the
        // scalable-mode/IR era, not Phase 0).
        let mut drhd: Option<&Drhd> = None;
        let mut units = 0usize;
        for s in &dmar.structures[..dmar.structure_count] {
            if let DmarStruct::Drhd(d) = s {
                units += 1;
                if drhd.is_none() {
                    drhd = Some(d);
                }
            }
        }
        if units == 0 {
            return Err(VtdError::NoDrhd);
        }
        if units > 1 {
            return Err(VtdError::UnsupportedMultiDrhd(units));
        }
        let drhd = drhd.expect("units >= 1 checked above");
        let caps = validate_caps(ver, cap, ecap, dmar.haw_bits)?;
        if caps.levels != 4 {
            return Err(VtdError::UnsupportedLevels(caps.levels));
        }
        Ok(Vtd {
            reg_base: drhd.reg_base,
            segment: drhd.segment,
            haw_bits: dmar.haw_bits,
            levels: caps.levels,
            caps,
            root_pa: tables[0],
            iq_pa: tables[1],
            iq_tail: 0,
            disabled: false,
            tables: *tables,
            table_cursor: 2,
            dom_slpt: [None; MAX_VTD_DOMAINS],
            assigned: 0,
            mapped_pages: 0,
            unmapped_pages: 0,
        })
    }

    #[must_use]
    pub fn haw_bits(&self) -> u8 {
        self.haw_bits
    }

    #[must_use]
    pub fn segment(&self) -> u16 {
        self.segment
    }

    #[must_use]
    pub fn root_pa(&self) -> u64 {
        self.root_pa
    }

    #[must_use]
    pub fn iq_pa(&self) -> u64 {
        self.iq_pa
    }

    /// Live mapped-page count (telemetry + tests).
    #[must_use]
    pub fn mapped_pages(&self) -> u64 {
        self.mapped_pages
    }

    /// Live unmapped-page count (telemetry + tests).
    #[must_use]
    pub fn unmapped_pages(&self) -> u64 {
        self.unmapped_pages
    }

    /// Next table frame from the bounded budget.
    fn next_table(&mut self) -> Result<u64, VtdError> {
        if self.table_cursor >= self.tables.len() {
            return Err(VtdError::OutOfTables);
        }
        let pa = self.tables[self.table_cursor];
        self.table_cursor += 1;
        Ok(pa)
    }

    /// Devices assigned so far (telemetry + tests).
    #[must_use]
    pub fn assigned_count(&self) -> u32 {
        self.assigned
    }

    /// Table frames consumed so far (tests pin the budget math).
    #[must_use]
    pub fn tables_used(&self) -> usize {
        self.table_cursor
    }
}

// ── second-level page-table walking (memops → host-testable) ──

/// Index of `iova` at `level` (level 1 = PT, 4 = PML4).
const fn slpt_index(iova: u64, level: u8) -> u64 {
    (iova >> (12 + 9 * (level as u64 - 1))) & 0x1FF
}

/// Walk `slpt_root`'s 4-level tables for `iova`, creating intermediate
/// tables on demand from `next_table`, and set the leaf PTE. Pure
/// table logic; all memory through `memops` (host: plain buffers).
fn slpt_map_page(
    slpt_root: u64,
    iova: u64,
    phys: u64,
    write: bool,
    next_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), VtdError> {
    let mut table = slpt_root;
    // levels 4 → 2 create/ descend; level 1 is the leaf write.
    for level in (2..=4u8).rev() {
        let entry_pa = table + slpt_index(iova, level) * 8;
        let entry = crate::memops::read_u64(entry_pa);
        table = if entry & ENTRY_P != 0 {
            entry & ADDR_MASK
        } else {
            let child = next_table().ok_or(VtdError::OutOfTables)?;
            crate::memops::write_u64(entry_pa, slpte_table(child));
            child
        };
    }
    let leaf_pa = table + slpt_index(iova, 1) * 8;
    crate::memops::write_u64(leaf_pa, slpte_leaf(phys, write));
    Ok(())
}

/// Clear the leaf PTE for `iova`. Returns whether a present mapping
/// was actually cleared (false = was already absent — the caller
/// treats repeated unmaps as benign idempotence, per the broker).
fn slpt_unmap_page(slpt_root: u64, iova: u64) -> bool {
    let mut table = slpt_root;
    for level in (2..=4u8).rev() {
        let entry = crate::memops::read_u64(table + slpt_index(iova, level) * 8);
        if entry & ENTRY_P == 0 {
            return false;
        }
        table = entry & ADDR_MASK;
    }
    let leaf_pa = table + slpt_index(iova, 1) * 8;
    let entry = crate::memops::read_u64(leaf_pa);
    if entry & ENTRY_P == 0 {
        return false;
    }
    crate::memops::write_u64(leaf_pa, 0);
    true
}

impl Vtd {
    /// Enqueue one invalidation descriptor into the IQ frame (RAM
    /// writes + tail math only — the doorbell is target-only, so host
    /// tests verify the exact bytes and the wrap).
    fn qi_enqueue(&mut self, desc: &[u64; 4]) {
        let slot = (self.iq_tail % IQ_ENTRIES) as usize;
        let base = self.iq_pa + (slot as u64) * 16;
        crate::memops::write_u64(base, desc[0]);
        crate::memops::write_u64(base + 8, desc[1]);
        crate::memops::write_u64(base + 16, desc[2]);
        crate::memops::write_u64(base + 24, desc[3]);
        self.iq_tail += 1;
    }

    /// The doorbell + hardware drain (target-only: MMIO).
    #[cfg(not(test))]
    fn qi_kick_and_drain(&mut self) -> Result<(), VtdError> {
        // IQT/QIH carry the descriptor index shifted by 4.
        let tail = (self.iq_tail % IQ_ENTRIES) << 4;
        crate::memops::write_u32(self.reg_base + REG_IQT, tail);
        let budget = 1_000_000u64; // bounded: ADR-0013's no-infinite-spin rule
        let mut spins = 0u64;
        while spins < budget {
            let head = crate::memops::read_u32(self.reg_base + REG_IQH);
            if (head >> 4) & (IQ_ENTRIES - 1) == self.iq_tail % IQ_ENTRIES {
                break;
            }
            spins += 1;
        }
        if spins == budget {
            return Err(VtdError::SpinTimeout("IQ drain"));
        }
        let fsts = crate::memops::read_u32(self.reg_base + REG_FSTS);
        if fsts & FSTS_INV_ERRORS != 0 {
            return Err(VtdError::InvalidationError(fsts));
        }
        Ok(())
    }

    #[cfg(test)]
    fn qi_kick_and_drain(&mut self) -> Result<(), VtdError> {
        // Host: the doorbell is MMIO; the enqueue side is fully
        // verified by tests. Drain is trivially "done".
        Ok(())
    }

    /// Read the leaf PTE for `iova` (proof + tests). None when the
    /// walk hits an absent entry.
    #[must_use]
    pub fn slpte_of(&self, slpt_root: u64, iova: u64) -> Option<u64> {
        let mut table = slpt_root;
        for level in (2..=4u8).rev() {
            let entry = crate::memops::read_u64(table + slpt_index(iova, level) * 8);
            if entry & ENTRY_P == 0 {
                return None;
            }
            table = entry & ADDR_MASK;
        }
        let leaf = crate::memops::read_u64(table + slpt_index(iova, 1) * 8);
        (leaf & ENTRY_P != 0).then_some(leaf)
    }

    /// Diagnostics: the four walk entries for `iova` (PML4, PDPT,
    /// PD, PT) from this domain's root — the boot proof prints them
    /// when the device faults and we need to see which link is dead.
    #[must_use]
    pub fn walk_entries(&self, dom: u32, iova: u64) -> [u64; 4] {
        let Some(&Some(root)) = self.dom_slpt.get(dom as usize) else {
            return [0; 4];
        };
        let mut out = [0u64; 4];
        let mut table = root;
        for (i, level) in (2..=4u8).rev().enumerate() {
            let entry = crate::memops::read_u64(table + slpt_index(iova, level) * 8);
            out[i] = entry;
            if entry & ENTRY_P == 0 {
                return out;
            }
            table = entry & ADDR_MASK;
        }
        out[3] = crate::memops::read_u64(table + slpt_index(iova, 1) * 8);
        out
    }

    /// The domain's SLPT root (boot-proof + tests). None until the
    /// domain has a device assigned.
    #[must_use]
    pub fn dom_slpt(&self, dom: u32) -> Option<u64> {
        self.dom_slpt.get(dom as usize).copied().flatten()
    }

    /// The root entry for `bus` (proof + tests).
    #[must_use]
    pub fn root_entry_of(&self, bus: u8) -> u64 {
        crate::memops::read_u64(self.root_pa + (bus as u64) * 16)
    }

    /// The context entry words for `devfn` on `bus` (proof + tests).
    #[must_use]
    pub fn context_entry_of(&self, bus: u8, devfn: (u8, u8)) -> (u64, u64) {
        let root = self.root_entry_of(bus) & ADDR_MASK;
        let devfn_idx = ((devfn.0 as u64) << 3) | (devfn.1 as u64);
        (
            crate::memops::read_u64(root + devfn_idx * 16),
            crate::memops::read_u64(root + devfn_idx * 16 + 8),
        )
    }
}

impl DmaProt for Vtd {
    fn verdict(&self) -> DmaVerdict {
        // A Vtd only exists after caps validated + TE sequenced: the
        // verdict is structural, never optimistic. The one exception
        // is the `absent()` placeholder (no DMAR in the firmware):
        // every broker operation refuses against it.
        if self.disabled {
            return DmaVerdict::Absent {
                reason: DmaAbsentReason::NoDmar,
            };
        }
        DmaVerdict::Available {
            haw_bits: self.haw_bits,
            queued_invalidation: true,
        }
    }

    fn assign_device(
        &mut self,
        dom: u32,
        segment: u16,
        bus: u8,
        devfn: (u8, u8),
    ) -> Result<(), DmaError> {
        if segment != self.segment {
            return Err(DmaError::Hardware(1));
        }
        if dom as usize >= MAX_VTD_DOMAINS {
            return Err(DmaError::Hardware(6));
        }
        let did = dom as usize;
        // Root entry (context table) on demand.
        let root = self.root_entry_of(bus);
        let ctx_table = if root & ENTRY_P != 0 {
            root & ADDR_MASK
        } else {
            let t = self.next_table().map_err(|_| DmaError::Hardware(2))?;
            crate::memops::write_u64(self.root_pa + (bus as u64) * 16, root_entry(t));
            t
        };
        // The domain's SLPT root on demand.
        if self.dom_slpt[did].is_none() {
            let t = self.next_table().map_err(|_| DmaError::Hardware(2))?;
            self.dom_slpt[did] = Some(t);
        }
        let slpt = self.dom_slpt[did].expect("just set");
        // Context entry (fresh: no invalidation needed — an absent
        // entry was never cached; see qi_desc_context for the replace
        // path).
        let devfn_idx = ((devfn.0 as u64) << 3) | (devfn.1 as u64);
        // Domain ids are 1-based in the hardware: DID 0 reads as the
        // "no domain" pattern (QEMU rejects hi=0 entries, measured).
        let did = (dom + 1) as u16;
        crate::memops::write_u64(ctx_table + devfn_idx * 16, context_entry(slpt, did));
        crate::memops::write_u64(ctx_table + devfn_idx * 16 + 8, context_entry_hi(did));
        self.assigned += 1;
        Ok(())
    }

    fn map_run(&mut self, dom: u32, base: u64, len: u64, dir: DmaDir) -> Result<(), DmaError> {
        let did = dom as usize;
        let Some(&Some(slpt)) = self.dom_slpt.get(did) else {
            return Err(DmaError::Hardware(5));
        };
        // Identity IOVA (D4): the device-visible address IS the
        // physical address; writes per direction. The broker has
        // already bounds-checked base+len against the HAW.
        let write = matches!(dir, DmaDir::FromDevice | DmaDir::Bidirectional);
        let tables = &self.tables;
        let mut cursor = self.table_cursor;
        let mut pa = base;
        while pa < base + len {
            let r = slpt_map_page(slpt, pa, pa, write, &mut || {
                if cursor >= TABLE_BUDGET {
                    None
                } else {
                    let t = tables[cursor];
                    cursor += 1;
                    Some(t)
                }
            });
            r.map_err(|_| DmaError::Hardware(3))?;
            self.mapped_pages += 1;
            pa += PAGE_SIZE as u64;
        }
        self.table_cursor = cursor;
        Ok(())
    }

    fn unmap_run(&mut self, dom: u32, base: u64, len: u64) -> Result<(), DmaError> {
        let did = dom as usize;
        let Some(&Some(slpt)) = self.dom_slpt.get(did) else {
            return Err(DmaError::Hardware(5));
        };
        let mut pa = base;
        while pa < base + len {
            if slpt_unmap_page(slpt, pa) {
                self.unmapped_pages += 1;
            }
            pa += PAGE_SIZE as u64;
        }
        // Real hardware caches translations: one domain-wide IOTLB
        // invalidation per unmap, drained and error-checked.
        let desc = qi_desc_iotlb_domain((dom + 1) as u16);
        self.qi_enqueue(&desc);
        self.qi_kick_and_drain()
            .map_err(|_| DmaError::Hardware(4))?;
        Ok(())
    }
}

// ── target bring-up: MMIO sequence (cfg(not(test))) ──

/// Map the 4th GiB window (PA 0xC0000000..0x1_0000_0000) into the
/// direct map — the LAPIC's WINDOW_PTE trick, idempotent. VT-d at
/// 0xFED90000 and q35 PCI MMIO BARs live there. The bring-up caller
/// maps it once before reading any register.
#[cfg(not(test))]
pub fn map_mmio_window() {
    let pml4 = crate::hw::read_cr3() & crate::mm::ADDR_MASK;
    let pdpt = crate::memops::read_u64(pml4 + 273 * 8) & crate::mm::ADDR_MASK;
    crate::memops::write_u64(pdpt + 3 * 8, crate::arch::lapic::WINDOW_PTE);
    crate::hw::write_cr3(pml4);
}

#[cfg(not(test))]
impl Vtd {
    fn read32(&self, off: u64) -> u32 {
        crate::memops::read_u32(self.reg_base + off)
    }

    fn write32(&self, off: u64, v: u32) {
        crate::memops::write_u32(self.reg_base + off, v)
    }

    /// Bounded spin for a GSTS bit. Returns the iterations consumed.
    fn spin_gsts(&self, bit: u32) -> Result<u64, VtdError> {
        let budget = 1_000_000u64;
        let mut spins = 0u64;
        while spins < budget {
            if self.read32(REG_GSTS) & bit != 0 {
                return Ok(spins);
            }
            spins += 1;
        }
        Err(VtdError::SpinTimeout("GSTS"))
    }

    /// Program RTADDR/IQA and sequence SRTP → QIE → TE, each with a
    /// bounded spin. Only reachable from `Vtd::plan` (caps already
    /// validated; the MMIO window already mapped by the caller).
    /// Reports the iteration counts for the boot log.
    pub fn program_and_enable(&mut self) -> Result<(u64, u64, u64), VtdError> {
        // GCMD discipline (Linux's pattern): the register is written
        // as one ACCUMULATED word. QEMU interprets a missing enabled
        // bit as a DISABLE command — measured on this lane: writing
        // TE alone silently disabled the just-enabled invalidation
        // queue ("improper state when disable QI", head=tail=0), every
        // IQT write was then ignored, and the device's first ring DMA
        // hit an untranslated IOVA.
        let mut gcmd: u32 = 0; // bring-up: nothing enabled yet
                               // Root table: legacy RTT (bit 0 clear), 4 KiB-aligned address.
        crate::memops::write_u64(self.reg_base + REG_RTADDR, self.root_pa & ADDR_MASK);
        gcmd |= GCMD_SRTP;
        self.write32(REG_GCMD, gcmd);
        let srtp_spins = self.spin_gsts(GSTS_RTPS)?;
        // Invalidation queue: address + QS order, then enable.
        crate::memops::write_u64(self.reg_base + REG_IQA, (self.iq_pa & ADDR_MASK) | IQ_QS);
        gcmd |= GCMD_QIE;
        self.write32(REG_GCMD, gcmd);
        let qie_spins = self.spin_gsts(GSTS_QIES)?;
        // Translation enable: from here every unclaimed device DMA
        // faults (the fail-closed world ADR-0013 is about).
        gcmd |= GCMD_TE;
        self.write32(REG_GCMD, gcmd);
        let te_spins = self.spin_gsts(GSTS_TES)?;
        Ok((srtp_spins, qie_spins, te_spins))
    }

    /// The raw FSTS (fault status) — marker material; a set PPF means
    /// some device already hit a remapping fault (Phase 2 reads the
    /// fault records themselves).
    #[must_use]
    pub fn fsts(&self) -> u32 {
        self.read32(REG_FSTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host "physical" frames: a **4 KiB-aligned** arena handed to the
    /// Vtd as its bounded table budget (memops translates by identity
    /// in test builds). Alignment is load-bearing: VT-d table pointers
    /// mask to 4 KiB boundaries by architecture — pool frames on the
    /// target are page-aligned, and the arena must be too or the
    /// encodings legitimately round it.
    struct Arena {
        words: Vec<u64>,
        base: u64,
    }

    impl Arena {
        fn new(frames: usize) -> Self {
            // One slack frame absorbs the heap pointer's misalignment.
            let words = vec![0u64; frames * 512 + 512];
            let base = ((words.as_ptr() as u64) + 0xFFF) & !0xFFF;
            Arena { words, base }
        }
        fn pa(&self, frame: usize) -> u64 {
            self.base + (frame * 4096) as u64
        }
        fn read(&self, pa: u64) -> u64 {
            crate::memops::read_u64(pa)
        }
        fn write(&self, pa: u64, v: u64) {
            crate::memops::write_u64(pa, v)
        }
    }

    /// A DMAR with one DRHD (seg 0, 0xFED90000, include_all, no
    /// scopes) — the QEMU shape with the HAW we boot with.
    fn dmar_48() -> Dmar {
        Dmar {
            haw_bits: 48,
            intr_remap: false,
            x2apic_opt_out: false,
            structures: [DmarStruct::Drhd(Drhd {
                segment: 0,
                include_all: true,
                reg_base: 0xFED9_0000,
                scopes: [aegis_os::dmar::DeviceScope {
                    kind: aegis_os::dmar::ScopeType::Reserved(0),
                    enumeration_id: 0,
                    start_bus: 0,
                    path: [(0, 0); aegis_os::dmar::MAX_SCOPE_PATH],
                    path_len: 0,
                }; aegis_os::dmar::MAX_SCOPES],
                scope_count: 0,
            }); aegis_os::dmar::MAX_STRUCTS],
            structure_count: 1,
        }
    }

    /// QEMU-like caps: SAGAW with 3+4 level bits, QI+C set.
    const CAP_QEMU: u64 = (1 << 8) | CAP_SAGAW_4_LEVEL | (47 << 16);
    const ECAP_QEMU: u64 = ECAP_QI | ECAP_C;

    fn plan_vtd(arena: &Arena) -> Result<Vtd, VtdError> {
        let mut tables = [0u64; TABLE_BUDGET];
        for (i, slot) in tables.iter_mut().enumerate() {
            *slot = arena.pa(i);
        }
        Vtd::plan(&dmar_48(), 0x10, CAP_QEMU, ECAP_QI | ECAP_C, &tables)
    }

    #[test]
    fn register_offsets_match_the_spec() {
        // Pinned against Linux's DMAR_* map (battle-tested on hardware
        // and QEMU alike): a wrong offset writes a neighboring
        // register — the exact bug class worth pinning.
        assert_eq!(REG_VER, 0x00);
        assert_eq!(REG_CAP, 0x08);
        assert_eq!(REG_ECAP, 0x10);
        assert_eq!(REG_GCMD, 0x18);
        assert_eq!(REG_GSTS, 0x1C);
        assert_eq!(REG_RTADDR, 0x20);
        assert_eq!(REG_FSTS, 0x34);
        assert_eq!(REG_IQH, 0x80);
        assert_eq!(REG_IQT, 0x88);
        assert_eq!(REG_IQA, 0x90);
        // Command/status bit pairs.
        assert_eq!(GCMD_TE, 1 << 31);
        assert_eq!(GCMD_SRTP, 1 << 30);
        assert_eq!(GCMD_QIE, 1 << 26);
        assert_eq!(GSTS_TES, 1 << 31);
        assert_eq!(GSTS_RTPS, 1 << 30);
        assert_eq!(GSTS_QIES, 1 << 26);
    }

    #[test]
    fn entry_encodings_are_pinned() {
        assert_eq!(root_entry(0x1000), 0x1001);
        assert_eq!(
            root_entry(0xFED9_0000) & 0xFFF,
            1,
            "present, address low bits masked"
        );
        // Context: present, TT=0, AW=2 (4-level), SLPTPTR; DID high.
        let lo = context_entry(0x2000, 5);
        assert_eq!(lo & 0xFFF, 0x9, "P | TT=0b10 (the 4-level walk)");
        assert_eq!(lo & ADDR_MASK, 0x2000);
        assert_eq!(
            lo & (3 << 2),
            0b10 << 2,
            "TT=0b10 (QEMU's 4-level walk selector)"
        );
        assert_eq!(
            context_entry_hi(5),
            (5 << 8) | 2,
            "DID at bits 8-23, AW=2 (the 4-level walk) in the high word"
        );
        // SLPT leaves: P, W per direction, frame address.
        assert_eq!(slpte_leaf(0x7000, false), 0x7001);
        assert_eq!(slpte_leaf(0x7000, true), 0x7003);
        assert_eq!(slpte_table(0x9000), 0x9001);
        assert_eq!(slpte_table(0x9000) & SLPT_W, 0, "non-leaf carries no W");
    }

    #[test]
    fn qi_descriptors_are_pinned() {
        // IOTLB domain-wide: type 2, IG=0b10, DID at 16, all else zero.
        let d = qi_desc_iotlb_domain(3);
        assert_eq!(d[0], 0x2 | (0b10 << 4) | (3 << 16));
        assert_eq!((d[1], d[2], d[3]), (0, 0, 0));
        // Context-entry invalidation: type 1, GRAN, DID@16, SID@32.
        let c = qi_desc_context(3, 0x02, (0x03, 0));
        assert_eq!(c[0] & 0xF, 1);
        assert_eq!(c[0] & (1 << 4), 1 << 4);
        assert_eq!((c[0] >> 16) & 0xFFFF, 3);
        assert_eq!((c[0] >> 32) & 0xFFFF, (0x02 << 8) | (0x03 << 3));
    }

    #[test]
    fn haw_to_levels_and_sagaw_math() {
        assert_eq!(levels_for_haw(32), 2);
        assert_eq!(levels_for_haw(39), 3);
        assert_eq!(levels_for_haw(48), 4);
        assert_eq!(levels_for_haw(57), 5);
        assert_eq!(levels_for_haw(64), 6);
        assert_eq!(sagaw_bit(4), 1 << 9, "4-level is SAGAW bit 9");
        assert_eq!(sagaw_bit(3), 1 << 8);
    }

    #[test]
    fn caps_validation_accepts_qemu_and_refuses_the_rest() {
        let ok = validate_caps(0x10, CAP_QEMU, ECAP_QEMU, 48).unwrap();
        assert_eq!(ok.levels, 4);
        assert!(ok.coherent);
        // Dead window: VER 0.
        assert_eq!(
            validate_caps(0, CAP_QEMU, ECAP_QEMU, 48),
            Err(VtdError::BadVer(0))
        );
        // SAGAW without the 4-level bit (only 3-level offered).
        assert_eq!(
            validate_caps(0x10, 1 << 8, ECAP_QEMU, 48),
            Err(VtdError::UnsupportedAgaw {
                cap: 1 << 8,
                need_bit: 1 << 9
            })
        );
        // No QI: no support.
        assert_eq!(validate_caps(0x10, CAP_QEMU, 0, 48), Err(VtdError::NoQi(0)));
        // A 39-bit HAW needs 3 levels and accepts the 3-level-only cap.
        assert!(validate_caps(0x10, 1 << 8, ECAP_QEMU, 39).is_ok());
    }

    #[test]
    fn plan_takes_the_first_two_frames_and_refuses_multi_drhd() {
        let arena = Arena::new(TABLE_BUDGET);
        let vtd = plan_vtd(&arena).unwrap();
        assert_eq!(vtd.root_pa(), arena.pa(0));
        assert_eq!(vtd.iq_pa(), arena.pa(1));
        assert_eq!(vtd.tables_used(), 2, "root + IQ");
        assert_eq!(vtd.segment(), 0);
        assert_eq!(vtd.haw_bits(), 48);
        // Two DRHDs: refused loudly for Phase 0.
        let mut d = dmar_48();
        d.structures[1] = d.structures[0];
        d.structure_count = 2;
        let mut tables = [0u64; TABLE_BUDGET];
        for (i, slot) in tables.iter_mut().enumerate() {
            *slot = arena.pa(i);
        }
        assert_eq!(
            Vtd::plan(&d, 0x10, CAP_QEMU, ECAP_QEMU, &tables),
            Err(VtdError::UnsupportedMultiDrhd(2))
        );
        // No DRHD at all.
        let mut d = dmar_48();
        d.structure_count = 0;
        assert_eq!(
            Vtd::plan(&d, 0x10, CAP_QEMU, ECAP_QEMU, &tables),
            Err(VtdError::NoDrhd)
        );
    }

    #[test]
    fn verdict_is_structural_available() {
        let arena = Arena::new(TABLE_BUDGET);
        let vtd = plan_vtd(&arena).unwrap();
        assert_eq!(
            vtd.verdict(),
            DmaVerdict::Available {
                haw_bits: 48,
                queued_invalidation: true
            }
        );
    }

    #[test]
    fn assign_device_builds_root_context_and_slpt() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        // Root entry for bus 0 is present and points at a frame.
        let re = vtd.root_entry_of(0);
        assert_eq!(re & 1, 1);
        let _ctx_table = re & ADDR_MASK;
        // Context entry for devfn 00:03.0: present, DID 0, SLPT root.
        let (lo, hi) = vtd.context_entry_of(0, (0x03, 0));
        assert_eq!(lo & 1, 1);
        assert_eq!(lo & ADDR_MASK, vtd.dom_slpt[0].unwrap());
        assert_eq!(
            (hi >> 8) & 0xFFFF,
            1,
            "DIDs are 1-based (dom 0 → DID 1), at QEMU's bits 8-23"
        );
        assert_eq!(hi & 7, 2, "AW=2: QEMU walks 2+(hi&7)=4 levels");
        // The context table frame came from the budget.
        assert_eq!(vtd.tables_used(), 4, "root + IQ + ctx table + SLPT root");
        // Wrong segment: refused.
        assert!(vtd.assign_device(0, 1, 0, (0x03, 0)).is_err());
        // Dom id out of range: refused.
        assert!(vtd
            .assign_device(MAX_VTD_DOMAINS as u32, 0, 0, (0x03, 0))
            .is_err());
    }

    #[test]
    fn map_run_sets_identity_ptes_per_direction() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        let slpt = vtd.dom_slpt[0].unwrap();
        // 2 MiB-aligned so the four maps provably share one leaf
        // table regardless of where the heap put the arena.
        let pa = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        vtd.map_run(0, pa, 4096, DmaDir::ToDevice).unwrap();
        assert_eq!(
            vtd.slpte_of(slpt, pa).unwrap(),
            pa | 1,
            "identity IOVA, read-only"
        );
        vtd.map_run(0, pa + 4096, 4096, DmaDir::FromDevice).unwrap();
        assert_eq!(vtd.slpte_of(slpt, pa + 4096).unwrap(), (pa + 4096) | 3);
        vtd.map_run(0, pa + 8192, 4096, DmaDir::Bidirectional)
            .unwrap();
        assert_eq!(vtd.slpte_of(slpt, pa + 8192).unwrap(), (pa + 8192) | 3);
        assert_eq!(vtd.mapped_pages(), 3);
        // Same-2 MiB maps allocate nothing; a fresh 1 GiB region
        // allocates exactly one PD and one PT.
        let used_before = vtd.tables_used();
        vtd.map_run(0, pa + 12_288, 4096, DmaDir::ToDevice).unwrap();
        assert_eq!(
            vtd.tables_used(),
            used_before,
            "same-region map allocates nothing"
        );
        vtd.map_run(0, pa + (1 << 30), 4096, DmaDir::ToDevice)
            .unwrap();
        assert_eq!(
            vtd.tables_used(),
            used_before + 2,
            "new 1 GiB chain: PD + PT"
        );
    }

    #[test]
    fn unmap_run_clears_ptes_and_enqueues_iotlb_invalidation() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        let slpt = vtd.dom_slpt[0].unwrap();
        let pa = arena.pa(20);
        vtd.map_run(0, pa, 8192, DmaDir::Bidirectional).unwrap();
        vtd.unmap_run(0, pa, 8192).unwrap();
        assert_eq!(vtd.slpte_of(slpt, pa), None, "leaf cleared");
        assert_eq!(vtd.slpte_of(slpt, pa + 4096), None);
        assert_eq!(vtd.unmapped_pages(), 2);
        // The invalidation descriptor landed in the IQ frame, slot 0
        // (DID 1: domains are 1-based in the hardware).
        let qw0 = arena.read(vtd.iq_pa());
        assert_eq!(
            qw0,
            0x2 | (0b10 << 4) | (1 << 16),
            "IOTLB domain-wide, did=1"
        );
        // Unmapping again is benign idempotence (no page counted twice).
        vtd.unmap_run(0, pa, 8192).unwrap();
        assert_eq!(vtd.unmapped_pages(), 2);
        assert_eq!(
            arena.read(vtd.iq_pa() + 16),
            0x2 | (0b10 << 4) | (1 << 16),
            "second desc at slot 1"
        );
    }

    #[test]
    fn map_before_assign_is_refused() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        assert!(vtd
            .map_run(0, arena.pa(20), 4096, DmaDir::ToDevice)
            .is_err());
        assert!(vtd.unmap_run(7, arena.pa(20), 4096).is_err());
    }

    #[test]
    fn table_budget_exhaustion_is_loud_and_partial() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        // Deterministic exhaustion: consume the budget by hand, then
        // watch allocations that need more frames refuse. (Driving it
        // via address strides would depend on heap placement — the
        // exact flakiness the pinned-2 MiB test above avoids.)
        vtd.table_cursor = TABLE_BUDGET - 2;
        let pa = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        // assign_device needs exactly two frames (ctx table + SLPT
        // root): it succeeds and empties the budget...
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        assert_eq!(vtd.tables_used(), TABLE_BUDGET);
        // ...so the first map — which needs a fresh chain — refuses.
        assert!(
            vtd.map_run(0, pa, 4096, DmaDir::ToDevice).is_err(),
            "no frames for the chain"
        );
        // The verdict stays available: exhaustion is a map-time
        // refusal, not a dead unit.
        assert!(matches!(vtd.verdict(), DmaVerdict::Available { .. }));
    }

    #[test]
    fn slpt_index_math_spans_the_levels() {
        // Level 1 (PT): bits 20:12; level 2 (PD): 29:21; level 3
        // (PDPT): 38:30; level 4 (PML4): 47:39. One bit per level.
        assert_eq!(slpt_index(0x123_456_789, 1), 0x56);
        assert_eq!(slpt_index(1 << 39, 4), 1);
        assert_eq!(slpt_index(1 << 30, 3), 1);
        assert_eq!(slpt_index(1 << 21, 2), 1);
        assert_eq!(slpt_index(1 << 47, 4), 256);
        assert_eq!(slpt_index(0x1FF << 12, 1), 0x1FF);
    }
}
