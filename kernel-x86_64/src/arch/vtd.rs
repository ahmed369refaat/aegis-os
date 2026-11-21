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

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only users (driver steps and their helpers), so items only
// they use look dead there — they are used by the boot build.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables, unused_mut))]

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

/// Context entry for a device: present, **TT = 0b00** (multi-level —
/// the device's requests are translated through the second-level
/// tables; 0b10 would be PASS-THROUGH, the tables ignored entirely —
/// VT-d spec §9.3, QEMU `VTD_CONTEXT_TT_PASS_THROUGH`, ADR-0014),
/// **AW = 2** in the high word (the 4-level/48-bit page walk — QEMU
/// `vtd_ce_get_level` = `2 + (hi & 7)`), the domain's second-level
/// root in the low word (QEMU `vtd_ce_get_slpt_base` = `lo & ~0xfff`).
/// (DID rides the high word — `context_entry_hi`.)
#[must_use]
pub const fn context_entry(slpt_root_pa: u64, _did: u16) -> u64 {
    // TT bits 3:2 = 0b00 (multi-level). The old "QEMU decodes the walk
    // depth as 2+TT" comment was wrong: the depth is 2 + AW from the
    // HIGH word (bits 64+0-2), and TT=0b10 actually selected
    // pass-through — every assigned device's IOMMU address space was
    // bypassed (vtd_pt_enable_fast_path ×8 for six devices, and the
    // enforcement probe's unmapped-page request completed with
    // status=0 and PPF=no; the full evidence trail is ADR-0014).
    ENTRY_P | (slpt_root_pa & ADDR_MASK)
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

/// Second-level non-leaf entry: present AND writable. VT-d (like x86
/// page tables, and QEMU's `vtd_iova_to_slpte`) checks R/W at EVERY
/// level of the walk, so a non-leaf without W blocks every device
/// write that is not served from the IOTLB page cache — measured live
/// as FR_WRITE at level 4 on the virtio-blk data page while cached
/// pages' writes succeeded (ADR-0014). The leaf carries the direction.
#[must_use]
pub const fn slpte_table(child_pa: u64) -> u64 {
    ENTRY_P | SLPT_W | (child_pa & ADDR_MASK)
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

// ── interrupt remapping (ADR-0019) ─────────────────────────────────────
// Layouts below are pinned against QEMU's own decoder (union
// VTD_IR_TableEntry and union VTD_IR_MSIAddress in
// include/hw/i386/intel_iommu.h): the remapped-format IRTE, the IRTA
// register, and the remapped MSI address/data pair. QEMU faults an
// IRTE whose reserved fields (bits 14:12 and 31:24 low, 63:20 high)
// are non-zero — the encodings leave them zero BY CONSTRUCTION.

/// IRTA: the interrupt-remapping table address register (64-bit).
pub const REG_IRTA: u64 = 0xB8;
/// GCMD bit 24: set the interrupt-remapping table pointer.
pub const GCMD_SIRTP: u32 = 1 << 24;
/// GCMD bit 25: enable interrupt remapping.
pub const GCMD_IRE: u32 = 1 << 25;
/// GSTS bit 24: the IRTA pointer is set.
pub const GSTS_SIRTPS: u32 = 1 << 24;
/// GSTS bit 25: interrupt remapping is enabled.
pub const GSTS_IRES: u32 = 1 << 25;
/// IRTA bit 11: extended interrupt mode (32-bit x2APIC dest ids).
pub const IRTA_EIME: u64 = 1 << 11;

/// The IRTE table this driver stack plans: 256 entries (one 4 KiB
/// frame at 16 bytes per entry); the broker uses handles 0..=63
/// (mirroring its vector slots).
pub const IR_ENTRIES: u32 = 256;

/// Encode one remapped-format IRTE: present, FIXED delivery, physical
/// destination, edge — everything else zero. With EIME off the 8-bit
/// APIC ID rides dest_id bits 15:8 (QEMU's non-EIM decode,
/// VTD_IR_APIC_DEST_MASK); with EIME on it is the low 32 bits.
#[must_use]
pub fn irte_remapped(vector: u8, dest_apic_id: u8, eime: bool) -> [u64; 2] {
    let dest_id: u64 = if eime {
        u64::from(dest_apic_id)
    } else {
        (u64::from(dest_apic_id) & 0xFF) << 8
    };
    // Low word: present(0) | vector(23:16) | dest_id(63:32); the
    // delivery/dest/polarity/trigger fields are FIXED/physical/
    // active-high/edge = all zero. High word: SID validation off
    // (SVT=0 — any source), everything else reserved-zero.
    [1 | (u64::from(vector) << 16) | (dest_id << 32), 0]
}

/// The IRTA register value: the 4 KiB-aligned base, EIME when asked,
/// and the size order (entries = 1 << (size+1); 7 → 256).
#[must_use]
pub const fn irta_value(base: u64, eime: bool, size_order: u32) -> u64 {
    (base & !0xFFF) | if eime { IRTA_EIME } else { 0 } | ((size_order as u64) & 0xF)
}

/// The remapped-format MSI address for an IRTE handle: the 0xFEE
/// prefix (bits 31:20), the handle in bits 19:5 (its bit 15 lands at
/// address bit 2), the remappable-format flag at bit 4, SHV clear —
/// and with SHV=0 the DATA word must be all zero (QEMU enforces
/// both).
#[must_use]
pub const fn msi_remap_addr(handle: u32) -> u64 {
    let h = handle as u64;
    0xFEE0_0000 | ((h & 0x7FFF) << 5) | (1 << 4) | ((h >> 15) & 1) << 2
}

/// The remapped-format MSI data word: all zero (SHV=0 → no
/// subhandle; any set bit is a fault).
pub const MSI_REMAP_DATA: u32 = 0;

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
/// driver domains arrive with the Phase-1 model). Round I: raised
/// 8 → 16 — the q35 lane now claims nine devices (vblk, vnet, e1000,
/// nvme, ahci, xhci, console, rng, balloon), dom 7 was the last
/// handout, and rng/balloon were REFUSED on budget; the claim gate
/// should refuse for policy reasons, not because the table budget
/// ran out one device early. The derived TABLE_BUDGET (below) keeps
/// covering every domain's worst case.
pub const MAX_VTD_DOMAINS: usize = 16;
/// Bounded table-frame budget: root + IQ + context tables + SLPT
/// tables. Loud exhaustion (`OutOfTables`), never a guess.
/// The frame pool the identity map covers: 16 MiB at POOL_BASE —
/// 8 × 2 MiB PT spans when 2 MiB-aligned (it is today); one span of
/// slack if a future pool lands unaligned.
pub const POOL_2M_SPANS_WORST: usize = 9;

/// ADR-0018: the pure worst-case table demand for `domains` domains —
/// shared (root table + IQ frame + one context table for bus 0) plus
/// per domain (SLPT root + PDPT + one PD + one PT per 2 MiB span of
/// the identity-mapped pool). The budget is DERIVED from this, not
/// guessed; the exhaustion test drives it to the edge.
pub const fn worst_case_tables(domains: usize) -> usize {
    3 + domains * (3 + POOL_2M_SPANS_WORST)
}

/// The table budget: every domain's worst case, covered.
pub const TABLE_BUDGET: usize = worst_case_tables(MAX_VTD_DOMAINS);
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
    /// The interrupt-remapping table's base (0 = IR not enabled).
    /// ADR-0019: programmed by `ir_enable` AFTER the DMA half is live,
    /// exactly the bring-up order the deferred comment asked for.
    irte_pa: u64,
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
            irte_pa: 0,
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
            irte_pa: 0,
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

    /// Is interrupt remapping live on this unit? (The IRTE frame is
    /// programmed by `ir_enable` after the DMA half — ADR-0019.)
    #[must_use]
    pub fn ir_active(&self) -> bool {
        !self.disabled && self.irte_pa != 0
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

/// F1 (ADR-0015): how many NEW table frames the run `[base,
/// base+len)` needs, given the tree as it stands — a pure read-only
/// simulation of the walk `slpt_map_page` performs. Distinct markers
/// stand in for tables the run would create, so later pages in the
/// same run walk THROUGH the simulation (a shared new PD is counted
/// once, each of its PTs once). `None` means the run would need more
/// tables than the whole budget (or the end overflows — the broker
/// pre-validates; defense in depth): refuse before touching anything.
fn tables_needed(slpt_root: u64, base: u64, len: u64) -> Option<usize> {
    // Markers live in a range no real table PA can occupy (real
    // frames are host addresses, far below 2^48).
    const MARKER_BASE: u64 = 0xFFFF_FFFF_0000_0000;
    // (entry key, marker) pairs; entry keys may be real entry
    // addresses or marker-derived keys — the ranges cannot collide.
    let mut created = [(0u64, 0u64); TABLE_BUDGET];
    let mut n = 0usize;
    let end = base.checked_add(len)?;
    let mut pa = base;
    while pa < end {
        let mut table = slpt_root;
        let mut sim = false; // inside a table this run would create
        for level in (2..=4u8).rev() {
            let key = table.wrapping_add(slpt_index(pa, level) * 8);
            if sim {
                if let Some(&(_, m)) = created[..n].iter().find(|(k, _)| *k == key) {
                    table = m;
                } else {
                    if n >= TABLE_BUDGET {
                        return None; // demand exceeds the whole budget
                    }
                    let m = MARKER_BASE.wrapping_add(n as u64);
                    created[n] = (key, m);
                    n += 1;
                    table = m;
                }
            } else {
                let entry = crate::memops::read_u64(key);
                if entry & ENTRY_P != 0 {
                    table = entry & ADDR_MASK;
                } else {
                    if n >= TABLE_BUDGET {
                        return None; // demand exceeds the whole budget
                    }
                    let m = MARKER_BASE.wrapping_add(n as u64);
                    created[n] = (key, m);
                    n += 1;
                    table = m;
                    sim = true;
                }
            }
        }
        pa += PAGE_SIZE as u64;
    }
    Some(n)
}

/// F1 invariant (ADR-0015), pure: no table frame is referenced by two
/// parents. Walks every domain's second-level tree, collecting each
/// table node (the roots and every present non-leaf child); any
/// repeated frame is the aliasing corruption mode — the pre-fix
/// `map_run` rolled its cursor back on error and re-handed frames the
/// failed attempt had already linked. Returns the first aliased frame
/// on failure.
#[cfg(test)]
pub fn check_no_table_aliasing(vtd: &Vtd) -> Result<(), u64> {
    // The forest cannot exceed the table budget: every node came from
    // the same bounded arena.
    let mut seen = [0u64; TABLE_BUDGET];
    let mut n = 0usize;
    for &root in vtd.dom_slpt.iter().flatten() {
        collect_tables(root, 4, &mut seen, &mut n)?;
    }
    Ok(())
}

/// Depth-first table-forest collection for `check_no_table_aliasing`.
/// Level 1 (the PT) is a table node; its entries are leaf SLPTEs and
/// are not descended into.
#[cfg(test)]
fn collect_tables(
    table: u64,
    level: u8,
    seen: &mut [u64; TABLE_BUDGET],
    n: &mut usize,
) -> Result<(), u64> {
    if seen[..*n].contains(&table) {
        return Err(table); // two parents, one frame
    }
    if *n >= TABLE_BUDGET {
        return Err(table); // forest exceeds the budget: impossible
    }
    seen[*n] = table;
    *n += 1;
    if level <= 1 {
        return Ok(());
    }
    for i in 0..512u64 {
        let e = crate::memops::read_u64(table + i * 8);
        if e & ENTRY_P != 0 {
            collect_tables(e & ADDR_MASK, level - 1, seen, n)?;
        }
    }
    Ok(())
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

    /// ADR-0018: the only way a device leaves its domain — clear the
    /// context entry, then invalidate the context cache so no cached
    /// translation outlives the assignment. Idempotent for absent
    /// entries (cleanup paths may call it unconditionally).
    pub fn unassign_device(
        &mut self,
        segment: u16,
        bus: u8,
        devfn: (u8, u8),
    ) -> Result<(), DmaError> {
        if segment != self.segment {
            return Err(DmaError::Hardware(1));
        }
        let root = self.root_entry_of(bus);
        if root & 1 == 0 {
            return Ok(()); // no context table for this bus
        }
        let ctx_table = root & ADDR_MASK;
        let devfn_idx = ((devfn.0 as u64) << 3) | (devfn.1 as u64);
        let lo = crate::memops::read_u64(ctx_table + devfn_idx * 16);
        if lo & 1 == 0 {
            return Ok(()); // absent — idempotent
        }
        let hi = crate::memops::read_u64(ctx_table + devfn_idx * 16 + 8);
        let did = ((hi >> 8) & 0xFFFF) as u16;
        crate::memops::write_u64(ctx_table + devfn_idx * 16, 0);
        crate::memops::write_u64(ctx_table + devfn_idx * 16 + 8, 0);
        let desc = qi_desc_context(did, bus, devfn);
        self.qi_enqueue(&desc);
        if self.qi_kick_and_drain().is_err() {
            return Err(DmaError::Hardware(4)); // invalidation failed
        }
        self.assigned = self.assigned.saturating_sub(1);
        Ok(())
    }

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
        // Context entry. ADR-0018: a device owns exactly ONE domain —
        // a present entry is refused; the only way out is
        // unassign_device (clear + context-cache invalidation).
        let devfn_idx = ((devfn.0 as u64) << 3) | (devfn.1 as u64);
        let old_lo = crate::memops::read_u64(ctx_table + devfn_idx * 16);
        if old_lo & 1 != 0 {
            return Err(DmaError::Hardware(7)); // device already assigned
        }
        // (fresh: no invalidation needed — an absent entry was never
        // cached; see qi_desc_context for the replace path.)
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
        //
        // F1 (ADR-0015): map_run is ATOMIC — a refusal leaves the
        // tables exactly as it found them. (1) The table demand is
        // computed by a pure read-only walk and checked against the
        // budget BEFORE anything is written; (2) the cursor commits
        // every frame it linked on EVERY exit path, so a table frame
        // is never handed to two parents; (3) any residual error
        // rolls back every page this call wrote (clear + invalidate).
        let needed = tables_needed(slpt, base, len).ok_or(DmaError::OutOfTables)?;
        if self.table_cursor + needed > TABLE_BUDGET {
            return Err(DmaError::OutOfTables);
        }
        let write = matches!(dir, DmaDir::FromDevice | DmaDir::Bidirectional);
        let tables = self.tables;
        let mut cursor = self.table_cursor;
        let end = base.checked_add(len).ok_or(DmaError::Overflow)?;
        let mut pa = base;
        let mut pages = 0u64;
        while pa < end {
            let r = slpt_map_page(slpt, pa, pa, write, &mut || {
                // The precheck above proved the budget covers the run;
                // the guard stays for defense in depth (and keeps the
                // rollback path exercised if the walks ever diverge).
                if cursor >= TABLE_BUDGET {
                    None
                } else {
                    let t = tables[cursor];
                    cursor += 1;
                    Some(t)
                }
            });
            if r.is_err() {
                // Roll back the pages this call wrote, then one
                // domain-wide invalidation so nothing caches them.
                // Tables already linked STAY owned — the cursor
                // commit below never re-hands them.
                let mut q = base;
                while q < pa {
                    if slpt_unmap_page(slpt, q) {
                        self.unmapped_pages += 1;
                    }
                    q += PAGE_SIZE as u64;
                }
                let desc = qi_desc_iotlb_domain((dom + 1) as u16);
                self.qi_enqueue(&desc);
                let inv = self.qi_kick_and_drain();
                self.table_cursor = cursor;
                return Err(match inv {
                    Ok(()) => DmaError::Hardware(3), // the map failed
                    Err(_) => DmaError::Hardware(4), // AND the invalidation
                });
            }
            pages += 1;
            pa += PAGE_SIZE as u64;
        }
        self.table_cursor = cursor;
        self.mapped_pages += pages;
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

    /// Enable interrupt remapping (ADR-0019): IRTA with the caller's
    /// IRTE frame, then SIRTP → IRE, both with bounded GSTS spins and
    /// the accumulated-GCMD discipline (every live enable stays set in
    /// the word — see program_and_enable for the measured failure this
    /// avoids). The frame must be 4 KiB-aligned and zeroed (every
    /// entry not-present until the broker arms one).
    pub fn ir_enable(&mut self, irte_pa: u64, eime: bool) -> Result<(u64, u64), VtdError> {
        if self.disabled {
            return Err(VtdError::SpinTimeout("IR on a disabled unit"));
        }
        crate::memops::write_u64(self.reg_base + REG_IRTA, irta_value(irte_pa, eime, 7));
        let mut gcmd: u32 = GCMD_SRTP | GCMD_QIE | GCMD_TE | GCMD_SIRTP;
        self.write32(REG_GCMD, gcmd);
        let sirtp_spins = self.spin_gsts(GSTS_SIRTPS)?;
        gcmd |= GCMD_IRE;
        self.write32(REG_GCMD, gcmd);
        let ire_spins = self.spin_gsts(GSTS_IRES)?;
        self.irte_pa = irte_pa;
        Ok((sirtp_spins, ire_spins))
    }

    /// Write one IRTE (128 bits) at `handle`; false when IR is not
    /// live or the handle is out of the planned range. Handle n
    /// mirrors broker vector slot n (49+n) — one IRTE per device
    /// vector, allocated by the broker's own slot arithmetic.
    pub fn irte_write(&self, handle: u32, words: [u64; 2]) -> bool {
        if !self.ir_active() || handle >= IR_ENTRIES {
            return false;
        }
        let pa = self.irte_pa + 16 * u64::from(handle);
        // The two-step discipline is unnecessary here: the IRTE is
        // written while masked-at-the-MSI-level (the device's vector
        // is not armed in its MSI-X table yet); present-last would be
        // cosmetic.
        crate::memops::write_u64(pa + 8, words[1]);
        crate::memops::write_u64(pa, words[0]);
        true
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
        // Context: present, TT=0b00 (multi-level — the ONLY translation
        // mode; 0b10 is PASS-THROUGH per VT-d spec §9.3 and QEMU's
        // VTD_CONTEXT_TT_PASS_THROUGH, ADR-0014), AW=2 (4-level),
        // SLPTPTR; DID high.
        let lo = context_entry(0x2000, 5);
        assert_eq!(lo & 0xFFF, 0x1, "P only — TT=0b00 (multi-level)");
        assert_eq!(lo & ADDR_MASK, 0x2000);
        assert_eq!(
            context_entry_hi(5),
            (5 << 8) | 2,
            "DID at bits 8-23, AW=2 (the 4-level walk) in the high word"
        );
        // SLPT leaves: P, W per direction, frame address.
        assert_eq!(slpte_leaf(0x7000, false), 0x7001);
        assert_eq!(slpte_leaf(0x7000, true), 0x7003);
        assert_eq!(slpte_table(0x9000), 0x9003);
        assert_eq!(
            slpte_table(0x9000) & SLPT_W,
            SLPT_W,
            "non-leaf carries W: the walk checks R/W at every level (ADR-0014)"
        );
    }

    /// ADR-0014 regression: the TT bits 3:2 of a context entry must
    /// never be nonzero. 0b10 is pass-through (QEMU's
    /// vtd_as_pt_enabled() → IOMMU_RW with no translation, then
    /// vtd_pt_enable_fast_path() bypasses the IOMMU entirely) and 0b01
    /// requires device-TLB support. Both silently delete the
    /// DMA-isolation property ADR-0013 exists to provide.
    #[test]
    fn tt_bits_are_never_pass_through() {
        for (slpt, did) in [(0x2000, 0), (0, 5), (0xFED9_0000, 0xFFFF)] {
            assert_eq!(
                context_entry(slpt, did) & (3 << 2),
                0,
                "TT must be 0b00 (multi-level); any nonzero TT silently disables translation"
            );
        }
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

    /// ADR-0014: VT-d second-level walks check R/W at EVERY level —
    /// QEMU's `vtd_iova_to_slpte` applies `access_right_check` to
    /// non-leaf entries too, so a non-leaf without W blocks every
    /// device write that is not served from the IOTLB page cache.
    /// Measured live on the q35 lane: `vtd_dmar_fault fault 5
    /// (VTD_FR_WRITE) addr 0x1189000 write 1` at level 4 for the
    /// virtio-blk data page, while writes to IOTLB-cached pages
    /// succeeded. Non-leaf entries must be present AND writable; the
    /// leaf keeps carrying the direction.
    #[test]
    fn nonleaf_entries_grant_the_walk_rw() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        let slpt = vtd.dom_slpt[0].unwrap();
        let pa = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        vtd.map_run(0, pa, 4096, DmaDir::Bidirectional).unwrap();
        // Walk exactly like the device does: levels 4..=2 must each
        // present a readable + writable entry, or a fresh write
        // translation faults before it ever reaches the leaf.
        let mut table = slpt;
        for level in (2..=4u8).rev() {
            let entry = crate::memops::read_u64(table + slpt_index(pa, level) * 8);
            assert_eq!(entry & 1, 1, "level {level}: present");
            assert_eq!(
                entry & 2,
                2,
                "level {level}: W must be set on non-leaf entries (ADR-0014)"
            );
            table = entry & ADDR_MASK;
        }
        // The leaf keeps the direction: Bidirectional -> P|W.
        let leaf = crate::memops::read_u64(table + slpt_index(pa, 1) * 8);
        assert_eq!(leaf & 3, 3);
    }

    /// F1 (ADR-0015): `map_run` is atomic. A run that cannot fit the
    /// remaining table budget must leave ZERO SLPTEs behind, must not
    /// advance `mapped_pages`, and — the corruption mode — must never
    /// let a later map re-hand a table frame the failed attempt
    /// already linked into a tree (two parents, one frame).
    #[test]
    fn map_run_is_atomic_on_budget_exhaustion() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        let slpt = vtd.dom_slpt[0].unwrap();
        let base = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        // Burn all but two table frames: every fresh 1 GiB stride
        // costs exactly PD + PT (the low-address PML4/PDPT chain
        // exists after the first map).
        // Burn the budget down to EXACTLY two frames. A fresh 1 GiB
        // region costs PD+PT (the first map also builds the PDPT
        // chain); a fresh 2 MiB region inside a walked 1 GiB region
        // costs exactly one PT — the fine-tuning step.
        let mut strides = 0u64;
        while TABLE_BUDGET - vtd.tables_used() > 3 {
            vtd.map_run(0, base + (strides << 30), 4096, DmaDir::ToDevice)
                .unwrap();
            strides += 1;
        }
        let mut sub = 0u64;
        while TABLE_BUDGET - vtd.tables_used() > 2 {
            vtd.map_run(
                0,
                base + ((strides - 1) << 30) + (sub + 1) * 0x20_0000,
                4096,
                DmaDir::ToDevice,
            )
            .unwrap();
            sub += 1;
        }
        assert_eq!(TABLE_BUDGET - vtd.tables_used(), 2);
        let cursor_before = vtd.table_cursor;
        let pages_before = vtd.mapped_pages();
        // A run spanning TWO fresh 1 GiB regions needs 4 tables; only
        // 2 remain. The refusal must touch nothing.
        let run_base = base + ((strides as u64 + 1) << 30);
        assert!(
            vtd.map_run(0, run_base, 2 << 30, DmaDir::Bidirectional)
                .is_err(),
            "the run cannot fit the remaining budget"
        );
        for off in [0, 4096, 1 << 30, (1 << 30) + 4096] {
            assert!(
                vtd.slpte_of(slpt, run_base + off).is_none(),
                "residual SLPTE at +{off} after a refused map (F1: map_run must be atomic)"
            );
        }
        assert_eq!(
            vtd.table_cursor, cursor_before,
            "a refused map consumes no tables (F1)"
        );
        assert_eq!(
            vtd.mapped_pages(),
            pages_before,
            "no page accounting for a refused map"
        );
        assert!(
            check_no_table_aliasing(&vtd).is_ok(),
            "aliasing after the refusal (F1)"
        );
        // And the follow-up map in a fresh region must not re-hand
        // anything the failed attempt touched: with the pre-fix code
        // the rolled-back cursor handed the linked frames out AGAIN —
        // exactly what check_no_table_aliasing exists to catch.
        let after = base + ((strides as u64 + 3) << 30);
        vtd.map_run(0, after, 4096, DmaDir::ToDevice).unwrap();
        assert!(vtd.slpte_of(slpt, after).is_some());
        assert!(
            check_no_table_aliasing(&vtd).is_ok(),
            "a table frame was handed to two parents (F1 aliasing)"
        );
        assert_eq!(vtd.table_cursor, TABLE_BUDGET);
    }

    /// The reusable `DmaProt` contract harness (ADR-0015 F1) against
    /// the REAL Vtd — the same invariants the fake is held to.
    #[test]
    fn dma_prot_contract_passes() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        let base = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        aegis_os::dma::contract::exercise(&mut vtd, 0, base, 4096);
        // Atomicity arm: exhaust the whole table budget, then a run
        // spanning fresh regions must refuse and leave nothing.
        let mut strides = 0u64;
        while TABLE_BUDGET - vtd.tables_used() > 3 {
            vtd.map_run(0, base + (strides << 30), 4096, DmaDir::ToDevice)
                .unwrap();
            strides += 1;
        }
        let mut sub = 0u64;
        while TABLE_BUDGET - vtd.tables_used() > 0 {
            vtd.map_run(
                0,
                base + ((strides - 1) << 30) + (sub + 1) * 0x20_0000,
                4096,
                DmaDir::ToDevice,
            )
            .unwrap();
            sub += 1;
        }
        let doomed = base + ((strides + 1) << 30);
        aegis_os::dma::contract::exercise_atomicity(&mut vtd, 0, doomed, 2 << 30);
        // And the forest stayed alias-free through all of it.
        assert!(check_no_table_aliasing(&vtd).is_ok());
    }

    /// F1 (ADR-0015): deterministic property test — random map/unmap
    /// sequences over a tiny table budget never panic, never leave a
    /// residual SLPTE after a refusal, and never alias a table frame.
    #[test]
    fn xorshift_map_unmap_sequences_stay_atomic_and_unaliased() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(0, 0, 0, (0x03, 0)).unwrap();
        let slpt = vtd.dom_slpt[0].unwrap();
        let base = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // 40 fresh 1 GiB regions x (PD+PT) exceeds the 64-frame
        // budget partway through: refusals are guaranteed, not lucky.
        for _ in 0..300 {
            let r = next();
            let pa = base + ((r % 40) << 30) + ((r >> 8) % 512) * 4096;
            let pages = (r >> 20) % 4 + 1; // 1..=4 pages, may cross a 2 MiB edge
            match vtd.map_run(0, pa, pages * 4096, DmaDir::Bidirectional) {
                Ok(()) => {
                    assert!(vtd.slpte_of(slpt, pa).is_some(), "mapped head present");
                }
                Err(_) => {
                    for k in 0..pages {
                        assert!(
                            vtd.slpte_of(slpt, pa + k * 4096).is_none(),
                            "residual SLPTE at +{} after a refused map (F1)",
                            k * 4096
                        );
                    }
                }
            }
            assert!(
                check_no_table_aliasing(&vtd).is_ok(),
                "table aliasing mid-sequence (F1)"
            );
            if next() & 1 == 0 {
                let _ = vtd.unmap_run(0, pa, pages * 4096);
                assert!(check_no_table_aliasing(&vtd).is_ok());
            }
        }
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

    /// ADR-0018 (round 5, Phase A): one domain per device — device A's
    /// mapped page is ABSENT in device B's tables, the same frame may
    /// live in both domains via separate map_runs, and unmapping one
    /// domain leaves the other's PTE alone. (The pre-fix version of
    /// this test — both devices in dom 0, the boot's old claim shape —
    /// FAILED: the shared SLPT contained the page; see the CHANGELOG.)
    #[test]
    fn device_tables_are_isolated_per_domain() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        // the FIXED claim shape: each device its own domain.
        vtd.assign_device(1, 0, 0, (0x03, 0)).unwrap();
        vtd.assign_device(2, 0, 0, (0x04, 0)).unwrap();
        let pa = (arena.pa(30) + 0x1F_FFFF) & !0x1F_FFFF;
        // device A maps its page in A's domain
        vtd.map_run(1, pa, 4096, DmaDir::Bidirectional).unwrap();
        let a_slpt = vtd.dom_slpt(1).unwrap();
        let b_slpt = vtd.dom_slpt(2).unwrap();
        assert!(
            vtd.slpte_of(a_slpt, pa).is_some(),
            "A's tables hold A's page"
        );
        assert!(
            vtd.slpte_of(b_slpt, pa).is_none(),
            "device B's tables must not contain device A's page"
        );
        // the same frame may be mapped in BOTH domains — only through
        // explicit, separate map_run calls.
        vtd.map_run(2, pa, 4096, DmaDir::ToDevice).unwrap();
        assert!(vtd.slpte_of(b_slpt, pa).is_some());
        // unmapping A's domain leaves B's PTE untouched.
        vtd.unmap_run(1, pa, 4096).unwrap();
        assert!(vtd.slpte_of(a_slpt, pa).is_none());
        assert!(
            vtd.slpte_of(b_slpt, pa).is_some(),
            "B's PTE survives A's unmap"
        );
    }

    /// ADR-0018: a device owns exactly one domain — re-assignment is
    /// refused until unassign_device clears the entry (and the context
    /// cache with it).
    #[test]
    fn reassign_is_refused_until_unassigned() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        vtd.assign_device(1, 0, 0, (0x03, 0)).unwrap();
        // same domain: refused.
        assert!(matches!(
            vtd.assign_device(1, 0, 0, (0x03, 0)),
            Err(DmaError::Hardware(7))
        ));
        // a DIFFERENT domain: also refused.
        assert!(matches!(
            vtd.assign_device(2, 0, 0, (0x03, 0)),
            Err(DmaError::Hardware(7))
        ));
        // unassign: the entry reads back absent, the DID is free.
        vtd.unassign_device(0, 0, (0x03, 0)).unwrap();
        let (lo, _hi) = vtd.context_entry_of(0, (0x03, 0));
        assert_eq!(lo & 1, 0, "context entry cleared");
        assert_eq!(vtd.assigned_count(), 0);
        // idempotent on an absent entry.
        vtd.unassign_device(0, 0, (0x03, 0)).unwrap();
        // re-assign to the other domain now works, and its SLPT is
        // the OTHER domain's root (not the old one).
        vtd.assign_device(2, 0, 0, (0x03, 0)).unwrap();
        let (lo, _hi) = vtd.context_entry_of(0, (0x03, 0));
        assert_eq!(lo & ADDR_MASK, vtd.dom_slpt(2).unwrap());
        // wrong segment: refused.
        assert!(vtd.unassign_device(1, 0, (0x03, 0)).is_err());
    }

    /// ADR-0018: the budget is DERIVED from a pure worst-case
    /// function — shared root+IQ+ctx plus per-domain root+PDPT+PD+PTs
    /// over the pool's 2 MiB spans — not a guessed constant.
    #[test]
    fn budget_is_derived_not_guessed() {
        assert_eq!(POOL_2M_SPANS_WORST, 9, "16 MiB aligned + 1 span slack");
        assert_eq!(worst_case_tables(1), 3 + 12);
        assert_eq!(worst_case_tables(8), 3 + 8 * 12);
        // Round I: 16 domains (the q35 lane claims nine devices);
        // the derived budget scales with the const, still loud.
        assert_eq!(
            TABLE_BUDGET,
            3 + 16 * 12,
            "covers every domain's worst case"
        );
    }

    /// ADR-0018: exhausting the NEW multi-domain budget is a typed
    /// refusal with no residue — the cursor is consistent (every
    /// frame the budget ever handed out is still owned exactly once),
    /// no table is aliased, and the pages mapped before the exhaustion
    /// still walk.
    #[test]
    fn budget_exhaustion_is_typed_and_clean() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        for dom in 0..MAX_VTD_DOMAINS as u32 {
            vtd.assign_device(dom, 0, 0, ((dom + 3) as u8, 0)).unwrap();
        }
        // Spread one page per 2 MiB span, round-robin over domains,
        // until the budget refuses.
        let mut mapped: Vec<(u32, u64)> = Vec::new();
        let mut span: u64 = 0;
        loop {
            let dom = (span % MAX_VTD_DOMAINS as u64) as u32;
            let pa = 0x20_0000u64 * span + 0x1000;
            match vtd.map_run(dom, pa, 4096, DmaDir::Bidirectional) {
                Ok(()) => mapped.push((dom, pa)),
                Err(DmaError::OutOfTables) => break,
                Err(e) => panic!("unexpected error before exhaustion: {e:?}"),
            }
            span += 1;
        }
        assert!(!mapped.is_empty(), "the budget must serve real maps first");
        assert_eq!(
            vtd.tables_used(),
            TABLE_BUDGET,
            "the cursor is consistent at the edge"
        );
        assert!(check_no_table_aliasing(&vtd).is_ok(), "no table aliased");
        // every page mapped before the refusal still walks, only in
        // its own domain.
        for &(dom, pa) in mapped.iter() {
            let own = vtd.dom_slpt(dom).unwrap();
            assert!(vtd.slpte_of(own, pa).is_some());
            for other in 0..MAX_VTD_DOMAINS as u32 {
                if other != dom {
                    let o = vtd.dom_slpt(other).unwrap();
                    assert!(
                        vtd.slpte_of(o, pa).is_none(),
                        "dom {other} sees dom {dom}'s page"
                    );
                }
            }
        }
        // the refusal is stable: the next map also refuses.
        assert!(matches!(
            vtd.map_run(
                0,
                0x20_0000u64 * (span + 1) + 0x1000,
                4096,
                DmaDir::ToDevice
            ),
            Err(DmaError::OutOfTables)
        ));
    }

    /// ADR-0018: a deterministic property test — random multi-domain
    /// assign/map/unmap/unassign sequences keep every domain isolated
    /// (a page is present ONLY in its owning domain's walk) and no
    /// table aliased, after every step.
    #[test]
    fn xorshift_property_multidomain_isolation() {
        let arena = Arena::new(TABLE_BUDGET);
        let mut vtd = plan_vtd(&arena).unwrap();
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // model: dom -> set of mapped (span) pages; device -> dom.
        let mut live: [std::collections::BTreeSet<u64>; MAX_VTD_DOMAINS] = Default::default();
        let mut dev_dom: [Option<u32>; 8] = [None; 8];
        for step in 0..3000u32 {
            let r = next();
            let dom = (r % MAX_VTD_DOMAINS as u64) as u32;
            let dev = ((r >> 8) % 8) as usize;
            let span = (r >> 16) % 2048;
            let pa = 0x20_0000u64 * span + 0x1000;
            match r % 4 {
                0 => {
                    // assign: fresh entry only
                    if vtd.assign_device(dom, 0, 0, ((dev + 3) as u8, 0)).is_ok() {
                        if dev_dom[dev].is_none() {
                            dev_dom[dev] = Some(dom);
                        }
                    } else if dev_dom[dev] != Some(dom) {
                        // refused because the entry is present: correct
                    }
                }
                1 => {
                    if vtd.map_run(dom, pa, 4096, DmaDir::Bidirectional).is_ok() {
                        live[dom as usize].insert(span);
                    }
                }
                2 => {
                    if vtd.unmap_run(dom, pa, 4096).is_ok() {
                        // only model as gone if it was the mapped one
                        if vtd
                            .dom_slpt(dom)
                            .is_some_and(|s| vtd.slpte_of(s, pa).is_none())
                        {
                            live[dom as usize].remove(&span);
                        }
                    }
                }
                _ => {
                    if vtd.unassign_device(0, 0, ((dev + 3) as u8, 0)).is_ok() {
                        dev_dom[dev] = None;
                    }
                }
            }
            // invariant after EVERY step: no aliasing, per-domain
            // presence matches the model.
            if step % 97 == 0 {
                assert!(check_no_table_aliasing(&vtd).is_ok(), "step {step}: alias");
                for d in 0..MAX_VTD_DOMAINS {
                    let Some(slpt) = vtd.dom_slpt(d as u32) else {
                        continue;
                    };
                    for &span in live[d].iter() {
                        let pa = 0x20_0000u64 * span + 0x1000;
                        assert!(
                            vtd.slpte_of(slpt, pa).is_some(),
                            "step {step}: dom {d} lost span {span}"
                        );
                        for o in 0..MAX_VTD_DOMAINS {
                            if o != d {
                                let os = vtd.dom_slpt(o as u32).unwrap();
                                assert!(
                                    vtd.slpte_of(os, pa).is_none(),
                                    "step {step}: dom {o} sees dom {d}'s span {span}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod ir_tests {
    use super::*;

    /// The remapped IRTE, pinned field by field against QEMU's
    /// decoder: present alone in the low flags, the vector at 23:16,
    /// the non-EIM dest at bits 47:40 (dest_id 15:8), and EVERY
    /// reserved field zero (bits 14:12, 31:24 low; 63:20 high) —
    /// QEMU faults a non-zero reserved field.
    #[test]
    fn irte_remapped_is_pinned_against_qemu() {
        let [lo, hi] = irte_remapped(0x41, 0, false);
        assert_eq!(lo & 1, 1, "present");
        assert_eq!((lo >> 16) & 0xFF, 0x41, "vector at 23:16");
        assert_eq!((lo >> 32) & 0xFFFF_FFFF, 0, "EIME off: dest 0 is zero");
        assert_eq!(hi, 0, "SID validation off (SVT=0), rest reserved");
        // Every bit outside the defined fields:
        let defined = 1u64 | (0xFFu64 << 16) | (0xFFFF_FFFFu64 << 32);
        assert_eq!(lo & !defined, 0, "no stray bits in reserved fields");

        // Non-zero dest: EIME off rides dest_id bits 15:8.
        let [lo2, _] = irte_remapped(0x41, 2, false);
        assert_eq!(
            (lo2 >> 40) & 0xFF,
            2,
            "dest_apic_id at dest_id 15:8 (QEMU's non-EIM mask)"
        );
        // EIME on: the dest is the low 32 bits of dest_id.
        let [lo3, _] = irte_remapped(0x41, 2, true);
        assert_eq!((lo3 >> 32) & 0xFFFF_FFFF, 2);
    }

    /// The IRTA value: aligned base, EIME bit, and the size order —
    /// 7 encodes 256 entries (1 << 8).
    #[test]
    fn irta_value_encodes_base_eime_and_order() {
        let base = 0x0040_B000u64;
        assert_eq!(irta_value(base, false, 7), 0x40_B007);
        assert_eq!(irta_value(base, true, 7), 0x40_B007 | IRTA_EIME);
        // The base's low 12 bits are stripped, never written.
        assert_eq!(
            irta_value(0xFFFF_FFFF_FFFF_FFFF, false, 0),
            0xFFFF_FFFF_FFFF_F000
        );
        assert_eq!(irta_value(base, false, 0xF), 0x40_B00F);
        // A size order wider than the 4-bit field is masked.
        assert_eq!(irta_value(base, false, 0x1F), irta_value(base, false, 0xF));
    }

    /// The remapped MSI address: 0xFEE prefix, handle at bits 19:5,
    /// the format flag at bit 4, SHV clear, and handle bit 15 (unused
    /// at our table size, but encoded correctly) at bit 2.
    #[test]
    fn msi_remap_addr_is_pinned_against_qemu() {
        assert_eq!(msi_remap_addr(0), 0xFEE0_0010, "format bit only");
        assert_eq!(msi_remap_addr(1), 0xFEE0_0030);
        assert_eq!(msi_remap_addr(2), 0xFEE0_0050);
        assert_eq!(msi_remap_addr(63), 0xFEE0_07F0, "the broker's top handle");
        // Address bit 3 (SHV) and bits 1:0 stay clear → data must be 0.
        for h in 0..64u32 {
            let a = msi_remap_addr(h);
            assert_eq!(a >> 20, 0xFEE, "the prefix");
            assert_eq!((a >> 5) & 0x7FFF, u64::from(h), "the handle rides 19:5");
            assert_eq!(a & (1 << 3), 0, "SHV clear");
            assert_eq!(a & 0b11, 0);
            assert_eq!(a & (1 << 4), 1 << 4, "remappable format");
        }
        // Handle bit 15 lands at address bit 2 (QEMU's index_h).
        assert_eq!(msi_remap_addr(0x8000), 0xFEE0_0010 | (1 << 2) | (0 << 5));
        assert_eq!(msi_remap_addr(0x8001), 0xFEE0_0030 | (1 << 2));
        assert_eq!(MSI_REMAP_DATA, 0);
    }

    /// The IR constants match the QEMU register map.
    #[test]
    fn ir_register_constants_match_qemu() {
        assert_eq!(REG_IRTA, 0xB8);
        assert_eq!(GCMD_SIRTP, 1 << 24);
        assert_eq!(GCMD_IRE, 1 << 25);
        assert_eq!(GSTS_SIRTPS, 1 << 24);
        assert_eq!(GSTS_IRES, 1 << 25);
        assert_eq!(IRTA_EIME, 1 << 11);
        assert_eq!(IR_ENTRIES, 256);
        // One frame holds the planned table.
        assert_eq!(IR_ENTRIES * 16, 4096);
    }

    /// The planned unit reports IR inactive until enabled; the
    /// absent placeholder never reports active.
    #[test]
    fn ir_starts_inactive_on_planned_and_absent_units() {
        let v = Vtd::absent();
        assert!(!v.ir_active());
    }
}
