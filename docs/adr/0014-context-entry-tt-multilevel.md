# ADR-0014: Context-entry TT = multi-level — the tables become load-bearing

- **Status:** Proposed (implementation lands in the same commit group;
  per the ADR process in `README.md`)
- **Stage:** M2 driver stack, review round 4, Phase 1.
- **Date:** 2026-11-20
- **Depends on:** ADR-0013 (the brokered VT-d design this corrects).
- **Supersedes:** nothing; **corrects** ADR-0013's implementation detail
  "TT = 0b10" and the comments in `arch/vtd.rs` that justified it.

## Context

Review round 4, Phase 1: `arch/vtd.rs::context_entry` sets the
context-entry Translation Type (bits 3:2) to `0b10`, with a comment
claiming "QEMU decodes the walk depth as 2+TT". If TT=0b10 is
pass-through, then every table this kernel builds is decorative: the
device never walks it, and ADR-0013's DMA-isolation property does not
exist. This ADR verifies that claim before changing anything, then
fixes it.

### Verification (measured and quoted, not remembered)

**1. Intel VT-d spec** (Intel® Virtualization Technology for Directed
I/O Architecture Specification, Rev 5.20, order D51397-019), §9.3
"Context-Entry Format", Figure 9-3, field TT bits 3:2:

> • 00b: Untranslated requests are translated using second-stage paging
>   structures referenced through the SSPTPTR field. Translated requests
>   and Translation Requests are blocked.
> • 10b: Untranslated requests are processed as pass-through. The
>   SSPTPTR field is ignored by hardware.

and the SSPTPTR field (bits 63:12):

> This field is ignored by hardware when Translation-Type (TT) field is
> 10b (pass-through).

**2. QEMU v10.0.0 source** (the emulator this lane runs; 10.0.13
Debian build of the same tree):

- `hw/i386/intel_iommu_internal.h:532-535`:
  `VTD_CONTEXT_ENTRY_TT (3ULL << 2)`, `VTD_CONTEXT_TT_MULTI_LEVEL 0`,
  `VTD_CONTEXT_TT_PASS_THROUGH (2ULL << 2)`.
- `hw/i386/intel_iommu.c:1058-1061` — `vtd_ce_get_type()` returns
  `ce->lo & VTD_CONTEXT_ENTRY_TT`.
- `hw/i386/intel_iommu.c:1067-1086` — `vtd_ce_type_check()`: TT=0 is
  "always supported"; TT=pass-through is accepted only when
  `x86_iommu->pt_supported`.
- `hw/i386/x86-iommu.c:132` — `DEFINE_PROP_BOOL("pt", X86IOMMUState,
  pt_supported, true)`: **pass-through is accepted by default** in this
  QEMU, so nothing rejected our entries.
- `hw/i386/intel_iommu.c:1697-1701` — `vtd_as_pt_enabled()` (legacy
  mode) ⇔ `vtd_ce_get_type(ce) == VTD_CONTEXT_TT_PASS_THROUGH`.
- `hw/i386/intel_iommu.c:2185-2198` — `vtd_do_iommu_translate()`: when
  pt is enabled, `entry->perm = IOMMU_RW` (full access, **no
  translation**), `trace_vtd_translate_pt(...)`, then
  `vtd_pt_enable_fast_path()`.
- `hw/i386/intel_iommu.c:1896-1913` — `vtd_pt_enable_fast_path()`
  swaps the device's DMA address space to bypass the IOMMU entirely;
  `trace_vtd_pt_enable_fast_path(source_id, success)`.
- `hw/i386/intel_iommu.c:1016-1018` — `vtd_ce_get_level()` is
  `2 + (ce->hi & VTD_CONTEXT_ENTRY_AW)`: the walk depth comes from **AW
  in the high word** (spec bits 66:64), never from TT. The "2+TT"
  comment was a false memory from before commit 38e3518 moved AW into
  `context_entry_hi`; TT stayed 0b10 and nobody re-checked it.
- `hw/i386/intel_iommu.c:751-753` — `vtd_ce_get_slpt_base()` is
  `ce->lo & ~0xfffULL`: SLPTPTR lives in the low word (spec bits
  63:12) — the current low-word placement is correct.

**3. Live trace on the current (buggy) build** (q35 lane, QEMU 10.0.13,
`-trace enable=vtd_*`, serial `target/serial-before.txt`, trace
`target/trace-before.txt`, 2026-11-20):

- `vtd_pt_enable_fast_path` fires **8 times, success=1, six distinct
  devices** — SIDs 0x10, 0x18 (×2), 0x20, 0x28, 0x30, 0xFA (the ICH9
  SATA at 00:1f.2). Every device the kernel assigned was switched to
  pass-through.
- Serial: `[VBLK] enforcement: request completed WITH ERROR status=0
  fsts=0x0000000000000000 PPF=no` — the virtio-blk request whose data
  page had been unmapped and freed **completed with status OK and no
  page-fault pending**: the device wrote into a freed page and nothing
  faulted. The probe's own follow-up line (`PPF did NOT set —
  INVESTIGATE`) was the smoking gun the previous round missed.
- The unit test `entry_encodings_are_pinned` asserted
  `lo & 0xFFF == 0x9` — i.e. P | TT=0b10 — pinning the bug in place.
  ADR-0013's text says "no passthrough entries"; the code contradicted
  its own ADR.

## Decision

1. `context_entry` uses **TT = 0b00** (multi-level). AW stays 2 in
   `context_entry_hi` (bits 64+0-2), DID stays at high-word bits 8-23,
   SLPTPTR stays in the low word — all three verified correct above.
2. `entry_encodings_are_pinned` is rewritten to assert TT == 0, and a
   new regression test (`tt_bits_are_never_pass_through`) fails if any
   future encoder sets bits 3:2 of a context entry's low word.
3. The enforcement probe reports honestly: a completed request to the
   unmapped page prints an **enforcement-failure** marker; the proof
   marker is non-completion **and** `PPF=yes`. The probe additionally
   reads the SLPTE back from the tables after unmap and prints
   `slpte P=0` (absent).
4. `boot.sh --verify-q35` boots with `-trace enable=vtd_*`, and the
   lane **FAILS** if the trace contains `vtd_pt_enable_fast_path` for
   any device, and **FAILS** unless the probe prints `PPF=yes` and the
   absent-SLPTE marker.
5. Every anomaly measured under pass-through is re-measured after this
   change and the ledger in `docs/arch/drivers.md` records
   before/after; retracted conclusions stay visible.

## Consequences

- The second-level tables are load-bearing for the first time: mapped
  regions work because the walk finds them, unmapped accesses fault.
  This is the property ADR-0013 claimed and the code did not deliver.
- Devices whose drivers miss a mapping will now fault where they
  previously "worked" through pass-through — each such regression is a
  real finding, not noise, and goes into the ledger.
- The NVMe `prp1=0` and AHCI stale-FIS anomalies were measured under
  pass-through; both are re-measured before drawing conclusions.
- New tests: `entry_encodings_are_pinned` (rewritten),
  `tt_bits_are_never_pass_through`, lane trace/probe assertions.
- Security impact: closes the "any assigned device can DMA anywhere"
  hole on this lane. The isolation property is still **not** a driver
  isolation story — drivers still run in the kernel (that is Phase 6).

## Outcome (2026-11-21, same commit group)

- The TT fix alone was **not sufficient**: with translation live, the
  first device write faulted `VTD_FR_WRITE` at level 4 —
  `slpte_table` wrote non-leaf entries without W, and VT-d (like x86
  page tables; QEMU `vtd_iova_to_slpte` applies `access_right_check`
  at every level) requires W on the whole chain for writes. Reads had
  passed, and writes only succeeded when QEMU's IOTLB page cache
  (which re-checks the leaf alone) served them — which is why this
  bug hid under pass-through and even survived the first fix boot.
  `slpte_table` now carries P|W; the leaf keeps the direction.
- Step 5's AHCI control experiment **refuted the vIOMMU bounce-buffer
  hypothesis**: the stale-FIS signature reproduced on the no-IOMMU
  lane, and the trace + command-table read-back pinned three driver
  bugs (PRDT DBC in the reserved dword, FIS LBA fields at the wrong
  offsets, sector count never written). The ext2 mount now reads
  hello.txt on both lanes; the historical "stale FIS" reading is
  retracted in `docs/arch/drivers.md`.
- Re-measured anomalies: virtio-net and e1000 now complete full DHCP
  round trips through the IOMMU (the old TX "stall"/"no egress" was
  the non-leaf W bit); the NVMe prp1=0 anomaly is UNCHANGED by real
  translation and remains the open item.
- Tests (each red on the pre-fix code, green after):
  `entry_encodings_are_pinned` (rewritten: TT==0),
  `tt_bits_are_never_pass_through` (new),
  `nonleaf_entries_grant_the_walk_rw` (new).
  Lane assertions live in `boot.sh --verify-q35`: the trace must
  contain no `vtd_pt_enable_fast_path`, and the probe must print
  `PPF=yes` + the absent-SLPTE marker.

## Alternatives considered

- **Keep TT=0b10, delete the isolation claims.** Rejected: the entire
  ADR-0013 architecture (broker, regions, invalidations) exists to
  make tables the device must walk.
- **TT=0b01 (device-TLB).** Rejected: requires DT support
  (`dt_supported`, off by default in this QEMU), and no device-TLB
  hardware exists on this lane; it adds a failure mode, not a feature.
- **Wait for Phase 6 (driver domains) and fix TT then.** Rejected: the
  kernel's own docs claim enforcement today; the claim is false until
  this lands.
