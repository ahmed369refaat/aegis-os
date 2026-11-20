# IOMMU (VT-d) — Kernel-Brokered DMA Isolation

Design authority: [ADR-0013](../adr/0013-iommu-vtd-dma-isolation.md).
Status: design accepted for implementation (Phase 0, PRs 0.2–0.5);
until those merge, **none of this exists** — per the method rule, the
component springs into existence with its first marker, not with this
file.

## What it is

The one hardware boundary between DMA-capable devices and physical
RAM. The kernel enumerates the VT-d remapping hardware from the
firmware's DMAR table, programs per-driver-domain page tables that map
**only broker-granted frames**, and exposes DMA to driver domains as
a message protocol over ADR-0004 IPC. Devices addressing anything else
fault, and the fault is attributed to the owning domain and escalated
through the behavior monitor.

Layering (ADR-0011 D3 discipline):

```text
src/dmar.rs      parser policy: RSDP/RSDT/XSDT/DMAR/DRHD/RMRR decode,
                 checksums, bounds — pure, host-tested, cross-arch
src/dma.rs       DmaProt trait (ADR-0011 D2 row), broker protocol,
                 quotas, map/unmap state machine — pure
arch/acpi.rs     physical discovery: RSDP scan, table fetch via memops
arch/vtd.rs      registers, root/context/second-level tables, QI
                 invalidation, FSTS/FRCD fault reads — unsafe-free on
                 the memops/hw primitives (lapic.rs precedent)
```

The VT-d register window `0xFED9_0000` and the IOAPIC at `0xFEC0_0000`
sit inside the 1 GiB MMIO window PTE ADR-0012 added for the LAPIC
(`0xC000_0000..0x1_0000_0000`); firmware tables sit inside the direct
map's first GiB. **No new mappings, no new unsafe** — target delta 0
against the ratchet baseline of 89.

## Invariants (each with its proof)

1. **Fail closed on absent/broken hardware.** No DMAR, a malformed
   DMAR, or a failed bring-up ⇒ the `DmaProt` service reports absent;
   DMA-capable devices stay unclaimed; a marker says so.
   Proof: `no_dmar_means_no_dma_drivers` + the negative q35 lane
   (no `-device intel-iommu` ⇒ no DMAR table — verified on QEMU
   10.0.13); marker `[IOMMU] policy: dma-drivers=0 (fail-closed ok)`.
2. **The parser never trusts firmware.** Every length, index and
   pointer is bounds-checked before use; checksums verified; unknown
   structure types with `len < 4` stop the walk; tables are unaligned
   in the wild (SeaBIOS pmm packs them) and the parser assumes
   nothing. Proof: seeded byte-stream fuzz (never panic, never OOB,
   never hang) + `dmar_header_is_48_bytes_drhd_is_type_0` pinning the
   measured QEMU-10 layout + per-truncation case tests.
3. **Only granted frames are mapped.** A domain's second-level tables
   contain exactly the frames the broker granted; the boot self-check
   walks them back and compares. Proof: `map_covers_only_granted_
   frames`; marker `[IOMMU] map: ... → walk-back ok`.
4. **No kernel hang from device registers.** GSTS (translation-enable)
   and IQH (invalidation-completion) spins carry explicit budgets;
   budget exhaustion is a typed error that disables the path.
   Proof: `gsts_spin_is_bounded`, `qi_completion_is_bounded`.
5. **Unmap is ordered: abort first, invalidate, then release.**
   Frames return to the pool through scrub-on-free; queued
   invalidation completes before the release, so no stale translation
   outlives a grant and no freed frame carries device data.
   Proof: state-machine tests (`unmap_after_abort_only`,
   `unmap_invalidates_before_free`); marker
   `[IOMMU] unmap+inval: walk-back absent ok`.
6. **Domains never see addresses.** Drivers hold region cookies and
   offsets; the kernel materializes device-visible addresses only
   when validating and rewriting driver submissions (the snapshot
   rule — see threat model). Proof: broker protocol tests assert no
   address field ever crosses the gate toward a domain.
7. **The driver syscall surface does not grow.** DMA is an IPC
   protocol, not new syscalls; a degraded driver (no IPC) has no DMA
   and must drain, abort, and exit. Proof: existing profile tests +
   broker degrade-path tests; ABI-VERSION.md untouched.

## Threat model

**Assets.** Physical RAM at large: the kernel image, all domains'
private frames, capability/endpoint tables, the frame pool.

**Adversaries.** (1) a compromised driver domain — fully malicious,
coordinated software; (2) a malicious or spoofed device — hostile DMA
streams and forged completions; (3) malformed firmware — accidental
or planted table corruption; (4) a buggy/thin emulator — missing
features, under-reported faults.

| Attack | Mitigation | Residual risk |
|---|---|---|
| Driver asks the broker for something absurd (oversized len, wrap-around iova+len, zero, quota exhaustion) | Checked/saturating arithmetic on every hardware- or domain-supplied value; typed errors; per-domain quotas; validate exactly once at the gate | none identified; fuzzed |
| Driver programs its device to DMA outside the grant | Per-domain second-level tables contain only granted frames — hardware blocks the rest; fault attributed via SID→context→domain | kernel must also rewrite descriptor addresses (snapshot rule) so the driver never had a valid address to begin with |
| Device writes into ring/descriptor memory between kernel validation and use (TOCTOU) | **Snapshot rule**: device-writable memory is copied into kernel frames, validated, and acted on from the copy; raw device memory is never re-read after validation | enforced as the driver-protocol rule from Phase 2 on; stated here so no driver design can skip it |
| Malformed DMAR/DRHD (bad length, OOB pointer, wrong checksum, unknown struct) | bounds + checksum + typed errors ⇒ absent verdict (fail closed, never a guess) | none — fuzzed |
| Fault storm / invalidation storm as DoS | every fault-read and spin loop budgeted; storm ends in Log→Tighten→Quarantine of the owning domain | quarantine latency during a storm |
| Physical-layout disclosure via identity IOVA=GPA | IOVA values are kernel-internal; domains see handles/offsets; domains cannot act on GPAs anyway (no supervisor access, no direct map in their spaces) | informational at most; revisit via non-identity IOVA if ever stated as a threat |
| Emulator under-reporting faults (FRCD is a single register on QEMU) | bounded polls, absent-verdict on anomaly; markers guard QEMU-version drift | confinement proof is per-lane, not universal |

**Out of scope (stated, not forgotten):** interrupt remapping (raw
device MSI is blocked while `intremap=off` on the lane — the
interrupt-broker ADR owns it), ATS/device-IOTLB, scalable mode/PASID,
RMRR identity ranges (RMRR'd devices are unusable, not mapped),
multi-segment, IOMMU on the pc machine.

## Locking / IRQ context

Phase 0: every VT-d register access, table program, and invalidation
happens in single-threaded boot context (CPL0, pre-ring-3) — **no
locks exist in this component yet**, so no lock-order or hold-across-
fault question can arise. The runtime fault-poll hook and any
broker-concurrency locks land with the driver model (that ADR must
extend this section with the global lock order before the first
driver domain runs).

## Capacity (construction parameters, not secrets)

- VT-d domain-ids: 16-bit space, one per live driver domain —
  MAX_DOMAINS=4 today; no pressure.
- Table frames: 1 root frame total + 1 context frame per driven bus +
  1+ second-level frames per domain (4 KiB granularity).
- Broker quotas per domain: max regions, max total bytes — constants
  with a capacity self-test PR (separate, per the baseline contract).
