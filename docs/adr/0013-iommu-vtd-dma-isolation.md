# ADR-0013: IOMMU/VT-d — Kernel-Brokered DMA Isolation for Driver Domains

- **Status:** Proposed (Phase-0 GO given 2026-11-20; implementing PRs
  0.2–0.5 follow — becomes Accepted when they merge, per the ADR
  process in `README.md`)
- **Stage:** M2 driver stack, Phase 0. Fills the reserved `DmaProt` row
  of ADR-0011 D2 ("IOMMU: per-domain DMA windows — VT-d (not yet
  present)").
- **Date:** 2026-11-20
- **Depends on:** ADR-0002 (direct map), ADR-0004 (capability IPC),
  ADR-0008 (SMEP/SMAP), ADR-0011 (HAL seam + D3 discipline),
  ADR-0012 (the LAPIC 1 GiB MMIO window PTE this design reuses).

## Context

**Why now, in one paragraph.** Every isolation boundary this kernel has
is CPU-side: per-domain page tables, SMEP/SMAP, W^X with CR0.WP,
guard pages, capability-gated syscalls. A PCI device with bus-master
capability ignores all of it — DMA writes physical memory directly.
GAP-ANALYSIS-v2 §2.3 states the exposure exactly: nothing DMAs today
so the hole is latent, but "any 'restricted driver domain' can
overwrite all of physical memory" the moment one DMA-capable driver
exists. The driver stack adds six of them (virtio-blk, NVMe, AHCI,
virtio-net, e1000, XHCI). Per GAP-ANALYSIS-v2 line 84, this ADR lands
**before** any of them.

**What exists that this builds on (verified at a915e60):**

- `kernel-x86_64/src/memops.rs` — the allowlisted physical-access layer:
  `read_u32/read_u64/write_u32/write_u64` at a PA through the direct
  map. ADR-0012 proved with `arch/lapic.rs` that a whole MMIO device
  can sit on these primitives **unsafe-free**.
- `arch/lapic.rs` `WINDOW_PTE` — a 1 GiB page mapping PA
  `0xC000_0000..0x1_0000_0000` RW/NX/global, shared into every address
  space via `install_kernel_entries` (ADR-0002). QEMU's VT-d registers
  live at `0xFED9_0000` — **inside this exact GiB**. No new mapping is
  needed.
- `mm/direct_map.rs` — `DIRECT_MAP_BASE 0xFFFF_8880_0000_0000`, size
  1 GiB, RW, kernel-only, NX. SeaBIOS places its ACPI tables at the
  top of low RAM (`0x7FE_xxxx` measured, below 1 GiB) — also already
  reachable.
- `frames.rs` `FramePool` — scrub-on-free with read-back verification;
  VT-d root/context/page tables come from these scrubbed frames.
- `src/ipc.rs` (ADR-0004) — 64-byte fixed messages, depth-4 FIFO,
  capability-gated endpoints, monotonic never-reused ids. Driver↔kernel
  traffic rides this; the DMA broker is a new *protocol* on it, not a
  new mechanism.
- `src/profile.rs` `driver_profile()` — READ|WRITE|IOCTL|IPC_SEND|
  IPC_RECV|EXIT; degraded drops IPC (a driver that loses IPC loses DMA
  by construction — correct degradation, already enforced).
- `src/capability.rs` — `Resource::Device`, GRANT-gated derivation,
  fail-closed stale handles: the claim path for driver domains.

**QEMU evidence (every line measured, not remembered; QEMU 10.0.13
Debian trixie, TCG, `-M q35`, 2026-11-20):**

1. The unmodified kernel boots on `-M q35 -device intel-iommu` and
   prints the full M1 acceptance sequence, including
   `M1-EXIT-CRITERIA: PASS`; it powers off on its own in ~22 s
   (`rc=0`). The pc control run passes `boot.sh --verify` too.
2. `intel-iommu` exists **only on q35** (`-device help` listing; QEMU
   docs concur). The pc lanes stay as they are; the IOMMU lane is q35.
3. SeaBIOS leaves `RSDP @ 0xF52C0` (rev 0) → `RSDT @ 0x7FE23C9`
   (unaligned — pmm packs tables at top of low RAM; a parser must not
   assume alignment) → 6 entries: FACP, APIC, HPET, MCFG, **DMAR**,
   WAET. All inside the direct map's first GiB.
4. `DMAR @ 0x7FE2329`, len 120: HAW = 48 bits, flags = 0x01
   (INTR_REMAP). Header is **48 bytes** (HAW(1)+flags(1)+reserved(10))
   — remapping structures start at +48. Structure types per VT-d
   §8.2–8.5: **DRHD = 0**, RMRR = 1, ATSR = 2.
5. One `DRHD`: seg 0, `include_all = false`, `reg_base = 0xFED9_0000`,
   len 72; scopes: IOAPIC (pseudo-bus 0xFF) + PCI endpoints 00:00.0,
   00:01.0, 00:02.0, 00:1f.0, 00:1f.2, 00:1f.3. **Per-device
   assignment by scope walk is mandatory** — this DRHD does not say
   INCLUDE_ALL.
6. Adding `-device virtio-blk-pci,drive=d0,iommu_platform=on,
  disable-legacy=on` grows the DRHD to len 80 with a new scope
   00:03.0: added devices appear in scopes, so the kernel can find the
   governing DRHD for any device it drives. (`iommu_platform=on`
   without `disable-legacy=on` is rejected by QEMU: modern-only virtio
   required. That incantation is load-bearing for Phase 2.)
7. `-M q35` **without** `-device intel-iommu`: no DMAR table at all.
   The fail-closed path is directly testable in CI.
8. Register facts from QEMU v10.0 source (`hw/i386/
   intel_iommu_internal.h`, `intel_iommu.c`): VER 0x00 (reads 0x10),
   CAP 0x08, ECAP 0x10, GCMD 0x18, GSTS 0x1C, RTADDR 0x20, FSTS 0x34,
   IQH 0x80, IQT 0x88, IQA 0x90, FRCD 0x220 (1 register). ECAP always
   includes QI (queued invalidation) + IRO. Fault recording (FSTS.PPF
   → FRCD: SID, reason, address) is implemented and pollable. TCG
   needs no `caching-mode` (that is for KVM device assignment).

**Sequencing hazard found while probing.** With `intel-iommu` present,
`intremap` defaults on (DMAR flags=0x01 measured) and raw device
MSI/MSI-X delivery is blocked until interrupt remapping tables exist.
Phase 1's interrupt broker must either program IRTEs or the DMA lane
boots with `intremap=off`. **Decision: the Phase-0/1 q35 lane runs
`intremap=off` and this ADR excludes IR; the interrupt-broker ADR
takes IR explicitly.** We parse and log the INTR_REMAP flag; we do not
act on it.

## Decision

The kernel — and only the kernel — programs the VT-d hardware. Every
DMA-capable device is assigned, via a DRHD device-scope walk, to a
context entry carrying one VT-d domain-id per AegisOS driver domain,
whose second-level page tables map **only the frames the broker has
granted that domain**, identity-mapped (IOVA = GPA). Everything else
any device addresses faults. Driver domains never learn GPAs or IOVAs
and never touch IOMMU MMIO (not mapped into their spaces): they
request DMA regions over ADR-0004 IPC from the kernel broker and
receive opaque region handles plus offsets; the kernel materializes
device-visible addresses only when it validates and rewrites driver
submissions. If the DMAR is absent, a DRHD is invalid, or bring-up
fails, the `DmaProt` service reports **absent**: DMA-capable devices
stay unclaimed, a boot marker says so, and no driver that requires DMA
attaches. Interrupt remapping is out of scope (interrupt-broker ADR).

### D1 — Layering (the ADR-0011 D3 discipline, applied now)

- `src/dmar.rs` (policy core, `#![forbid(unsafe_code)]`, host-tested,
  cross-arch builds stay green): the pure firmware-table parser —
  RSDP/RSDT/XSDT/DMAR/DRHD/RMRR decode over caller-supplied reads,
  checksums, bounds on every length/index, typed errors. This is also
  the ACPI-parse-only slice of the driver-stack plan (item 14):
  discovery *plumbing* is kernel-side, *parsing policy* lives here from
  day one.
- `src/dma.rs` (policy core): the `DmaProt` trait (the ADR-0011 D2
  row), broker protocol types, quotas, region bookkeeping policy, and
  the map/unmap state machine as pure logic.
- `kernel-x86_64/src/arch/acpi.rs`: physical discovery only — RSDP
  scan (EBDA + 0xE0000–0xFFFFF), table fetch via `memops` (everything
  lands inside the already-mapped first GiB).
- `kernel-x86_64/src/arch/vtd.rs`: registers, root/context/second-
  level table programming, QI invalidation, FSTS/FRCD fault reads.
  **Target unsafe delta: zero** — the lapic.rs precedent (all raw
  access through `memops`/`hw`, all encodings pure and host-tested) is
  the explicit engineering constraint. If a genuinely unavoidable
  primitive appears, it needs its own justification line in that PR
  per the ratchet contract (unsafe-count.txt is 89 today).

### D2 — Enumeration (fail-closed at every step)

RSDP scan → checksum verify → RSDT/XSDT → per-table bounds check →
DMAR → DRHD list (type 0), each with register base, segment, scopes.
Every malformed field (bad length, out-of-window pointer, failed
checksum, unknown structure with len<4) is a typed error that
**disables the IOMMU path**, never a guess. RMRR structures (QEMU
emits none today): logged; devices whose scopes fall inside an RMRR
are **unusable** (fail-closed), not identity-mapped. The walker pins
the exact QEMU-10 byte layout in tests: 48-byte DMAR header, DRHD
type 0, unaligned table pointers, scopes at DRHD+16.

### D3 — Bring-up (bounded waits, fail-loud)

Read VER (must read `0x10`, never all-zeros/all-ones — the lapic.rs
`map_window` sanity pattern). Decode CAP/ECAP: SAGAW (paging levels
supported) vs the 48-bit HAW from DMAR; QI required (ECAP bit). Root
table from a scrubbed frame; context entries per (bus, devfn) of
driven devices; RTADDR program; TE via GCMD with a **bounded** GSTS
spin (spin budget exceeded = typed error = absent, never a hang).
Domain-id allocation: monotonic, one per live driver domain, freed on
domain teardown (16-bit space vs MAX_DOMAINS=4 today — no pressure;
recorded as a construction parameter).

> **Correction (2026-11-20, review round 4):** the implementation
> shipped TT=0b10 in `context_entry` — pass-through, the exact
> opposite of this section — while this text claimed "no passthrough
> entries". Every device's DMA bypassed the tables
> (`vtd_pt_enable_fast_path` ×8, six devices) and the enforcement
> probe's request against an unmapped page completed with PPF=no.
> ADR-0014 carries the verification and the fix; the tables are
> load-bearing from that commit on. Recorded here so the wrong
> history stays visible.

### D4 — Mapping model

Per-domain second-level tables, 4 KiB granularity (QEMU's `fs1gp`
1 GiB pages are an optimization we do not need yet), TT=0 multi-level
(no passthrough entries — QEMU's `pt=on` capability stays unused).
Identity IOVA=GPA **within the domain's own granted frames only** —
matches GAP-ANALYSIS-v2 Phase 3 ("identity maps only for the driver's
own frames"). The IOVA values are kernel-internal: domains see
handles and offsets, never addresses. Unmap → queued-invalidation
descriptor → bounded IQH==IQT completion wait → frames return to the
pool **through scrub-on-free** (no stale translation can outlive the
frame grant, and no freed frame carries device data forward).

### D5 — Fault path (Log → Tighten → Quarantine)

Poll FSTS (boot-time in Phase 0; the runtime poll hook lands with the
driver model). On FSTS.PPF: read FRCD (SID, reason, fault address),
map SID → owning domain via the context table, escalate through the
existing behavior monitor at driver sensitivity, then invalidate,
revoke the Device capability, reclaim and scrub frames. A fault storm
from one device ends in Quarantine (exit-only), not in a kernel hang:
every fault-read loop has a budget.

### D6 — The broker protocol (ADR-0004 discipline, no exceptions)

64-byte messages on capability-gated endpoints: `DMA_MAP {len, dir}`
→ `{region cookie, offset span}` (kernel allocates DMA frames,
programs the second-level tables, pins them); `DMA_UNMAP {cookie}` →
abort-required-first ordering: a region with in-flight device work
is refused until the driver completes its abort handshake (the
storage-driver protocol carries it). Per-domain quotas (max regions,
max total bytes — construction parameters with a capacity self-test,
not silent exhaustion). Validate **exactly once, fully, at the
receiving gate**; all length arithmetic checked; the queue-depth-4
EAGAIN discipline applies unchanged. Degraded driver (no IPC) = no
DMA: the driver drains, aborts, and exits cleanly — the profile
already removes IPC under Tighten, so the security property falls out
of existing policy.

### D7 — Proof matrix and CI lanes

- New lane: `boot.sh --verify-q35` (q35 + `-device intel-iommu,
  intremap=off`), asserting the IOMMU markers below; the pc lane and
  its existing markers are untouched.
- Negative lane: q35 without the device asserts the absent-marker.
- Phase 2 adds `iommu_platform=on,disable-legacy=on` virtio devices
  to the q35 lane; **translation enforcement** (an unmapped DMA faults
  a device, a mapped one completes) is provable only with a real DMA
  device, so the checklist keeps item 1 honest: walker/init/invalida-
  tion proof = Phase 0; enforcement proof = the Phase-2 virtio-blk PR,
  where the negative test greps the FRCD-reported fault marker.
- QEMU-version drift is a CI reality (ubuntu-latest vs local 10.0.13);
  the markers themselves are the version guard — any QEMU whose tables
  or registers diverge fails the marker, loudly.

## Consequences

- **Easier:** every later DMA driver (virtio-blk, NVMe, AHCI,
  virtio-net, e1000, XHCI) inherits device→RAM confinement by
  construction; the broker gives the monitor a single choke point for
  DMA misbehavior.
- **Harder:** map/unmap + queued invalidation adds latency and one
  more frame consumer (root/context/page tables) to the pool; driver
  protocols must carry the abort handshake before unmap.
- **New invariants (each with named tests):**
  - `dmar_rejects_truncated_table` / `..._bad_checksum` /
    `..._unknown_struct_short_len` — parser never panics, never OOB,
    never loops (host fuzz: pseudo-random bytes, seeded).
  - `dmar_header_is_48_bytes_drhd_is_type_0` — pins the QEMU-10 byte
    layout this design was verified against.
  - `vtd_register_encodings_pinned` — RTADDR/context-entry/second-
    level PTE encodings pure and host-tested (lapic.rs pattern).
  - `gsts_spin_is_bounded` / `qi_completion_is_bounded` — no path to
    a kernel hang from device registers.
  - `unmapped_iova_faults_domain_scoped` — FRCD parse + SID→domain
    attribution logic (host); live proof in the Phase-2 lane.
  - `map_covers_only_granted_frames` — second-level walk reads back
    exactly the granted set (kernel self-check at boot, marker'd).
  - `no_dmar_means_no_dma_drivers` — the fail-closed verdict marker.
- **Threat-model delta (full section in `docs/arch/iommu.md`):**
  device-DMA overwrite goes from "unbounded, unproven" to "confined to
  granted, scrubbed frames, faults attributed and escalated". New
  residual risks stated honestly: TOCTOU between validate and use in
  *device-shared* memory (mitigation: snapshot descriptors into kernel
  frames, validate and act on the copy — enforced as the driver
  protocol rule from Phase 2 on), fault-register under-reporting on
  other emulators (bounded budgets everywhere), and physical-layout
  disclosure via identity mapping (analyzed: domains cannot act on
  GPAs — no supervisor access, no direct map in their spaces).
- **Explicitly not doing:** interrupt remapping (interrupt-broker
  ADR), ATS/device-IOTLB, scalable mode/PASID, RMRR identity ranges,
  multi-segment, IOMMU on pc, AML interpretation or power management
  (ACPI stays parse-only).

## Alternatives considered

1. **No IOMMU, rely on driver discipline.** Rejected — GAP-ANALYSIS
   §2.3 calls it what it is: any driver bug or compromise is a
   full-physical-memory write primitive. The stack ships six DMA
   drivers; the latency of this decision is zero remaining.
2. **Identity-map all of RAM per driver domain.** Rejected — grants
   each device every byte; strictly worse than (1) with extra steps.
3. **Opaque non-identity IOVA spaces.** Deferred — the stronger
   information-hiding model needs a per-domain allocator whose benefit
   QEMU cannot demonstrate (no GPA side channel measurable); revisit
   if GPA-disclosure becomes a stated threat. Identity within granted
   frames gives the same confinement.
4. **virtio-iommu or AMD-Vi instead of VT-d.** Rejected for now —
   virtio-iommu is a different paravirt protocol (no DMAR/MCFG reuse);
   AMD-Vi exists on q35 (`amd-iommu`) but VT-d matches the stated
   target and the Intel SDM-style documentation trail. The `DmaProt`
   trait keeps the swap cheap later.
5. **Interrupt remapping in this ADR.** Rejected — scope discipline;
   the intremap=off lane keeps Phase 0/1 honest, and the interrupt
   broker must own MSI routing design anyway (IRTEs or IOAPIC pins).
6. **A shared kernel DMA pool without per-domain tables.** Rejected —
   one domain's device could reach another's buffers; per-domain
   second-level tables are the whole point.

## Implementation plan (Phase 0 PRs, each ≤ 500 diff lines)

| PR | Content | Tests | Boot markers added | Unsafe Δ |
|---|---|---|---|---|
| 0.1 | This ADR + `docs/arch/iommu.md` (design, invariants, threat model) + `docs/DRIVER-STACK-CHECKLIST.md` | — | — | 0 |
| 0.2 | `src/dmar.rs` + `src/dma.rs`: parser, `DmaProt` trait, broker types, quotas | ~50–70 host tests: layout pins (48-byte header, DRHD=0, unaligned ptrs), every truncation/checksum/bounds case, seeded byte-stream fuzz (never panic/OOB/hang), checked-arithmetic properties | — | 0 |
| 0.3 | `kernel-x86_64/src/arch/acpi.rs` discovery + `boot.sh --verify-q35` lane + CI job `boot-test-q35` (+ negative lane) | ~15–20 kernel host tests (synthetic low memory via memops host mode); QEMU proof: markers grep | `[IOMMU] dmar: absent` (negative lane) / `[IOMMU] dmar: haw=48 units=1` / `[IOMMU] drhd: seg=0 base=0xFED90000 include_all=no scopes=7` | 0 |
| 0.4 | `arch/vtd.rs` registers + bring-up + QI engine + fault regs | ~25–35 kernel host tests via fake register file: encodings pinned, GSTS/IQH spin budgets, FSTS/FRCD decode | `[IOMMU] vtd: ver=0x10 qi=yes sagaw=...` / `[IOMMU] vtd: te=on` / `[IOMMU] vtd: qi round-trip ok` | 0 |
| 0.5 | Second-level map/unmap + domain-ids + boot self-check (kernel walks its own tables via `src::dmar` and reads back the granted set) + capacity constants + self-test wiring | ~15–25 host tests (mapping state machine, quota exhaustion, unmap-after-abort ordering) + boot self-check | `[IOMMU] map: dom=1 npages=1 → walk-back ok` / `[IOMMU] unmap+inval: walk-back absent ok` / `[IOMMU] policy: dma-drivers=0 (fail-closed ok)` | 0 |

Expected unsafe-count delta across the whole phase: **zero** (89 stays
89). If reality disagrees, the offending PR carries the ADR reference
and a justification line in unsafe-count.txt — the ratchet contract.

Deferred to Phase 2 (recorded so nobody hunts for it in Phase 0):
live enforcement proof (`[IOMMU] fault: sid=... reason=... → dom=N
quarantined`) and the descriptor-snapshot rule's implementation, both
of which need a real DMA device on the q35 lane.

## Evidence appendix — reproducible probes (2026-11-20)

Probe scripts (socket-monitor QEMU boot probe with pmemsave windows,
and a sparse-window ACPI/DMAR parser) are re-run from
`scripts/` in the working sandbox; they move into the repo as dev
tooling with PR 0.3.

```
$ qemu-system-x86_64 --version          # QEMU 10.0.13 (Debian trixie)
$ ./qemu-probe.py q35 -device intel-iommu
  verdict=PASS ... pmem: low 1 MiB + [0x7F00000,0x8000000)
$ ./parse-dmar.py low.bin low.bin.hi:7f00000
  RSDP @ 0xf52c0: rev=0 oem='BOCHS '
  RSDT @ 0x7fe23c9 — FACP APIC HPET MCFG DMAR WAET
  DMAR @ 0x7fe2329 len=120 haw=48 flags=0x01
    DRHD @ +48: seg=0 include_all=False reg_base=0xfed90000 len=72
      ioapic, 00:00.0, 00:01.0, 00:02.0, 00:1f.0, 00:1f.2, 00:1f.3
  # with virtio-blk-pci,iommu_platform=on,disable-legacy=on:
    DRHD ... len=80 ... + 00:03.0
  # q35 without -device intel-iommu: NO DMAR TABLE
```
