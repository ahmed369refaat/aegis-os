# Driver Stack — Checklist & Proof Ledger

The definition of "done" for the driver-stack mission. Rule
(GAP-ANALYSIS-v2 §method): an item "exists" only when a test, a CI
job, or a grepped boot marker proves it. **A driver that compiles but
never proves itself on a device in QEMU does not exist.** This file
is the living ledger: updated after every PR, and nothing gets
checked without its proof.

Baseline: commit `a915e60`, re-verified line-by-line on 2026-11-20
(see the verified-facts section below). Phases are dependency- and
security-ordered; each phase is PR-sized slices per CONTRIBUTING
(≤ 500 diff lines, ≥ 80% host coverage on testable logic, markers,
docs with threat model, ADR before code, ABI-VERSION bump only for
syscall changes).

Hard gates applying to EVERY item (not deferrable): host-side fuzz
for its wire format (malformed input → typed error; never panic, OOB,
or hang); threat model + adversarial self-review per component
(docs/arch/<component>.md); documented lock/IRQ context and global
lock order, no spinlock across anything that can sleep or fault; all
driver↔kernel traffic on ADR-0004 IPC (64-byte fixed messages,
depth-4 FIFO, capability-gated; parse exactly once, fully, at the
receiving gate; checked arithmetic on every hardware/domain-supplied
length; fail closed with Log→Tighten→Quarantine; degraded driver =
no IPC = drain + clean exit); syscall surface never exceeds
`driver_profile()`; DMA only via the kernel broker (ADR-0013).

## Phases

0. IOMMU/VT-d — **BLOCKING**: nothing DMA-capable merges before it.
1. Foundations, no DMA: PCI enumeration, interrupt broker, driver
   model, ACPI parse-only.
2. Storage: virtio-blk, NVMe, AHCI, block layer + ext2 (read-only
   first).
3. Network: virtio-net, e1000.
4. Input & display: PS/2 keyboard, XHCI + one HID keyboard (hub/tree
   explicitly out of scope), basic framebuffer (no GPU acceleration).
5. RTC + HPET + hardening.

## The checklist

| # | Item | Phase | Done means (proof form) | Status |
|---|---|---|---|---|
| 1 | IOMMU/VT-d | 0 | ADR-0013 accepted; DMAR walker + DRHD init + map/unmap + QI round-trip proven by host tests + q35-lane markers; **enforcement proof (unmapped DMA faults) deferred to the first real DMA device (Phase 2 virtio-blk) — recorded as an honest split, not silently claimed** | PRs 0.1–0.5 landed — **Phase 0 code complete**: parser+broker (49 host tests), discovery on 3 lanes, VT-d live (TE, ctx/SLPT, QI invalidation, 13 host tests), and the **DmaBroker live over VT-d** (boot-proven: cookie-only views, AbortRequired ordering, quota refusal, revoke_all teardown; `dma-drivers=1/0` verdict markers on positive/negative lanes, CI-grepped). Claim-path gating + domain-destroy revoke hook = Phase 1 item 4; enforcement = Phase 2 |
| 2 | PCI/PCIe enumeration | 1 | CF8/CFC type-0/1 walks + ECAM via MCFG (MCFG verified present on q35); capability walk; BAR sizing with overflow checks; boot marker prints the tree; fuzz on config headers | not started |
| 3 | Interrupt broker | 1 | Kernel-owned vector table above 0x30 (existing 32..=47 + 48 wiring reused, not rebuilt); IOAPIC routing design (IOAPIC 0xFEC00000 inside the LAPIC window GiB); MSI/MSI-X allocation as capabilities; own ADR (owns the IRTE decision — lane runs intremap=off until then, per ADR-0013) | not started |
| 4 | Driver model | 1 | DriverDomain lifecycle probe→claim (Device capability, GRANT-gated)→start→degrade→teardown; monitor telemetry feeds (incl. broker faults); markers for each transition | not started |
| 5 | virtio-blk | 2 | Queue setup, descriptor validation, snapshot rule, timeouts/abort; DMA via broker only; **ADR-0013's enforcement proof lands here** (negative test greps the FRCD fault marker); `iommu_platform=on,disable-legacy=on` (verified incantation) | not started (QEMU facts pre-verified) |
| 6 | NVMe | 2 | Admin + I/O queues, PRDT bounds validation, timeout/abort, error recovery to known state; fuzz on queues/completions | not started |
| 7 | AHCI/SATA | 2 | Port enumeration, FIS validation, NCQ where supported, timeouts; same BlockDevice trait as 5–6 | not started |
| 8 | Block layer + ext2 (read-only first) | 2 | Bounded request queue; superblock/group/dirent/inode validation + fuzz; checked arithmetic everywhere; write path behind the existing VFS capability | not started |
| 9 | virtio-net | 3 | RX/TX ring validation; packets enter brokered sockets only (existing token buckets reused); fuzz on rings | not started |
| 10 | e1000 | 3 | Same discipline as 9; fuzz on descriptors/RX rings | not started |
| 11 | PS/2 keyboard (i8042) | 4 | Scancode-set negotiation; buffer-overflow recovery; marker: keystroke round-trip in the boot demo | not started |
| 12 | USB basic (XHCI + one HID keyboard) | 4 | XHCI bring-up (MMIO doorbells/registers via memops), device enumeration, interrupt-IN pipe; hub/tree support **explicitly out of scope, stated in its ADR**; TRB-stream fuzz; DMA via broker | not started |
| 13 | Basic framebuffer | 4 | Linear FB from multiboot/QEMU (stdvga/VBE or virtio-gpu scanout), double-buffered writes, pixel/text layer behind a domain capability; **no GPU acceleration (explicitly out of scope)** | not started |
| 14 | ACPI tables (parse-only) | 1 | RSDP/RSDT/XSDT walk + MADT (IOAPIC entries feed items 2–3) + fixed MCFG for ECAM; **DMAR slice lands earlier with item 1 (src/dmar.rs)**; no AML, no power management; fuzz per table layout | not started (DMAR slice scoped by ADR-0013 D2) |
| 15 | RTC + HPET | 5 | Read-only wall clock (RTC); HPET as LAPIC-timer calibration source (HPET table verified present on q35); lowest priority | not started |

Scale reality check (separate PR, ADR only if an invariant changes):
raise the toy limits (MAX_DOMAINS=4, MAX_ENDPOINTS=8,
MAX_CAPABILITIES=16) to measured construction parameters with a
capacity self-test.

## Verified baseline facts this plan stands on (2026-11-20, a915e60)

- Tests at Phase-0 PR 0.2: `cargo test` 300 passed (282 lib — incl.
  49 IOMMU-policy tests — + 6/10/2 integration); `cargo test -p
  aegis-kernel` 88 passed; `cargo fmt --check` clean;
  `scripts/check_unsafe.sh` PASS **89/89** — the pin at a915e60 is 89
  (ADR-0012 moved it 78→89; the growth-needs-an-ADR invariant is
  intact, and PR 0.2 held the ratchet at 89 with zero unsafe).
- `boot.sh --verify`: PASS on pc (QEMU 10.0.13, TCG, 48 s, clean
  poweroff). The unmodified kernel also boots `-M q35 -device
  intel-iommu` to the full M1 PASS and powers off (~22 s) — the
  machine-type risk for the IOMMU lane is retired.
- DMAR/DRHD enumeration chain proven from raw memory dumps (ADR-0013
  evidence appendix): DRHD `reg_base=0xFED90000`, 48-bit HAW,
  `include_all=false`, scope-listed devices incl. an added virtio-blk;
  q35 without the IOMMU device ⇒ no DMAR (fail-closed path testable);
  ECAP always QI; FSTS 0x34 / FRCD 0x220 implemented and pollable;
  VER reads 0x10; the register window sits inside the existing LAPIC
  1 GiB window PTE ⇒ zero new mappings, zero unsafe delta targeted.
- CI: 10 jobs incl. thumbv7em no-std + aarch64/riscv64 policy-core
  builds; the new q35 lanes are additive.
