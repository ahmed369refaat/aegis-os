# Changelog

All notable changes to AegisOS. Format: [Keep a Changelog](https://keepachangelog.com/), versions: [SemVer](https://semver.org/).

## [Unreleased] — Stage 1: Ring-3 isolation (in progress)

### Changed — review round 5, Phase D: leftovers made loud

- **MAX_SESSION_FRAMES is proven, and outgrowing it is LOUD**: the
  per-driver frame sets are enumerated in the constant's doc (vblk 5,
  vnet 8, e1k 4, nvme 6, ahci 4, xhci 2+4 — largest is 8 of 16);
  `DriverSession::frame()` now returns a typed `FrameError::{Pool,
  Budget}` instead of a bare Option, and a budget violation prints
  "[SESSION] BUDGET EXCEEDED..." at close — never again a silent
  "pool exhausted" for a driver bug. Host test
  `frame_budget_exceeded_is_loud_and_conserving` pins it (16 frames
  in, the 17th refused, everything conserved). Writing that test
  caught a REAL harness hazard: world()'s 9-frame FakePhys buffer
  corrupts the host heap when a test allocates past it — the budget
  test uses a dedicated 192 KiB backing (documented in the test).
- **Bridge topology**: already a loud refusal (the "[PCI ] bridge at
  this slot — devices behind it are NOT driven (isolation boundary,
  F9)" marker) with the claim gate host-tested (ClaimError::
  BridgeClass/NotEndpoint, pci.rs's fake-config tests); the bus-0-only
  limitation stays documented in the module header and the checklist
  row. No code change needed — verified, not reimplemented.
- Test counts regenerated (497 -> 498).

### Changed — review round 5, Phase C: history, secrets and repo guards (NO history changes)

- **`scripts/check-history-clean.sh`**: scans every blob reachable
  from any ref — not just the tree at HEAD — for the incident classes
  (ELF cores via the 20-byte header's e_type, oversize blobs outside
  the known allowlist, assignment-shaped credential patterns shared
  with check-no-binaries.sh, with the same self-literal exclusions).
  Measured today: exactly the three historical `kernel-x86_64/core`
  blobs (8,167,424 / 8,183,808 / 2,805,760 bytes) and nothing else —
  zero false positives. Wired into CI as REPORT-ONLY: its failure is
  the standing reminder that the human purge is pending; the flip to
  `--strict` (build-fatal) is documented in the script, the runbook,
  and the CI step.
- **The incident runbook grows the verification step**: after the
  purge, both `git log --all --oneline -- kernel-x86_64/core` and
  `git rev-list --all --objects | grep -E '(^|/)core$'` must print
  NOTHING — checked on the purged clone before pushing and on a fresh
  clone after.
- **`check-ist-sections.sh` fails honestly**: a missing kernel ELF now
  prints "kernel ELF not found: build first or pass a path" instead of
  the misleading "IST symbols missing" (hit twice in practice during
  this round — the raw kernel ELF, not the packaged boot image, is
  the expected argument; CI already invokes it argument-less after the
  build).
- NO history was rewritten, no refs deleted, no force used — the
  purge and rotation remain human steps per the runbook.

### Changed — review round 5, Phase B: hostile-device tests for every driver

The drvstack tree compiled OUT of test builds entirely
(`#[cfg(not(test))] mod drvstack`) — every driver module had ZERO
tests and nothing exercised a lying device. Phase B opens the tree to
host builds (the step functions stay cfg'd; the pure logic does not)
and drives the REAL driver code — memops is identity on host, so the
actual submit/encode/parse functions run against the new fakes:

- **`drvstack/testharness.rs`**: one shared, deterministic harness —
  a scriptable fake `MmioBus` (constant / cycling-sequence /
  flipping-garbage registers, a write log), a budget-capped fake
  `DmaProt`, the host-"physical" `FakePhys` buffer pattern, and the
  repo's xorshift. The harness has its own self-test (which caught a
  real mixing bug: xorshift's three shifts do not propagate low-bit
  differences into the high half — folded with a finalizer).
- **Per-module hostile tests** (19 in drvstack, every driver module
  covered): nvme's SQE encoder + CQE poll (the F11 pin: the data
  pointer at BOTH +16/+24, the phase bit at 16; a never-completing
  device cannot hang the poll — budget-bounded by test; 1000-garbage
  CQEs, every accepted status within bounds); e1k's TX descriptor +
  the RX DD bit (garbage in neighboring fields cannot flip it); ahci's
  READ-DMA-EXT command table (every ADR-0014 offset pinned — each was
  once wrong; a 1000-LBA fuzz roundtrips the 48-bit field); xhci's
  No-Op TRB + event-type extraction (bounded to 6 bits under garbage);
  netutil's DHCP DISCOVER (checksum VERIFIES over the built packet;
  1000 hostile MACs all build checksum-valid frames); vblk's
  3-descriptor chain (IN/OUT flag polarity, avail publish + wrap
  semantics); vnet's avail publish; legacy's BCD decode (hostile
  nibbles decode to face value, never panic).
- **Extractions** (the trait-seam move the round asked for):
  e1k::build_tx_desc/rx_desc_done, xhci::build_noop_trb/
  event_trb_type, ahci::build_read_dma_cmdtable/
  build_identify_cmdtable (module-scope, host-testable; the boot steps
  call them — single source of truth), netutil un-cfg'd, vblk::submit
  and vnet::net_publish un-cfg'd, legacy::bcd_decode extracted.
- The step-orchestration modules without their own #[test]
  (drvstack/pci.rs, vtd.rs, broker.rs, ext2.rs, acpi.rs) are thin
  sequencing over layers that ARE tested (crate pci.rs, arch/vtd.rs,
  arch/acpi.rs, the ext2 policy core) — noted in the report.
- Boot markers byte-identical (all three lanes PASS unchanged).

### Changed — review round 5, Phase A (ADR-0018): one IOMMU domain per device

The main remaining isolation gap: every device sat in IOMMU domain 0
(one shared second-level table — any device could DMA into any
other's buffers; one driver's revoke_all(0) tore down every driver's
mappings; ADR-0015's domain-scoped cookies had no second domain to
be wrong in). Red test first: `device_tables_are_isolated_per_domain`
FAILED on the old claim shape (both devices in dom 0 share one SLPT).

- **ADR-0018**: domain 0 is the kernel's own (the hw-proof + broker
  demo); every claimed device draws its own id from the kernel-side
  `DomainIds` allocator (never device-supplied; exhaustion = typed
  None; release is explicit and double-release refused). The hardware
  proof now UNASSIGNS its probe device (context clear + QI
  context-cache invalidation — the only way a device changes
  domains); `assign_device` refuses an already-assigned device.
- **DriverSession carries the domain** (from PciDev.dom, set at
  claim time): map/complete/unmap/revoke_all all scoped — one
  session's teardown provably leaves every other's mappings alone.
- **The table budget is derived, not guessed**: a pure
  `worst_case_tables(domains)` (shared root+IQ+ctx + per-domain
  root+PDPT+PD+9 PT spans) sizes TABLE_BUDGET to 99 (was 64 — 6-8
  devices × per-domain trees would have exhausted it). The exhaustion
  test drives the new sizing to its edge: typed refusal, cursor
  consistent, no table aliasing.
- **Live negative probe on the q35 lane**: the e1000 (its own domain)
  DMAs at a page mapped ONLY in the virtio-net's domain — it MUST
  fault; the lane grep requires "cross-device DMA FAULTED
  (FSTS.PPF set)" and --verify-q35 FAILS without it. Measured: it
  faults.
- **Truthful teardown markers**: `revoke_or_quarantine` now reports
  revoked/freed/quarantined/poisoned counts per domain and never
  claims "frames return scrubbed" when any region was poisoned. The
  claim markers carry the real domain id ("→ dom 3 ok"); the lane
  greps were updated in the same commit (dom-number-agnostic
  prefixes).
- Host tests: per-domain isolation (A's page absent in B's walk; the
  same frame in both domains only via separate map_runs; unmap
  scoping), reassign-until-unassigned, budget math, multi-domain
  exhaustion, a 3000-step xorshift property test over random
  assign/map/unmap/unassign sequences (no aliasing, per-domain
  presence matches the model after every sampled step), and the
  DomainIds allocator (kernel-domain reservation, exhaustion,
  release rules).

### Docs — review round 4, Phase 6: ADR-0017 — ring-3 driver domains

The architecture ADR-0016 built its seams for: drivers become ring-3
monitored domains with exactly four grants — an `IpcMmio` channel
(the device core checks every offset against the same validated
window), broker-only DMA (domain-scoped cookies), an organic monitor
feed the domain cannot forge, and a `Device` capability for its own
device. A driver bug becomes a quarantined domain event, not a
kernel compromise. The first implementation slice is the `IpcMmio`
channel; polling stays (no IRQ routing in this phase), one domain
per device, the domain image built with the kernel like today's
ring-3 examples.

### Changed — driver-stack review round 4, Phase 5 (F13): ext2 parsing moves to the policy core

- **`src/ext2.rs` — the on-disk parser, pure and validated.** Every
  structure the boot walk consumed (superblock, inode, dirent) moves
  from the kernel's raw field reads into the policy lib as pure
  functions over byte slices: magic/inode-size sanity, inode-number
  and block-range geometry math (every step checked against the
  superblock's own counts), inode extents bounded by the slice, and
  a directory walk where a hostile record (rec_len < 8 + name_len,
  not 4-aligned, zero, running past the block, or a name crossing
  the caller's slice edge) is a typed refusal — never a skipped
  record, never a panic.
- **The kernel keeps the transport and the markers**: sector reads
  through AHCI, the boot markers byte-identical (the lane grep pins
  hello.txt's line verbatim), and explicit refusal markers naming
  the policy verdict on hostile images.
- **Host tests pin the parser from every side**: the real
  `mkext2.py` image (mirrored by a test builder) parses end-to-end
  to "HELLO-AEGIS-EXT2."; hostile superblocks (bad magic, inode
  sizes 0/999/130, truncation) refuse; hostile inode numbers and
  blocks refuse; hostile dirents refuse-never-skip; the exact
  512-byte-sector shape the kernel hands the parser (a last record
  padding its rec_len to the 1 KiB block end, past the slice) is
  pinned as its own test; and a deterministic 2000-iteration fuzz
  (seeded corruptions biased at the format's structures) runs the
  full parse chain with zero panics.

### Fixed — driver-stack review round 4, Phase 5 (F12): ACPI firmware-table validation

- **`read_table` (the DMAR/RSDT path) now verifies the ACPI
  checksum** — every byte of the declared length must sum to zero. A
  bit-flipped table was previously a parsed table (length was the
  only check). Red-proven by `read_table_rejects_checksum_corruption`
  on the pre-fix code.
- **`table_ok(pa, sig, scratch)` — the validation gate for the
  directory walk's target tables**: signature, declared length
  (36..=scratch), and checksum before the HPET/MADT/MCFG walks trust
  a pointer they found in the RSDT/XSDT. The directory itself is
  validated first (sig + length + checksum — the old walk trusted a
  raw header length), and each target table is gated before any
  field read; a corrupted table prints an explicit refusal marker
  instead of walking hostile bytes. Host tests pin the gate from
  every side: valid table accepted with its length, broken checksum
  refused, wrong signature refused, hostile lengths (0, 35, 1025,
  u32::MAX) refused, and the minimum legal 36-byte table accepted.
- The lane markers are unchanged on healthy firmware (all three
  lanes PASS); the q35 lane caught a byte-1 sig heuristic bug
  (R**S**DT vs X**S**DT share byte 1) before it shipped.

### Fixed — driver-stack review round 4, Phase 5 (F11): the NVMe data path — SOLVED

Two compounding layout quirks of this QEMU's nvme plus one lane
device property, each masking the others for two sessions:

- **The command data pointer is read from SQE bytes 24-31** (the
  spec's PRP2 slot), not 16-23 — measured by planting a distinct
  page in every PRP-candidate slot and watching the identify DMA
  fault at exactly the +24 plant (1,024 IOMMU write faults on its
  page) while ignoring the +16 plant. The historical "data lands at
  PA 0" was this bug writing at pointer 0 in the pass-through era.
  The driver now writes the pointer at BOTH slots — spec hardware
  ignores PRP2 for single-page aligned buffers, so both worlds work.
- **CC's entry-size fields sit at bits 19:16 (IOSQES) / 23:20
  (IOCQES)** here, not the spec's 23:20 / 27:24 — measured by
  QEMU's own `pci_nvme_err_invalid_create_cq_entry_size iosqes 4
  iocqes 6` after a spec-layout write. CC returns to 0x0046_0001
  (the value the 2026-11-20 session had and "fixed" into the spec
  layout while chasing the PRP symptom).
- **The lane's nvme device needs `num_queues=2`** — the property
  defaults to 0 (zero I/O queue pairs; `max_ioqpairs` is only a
  cap). The q35 lane now passes it.

After all three, the FIRST complete NVMe run: the Identify data
page arrives (serial "AEGISN1", VID 0x1b36, NN=256), CreateIoCq +
CreateIoSq pass, and a 512-byte LBA-0 read completes through the
IOMMU. The lane greps pin all of it. docs/arch/drivers.md's anomaly
note is rewritten as the resolution (the AHCI-retraction pattern).

### Changed — driver-stack review round 4, Phase 4-B (ADR-0016): MmioBus windows

- **`kernel-x86_64/src/mmio.rs` — every device register access goes
  through a bounds-checked window** (ADR-0016). A `MmioWindow` is
  established once per device — `BarMmio` from an enumerated BAR
  (base + the size the scanner measured), `FixedMmio` for
  firmware-named blocks (the HPET) — refusing zero-length and
  wrapping ranges. The `MmioBus` trait's accessors (`read8/16/32/64`,
  `write32/64`) take window-relative offsets and refuse out-of-window
  access with `None`/`false` — a device-supplied number (or our own
  arithmetic bug) can never steer the kernel outside the claimed
  registers; refusals are verdicts the caller handles, never panics
  and never a silent 0. The window math is pure and host-tested at
  the edges (zero/wrap refusal, `off+len` overflow, the last valid
  byte, a 16-bit access straddling the end, byte reads needing their
  whole containing dword, and a fake-bus test proving out-of-window
  offsets never reach the volatile core). The volatile core delegates
  to `memops` — no new `unsafe` enters the tree (check_unsafe 93/93).
- **Five drivers converted** (e1k, nvme, ahci+ext2, xHCI ×2 steps,
  HPET): raw `memops::*(bar_base + off)` register accesses are gone;
  the device-derived offsets that remained raw — NVMe doorbells
  (stride from CAP.DSTRD), xHCI's caplen/dboff/rtsoff — are now
  door-checked once then window-checked per access, and every
  refusal prints an explicit marker. The virtio drivers keep their
  F5 `MmioVirtio` (already windowed at `resolve()`); the arch layer's
  own registers (LAPIC, VT-d programming in `arch/vtd.rs`) stay in
  the tested arch module.

### Changed — driver-stack review round 4, Phase 4-C (ADR-0016): one-close() DriverSession (F10)

- **`kernel-x86_64/src/session.rs` — the mid-flight refusal leak dies
  by construction.** Every driver run (vblk, vnet, e1k, nvme, ahci,
  both xHCI steps) now acquires pool frames and broker regions
  through a `DriverSession` that records them as they are acquired;
  ONE `close(out)` runs the ordered teardown (BME off →
  revoke_or_quarantine → frames home) with the lane markers verbatim,
  and `Drop` is the silent safety net — a driver that returns early
  for ANY reason still cannot strand a frame, leave a region mapped,
  or leave a device with bus mastering past its owner's lifetime.
  Pinned by four host tests (a fake `DmaProt` + the real
  `FramePool`/`Kernel`): `no_frame_stranded_on_early_refusal` (alloc
  three, map two, refuse the third, drop — everything home),
  `close_frees_and_revokes_everything` (marker verbatim),
  `drop_alone_is_the_safety_net`, `identity_close_prints_and_frees`.
- The session is generic over `DmaProt` (the fake in tests today;
  ADR-0017's brokered channels next) and carries the teardown core
  (`revoke_or_quarantine` moved in from drvstack/mod.rs — it was only
  ever the session's engine). `strutil::line` is the shared logging
  primitive (moved out of drvstack for the same reason).
- The identity lanes close correctly for the first time: bus
  mastering is cut BEFORE the frames go home (the old hand-rolled
  identity teardowns freed first — a real device-reach window on the
  no-IOMMU lane).
- vblk's enforcement probe runs through the session
  (`complete_unmap` + `with_prot` + `hand_back` — the unmapped data
  page returns home exactly once).

### Changed — driver-stack review round 4, Phase 4-A (ADR-0016): the module split

- `kernel-x86_64/src/drvstack.rs` (4,389 lines, twelve subsystems
  accreted across ADR-0013/0014/0015 and F4–F9) is now
  `src/drvstack/` — one module per subsystem (`vtd`, `broker`, `pci`,
  `vblk`, `vnet`, `netutil`, `e1k`, `nvme`, `ahci`, `xhci`, `acpi`,
  `ext2`, `legacy`) with `mod.rs` keeping the shared teardown
  discipline, the pool-owner tags, and the step sequencing. A **pure
  move**: signatures, boot markers, and lane greps stay
  byte-identical — all three boot lanes PASS on the split alone (the
  pc lane's M1 exit criteria, the q35 lane's VT-d trace assertions +
  7/7 screen check, the q35-neg fail-closed control).
- The ADR index rows for 0014/0015 (missing since their landing) are
  restored; ADR-0016 documents the split and the two commits that
  follow in-phase (MmioBus windows, one-close() DriverSession).
- One source typo fixed in the move: AHCI_OWNER's doc comment had a
  `//` line where `///` was meant.

### Fixed — driver-stack review round 4, Phase 2 (ADR-0015): IOMMU integrity

- **F1 — `map_run` is atomic** (a `DmaProt` contract guarantee now):
  the table demand is precomputed by a pure read-only walk and checked
  against the budget BEFORE anything is written; the table cursor
  commits every linked frame on every exit path (a table frame is
  never handed to two parents); residual errors roll back every page
  the call wrote. Pinned by `map_run_is_atomic_on_budget_exhaustion`
  (red on the pre-fix code), a 300-step xorshift property test, the
  pure `check_no_table_aliasing` walk, and a reusable
  `dma::contract` harness run against BOTH the fake and the real Vtd.
- **F2 — revoke fails closed**: `revoke_all` returns
  `{revoked, poisoned}`; a region whose hardware unmap failed is
  poisoned (still live in hardware, still holding its quota,
  enumerable for kernel quarantine), its frames are re-tagged under a
  `QUARANTINE_OWNER` in the FramePool and never freed, the device's
  bus mastering is cut (new `pci::disable_bus_master`, a 16-bit
  command write that never echoes the RW1C Status half), and
  `retry_poisoned()` is the only release path. All 19 drvstack
  teardown/refusal sites route through one `revoke_or_quarantine`
  helper (this also fixes the VBLK teardown frame leak and its lying
  "frames return scrubbed" marker).
- **F3 — cookies are domain-scoped**:
  `region_complete(dom, cookie)` / `unmap_region(dom, cookie)`; a
  foreign cookie returns the same `InvalidHandle` as an unknown one
  (no oracle), and the domain id always comes from the kernel.
- Typed `DmaError::OutOfTables` (+ wire refusal 11) for the atomic
  budget refusal.

### Fixed — driver-stack review round 4, Phase 0 + Phase 1 (ADR-0014)

- **P0.1**: the 8 MiB ELF core dump committed as `kernel-x86_64/core`
  (environment block included) is untracked; `.gitignore` covers core
  files; `scripts/check-no-binaries.sh` (self-tested, CI-wired) fails
  on tracked ELF cores, oversize files, and credential patterns;
  `docs/incident-core-dump.md` is the maintainer runbook (token
  rotation + history purge are human steps).
- **P0.2**: clippy clean on the pinned toolchain for BOTH profiles
  (host: 5 errors; kernel target: 43 more behind `cfg(not(test))`),
  plus the asm-pattern guard generalized off its %rbx-only heuristic
  (false positive on `cpuid1_ecx`).
- **ADR-0014**: context entries carried TT=0b10 — pass-through — so no
  device ever walked the second-level tables (`vtd_pt_enable_fast_path`
  ×8, six devices; enforcement probe completed against an unmapped
  page). TT=0b00 + non-leaf entries now carry W (VT-d checks R/W at
  every level). The q35 lane boots with `-trace enable=vtd_*` and
  FAILS on any fast-path event or a missing `PPF=yes`.
- Cascades solved by real translation: virtio-net and e1000 full DHCP
  round trips through the IOMMU; AHCI's "stale FIS" was three driver
  bugs (PRDT DBC offset, FIS LBA offsets, missing sector count) — the
  ext2 mount now reads hello.txt on BOTH the IOMMU and no-IOMMU lanes.
- Boot-lane hygiene: the q35/q35-neg lanes now generate all their disk
  images (previously they existed only on one dev machine — a latent
  CI break), and the no-IOMMU control lane carries the AHCI control
  experiment.

### Added — PR-1.1: exception machinery (`kernel-x86_64/src/arch/`, ADR-0005)

- Kernel-owned GDT/TSS/IDT mirroring the boot stub's selector map (the
  boot ABI — pinned by a host test against the stub's literal GDT
  values), a uniform exception frame from 32 naked stubs generated by
  one macro, IST stacks for `#DF/#NMI/#MC/#SS` (`#PF` deliberately not),
  and a Rust dispatch printing full diagnoses (vector/rip/cs/err/cr2).
- Live selftest: the boot forces a hardware `#DE`; `boot.sh --verify`
  greps the diagnosis and marker lines.

### Added — PR-1.2: higher-half kernel + direct map (`kernel-x86_64/src/mm/`, ADR-0002)

- The kernel links at `0xFFFFFFFF80000000`, loaded at PA 2 MiB (linker
  `AT()`; objcopy places by LMA), and the stub maps three windows before
  entry: kernel image, direct map (`0xFFFF888000000000`+PA, RW, never
  executable), and a bring-up identity window that `mm::init` **tears
  down and proves dead** (PML4[0]=0 + CR3 reload + read-back assert).
- `memops` becomes the one physical-memory door (translate-through-
  direct-map; host tests unchanged by an identity `translate`); `mm`
  itself is unsafe-free.
- Guarded kernel stacks (`mm/stacks.rs`): one 2 MiB slot per stack,
  absent-PTE guard page, PD/PT/frames from the pool with owner 0,
  scrub-on-free, per-page `invlpg`.
- Per-CPU state at the GS base (`arch/percpu.rs`).
- The `#DE` selftest now **returns** (dispatch advances RIP past the
  `idiv`; `exception_common`'s unwind is live — the seed of Ring-3
  fault→signal delivery), and the boot ends with a terminal guard-page
  `#PF` proof (`cr2` names the exact guard page).

### Added — PR-1.4: SYSCALL/SYSRET entry + ring-3 machinery (ADR-0005; status: environment-blocked, see below)

- `arch/gdt.rs`: STAR slot arithmetic made real — user data @0x20 /
  user code @0x28 (SYSRET SS=base+8 / CS=base+16), a dedicated
  SYSCALL pair @0x30/0x38, TSS at 0x40, `set_rsp0`/`rsp0`; pinned by a
  new host test.
- `arch/syscall_entry.rs` (new): STAR/LSTAR/FMASK/SCE MSRs,
  KERNEL_GS_BASE = user value (swapgs partner), naked entry: swapgs,
  stack from a static, 12-quadword SysV-aligned frame, RDTSC-bracketed
  dispatch, restore-all-but-RAX/RCX/R11, swapgs, sysretq.
- `syscall.rs` (kernel, new): the shared gate first
  (`aegis_os::syscall::gate`, extracted from `request_syscall`), a
  full-width syscall-number bounds check (nr=256 must not truncate
  into SYS_READ — host-tested), SYS_WRITE with per-page user-buffer
  validation, -ENOSYS + audit counters for unknown numbers.
- `sched/context.rs` (new): UserContext / launch (explicit RSP+RIP
  resume point — immune to the LTO tail-jump on `-> !` entry points,
  a real bug this PR found and fixed) / resume_kernel / user-run state.
- `mm/user_layout.rs` + `mm/user.rs` (new): canonical user layout
  (host-tested against the real ten-check gate) and spawn_user_blob.
- `examples/ring3-hello` + `examples/ring3-rogue` (new): flat-asm user
  blobs built by boot.sh; rogue performs one hostile act per run.
- #PF moved to a dedicated IST; a CPL3 fault during an active run is
  the user's death, not the kernel's (recorded + honest verdict).
- `Makefile` with `test-qemu-pr14`; unsafe ratchet 39 to 61 (all in
  allowlisted arch/sched modules, each with a SAFETY note).
- Status (documented in `docs/arch/syscall-entry.md`): in this
  sandbox's QEMU (10.0.13 TCG, no KVM) the first user-context fault
  cannot be relayed by the inter-privilege delivery path; one build
  did reach ring-3 executing real gated syscalls. The boot ends the
  chapter with `[RING3] launch blocked` + a clean poweroff; the full
  marker set is required the moment the environment allows it. Real
  bugs fixed along the way: nr-truncation smuggling, KERNEL_GS_BASE
  initial value, missing user-CR3 activation, LTO
  tail-jump/unreachable-deletion on `-> !` entry points, an
  indirect-`jmp *sym` misuse.

### Added — PR-1.3: per-domain page tables (`kernel-x86_64/src/mm/{pte,page_table}.rs`, ADR-0002)

- `mm/page_table.rs`: the lib's ten-check `AddressSpace::map` runs
  first and is the only gate; accepted regions become live PTEs (U set,
  NX unless executable, fresh scrubbed pool frames, guard gaps as
  absent PTEs). Walk/unmap/translate are allocation-free and
  **unsafe-free**; host tests cover the walk, policy gating
  (GuardGap/W^X/NULL/kernel-half), disjoint same-VA tables, unmap, and
  pool-exhaustion rollback.
- `mm/pte.rs`: `PteFlags` → PTE bits (XD for `!x`), `USER_LIMIT`
  enforcement, per-page TLB flush. EFER.NXE + CR4.PGE enabled in
  `mm::init`; kernel leaves marked global; the direct map's 1 GiB leaf
  becomes RW+NX (never executable, now hardware-enforced).
- QEMU selftest (CI-grepped): two domains, the same VA resolving to
  different frames; an NX instruction-fetch fault (`err` P+I/D) that
  **resumes execution**; an RX page executing `ret`; the policy
  guard-gap page faulting on read with CR2 naming it.
- Generic pool: `BuddyAllocator<const N>`, `Kernel<const N>`,
  `FramePool<const N>` (defaults keep every existing call site green);
  the kernel boots a 4096-frame pool (physical 16..32 MiB).
- Fixed a real fault-resume bug found by the selftest: the NX trigger
  must be a faulting `jmp`, not `call` — a faulting `call` pushes its
  return address before the fetch fault and silently slides every
  RSP-relative local in the caller.

### Changed

- Unsafe ratchet 23 → 33 (PR-1.2), then 33 → 39 (PR-1.3: two `hw` CR4 wrappers, four exceptions selftest items) (five `hw` wrappers: cr3 r/w, invlpg, wrmsr,
  rdmsr; two `memops` `_va` variants; two percpu derefs; one fault
  trigger) — referenced to ADR-0002.
- CI: kernel-build greps the higher-half entry point
  (`0xffffffff80000000`); boot-test greps the new `[MM ]`/`[EXC]`
  markers.

## [0.2.0] — 2026-11-19 — "It boots" (M1)

The project is no longer just a library: AegisOS now **boots on QEMU** and
runs its M1 exit-criteria sequence on real physical memory, with CI
proving it on every push.

### Added — bootable kernel (`kernel-x86_64/`, new workspace member)

- Two-stage multiboot v1 bring-up (QEMU's `-kernel` loader rejects
  ELF64 — discovered on the first CI boot run and fixed with this
  design): a pure-asm ELF32 stub (`boot-x86_64/stub.S`) — own GDT,
  identity page tables (1 GiB, 2 MiB pages), PAE → EFER.LME → CR0.PG
  long-mode transition, relocation-free 64-bit handoff — embeds the
  flattened ELF64 kernel at its 2 MiB link base and jumps to its entry
  with the boot TSC stamped at the stub's first instruction.
- Real frame pool: 256 × 4 KiB at physical 16 MiB, claimed only after
  multiboot `mem_upper` validation, managed by the **existing** policy-core
  buddy allocator (the `Kernel.frames` instance), with per-frame ownership
  tracking and **scrub-on-free verified by read-back**.
- The M1 boot sequence: hello domain (guard-gap policy rejecting an
  adjacent mapping live, 3 real backed frames, CFS slices), the proven
  five-window monitor escalation (55 → 50 → 37 → 80 → 80, quarantine,
  healthy neighbor unaffected), supervised cleanup, and a 1000-cycle
  create/destroy stress asserting zero frame leaks. Verdict printed as a
  single `M1-EXIT-CRITERIA` line; clean QEMU poweroff.
- `boot.sh` (one command to build+boot; `--verify` asserts the exit
  criteria and is what CI runs).
- Unsafe policy, machine-enforced: kernel is `deny(unsafe_code)` with a
  documented allowlist (`arch/`, `boot/`, `hw.rs`, `memops.rs`, `sched/`), each
  item carrying a `SAFETY` note; `scripts/check_unsafe.sh` fails CI on
  violations.

### Added — policy core

- `Kernel::destroy_domain`: releases pipe ends (dup-aware), brokered
  socket, rate bucket, scheduler registration, and the table slot; works
  on quarantined domains (the supervised-respawn removal path). Files it
  created persist (Unix semantics).
- Public `Kernel::domain_mut` accessor for supervisors and the kernel
  runtime (all Domain fields were already public).

### Changed

- Repository is now a Cargo workspace (`kernel-x86_64/` member;
  `default-members = ["."]` keeps root `cargo test` scoped to the core).
- CI expanded from 3 to 7 jobs: core tests, kernel host tests (the same
  M1 sequence logic without an emulator), ARM no_std build, kernel ELF
  build with ELF sanity checks, **QEMU boot test**, dependency audit
  (workspace-wide), and the unsafe-policy allowlist check.
- Docs: README rewritten around the real boot status; new
  `docs/SECURITY-MODEL.md` one-pager; `docs/M1-PLAN.md` (assessment,
  design, exit-criteria mapping); ARCHITECTURE/ROADMAP updated.

### Numbers

- Tests: 196 (policy core) + 23 (kernel host) = **219**, all green.
- Kernel ELF: ~53 KiB release; kernel image + bss + stack end ≈ 0x14F010,
  far below the 8 MiB safety line and the 16 MiB pool.
- Boot time target (< 300 ms in QEMU) is measured and reported by the CI
  boot job (wall-clock of the full QEMU run, startup included).

## [0.1.0] — 2026-11-19 — Policy kernel M0 + Linux semantics

- Attenuation-only syscall masks, capability generations, ten-check memory
  policy, VFS with Unix DAC + chroot, fd tables, refcounted pipes,
  POSIX signals, CFS scheduling (real Linux weight table), buddy
  allocator, brokered rate-limited sockets, executing syscall layer
  (gate → execute), behavior monitor with graduated response, SPSC
  telemetry rings.
- 191 tests; zero dependencies; `forbid(unsafe_code)`; no_std proven on
  thumbv7em-none-eabihf.
