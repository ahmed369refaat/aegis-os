# Changelog

All notable changes to AegisOS. Format: [Keep a Changelog](https://keepachangelog.com/), versions: [SemVer](https://semver.org/).

## [Unreleased] — Stage 1: Ring-3 isolation (in progress)

### Added — review round 10 ("J"): the ring-3 file lifecycle — the syscall surface crosses the fd line

- **The file family executes on the LIVE lib kernel** (`kernel-x86_64/src/syscall.rs` + the new `sysabi.rs`): OPEN, READ, WRITE, CLOSE, PIPE and DUP are marshaled from the six-register SYSCALL convention into the lib's `SysRequest` values and run through `Kernel::execute` — the same domains, fd tables, pipes and VFS the behavior monitor reads. The runtime gates first (`dispatch`, where the used-bits/denial accounting lands exactly once) and only an Allowed reaches the executor: the lib's `syscall` was split into gate + `execute` for exactly this seam, and the split's contract (execute NEVER gates; the caller must) is host-tested by watching the parser profile's masked OPEN both ways.
- **The ABI layer** (`kernel-x86_64/src/sysabi.rs`, pure + host-tested): the open-flag decoding (O_READ/WRITE/CREAT/TRUNC; unknown bits and O_TRUNC-without-O_WRITE refuse -EINVAL), the complete `SysError → errno` table (every lib refusal keeps a distinct Linux meaning — 40+ variants pinned one by one), the pipe fd-pair packing into the single RAX the naked entry returns (`(w << 8) | r`), and the file-family number table pinned against the lib's constants. `docs/ABI-VERSION.md` now carries the full v0.3 register table.
- **The copy-OUT primitive** (`mm::user_range::copy_out_bytes` + `memops::write_u8_va`): SYS_READ's byte-exact mirror of the PR-1.4 copy-in — validate every covering page through the domain's own tables first, execute into a KERNEL buffer (the user pointer is read once for validation and never again — no double-fetch), then write the bytes out under the single blessed SMAP window. `read_user_cstr` reads SYS_OPEN's path page-check-as-you-go: a short string before an absent page succeeds, a missing NUL within 128 bytes is -ENAMETOOLONG, and the walk's page checks are exact (a string ending at a page boundary never asks about the next page — host-tested with a counting map).
- **The stdio triplet** (`Kernel::reserve_stdio` + `FdTarget::Reserved`): a spawned domain's fds 0/1/2 belong to the runtime, Unix-style, so the domain's own pipe()/open() allocations begin at fd 3 and the console device alias behind fd 1 can never collide with a real fd-table entry. Reserved slots refuse I/O through the policy core (`SysError::Reserved` → -EIO) but close and dup like plain entries — closing one frees it for allocation again (all host-tested, including the reservation refusing to shadow a real target).
- **The proof blob** (`examples/ring3-files`): the full Unix dance from CPL=3, every answer checked IN the blob — pipe() → (3,4); a pipe round-trip with byte-verified read-back; dup keeping the read end alive past its original's close (the second message arrives through the survivor); open(O_CREAT)/write/read-back through the duplicate's independent cursor (the snapshot-pos semantics the lib documents); close of the original with the dup reading EOF; and the three errno refusals (-EBADF on a never-open fd, -ENOENT on a missing path, -EBADF on the closed pipe end). Exit 42 only when every step verified; the boot asserts it plus write_bytes=101 (every byte the run contributed), and the J:pipe/J:dup/J:file/J:neg console markers are grepped by `boot.sh --verify`. kmain prepares /pub world-writable through a kernel-resident uid-0 supervisor first — the init-prepares-/tmp pattern.
- Host tests: +5 lib (stdio reservation, Reserved I/O refusals, the gate/execute split contract, and the files blob's phase-F sequence replayed on the host — the same supervisor//pub/domain shape the boot runs) and +9 kernel (sysabi's five tables, the copy-out bounds, the cstr reader's three behaviors) — plus the three resurrected syscall-module tests below — 331 lib + 265 kernel = 596 total.

### Fixed — review round 10 ("J"): two hidden debts of the ring-3 path, found the way they always are

- **SYSRET never restored the user RSP** (`arch/syscall_entry.rs`): SYSRET restores only RIP/RFLAGS (from RCX/R11), and the stub switches RSP to the kernel stack on entry — so every sysret since PR-1.4 returned to ring-3 code running on the KERNEL's stack pointer. Invisible for the whole seven-run sequence because every earlier blob is pure register code that never touches its stack; the files blob's verify subroutine (the first `call` in ring-3 history) pushed its return address through a kernel-half RSP and faulted with the full record printing `rsp=0xffffffff40002ff8`-shaped values. The stub now parks the user RSP before the stack switch (`USER_RSP_SAVE`, the same single-CPU/no-nesting lifetime as `SYSCALL_RSP`) and reloads it as the only RSP restore before SYSRETQ. The saved-register contract in the module docs now says so explicitly.
- **The syscall module never ran its own tests** (`kernel-x86_64/src/main.rs`): an outer `#[cfg(not(test))]` sat on `pub mod syscall`, compiling the whole module — its three host tests included — out of every `cargo test` run ever taken. The tests' missing `SyscallMask` import had been invisible for exactly that long; removing the outer gate (the module's target-only `mod exec` is internally gated, as designed) put all three back on the host, and the import was fixed. The kernel host count jumped 253 → 262 before round J's own tests even landed — the count had been quietly lying by three.
- **The boot stack was 1.6 KiB from its own guard page** (`kernel-x86_64/linker.ld`): the driver-stack call chain (kmain → driver_stack_step → the per-driver steps, with their multi-KiB inventory frames) bottoms out barely 1.6 KiB above `stack_bottom` — measured, not guessed, when round J's first draft put the files blob's 4 KiB data page on kmain's stack and the very next deep call (#PF err=2: supervisor write to the not-present guard page) caught it. The F15 guard page did exactly what it was built to do — the overflow faulted loudly instead of corrupting .bss. The data page is now a compile-time `static` (zero stack cost, and `const fn`-built into .rodata), and the boot stack grows 256K → 512K so the margin is honest rather than lucky; image + bss + stack stay inside the single 2 MiB page (kernel end ≈ 1.01 MiB).

### Added — review round 7 ("I"): read-only FAT32 — the EFI System Partition

- **The FAT32 policy core** (`src/fat32.rs`): BPB validation with the
  spec's own type determination (a cluster count below 65525 is
  FAT12/FAT16-shaped and REFUSED as `NotFat32`, never misread),
  FAT-entry classification (free/reserved/bad/past-the-volume values
  refuse; a legal follow and end-of-chain are distinct outcomes), 8.3
  dirent parsing (long-name, deleted, and volume-label records are
  skipped per the format; a size>0 record with no cluster behind it
  refuses), and the cluster-chain walk with a structural termination
  proof — each iteration covers exactly one cluster, so the walk ends
  after ceil(len/cluster_bytes) steps; a loop-back entry re-reads a
  bounded cluster and still terminates; a chain shorter than the
  dirent's length refuses with `ChainTooShort`, a length the volume
  cannot hold refuses up front with `ChainTooLong`. Seven host tests
  including a 2000-image fuzz corpus; the walk itself lives in the
  core (the kernel supplies only the sector loader), so every bound
  above is host-proven, not boot-hoped.
- **`scripts/mkfat32.py`**: grows the mkext2 disk with GPT partition 2
  — an ESP (type GUID C12A7328-…) holding an honest FAT32 volume:
  65600 clusters (≥ the 65525 minimum), two 516-sector FAT copies, the
  FSInfo sector with true free-cluster accounting, the backup boot
  sector, and HELLO.ESP — 1200 bytes across clusters 3→4→5, so the
  chain has real hops to walk. The GPT backup moves to the new tail;
  the stale copy is zeroed; the protective MBR is resized.
- **The transport** (`drvstack/fat32.rs`): mounts on the LIVE AHCI
  port right after ext2 (same frames, no restart), walks the GPT again
  for partition 2, and reads HELLO.ESP through the policy core's walk
  — the marker prints the head (cluster 3) AND the tail (cluster 5),
  so every hop between them is proven. Live on BOTH lanes (IOMMU and
  no-IOMMU), grepped by the CI lanes.

### Fixed — review round 7 ("I"): the hidden lane debt of rounds 6–H

- **The TSC calibration that never calibrated** (`drvstack/acpi.rs`):
  `tsc_delta.checked_mul(10^15)` overflows u64 for ANY real window —
  a 2M-spin calibration is millions of TSC ticks and the product
  exceeds 2^64 ten times over — so the "[TSC ] calibrated" marker
  had never printed (hidden behind the round-6 lane crash). The
  arithmetic moved to u128; the quotient bounds (1 MHz..16 GHz)
  stay.
- **The virtio-console chain that never chained**
  (`drvstack/vcon.rs`): the header descriptor was written with
  `flags = 0` — without `DESC_F_NEXT` the next-index field is
  ignored, the device treated the 4-byte port header as the whole
  request, and the host file received exactly those 4 bytes while
  the guest-side completion reported success. One flag; the host
  file now holds the full round-trip payload.
- **The CPUID RBX destruction** (`hw::cpuid7_ebx` / `hw::cpuid1_ecx`):
  the "bulletproof" push/cpuid/store/pop pattern was inverted — the
  `mov %rbx,(%rsp)` overwrote the SAVED original RBX with CPUID's
  output and the `pop` handed that to the output operand, so the
  caller's callee-saved RBX never came back. CPUID destroys RBX and
  the block never declared it; whether anything broke was allocation
  luck (a release build kept the driver stack's inventory pointer in
  RBX across `cpuid7_ebx()` — the q35 lane #PF'd at a garbage
  pointer, deterministically, while a marker-instrumented build with
  different register allocation ran clean). `cpuid7_ebx` now shuttles
  the word out with `xchg` (the original RBX lands back in the
  register, the wanted EBX in the slot); `cpuid1_ecx` stores ECX to
  its operand directly and pops the original RBX. The other push-RBX
  sites (the naked entry stubs) are self-balanced and untouched.
- **The unclaimed-virtio DMA failure** (`drvstack/pci.rs` +
  `pci::Inventory::set_dom_dev`, host-tested): the round-G/H steps
  drove virtio-rng, virtio-console, and virtio-balloon WITHOUT
  walking the claim gate — their sessions ran with `dev.dom = 0`
  (the kernel's own domain), and an unclaimed device's DMA fails
  closed at the IOMMU, so every device completion honestly timed
  out ("DID NOT COMPLETE (budget)") the moment the ECAM fix let the
  q35 lane reach them. Claimed devices beside them (vblk dom 1,
  vnet dom 2) completed everything — the differential that pinned
  it. The three devices now walk the same claim gate as the rest
  (matched by virtio device id, legacy and modern both; the family's
  class codes are ambiguous), recorded through the new id-matched
  `set_dom_dev`. The domain budget that made the fix visible —
  `MAX_VTD_DOMAINS` 8 → 16, with the derived `TABLE_BUDGET` scaling
  along (the q35 lane now claims nine devices; dom 7 was the last
  handout, so rng/balloon were refused on budget before the raise) —
  and console's device round trip completing on its own domain
  ("TX complete … the HOST file holds the other half") is the
  end-to-end proof.
- **The idle-queue MSI-X kick** (`drvstack/vnet.rs`): the ADR-0019
  delivery proof kicked the TX queue AFTER the DHCP exchange drained
  it — a notify with no pending buffer never produces a used-ring
  update, so the device never fired and the 400M-TSC-cycle delivery
  window ground the whole lane into its timeout (under QEMU TCG the
  emulated TSC makes 400M cycles ten-plus wall-clock minutes). The
  step now queues one fresh TX before the kick (the used-ring update
  itself — not the network — is the event that fires entry 2), and
  the window's budget drops to 40M cycles (~13 ms on real iron at
  3 GHz, under a minute under TCG).

### Known-open (round I, honestly recorded — not claimed)

- **MSI message delivery (both formats)**: the arming, read-back,
  fresh-work kick, bounded window, and teardown are proven live, but
  the message never lands (compat on the base lane, remapped on IR).
  The delivery window's own honesty is what exposed it: the old
  mwait window slept through its deadline (a silent device = a
  hung boot), the new `wait_for_delivery_spin` says "NOT delivered"
  loudly and the boot continues. The DELIVERED greps moved off both
  lanes; the line-interrupt chain (IOAPIC → vector → mailbox) is
  delivered and stays grepped.
- **The balloon inflate**: the deflate round trip is live (the page
  returns home); the inflate's host-side discard never completes the
  queue entry under this QEMU. Round H's "real inflate/deflate"
  claim was never exercised (the lane crashed at ECAM first) — the
  checklist now says what actually happens.
- **The ECAM direct-map hole** (`mm::map_gib_windows` + `gib_span`):
  round 6's ADR-0020 shipped the ECAM seam without mapping the GiB the
  MCFG window lives in — on q35 the third GiB (PCIEXBAR 0xB000_0000),
  which nothing else maps — so the FIRST config read through the
  direct map #PF'd and the kernel halted ("unexpected fault"). The q35
  lane never got that far (see below), so the crash hid. The fix
  generalizes the fourth-GiB LAPIC/VT-d window trick: the spanned
  1-GiB PDPT entries are mapped as RW+NX huge pages, idempotently,
  only-if-absent; the span math is pure and host-tested. The lane now
  greps the mapping marker.
- **The GPT lane marker** (`drvstack/ext2.rs`): the lane greps
  expected `LBA 34..=289` while the kernel printed `LBA 34..289` —
  every lane ran red on that grep since round 6, which is exactly how
  the ECAM crash above stayed hidden. The kernel now prints the
  inclusive range (the GPT span is first..=last); the FAT32 marker
  matches the same convention.
- **The fmt debt**: rounds G/H shipped 25 files without a fmt pass —
  `cargo fmt --all --check` (the CI job) reported 1407 diff lines on a
  tree that was clean at 15d9441. Reformatted, zero semantic change,
  full suite green.
- **The lane timeouts**: q35/IR lanes raised 240s → 600s. The M2
  syscall audit phase alone emits ~390k serial lines before the driver
  stack starts, and q35 + intel-iommu under TCG on a loaded host needs
  more than 240s just to reach `[PCI ]` — the timeout kill looked like
  a boot failure while it was really a budget failure.
- **A dead comparison in `pci::ecam_addr`** (flagged by the compiler):
  `bus.wrapping_sub(start_bus) > 255` on u8s is always false; the
  window's end is the caller's bound (`CfgAccess::resolve` checks
  `end_bus`). Removed with the responsibility stated.
- unsafe ratchet: unchanged at 100/100 — the round adds ZERO unsafe
  (the transport reuses the proven AHCI read path; the GiB-window
  writes go through the memops wrappers).

### Changed — review round 6, part 2 ("H"): the watchdogs, AMD-Vi's IVRS, and two more virtio devices

- **The watchdogs** (`drvstack/wdt.rs`, register maps pinned against
  QEMU's ich9_tco.h / ich9.h / wdt_i6300esb.c): **iTCO_wdt** — the
  ICH9 LPC's TCO block probed through PMBASE (config 0x40, bits
  15:7), its registers read live, and the timer reprogrammed with a
  read-back proof — but ONLY after the chipset's NO_REBOOT gate (GCS
  bit 5, read through the RCBA) says a timeout is inert (QEMU's
  default; a clear gate refuses to reprogram, CI-safety stated).
  **i6300esb** — the unlock×3 / max-preload / ping sequence on the
  write-only MMIO registers, with reboot-on-timeout masked in config.
  New `hw::inw` (the 16-bit I/O read TCO needs); unsafe ratchet
  99 → 100.
- **AMD-Vi's IVRS parsed** (`src/ivrs.rs`, policy core, layouts
  pinned against Linux's actbl2.h): IVHD blocks (the IOMMU MMIO
  bases, ids, flags) and the device-entry topology (selects, ranges,
  aliases, specials — including the 8-byte types whose values EMBED
  their length bits, a trap the tests pin), IVMD unity-map blocks
  counted. Typed hostile refusals. The boot probe prints the honest
  absence on QEMU (no AMD-Vi emulation); the register-engine slice
  follows on real AMD machines.
- **virtio-console** (`drvstack/vcon.rs`, 0x1043): port 0's transmit
  queue driven — the [port-id header + payload] chain sent through
  the broker, completion validated, and the HOST half of the round
  trip asserted by the lane (the chardev file must contain the proof
  string; the guest marker alone is not the claim).
- **virtio-balloon** (`drvstack/vballoon.rs`, 0x1045): a REAL
  one-page cycle — a fresh pool frame offered on the inflate queue,
  the config's `actual` watched advancing to the checked target, the
  SAME page deflated home, the frame returned to the pool. The stats
  vq is not negotiated (stated scope).


### Changed — review round 6 ("G"): the interrupt chain, multi-bus PCI, and the platform slice (ADR-0019 + ADR-0020)

- **The interrupt broker (ADR-0019)** — `kernel-x86_64/src/irq.rs`:
  vectors 49..=112 are broker-owned from boot (64 stubs + gates in
  `idt::load`, the dispatch route); `alloc` is the only way a vector
  gets an owner (one per device, duplicate tags refuse); `deliver`
  EOIs FIRST then lands the delivery in a per-device mailbox
  (served/lost/pending, cap 1024 — surplus counted, never wrapped);
  an unowned vector is a named halt. The bounded delivery window
  (`wait_for_delivery`) pauses the tick, opens IF, and sleeps in
  **MWAIT on the LAST_DELIVERED word** when the CPU offers MONITOR
  (armed-late re-check included), spinning otherwise.
- **IOAPIC + x2APIC**: the MADT's interrupt view parsed pure
  (IOAPIC entries + ISA-IRQ→GSI overrides, hostile truncations
  stop the walk); the IOAPIC's RTE encoded field-by-field,
  programmed masked-first, bounds-checked against the probed max;
  the LAPIC switches to x2APIC when CPUID offers it (MSR
  0x800+(off>>4), mode-aware EOI). **The lane's proof**: the QMP
  key arrives MID-WINDOW and delivers ISA IRQ1 → GSI1 → vector →
  EOI → mailbox — the first line interrupt in the tree that is not
  a poll.
- **MSI/MSI-X + VT-d IRTE**: the MSI-X table (BIR/offset decode,
  BAR-size bounds, masked-first entry writes, read-back) points
  virtio-net at a broker vector — the TX kick's completion arrives
  as a MESSAGE. When the DMAR declares interrupt remapping, IR
  enables (IRTA + SIRTP + IRE on the accumulated GCMD word, 256
  IRTEs on a scrubbed frame) and the NIC's messages switch to the
  REMAPPED format through IRTE n = broker slot n (layouts pinned
  against QEMU's decoder; reserved fields zero by construction).
  New lane `--verify-q35-ir` (`intremap=on`) proves the remapped
  path end to end in CI.
- **Multi-bus PCI (ADR-0020)**: the config seam
  (`CfgAccess::LegacyPorts | Ecam`) with bounds-checked ECAM
  address math; `enumerate_multi` walks THROUGH type-1 bridges
  (visited-set loop protection, depth cap 8, the same
  BAR/capability code now bus-parameterized); the F9 bus-0-only
  refusal is LIFTED — devices behind bridges claim their own
  ADR-0018 domains. The q35 lane gains a pcie-root-port with a
  virtio-blk behind it; the ECAM marker, the traversed marker, and
  the bus-1 device line are asserted. Inventory cap 32 → 48.
- **The platform slice**: power paths read the FADT
  (`arch/pwr.rs` — PM1a + the reset register, offsets pinned
  against Linux's actbl.h; power-off and reboot go through the
  firmware's addresses with loud legacy fallbacks); the TSC is
  calibrated against the live HPET counter (the preempt tick stops
  riding a guessed constant); entropy exists (RDRAND/RDSEED +
  virtio-rng harvested through the broker into a splitmix64-mixed
  pool with honest counters — a mixer, not yet a CSPRNG, stated);
  and the storage stack reads a REAL partition table
  (`src/part.rs`: protective MBR + GPT with both CRC-32s enforced,
  typed hostile refusals — the ext2 mount rides the 'aegis-root'
  partition base, raw-LBA-0 fallback marked).
- **Unsafe ratchet 93 → 99** (six single-instruction `hw` wrappers,
  ADR-0019 referenced in `scripts/unsafe-count.txt`); ~60 new host
  tests across the kernel and policy crates; every marker the new
  lanes assert is listed in the ADRs.


### Changed — review round 5, Phase E: ADR-0017's first slice — the IpcMmio channel

- **`kernel-x86_64/src/ipc_mmio.rs`**: a driver's register access as
  a MESSAGE, not a volatile load. `IpcMmio` implements the `MmioBus`
  trait (ADR-0016's seam) by forwarding every accessor through an
  `MmioChannel` to a ring-0 **DeviceCore** that checks offset AND
  width against the same validated window before anything volatile
  happens — a ring-3 driver domain cannot even NAME a register
  outside its grant. The core counts served/refused (the organic
  monitor feed a domain cannot forge or suppress). The first slice's
  channel runs in-process (the core is the far end); the ring-3
  slice swaps the transport for a capability-gated IPC endpoint
  without touching the message types or the discipline.
- **Host proofs**: the headline ADR-0017 test — the SAME driver code
  (a register sequence written only against the trait) runs unchanged
  against the direct ring-0 bus and the channel, with identical
  answers; out-of-window requests never reach the register page (a
  poison guard proves it) and are counted; hostile widths (0/1/3/255)
  are refused by the core; and the rogue-driver suite walks the six
  forbidden operations (MMIO outside the window, quota overrun,
  another domain's cookie, in-flight unmap, the absent-verdict DMA
  gate, descriptor bounds via the channel + virtio's tests) — every
  one refused, typed, side-effect-free, and a healthy driver keeps
  working after each.
- **What is NOT in this slice** (the next one, per ADR-0017's own
  sequencing): the ring-3 transport itself (a launched driver domain
  whose channel is an IPC endpoint), the syscall-mask + capability
  gating on the domain's driver-facing calls, the monitor wiring of
  the core counters, and the boot-lane marker for a live ring-3
  driver. The broker/channel refusal proofs here are host-level; the
  ring-3 rogue demo stays the ADR-0010 one until then.

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
