# ADR-0019: The interrupt chain — broker-owned vectors, MSI/MSI-X, VT-d IRTE, and delivery into the system

- **Status:** Accepted (implementation: review round 6, "G")
- **Stage:** M3 driver stack / the platform layer (closes the "interrupt broker: not started" row of the gap analysis)
- **Date:** 2026-11-21
- **Supersedes:** none; delivers the decision `arch/vtd.rs`'s deferred
  comment asked for ("intremap=off … until the interrupt-broker ADR owns
  the IRTE decision"), and extends ADR-0010's named-halt discipline and
  ADR-0012's timer path.

## Context

Until this round, the LAPIC timer was the system's ONLY interrupt
source. Every driver polled — virtio-blk/net, NVMe, AHCI, xHCI, e1000
— and the tree said so honestly (`virtio.rs`: "we configure no MSI —
every wait is a bounded poll"; `arch/idt.rs`: "nothing delivers on an
unwired vector until MSI exists"). The gap analysis listed the whole
chain as absent: IOAPIC, MSI/MSI-X, x2APIC, interrupt remapping
(IRTE), and the broker itself. On top of that, the kernel's power
paths were QEMU constants (`outw(0x604, 0x2000)`), the TSC cadence
was a guessed constant (25 M ≈ 10 ms), and the idle instruction
(MWAIT) was unused.

The design constraint that shapes everything below: **the kernel runs
IF=0 in CPL0** (ADR-0012's invariant — the tick path models CPL3
frames only). Any interrupt-delivery proof must therefore open a
DELIBERATE, bounded window — not rely on incidental STIs.

## Decision

1. **The interrupt broker owns the device-vector half of the IDT.**
   Vectors **49..=112** (64 slots) are armed at boot (stubs + gates
   from `idt::load`); `irq::alloc(dev_tag, dom, source)` is the only
   way a vector gets an owner (one vector per device — duplicate tags
   refuse), and the exception dispatch routes the whole range to
   `irq::deliver` BEFORE any fault classification (a device IRQ that
   interrupted ring-3 code is not the domain's death). An **unowned**
   vector reaching deliver is a NAMED halt — ADR-0010's discipline
   extended from the legacy 8259 range (32..=47) to the device range.

2. **EOI first, bookkeeping second.** `deliver` acknowledges the
   LAPIC before touching the mailbox — a pending in-service interrupt
   must never wedge the APIC behind bookkeeping.

3. **Deliveries land in a per-device mailbox** (served/lost/pending,
   cap 1024, surplus COUNTED as `lost` — the frame-budget discipline
   applied to interrupts). The mailbox is the ring-0 half of the
   "interrupts into driver domains" chain: every slot records the
   device's ADR-0018 domain, so the ring-3 slice (ADR-0017's
   transport) reclaims it by wiring the drain into the domain's
   channel — the kernel-side chain is identical either way.

4. **The delivery window is explicit and bounded**
   (`irq::wait_for_delivery`): pause the preempt timer (a CPL0 tick
   is a named kernel bug), STI, wait — **MWAIT on the
   `LAST_DELIVERED` word when the CPU offers MONITOR** (with the
   re-check after arming: a delivery that raced the arming is caught,
   never slept past), spin otherwise — then CLI and resume the timer.
   The window is the ONE place the kernel opens IF in CPL0, and every
   vector that can land in it is one the IDT deliberately gates.

5. **Line interrupts come through the IOAPIC** (`arch/ioapic.rs`):
   the MADT's IOAPIC entries + ISA-IRQ→GSI overrides are parsed PURE
   (`parse_madt_irq`, host-tested against hostile truncations), the
   probe refuses an address outside the 4th-GiB window, every RTE is
   encoded pure and pinned field-by-field (fixed/physical/
   active-high/edge, mask bit 16, dest in 63:56), and programming is
   the masked-first two-step. The proof lane: the PS/2 keyboard's
   ISA IRQ 1 → GSI 1 → a broker vector, and the QMP-injected key
   arrives MID-WINDOW (the window IS the wait — `ps2_step` no longer
   spins for the key), delivering end to end: IRQ → IOAPIC → LAPIC →
   stub → dispatch → EOI → mailbox → marker.

6. **x2APIC is enabled when CPUID offers it**: IA32_APIC_BASE bit 10
   alongside bit 11, and every LAPIC access (including the EOI)
   routes through MSR 0x800+(off>>4) — the packed MSR map, pinned by
   tests against exactly-the-neighboring-MSR bugs. The MMIO window
   mapping stays (the IOAPIC and BARs live in the same 4th GiB).

7. **MSI/MSI-X is programmed through a pure encoding layer**
   (`msi.rs`): the capability layouts (MSI 0x05, MSI-X 0x11), the
   N−1 table size, the BIR/offset split, entry writes
   masked-first/addr/data/unmask, bounds against the BAR's SIZE (the
   F5 rule), and the xAPIC physical-destination message pair. The
   proof: virtio-net's MSI-X table points at a broker vector; the TX
   kick's used-ring update arrives as a MESSAGE (QEMU's modern
   virtio-pci assigns entry 0 to config, i+1 to queue i — every
   entry gets the vector); the used ring's completion is validated
   against the submission (F7).

8. **Interrupt remapping turns ON when the DMAR declares it, and the
   broker owns the IRTE table** (`arch/vtd.rs`, layouts pinned
   against QEMU's own decoder): one 4-KiB frame, 256 entries, IRTA
   base|EIME=off|order-7, then SIRTP → IRE on the accumulated GCMD
   word (the discipline `program_and_enable` learned the hard way).
   The IRTE format is remapped (present|vector@23:16|dest@63:32 with
   the non-EIM dest at dest_id 15:8), reserved fields zero BY
   CONSTRUCTION (QEMU faults them), SID validation off. The remapped
   MSI pair: address bit 4 set, the handle in 19:5 (bit 15 at bit 2),
   SHV clear, data all-zero. **Handle n mirrors broker slot n** — one
   IRTE per device vector, allocated by the broker's own arithmetic,
   which is exactly what the old deferred comment required. The new
   `--verify-q35-ir` lane boots `-device intel-iommu,intremap=on`:
   the NIC's MSI-X must arrive in the remapped format through its
   IRTE or the IOMMU faults it — the compat format is not an option
   there.

9. **The platform slice rides the same discipline** (no ADR of its
   own, listed here because it shares the window):
   - **Power paths read the FADT** (`arch/pwr.rs`): PM1a control,
     the reset-register GAS + value, flags bit 10 — offsets pinned
     against Linux's `actbl.h`; power-off writes SLP_EN|SLP_TYP(0)
     (QEMU's `_S5` package; DSDT parsing is the next slice) to the
     FIRMWARE's address, reboot writes the table's reset value to
     the table's register, and every refusal degrades loudly to the
     legacy constants.
   - **The TSC is calibrated against the HPET** (counter delta ×
     period in femtoseconds): the preempt tick's interval stops
     being a guessed constant; out-of-band quotients keep the
     fallback, marked.
   - **Entropy exists** (`rng.rs` + `drvstack/vrng.rs`): RDRAND
     (CPUID-gated, 10 bounded retries, refusals counted), RDSEED,
     and virtio-rng (device id 0x1044/0x1004 — pinned with the
     neighbor ids that are NOT it) harvested through the broker into
     a splitmix64-mixed pool with honest counters. HONEST SCOPE:
     splitmix64 is a mixer, not a CSPRNG — the ChaCha20 read side
     and KASLR are the next slice.
   - **GPT/MBR** (`src/part.rs`, policy core): IEEE CRC-32 with a
     compile-time table (the reference vector pinned), the
     protective MBR, the GPT header/entries with BOTH CRCs enforced
     and typed refusals for hostile geometry/overlap — the ext2
     mount now rides the partition base ('aegis-root' LBA 34), with
     the raw-LBA-0 fallback marked honestly.

## Consequences

- **The poll era ends where the broker reaches.** The keyboard and
  the NIC are interrupt-driven through the full chain; the remaining
  polling drivers (virtio-blk, NVMe, AHCI, xHCI) migrate to
  `irq::alloc` one by one — the mailbox drain is the same API for
  each.
- **The unsafe ratchet rises 93 → 99** (six single-instruction `hw`
  wrappers: sti/cli, monitor/mwait, rdrand64/rdseed64 with the CF
  gate materialized by `setc`) — this ADR is the reference in
  `scripts/unsafe-count.txt`.
- **QEMU-specific honesty:** the IR lane was designed against
  QEMU's decoder (the IRTE union and the MSI address union) because
  that is the machine CI boots; the encodings are Intel-spec, but
  the PROOF is QEMU-shaped. The IOAPIC compat-format proof stays on
  the base lane deliberately (QEMU's IOAPIC-under-IR behavior is
  not modeled here; the IR lane asserts only the PCI-MSI path).
- **What is NOT in this round:** delivering IRQs into a live ring-3
  domain's channel (the mailbox + recorded domain are the landing
  pad; the transport slice follows), EIM/x2APIC-dest IRTEs (EIME
  off, 8-bit dests — fine for single-socket), and per-vqueue MSI-X
  vectors (one vector per device, every entry programmed).

## Tests

Host (pure, hostile): the broker's alloc/refusal/overflow/drain
semantics; the IOAPIC RTE field-by-field + bounds; the x2APIC MSR
map (the test that caught the flat-offset bug); the MADT parse
fixtures + truncations; MSI-X control/BIR/entry-bounds (including
wrap and multiplication overflow); the IRTE/IRTA/remap-address
encodings against QEMU's fields; FADT offsets + GAS decode
refusals; splitmix64 structure; the partition CRC vector + hostile
GPT/MBR fixtures. Lane markers (CI): `[IRQ ] ioapic live @`,
`[IRQ ] armed: isa irq 1 → gsi`, `[IRQ ] DELIVERED: vector`,
`[MSIX] armed/DELIVERED/disabled`, `[IR  ] enabled: 256 IRTEs`,
`[MSIX] format: remapped` (IR lane), `[TSC ] calibrated`,
`[PWR ] FADT`, `[IDLE] mwait woke`, `[RNG ] rdrand/virtio-rng/pool`,
`[GPT ] partition 1 'aegis-root'`.


## K18 addendum — the DELIVERED marker's semantics, corrected

The keyboard's `[IRQ ] DELIVERED: vector` marker had TWO false
positives, both found live in K18: (a) the i8042 self-test byte's
IRQ1 edge latches in the LAPIC's IRR while the self-test poll runs
at IF=0 and delivers at the window's very first STI — keyless lanes
were green on exactly that stale edge, never a key; (b) the window
accepted ANY owner's delivery (the serial's IRQ4 on a session lane
qualifies too). The proof now: the stale edge is drained BEFORE the
window, the window accepts only the keyboard's own vector and is
1.5 s TSC-bounded, and the captured byte must be KEYBOARD-TAGGED in
the console-in ring (the tty ring's per-byte source tag — the old
untagged capture could eat a serial byte and claim a round trip with
it). The pin lives on the dedicated `--verify-ps2` lane, whose
machine has no USB keyboard, so send-key has exactly one target.


## K19 addendum — the message DELIVERS; the round-one silence was ours

The message-signaled interrupt is live end-to-end, both formats:
`[MSIX] DELIVERED` is pinned on the q35 lane (compat) and the IR
lane (remapped through the device's IRTE). The round-one silence —
"the machinery is proven but the message never lands" — was a driver
bug, not a QEMU limitation: the queues' MSI-X vectors were never
BOUND. QEMU's modern virtio-pci sends a message for a completion
only if the driver wrote the queue's `queue_msix_vector` (and the
config's `config_vector`); unwritten, they stay VIRTIO_MSI_NO_VECTOR
and no completion ever fires, however the table is programmed. The
step now binds config→entry 0, RX→entry 1, TX→entry 2 BEFORE
DRIVER_OK (the queue's notifier setup runs then), reading each grant
back (0xFFFF is a refusal — fail-closed), and the DHCP completions'
messages deliver through the bounded spin window, EOI'd and counted
in the broker's mailbox. The teardown reverses it in order: the
capability off (no message can land on a vector about to be
unowned), the mailbox drained, the vector released.
