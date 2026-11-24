//! The interrupt broker (ADR-0019): the ONLY path by which a device
//! interrupt reaches its owner. Until now every driver in the tree
//! polled — the LAPIC timer was the sole interrupt source. This module
//! owns the device-vector half of the IDT (49..=112), allocates those
//! vectors to devices, and turns each delivery into a per-device
//! mailbox the driver's session drains — the ring-0 half of the
//! "interrupts into driver domains" chain (the ring-3 notification
//! slice rides the same mailbox through the ADR-0017 channel).
//!
//! Design, in one breath: the broker is a table of 64 vector slots,
//! each an all-atomic record (single CPU today — Stage 4 SMP adds
//! per-CPU disabling, not locks). `alloc(dev_tag, dom, gsi)` claims
//! the first free slot for a device; a device holds exactly one vector
//! (duplicate tags refuse loudly — the "who owns this line" question
//! must never have two answers). The dispatch calls `deliver(vector)`
//! for any vector in 49..=112; the broker EOI's the LAPIC FIRST (a
//! pending in-service interrupt must never wedge the APIC behind
//! bookkeeping), then increments the owner's mailbox. The mailbox is
//! bounded the way everything in this kernel is bounded: `pending`
//! saturates, and the surplus is COUNTED in `lost` — a lost interrupt
//! is a loud fact, not a silent wrap.
//!
//! An unowned vector reaching `deliver` is a NAMED halt (ADR-0010's
//! discipline applied to the device range): nothing delivers on a
//! vector the broker did not arm, so reaching that arm is a wiring bug
//! and the log says exactly which vector.
//!
//! The proof lane (q35): the PS/2 keyboard's GSI 1 is routed through
//! the IOAPIC to a broker vector; the 8042 IRQ is raised with the CPU
//! at IF=0 (kernel convention), pends in the LAPIC IRR, and a bounded
//! `wait_for_delivery` window — timer ticks paused, IF opened for
//! microseconds, IF closed again — delivers it end to end: vector →
//! dispatch → EOI → mailbox → marker.

// The host-test build compiles this module WITHOUT its boot-only
// window helpers (they need `hw`); the pure broker logic runs on the
// host against the same static table.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// The first broker-owned device vector: above the legacy 8259
/// catch-alls (32..=47) and the LAPIC timer (48), below anything
/// exotic. Stubs exist for the whole range; the IDT wires them all.
pub const DEVICE_VECTOR_BASE: u8 = 49;

/// The last broker-owned device vector (inclusive): 64 slots — more
/// than every device this driver stack can claim, few enough that the
/// stub table stays hand-checkable.
pub const DEVICE_VECTOR_MAX: u8 = 112;

/// The slot count (constexpr'd so tests can't drift from the range).
pub const VEC_SLOTS: usize = (DEVICE_VECTOR_MAX - DEVICE_VECTOR_BASE + 1) as usize;

/// One vector slot: who owns it and the mailbox of deliveries. All
/// atomic — `deliver` runs in interrupt context against the same words
/// boot code reads; the atomics keep the words torn-free, and the
/// single CPU keeps the sequences non-interleaved (Stage 4 revisits
/// with per-CPU vector disabling).
struct Slot {
    taken: AtomicBool,
    /// The frames-ledger owner tag of the owning device (e.g.
    /// E1K_OWNER); `dom` is its ADR-0018 IOMMU domain. Domain 0 is
    /// the kernel's own — a boot-time demo device legitimately parks
    /// there until its driver domain exists; the pairing is still
    /// recorded, so the ring-3 slice can reclaim it.
    dev_tag: AtomicU32,
    dom: AtomicU32,
    /// The GSI this vector serves (MSI-X sources store their entry
    /// index + 0x1_0000_0000 offset so the two namespaces cannot
    /// collide in the table).
    source: AtomicU32,
    /// Deliveries observed by the handler (monotonic).
    served: AtomicU64,
    /// Deliveries that arrived while `pending` was already at the
    /// cap — counted, never wrapped (the frame-budget discipline).
    lost: AtomicU64,
    /// Deliveries the owner has not drained yet (bounded).
    pending: AtomicU64,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            taken: AtomicBool::new(false),
            dev_tag: AtomicU32::new(0),
            dom: AtomicU32::new(0),
            source: AtomicU32::new(0),
            served: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            pending: AtomicU64::new(0),
        }
    }
}

/// The GSI namespace offset for MSI-X sources (entry index + this
/// offset; a GSI is at most 0xFFFF on any machine this driver stack
/// boots, so the namespaces cannot collide).
pub const MSI_SOURCE_BASE: u32 = 0x8000_0000;

/// The mailbox cap: a device this driver stack drives is serviced on
/// its next poll window; if THIS many interrupts stack up un-drained,
/// the surplus is `lost` — loud, and a bug in the driver's cadence.
pub const MAILBOX_CAP: u64 = 1024;

/// The single broker table (single CPU today; see the module doc).
/// Built with an inline-const repeat: the slots are not `Copy`
/// (atomics never are), and a plain `[Slot::new(); N]` requires Copy.
static SLOTS: [Slot; VEC_SLOTS] = [const { Slot::new() }; VEC_SLOTS];

/// The vector the last delivery landed on (0 = none) — the
/// `wait_for_delivery` window watches this word.
static LAST_DELIVERED: AtomicU8 = AtomicU8::new(0);

/// Claim the first free vector for `dev_tag` (one vector per device —
/// a second `alloc` with a live tag refuses; release first). Returns
/// the vector, or `None` when the table is full or the tag is live.
pub fn alloc(dev_tag: u32, dom: u32, source: u32) -> Option<u8> {
    // A live duplicate tag refuses — one vector per device, always.
    if vector_for(dev_tag).is_some() {
        return None;
    }
    for (i, slot) in SLOTS.iter().enumerate() {
        if !slot.taken.swap(true, Ordering::SeqCst) {
            slot.dev_tag.store(dev_tag, Ordering::SeqCst);
            slot.dom.store(dom, Ordering::SeqCst);
            slot.source.store(source, Ordering::SeqCst);
            slot.served.store(0, Ordering::SeqCst);
            slot.lost.store(0, Ordering::SeqCst);
            slot.pending.store(0, Ordering::SeqCst);
            return Some(DEVICE_VECTOR_BASE + i as u8);
        }
    }
    None
}

/// Release a device's vector (teardown — the slot is reusable after).
pub fn release(dev_tag: u32) -> bool {
    match vector_for(dev_tag) {
        Some(i) => {
            SLOTS[i].taken.store(false, Ordering::SeqCst);
            true
        }
        None => false,
    }
}

/// The slot index (not the vector) serving `dev_tag`, if any.
fn vector_for(dev_tag: u32) -> Option<usize> {
    SLOTS
        .iter()
        .position(|s| s.taken.load(Ordering::SeqCst) && s.dev_tag.load(Ordering::SeqCst) == dev_tag)
}

/// The vector serving `dev_tag`, if any (marker printing, drain paths).
#[must_use]
pub fn vector_of(dev_tag: u32) -> Option<u8> {
    vector_for(dev_tag).map(|i| DEVICE_VECTOR_BASE + i as u8)
}

/// The registered owner of a vector, for dispatch decisions:
/// (dev_tag, dom, source).
#[must_use]
pub fn owner_of(vector: u8) -> Option<(u32, u32, u32)> {
    if !(DEVICE_VECTOR_BASE..=DEVICE_VECTOR_MAX).contains(&vector) {
        return None;
    }
    let slot = &SLOTS[(vector - DEVICE_VECTOR_BASE) as usize];
    if slot.taken.load(Ordering::SeqCst) {
        Some((
            slot.dev_tag.load(Ordering::SeqCst),
            slot.dom.load(Ordering::SeqCst),
            slot.source.load(Ordering::SeqCst),
        ))
    } else {
        None
    }
}

/// The delivery half, called from the exception dispatch with the
/// vector that fired. EOI FIRST (see the module doc), then the
/// mailbox. An unowned vector is a NAMED halt — nothing in this
/// kernel arms a vector the broker did not hand out.
#[cfg(not(test))]
pub fn deliver(vector: u8) {
    let Some((_dev_tag, _dom, _source)) = owner_of(vector) else {
        let mut bv = [0u8; 20];
        crate::serial::write_str("[IRQ ] unexpected device vector=");
        crate::serial::write_str(crate::strutil::dec(u64::from(vector), &mut bv));
        crate::serial::write_str(" — no broker owner (nothing armed it); halting loudly\n");
        crate::hw::halt_forever();
    };
    // A pending in-service interrupt must never wedge the APIC behind
    // bookkeeping: acknowledge before the mailbox runs.
    crate::arch::lapic::eoi();
    // Phase 7 (the TTY): EOI done, mailbox next — and the serial's
    // FIFO drains into the ring RIGHT HERE, at delivery time, so the
    // 16550 never overruns while a shell session types ahead. The
    // read path drains opportunistically too; this is the
    // interrupt-driven half.
    if _dev_tag == crate::tty::TTY_OWNER {
        crate::tty::drain_uart();
    }
    // Phase 4 (item 11's completion): the keyboard's own bottom half
    // — the 8042's output buffer drains, decodes, and feeds the SAME
    // TTY ring the serial RX uses, RIGHT HERE at delivery time. The
    // vector stays armed for the whole session, so every keystroke
    // after the boot probe lands in console-in without any polling
    // loop: the shell is keyboard-driven from this line on.
    if _dev_tag == crate::drvstack::irq::KBD_OWNER {
        crate::drvstack::kbd::irq_bottom_half();
    }
    let slot = &SLOTS[(vector - DEVICE_VECTOR_BASE) as usize];
    bump_mailbox(slot);
    LAST_DELIVERED.store(vector, Ordering::SeqCst);
}

/// The mailbox accounting (shared by the target path and the host
/// tests): `pending` saturates at [`MAILBOX_CAP`]; the surplus is
/// counted in `lost`.
fn bump_mailbox(slot: &Slot) {
    slot.served.fetch_add(1, Ordering::SeqCst);
    let pending = slot.pending.load(Ordering::SeqCst);
    if pending < MAILBOX_CAP {
        // The increment cannot race a second bump: single CPU, and
        // the interrupt gate masks further deliveries until iretq.
        slot.pending.store(pending + 1, Ordering::SeqCst);
    } else {
        slot.lost.fetch_add(1, Ordering::SeqCst);
    }
}

/// The owner-side drain: returns how many deliveries are waiting and
/// clears them (a driver's poll window asks exactly this).
pub fn drain(dev_tag: u32) -> Option<u64> {
    let i = vector_for(dev_tag)?;
    let n = SLOTS[i].pending.swap(0, Ordering::SeqCst);
    Some(n)
}

/// The monitor feed for a device: (served, lost, pending) — the
/// teardown report prints it so a lost interrupt is visible forever.
#[must_use]
pub fn counts(dev_tag: u32) -> Option<(u64, u64, u64)> {
    let i = vector_for(dev_tag)?;
    let s = &SLOTS[i];
    Some((
        s.served.load(Ordering::SeqCst),
        s.lost.load(Ordering::SeqCst),
        s.pending.load(Ordering::SeqCst),
    ))
}

/// The vector the last delivery landed on (0 = none).
#[must_use]
pub fn last_delivered() -> u8 {
    LAST_DELIVERED.load(Ordering::SeqCst)
}

/// Clear the last-delivered witness: a proof window's own reset. The
/// mwait helper clears internally, but a window that SPINS on the
/// witness (drvstack::irq — the wake-safe shape; under TCG, MWAIT
/// sleeps until an interrupt and a keyless lane with the tick paused
/// has none) needs the same reset without opening a sleep.
pub fn clear_last_delivered() {
    LAST_DELIVERED.store(0, Ordering::SeqCst);
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only: the bounded delivery window (the proof path).
// ─────────────────────────────────────────────────────────────────────────

/// Open IF for a bounded TSC budget and wait for one broker delivery.
///
/// The kernel's convention is IF=0 in CPL0 — but a pending GSI sits in
/// the LAPIC's IRR until the CPU accepts interrupts, so the proof
/// window: pause the preempt timer (a tick through here would be a
/// CPL0 preemption the tick path does not model), STI, spin on
/// [`last_delivered`] until it moves (or the budget expires), CLI,
/// resume the timer. Returns the delivered vector, or None when the
/// budget expired first (the caller prints the LOUD absence — never a
/// quiet success).
///
/// SAFETY of the window itself: every vector that can fire is one of
/// ours (49..=112 — owned, or a NAMED halt), the spurious vector (a
/// no-op), or an exception (the existing fault paths). The timer is
/// masked for the duration. This is the same set the machine can
/// raise at any SYSRET boundary; the window merely lets it happen
/// inside the kernel, deliberately, for microseconds.
#[cfg(not(test))]
pub fn wait_for_delivery(budget_tsc: u64) -> Option<u8> {
    use crate::hw;
    crate::sched::preempt::pause_ticks();
    LAST_DELIVERED.store(0, Ordering::SeqCst);
    // The idle-aware wait: MONITOR arms the LAST_DELIVERED word,
    // MWAIT sleeps until the delivery's store wakes the line (or an
    // unmasked interrupt does — IF is open below). A spin only when
    // the CPU offers no MONITOR/MWAIT (CPUID.01H:ECX bit 3). MWAIT
    // may wake spuriously — the loop re-arms; the TSC budget bounds
    // the whole window either way.
    let mwait_ok = crate::arch::features::has_monitor(hw::cpuid1_ecx());
    let line = &LAST_DELIVERED as *const AtomicU8 as u64;
    hw::sti();
    let deadline = hw::read_tsc() + budget_tsc;
    loop {
        let v = LAST_DELIVERED.load(Ordering::SeqCst);
        if v != 0 {
            // Round I: under load the delivery can land between the
            // sti and the first load (the sti shadow covers exactly
            // one instruction) — the silent break here printed NO
            // proof line and the lane's idle grep failed on a race.
            // The proof must name the path that actually happened.
            crate::serial::write_str(
                "[IDLE] delivery landed before mwait slept (loop top) — C0 window live\n",
            );
            break;
        }
        if hw::read_tsc() >= deadline {
            hw::cli();
            crate::sched::preempt::resume_ticks();
            return None;
        }
        if mwait_ok {
            hw::monitor(line, 0);
            // The re-check: a delivery between the load above and the
            // arming above already stored the word — without this
            // check the mwait would sleep on a line whose store
            // already happened (the timer is masked; nothing else
            // wakes it). Stores after the arming wake the line.
            if LAST_DELIVERED.load(Ordering::SeqCst) != 0 {
                crate::serial::write_str(
                    "[IDLE] mwait armed late — the delivery raced it (caught)\n",
                );
                break;
            }
            hw::mwait(0, 0);
            // Woke: either the store landed (the loop re-checks) or a
            // spurious wake (the loop re-arms).
            if LAST_DELIVERED.load(Ordering::SeqCst) != 0 {
                crate::serial::write_str(
                    "[IDLE] mwait woke on the delivery store (C0 idle, live)\n",
                );
                break;
            }
        }
    }
    hw::cli();
    crate::sched::preempt::resume_ticks();
    Some(LAST_DELIVERED.load(Ordering::SeqCst))
}

/// The non-idle variant of the delivery window: the same bounded,
/// interrupt-open wait WITHOUT MONITOR/MWAIT — a plain spin. MWAIT
/// sleeps until SOME interrupt arrives, so when the awaited message
/// never fires (a device that stays silent — a live outcome every
/// marker must be able to say loudly), the sleeping wait never
/// returns to check its own TSC deadline and the boot hangs INSIDE
/// the window (observed: the MSI-X proof under QEMU TCG; the budget
/// change from 400M to 40M cycles had no effect for exactly this
/// reason). The idle proof (the QMP key that always arrives) keeps
/// the mwait path; message proofs where silence is possible use
/// this one.
#[cfg(not(test))]
pub fn wait_for_delivery_spin(budget_tsc: u64) -> Option<u8> {
    use crate::hw;
    crate::sched::preempt::pause_ticks();
    LAST_DELIVERED.store(0, Ordering::SeqCst);
    hw::sti();
    let deadline = hw::read_tsc() + budget_tsc;
    loop {
        let v = LAST_DELIVERED.load(Ordering::SeqCst);
        if v != 0 || hw::read_tsc() >= deadline {
            break;
        }
    }
    hw::cli();
    crate::sched::preempt::resume_ticks();
    // A silent window is `None` — returning the zero word here would
    // have the caller print "DELIVERED: vector 0x0", a false proof.
    let v = LAST_DELIVERED.load(Ordering::SeqCst);
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SLOTS table is a process-wide static and cargo runs tests
    /// in parallel: every test in this module (and any other test that
    /// reaches alloc/release) must hold this lock for its whole body,
    /// or a sibling's reset() releases the slots mid-assert. The race
    /// was latent until ADR-0022 grew the Kernel struct enough to
    /// shift thread scheduling — pinned here for good.
    static SLOTS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Reset every slot so tests are order-independent.
    fn reset() {
        for s in SLOTS.iter() {
            s.taken.store(false, Ordering::SeqCst);
            s.dev_tag.store(0, Ordering::SeqCst);
            s.dom.store(0, Ordering::SeqCst);
            s.source.store(0, Ordering::SeqCst);
            s.served.store(0, Ordering::SeqCst);
            s.lost.store(0, Ordering::SeqCst);
            s.pending.store(0, Ordering::SeqCst);
        }
        LAST_DELIVERED.store(0, Ordering::SeqCst);
    }

    #[test]
    fn the_range_is_64_slots_and_matches_the_stubs() {
        assert_eq!(DEVICE_VECTOR_BASE, 49, "above the timer (48)");
        assert_eq!(DEVICE_VECTOR_MAX, 112);
        assert_eq!(VEC_SLOTS, 64);
        // The range must not touch the exceptions, the legacy
        // catch-alls, the timer, or the spurious vector.
        assert!(DEVICE_VECTOR_BASE > 48);
        assert!(DEVICE_VECTOR_MAX < 255);
        assert!(DEVICE_VECTOR_MAX < 0xF0, "leaves headroom below 255");
    }

    #[test]
    fn alloc_hands_out_the_range_in_order_and_refuses_duplicates() {
        let _g = SLOTS_TEST_LOCK.lock().unwrap();
        reset();
        let v = alloc(0xAAA, 3, 1).expect("first alloc");
        assert_eq!(v, DEVICE_VECTOR_BASE);
        // A duplicate tag refuses — one vector per device.
        assert!(alloc(0xAAA, 3, 1).is_none(), "duplicate tag must refuse");
        let v2 = alloc(0xBBB, 4, 2).expect("second alloc");
        assert_eq!(v2, DEVICE_VECTOR_BASE + 1);
        // The owner records round-trip.
        assert_eq!(owner_of(v), Some((0xAAA, 3, 1)));
        assert_eq!(owner_of(v2), Some((0xBBB, 4, 2)));
        assert_eq!(owner_of(48), None, "the timer is not ours");
        assert_eq!(owner_of(255), None, "the spurious vector is not ours");
        assert_eq!(owner_of(0), None);
        assert_eq!(owner_of(200), None, "outside the range");
        release(0xAAA);
        assert_eq!(owner_of(v), None, "released slot has no owner");
        // A fresh device can reuse the released slot.
        assert_eq!(alloc(0xCCC, 5, 3), Some(v));
        reset();
    }

    #[test]
    fn alloc_exhausts_loudly_at_the_slot_count() {
        let _g = SLOTS_TEST_LOCK.lock().unwrap();
        reset();
        for i in 0..VEC_SLOTS as u32 {
            assert_eq!(
                alloc(0x100 + i, 0, i),
                Some(DEVICE_VECTOR_BASE + i as u8),
                "slot {i}"
            );
        }
        assert!(alloc(0xFFF, 0, 0).is_none(), "the 65th device refuses");
        release(0x100 + 5);
        // Freed capacity serves the next device.
        assert_eq!(alloc(0xFFF, 0, 0), Some(DEVICE_VECTOR_BASE + 5));
        reset();
    }

    #[test]
    fn mailbox_counts_saturate_and_report_losses_loudly() {
        let _g = SLOTS_TEST_LOCK.lock().unwrap();
        reset();
        let _ = alloc(0xAAA, 3, 1);
        let slot = &SLOTS[0];
        // Fill to the cap: every bump is pending.
        for _ in 0..MAILBOX_CAP {
            bump_mailbox(slot);
        }
        assert_eq!(slot.pending.load(Ordering::SeqCst), MAILBOX_CAP);
        assert_eq!(slot.lost.load(Ordering::SeqCst), 0);
        // Surplus bumps are LOST, counted — never wrapped.
        bump_mailbox(slot);
        bump_mailbox(slot);
        assert_eq!(slot.pending.load(Ordering::SeqCst), MAILBOX_CAP);
        assert_eq!(slot.lost.load(Ordering::SeqCst), 2);
        assert_eq!(
            slot.served.load(Ordering::SeqCst),
            MAILBOX_CAP + 2,
            "served counts every delivery, lost included"
        );
        // The drain takes exactly the cap and clears it.
        assert_eq!(drain(0xAAA), Some(MAILBOX_CAP));
        assert_eq!(drain(0xAAA), Some(0));
        // And the counts feed stays honest after the drain.
        assert_eq!(counts(0xAAA), Some((MAILBOX_CAP + 2, 2, 0)));
        reset();
    }

    #[test]
    fn unknown_devices_drain_and_count_as_absent() {
        let _g = SLOTS_TEST_LOCK.lock().unwrap();
        reset();
        assert_eq!(drain(0xDEAD), None);
        assert_eq!(counts(0xDEAD), None);
        assert_eq!(vector_of(0xDEAD), None);
        reset();
    }

    #[test]
    fn msi_sources_cannot_collide_with_gsis() {
        let _g = SLOTS_TEST_LOCK.lock().unwrap();
        // The namespaces are disjoint by construction: a GSI fits in
        // 16 bits on any bootable machine; MSI entries ride above
        // 0x8000_0000.
        assert!(MSI_SOURCE_BASE > 0xFFFF);
        assert_ne!(Some(MSI_SOURCE_BASE + 0), Some(0));
        // And the table keeps them distinguishable.
        reset();
        let _ = alloc(0xAAA, 1, 1);
        let _ = alloc(0xBBB, 1, MSI_SOURCE_BASE + 0);
        assert_eq!(owner_of(DEVICE_VECTOR_BASE), Some((0xAAA, 1, 1)));
        assert_eq!(
            owner_of(DEVICE_VECTOR_BASE + 1),
            Some((0xBBB, 1, MSI_SOURCE_BASE))
        );
        reset();
    }
}
