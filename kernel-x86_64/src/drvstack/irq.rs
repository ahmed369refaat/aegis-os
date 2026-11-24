//! The interrupt bring-up step (ADR-0019): route the PS/2 keyboard's
//! ISA IRQ 1 through the IOAPIC to a broker-owned vector — the first
//! line interrupt in the system that is NOT a poll — and prove the
//! chain end to end when the boot lane's QMP key arrives.
//!
//! Why the keyboard is the proof vehicle: it is the one interrupt
//! source the lane can trigger deterministically from the host (the
//! QMP `send-key` driver fires once the "[KBD] armed" marker appears),
//! its line is edge/active-high (the simple RTE encoding), and its
//! existing poll path stays byte-identical — the IRQ is additive
//! notification, not a rewrite.

// Host-test builds compile this module without its boot-only step
// functions (they need `hw`/`memops`).
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables))]

use crate::strutil;
use crate::strutil::line;

/// The frames-ledger owner tag for the keyboard's broker vector
/// (legacy device: no DMA, no IOMMU domain — domain 0, the kernel's
/// own; the ring-3 slice reassigns it when the input domain exists).
pub const KBD_OWNER: u32 = 77;

/// The keyboard's ISA IRQ number.
pub const KBD_ISA_IRQ: u8 = 1;

/// kmain's irq step: probe the IOAPIC the MADT named, claim the
/// keyboard's GSI for a broker vector, program the redirection entry,
/// and read it back — the arm markers the proof lane greps. Refuses
/// closed (loud markers, no crash) on every failure: absent MADT,
/// out-of-window address, dead registers, broker exhaustion.
#[cfg(not(test))]
pub(crate) fn irq_step(out: &mut dyn FnMut(&str), madt: Option<&crate::drvstack::acpi::MadtIrq>) {
    use crate::arch::ioapic;
    use crate::irq;

    let Some(m) = madt else {
        line(
            out,
            &["[IRQ ] ioapic: no MADT interrupt view — refusing closed"],
        );
        return;
    };
    let Some(base) = m.primary_ioapic() else {
        line(out, &["[IRQ ] ioapic: MADT names none — refusing closed"]);
        return;
    };
    let Some(ioapic) = ioapic::IoApic::probe(base) else {
        let mut h = [0u8; 18];
        line(
            out,
            &[
                "[IRQ ] ioapic: probe refused @",
                strutil::hex(base, &mut h),
                " (window or dead registers) — refusing closed",
            ],
        );
        return;
    };
    let mut h = [0u8; 18];
    let mut v = [0u8; 18];
    let mut n = [0u8; 20];
    line(
        out,
        &[
            "[IRQ ] ioapic live @",
            strutil::hex(base, &mut h),
            ": ver=",
            strutil::hex(u64::from(ioapic.version()), &mut v),
            " max_gsi=",
            strutil::dec(u64::from(ioapic.max_gsi()), &mut n),
        ],
    );

    // The keyboard's GSI, through the MADT's override table (irq0→2
    // is the PIT's famous remap; irq1 passes through unmapped on q35).
    let gsi = m.gsi_of_isa_irq(KBD_ISA_IRQ);
    let Some(vector) = irq::alloc(KBD_OWNER, 0, gsi) else {
        let mut g = [0u8; 20];
        line(
            out,
            &[
                "[IRQ ] broker refused the keyboard (table full or duplicate) — gsi ",
                strutil::dec(u64::from(gsi), &mut g),
            ],
        );
        return;
    };
    // Program the RTE: edge, active-high, physical dest 0 (the BSP),
    // unmasked — through the masked-first two-step (ioapic::program).
    let rte = ioapic::rte_encode(vector, 0, ioapic::TRIGGER_EDGE, false);
    if !ioapic.program(gsi, rte) {
        line(out, &["[IRQ ] ioapic refused the RTE (gsi out of range)"]);
        irq::release(KBD_OWNER);
        return;
    }
    // Read-back: what we programmed is what the device holds (the
    // same discipline as the LAPIC version check).
    let back = ioapic.read_rte(gsi).unwrap_or(0);
    if back != rte {
        let mut b1 = [0u8; 18];
        let mut b2 = [0u8; 18];
        line(
            out,
            &[
                "[IRQ ] RTE read-back mismatch: wrote ",
                strutil::hex(rte, &mut b1),
                " read ",
                strutil::hex(back, &mut b2),
                " — refusing",
            ],
        );
        let _ = ioapic.mask(gsi);
        irq::release(KBD_OWNER);
        return;
    }
    let mut vv = [0u8; 18];
    let mut gg = [0u8; 20];
    line(
        out,
        &[
            "[IRQ ] armed: isa irq 1 → gsi ",
            strutil::dec(u64::from(gsi), &mut gg),
            " → vector ",
            strutil::hex(u64::from(vector), &mut vv),
            " (edge, active-high, dest 0, RTE read-back ok)",
        ],
    );

    // ── Phase 7: the TTY — the same chain for ISA IRQ 4 (COM1), the
    // serial the shell session types on. The UART itself comes up
    // FIRST (IER RX-interrupt + FIFOs): the RTE going live with the
    // device deaf would arm a line that can never fire. Refuses
    // closed like the keyboard above; on refusal the read path's
    // service-time drain keeps the TTY alive (documented polling).
    crate::tty::uart_init();
    let tgsi = m.gsi_of_isa_irq(crate::tty::TTY_ISA_IRQ);
    let Some(tvec) = irq::alloc(crate::tty::TTY_OWNER, 0, tgsi) else {
        line(
            out,
            &["[TTY] broker refused the serial (table full or duplicate) — poll mode"],
        );
        return;
    };
    let tre = ioapic::rte_encode(tvec, 0, ioapic::TRIGGER_EDGE, false);
    if !ioapic.program(tgsi, tre) {
        line(
            out,
            &["[TTY] ioapic refused the RTE (gsi out of range) — poll mode"],
        );
        irq::release(crate::tty::TTY_OWNER);
        return;
    }
    if ioapic.read_rte(tgsi) != Some(tre) {
        line(out, &["[TTY] RTE read-back mismatch — poll mode"]);
        let _ = ioapic.mask(tgsi);
        irq::release(crate::tty::TTY_OWNER);
        return;
    }
    let mut tv = [0u8; 18];
    let mut tg = [0u8; 20];
    let mut tb = [0u8; 20];
    let mut td = [0u8; 20];
    line(
        out,
        &[
            "[TTY] armed: isa irq 4 → gsi ",
            strutil::dec(u64::from(tgsi), &mut tg),
            " → vector ",
            strutil::hex(u64::from(tvec), &mut tv),
            " — RX by interrupt, ring 256B, buffered=",
            strutil::dec(crate::tty::buffered() as u64, &mut tb),
            " dropped=",
            strutil::dec(crate::tty::dropped() as u64, &mut td),
        ],
    );
}

/// The IR bring-up half (ADR-0019): allocate the IRTE frame and turn
/// interrupt remapping ON — but only when the DMAR declares it (the
/// base q35 lane boots `-device intel-iommu,intremap=off`, and the
/// honest answer there is "not enabling"). This is the step the old
/// deferred comment waited for: the interrupt broker now exists and
/// owns the IRTE decision, so IR can be enabled without creating an
/// unowned vector path.
#[cfg(not(test))]
pub(crate) fn ir_setup_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut crate::frames::FramePool<N>,
    out: &mut dyn FnMut(&str),
    unit: &mut crate::arch::vtd::Vtd,
    dmar: &aegis_os::dmar::Dmar,
) {
    if !dmar.intr_remap {
        line(
            out,
            &["[IR  ] dmar declares intr_remap=off — not enabling (fail-honest, base lane)"],
        );
        return;
    }
    let Ok(frame) = pool.alloc_for(&mut k.frames, crate::drvstack::VTD_TABLE_OWNER) else {
        line(
            out,
            &["[IR  ] IRTE frame allocation failed — not enabling (fail-closed)"],
        );
        return;
    };
    // The frame arrives scrubbed (the pool discipline): every IRTE
    // reads not-present until the broker arms one.
    match unit.ir_enable(frame, false) {
        Ok((sirtp, ire)) => {
            let mut f = [0u8; 18];
            let mut s1 = [0u8; 20];
            let mut s2 = [0u8; 20];
            line(
                out,
                &[
                    "[IR  ] enabled: 256 IRTEs @",
                    strutil::hex(frame, &mut f),
                    " eim=off (sirtp spins=",
                    strutil::dec(sirtp, &mut s1),
                    ", ire spins=",
                    strutil::dec(ire, &mut s2),
                    ") — the broker owns the table",
                ],
            );
        }
        Err(_) => {
            line(
                out,
                &["[IR  ] enable handshake failed — not enabling (fail-closed)"],
            );
            let _ = pool.free(&mut k.frames, frame, crate::drvstack::VTD_TABLE_OWNER);
        }
    }
}

/// The delivery window, called from the PS/2 step BEFORE the scancode
/// read: the wait IS the window — the QMP driver fires the key at the
/// "[KBD] armed" marker, the press arrives MID-WINDOW, and the IRQ
/// delivers through the broker chain (vector → EOI → mailbox). MWAIT
/// sleeps until the delivery's store wakes the armed line (CPUID-
/// gated; a spin otherwise). The scancode itself waits in the 8042's
/// output buffer and is read right after.
///
/// Three honesty fixes this round, each found live:
/// (1) **The stale-edge drain runs FIRST.** The i8042 self-test
///     byte's IRQ1 edge latches in the LAPIC's IRR while the
///     self-test poll runs at IF=0 — it then delivers at the window's
///     very first STI and satisfies DELIVERED with no key ever sent
///     (keyless lanes were green on exactly that false positive). A
///     short window opens IF, lets the latched edge land, and
///     DISCARDS it.
/// (2) **The window accepts only the KEYBOARD'S OWN vector.** A
///     delivery on any other owner's vector (the serial's IRQ4 on a
///     session lane, for one) no longer satisfies the keyboard proof —
///     the loop keeps waiting until the keyboard's edge or the
///     budget.
/// (3) After a REAL delivery, a bounded RELEASE window absorbs the
///     key's break-code edge (~the send-key hold time later), so it
///     does not latch and deliver at some later IF-open (the
///     kmain→user boundary, where the tick guard would name it).
///
/// Absence prints the honest lane text — no key sent here; the pinned
/// proof lives on the `--verify-ps2` lane, whose machine has no USB
/// keyboard, so send-key has exactly one keyboard to route to.
/// Returns whether the keyboard's own delivery landed.
/// A STI'd, TSC-bounded SPIN on the broker's last-delivered witness —
/// the delivery window's wake-safe shape. NOT the mwait sleep: under
/// TCG, MWAIT sleeps until an interrupt, and with the preempt tick
/// paused a keyless lane has NO wake source at all (found live, K18:
/// the drain consumed the stale self-test edge that used to satisfy
/// the window at the loop top, and the very next mwait slept forever
/// — the lane hung mid-proof). The spin sees the delivery's store
/// within microseconds of the IRQ; the TSC budget bounds the keyless
/// case honestly. Returns TRUE only for the KEYBOARD'S vector; any
/// other owner's edge is consumed (its bottom half already ran at
/// delivery time) and the wait goes on — a serial delivery never
/// satisfies a keyboard proof.
#[cfg(not(test))]
fn spin_window_for(vector: u8, budget_tsc: u64) -> bool {
    use crate::irq;
    crate::sched::preempt::pause_ticks();
    irq::clear_last_delivered();
    crate::hw::sti();
    let deadline = crate::hw::read_tsc() + budget_tsc;
    let mut delivered = false;
    while crate::hw::read_tsc() < deadline {
        let v = irq::last_delivered();
        if v == vector {
            delivered = true;
            break;
        }
        if v != 0 {
            irq::clear_last_delivered();
        }
    }
    crate::hw::cli();
    crate::sched::preempt::resume_ticks();
    delivered
}

#[cfg(not(test))]
pub(crate) fn keyboard_delivery_step(out: &mut dyn FnMut(&str)) -> bool {
    use crate::irq;

    let Some(vector) = irq::vector_of(KBD_OWNER) else {
        // The arm step refused — the arm markers already said so.
        line(out, &["[IRQ ] delivery window skipped: keyboard not armed"]);
        return false;
    };
    // (1) the stale-edge drain: wait_for_delivery is SAFE here — the
    // latched IRR delivers at the window's very first STI (its own
    // loop-top log line), so it never reaches the mwait sleep; its
    // [IDLE] line feeds the C0-window OR-proof.
    let drain = crate::clock::ns_to_cycles(50_000_000).unwrap_or(1 << 27);
    let _ = irq::wait_for_delivery(drain);
    // (2) the real window: the wake-safe SPIN (the helper's doc is
    // the why), 1.5 s TSC-bounded — the QMP driver polls its marker
    // at 0.5 s granularity; a loaded TCG box needs the slack.
    let window = crate::clock::ns_to_cycles(1_500_000_000).unwrap_or(1 << 31);
    let delivered = spin_window_for(vector, window);
    if !delivered {
        line(
            out,
            &["[IRQ ] no IRQ1 delivery in this window (no key sent on this lane) — the chain stays armed; the pinned proof lives on the PS/2 lane"],
        );
        return false;
    }
    let (served, lost, _pending) = irq::counts(KBD_OWNER).unwrap_or((0, 0, 0));
    let mut b1 = [0u8; 18];
    let mut b3 = [0u8; 20];
    let mut b4 = [0u8; 20];
    line(
        out,
        &[
            "[IRQ ] DELIVERED: vector ",
            strutil::hex(u64::from(vector), &mut b1),
            " — the key's own IRQ1 edge, EOI'd, mailbox served=",
            strutil::dec(served, &mut b3),
            " lost=",
            strutil::dec(lost, &mut b4),
            " (the interrupt→domain chain, live)",
        ],
    );
    // (3) the break-code release: the send-key hold time is 300 ms —
    // a 600 ms spin absorbs the break's edge here, silently, so
    // nothing latches past this step.
    let release = crate::clock::ns_to_cycles(600_000_000).unwrap_or(1 << 31);
    let _ = spin_window_for(vector, release);
    true
}
