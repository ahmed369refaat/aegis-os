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
                "[IRQ ] ioapic: probe refused @0x",
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
            "[IRQ ] ioapic live @0x",
            strutil::hex(base, &mut h),
            ": ver=0x",
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
                "[IRQ ] RTE read-back mismatch: wrote 0x",
                strutil::hex(rte, &mut b1),
                " read 0x",
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
            " → vector 0x",
            strutil::hex(u64::from(vector), &mut vv),
            " (edge, active-high, dest 0, RTE read-back ok)",
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
                    "[IR  ] enabled: 256 IRTEs @0x",
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
/// output buffer and is read right after. Absence prints LOUD (the
/// lane greps the success marker, so a regression fails CI, not
/// silently). Returns whether the delivery landed.
#[cfg(not(test))]
pub(crate) fn keyboard_delivery_step(out: &mut dyn FnMut(&str)) -> bool {
    use crate::irq;

    let Some(vector) = irq::vector_of(KBD_OWNER) else {
        // The arm step refused — the arm markers already said so.
        line(out, &["[IRQ ] delivery window skipped: keyboard not armed"]);
        return false;
    };
    match irq::wait_for_delivery(150_000_000) {
        Some(v) => {
            let (served, lost, _pending) = irq::counts(KBD_OWNER).unwrap_or((0, 0, 0));
            let mut b1 = [0u8; 18];
            let mut b2 = [0u8; 18];
            let mut b3 = [0u8; 20];
            let mut b4 = [0u8; 20];
            line(
                out,
                &[
                    "[IRQ ] DELIVERED: vector 0x",
                    strutil::hex(u64::from(v), &mut b1),
                    " (armed 0x",
                    strutil::hex(u64::from(vector), &mut b2),
                    ") — EOI'd, mailbox served=",
                    strutil::dec(served, &mut b3),
                    " lost=",
                    strutil::dec(lost, &mut b4),
                    " (the interrupt→domain chain, live)",
                ],
            );
            true
        }
        None => {
            line(
                out,
                &["[IRQ ] keyboard IRQ NOT delivered within the window — LOUD (proof failed)"],
            );
            false
        }
    }
}
