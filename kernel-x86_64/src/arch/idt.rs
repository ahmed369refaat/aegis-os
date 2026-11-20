//! IDT: gate encoding (pure, host-tested) and the one-time load
//! (target-only).
//!
//! SAFETY POLICY: part of the documented unsafe allowlist (see
//! `docs/adr/0005`). The only unsafe is the `lidt` and the single fill of
//! the `.bss`-resident table before it, at single-CPU bring-up.

#![allow(unsafe_code)]

pub const VECTORS: usize = 256;

/// One 16-byte IDT gate descriptor (SDM vol. 3, §6.14).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

/// Gate type `0xE` = 64-bit interrupt gate (interrupts masked on entry).
const GATE_INTERRUPT: u8 = 0x0E;

impl Entry {
    /// Encode a gate. `ist` = 0 keeps the current stack; 1..=7 switches to
    /// the matching TSS IST stack. `dpl` = 0 means ring-3 cannot raise the
    /// vector with `int`.
    pub const fn encode(handler: u64, selector: u16, ist: u8, dpl: u8) -> Entry {
        Entry {
            offset_low: handler as u16,
            selector,
            ist: ist & 0x7,
            type_attr: 0x80 | ((dpl & 0x3) << 5) | GATE_INTERRUPT,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }

    pub const ABSENT: Entry = Entry {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        _reserved: 0,
    };

    /// The handler address, for round-trip verification (host-tested).
    pub const fn handler(&self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_mid as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }

    pub const fn type_attr(&self) -> u8 {
        self.type_attr
    }

    pub const fn ist(&self) -> u8 {
        self.ist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_round_trips_the_handler_address() {
        for h in [0u64, 0x200_ABCD, 0xFFFF_FFFF_1234_5678, 0x1_0000_0000] {
            let e = Entry::encode(h, 0x08, 0, 0);
            assert_eq!(e.handler(), h);
        }
    }

    #[test]
    fn ring0_gate_encoding_is_present_interrupt_dpl0() {
        let e = Entry::encode(0x200000, 0x08, 0, 0);
        assert_eq!(e.type_attr(), 0x8E, "P=1, DPL=0, type=0xE");
        assert_eq!(e.ist(), 0);
        // Ring-3 software must not be able to raise exception vectors.
        let d3 = Entry::encode(0x200000, 0x08, 0, 3);
        assert_eq!(d3.type_attr(), 0xEE);
    }

    #[test]
    fn ist_index_lands_in_the_low_three_bits_only() {
        assert_eq!(Entry::encode(1, 0x08, 4, 0).ist(), 4);
        assert_eq!(Entry::encode(1, 0x08, 7, 0).ist(), 7);
        assert_eq!(Entry::encode(1, 0x08, 8, 0).ist(), 0, "IST is 3 bits");
        assert_eq!(Entry::encode(1, 0x08, 0xFF, 0).ist(), 7);
    }

    #[test]
    fn entry_size_is_16_bytes() {
        assert_eq!(core::mem::size_of::<Entry>(), 16);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Target-only load path (needs the naked stubs from `stubs`).
// ─────────────────────────────────────────────────────────────────────────
#[cfg(not(test))]
mod load {
    use super::{Entry, VECTORS};
    use core::arch::asm;

    #[repr(C, align(16))]
    struct Idt {
        entries: [Entry; VECTORS],
    }

    static mut IDT: Idt = Idt {
        entries: [Entry::ABSENT; VECTORS],
    };

    #[repr(C, packed)]
    struct PseudoDescriptor {
        limit: u16,
        base: u64,
    }

    static mut IDTR: PseudoDescriptor = PseudoDescriptor { limit: 0, base: 0 };

    /// Fill vectors 0..=31 from the stub registry and `lidt`. Called
    /// exactly once from `arch::init()`. Vectors 32.. stay absent on
    /// purpose: no device IRQ exists yet (the timer arrives in Stage 4),
    /// and the boot keeps IF=0 throughout — a stray IRQ double-faults
    /// loudly instead of running an absent handler.
    pub fn load() {
        // SAFETY: single-CPU bring-up: the table is filled once, before
        // lidt publishes it to the CPU, and is never written again.
        unsafe {
            let i = &raw mut IDT;
            let idtr = &raw mut IDTR;
            for vector in 0u8..32 {
                let (handler, ist) = crate::arch::stubs::vector_handler(vector);
                (*i).entries[vector as usize] =
                    Entry::encode(handler, crate::arch::gdt::KERNEL_CODE, ist, 0);
            }
            (*idtr).limit = (VECTORS * 16 - 1) as u16;
            (*idtr).base = i as u64;
            asm!("lidt (%rax)", in("rax") idtr, options(att_syntax, nostack, preserves_flags));
        }
    }
}

#[cfg(not(test))]
pub use load::load;
