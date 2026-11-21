//! MmioBus (ADR-0016): every device register access goes through a
//! bounds-checked window. The window is established ONCE per device —
//! BAR sizing at enumeration (`BarMmio`) or a fixed platform address
//! from a firmware table (`FixedMmio`) — and the accessors take an
//! *offset*, refusing anything outside with `None`/`false`. A
//! device-supplied number (or our own arithmetic bug) can never steer
//! the kernel outside the registers the claim validated; refusals are
//! verdicts the caller handles, never panics and never a silent 0.
//!
//! The window math is pure and host-tested (`window_bounds_*`). The
//! volatile core is delegated to `memops` (the audited, direct-map
//! translating layer — no new unsafe enters the tree); a
//! test fake replaces it today and ADR-0017's `IpcMmio` replaces it
//! from ring 3, so the *same driver code* runs in both worlds.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only users (driver steps and their helpers), so items only
// they use look dead there — they are used by the boot build.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables, unused_mut))]

use crate::memops;

/// A validated physical-address window: `base .. base+len`, `len > 0`,
/// no wraparound at `u64::MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MmioWindow {
    base: u64,
    len: u64,
}

impl MmioWindow {
    /// Establish the window once; refuses zero length and any base+len
    /// that wraps (the two ways a bad BAR or a bad table entry becomes
    /// an all-access pass).
    pub fn new(base: u64, len: u64) -> Option<Self> {
        if len == 0 || base.checked_add(len).is_none() {
            return None;
        }
        Some(Self { base, len })
    }

    /// Pure bounds check: does `[off, off+access_len)` lie inside the
    /// window? Overflow-safe by construction (`len - off` cannot wrap
    /// once `off <= len`).
    pub fn contains(&self, off: u64, access_len: u64) -> bool {
        off <= self.len && access_len <= self.len - off
    }

    /// The physical address for an in-window offset, `None` otherwise.
    pub fn pa(&self, off: u64) -> Option<u64> {
        if self.contains(off, 1) {
            Some(self.base + off)
        } else {
            None
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

/// The register-access surface every driver is written against. The
/// default methods carry the whole discipline (bounds first, volatile
/// second), so an implementation only supplies its window + the
/// volatile primitives — `BarMmio` today, the test fake below, and
/// ADR-0017's `IpcMmio` from ring 3.
pub(crate) trait MmioBus {
    /// The validated window this bus serves.
    fn window(&self) -> MmioWindow;

    /// In-window volatile primitives. `pa` comes straight from
    /// `MmioWindow::pa` — in-window by construction — and reaches RAM
    /// or device registers through `memops` (direct-map translating,
    /// the audited unsafe layer).
    fn volatile_read32(&self, pa: u64) -> u32;
    fn volatile_write32(&self, pa: u64, v: u32);
    fn volatile_read64(&self, pa: u64) -> u64;
    fn volatile_write64(&self, pa: u64, v: u64);
    fn volatile_read16(&self, pa: u64) -> u16;

    /// Read a 32-bit register at `off`; `None` = out-of-window refusal.
    fn read32(&self, off: u64) -> Option<u32> {
        self.window().pa(off).map(|pa| self.volatile_read32(pa))
    }

    /// Write a 32-bit register at `off`; `false` = refused.
    fn write32(&self, off: u64, v: u32) -> bool {
        match self.window().pa(off) {
            Some(pa) => {
                self.volatile_write32(pa, v);
                true
            }
            None => false,
        }
    }

    /// Read a 64-bit register at `off`; `None` = out-of-window refusal.
    fn read64(&self, off: u64) -> Option<u64> {
        self.window().pa(off).map(|pa| self.volatile_read64(pa))
    }

    /// Write a 64-bit register at `off`; `false` = refused.
    fn write64(&self, off: u64, v: u64) -> bool {
        match self.window().pa(off) {
            Some(pa) => {
                self.volatile_write64(pa, v);
                true
            }
            None => false,
        }
    }

    /// Read a 16-bit register at `off` — the full 2-byte span must be
    /// in-window (a straddling access is a refusal, never a fabricated
    /// byte); `None` = out-of-window refusal.
    fn read16(&self, off: u64) -> Option<u16> {
        if !self.window().contains(off, 2) {
            return None;
        }
        Some(self.volatile_read16(self.window().base() + off))
    }

    /// Read a single register byte (xHCI's CAPLENGTH lives at byte 0
    /// of the caps block). Built on the containing aligned dword: the
    /// whole dword must be in-window; `None` = refusal.
    fn read8(&self, off: u64) -> Option<u8> {
        let aligned = off & !3;
        if !self.window().contains(aligned, 4) {
            return None;
        }
        let word = self.volatile_read32(self.window().base() + aligned);
        Some((word >> (8 * (off & 3))) as u8)
    }
}

/// A PCI BAR-derived window: the registers of one claimed device.
pub(crate) struct BarMmio(MmioWindow);

impl BarMmio {
    /// From an enumerated BAR (base + size as the scanner measured it).
    /// Refuses the same way `MmioWindow::new` does — a malformed BAR is
    /// a refusal, not a wild window.
    pub fn new(bar_base: u64, bar_len: u64) -> Option<Self> {
        MmioWindow::new(bar_base, bar_len).map(BarMmio)
    }
}

/// A fixed platform window: HPET blocks, VT-d register sets —
/// addresses firmware tables named, validated at parse time (F12).
pub(crate) struct FixedMmio(MmioWindow);

impl FixedMmio {
    pub fn new(base: u64, len: u64) -> Option<Self> {
        MmioWindow::new(base, len).map(FixedMmio)
    }
}

macro_rules! impl_bus {
    ($t:ty) => {
        impl MmioBus for $t {
            fn window(&self) -> MmioWindow {
                self.0
            }
            fn volatile_read32(&self, pa: u64) -> u32 {
                memops::read_u32(pa)
            }
            fn volatile_write32(&self, pa: u64, v: u32) {
                memops::write_u32(pa, v)
            }
            fn volatile_read64(&self, pa: u64) -> u64 {
                memops::read_u64(pa)
            }
            fn volatile_write64(&self, pa: u64, v: u64) {
                memops::write_u64(pa, v)
            }
            fn volatile_read16(&self, pa: u64) -> u16 {
                memops::read_u16(pa)
            }
        }
    };
}

impl_bus!(BarMmio);
impl_bus!(FixedMmio);

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn window_new_refuses_zero_and_wrap() {
        assert!(MmioWindow::new(0, 0).is_none());
        assert!(MmioWindow::new(0x10, 0).is_none());
        // base+len must not wrap: the classic bad-BAR all-access pass.
        assert!(MmioWindow::new(u64::MAX - 4, 8).is_none());
        assert!(MmioWindow::new(u64::MAX - 7, 8).is_none()); // end == 2^64
        assert!(MmioWindow::new(u64::MAX - 7, 7).is_some()); // last byte reachable
                                                             // The 4-GiB boundary the MMIO direct map lives above.
        assert!(MmioWindow::new(0xFD000000, 0x1000000).is_some());
    }

    #[test]
    fn window_bounds_edge_cases() {
        let w = MmioWindow::new(0x1000, 0x100).unwrap();
        // Offsets are window-relative: [0, 0x100).
        assert!(w.contains(0, 1));
        assert!(w.contains(0xFF, 1)); // last valid byte
        assert!(!w.contains(0x100, 1)); // one past the end
        assert!(!w.contains(u64::MAX, 1)); // device-supplied garbage
        assert!(w.contains(0, 0x100)); // the whole window
        assert!(!w.contains(0, 0x101)); // one byte too wide
        assert!(!w.contains(1, 0x100)); // runs off the end
                                        // off+access_len overflow must not admit anything.
        assert!(!w.contains(0xF0, u64::MAX));
        assert!(!w.contains(u64::MAX - 1, 2));
        // A 16-bit access straddling the end is a refusal.
        assert!(w.contains(0xFF, 1));
        assert!(!w.contains(0xFF, 2));
    }

    #[test]
    fn window_pa_maps_and_refuses() {
        let w = MmioWindow::new(0xFEBC0000, 0x20000).unwrap();
        assert_eq!(w.pa(0x08), Some(0xFEBC0008));
        assert_eq!(w.pa(0x1FFFF), Some(0xFEBDFFFF)); // last byte of the window
        assert_eq!(w.pa(0x20000), None);
        assert_eq!(w.pa(u64::MAX), None);
    }

    /// The refusal semantics a driver sees through the trait: a fake
    /// bus whose volatile core counts accesses — out-of-window offsets
    /// never reach the device at all.
    struct FakeBus {
        win: MmioWindow,
        reads: Cell<u32>,
        writes: Cell<u32>,
    }

    impl MmioBus for FakeBus {
        fn window(&self) -> MmioWindow {
            self.win
        }
        fn volatile_read32(&self, _pa: u64) -> u32 {
            self.reads.set(self.reads.get() + 1);
            0xA5A5_0000
        }
        fn volatile_write32(&self, _pa: u64, _v: u32) {
            self.writes.set(self.writes.get() + 1);
        }
        fn volatile_read64(&self, _pa: u64) -> u64 {
            self.reads.set(self.reads.get() + 1);
            0
        }
        fn volatile_write64(&self, _pa: u64, _v: u64) {
            self.writes.set(self.writes.get() + 1);
        }
        fn volatile_read16(&self, _pa: u64) -> u16 {
            self.reads.set(self.reads.get() + 1);
            0
        }
    }

    #[test]
    fn bus_refusals_never_reach_the_device() {
        let bus = FakeBus {
            win: MmioWindow::new(0x1000, 0x40).unwrap(),
            reads: Cell::new(0),
            writes: Cell::new(0),
        };
        assert_eq!(bus.read32(0x10), Some(0xA5A5_0000));
        assert_eq!(bus.reads.get(), 1);
        assert_eq!(bus.read32(0x40), None); // one past the end
        assert_eq!(bus.reads.get(), 1); // nothing reached the device
        assert!(bus.write32(0x3C, 1));
        assert_eq!(bus.writes.get(), 1);
        assert!(!bus.write32(0x7F, 1));
        assert_eq!(bus.writes.get(), 1); // still nothing sent
        assert_eq!(bus.read64(u64::MAX), None);
        assert_eq!(bus.reads.get(), 1);
    }

    #[test]
    fn bus_16bit_full_span_in_window() {
        let bus = FakeBus {
            win: MmioWindow::new(0x2000, 0x10).unwrap(),
            reads: Cell::new(0),
            writes: Cell::new(0),
        };
        assert_eq!(bus.read16(0xE), Some(0)); // bytes 0xE..0x10, inside
        assert_eq!(bus.reads.get(), 1);
        assert_eq!(bus.read16(0xF), None); // straddles the end: refused
        assert_eq!(bus.reads.get(), 1); // and never sent
    }

    #[test]
    fn bus_8bit_reads_the_containing_dword() {
        let bus = FakeBus {
            win: MmioWindow::new(0x2000, 0x10).unwrap(),
            reads: Cell::new(0),
            writes: Cell::new(0),
        };
        // FakeBus returns 0xA5A5_0000 per dword: LE bytes are
        // [0x00, 0x00, 0xA5, 0xA5] — byte 3 of the dword at 0xC is 0xA5.
        assert_eq!(bus.read8(0x0), Some(0)); // dword 0..4, byte 0
        assert_eq!(bus.reads.get(), 1);
        assert_eq!(bus.read8(0xF), Some(0xA5)); // dword 0xC..0x10, byte 3
        assert_eq!(bus.reads.get(), 2);
        // The byte at 0x10 would need the dword 0x10..0x14: outside.
        assert_eq!(bus.read8(0x10), None);
        assert_eq!(bus.reads.get(), 2);
    }
}
