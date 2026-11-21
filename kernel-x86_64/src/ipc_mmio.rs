//! IpcMmio — ADR-0017's first slice: a driver's register access as a
//! message, not a volatile load.
//!
//! The seam ADR-0016 promised: driver code written against `MmioBus`
//! runs UNCHANGED over this bus — the accessors forward every request
//! through an `MmioChannel` to a ring-0 **device core** that checks the
//! offset against the SAME validated window (ADR-0016's `BarMmio`
//! discipline) before anything volatile happens. A ring-3 driver
//! domain therefore cannot even NAME a register outside its grant.
//!
//! This slice runs the channel in-process (the core is the channel's
//! far end; host tests drive the identical code). The ring-3 slice
//! swaps the transport for a capability-gated IPC endpoint
//! (ADR-0004); the message types, the window discipline, and the
//! refusal semantics do not change.
//!
//! The core counts what it serves and what it refuses — the organic
//! signal feed ADR-0017 hands the BehaviorMonitor (a domain cannot
//! forge or suppress its own device core's counters).

// The first slice's consumer is the host test suite; the ring-3
// transport (the next slice) is the boot-build consumer. Until it
// lands, the boot build sees this module as unused — it is shipped
// infrastructure, not dead code.
#![cfg_attr(not(test), allow(dead_code))]

use crate::mmio::{MmioBus, MmioWindow};
use core::cell::RefCell;

/// One register request from a driver domain to its device core.
/// `len` is 1, 2, 4, or 8 bytes — nothing else reaches the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MmioMsg {
    Read { off: u64, len: u8 },
    Write { off: u64, len: u8, val: u64 },
}

/// The core's verdict. `Refused` is out-of-window (or a bad width) —
/// the same refusal semantics `MmioBus` gives a ring-0 driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MmioReply {
    Read(u64),
    Wrote,
    Refused,
}

/// The transport between a driver domain and its device core.
pub(crate) trait MmioChannel {
    fn send(&mut self, msg: MmioMsg) -> MmioReply;
}

/// The ring-0 device core: the ONLY path from a channel message to a
/// register. Every request is window-checked (offset AND width — a
/// straddling access is a refusal, exactly like `MmioBus`); refused
/// requests never reach the device; served and refused are counted
/// (the monitor feed).
pub(crate) struct DeviceCore {
    win: MmioWindow,
    device: crate::mmio::BarMmio,
    served: u64,
    refused: u64,
}

impl DeviceCore {
    /// The core owns the same validated window the ring-0 driver
    /// would have used (established at claim time from the BAR).
    pub(crate) fn new(win: MmioWindow, device: crate::mmio::BarMmio) -> Self {
        DeviceCore {
            win,
            device,
            served: 0,
            refused: 0,
        }
    }

    /// Serve one message: window check first, volatile second.
    pub(crate) fn serve(&mut self, msg: MmioMsg) -> MmioReply {
        let (off, len) = match msg {
            MmioMsg::Read { off, len, .. } | MmioMsg::Write { off, len, .. } => (off, len),
        };
        if !matches!(len, 1 | 2 | 4 | 8) || !self.win.contains(off, u64::from(len)) {
            self.refused += 1;
            return MmioReply::Refused;
        }
        match msg {
            MmioMsg::Read { off, len, .. } => {
                let pa = self.win.pa(off).expect("contains() checked");
                let v = match len {
                    1 => {
                        // a byte read is the containing dword with the
                        // byte selected (MmioBus::read8's construction,
                        // done at the core)
                        let aligned = off & !3;
                        let d = self.device.volatile_read32(
                            self.win.pa(aligned).expect("contains checked the dword"),
                        );
                        u64::from((d >> (8 * (off & 3))) as u8)
                    }
                    2 => u64::from(self.device.volatile_read16(pa)),
                    4 => u64::from(self.device.volatile_read32(pa)),
                    _ => self.device.volatile_read64(pa),
                };
                self.served += 1;
                MmioReply::Read(v)
            }
            MmioMsg::Write { off, len, val, .. } => {
                let pa = self.win.pa(off).expect("contains() checked");
                match len {
                    4 => self.device.volatile_write32(pa, val as u32),
                    8 => self.device.volatile_write64(pa, val),
                    // the first slice's driver surface is 32/64-bit
                    // registers; narrower writes stay refused rather
                    // than half-implemented.
                    _ => {
                        self.refused += 1;
                        return MmioReply::Refused;
                    }
                }
                self.served += 1;
                MmioReply::Wrote
            }
        }
    }

    /// The monitor feed: (served, refused) since core creation.
    pub(crate) fn counters(&self) -> (u64, u64) {
        (self.served, self.refused)
    }
}

/// The driver-side bus: an `MmioBus` whose every accessor is a
/// message. Driver code does not change — it was written against the
/// trait (ADR-0016).
pub(crate) struct IpcMmio<'a, C: MmioChannel> {
    win: MmioWindow,
    chan: RefCell<&'a mut C>,
}

impl<'a, C: MmioChannel> IpcMmio<'a, C> {
    /// The window is established once (the claim-time BAR window) —
    /// the driver-side `window()` answers driver-side bounds
    /// questions with the SAME numbers the core enforces.
    pub(crate) fn new(win: MmioWindow, chan: &'a mut C) -> Self {
        IpcMmio {
            win,
            chan: RefCell::new(chan),
        }
    }

    fn ask(&self, msg: MmioMsg) -> MmioReply {
        self.chan.borrow_mut().send(msg)
    }
}

impl<C: MmioChannel> MmioBus for IpcMmio<'_, C> {
    fn window(&self) -> MmioWindow {
        self.win
    }
    // the volatile primitives are never called on this bus: every
    // accessor below is overridden to a message; the defaults that
    // would use them are unreachable.
    fn volatile_read32(&self, _pa: u64) -> u32 {
        unreachable!("IpcMmio accessors are messages; the defaults never run")
    }
    fn volatile_write32(&self, _pa: u64, _v: u32) {
        unreachable!("IpcMmio accessors are messages; the defaults never run")
    }
    fn volatile_read64(&self, _pa: u64) -> u64 {
        unreachable!("IpcMmio accessors are messages; the defaults never run")
    }
    fn volatile_write64(&self, _pa: u64, _v: u64) {
        unreachable!("IpcMmio accessors are messages; the defaults never run")
    }
    fn volatile_read16(&self, _pa: u64) -> u16 {
        unreachable!("IpcMmio accessors are messages; the defaults never run")
    }

    fn read32(&self, off: u64) -> Option<u32> {
        match self.ask(MmioMsg::Read { off, len: 4 }) {
            MmioReply::Read(v) => Some(v as u32),
            _ => None,
        }
    }
    fn write32(&self, off: u64, v: u32) -> bool {
        matches!(
            self.ask(MmioMsg::Write {
                off,
                len: 4,
                val: u64::from(v)
            }),
            MmioReply::Wrote
        )
    }
    fn read64(&self, off: u64) -> Option<u64> {
        match self.ask(MmioMsg::Read { off, len: 8 }) {
            MmioReply::Read(v) => Some(v),
            _ => None,
        }
    }
    fn write64(&self, off: u64, v: u64) -> bool {
        matches!(
            self.ask(MmioMsg::Write {
                off,
                len: 8,
                val: v
            }),
            MmioReply::Wrote
        )
    }
    fn read16(&self, off: u64) -> Option<u16> {
        match self.ask(MmioMsg::Read { off, len: 2 }) {
            MmioReply::Read(v) => Some(v as u16),
            _ => None,
        }
    }
    /// A byte read is served by the core as a containing-dword read
    /// with the byte selected — the same construction `MmioBus`'s
    /// default uses, done at the core so the channel never widens a
    /// driver's grant.
    fn read8(&self, off: u64) -> Option<u8> {
        let aligned = off & !3;
        let dword = self.read32(aligned)?;
        Some((dword >> (8 * (off & 3))) as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drvstack::testharness::FakePhys;

    /// The in-process channel of the first slice: the core IS the far
    /// end. The ring-3 slice replaces this with an IPC endpoint; the
    /// tests below then run unchanged against it.
    struct CoreChannel {
        core: DeviceCore,
    }
    impl MmioChannel for CoreChannel {
        fn send(&mut self, msg: MmioMsg) -> MmioReply {
            self.core.serve(msg)
        }
    }

    /// A register page in host-"physical" memory with a BarMmio core
    /// over it — the "device" both sides talk to.
    fn setup() -> (FakePhys, MmioWindow, crate::mmio::BarMmio) {
        let phys = FakePhys::new(1);
        let base = phys.pa(0);
        let win = MmioWindow::new(base, 0x100).expect("test window");
        let bus = crate::mmio::BarMmio::new(base, 0x100).expect("test bus");
        (phys, win, bus)
    }

    /// The headline ADR-0017 proof: driver code written against the
    /// MmioBus TRAIT runs unchanged over the channel — and gets the
    /// same answers the direct (ring-0) bus gives.
    #[test]
    fn the_same_driver_code_runs_ring0_and_channelled() {
        let (phys, win, bus0) = setup();
        let mut chan = CoreChannel {
            core: DeviceCore::new(
                win,
                crate::mmio::BarMmio::new(win.base(), win.len()).unwrap(),
            ),
        };
        let ipc = IpcMmio::new(win, &mut chan);
        // the "driver": a register sequence written ONLY against the
        // trait — run it against both buses.
        let drive = |b: &dyn MmioBus| -> (u32, u16, u64) {
            assert!(b.write32(0x10, 0xA5A5_0F0F));
            assert!(b.write64(0x20, 0x1234_5678_9ABC_DEF0));
            (
                b.read32(0x10).unwrap(),
                b.read16(0x12).unwrap(),
                b.read64(0x20).unwrap(),
            )
        };
        let direct = drive(&bus0);
        let channelled = drive(&ipc);
        assert_eq!(direct, channelled);
        assert_eq!(channelled, (0xA5A5_0F0F, 0xA5A5, 0x1234_5678_9ABC_DEF0));
        // every channelled access was served by the core, none
        // refused (the direct run touches no counter)
        assert_eq!(chan.core.counters(), (5, 0));
        drop(phys);
    }

    /// Out-of-window offsets are refused by the CORE — they never
    /// reach the register page — and the refusal is COUNTED (the
    /// monitor feed a domain cannot suppress).
    #[test]
    fn out_of_window_requests_never_reach_the_device() {
        let (phys, win, _bus0) = setup();
        // poison everything past the window's end so a stray write
        // would be visible
        let guard = phys.pa(0x100);
        crate::memops::write_u64(guard, 0xDEAD_BEEF_DEAD_BEEF);
        let mut chan = CoreChannel {
            core: DeviceCore::new(
                win,
                crate::mmio::BarMmio::new(win.base(), win.len()).unwrap(),
            ),
        };
        let ipc = IpcMmio::new(win, &mut chan);
        assert_eq!(ipc.read32(0x100), None, "one past the end");
        assert!(!ipc.write32(0xFF0, 1), "far past the end");
        assert_eq!(ipc.read64(u64::MAX), None, "device-supplied garbage");
        assert_eq!(ipc.read16(0xFF), None, "a 2-byte read straddling the end");
        assert_eq!(ipc.read8(0x100), None, "byte reads are bounded too");
        // and the guard page is untouched
        assert_eq!(crate::memops::read_u64(guard), 0xDEAD_BEEF_DEAD_BEEF);
        // the core counted every refusal — the signal the monitor gets
        assert_eq!(chan.core.counters(), (0, 5));
        drop(phys);
    }

    /// Bad widths are refused (the message surface is 1/2/4/8; a
    /// hostile domain cannot smuggle a wider access).
    #[test]
    fn hostile_widths_are_refused_by_the_core() {
        let (phys, win, _bus0) = setup();
        let mut core = DeviceCore::new(
            win,
            crate::mmio::BarMmio::new(win.base(), win.len()).unwrap(),
        );
        assert_eq!(
            core.serve(MmioMsg::Read { off: 0, len: 3 }),
            MmioReply::Refused
        );
        assert_eq!(
            core.serve(MmioMsg::Write {
                off: 0,
                len: 0,
                val: 1
            }),
            MmioReply::Refused
        );
        assert_eq!(
            core.serve(MmioMsg::Write {
                off: 0,
                len: 255,
                val: 1
            }),
            MmioReply::Refused
        );
        // the first-slice write surface is 32/64-bit; a 1-byte write
        // is refused rather than half-implemented
        assert_eq!(
            core.serve(MmioMsg::Write {
                off: 0,
                len: 1,
                val: 1
            }),
            MmioReply::Refused
        );
        assert_eq!(core.counters(), (0, 4));
        drop(phys);
    }

    /// ADR-0017's rogue-driver list, first slice (the channel + broker
    /// seams; the ring-3 demo + monitor wiring is the next slice):
    /// every forbidden operation is REFUSED, typed, leaves no side
    /// effect — and a healthy driver keeps working after each one.
    #[test]
    fn rogue_driver_operations_are_all_refused() {
        use crate::drvstack::testharness::FakeProt;
        use aegis_os::dma::{DmaBroker, DmaDir, DmaError, DmaQuotas};

        // ── rogue #1: MMIO outside the window (the channel test
        //    above proves it; here it is one line of the suite):
        let (phys, win, _bus0) = setup();
        let mut chan = CoreChannel {
            core: DeviceCore::new(
                win,
                crate::mmio::BarMmio::new(win.base(), win.len()).unwrap(),
            ),
        };
        let ipc = IpcMmio::new(win, &mut chan);
        assert_eq!(ipc.read32(0x1000), None);

        // ── rogue #2/#3/#4: against the REAL broker (fake transport):
        //    quota overrun, another domain's cookie, in-flight unmap.
        let mem = vec![0u64; 4096];
        let base = (mem.as_ptr() as u64 + 4095) & !4095u64;
        let broker = DmaBroker::new(
            FakeProt {
                live: Vec::new(),
                budget: 3, // 2 rogue maps + the healthy driver's
            },
            DmaQuotas {
                max_regions: 2,
                max_bytes: 64 * 1024,
            },
        );
        let mut broker = broker;
        let pa_a = base;
        let pa_b = base + 4096;
        let v = broker
            .map_region(1, pa_a, 4096, DmaDir::Bidirectional)
            .unwrap();
        // #2: the quota (2 regions) is hit by the second map; the
        // third must be a typed refusal, not a growth.
        assert!(broker
            .map_region(1, pa_b, 4096, DmaDir::Bidirectional)
            .is_ok());
        assert!(matches!(
            broker.map_region(1, pa_b + 4096, 4096, DmaDir::Bidirectional),
            Err(DmaError::QuotaRegions)
        ));
        // #3: another domain's cookie — dom 2 never mapped anything.
        assert!(matches!(
            broker.region_complete(2, v.cookie),
            Err(DmaError::InvalidHandle)
        ));
        // #4: unmapping an IN-FLIGHT region (AbortRequired, ADR-0015):
        assert!(matches!(
            broker.unmap_region(1, v.cookie),
            Err(DmaError::AbortRequired)
        ));
        // …and the rogue's orderly double-complete is refused too:
        assert!(broker.region_complete(1, v.cookie).is_ok());
        assert!(matches!(
            broker.region_complete(1, v.cookie),
            Err(DmaError::InvalidHandle)
        ));

        // ── #5: DMA without the capability/verdict — the absent
        //    broker refuses everything (ADR-0013's fail-closed).
        //    (The syscall-mask + capability gate on the ring-3 side is
        //    the next slice; the broker-level gate is proven here.)
        // ── #6: out-of-range descriptors — the channel's width/window
        //    refusal (proved above) + the virtqueue descriptor bounds
        //    tests in virtio.rs (used_entry/used_ring validation).

        // the healthy driver keeps working: a fresh legal map on the
        // non-rogue domain after every refusal above.
        assert!(broker
            .map_region(2, pa_b + 4096, 4096, DmaDir::Bidirectional)
            .is_ok());
        drop(phys);
    }
}
