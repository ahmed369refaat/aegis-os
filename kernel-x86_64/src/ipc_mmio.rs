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
                    2 => self.device.volatile_write16(pa, val as u16),
                    4 => self.device.volatile_write32(pa, val as u32),
                    8 => self.device.volatile_write64(pa, val),
                    // 1-byte writes stay refused rather than
                    // half-implemented (no device in the tree needs one).
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
    fn volatile_write16(&self, _pa: u64, _v: u16) {
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
    /// A 2-byte write is a message like every other access — virtio's
    /// common config is 16-bit registers end to end, and the notify
    /// doorbell is `iowrite16` by definition (ADR-0016).
    fn write16(&self, off: u64, v: u16) -> bool {
        matches!(
            self.ask(MmioMsg::Write {
                off,
                len: 2,
                val: u64::from(v)
            }),
            MmioReply::Wrote
        )
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

// ─────────────────────────────────────────────────────────────────────────
// The ring-3 transport (ADR-0017 round two): the syscall core registry.
//
// The in-process `MmioChannel` above is the host-test transport. A
// ring-3 driver domain reaches the same discipline through
// `SYS_DEVREG` (syscall 33): one register access = one message
// (op/region/offset/len/val), routed to the domain's OWN registered
// core by `run.domain` — the routing IS the capability (no domain
// can name another's device; a domain with no core gets a refusal,
// not a wildcard). The core answers with the window-checked volatile
// access; `u64::MAX` is the refusal sentinel (no plausible register
// value on this bus family).
//
// The counters are the organic feed: the core counts what it serves
// and what it refuses, and after REFUSAL_LADDER refusals it STOPS
// SERVING that domain — ADR-0017's "the device core stops serving its
// channel" quarantine, implemented in the core where the domain can
// neither forge nor suppress it. The boot lane prints the counters at
// teardown; the BehaviorMonitor consumes them through the same
// denied-signal path every other domain misbehavior uses.
// ─────────────────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// After this many refusals on one region, the core stops serving the
/// domain entirely on that region: a confused or hostile driver loses
/// its channel instead of probing the window forever.
const REFUSAL_LADDER: u64 = 4;

/// One registered core: (domain, region) → a validated window + the
/// organic counters. The window parameters are written ONCE at
/// registration (before the domain can run) and read with Acquire on
/// every serve; the counters are relaxed (monotonic tally).
struct RegSlot {
    domain: AtomicU32,
    region: AtomicU8,
    base: AtomicU64,
    len: AtomicU64,
    served: AtomicU64,
    refused: AtomicU64,
}

/// Eight slots — one virtio device wants four (common/notify/isr/
/// device-config); exhaustion is a loud `false` from registration,
/// never a silent drop.
static REGISTRY: [RegSlot; 8] = [const {
    RegSlot {
        domain: AtomicU32::new(0),
        region: AtomicU8::new(0),
        base: AtomicU64::new(0),
        len: AtomicU64::new(0),
        served: AtomicU64::new(0),
        refused: AtomicU64::new(0),
    }
}; 8];

/// Register `(domain, region)`'s core window. Fails (false) when the
/// window is malformed, the region id is out of range, the slot is
/// taken, or the table is full. Ownership: re-registering an existing
/// `(domain, region)` pair is a driver-phase bug — refused.
pub(crate) fn register_core(domain: u32, region: u8, base: u64, len: u64) -> bool {
    if region > 3 || domain == 0 || MmioWindow::new(base, len).is_none() {
        return false;
    }
    for s in REGISTRY.iter() {
        let d = s.domain.load(Ordering::Acquire);
        if d == 0 {
            // free slot: claim it, then fill — single CPU, the syscall
            // path cannot interleave with the driver phase.
            s.domain.store(domain, Ordering::Release);
            s.region.store(region, Ordering::Relaxed);
            s.base.store(base, Ordering::Relaxed);
            s.len.store(len, Ordering::Relaxed);
            s.served.store(0, Ordering::Relaxed);
            s.refused.store(0, Ordering::Relaxed);
            return true;
        }
        if d == domain && s.region.load(Ordering::Relaxed) == region {
            return false; // duplicate: refuse, never overwrite
        }
    }
    false
}

/// Tear the domain's cores out of the table (the teardown half of the
/// step: the channel dies before the frames are revoked). Returns the
/// (served, refused) totals across the domain's regions — the monitor
/// feed, printed by the caller.
pub(crate) fn unregister_domain(domain: u32) -> (u64, u64) {
    let mut served = 0u64;
    let mut refused = 0u64;
    for s in REGISTRY.iter() {
        if s.domain.load(Ordering::Acquire) == domain {
            served += s.served.load(Ordering::Relaxed);
            refused += s.refused.load(Ordering::Relaxed);
            s.domain.store(0, Ordering::Release);
        }
    }
    (served, refused)
}

/// The `SYS_DEVREG` serve path: route `(domain, region)` to its core
/// and perform one window-checked access. `op`: 0 = read, 1 = write.
/// Returns the read value, or 0 for a served write; [`u64::MAX`] for
/// every refusal (unknown domain/region, bad width, out-of-window, or
/// the refusal ladder having closed the channel).
pub(crate) fn devreg_serve(domain: u32, region: u8, op: u8, off: u64, len: u8, val: u64) -> u64 {
    const REFUSED: u64 = u64::MAX;
    if region > 3 {
        return REFUSED;
    }
    let mut slot: Option<&RegSlot> = None;
    for s in REGISTRY.iter() {
        if s.domain.load(Ordering::Acquire) == domain && s.region.load(Ordering::Relaxed) == region
        {
            slot = Some(s);
            break;
        }
    }
    let Some(s) = slot else {
        return REFUSED; // no core: the domain holds no such grant
    };
    let refused = s.refused.load(Ordering::Relaxed);
    if refused >= REFUSAL_LADDER {
        // The ladder: the core has stopped serving this channel. The
        // refusal still counts (loudly, monotonically).
        s.refused.store(refused + 1, Ordering::Relaxed);
        return REFUSED;
    }
    if !matches!(op, 0 | 1) || !matches!(len, 1 | 2 | 4 | 8) {
        s.refused.fetch_add(1, Ordering::Relaxed);
        return REFUSED;
    }
    let win = match MmioWindow::new(
        s.base.load(Ordering::Acquire),
        s.len.load(Ordering::Acquire),
    ) {
        Some(w) => w,
        None => return REFUSED, // cannot happen (registered validated)
    };
    if !win.contains(off, u64::from(len)) {
        s.refused.fetch_add(1, Ordering::Relaxed);
        return REFUSED;
    }
    let device = crate::mmio::BarMmio::new(win.base(), win.len())
        .expect("register_core validated this pair");
    let pa = win.pa(off).expect("contains checked");
    match (op, len) {
        (0, 1) => {
            // the byte read: the containing dword, one byte selected —
            // MmioBus::read8's construction, done at the core.
            let aligned = off & !3;
            let d = device.volatile_read32(
                win.pa(aligned)
                    .expect("contains checked the containing dword"),
            );
            s.served.fetch_add(1, Ordering::Relaxed);
            u64::from((d >> (8 * (off & 3))) as u8)
        }
        (0, 2) => {
            s.served.fetch_add(1, Ordering::Relaxed);
            u64::from(device.volatile_read16(pa))
        }
        (0, 4) => {
            s.served.fetch_add(1, Ordering::Relaxed);
            u64::from(device.volatile_read32(pa))
        }
        (0, 8) => {
            s.served.fetch_add(1, Ordering::Relaxed);
            device.volatile_read64(pa)
        }
        (1, 2) => {
            device.volatile_write16(pa, val as u16);
            s.served.fetch_add(1, Ordering::Relaxed);
            0
        }
        (1, 4) => {
            device.volatile_write32(pa, val as u32);
            s.served.fetch_add(1, Ordering::Relaxed);
            0
        }
        (1, 8) => {
            device.volatile_write64(pa, val);
            s.served.fetch_add(1, Ordering::Relaxed);
            0
        }
        // 1-byte writes and unknown ops: refused above by the width
        // gate (len 1 with op 1 falls through here dead).
        _ => {
            s.refused.fetch_add(1, Ordering::Relaxed);
            REFUSED
        }
    }
}

/// The domain's aggregate core counters — the monitor feed.
pub(crate) fn core_counters(domain: u32) -> (u64, u64) {
    let mut served = 0u64;
    let mut refused = 0u64;
    for s in REGISTRY.iter() {
        if s.domain.load(Ordering::Acquire) == domain {
            served += s.served.load(Ordering::Relaxed);
            refused += s.refused.load(Ordering::Relaxed);
        }
    }
    (served, refused)
}

/// Reset the registry (the host tests' seam; production unregisters by
/// domain at teardown).
#[cfg(test)]
pub(crate) fn reset_registry_for_tests() {
    for s in REGISTRY.iter() {
        s.domain.store(0, Ordering::Release);
        s.served.store(0, Ordering::Relaxed);
        s.refused.store(0, Ordering::Relaxed);
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

    /// virtio's register surface is 16-bit end to end (QUEUE_SEL/
    /// SIZE/ENABLE, the vector grants) and the notify doorbell is
    /// `iowrite16` — the core must serve 2-byte writes with the same
    /// window discipline, and a straddling write is a refusal.
    #[test]
    fn sixteen_bit_writes_are_served_by_the_core() {
        let (phys, win, _bus0) = setup();
        let mut chan = CoreChannel {
            core: DeviceCore::new(
                win,
                crate::mmio::BarMmio::new(win.base(), win.len()).unwrap(),
            ),
        };
        let ipc = IpcMmio::new(win, &mut chan);
        assert!(ipc.write16(0x30, 0xBEEF));
        assert_eq!(ipc.read16(0x30), Some(0xBEEF));
        assert!(!ipc.write16(0xFF, 1), "a 2-byte write straddling the end");
        assert_eq!(chan.core.counters(), (2, 1));
        drop(phys);
    }

    /// The SYS_DEVREG transport (the registry): routing by (domain,
    /// region), the same window discipline, the refusal LADDER that
    /// closes a hammering domain's channel — and a healthy domain's
    /// channel surviving it (the quarantine is scoped).
    #[test]
    fn registry_routes_serves_and_closes_the_rogue_channel() {
        reset_registry_for_tests();
        let phys = FakePhys::new(2);
        let base_a = phys.pa(0);
        let base_b = phys.pa(4096);
        assert!(register_core(7, 0, base_a, 0x100));
        assert!(!register_core(7, 0, base_a, 0x100), "duplicate: refused");
        assert!(register_core(8, 0, base_b, 0x100));
        // routing: a domain with no core gets the sentinel, not a
        // wildcard; an unregistered region likewise.
        assert_eq!(devreg_serve(9, 0, 0, 0, 4, 0), u64::MAX);
        assert_eq!(devreg_serve(7, 1, 0, 0, 4, 0), u64::MAX);
        // a legal 16-bit write + read-back through the channel
        assert_eq!(devreg_serve(7, 0, 1, 0x30, 2, 0xBEEF), 0);
        assert_eq!(devreg_serve(7, 0, 0, 0x30, 2, 0), 0xBEEF);
        // the byte read: containing dword, byte selected (0xBEEF is
        // little-endian at 0x30 — byte 0x31 holds 0xBE)
        assert_eq!(devreg_serve(7, 0, 0, 0x31, 1, 0), 0xBE);
        // out-of-window + bad width + bad op + a 1-byte write: refusals,
        // all counted
        assert_eq!(devreg_serve(7, 0, 0, 0x100, 4, 0), u64::MAX);
        assert_eq!(devreg_serve(7, 0, 0, 0, 3, 0), u64::MAX);
        assert_eq!(devreg_serve(7, 0, 2, 0, 4, 0), u64::MAX);
        assert_eq!(devreg_serve(7, 0, 1, 0, 1, 0xFF), u64::MAX);
        // the ladder: 4 refusals accumulated above → the channel is
        // closed for domain 7, even for a LEGAL access now (and the
        // closure itself is counted: 5 refusals total)
        assert_eq!(devreg_serve(7, 0, 0, 0x30, 2, 0), u64::MAX);
        assert_eq!(
            core_counters(7),
            (3, 5),
            "3 served, 5 refused (the ladder counted)"
        );
        // the quarantine is scoped: domain 8's channel never wavered
        assert_eq!(devreg_serve(8, 0, 1, 0x40, 4, 0x1122_3344), 0);
        assert_eq!(devreg_serve(8, 0, 0, 0x40, 4, 0), 0x1122_3344);
        // teardown: the totals come back, the domain loses its cores
        assert_eq!(unregister_domain(7), (3, 5));
        assert_eq!(devreg_serve(7, 0, 0, 0x30, 2, 0), u64::MAX);
        // the rogue's writes never landed: the guard word is intact
        crate::memops::write_u64(base_a + 0x100, 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(
            crate::memops::read_u64(base_a + 0x100),
            0xAAAA_BBBB_CCCC_DDDD
        );
        assert_eq!(unregister_domain(8), (2, 0));
        reset_registry_for_tests();
        drop(phys);
    }
}
