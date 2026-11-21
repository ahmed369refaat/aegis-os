//! The shared hostile-device test harness (review round 5, Phase B).
//!
//! One deterministic, seeded place for the fake pieces every driver's
//! host tests need: a scriptable `MmioBus` whose registers can lie
//! (garbage, flips, refusals), a fake `DmaProt` with a region budget,
//! and the host-"physical"-memory pattern (a `Vec` whose address plays
//! a PA, so the pool/scrub/frame paths run the identical kernel code).
//! Everything here is `cfg(test)` — it never ships in the image.

#![cfg(test)]

use crate::mmio::{MmioBus, MmioWindow};
use core::cell::{Cell, RefCell};

/// Host "physical" memory: a real buffer whose (aligned) address
/// plays the physical address, so reads/writes at PA offsets execute
/// the identical code paths. Returned by value so it outlives the
/// pool it backs.
pub(crate) struct FakePhys {
    pub mem: Vec<u64>,
    pub base: u64,
}

impl FakePhys {
    /// `frames` 4-KiB frames, 16-byte-aligned base (the scan/pool
    /// math stays honest).
    pub(crate) fn new(frames: usize) -> Self {
        let mem = vec![0u64; frames * 512 + 512];
        let base = (mem.as_ptr() as u64 + 4095) & !4095u64;
        FakePhys { mem, base }
    }

    pub(crate) fn pa(&self, off: u64) -> u64 {
        self.base + off
    }
}

/// A register script for one offset: what the fake returns (and
/// whether it flips between reads, refuses, or storms garbage).
#[derive(Clone)]
pub(crate) enum RegScript {
    /// Always this value.
    Constant(u32),
    /// Cycle through these values per read (a lying device).
    Sequence(Vec<u32>),
    /// Every read returns a fresh pseudo-random u32 (garbage mode,
    /// deterministic per (offset, read-index) seed).
    Garbage(u64),
}

/// The fake device: a window over a scriptable register bank. Reads
/// consult the script (default 0); writes record themselves so tests
/// assert exactly what the driver sent.
pub(crate) struct FakeBus {
    win: MmioWindow,
    reads: Cell<u32>,
    writes: Cell<u32>,
    script: std::collections::BTreeMap<u64, RegScript>,
    pub(crate) write_log: RefCell<std::collections::BTreeMap<u64, u32>>,
}

impl FakeBus {
    pub(crate) fn new(base: u64, len: u64) -> Self {
        FakeBus {
            win: MmioWindow::new(base, len).expect("test window"),
            reads: Cell::new(0),
            writes: Cell::new(0),
            script: std::collections::BTreeMap::new(),
            write_log: RefCell::new(std::collections::BTreeMap::new()),
        }
    }

    /// Script one register offset.
    pub(crate) fn set(&mut self, off: u64, s: RegScript) {
        self.script.insert(off, s);
    }

    pub(crate) fn reads(&self) -> u32 {
        self.reads.get()
    }
    pub(crate) fn writes(&self) -> u32 {
        self.writes.get()
    }

    fn script_read(&self, off: u64, idx: u32) -> u32 {
        match self.script.get(&off) {
            None => 0,
            Some(RegScript::Constant(v)) => *v,
            Some(RegScript::Garbage(seed)) => {
                // xorshift over (seed, offset, read index): deterministic
                // garbage — the same every run, hostile every time.
                let mut x = *seed ^ (off << 8) ^ u64::from(idx);
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // finalizer: xorshift's three shifts do not propagate
                // low-bit differences into the high half (measured by
                // the harness self-test) — fold the halves.
                ((x >> 32) ^ x) as u32
            }
            Some(RegScript::Sequence(vs)) => vs[(idx as usize) % vs.len()],
        }
    }
}

impl MmioBus for FakeBus {
    fn window(&self) -> MmioWindow {
        self.win
    }
    fn volatile_read32(&self, pa: u64) -> u32 {
        let idx = self.reads.get();
        self.reads.set(idx + 1);
        let off = pa - self.win.base();
        self.script_read(off, idx)
    }
    fn volatile_write32(&self, pa: u64, v: u32) {
        self.writes.set(self.writes.get() + 1);
        let off = pa - self.win.base();
        self.write_log.borrow_mut().insert(off, v);
    }
    fn volatile_read64(&self, pa: u64) -> u64 {
        let lo = self.volatile_read32(pa);
        let hi = self.volatile_read32(pa + 4);
        (u64::from(hi) << 32) | u64::from(lo)
    }
    fn volatile_write64(&self, pa: u64, v: u64) {
        self.volatile_write32(pa, v as u32);
        self.volatile_write32(pa + 4, (v >> 32) as u32);
    }
    fn volatile_read16(&self, pa: u64) -> u16 {
        self.volatile_read32(pa) as u16
    }
}

/// The minimal honest DmaProt: a set of live runs with a region
/// budget, so the refusal path (and the teardown discipline) run for
/// real. Shared shape with the session tests' fake.
pub(crate) struct FakeProt {
    pub(crate) live: Vec<(u64, u64)>,
    pub(crate) budget: usize,
}

impl aegis_os::dma::DmaProt for FakeProt {
    fn verdict(&self) -> aegis_os::dma::DmaVerdict {
        aegis_os::dma::DmaVerdict::Available {
            haw_bits: 48,
            queued_invalidation: true,
        }
    }
    fn assign_device(
        &mut self,
        _dom: u32,
        _segment: u16,
        _bus: u8,
        _devfn: (u8, u8),
    ) -> Result<(), aegis_os::dma::DmaError> {
        Ok(())
    }
    fn map_run(
        &mut self,
        _dom: u32,
        base: u64,
        len: u64,
        _dir: aegis_os::dma::DmaDir,
    ) -> Result<(), aegis_os::dma::DmaError> {
        if self.live.len() >= self.budget {
            return Err(aegis_os::dma::DmaError::Hardware(2));
        }
        self.live.push((base, len));
        Ok(())
    }
    fn unmap_run(&mut self, _dom: u32, base: u64, len: u64) -> Result<(), aegis_os::dma::DmaError> {
        self.live.retain(|&(b, l)| !(b == base && l == len));
        Ok(())
    }
}

/// A deterministic xorshift (the repo's fuzz pattern).
pub(crate) struct XorShift(pub(crate) u64);
impl XorShift {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}
