//! DriverSession (ADR-0016, F10): one owner per driver run, one
//! `close()` per driver — the mid-flight refusal leak dies by
//! construction.
//!
//! Every resource a driver acquires — pool frames, broker regions —
//! is recorded in the session AS IT IS ACQUIRED. `close(out)` is the
//! explicit exit (markers byte-compatible with the lanes); `Drop` is
//! the silent safety net: a driver that returns early — for any
//! reason, including a refusal path written tomorrow — still gets
//! bus mastering cut, regions revoked (or poisoned + quarantined),
//! and frames home. There is no code path that allocates and does
//! not close.
//!
//! The identity control lanes (no IOMMU): `close` cuts bus mastering
//! FIRST there too (the old hand-rolled identity teardowns freed
//! frames while the device could still DMA them — a real window on
//! the no-IOMMU lane), then frees.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only users (the driver steps), so items only they use (the
// enforcement-probe helpers) look dead there — they are used by the
// boot build.
#![cfg_attr(test, allow(dead_code, unused_imports, unused_variables, unused_mut))]

use crate::frames::FramePool;
use crate::pci::PciDev;
use crate::strutil;
use crate::strutil::line;
use aegis_os::dma::DmaProt;

/// F2 (ADR-0015) teardown semantics, shared by every driver path:
/// revoke the domain, print the byte-compatible happy-path marker,
/// and on POISON fail closed — the device's bus mastering goes off,
/// frames inside poisoned ranges are quarantined (QUARANTINE_OWNER,
/// never freed while the device can still reach them) and only the
/// clean frames return to the pool. Every teardown and refusal path
/// goes through here, so no driver can hand a device-reachable page
/// back to the allocator.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, allow(unused_variables))]
pub(crate) fn revoke_or_quarantine<const N: usize, P: DmaProt>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<P>,
    owner: u32,
    dom: u32,
    frames: &[u64],
    dev: Option<&crate::pci::PciDev>,
    marker: &str,
) -> aegis_os::dma::RevokeOutcome {
    // F9b: bus mastering goes off FIRST — every teardown, refusal
    // and poison path arrives here, and none of them may leave a
    // device that can still issue DMA while its mappings dissolve.
    #[cfg(not(test))]
    if let Some(d) = dev {
        crate::pci::disable_bus_master(d);
    }
    let outcome = broker.revoke_all(dom);
    // ADR-0018: the teardown line reports the REAL counts — revoked,
    // freed, quarantined, poisoned — and never claims "scrubbed" for
    // frames that were quarantined instead of freed.
    let mut nr = [0u8; 20];
    let mut nf = [0u8; 20];
    let mut nq = [0u8; 20];
    let mut dom_b = [0u8; 20];

    let mut freed: u64 = 0;
    let mut quarantined: u64 = 0;
    if outcome.poisoned > 0 {
        for &pa in frames {
            let hit = broker
                .poisoned_regions()
                .any(|p| pa >= p.base && pa + 4096 <= p.base + p.len);
            if hit {
                quarantined += 1;
            } else {
                freed += 1;
            }
        }
    } else {
        freed = frames.len() as u64;
    }
    line(
        out,
        &[
            marker,
            " dom ",
            strutil::dec(u64::from(dom), &mut dom_b),
            " revoke_all: revoked ",
            strutil::dec(outcome.revoked as u64, &mut nr),
            ", freed ",
            strutil::dec(freed, &mut nf),
            if outcome.poisoned > 0 {
                ", quarantined "
            } else {
                ""
            },
            if outcome.poisoned > 0 {
                strutil::dec(quarantined, &mut nq)
            } else {
                ""
            },
            if outcome.poisoned > 0 {
                " — frames QUARANTINED, not freed (ADR-0015 F2)"
            } else {
                " (frames scrubbed home)"
            },
        ],
    );
    if outcome.poisoned > 0 {
        #[cfg(not(test))]
        if let Some(d) = dev {
            crate::pci::disable_bus_master(d);
        }
        let mut np = [0u8; 20];
        line(
            out,
            &[
                marker,
                " dom ",
                strutil::dec(u64::from(dom), &mut dom_b),
                " POISON: ",
                strutil::dec(outcome.poisoned as u64, &mut np),
                " region(s) still mapped in hardware — bus mastering off (ADR-0015 F2)",
            ],
        );
        for &pa in frames {
            let hit = broker
                .poisoned_regions()
                .any(|p| pa >= p.base && pa + 4096 <= p.base + p.len);
            if hit {
                let _ = pool.quarantine(pa, crate::frames::QUARANTINE_OWNER);
            } else {
                let _ = pool.free(&mut k.frames, pa, owner);
            }
        }
    } else {
        for &pa in frames {
            let _ = pool.free(&mut k.frames, pa, owner);
        }
    }
    outcome
}

/// The broker's own region budget is 16; no driver may hold more.
pub(crate) const MAX_SESSION_FRAMES: usize = 16;

/// ADR-0018: the kernel-side IOMMU domain-id allocator. Domain 0 is
/// the kernel's own (the ADR-0013 hardware proof, the broker demo) —
/// a device is NEVER assigned to it. Device domains are 1.. and are
/// handed out here, never chosen by a device or driver; exhaustion
/// is a typed `None` (the caller claims later or refuses the step).
pub(crate) struct DomainIds {
    used: [bool; crate::arch::vtd::MAX_VTD_DOMAINS],
}

impl DomainIds {
    /// Domain 0 pre-reserved for the kernel.
    pub(crate) fn new() -> Self {
        let mut used = [false; crate::arch::vtd::MAX_VTD_DOMAINS];
        used[0] = true;
        DomainIds { used }
    }

    /// Draw the next free domain id.
    pub(crate) fn alloc(&mut self) -> Option<u32> {
        for (i, u) in self.used.iter_mut().enumerate() {
            if !*u {
                *u = true;
                return Some(i as u32);
            }
        }
        None
    }

    /// Release a domain id. Double-release and out-of-range are
    /// refused (a released id is only reusable after the device's
    /// context entry was cleared — `Vtd::unassign_device`).
    pub(crate) fn release(&mut self, dom: u32) -> bool {
        match self.used.get_mut(dom as usize) {
            Some(true) if dom != 0 => {
                self.used[dom as usize] = false;
                true
            }
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self, dom: u32) -> bool {
        self.used.get(dom as usize).copied().unwrap_or(false)
    }
}

pub(crate) struct DriverSession<'a, const N: usize, P: DmaProt> {
    k: &'a mut aegis_os::Kernel<N>,
    pool: &'a mut FramePool<N>,
    broker: &'a mut aegis_os::dma::DmaBroker<P>,
    dev: Option<&'a PciDev>,
    owner: u32,
    /// ADR-0018: the device's own IOMMU domain — every broker call
    /// this session makes is scoped by it.
    dom: u32,
    identity: bool,
    /// The broker-path teardown marker, verbatim (lane-grepped).
    marker: &'static str,
    /// The identity-path teardown line, verbatim.
    identity_marker: &'static str,
    frames: [u64; MAX_SESSION_FRAMES],
    nframes: usize,
    closed: bool,
}

impl<'a, const N: usize, P: DmaProt> DriverSession<'a, N, P> {
    /// Both markers are passed verbatim so the lanes stay
    /// byte-identical; `identity` selects which one `close` prints.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        k: &'a mut aegis_os::Kernel<N>,
        pool: &'a mut FramePool<N>,
        broker: &'a mut aegis_os::dma::DmaBroker<P>,
        dev: Option<&'a PciDev>,
        owner: u32,
        dom: u32,
        identity: bool,
        marker: &'static str,
        identity_marker: &'static str,
    ) -> Self {
        DriverSession {
            k,
            pool,
            broker,
            dev,
            owner,
            dom,
            identity,
            marker,
            identity_marker,
            frames: [0; MAX_SESSION_FRAMES],
            nframes: 0,
            closed: false,
        }
    }

    /// Allocate one pool frame and record it. `None` = the pool
    /// refused; everything acquired so far is still owned by the
    /// session (the caller returns; `Drop` closes).
    pub(crate) fn frame(&mut self) -> Option<u64> {
        if self.nframes == MAX_SESSION_FRAMES {
            return None;
        }
        let pa = self.pool.alloc_for(&mut self.k.frames, self.owner).ok()?;
        self.frames[self.nframes] = pa;
        self.nframes += 1;
        Some(pa)
    }

    /// Broker-map one acquired frame (Bidirectional, one page — every
    /// driver in the stack maps exactly this shape). `None` = the
    /// broker refused; prior mappings and frames stay owned.
    pub(crate) fn map(&mut self, pa: u64) -> Option<u64> {
        let view = self
            .broker
            .map_region(self.dom, pa, 4096, aegis_os::dma::DmaDir::Bidirectional)
            .ok()?;
        Some(view.cookie)
    }

    /// Complete an in-flight region (the AbortRequired handshake) and
    /// unmap it — vblk's enforcement proof unmapped the data page
    /// through exactly this sequence before asking the device to DMA
    /// at it again. Scoped to the session's own domain (ADR-0018).
    pub(crate) fn complete_unmap(&mut self, cookie: u64) -> Result<(), aegis_os::dma::DmaError> {
        self.broker.region_complete(self.dom, cookie)?;
        self.broker.unmap_region(self.dom, cookie)
    }

    /// Read-only access to the hardware translation state (the
    /// enforcement proofs read the SLPT and the fault-status register
    /// directly).
    pub(crate) fn with_prot<R>(&mut self, f: impl FnOnce(&P) -> R) -> R {
        f(self.broker.prot())
    }

    /// Return ONE frame home early (the enforcement probe returns the
    /// unmapped data page before the rest of the teardown). The
    /// session forgets it — `close` will not double-free it.
    pub(crate) fn hand_back(&mut self, pa: u64) {
        let _ = self.pool.free(&mut self.k.frames, pa, self.owner);
        if let Some(i) = self.frames[..self.nframes].iter().position(|&p| p == pa) {
            self.frames[i] = self.frames[self.nframes - 1];
            self.nframes -= 1;
        }
    }

    /// The ordered teardown, shared by `close` and `Drop`. `None` =
    /// the silent path (no markers, no `out` to print to).
    fn teardown(&mut self, out: Option<&mut dyn FnMut(&str)>) {
        if self.closed {
            return;
        }
        self.closed = true;
        if self.identity {
            // The device could DMA these frames a moment ago — cut
            // bus mastering BEFORE they go home (the old identity
            // teardowns freed first; on the no-IOMMU lane that is a
            // real device-reach window).
            #[cfg(not(test))]
            if let Some(d) = self.dev {
                crate::pci::disable_bus_master(d);
            }
            for &pa in self.frames[..self.nframes].iter() {
                let _ = self.pool.free(&mut self.k.frames, pa, self.owner);
            }
            return;
        }
        // Broker path: the F2/F9b discipline owns the order (BME off
        // first, revoke, poison → quarantine, frames home). On the
        // silent path the markers land in a sink.
        revoke_or_quarantine(
            self.k,
            self.pool,
            out.unwrap_or(&mut |_s: &str| {}),
            self.broker,
            self.owner,
            self.dom,
            &self.frames[..self.nframes],
            self.dev,
            self.marker,
        );
    }

    /// The ONE explicit exit. Prints the lane markers verbatim.
    pub(crate) fn close(&mut self, out: &mut dyn FnMut(&str)) {
        if self.identity {
            line(out, &[self.identity_marker]);
        }
        self.teardown(Some(out));
    }
}

impl<const N: usize, P: DmaProt> Drop for DriverSession<'_, N, P> {
    fn drop(&mut self) {
        // The safety net: no markers (there may be no `out` here),
        // but never a leaked frame, a live region, or a device with
        // bus mastering past its owner's lifetime.
        self.teardown(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_os::dma::{DmaDir, DmaError, DmaQuotas, DmaVerdict};

    /// Host "physical" memory (the frames.rs FakePhys pattern): a
    /// real buffer whose address plays the physical address, so the
    /// pool/scrub/frame paths execute the identical code. Returned
    /// from `world` so it outlives the pool it backs.
    struct FakePhys {
        mem: Vec<u64>,
        base: u64,
    }

    /// The minimal honest DmaProt: a set of live runs; `budget` caps
    /// how many may be live at once (driving the refusal path).
    struct FakeProt {
        live: Vec<(u64, u64)>,
        budget: usize,
    }
    impl DmaProt for FakeProt {
        fn verdict(&self) -> DmaVerdict {
            DmaVerdict::Available {
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
        ) -> Result<(), DmaError> {
            Ok(())
        }
        fn map_run(
            &mut self,
            _dom: u32,
            base: u64,
            len: u64,
            _dir: DmaDir,
        ) -> Result<(), DmaError> {
            if self.live.len() >= self.budget {
                return Err(DmaError::Hardware(7));
            }
            self.live.push((base, len));
            Ok(())
        }
        fn unmap_run(&mut self, _dom: u32, base: u64, len: u64) -> Result<(), DmaError> {
            self.live.retain(|&(b, l)| !(b == base && l == len));
            Ok(())
        }
    }

    const TEST_OWNER: u32 = 43; // VBLK_OWNER's slot; any owner tag works

    fn world(
        budget: usize,
    ) -> (
        FakePhys,
        aegis_os::Kernel<256>,
        FramePool<256>,
        aegis_os::dma::DmaBroker<FakeProt>,
    ) {
        let mem = vec![0u64; 4096 / 8 * 8 + 512];
        let base = (mem.as_ptr() as u64 + 4095) & !4095u64;
        let phys = FakePhys { mem, base };
        let pool = FramePool::<256>::new(phys.base, crate::memops::scrub_frame);
        let broker = aegis_os::dma::DmaBroker::new(
            FakeProt {
                live: Vec::new(),
                budget,
            },
            DmaQuotas {
                max_regions: budget,
                max_bytes: 64 * 1024,
            },
        );
        (
            phys,
            aegis_os::Kernel::<256>::new_over_arena(),
            pool,
            broker,
        )
    }

    /// F10's headline test: a mid-flight broker refusal strands
    /// NOTHING — the frames allocated so far all go home on return.
    #[test]
    fn no_frame_stranded_on_early_refusal() {
        let (phys, mut k, mut pool, mut broker) = world(2);
        let mut session = DriverSession::new(
            &mut k,
            &mut pool,
            &mut broker,
            None,
            TEST_OWNER,
            1,
            false,
            "[T] teardown",
            "",
        );
        let mut got = [0u64; 3];
        for slot in got.iter_mut() {
            *slot = session.frame().expect("pool has frames");
        }
        assert!(session.map(got[0]).is_some());
        assert!(session.map(got[1]).is_some());
        // The third map exceeds the region budget: the exact point
        // the old drivers leaked frames 0..2 + two live regions.
        assert!(session.map(got[2]).is_none());
        drop(session); // the early return's safety net
        assert_eq!(k.frames.frames_in_use(), 0, "no frame stranded");
        assert_eq!(pool.owned_by(TEST_OWNER), 0);
        assert!(pool.is_clear());
        assert_eq!(broker.live_regions(0), 0, "no region left mapped");
        drop(phys);
    }

    /// The explicit close: broker path, markers verbatim, everything
    /// home.
    #[test]
    fn close_frees_and_revokes_everything() {
        let (phys, mut k, mut pool, mut broker) = world(8);
        let mut sink: Vec<String> = Vec::new();
        {
            let mut session = DriverSession::new(
                &mut k,
                &mut pool,
                &mut broker,
                None,
                TEST_OWNER,
                1,
                false,
                "[T] teardown",
                "",
            );
            let a = session.frame().expect("frame");
            let b = session.frame().expect("frame");
            assert!(session.map(a).is_some());
            assert!(session.map(b).is_some());
            session.close(&mut |s: &str| sink.push(String::from(s)));
        }
        assert_eq!(k.frames.frames_in_use(), 0);
        assert!(pool.is_clear());
        assert_eq!(broker.live_regions(0), 0);
        let joined = sink.concat();
        assert!(
            joined.contains(
                "[T] teardown dom 1 revoke_all: revoked 2, freed 2 (frames scrubbed home)"
            ),
            "the lane marker must be verbatim, got: {joined}"
        );
        drop(phys);
    }

    /// A driver that simply forgets: Drop alone still frees.
    #[test]
    fn drop_alone_is_the_safety_net() {
        let (phys, mut k, mut pool, mut broker) = world(4);
        {
            let mut session = DriverSession::new(
                &mut k,
                &mut pool,
                &mut broker,
                None,
                TEST_OWNER,
                1,
                false,
                "[T] teardown",
                "",
            );
            for _ in 0..4 {
                let pa = session.frame().expect("frame");
                assert!(session.map(pa).is_some());
            }
            // no close — just let it drop
        }
        assert_eq!(k.frames.frames_in_use(), 0);
        assert!(pool.is_clear());
        drop(phys);
    }

    /// The identity lane: close frees + prints the identity marker,
    /// and never touches the broker.
    #[test]
    fn identity_close_prints_and_frees() {
        let (phys, mut k, mut pool, mut broker) = world(4);
        let mut sink: Vec<String> = Vec::new();
        {
            let mut session = DriverSession::new(
                &mut k,
                &mut pool,
                &mut broker,
                None,
                TEST_OWNER,
                1,
                true,
                "[T] teardown",
                "[T] teardown (identity): frames freed, no broker regions",
            );
            let _ = session.frame().expect("frame");
            session.close(&mut |s: &str| sink.push(String::from(s)));
        }
        assert_eq!(k.frames.frames_in_use(), 0);
        let joined = sink.concat();
        assert!(joined.contains("teardown (identity): frames freed"));
        drop(phys);
    }

    // ── ADR-0018: the kernel-side domain-id allocator ──

    #[test]
    fn domain_ids_reserve_kernel_domain_and_exhaust() {
        let mut d = DomainIds::new();
        assert!(d.in_use(0), "domain 0 is the kernel's own, pre-reserved");
        // 7 device domains left (MAX_VTD_DOMAINS = 8).
        let mut drawn = Vec::new();
        while let Some(dom) = d.alloc() {
            assert!(dom >= 1, "a device is never assigned domain 0");
            drawn.push(dom);
        }
        assert_eq!(drawn.len(), crate::arch::vtd::MAX_VTD_DOMAINS - 1);
        assert_eq!(d.alloc(), None, "exhaustion is a typed None");
        // release + redraw works; double-release refused; 0 never allocatable.
        assert!(d.release(drawn[0]));
        assert!(!d.release(drawn[0]), "double release refused");
        assert!(!d.release(0), "the kernel domain is never releasable");
        assert!(!d.release(99), "out of range refused");
        assert_eq!(d.alloc(), Some(drawn[0]));
    }
}
