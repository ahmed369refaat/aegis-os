//! DMA protection policy — ADR-0013 D1/D6, driver stack PR 0.2.
//!
//! The `DmaProt` trait is the ADR-0011 D2 row: the contract the VT-d
//! implementation (`kernel-x86_64/src/arch/vtd.rs`, PR 0.4) must
//! satisfy, on the same `memops`/pure-encoding discipline as
//! `arch/lapic.rs`. `DmaBroker` is the pure bookkeeping half of the
//! kernel broker: region cookies, quotas, and the map/unmap state
//! machine on top of any `DmaProt`.
//!
//! Invariants, all test-proven:
//! - **Fail closed on absent hardware**: a `DmaProt` reporting
//!   `Absent` refuses every map/assign — no region is ever created
//!   against hardware that is not there (the `dma-drivers=0` verdict).
//! - **Driver domains never see addresses**: `RegionView` carries a
//!   cookie and a length only. The kernel materializes device-visible
//!   addresses when it validates and rewrites driver submissions
//!   (ADR-0013 D4/D6; the descriptor-snapshot rule is the Phase-2
//!   driver-protocol enforcement).
//! - **Abort before unmap**: a region with in-flight device work
//!   refuses `DMA_UNMAP` with `AbortRequired` until the driver
//!   completes its abort handshake (`region_complete`). Teardown
//!   (`revoke_all`) is the only path that skips the handshake — the
//!   domain is dying and the frames are being reclaimed.
//! - **Cookies are never reused**: monotonic, like endpoint ids
//!   (ADR-0004) — a stale cookie can never reach a reincarnated
//!   region (no ABA), even after slot reuse.
//! - **Every length is checked**: page-multiple lengths, page-aligned
//!   bases, and `base + len` within the host address width with
//!   checked arithmetic — wrap-around grants are impossible.
//! - **Quotas are enforced, exhaustion is surfaced**: per-domain
//!   region count and byte budget refuse loudly (`QuotaRegions` /
//!   `QuotaBytes`), never silently.
//! - **The wire format is fixed and fuzzed**: 64-byte messages per
//!   ADR-0004 §1; random bytes decode to a typed error or a valid
//!   message, never a panic; every decode/encode pair round-trips.

use crate::memory::PAGE_SIZE;

/// DMA page granularity (matches the frame pool's `PAGE_SIZE`).
const DMA_PAGE: u64 = PAGE_SIZE as u64;

/// Broker-wide region slots (fixed array, fail-loud exhaustion).
pub const MAX_DMA_REGIONS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaVerdict {
    /// The protection service is unusable: no DMA-capable device may
    /// be claimed. Carries the machine-readable reason for the boot
    /// marker and the claim path's refusal.
    Absent { reason: DmaAbsentReason },
    /// Hardware is programmed and serving. `haw_bits` is the host
    /// address width every map is bounds-checked against;
    /// `queued_invalidation` is the ECAP.QI capability bit (required
    /// by ADR-0013 D3 — recorded for the bring-up marker).
    Available {
        haw_bits: u8,
        queued_invalidation: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaAbsentReason {
    /// No DMAR table in the firmware (q35 without `-device
    /// intel-iommu` — measured).
    NoDmar,
    /// DMAR present but malformed: parsing failed (typed
    /// `DmarError` details live in the kernel log).
    MalformedDmar,
    /// Bring-up failed (bad VER, unsupported paging levels, spin
    /// budget exhausted).
    BringUpFailed,
}

/// Direction of a mapped region (second-level-table permissions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDir {
    ToDevice,
    FromDevice,
    Bidirectional,
}

impl DmaDir {
    fn code(self) -> u8 {
        match self {
            DmaDir::ToDevice => 1,
            DmaDir::FromDevice => 2,
            DmaDir::Bidirectional => 3,
        }
    }
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(DmaDir::ToDevice),
            2 => Some(DmaDir::FromDevice),
            3 => Some(DmaDir::Bidirectional),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// The service is absent: fail closed (ADR-0013 D2).
    Absent,
    /// Unknown, unmapped, or stale cookie (fail closed; ids are never
    /// reused, so this is also the double-complete/double-unmap
    /// answer).
    InvalidHandle,
    /// Region has in-flight device work: the abort handshake must
    /// complete before unmap.
    AbortRequired,
    /// Zero or non-page-multiple length.
    BadLength(u64),
    /// Base not page-aligned.
    NotAligned(u64),
    /// `base + len` beyond the host address width (checked, never
    /// wrapped).
    Overflow,
    /// Per-domain region-count quota exhausted.
    QuotaRegions,
    /// Per-domain byte budget exhausted.
    QuotaBytes,
    /// Broker region table exhausted.
    TableFull,
    /// The arch implementation refused (its own typed error surfaced
    /// by the kernel glue; opaque code here).
    Hardware(u8),
    /// Wire decode: unknown message tag.
    BadTag(u8),
}

/// The protection contract the VT-d layer implements (ADR-0011 D2).
/// Pure policy in this crate; the kernel-side implementation programs
/// real hardware. All methods run in the caller's context — Phase 0
/// is single-threaded boot context (see docs/arch/iommu.md).
pub trait DmaProt {
    /// Current verdict. Polled by the broker before every grant: a
    /// verdict that turned `Absent` after bring-up fails every
    /// subsequent map closed.
    fn verdict(&self) -> DmaVerdict;

    /// Bind (segment, bus, devfn) to `dom`'s translation tables.
    /// Double-assigning a device to a different domain is the arch
    /// layer's error to refuse (a device lives in exactly one domain).
    fn assign_device(
        &mut self,
        dom: u32,
        segment: u16,
        bus: u8,
        devfn: (u8, u8),
    ) -> Result<(), DmaError>;

    /// Map the contiguous run `[base, base+len)` into `dom`'s
    /// second-level tables (identity IOVA, ADR-0013 D4). Called only
    /// with broker-validated page-aligned, in-bounds runs.
    fn map_run(&mut self, dom: u32, base: u64, len: u64, dir: DmaDir) -> Result<(), DmaError>;

    /// Unmap the run and invalidate; returns only after the hardware
    /// is quiesced (bounded waits are the implementation's contract,
    /// ADR-0013 D4/D5). Frames return to the pool through
    /// scrub-on-free on the kernel side.
    fn unmap_run(&mut self, dom: u32, base: u64, len: u64) -> Result<(), DmaError>;
}

/// Per-domain quotas (construction parameters, not secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaQuotas {
    /// Max simultaneously live regions per domain.
    pub max_regions: usize,
    /// Max total mapped bytes per domain.
    pub max_bytes: u64,
}

impl Default for DmaQuotas {
    fn default() -> Self {
        DmaQuotas {
            max_regions: 8,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

/// One live region. Copy by design: bookkeeping only — the hardware
/// mapping lives in the `DmaProt` implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    cookie: u64,
    dom: u32,
    base: u64,
    len: u64,
    dir: DmaDir,
    /// Device work outstanding: unmap refuses until cleared by
    /// `region_complete` (the abort handshake, ADR-0013 D6).
    in_flight: bool,
}

/// What a driver domain receives for a mapped region: a cookie and a
/// length. **No addresses** — the kernel writes device-visible
/// addresses itself when validating submissions (ADR-0013 D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionView {
    pub cookie: u64,
    pub len: u64,
}

/// The kernel-side DMA broker: pure bookkeeping (cookies, quotas, the
/// abort-before-unmap ordering) over any `DmaProt`.
pub struct DmaBroker<P: DmaProt> {
    prot: P,
    slots: [Option<Region>; MAX_DMA_REGIONS],
    next_cookie: u64,
    quotas: DmaQuotas,
}

impl<P: DmaProt> DmaBroker<P> {
    pub fn new(prot: P, quotas: DmaQuotas) -> Self {
        DmaBroker {
            prot,
            slots: [None; MAX_DMA_REGIONS],
            next_cookie: 1,
            quotas,
        }
    }

    /// The underlying protection service (bring-up, fault polling).
    pub fn prot(&self) -> &P {
        &self.prot
    }

    pub fn prot_mut(&mut self) -> &mut P {
        &mut self.prot
    }

    #[must_use]
    pub fn verdict(&self) -> DmaVerdict {
        self.prot.verdict()
    }

    /// Bind a device to a domain's tables (supervisor/claim path).
    pub fn assign_device(
        &mut self,
        dom: u32,
        segment: u16,
        bus: u8,
        devfn: (u8, u8),
    ) -> Result<(), DmaError> {
        if matches!(self.prot.verdict(), DmaVerdict::Absent { .. }) {
            return Err(DmaError::Absent);
        }
        self.prot.assign_device(dom, segment, bus, devfn)
    }

    fn live_regions_of(&self, dom: u32) -> usize {
        self.slots.iter().flatten().filter(|r| r.dom == dom).count()
    }

    fn bytes_of(&self, dom: u32) -> u64 {
        self.slots
            .iter()
            .flatten()
            .filter(|r| r.dom == dom)
            .map(|r| r.len)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Grant `dom` the contiguous run `[base, base+len)`. The kernel
    /// allocates the frames (buddy pool, contiguous run, scrubbed) and
    /// passes them here; scatter-gather is descriptor-level work in
    /// the Phase-2 driver protocols. Returns the domain-facing view
    /// (cookie + length, nothing else).
    pub fn map_region(
        &mut self,
        dom: u32,
        base: u64,
        len: u64,
        dir: DmaDir,
    ) -> Result<RegionView, DmaError> {
        let haw_bits = match self.prot.verdict() {
            DmaVerdict::Available { haw_bits, .. } => haw_bits,
            DmaVerdict::Absent { .. } => return Err(DmaError::Absent),
        };
        if len == 0 || !len.is_multiple_of(DMA_PAGE) {
            return Err(DmaError::BadLength(len));
        }
        if !base.is_multiple_of(DMA_PAGE) {
            return Err(DmaError::NotAligned(base));
        }
        // The run must fit inside the host address width. u64 math
        // cannot express the last page of a 64-bit HAW (its exclusive
        // end is exactly 2^64), so the comparison happens in u128 —
        // both operands are < 2^64, the sum cannot wrap.
        let limit = if haw_bits >= 64 {
            1u128 << 64
        } else {
            1u128 << haw_bits
        };
        if base as u128 + len as u128 > limit {
            return Err(DmaError::Overflow);
        }
        if self.live_regions_of(dom) >= self.quotas.max_regions {
            return Err(DmaError::QuotaRegions);
        }
        if let Some(total) = self.bytes_of(dom).checked_add(len) {
            if total > self.quotas.max_bytes {
                return Err(DmaError::QuotaBytes);
            }
        } else {
            return Err(DmaError::Overflow);
        }
        let slot = self
            .slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(DmaError::TableFull)?;
        // Program the hardware FIRST: a refused map leaves no region.
        self.prot.map_run(dom, base, len, dir)?;
        let cookie = self.next_cookie;
        self.next_cookie = self.next_cookie.checked_add(1).ok_or(DmaError::TableFull)?;
        self.slots[slot] = Some(Region {
            cookie,
            dom,
            base,
            len,
            dir,
            in_flight: true,
        });
        Ok(RegionView { cookie, len })
    }

    /// The driver reports device work on the region complete (the
    /// abort handshake's final step). Double-complete is a stale
    /// handle: fail closed.
    pub fn region_complete(&mut self, cookie: u64) -> Result<(), DmaError> {
        let r = self
            .slots
            .iter_mut()
            .flatten()
            .find(|r| r.cookie == cookie)
            .ok_or(DmaError::InvalidHandle)?;
        if !r.in_flight {
            return Err(DmaError::InvalidHandle);
        }
        r.in_flight = false;
        Ok(())
    }

    /// Release a region: unmap + invalidate through the arch layer,
    /// then free the slot. Refuses while device work is in flight
    /// (`AbortRequired` — the driver must complete first, ADR-0013
    /// D6). The cookie dies forever.
    pub fn unmap_region(&mut self, cookie: u64) -> Result<(), DmaError> {
        let slot = self
            .slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|r| r.cookie == cookie))
            .ok_or(DmaError::InvalidHandle)?;
        let r = self.slots[slot].expect("checked above");
        if r.in_flight {
            return Err(DmaError::AbortRequired);
        }
        self.prot.unmap_run(r.dom, r.base, r.len)?;
        self.slots[slot] = None;
        Ok(())
    }

    /// Domain teardown / quarantine: unmap everything the domain
    /// holds, handshake or not — the domain is dying and its frames
    /// are being reclaimed (scrubbed by the pool on the kernel side).
    /// Returns how many regions were revoked.
    pub fn revoke_all(&mut self, dom: u32) -> usize {
        let mut revoked = 0;
        for slot in self.slots.iter_mut() {
            if let Some(r) = slot.take_if(|r| r.dom == dom) {
                let _ = self.prot.unmap_run(r.dom, r.base, r.len);
                revoked += 1;
            }
        }
        revoked
    }

    /// Live region count for a domain (telemetry + tests).
    #[must_use]
    pub fn live_regions(&self, dom: u32) -> usize {
        self.live_regions_of(dom)
    }

    /// Mapped byte total for a domain (telemetry + tests).
    #[must_use]
    pub fn bytes_used(&self, dom: u32) -> u64 {
        self.bytes_of(dom)
    }
}

// ── Wire format (ADR-0004 §1: fixed 64-byte envelopes) ──

/// Driver → broker requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaRequest {
    Map { len: u64, dir: DmaDir },
    Unmap { cookie: u64 },
    Complete { cookie: u64 },
}

/// Broker → driver replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaReply {
    Mapped { cookie: u64, len: u64 },
    Refused { reason: DmaRefusal },
    Unmapped,
    Completed,
}

/// Machine-readable refusal reasons (the wire face of `DmaError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaRefusal {
    Absent,
    BadLength,
    NotAligned,
    Overflow,
    QuotaRegions,
    QuotaBytes,
    TableFull,
    AbortRequired,
    InvalidCookie,
    Hardware,
}

impl From<DmaError> for DmaRefusal {
    fn from(e: DmaError) -> Self {
        match e {
            DmaError::Absent => DmaRefusal::Absent,
            DmaError::BadLength(_) => DmaRefusal::BadLength,
            DmaError::NotAligned(_) => DmaRefusal::NotAligned,
            DmaError::Overflow => DmaRefusal::Overflow,
            DmaError::QuotaRegions => DmaRefusal::QuotaRegions,
            DmaError::QuotaBytes => DmaRefusal::QuotaBytes,
            DmaError::TableFull => DmaRefusal::TableFull,
            DmaError::AbortRequired => DmaRefusal::AbortRequired,
            DmaError::InvalidHandle => DmaRefusal::InvalidCookie,
            DmaError::Hardware(_) => DmaRefusal::Hardware,
            DmaError::BadTag(_) => DmaRefusal::Hardware, // never sent; decode-side only
        }
    }
}

fn put_u64(buf: &mut [u8; 64], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u64(buf: &[u8; 64], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

impl DmaRequest {
    /// Encode into the fixed 64-byte envelope (tag + LE fields).
    pub fn encode(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        match *self {
            DmaRequest::Map { len, dir } => {
                buf[0] = 1;
                put_u64(&mut buf, 1, len);
                buf[9] = dir.code();
            }
            DmaRequest::Unmap { cookie } => {
                buf[0] = 2;
                put_u64(&mut buf, 1, cookie);
            }
            DmaRequest::Complete { cookie } => {
                buf[0] = 3;
                put_u64(&mut buf, 1, cookie);
            }
        }
        buf
    }

    pub fn decode(buf: &[u8; 64]) -> Result<Self, DmaError> {
        match buf[0] {
            1 => Ok(DmaRequest::Map {
                len: get_u64(buf, 1),
                dir: DmaDir::from_code(buf[9]).ok_or(DmaError::BadTag(buf[9]))?,
            }),
            2 => Ok(DmaRequest::Unmap {
                cookie: get_u64(buf, 1),
            }),
            3 => Ok(DmaRequest::Complete {
                cookie: get_u64(buf, 1),
            }),
            tag => Err(DmaError::BadTag(tag)),
        }
    }
}

impl DmaReply {
    /// Encode into the fixed 64-byte envelope.
    pub fn encode(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        match *self {
            DmaReply::Mapped { cookie, len } => {
                buf[0] = 1;
                put_u64(&mut buf, 1, cookie);
                put_u64(&mut buf, 9, len);
            }
            DmaReply::Refused { reason } => {
                buf[0] = 2;
                buf[1] = reason.code();
            }
            DmaReply::Unmapped => buf[0] = 3,
            DmaReply::Completed => buf[0] = 4,
        }
        buf
    }

    pub fn decode(buf: &[u8; 64]) -> Result<Self, DmaError> {
        match buf[0] {
            1 => Ok(DmaReply::Mapped {
                cookie: get_u64(buf, 1),
                len: get_u64(buf, 9),
            }),
            2 => Ok(DmaReply::Refused {
                reason: DmaRefusal::from_code(buf[1]).ok_or(DmaError::BadTag(buf[1]))?,
            }),
            3 => Ok(DmaReply::Unmapped),
            4 => Ok(DmaReply::Completed),
            tag => Err(DmaError::BadTag(tag)),
        }
    }
}

impl DmaRefusal {
    fn code(self) -> u8 {
        match self {
            DmaRefusal::Absent => 1,
            DmaRefusal::BadLength => 2,
            DmaRefusal::NotAligned => 3,
            DmaRefusal::Overflow => 4,
            DmaRefusal::QuotaRegions => 5,
            DmaRefusal::QuotaBytes => 6,
            DmaRefusal::TableFull => 7,
            DmaRefusal::AbortRequired => 8,
            DmaRefusal::InvalidCookie => 9,
            DmaRefusal::Hardware => 10,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(DmaRefusal::Absent),
            2 => Some(DmaRefusal::BadLength),
            3 => Some(DmaRefusal::NotAligned),
            4 => Some(DmaRefusal::Overflow),
            5 => Some(DmaRefusal::QuotaRegions),
            6 => Some(DmaRefusal::QuotaBytes),
            7 => Some(DmaRefusal::TableFull),
            8 => Some(DmaRefusal::AbortRequired),
            9 => Some(DmaRefusal::InvalidCookie),
            10 => Some(DmaRefusal::Hardware),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recording fake: verdict + ops log + injectable failures.
    #[derive(Clone)]
    struct FakeProt {
        haw_bits: u8,
        available: bool,
        ops: Vec<(&'static str, u32, u64, u64)>,
        /// Fail the Nth map call (0-based) with Hardware(7).
        fail_map_on: Option<usize>,
        map_calls: usize,
        /// Fail every unmap call with Hardware(9).
        fail_unmap: bool,
    }

    impl FakeProt {
        fn available(haw_bits: u8) -> Self {
            FakeProt {
                haw_bits,
                available: true,
                ops: vec![],
                fail_map_on: None,
                map_calls: 0,
                fail_unmap: false,
            }
        }
        fn absent() -> Self {
            FakeProt {
                available: false,
                ..FakeProt::available(48)
            }
        }
    }

    impl DmaProt for FakeProt {
        fn verdict(&self) -> DmaVerdict {
            if self.available {
                DmaVerdict::Available {
                    haw_bits: self.haw_bits,
                    queued_invalidation: true,
                }
            } else {
                DmaVerdict::Absent {
                    reason: DmaAbsentReason::NoDmar,
                }
            }
        }
        fn assign_device(
            &mut self,
            _dom: u32,
            _segment: u16,
            _bus: u8,
            _devfn: (u8, u8),
        ) -> Result<(), DmaError> {
            self.ops.push(("assign", _dom, _segment as u64, 0));
            Ok(())
        }
        fn map_run(&mut self, dom: u32, base: u64, len: u64, _dir: DmaDir) -> Result<(), DmaError> {
            let n = self.map_calls;
            self.map_calls += 1;
            self.ops.push(("map", dom, base, len));
            if self.fail_map_on == Some(n) {
                return Err(DmaError::Hardware(7));
            }
            Ok(())
        }
        fn unmap_run(&mut self, dom: u32, base: u64, len: u64) -> Result<(), DmaError> {
            self.ops.push(("unmap", dom, base, len));
            if self.fail_unmap {
                return Err(DmaError::Hardware(9));
            }
            Ok(())
        }
    }

    const K: u64 = DMA_PAGE;

    #[test]
    fn absent_verdict_fails_every_map_closed() {
        let mut b = DmaBroker::new(FakeProt::absent(), DmaQuotas::default());
        assert_eq!(
            b.verdict(),
            DmaVerdict::Absent {
                reason: DmaAbsentReason::NoDmar
            }
        );
        assert_eq!(
            b.map_region(1, 0x1000, K, DmaDir::Bidirectional),
            Err(DmaError::Absent)
        );
        assert!(b.assign_device(1, 0, 0, (0x1F, 2)).is_err());
        assert_eq!(b.live_regions(1), 0, "no region was created");
        assert!(b.prot().ops.is_empty(), "the hardware was never touched");
    }

    #[test]
    fn map_region_happy_path_and_view_has_no_addresses() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let view = b.map_region(1, 0x1000, 2 * K, DmaDir::FromDevice).unwrap();
        // The domain-facing view: cookie + length ONLY (ADR-0013 D4).
        assert_eq!(
            view,
            RegionView {
                cookie: 1,
                len: 2 * K
            }
        );
        assert_eq!(b.live_regions(1), 1);
        assert_eq!(b.bytes_used(1), 2 * K);
        assert_eq!(b.prot().ops, vec![("map", 1, 0x1000, 2 * K)]);
        // Quota accounting is per domain.
        let v2 = b.map_region(2, 0x9000, K, DmaDir::ToDevice).unwrap();
        assert_eq!(v2.cookie, 2, "cookies are sequential");
        assert_eq!(b.bytes_used(2), K);
    }

    #[test]
    fn map_validates_lengths_alignment_and_bounds() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        assert_eq!(
            b.map_region(1, 0x1000, 0, DmaDir::ToDevice),
            Err(DmaError::BadLength(0))
        );
        assert_eq!(
            b.map_region(1, 0x1000, K + 1, DmaDir::ToDevice),
            Err(DmaError::BadLength(K + 1))
        );
        assert_eq!(
            b.map_region(1, 0x1008, K, DmaDir::ToDevice),
            Err(DmaError::NotAligned(0x1008))
        );
        // 48-bit HAW: a run ending above 2^48 wraps into refusal.
        let top = 1u64 << 48;
        assert_eq!(
            b.map_region(1, top - K, 2 * K, DmaDir::ToDevice),
            Err(DmaError::Overflow)
        );
        // ...and one ending exactly at 2^48 is the last legal grant.
        assert!(b.map_region(1, top - K, K, DmaDir::ToDevice).is_ok());
        // 64-bit HAW: the bound is 2^64 itself, not a u64 overflow
        // panic. The last aligned page (base 0xFFFF..F000) ends at
        // exactly 2^64 and is legal; anything past it refuses.
        let mut b64 = DmaBroker::new(FakeProt::available(64), DmaQuotas::default());
        assert!(b64
            .map_region(1, u64::MAX - K + 1, K, DmaDir::ToDevice)
            .is_ok());
        assert_eq!(
            b64.map_region(1, u64::MAX - K + 1, 2 * K, DmaDir::ToDevice),
            Err(DmaError::Overflow)
        );
        // Nothing was mapped by any refused request.
        assert_eq!(b.prot().ops.len(), 1);
    }

    #[test]
    fn quotas_are_enforced_and_released() {
        let quotas = DmaQuotas {
            max_regions: 2,
            max_bytes: 4 * K,
        };
        let mut b = DmaBroker::new(FakeProt::available(48), quotas);
        b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        b.map_region(1, 0x9000, K, DmaDir::ToDevice).unwrap();
        assert_eq!(
            b.map_region(1, 0x11000, K, DmaDir::ToDevice),
            Err(DmaError::QuotaRegions)
        );
        // Another domain is unaffected: quotas are per domain.
        assert!(b.map_region(2, 0x1000, K, DmaDir::ToDevice).is_ok());
        // Byte budget: a 4-KiB domain cannot take a second page.
        let mut b2 = DmaBroker::new(
            FakeProt::available(48),
            DmaQuotas {
                max_regions: 8,
                max_bytes: K,
            },
        );
        b2.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        assert_eq!(
            b2.map_region(1, 0x9000, K, DmaDir::ToDevice),
            Err(DmaError::QuotaBytes)
        );
        // Release frees the budget: complete + unmap, then map again.
        b2.map_region(2, 0x9000, K, DmaDir::ToDevice).unwrap();
        let c = b2.map_region(1, 0x11000, K, DmaDir::ToDevice);
        assert!(c.is_err(), "dom 1's byte budget is still spent");
        let cookie = 1; // dom 1's first region
        b2.region_complete(cookie).unwrap();
        b2.unmap_region(cookie).unwrap();
        assert!(b2.map_region(1, 0x11000, K, DmaDir::ToDevice).is_ok());
    }

    #[test]
    fn abort_before_unmap_is_enforced() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let v = b.map_region(1, 0x1000, K, DmaDir::Bidirectional).unwrap();
        assert_eq!(b.unmap_region(v.cookie), Err(DmaError::AbortRequired));
        // The hardware mapping is untouched by the refusal.
        assert_eq!(b.prot().ops.len(), 1);
        b.region_complete(v.cookie).unwrap();
        // Double-complete fails closed.
        assert_eq!(b.region_complete(v.cookie), Err(DmaError::InvalidHandle));
        b.unmap_region(v.cookie).unwrap();
        assert_eq!(
            b.prot().ops,
            vec![("map", 1, 0x1000, K), ("unmap", 1, 0x1000, K)]
        );
        // Unmap AFTER unmap: stale cookie.
        assert_eq!(b.unmap_region(v.cookie), Err(DmaError::InvalidHandle));
    }

    #[test]
    fn cookies_are_never_reused_no_aba() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let a = b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        b.region_complete(a.cookie).unwrap();
        b.unmap_region(a.cookie).unwrap();
        let c = b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        assert_ne!(a.cookie, c.cookie, "slot reuse never revives a cookie");
        assert_eq!(b.region_complete(a.cookie), Err(DmaError::InvalidHandle));
        assert_eq!(b.unmap_region(a.cookie), Err(DmaError::InvalidHandle));
        // Complete on a stranger's cookie is refused.
        assert_eq!(b.region_complete(9999), Err(DmaError::InvalidHandle));
    }

    #[test]
    fn hardware_refusal_leaves_no_region() {
        let mut prot = FakeProt::available(48);
        prot.fail_map_on = Some(0);
        let mut b = DmaBroker::new(prot, DmaQuotas::default());
        assert_eq!(
            b.map_region(1, 0x1000, K, DmaDir::ToDevice),
            Err(DmaError::Hardware(7))
        );
        assert_eq!(b.live_regions(1), 0);
        assert_eq!(b.bytes_used(1), 0, "quota untouched by the refusal");
        // The next map is clean (the failure did not poison the broker).
        let mut b2 = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        b2.prot_mut().fail_map_on = Some(0);
        assert!(b2.map_region(1, 0x1000, K, DmaDir::ToDevice).is_err());
        b2.prot_mut().fail_map_on = None;
        assert!(b2.map_region(1, 0x1000, K, DmaDir::ToDevice).is_ok());
    }

    #[test]
    fn broker_table_exhaustion_is_surfaced() {
        let quotas = DmaQuotas {
            max_regions: MAX_DMA_REGIONS + 1,
            max_bytes: u64::MAX,
        };
        let mut b = DmaBroker::new(FakeProt::available(48), quotas);
        for i in 0..MAX_DMA_REGIONS as u64 {
            b.map_region(1, 0x1000 + i * K, K, DmaDir::ToDevice)
                .unwrap();
        }
        assert_eq!(
            b.map_region(1, 0x1000 + MAX_DMA_REGIONS as u64 * K, K, DmaDir::ToDevice),
            Err(DmaError::TableFull)
        );
        // Unmap one slot and the table serves again.
        b.region_complete(1).unwrap();
        b.unmap_region(1).unwrap();
        assert!(b.map_region(2, 0x1000, K, DmaDir::ToDevice).is_ok());
    }

    #[test]
    fn revoke_all_tears_down_only_that_domain() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let a = b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        let c = b.map_region(1, 0x9000, K, DmaDir::ToDevice).unwrap();
        let other = b.map_region(2, 0x11000, K, DmaDir::ToDevice).unwrap();
        // a is in flight; c is complete. Both must go: teardown skips
        // the handshake by design (the domain is dying).
        b.region_complete(c.cookie).unwrap();
        let n = b.revoke_all(1);
        assert_eq!(n, 2);
        assert_eq!(b.live_regions(1), 0);
        assert_eq!(b.live_regions(2), 1, "other domains untouched");
        assert_eq!(b.prot().ops.iter().filter(|o| o.0 == "unmap").count(), 2);
        // Revoke on a domain with nothing is a clean zero.
        assert_eq!(b.revoke_all(9), 0);
        // The survivor still completes and unmaps normally.
        b.region_complete(other.cookie).unwrap();
        b.unmap_region(other.cookie).unwrap();
        // And dom 1's cookies stayed monotonic across the teardown.
        assert!(a.cookie < c.cookie);
    }

    #[test]
    fn assign_device_delegates_with_verdict_gate() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        b.assign_device(1, 0, 0, (0x1F, 2)).unwrap();
        assert_eq!(b.prot().ops, vec![("assign", 1, 0, 0)]);
        let mut absent = DmaBroker::new(FakeProt::absent(), DmaQuotas::default());
        assert_eq!(
            absent.assign_device(1, 0, 0, (0x1F, 2)),
            Err(DmaError::Absent)
        );
    }

    #[test]
    fn request_and_reply_roundtrip_all_variants() {
        let requests = [
            DmaRequest::Map {
                len: 0,
                dir: DmaDir::ToDevice,
            },
            DmaRequest::Map {
                len: 4 * K,
                dir: DmaDir::FromDevice,
            },
            DmaRequest::Map {
                len: u64::MAX,
                dir: DmaDir::Bidirectional,
            },
            DmaRequest::Unmap { cookie: 1 },
            DmaRequest::Unmap { cookie: u64::MAX },
            DmaRequest::Complete { cookie: 42 },
        ];
        for r in &requests {
            assert_eq!(&DmaRequest::decode(&r.encode()).unwrap(), r);
        }
        let replies = [
            DmaReply::Mapped {
                cookie: 7,
                len: 3 * K,
            },
            DmaReply::Mapped {
                cookie: u64::MAX,
                len: 0,
            },
            DmaReply::Refused {
                reason: DmaRefusal::AbortRequired,
            },
            DmaReply::Refused {
                reason: DmaRefusal::Hardware,
            },
            DmaReply::Unmapped,
            DmaReply::Completed,
        ];
        for r in &replies {
            assert_eq!(&DmaReply::decode(&r.encode()).unwrap(), r);
        }
        // Every refusal code round-trips (the wire never invents one).
        for code in 1..=10u8 {
            let reason = DmaRefusal::from_code(code).unwrap();
            assert_eq!(
                DmaReply::decode(&DmaReply::Refused { reason }.encode()).unwrap(),
                DmaReply::Refused { reason }
            );
        }
    }

    #[test]
    fn decode_rejects_unknown_tags_and_bad_codes() {
        let mut buf = [0u8; 64];
        assert_eq!(DmaRequest::decode(&buf), Err(DmaError::BadTag(0)));
        assert_eq!(DmaReply::decode(&buf), Err(DmaError::BadTag(0)));
        buf[0] = 4;
        assert_eq!(DmaRequest::decode(&buf), Err(DmaError::BadTag(4)));
        buf[0] = 5;
        assert_eq!(DmaReply::decode(&buf), Err(DmaError::BadTag(5)));
        // Map with a direction code that does not exist.
        buf[0] = 1;
        buf[9] = 4;
        assert_eq!(DmaRequest::decode(&buf), Err(DmaError::BadTag(4)));
        // Refused with a reason code that does not exist.
        buf[0] = 2;
        buf[1] = 11;
        assert_eq!(DmaReply::decode(&buf), Err(DmaError::BadTag(11)));
    }

    #[test]
    fn fuzz_decode_random_bytes_never_panic() {
        // Seeded LCG: any 64 bytes decode to a message or a typed
        // error — and a decoding message re-encodes identically.
        let mut state = 0xAD_50_DE_AD_13u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        let mut oks = 0;
        for _ in 0..1024 {
            let mut buf = [0u8; 64];
            for b in buf.iter_mut() {
                *b = (next() & 0xFF) as u8;
            }
            if let Ok(req) = DmaRequest::decode(&buf) {
                oks += 1;
                assert_eq!(DmaRequest::decode(&req.encode()).unwrap(), req);
            }
            if let Ok(rep) = DmaReply::decode(&buf) {
                oks += 1;
                assert_eq!(DmaReply::decode(&rep.encode()).unwrap(), rep);
            }
        }
        // Random bytes overwhelmingly refuse; a few accidental hits
        // prove the decode/encode symmetry is exercised.
        assert!(
            oks < 64,
            "random 64-byte buffers rarely start with a valid tag ({oks})"
        );
    }

    #[test]
    fn error_to_refusal_mapping_is_total() {
        // Every DmaError has a wire refusal (Hardware carries no code
        // on the wire — the kernel log owns the detail).
        assert_eq!(DmaRefusal::from(DmaError::Absent), DmaRefusal::Absent);
        assert_eq!(
            DmaRefusal::from(DmaError::BadLength(9)),
            DmaRefusal::BadLength
        );
        assert_eq!(
            DmaRefusal::from(DmaError::NotAligned(4)),
            DmaRefusal::NotAligned
        );
        assert_eq!(DmaRefusal::from(DmaError::Overflow), DmaRefusal::Overflow);
        assert_eq!(
            DmaRefusal::from(DmaError::QuotaRegions),
            DmaRefusal::QuotaRegions
        );
        assert_eq!(
            DmaRefusal::from(DmaError::QuotaBytes),
            DmaRefusal::QuotaBytes
        );
        assert_eq!(DmaRefusal::from(DmaError::TableFull), DmaRefusal::TableFull);
        assert_eq!(
            DmaRefusal::from(DmaError::AbortRequired),
            DmaRefusal::AbortRequired
        );
        assert_eq!(
            DmaRefusal::from(DmaError::InvalidHandle),
            DmaRefusal::InvalidCookie
        );
        assert_eq!(
            DmaRefusal::from(DmaError::Hardware(7)),
            DmaRefusal::Hardware
        );
    }

    #[test]
    fn verdict_delegates_and_carries_the_absent_reason() {
        // MalformedDmar is a distinct, machine-readable verdict: the
        // claim path and the boot marker can tell "no IOMMU" from
        // "broken tables".
        let mut prot = FakeProt::absent();
        let b = DmaBroker::new(prot.clone(), DmaQuotas::default());
        assert_eq!(
            b.verdict(),
            DmaVerdict::Absent {
                reason: DmaAbsentReason::NoDmar
            }
        );
        prot.available = true;
        prot.haw_bits = 39;
        let b = DmaBroker::new(prot, DmaQuotas::default());
        assert_eq!(
            b.verdict(),
            DmaVerdict::Available {
                haw_bits: 39,
                queued_invalidation: true
            }
        );
    }

    #[test]
    fn multi_region_accounting_sums_per_domain() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        b.map_region(1, 0x9000, 2 * K, DmaDir::FromDevice).unwrap();
        b.map_region(2, 0x11000, 4 * K, DmaDir::Bidirectional)
            .unwrap();
        assert_eq!(b.live_regions(1), 2);
        assert_eq!(b.bytes_used(1), 3 * K);
        assert_eq!(b.live_regions(2), 1);
        assert_eq!(b.bytes_used(2), 4 * K);
        assert_eq!(b.live_regions(3), 0, "strangers hold nothing");
    }

    #[test]
    fn slot_reuse_across_domains_keeps_cookies_monotonic() {
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let a = b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        b.region_complete(a.cookie).unwrap();
        b.unmap_region(a.cookie).unwrap();
        // The freed slot serves ANOTHER domain, with a fresh cookie.
        let c = b.map_region(2, 0x9000, K, DmaDir::ToDevice).unwrap();
        assert_ne!(a.cookie, c.cookie);
        assert_eq!(b.unmap_region(a.cookie), Err(DmaError::InvalidHandle));
        // And dom 2's region is completable by its own cookie.
        b.region_complete(c.cookie).unwrap();
        b.unmap_region(c.cookie).unwrap();
    }

    #[test]
    fn revoke_all_restores_quotas_for_remap() {
        let quotas = DmaQuotas {
            max_regions: 1,
            max_bytes: K,
        };
        let mut b = DmaBroker::new(FakeProt::available(48), quotas);
        b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        assert_eq!(
            b.map_region(1, 0x9000, K, DmaDir::ToDevice),
            Err(DmaError::QuotaRegions)
        );
        assert_eq!(b.revoke_all(1), 1);
        assert_eq!(
            b.map_region(1, 0x9000, K, DmaDir::ToDevice),
            Ok(RegionView { cookie: 2, len: K })
        );
    }

    #[test]
    fn hardware_unmap_failure_keeps_the_region() {
        // Fail-closed teardown: if the arch layer cannot unmap, the
        // region stays live (its mapping may still exist in hardware)
        // and the error propagates; a retry after the failure clears
        // completes the release.
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let v = b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        b.region_complete(v.cookie).unwrap();
        b.prot_mut().fail_unmap = true;
        assert_eq!(b.unmap_region(v.cookie), Err(DmaError::Hardware(9)));
        assert_eq!(b.live_regions(1), 1, "the region survives a failed unmap");
        b.prot_mut().fail_unmap = false;
        b.unmap_region(v.cookie).unwrap();
        assert_eq!(b.live_regions(1), 0);
    }

    #[test]
    fn verdict_turning_absent_blocks_new_maps_but_not_teardown() {
        // Hardware dying mid-flight: new grants fail closed, but the
        // teardown path (complete/unmap/revoke) still runs — the
        // frames must be reclaimable even on a degraded device.
        let mut b = DmaBroker::new(FakeProt::available(48), DmaQuotas::default());
        let v = b.map_region(1, 0x1000, K, DmaDir::ToDevice).unwrap();
        b.prot_mut().available = false;
        assert_eq!(
            b.map_region(1, 0x9000, K, DmaDir::ToDevice),
            Err(DmaError::Absent)
        );
        b.region_complete(v.cookie).unwrap();
        b.unmap_region(v.cookie).unwrap();
        assert_eq!(b.live_regions(1), 0);
    }

    #[test]
    fn bounds_hold_at_a_39_bit_haw() {
        // Another real width (q35 default PA space): end == 2^39 is
        // the last legal grant; one byte more refuses.
        let mut b = DmaBroker::new(FakeProt::available(39), DmaQuotas::default());
        let top = 1u64 << 39;
        assert!(b.map_region(1, top - K, K, DmaDir::ToDevice).is_ok());
        assert_eq!(
            b.map_region(1, top - K, 2 * K, DmaDir::ToDevice),
            Err(DmaError::Overflow)
        );
    }
}
