//! DMAR / VT-d firmware-table parsing — ADR-0013, driver stack PR 0.2.
//!
//! Pure parsing *policy* over caller-supplied byte slices: the kernel
//! glue (PR 0.3, `arch/acpi.rs`) reads physical memory and hands the
//! bytes here; nothing in this module touches hardware, and the crate
//! stays `forbid(unsafe_code)` + zero-dependency.
//!
//! Invariants, all test-proven:
//! - **Firmware is untrusted input.** Every length, index and pointer
//!   is bounds-checked before use; checksums are verified; a malformed
//!   table is a typed error that disables the IOMMU path (fail closed,
//!   never a guess, never a panic).
//! - **Unaligned table pointers are normal** (SeaBIOS pmm packs tables
//!   at the top of low RAM — RSDT @ 0x7FE23C9, measured): the parser
//!   assumes nothing about alignment.
//! - **Bounded, fixed-size state**: tables ≤ `MAX_TABLE_BYTES`,
//!   structures/scopes/paths in constant arrays; no allocation.
//! - **The QEMU-10 byte layout this design was verified against is
//!   pinned by tests** (48-byte DMAR header, DRHD type 0, the measured
//!   120-byte table incl. the 00:03.0 virtio-blk variant) — any
//!   firmware or emulator that drifts fails loudly.
//! - **Truncation of a valid table never parses**: every prefix of a
//!   good table below its declared length is an error.
//! - **Random bytes never panic, never loop**: seeded fuzz over
//!   `parse_rsdp`/`parse_rsdt`/`parse_dmar` returns Ok or a typed
//!   error, always.

/// Directory entries per RSDT/XSDT (bounded, fail-loud exhaustion).
pub const MAX_TABLES: usize = 16;
/// Upper bound on any single table we are willing to parse.
pub const MAX_TABLE_BYTES: usize = 4096;
/// Remapping structures per DMAR.
pub const MAX_STRUCTS: usize = 16;
/// Device scopes per remapping structure.
pub const MAX_SCOPES: usize = 32;
/// Bridge hops per device scope path.
pub const MAX_SCOPE_PATH: usize = 8;
/// Smallest sane host address width (32-bit PA).
pub const MIN_HAW_BITS: u8 = 32;
/// Largest sane host address width (64-bit PA).
pub const MAX_HAW_BITS: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarError {
    /// Table signature mismatch (carries the first four bytes read).
    BadSignature([u8; 4]),
    /// ACPI checksum over the declared length is not zero.
    BadChecksum,
    /// Slice shorter than the structure requires.
    Truncated { need: usize, have: usize },
    /// Declared length impossible for the table kind (too small for the
    /// fixed header, over `MAX_TABLE_BYTES`, or not entry-strided).
    BadLength(u32),
    /// More directory entries than `MAX_TABLES`.
    TooManyTables,
    /// More remapping structures than `MAX_STRUCTS`.
    TooManyStructs,
    /// More device scopes than `MAX_SCOPES`.
    TooManyScopes,
    /// A structure declares a length below 4 — it cannot even be
    /// skipped safely, so the walk stops fail-closed.
    UnknownStructShort(u8),
    /// A device scope declares an impossible length (< 8, odd, or
    /// overrunning its structure).
    BadScopeLen(u8),
    /// A device-scope path with more hops than `MAX_SCOPE_PATH`.
    BadPathLen(u8),
    /// Register base zero or not 4 KiB-aligned (no DRHD may plausibly
    /// report either — firmware corruption is the working assumption).
    BadPointer(u64),
    /// RMRR range inverted, unaligned, or beyond the host address width.
    BadRange { base: u64, limit: u64 },
    /// Host address width byte outside 31..=63 (i.e. bits outside
    /// 32..=64).
    BadHaw(u8),
}

fn le_u16(bytes: &[u8], off: usize) -> Result<u16, DmarError> {
    let end = off.checked_add(2).ok_or(DmarError::Truncated {
        need: usize::MAX,
        have: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(DmarError::Truncated {
            need: end,
            have: bytes.len(),
        });
    }
    Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn le_u32(bytes: &[u8], off: usize) -> Result<u32, DmarError> {
    let end = off.checked_add(4).ok_or(DmarError::Truncated {
        need: usize::MAX,
        have: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(DmarError::Truncated {
            need: end,
            have: bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

fn le_u64(bytes: &[u8], off: usize) -> Result<u64, DmarError> {
    let end = off.checked_add(8).ok_or(DmarError::Truncated {
        need: usize::MAX,
        have: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(DmarError::Truncated {
            need: end,
            have: bytes.len(),
        });
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[off..end]);
    Ok(u64::from_le_bytes(b))
}

/// ACPI checksum: the low byte of the byte-sum over `len` bytes is 0.
fn checksum_ok(bytes: &[u8], len: usize) -> bool {
    if len > bytes.len() {
        return false;
    }
    bytes[..len].iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

/// Root System Description Pointer, rev 0 (legacy, RSDT only — what
/// SeaBIOS emits) or rev >= 2 (length field + XSDT address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rsdp {
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub rsdt_addr: u32,
    /// Zero for rev 0 (no XSDT pointer exists).
    pub xsdt_addr: u64,
}

/// The fixed 36-byte header every description table starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
}

/// A parsed RSDT/XSDT directory (unified to u64 addresses; zero
/// entries are legal padding and are skipped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableDir {
    pub addrs: [u64; MAX_TABLES],
    pub count: usize,
}

/// A parsed DMAR: host address width, flags, remapping structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dmar {
    /// Host address width in bits (raw byte + 1), 32..=64.
    pub haw_bits: u8,
    /// DMAR flags bit 0: interrupt remapping supported (we parse and
    /// log it; ADR-0013 scopes IR to the interrupt-broker ADR).
    pub intr_remap: bool,
    /// DMAR flags bit 1: x2APIC opt-out.
    pub x2apic_opt_out: bool,
    pub structures: [DmarStruct; MAX_STRUCTS],
    pub structure_count: usize,
}

impl Dmar {
    /// A placeholder for machines with **no DMAR** (the q35-neg
    /// control lane): no units, no RMRR — the claim path's scope and
    /// RMRR checks see an empty world, and the broker refuses anyway
    /// (verdict Absent). Never produced by parsing.
    #[must_use]
    pub const fn absent_stub() -> Self {
        Self {
            haw_bits: 39,
            intr_remap: false,
            x2apic_opt_out: false,
            structures: [DmarStruct::Unknown { kind: 0, len: 0 }; MAX_STRUCTS],
            structure_count: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarStruct {
    Drhd(Drhd),
    Rmrr(Rmrr),
    /// A known-to-exist but unhandled structure (ATSR, RHSR, ANDD...):
    /// skipped safely; callers log it.
    Unknown {
        kind: u8,
        len: u16,
    },
}

/// DMA-remapping hardware unit definition (structure type 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drhd {
    pub segment: u16,
    /// INCLUDE_ALL flag: this unit governs every endpoint in the
    /// segment not claimed by another unit's scope.
    pub include_all: bool,
    /// MMIO base of the remapping registers (validated nonzero + 4 KiB
    /// aligned — QEMU q35: 0xFED9_0000, measured).
    pub reg_base: u64,
    pub scopes: [DeviceScope; MAX_SCOPES],
    pub scope_count: usize,
}

/// Reserved memory region (structure type 1). Per ADR-0013 D2:
/// devices whose scopes fall inside an RMRR are **unusable**
/// (fail-closed), never identity-mapped — the data is here so the
/// claim path can refuse them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rmrr {
    pub segment: u16,
    pub base: u64,
    pub limit: u64,
    pub scopes: [DeviceScope; MAX_SCOPES],
    pub scope_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeType {
    /// 01h: PCI endpoint device.
    PciEndpoint,
    /// 02h: PCI sub-hierarchy (bridge) — subtree matching is Phase-1
    /// PCI-enumeration work; recorded but not yet used by `governs`.
    PciBridge,
    /// 03h: I/O APIC device (enumeration_id carries the IOAPIC id).
    IoApic,
    /// 04h: MSI-capable HPET.
    MsiHpet,
    /// 05h: ACPI namespace device.
    AcpiNameSpace,
    Reserved(u8),
}

impl ScopeType {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => ScopeType::PciEndpoint,
            2 => ScopeType::PciBridge,
            3 => ScopeType::IoApic,
            4 => ScopeType::MsiHpet,
            5 => ScopeType::AcpiNameSpace,
            other => ScopeType::Reserved(other),
        }
    }
}

/// One device scope entry: (bus, dev, fn) with optional bridge path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceScope {
    pub kind: ScopeType,
    /// IOAPIC id / HPET number for those kinds; 0 for PCI kinds.
    pub enumeration_id: u8,
    pub start_bus: u8,
    /// Bridge hops, path[0] = the device itself for endpoint scopes.
    pub path: [(u8, u8); MAX_SCOPE_PATH],
    pub path_len: usize,
}

impl DeviceScope {
    /// Exact endpoint match (bus + first path hop). Bridge-subtree
    /// matching deliberately returns false for now (Phase 1).
    fn matches_endpoint(&self, bus: u8, devfn: (u8, u8)) -> bool {
        self.kind == ScopeType::PciEndpoint
            && self.start_bus == bus
            && self.path_len >= 1
            && self.path[0] == devfn
    }
}

impl Drhd {
    /// Does this unit govern (segment, bus, dev, fn)? True when
    /// INCLUDE_ALL is set for the segment, or an endpoint scope names
    /// the device exactly.
    #[must_use]
    pub fn governs(&self, segment: u16, bus: u8, dev: u8, func: u8) -> bool {
        self.segment == segment
            && (self.include_all
                || self.scopes[..self.scope_count]
                    .iter()
                    .any(|s| s.matches_endpoint(bus, (dev, func))))
    }
}

impl Dmar {
    /// The DRHD governing (segment, bus, devfn), if any. First match
    /// wins (QEMU emits a single unit; multiple scope-matching units
    /// would be a firmware oddity either caller tolerates).
    #[must_use]
    pub fn find_drhd_for(&self, segment: u16, bus: u8, dev: u8, func: u8) -> Option<&Drhd> {
        self.structures[..self.structure_count]
            .iter()
            .find_map(|s| match s {
                DmarStruct::Drhd(d) if d.governs(segment, bus, dev, func) => Some(d),
                _ => None,
            })
    }

    /// Does any RMRR cover (segment, bus, devfn)? Such devices are
    /// refused by the claim path (fail-closed, ADR-0013 D2).
    #[must_use]
    pub fn rmrr_covers(&self, segment: u16, bus: u8, dev: u8, func: u8) -> bool {
        self.structures[..self.structure_count]
            .iter()
            .any(|s| match s {
                DmarStruct::Rmrr(r) => {
                    r.segment == segment
                        && r.scopes[..r.scope_count]
                            .iter()
                            .any(|sc| sc.matches_endpoint(bus, (dev, func)))
                }
                _ => false,
            })
    }
}

/// Parse an RSDP (rev 0 legacy or rev >= 2). Checks the "RSD PTR "
/// signature and the checksum over the rev-appropriate extent.
pub fn parse_rsdp(bytes: &[u8]) -> Result<Rsdp, DmarError> {
    if bytes.len() < 20 {
        return Err(DmarError::Truncated {
            need: 20,
            have: bytes.len(),
        });
    }
    if &bytes[0..8] != b"RSD PTR " {
        return Err(DmarError::BadSignature([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]));
    }
    let mut oem_id = [0u8; 6];
    oem_id.copy_from_slice(&bytes[9..15]);
    let revision = bytes[15];
    let rsdt_addr = le_u32(bytes, 16)?;
    match revision {
        0 => {
            if !checksum_ok(bytes, 20) {
                return Err(DmarError::BadChecksum);
            }
            Ok(Rsdp {
                revision,
                oem_id,
                rsdt_addr,
                xsdt_addr: 0,
            })
        }
        _ => {
            if bytes.len() < 36 {
                return Err(DmarError::Truncated {
                    need: 36,
                    have: bytes.len(),
                });
            }
            let length = le_u32(bytes, 20)?;
            if length < 36 || length as usize > MAX_TABLE_BYTES {
                return Err(DmarError::BadLength(length));
            }
            if bytes.len() < length as usize {
                return Err(DmarError::Truncated {
                    need: length as usize,
                    have: bytes.len(),
                });
            }
            if !checksum_ok(bytes, length as usize) {
                return Err(DmarError::BadChecksum);
            }
            let xsdt_addr = le_u64(bytes, 24)?;
            Ok(Rsdp {
                revision,
                oem_id,
                rsdt_addr,
                xsdt_addr,
            })
        }
    }
}

/// Parse the fixed 36-byte SDT header shared by every description
/// table. Length is validated (>= 36, <= `MAX_TABLE_BYTES`); the
/// checksum is checked by the table-specific parsers over their full
/// extent.
pub fn parse_sdt_header(bytes: &[u8]) -> Result<SdtHeader, DmarError> {
    if bytes.len() < 36 {
        return Err(DmarError::Truncated {
            need: 36,
            have: bytes.len(),
        });
    }
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&bytes[0..4]);
    let length = le_u32(bytes, 4)?;
    if length < 36 || length as usize > MAX_TABLE_BYTES {
        return Err(DmarError::BadLength(length));
    }
    if bytes.len() < length as usize {
        return Err(DmarError::Truncated {
            need: length as usize,
            have: bytes.len(),
        });
    }
    Ok(SdtHeader {
        signature,
        length,
        revision: bytes[8],
    })
}

fn parse_dir(bytes: &[u8], sig: &[u8; 4], stride: usize) -> Result<TableDir, DmarError> {
    let h = parse_sdt_header(bytes)?;
    if &h.signature != sig {
        return Err(DmarError::BadSignature(h.signature));
    }
    if !checksum_ok(bytes, h.length as usize) {
        return Err(DmarError::BadChecksum);
    }
    let entries = ((h.length - 36) / stride as u32) as usize;
    if (h.length - 36) % stride as u32 != 0 {
        return Err(DmarError::BadLength(h.length));
    }
    if entries > MAX_TABLES {
        return Err(DmarError::TooManyTables);
    }
    let mut dir = TableDir {
        addrs: [0; MAX_TABLES],
        count: 0,
    };
    for i in 0..entries {
        let off = 36 + i * stride;
        let addr = match stride {
            4 => u64::from(le_u32(bytes, off)?),
            _ => le_u64(bytes, off)?,
        };
        if addr != 0 {
            // Zero entries are legal padding, not tables.
            dir.addrs[dir.count] = addr;
            dir.count += 1;
        }
    }
    Ok(dir)
}

/// Parse an RSDT (32-bit entry stride).
pub fn parse_rsdt(bytes: &[u8]) -> Result<TableDir, DmarError> {
    parse_dir(bytes, b"RSDT", 4)
}

/// Parse an XSDT (64-bit entry stride).
pub fn parse_xsdt(bytes: &[u8]) -> Result<TableDir, DmarError> {
    parse_dir(bytes, b"XSDT", 8)
}

/// Parse one device scope at `so` inside a structure slice of `slen`
/// bytes. Returns the scope and its byte length.
fn parse_scope(s: &[u8], so: usize, slen: usize) -> Result<(DeviceScope, usize), DmarError> {
    if so + 2 > slen || s.len() < slen {
        return Err(DmarError::BadScopeLen(0));
    }
    let scope_len = s[so + 1] as usize;
    if scope_len < 8
        || !scope_len.is_multiple_of(2)
        || so.checked_add(scope_len).is_none_or(|e| e > slen)
    {
        return Err(DmarError::BadScopeLen(s[so + 1]));
    }
    let hops = (scope_len - 6) / 2;
    if hops > MAX_SCOPE_PATH {
        return Err(DmarError::BadPathLen(s[so + 1]));
    }
    let mut path = [(0u8, 0u8); MAX_SCOPE_PATH];
    for (h, slot) in path.iter_mut().enumerate().take(hops) {
        let off = so + 6 + h * 2;
        *slot = (s[off], s[off + 1]);
    }
    Ok((
        DeviceScope {
            kind: ScopeType::from_raw(s[so]),
            enumeration_id: s[so + 4],
            start_bus: s[so + 5],
            path,
            path_len: hops,
        },
        scope_len,
    ))
}

fn parse_scopes(
    s: &[u8],
    slen: usize,
    first: usize,
) -> Result<([DeviceScope; MAX_SCOPES], usize), DmarError> {
    let mut scopes = [DeviceScope {
        kind: ScopeType::Reserved(0),
        enumeration_id: 0,
        start_bus: 0,
        path: [(0, 0); MAX_SCOPE_PATH],
        path_len: 0,
    }; MAX_SCOPES];
    let mut count = 0usize;
    let mut off = first;
    while off < slen {
        if count == MAX_SCOPES {
            return Err(DmarError::TooManyScopes);
        }
        let (scope, len) = parse_scope(s, off, slen)?;
        scopes[count] = scope;
        count += 1;
        off += len;
    }
    Ok((scopes, count))
}

/// Parse a DMAR table: 36-byte SDT header + 12 DMAR bytes (HAW, flags,
/// reserved) + remapping structures from offset 48.
pub fn parse_dmar(bytes: &[u8]) -> Result<Dmar, DmarError> {
    let h = parse_sdt_header(bytes)?;
    if &h.signature != b"DMAR" {
        return Err(DmarError::BadSignature(h.signature));
    }
    // The DMAR header is 48 bytes: SDT(36) + HAW(1) + flags(1) + 10
    // reserved. Pinned by test against the measured QEMU-10 layout.
    if h.length < 48 {
        return Err(DmarError::BadLength(h.length));
    }
    if !checksum_ok(bytes, h.length as usize) {
        return Err(DmarError::BadChecksum);
    }
    let haw_raw = bytes[36];
    if !(MIN_HAW_BITS - 1..=MAX_HAW_BITS - 1).contains(&haw_raw) {
        return Err(DmarError::BadHaw(haw_raw));
    }
    let flags = bytes[37];
    let dmar_len = h.length as usize;

    let mut structures = [DmarStruct::Unknown { kind: 0, len: 0 }; MAX_STRUCTS];
    let mut structure_count = 0usize;
    let mut off = 48usize;
    while off < dmar_len {
        if dmar_len - off < 4 {
            // A structure header must fit before the table ends.
            return Err(DmarError::BadLength(h.length));
        }
        let kind = le_u16(bytes, off)?;
        let slen = le_u16(bytes, off + 2)? as usize;
        if slen < 4 {
            return Err(DmarError::UnknownStructShort(kind as u8));
        }
        let end = off
            .checked_add(slen)
            .ok_or(DmarError::BadLength(h.length))?;
        if end > dmar_len {
            return Err(DmarError::BadLength(h.length));
        }
        if structure_count == MAX_STRUCTS {
            return Err(DmarError::TooManyStructs);
        }
        let s = &bytes[off..end];
        let parsed = match kind {
            0 => {
                if slen < 16 {
                    return Err(DmarError::BadLength(h.length));
                }
                let reg_base = le_u64(s, 8)?;
                if reg_base == 0 || reg_base & 0xFFF != 0 {
                    return Err(DmarError::BadPointer(reg_base));
                }
                let (scopes, scope_count) = parse_scopes(s, slen, 16)?;
                DmarStruct::Drhd(Drhd {
                    segment: le_u16(s, 6)?,
                    include_all: s[4] & 1 != 0,
                    reg_base,
                    scopes,
                    scope_count,
                })
            }
            1 => {
                if slen < 24 {
                    return Err(DmarError::BadLength(h.length));
                }
                let base = le_u64(s, 8)?;
                let limit = le_u64(s, 16)?;
                // 1 << 64 overflows u64: a 64-bit HAW means "all of it".
                let max_pa = if haw_raw == 63 {
                    u64::MAX
                } else {
                    1u64 << (haw_raw + 1)
                };
                if base > limit || base & 0xFFF != 0 || limit >= max_pa {
                    return Err(DmarError::BadRange { base, limit });
                }
                let (scopes, scope_count) = parse_scopes(s, slen, 24)?;
                DmarStruct::Rmrr(Rmrr {
                    segment: le_u16(s, 6)?,
                    base,
                    limit,
                    scopes,
                    scope_count,
                })
            }
            _ => DmarStruct::Unknown {
                kind: kind as u8,
                len: slen as u16,
            },
        };
        structures[structure_count] = parsed;
        structure_count += 1;
        off = end;
    }

    Ok(Dmar {
        haw_bits: haw_raw + 1,
        intr_remap: flags & 0x1 != 0,
        x2apic_opt_out: flags & 0x2 != 0,
        structures,
        structure_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── builders (host tests may use std) ──

    /// Fix the ACPI checksum byte (offset 9) so the byte-sum is zero.
    fn fix_checksum(bytes: &mut [u8]) {
        let sum: u8 = bytes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 9)
            .fold(0u8, |a, (_, b)| a.wrapping_add(*b));
        bytes[9] = sum.wrapping_neg();
    }

    fn sdt_header(sig: &[u8; 4], length: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(sig);
        out.extend_from_slice(&length.to_le_bytes());
        out.push(1); // revision
        out.push(0); // checksum (fixed later)
        out.extend_from_slice(b"BOCHS "); // OEM id (6)
        out.extend_from_slice(b"BHYVE   "); // OEM table id (8)
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(b"BXPC");
        out.extend_from_slice(&1u32.to_le_bytes());
    }

    fn scope_bytes(kind: u8, enumeration_id: u8, start_bus: u8, path: &[(u8, u8)]) -> Vec<u8> {
        let mut s = vec![
            kind,
            (6 + 2 * path.len()) as u8,
            0,
            0,
            enumeration_id,
            start_bus,
        ];
        for (dev, func) in path {
            s.push(*dev);
            s.push(*func);
        }
        s
    }

    fn drhd_bytes(include_all: bool, segment: u16, reg_base: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
        let len = 16 + scopes.iter().map(Vec::len).sum::<usize>();
        let mut s = vec![];
        s.extend_from_slice(&0u16.to_le_bytes()); // type 0 = DRHD
        s.push((len as u16).to_le_bytes()[0]);
        s.push((len as u16).to_le_bytes()[1]);
        s.push(u8::from(include_all)); // flags
        s.push(0); // reserved
        s.extend_from_slice(&segment.to_le_bytes());
        s.extend_from_slice(&reg_base.to_le_bytes());
        for sc in scopes {
            s.extend_from_slice(sc);
        }
        s
    }

    fn rmrr_bytes(segment: u16, base: u64, limit: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
        let len = 24 + scopes.iter().map(Vec::len).sum::<usize>();
        let mut s = vec![];
        s.extend_from_slice(&1u16.to_le_bytes()); // type 1 = RMRR
        s.extend_from_slice(&(len as u16).to_le_bytes());
        s.extend_from_slice(&0u16.to_le_bytes()); // reserved
        s.extend_from_slice(&segment.to_le_bytes());
        s.extend_from_slice(&base.to_le_bytes());
        s.extend_from_slice(&limit.to_le_bytes());
        for sc in scopes {
            s.extend_from_slice(sc);
        }
        s
    }

    fn dmar_bytes(haw_raw: u8, flags: u8, structs: &[Vec<u8>]) -> Vec<u8> {
        let len = 48 + structs.iter().map(Vec::len).sum::<usize>();
        let mut t = vec![];
        sdt_header(b"DMAR", len as u32, &mut t);
        t.push(haw_raw);
        t.push(flags);
        t.extend_from_slice(&[0u8; 10]); // reserved → header is 48 bytes
        for s in structs {
            t.extend_from_slice(s);
        }
        fix_checksum(&mut t);
        t
    }

    /// The exact DMAR QEMU 10.0.13 q35 + intel-iommu emits (measured,
    /// ADR-0013 evidence appendix): 48-bit HAW, INTR_REMAP flag, one
    /// DRHD at 0xFED9_0000, include_all=false, 7 scopes (IOAPIC on the
    /// 0xFF pseudo-bus + 00:00.0/01.0/02.0/1f.0/1f.2/1f.3).
    fn qemu_dmar() -> Vec<u8> {
        let scopes = vec![
            scope_bytes(3, 0, 0xFF, &[(0, 0)]), // IOAPIC
            scope_bytes(1, 0, 0x00, &[(0x00, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x01, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x02, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x1F, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x1F, 2)]),
            scope_bytes(1, 0, 0x00, &[(0x1F, 3)]),
        ];
        dmar_bytes(47, 0x01, &[drhd_bytes(false, 0, 0xFED9_0000, &scopes)])
    }

    #[test]
    fn dmar_header_is_48_bytes_drhd_is_type_0() {
        // The pinned measured layout: header-only DMAR is 48 bytes and
        // parses to zero structures; the full QEMU table is 120 bytes
        // (48 + DRHD 72) and the DRHD is structure type 0.
        let empty = dmar_bytes(47, 0, &[]);
        assert_eq!(empty.len(), 48);
        let d = parse_dmar(&empty).unwrap();
        assert_eq!(d.structure_count, 0);
        assert_eq!(d.haw_bits, 48);
        let q = qemu_dmar();
        assert_eq!(q.len(), 120, "the measured table length");
        let d = parse_dmar(&q).unwrap();
        assert_eq!(d.structure_count, 1);
        assert!(matches!(d.structures[0], DmarStruct::Drhd(_)));
    }

    #[test]
    fn dmar_pin_qemu_layout() {
        let d = parse_dmar(&qemu_dmar()).unwrap();
        assert_eq!(d.haw_bits, 48);
        assert!(d.intr_remap);
        assert!(!d.x2apic_opt_out);
        match d.structures[0] {
            DmarStruct::Drhd(drhd) => {
                assert_eq!(drhd.segment, 0);
                assert_eq!(drhd.reg_base, 0xFED9_0000);
                assert!(!drhd.include_all);
                assert_eq!(drhd.scope_count, 7);
                assert_eq!(drhd.scopes[0].kind, ScopeType::IoApic);
                assert_eq!(drhd.scopes[0].enumeration_id, 0);
                assert_eq!(drhd.scopes[0].start_bus, 0xFF);
                assert_eq!(drhd.scopes[1].kind, ScopeType::PciEndpoint);
                assert_eq!(drhd.scopes[1].start_bus, 0);
                assert_eq!(drhd.scopes[1].path[0], (0x00, 0));
                assert_eq!(drhd.scopes[5].path[0], (0x1F, 2));
                // Governs every listed endpoint, nothing else.
                for (bus, dev, fn_) in [
                    (0, 0x00, 0),
                    (0, 0x01, 0),
                    (0, 0x02, 0),
                    (0, 0x1F, 0),
                    (0, 0x1F, 2),
                    (0, 0x1F, 3),
                ] {
                    assert!(drhd.governs(0, bus, dev, fn_), "{bus:02x}:{dev:02x}.{fn_}");
                }
                assert!(
                    !drhd.governs(0, 0, 0x03, 0),
                    "the added virtio-blk is not in this table"
                );
                assert!(!drhd.governs(0, 1, 0, 0), "wrong bus");
                assert!(!drhd.governs(1, 0, 0, 0), "wrong segment");
            }
            _ => panic!("expected a DRHD"),
        }
    }

    #[test]
    fn dmar_pin_virtio_variant() {
        // Adding -device virtio-blk-pci,iommu_platform=on grows the
        // DRHD to len 80 with a 00:03.0 scope (measured).
        let scopes = vec![
            scope_bytes(3, 0, 0xFF, &[(0, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x00, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x01, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x02, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x1F, 0)]),
            scope_bytes(1, 0, 0x00, &[(0x1F, 2)]),
            scope_bytes(1, 0, 0x00, &[(0x1F, 3)]),
            scope_bytes(1, 0, 0x00, &[(0x03, 0)]),
        ];
        let drhd = drhd_bytes(false, 0, 0xFED9_0000, &scopes);
        assert_eq!(drhd.len(), 80);
        let d = parse_dmar(&dmar_bytes(47, 0x01, &[drhd])).unwrap();
        assert!(d.find_drhd_for(0, 0, 0x03, 0).is_some());
        assert!(d.find_drhd_for(0, 0, 0x04, 0).is_none());
    }

    #[test]
    fn include_all_governs_every_endpoint_in_segment() {
        let scopes = vec![scope_bytes(1, 0, 0, &[(0x1F, 3)])];
        let d = parse_dmar(&dmar_bytes(
            47,
            0,
            &[drhd_bytes(true, 0, 0xFED9_0000, &scopes)],
        ))
        .unwrap();
        match d.structures[0] {
            DmarStruct::Drhd(drhd) => {
                assert!(
                    drhd.governs(0, 2, 0x10, 1),
                    "INCLUDE_ALL covers unlisted endpoints"
                );
                assert!(!drhd.governs(1, 2, 0x10, 1), "but not other segments");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rsdp_rev0_pin_bochs_layout() {
        // SeaBIOS emits rev 0 with the RSDT at an UNALIGNED address
        // (0x7FE23C9, measured) — the parser must accept it.
        let mut r = vec![0u8; 20];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[9..15].copy_from_slice(b"BOCHS ");
        r[15] = 0; // revision 0
        r[16..20].copy_from_slice(&0x07FE_23C9u32.to_le_bytes());
        let sum: u8 = r.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        r[8] = sum.wrapping_neg();
        let rsdp = parse_rsdp(&r).unwrap();
        assert_eq!(rsdp.revision, 0);
        assert_eq!(&rsdp.oem_id, b"BOCHS ");
        assert_eq!(rsdp.rsdt_addr, 0x07FE_23C9);
        assert_eq!(rsdp.xsdt_addr, 0);
    }

    #[test]
    fn rsdp_rev2_uses_length_and_xsdt() {
        let mut r = vec![0u8; 36];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[15] = 2;
        r[16..20].copy_from_slice(&0x07FE_23C9u32.to_le_bytes());
        r[20..24].copy_from_slice(&36u32.to_le_bytes());
        r[24..32].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        let sum: u8 = r.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        r[8] = sum.wrapping_neg();
        let rsdp = parse_rsdp(&r).unwrap();
        assert_eq!(rsdp.revision, 2);
        assert_eq!(rsdp.xsdt_addr, 0xDEAD_BEEF);
        // Declared length beyond the slice: truncation, not a guess.
        r[20..24].copy_from_slice(&64u32.to_le_bytes());
        assert!(matches!(
            parse_rsdp(&r),
            Err(DmarError::Truncated { need: 64, have: 36 })
        ));
    }

    #[test]
    fn rsdp_rejects_bad_signature_and_checksum() {
        let mut r = vec![0u8; 20];
        r[..8].copy_from_slice(b"RSD PTX ");
        assert!(matches!(parse_rsdp(&r), Err(DmarError::BadSignature(_))));
        let mut r = vec![0u8; 20];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[8] = 1; // broken checksum
        assert_eq!(parse_rsdp(&r), Err(DmarError::BadChecksum));
        assert!(matches!(
            parse_rsdp(&r[..19]),
            Err(DmarError::Truncated { need: 20, have: 19 })
        ));
    }

    #[test]
    fn rsdt_pin_six_entries_and_stride_check() {
        // The measured RSDT: 6 entries (FACP APIC HPET MCFG DMAR WAET).
        let addrs: [u32; 6] = [
            0x07FE_26F4,
            0x07FE_2588,
            0x07FE_2420,
            0x07FE_2290,
            0x07FE_2329,
            0x07FE_2610,
        ];
        let mut t = vec![];
        sdt_header(b"RSDT", (36 + 4 * addrs.len()) as u32, &mut t);
        for a in addrs {
            t.extend_from_slice(&a.to_le_bytes());
        }
        fix_checksum(&mut t);
        let dir = parse_rsdt(&t).unwrap();
        assert_eq!(dir.count, 6);
        assert_eq!(dir.addrs[4], 0x07FE_2329, "DMAR is the 5th entry");
        // A zero entry is legal padding, skipped (not counted, no crash).
        t.extend_from_slice(&0u32.to_le_bytes());
        let new_len = t.len() as u32;
        t[4..8].copy_from_slice(&new_len.to_le_bytes());
        fix_checksum(&mut t);
        let dir = parse_rsdt(&t).unwrap();
        assert_eq!(dir.count, 6, "the zero entry is skipped");
        // A length that is not 4-strided is malformed: fail closed.
        let mut bad = vec![];
        sdt_header(b"RSDT", 41, &mut bad); // 41 - 36 = 5, not % 4
        bad.extend_from_slice(&[0u8; 5]);
        fix_checksum(&mut bad);
        assert!(matches!(parse_rsdt(&bad), Err(DmarError::BadLength(41))));
    }

    #[test]
    fn xsdt_parses_64bit_entries() {
        let mut t = vec![];
        sdt_header(b"XSDT", 36 + 16, &mut t);
        t.extend_from_slice(&0x1_0000_07FEu64.to_le_bytes());
        t.extend_from_slice(&0x2_0000_07FEu64.to_le_bytes());
        fix_checksum(&mut t);
        let dir = parse_xsdt(&t).unwrap();
        assert_eq!(dir.count, 2);
        assert_eq!(dir.addrs[0], 0x1_0000_07FE);
    }

    #[test]
    fn table_signature_and_length_checks() {
        let mut t = vec![];
        sdt_header(b"FACP", 36, &mut t);
        fix_checksum(&mut t);
        assert!(matches!(
            parse_dmar(&t),
            Err(DmarError::BadSignature([0x46, 0x41, 0x43, 0x50]))
        ));
        // Header shorter than the 48-byte DMAR header.
        let mut short = vec![];
        sdt_header(b"DMAR", 47, &mut short);
        short.extend_from_slice(&[0u8; 11]); // slice matches the declared length
        assert!(matches!(parse_dmar(&short), Err(DmarError::BadLength(47))));
        // A generic SDT header below 36 bytes is impossible.
        assert!(matches!(
            parse_sdt_header(&[0u8; 35]),
            Err(DmarError::Truncated { need: 36, have: 35 })
        ));
    }

    #[test]
    fn dmar_checksum_bit_flip_detected() {
        let mut q = qemu_dmar();
        q[50] ^= 0x01; // inside the DRHD body
        assert_eq!(parse_dmar(&q), Err(DmarError::BadChecksum));
    }

    #[test]
    fn haw_byte_validated() {
        // raw 30 → 31 bits, below the 32-bit floor; raw 64 → 65 bits.
        let t = dmar_bytes(30, 0, &[]);
        assert!(matches!(parse_dmar(&t), Err(DmarError::BadHaw(30))));
        let t = dmar_bytes(64, 0, &[]);
        assert!(matches!(parse_dmar(&t), Err(DmarError::BadHaw(64))));
    }

    #[test]
    fn drhd_reg_base_validated() {
        let scopes = vec![scope_bytes(1, 0, 0, &[(0, 0)])];
        let zero = drhd_bytes(false, 0, 0, &scopes);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[zero])),
            Err(DmarError::BadPointer(0))
        ));
        let unaligned = drhd_bytes(false, 0, 0xFED9_0008, &scopes);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[unaligned])),
            Err(DmarError::BadPointer(0xFED9_0008))
        ));
        // DRHD below the 16-byte minimum.
        let mut tiny = vec![];
        tiny.extend_from_slice(&0u16.to_le_bytes());
        tiny.extend_from_slice(&12u16.to_le_bytes());
        tiny.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[tiny])),
            Err(DmarError::BadLength(_))
        ));
    }

    #[test]
    fn rmrr_parses_and_range_validated() {
        let scopes = vec![scope_bytes(1, 0, 0, &[(0x1F, 2)])];
        let good = rmrr_bytes(0, 0x7F00_0000, 0x7F00_0FFF, &scopes);
        let d = parse_dmar(&dmar_bytes(47, 0, &[good])).unwrap();
        match d.structures[0] {
            DmarStruct::Rmrr(r) => {
                assert_eq!(r.base, 0x7F00_0000);
                assert_eq!(r.limit, 0x7F00_0FFF);
                assert_eq!(r.scope_count, 1);
                assert!(d.rmrr_covers(0, 0, 0x1F, 2));
                assert!(!d.rmrr_covers(0, 0, 0x1F, 3));
            }
            _ => panic!(),
        }
        // Inverted and beyond-HAW ranges are refused (48-bit HAW: the
        // limit must stay below 2^48).
        let inverted = rmrr_bytes(0, 0x1000, 0x0FFF, &[]);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[inverted])),
            Err(DmarError::BadRange { .. })
        ));
        let beyond = rmrr_bytes(0, 0x0000_1000, 1u64 << 48, &[]);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[beyond])),
            Err(DmarError::BadRange { .. })
        ));
    }

    #[test]
    fn unknown_structures_skip_and_short_ones_stop() {
        // ATSR (type 2), len 24: skipped, recorded, walk continues.
        let mut atsr = vec![];
        atsr.extend_from_slice(&2u16.to_le_bytes());
        atsr.extend_from_slice(&24u16.to_le_bytes());
        atsr.extend_from_slice(&[0u8; 20]);
        let scopes = vec![scope_bytes(1, 0, 0, &[(0, 0)])];
        let d = parse_dmar(&dmar_bytes(
            47,
            0,
            &[atsr, drhd_bytes(false, 0, 0xFED9_0000, &scopes)],
        ))
        .unwrap();
        assert_eq!(d.structure_count, 2);
        assert_eq!(d.structures[0], DmarStruct::Unknown { kind: 2, len: 24 });
        assert!(matches!(d.structures[1], DmarStruct::Drhd(_)));
        // A structure with len < 4 cannot be skipped: fail closed.
        let mut shorty = vec![];
        shorty.extend_from_slice(&9u16.to_le_bytes());
        shorty.extend_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[shorty])),
            Err(DmarError::UnknownStructShort(9))
        ));
    }

    #[test]
    fn structure_len_overruns_dmar() {
        let scopes = vec![scope_bytes(1, 0, 0, &[(0, 0)])];
        let mut drhd = drhd_bytes(false, 0, 0xFED9_0000, &scopes);
        drhd[2..4].copy_from_slice(&200u16.to_le_bytes()); // len beyond the table
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[drhd])),
            Err(DmarError::BadLength(_))
        ));
    }

    #[test]
    fn scope_validation() {
        // Odd scope length, length below 8, overrun.
        let odd = vec![1u8, 9, 0, 0, 0, 0, 0, 0, 0]; // 9 is odd
        assert!(matches!(
            parse_dmar(&dmar_bytes(
                47,
                0,
                &[drhd_bytes(false, 0, 0xFED9_0000, &[odd])]
            )),
            Err(DmarError::BadScopeLen(9))
        ));
        let short = vec![1u8, 6, 0, 0, 0, 0]; // 6 bytes: no hop at all
        assert!(matches!(
            parse_dmar(&dmar_bytes(
                47,
                0,
                &[drhd_bytes(false, 0, 0xFED9_0000, &[short])]
            )),
            Err(DmarError::BadScopeLen(6))
        ));
        let overrun = vec![1u8, 16, 0, 0, 0, 0, 0, 0]; // 16 > remaining 8
        assert!(matches!(
            parse_dmar(&dmar_bytes(
                47,
                0,
                &[drhd_bytes(false, 0, 0xFED9_0000, &[overrun])]
            )),
            Err(DmarError::BadScopeLen(16))
        ));
        // Path with more hops than MAX_SCOPE_PATH.
        let mut long = vec![1u8, (6 + 2 * (MAX_SCOPE_PATH + 1)) as u8, 0, 0, 0, 0];
        for _ in 0..MAX_SCOPE_PATH + 1 {
            long.push(0);
            long.push(0);
        }
        assert!(matches!(
            parse_dmar(&dmar_bytes(
                47,
                0,
                &[drhd_bytes(false, 0, 0xFED9_0000, &[long])]
            )),
            Err(DmarError::BadPathLen(_))
        ));
        // Too many scopes for one structure.
        let many: Vec<Vec<u8>> = (0..MAX_SCOPES + 1)
            .map(|i| scope_bytes(1, 0, 0, &[(i as u8, 0)]))
            .collect();
        assert!(matches!(
            parse_dmar(&dmar_bytes(
                47,
                0,
                &[drhd_bytes(false, 0, 0xFED9_0000, &many)]
            )),
            Err(DmarError::TooManyScopes)
        ));
    }

    #[test]
    fn too_many_structures_and_tables() {
        // 17 empty DRHDs (16 bytes each) = 320 bytes total: within
        // MAX_TABLE_BYTES, so the count cap is what fires. Register
        // bases are page-strided: reg_base must stay 4 KiB-aligned.
        let many: Vec<Vec<u8>> = (0..MAX_STRUCTS + 1)
            .map(|i| drhd_bytes(false, 0, 0xFED9_0000 + i as u64 * 0x1000, &[]))
            .collect();
        let total = 48 + many.iter().map(Vec::len).sum::<usize>();
        assert!(total <= MAX_TABLE_BYTES);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &many)),
            Err(DmarError::TooManyStructs)
        ));
        // Directory: more entries than MAX_TABLES.
        let mut t = vec![];
        sdt_header(b"RSDT", (36 + 4 * (MAX_TABLES + 1)) as u32, &mut t);
        for i in 0..MAX_TABLES + 1 {
            t.extend_from_slice(&(i as u32 + 1).to_le_bytes());
        }
        fix_checksum(&mut t);
        assert_eq!(parse_rsdt(&t), Err(DmarError::TooManyTables));
    }

    #[test]
    fn truncation_of_valid_tables_never_parses() {
        let q = qemu_dmar();
        for cut in 0..q.len() {
            assert!(
                parse_dmar(&q[..cut]).is_err(),
                "prefix of {} bytes must not parse",
                cut
            );
        }
        let mut r = vec![];
        sdt_header(b"RSDT", 36 + 4, &mut r);
        r.extend_from_slice(&0x07FE_2329u32.to_le_bytes());
        fix_checksum(&mut r);
        for cut in 0..r.len() {
            assert!(parse_rsdt(&r[..cut]).is_err(), "RSDT prefix {cut}");
        }
    }

    #[test]
    fn fuzz_random_bytes_never_panic_or_hang() {
        // Seeded LCG (deterministic, no external fuzzer): every input
        // yields Ok or a typed error. 1024 rounds x 3 parsers.
        let mut state = 0x2026_1113u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..1024 {
            let len = (next() % 256) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = (next() & 0xFF) as u8;
            }
            // Ok or Err — the only contract; never a panic.
            let _ = parse_rsdp(&buf);
            let _ = parse_rsdt(&buf);
            let _ = parse_dmar(&buf);
            if let Ok(d) = parse_dmar(&buf) {
                // Ok results still satisfy the structural invariants.
                assert!(d.structure_count <= MAX_STRUCTS);
                assert!((MIN_HAW_BITS..=MAX_HAW_BITS).contains(&d.haw_bits));
                for s in &d.structures[..d.structure_count] {
                    if let DmarStruct::Drhd(drhd) = s {
                        assert_eq!(drhd.reg_base & 0xFFF, 0);
                        assert!(drhd.reg_base != 0);
                        assert!(drhd.scope_count <= MAX_SCOPES);
                    }
                }
            }
        }
    }

    #[test]
    fn fuzz_single_byte_flips_stay_invariant() {
        // Every single-byte mutation of the measured table: never a
        // panic; any Ok parse still satisfies the invariants.
        let q = qemu_dmar();
        for pos in 0..q.len() {
            for xor in [0x01u8, 0x80] {
                let mut m = q.clone();
                m[pos] ^= xor;
                if let Ok(d) = parse_dmar(&m) {
                    assert!(d.structure_count <= MAX_STRUCTS);
                    assert!((MIN_HAW_BITS..=MAX_HAW_BITS).contains(&d.haw_bits));
                    for s in &d.structures[..d.structure_count] {
                        if let DmarStruct::Drhd(drhd) = s {
                            assert_eq!(drhd.reg_base & 0xFFF, 0);
                            assert!(drhd.scope_count <= MAX_SCOPES);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rsdp_rev0_checksum_covers_exactly_20_bytes() {
        let mut r = vec![0u8; 20];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[9..15].copy_from_slice(b"BOCHS ");
        r[16..20].copy_from_slice(&0x07FE_23C9u32.to_le_bytes());
        let sum: u8 = r.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        r[8] = sum.wrapping_neg();
        // Bytes past 20 are not part of a rev-0 RSDP: garbage there
        // must not change the verdict.
        let padded = [r.clone(), vec![0xFFu8; 16]].concat();
        assert_eq!(parse_rsdp(&padded).unwrap(), parse_rsdp(&r).unwrap());
    }

    #[test]
    fn rsdp_truncation_prefixes_never_parse() {
        let mut r = [0u8; 20];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[9..15].copy_from_slice(b"BOCHS ");
        r[16..20].copy_from_slice(&0x07FE_23C9u32.to_le_bytes());
        let sum: u8 = r.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        r[8] = sum.wrapping_neg();
        for cut in 0..r.len() {
            assert!(parse_rsdp(&r[..cut]).is_err(), "RSDP prefix {cut}");
        }
    }

    #[test]
    fn sdt_header_length_beyond_slice_is_truncation() {
        let mut t = vec![];
        sdt_header(b"DMAR", 60, &mut t); // slice is 36 bytes, length says 60
        assert!(matches!(
            parse_sdt_header(&t),
            Err(DmarError::Truncated { need: 60, have: 36 })
        ));
    }

    #[test]
    fn governs_requires_exact_function() {
        let scopes = vec![scope_bytes(1, 0, 0, &[(0x1F, 2)])];
        let d = parse_dmar(&dmar_bytes(
            47,
            0,
            &[drhd_bytes(false, 0, 0xFED9_0000, &scopes)],
        ))
        .unwrap();
        assert!(d.find_drhd_for(0, 0, 0x1F, 2).is_some());
        assert!(
            d.find_drhd_for(0, 0, 0x1F, 0).is_none(),
            "function must match"
        );
        assert!(
            d.find_drhd_for(0, 0, 0x1E, 2).is_none(),
            "device must match"
        );
    }

    #[test]
    fn bridge_scopes_are_recorded_but_do_not_govern() {
        // A PCI-bridge scope (type 2) is parsed and recorded; endpoint
        // governing waits for Phase-1 subtree matching by design.
        let scopes = vec![scope_bytes(2, 0, 0, &[(0x1C, 0), (0x02, 0)])];
        let d = parse_dmar(&dmar_bytes(
            47,
            0,
            &[drhd_bytes(false, 0, 0xFED9_0000, &scopes)],
        ))
        .unwrap();
        match d.structures[0] {
            DmarStruct::Drhd(drhd) => {
                assert_eq!(drhd.scopes[0].kind, ScopeType::PciBridge);
                assert_eq!(drhd.scopes[0].path_len, 2);
                assert_eq!(drhd.scopes[0].path[1], (0x02, 0));
                assert!(
                    !drhd.governs(0, 0, 0x1C, 0),
                    "no endpoint match from a bridge scope"
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rmrr_unaligned_base_is_rejected() {
        let scopes = vec![scope_bytes(1, 0, 0, &[(0, 0)])];
        let bad = rmrr_bytes(0, 0x7F00_0008, 0x7F00_0FFF, &scopes);
        assert!(matches!(
            parse_dmar(&dmar_bytes(47, 0, &[bad])),
            Err(DmarError::BadRange { .. })
        ));
    }

    #[test]
    fn dmar_multiple_structures_preserve_order() {
        let ep = vec![scope_bytes(1, 0, 0, &[(0, 0)])];
        let d = parse_dmar(&dmar_bytes(
            47,
            0x01,
            &[
                drhd_bytes(false, 0, 0xFED9_0000, &ep),
                rmrr_bytes(0, 0x7F00_0000, 0x7F00_0FFF, &ep),
                drhd_bytes(true, 0, 0xFED9_1000, &[]),
            ],
        ))
        .unwrap();
        assert_eq!(d.structure_count, 3);
        assert!(matches!(d.structures[0], DmarStruct::Drhd(_)));
        assert!(matches!(d.structures[1], DmarStruct::Rmrr(_)));
        assert!(matches!(d.structures[2], DmarStruct::Drhd(_)));
    }
}
