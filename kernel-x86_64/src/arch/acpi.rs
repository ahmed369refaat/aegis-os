//! ACPI table discovery for the driver stack (ADR-0013, PR 0.3).
//!
//! One job, done one way: find the RSDP, walk the RSDT/XSDT, hand the
//! DMAR (if any) to the policy parser (`aegis_os::dmar`, PR 0.2 —
//! host-proven over byte slices). Everything downstream of this module
//! consumes a typed [`Discovery`]; nothing guesses and nothing
//! trusts the firmware beyond what the parser validates.
//!
//! ## Where it looks (the two standard RSDP windows)
//!
//! 1. the EBDA segment (the BDA word at physical 0x40E → segment,
//!    scanned for its first KiB), then
//! 2. the legacy BIOS ROM window 0xE0000..0x100000 — both regions are
//!    inside the first GiB, so the existing direct map reaches them.
//!
//! SeaBIOS packs tables at unaligned addresses (RSDT @ 0x7FE23C9
//! measured, ADR-0013 evidence): every access below is byte-granular
//! *by construction* and alignment assumptions are nowhere.
//!
//! ## Unsafe policy: zero, and it stays that way
//!
//! All physical reads go through `memops::read_u32` (allowlisted) at
//! **4-byte-aligned** addresses only; an unaligned byte is extracted
//! from its containing little-endian word by pure arithmetic. No new
//! unsafe site exists in this module.
//!
//! ## Host tests
//!
//! The scan, the directory walk and the DMAR lookup are pure functions
//! of injected scan-window addresses: on the host, `memops` translates
//! "physical" addresses with the identity (its own host-test
//! discipline), so the tests plant RSDP/RSDT/DMAR images in plain
//! buffers and run the *identical* kernel code path. Only
//! [`discover_boot`] hardcodes the real 0x40E/0xE0000 windows and is
//! target-only.

use aegis_os::dmar::{self, Dmar, DmarError, Rsdp};

/// The BDA word holding the EBDA segment (real-mode segment number).
pub const EBDA_SEG_PTR: u64 = 0x40E;
/// How much of the EBDA to scan (the RSDP sits near its start).
pub const EBDA_SCAN_LEN: u64 = 1024;
/// The legacy ROM window where firmware puts the RSDP when not in the
/// EBDA (SeaBIOS q35: ~0xF5xxx, measured).
pub const ROM_SCAN_BASE: u64 = 0xE_0000;
pub const ROM_SCAN_LEN: u64 = 0x2_0000; // ..0xF_FFFF
/// RSDP alignment per the ACPI spec: 16 bytes.
pub const SCAN_STRIDE: u64 = 16;
/// The only signature we scan for.
pub const RSDP_SIG: &[u8; 8] = b"RSD PTR ";

/// What the discovery walk concluded. `Copy` end to end so callers can
/// log it without borrowing the scratch buffer.
//
// The Found variant dwarfs the others (it carries the parsed RSDP and
// DMAR). The kernel has no allocator, so boxing the payload is not an
// option; the enum is returned exactly once per boot into a known
// stack slot and copied out for logging, so the padding cost is paid
// once and deliberately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discovery {
    /// Full success: RSDP + directory + a parsed DMAR.
    Found {
        rsdp_pa: u64,
        rsdp: Rsdp,
        dir_pa: u64,
        dir_entries: usize,
        dmar_pa: u64,
        dmar: Dmar,
    },
    /// The firmware tables parsed fine but carry no DMAR: no IOMMU on
    /// this machine (the q35-without-intel-iommu lane).
    NoDmar {
        rsdp_pa: u64,
        rsdp: Rsdp,
        dir_pa: u64,
        dir_entries: usize,
    },
    /// No usable firmware path to a DMAR — the fail-closed outcome.
    Failed(DiscoveryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    /// No RSDP signature in either window (nothing to walk).
    NoRsdp,
    /// Signatures existed but every candidate failed validation
    /// (carries the last parser error).
    BadRsdp(DmarError),
    /// The RSDT/XSDT itself is malformed.
    BadDir(DmarError),
    /// A DMAR entry exists but the table fails validation — the
    /// parser's error is the evidence.
    BadDmar(DmarError),
}

/// Read one byte at physical `pa` through a 4-byte-aligned `u32` read
/// (little-endian word, byte selected by pure arithmetic). This is the
/// whole trick that keeps this module unsafe-free: `memops::read_u32`
/// is the allowlisted primitive and it demands alignment, so unaligned
/// table addresses never reach it.
#[must_use]
pub fn read_byte(pa: u64) -> u8 {
    let word = crate::memops::read_u32(pa & !3);
    ((word >> (8 * (pa & 3))) & 0xFF) as u8
}

/// Read `buf.len()` bytes at physical `pa`, one word-aligned read per
/// byte. RAM only (firmware tables) — never MMIO.
pub fn read_bytes(pa: u64, buf: &mut [u8]) {
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = read_byte(pa + i as u64);
    }
}

/// The EBDA segment from the BDA word, shifted to a linear address.
#[must_use]
pub fn ebda_base(seg_ptr_pa: u64) -> u64 {
    let lo = read_byte(seg_ptr_pa) as u64;
    let hi = read_byte(seg_ptr_pa + 1) as u64;
    (lo | hi << 8) << 4
}

/// Does the 8-byte signature at `pa` equal `sig`?
fn sig_at(pa: u64, sig: &[u8; 8]) -> bool {
    // Cheap first-byte reject, then the full compare.
    if read_byte(pa) != sig[0] {
        return false;
    }
    for (i, want) in sig.iter().enumerate().skip(1) {
        if read_byte(pa + i as u64) != *want {
            return false;
        }
    }
    true
}

/// Scan `[base, base+len)` on 16-byte boundaries for the RSDP
/// signature, starting at offset `from` (resilience: the caller
/// re-scans past a candidate that failed validation). Returns the
/// candidate's physical address.
fn scan_region(base: u64, len: u64, from: u64) -> Option<u64> {
    let mut off = from;
    while off + RSDP_SIG.len() as u64 <= len {
        let pa = base + off;
        if sig_at(pa, RSDP_SIG) {
            return Some(pa);
        }
        off += SCAN_STRIDE;
    }
    None
}

/// Read and validate an RSDP at `pa` (20 bytes rev 0, 36 bytes rev 2+).
fn read_rsdp(pa: u64, buf: &mut [u8]) -> Result<Rsdp, DmarError> {
    read_bytes(pa, &mut buf[..20]);
    let len = if buf[15] >= 2 { 36 } else { 20 };
    read_bytes(pa, &mut buf[..len]);
    dmar::parse_rsdp(&buf[..len])
}

/// Read a description table at `pa` into `buf` (header first for the
/// declared length, then the whole table). The ACPI checksum over the
/// declared length must sum to zero — a bit-flipped table is a
/// refusal, not a parsed table. Returns the table length.
fn read_table(pa: u64, buf: &mut [u8]) -> Result<usize, DmarError> {
    read_bytes(pa, &mut buf[..36]);
    let length = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if length < 36 || length as usize > buf.len() {
        return Err(DmarError::BadLength(length));
    }
    read_bytes(pa, &mut buf[..length as usize]);
    if !checksum_ok(&buf[..length as usize]) {
        return Err(DmarError::BadChecksum);
    }
    Ok(length as usize)
}

/// The ACPI checksum rule: every byte of the table, from the
/// signature to the last byte of the declared length, sums to zero
/// (mod 256). Pure — host-tested directly and through both callers.
pub fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

/// F12: the directory-walk validation gate. Before the HPET/MADT/
/// MCFG walks trust a table pointer they found in the RSDT/XSDT,
/// verify the signature, the declared length (36..=scratch), and the
/// checksum — a hostile or corrupted table is a refusal (`None`),
/// never a parsed one. Returns the validated length.
pub fn table_ok(pa: u64, want_sig: &[u8; 4], scratch: &mut [u8]) -> Option<u32> {
    if scratch.len() < 36 {
        return None;
    }
    read_bytes(pa, &mut scratch[..36]);
    if &scratch[..4] != want_sig {
        return None;
    }
    let length = u32::from_le_bytes([scratch[4], scratch[5], scratch[6], scratch[7]]);
    if (length as usize) < 36 || (length as usize) > scratch.len() {
        return None;
    }
    let len = length as usize;
    read_bytes(pa, &mut scratch[..len]);
    if !checksum_ok(&scratch[..len]) {
        return None;
    }
    Some(length)
}

/// The full walk, parameterized over the two scan windows so the host
/// tests drive the identical code path with planted images.
///
/// `ebda`: `(base, len)` of the EBDA scan window (skipped when None —
/// a machine without a BDA word). `rom`: `(base, len)` of the ROM
/// window. `buf` is the shared scratch (≥ `dmar::MAX_TABLE_BYTES`).
pub fn discover(ebda: Option<(u64, u64)>, rom: (u64, u64), buf: &mut [u8]) -> Discovery {
    // ── 1. RSDP: EBDA first, then the ROM window. A candidate that
    //    fails validation does not abort the scan — firmware may keep
    //    stale copies; the next valid one wins.
    let windows: [(u64, u64); 2] = [ebda.unwrap_or((0, 0)), rom];
    let mut rsdp_pa = 0u64;
    let mut rsdp = None;
    let mut last_rsdp_err = None;
    'rsdp: for &(base, len) in windows.iter() {
        if ebda.is_none() && base == 0 && len == 0 {
            continue;
        }
        let mut from = 0u64;
        while let Some(pa) = scan_region(base, len, from) {
            match read_rsdp(pa, buf) {
                Ok(r) => {
                    rsdp_pa = pa;
                    rsdp = Some(r);
                    break 'rsdp;
                }
                Err(e) => {
                    last_rsdp_err = Some(e);
                    from = pa - base + SCAN_STRIDE;
                }
            }
        }
    }
    let Some(rsdp) = rsdp else {
        return Discovery::Failed(match last_rsdp_err {
            Some(e) => DiscoveryError::BadRsdp(e),
            None => DiscoveryError::NoRsdp,
        });
    };

    // ── 2. the directory: XSDT when rev 2+ carries one, else RSDT.
    //    (SeaBIOS emits rev 0 + RSDT; both paths are host-tested.)
    let (dir_pa, is_xsdt) = if rsdp.revision >= 2 && rsdp.xsdt_addr != 0 {
        (rsdp.xsdt_addr, true)
    } else {
        (u64::from(rsdp.rsdt_addr), false)
    };
    let dir = match read_table(dir_pa, buf) {
        Ok(len) => {
            if is_xsdt {
                dmar::parse_xsdt(&buf[..len])
            } else {
                dmar::parse_rsdt(&buf[..len])
            }
        }
        Err(e) => return Discovery::Failed(DiscoveryError::BadDir(e)),
    };
    let dir = match dir {
        Ok(d) => d,
        Err(e) => return Discovery::Failed(DiscoveryError::BadDir(e)),
    };

    // ── 3. find the DMAR among the directory entries. Other tables
    //    are not ours to validate: skip by signature, read only ours.
    for i in 0..dir.count {
        let table_pa = dir.addrs[i];
        if table_pa == 0 {
            continue;
        }
        let mut sig = [0u8; 8];
        read_bytes(table_pa, &mut sig);
        if &sig[..4] != b"DMAR" {
            continue;
        }
        return match read_table(table_pa, buf) {
            Ok(len) => match dmar::parse_dmar(&buf[..len]) {
                Ok(d) => Discovery::Found {
                    rsdp_pa,
                    rsdp,
                    dir_pa,
                    dir_entries: dir.count,
                    dmar_pa: table_pa,
                    dmar: d,
                },
                Err(e) => Discovery::Failed(DiscoveryError::BadDmar(e)),
            },
            Err(e) => Discovery::Failed(DiscoveryError::BadDmar(e)),
        };
    }
    Discovery::NoDmar {
        rsdp_pa,
        rsdp,
        dir_pa,
        dir_entries: dir.count,
    }
}

/// The kernel entry point: the real machine's windows (target-only —
/// reading host VA 0x40E on a test build would be nonsense).
#[cfg(not(test))]
pub fn discover_boot(buf: &mut [u8]) -> Discovery {
    let ebda = ebda_base(EBDA_SEG_PTR);
    // A zero/garbage BDA word means "no EBDA to scan": the ROM window
    // is the standard fallback and SeaBIOS q35 keeps the RSDP there.
    let ebda_window = if (0x400..0xA_0000).contains(&ebda) {
        Some((ebda, EBDA_SCAN_LEN))
    } else {
        None
    };
    discover(ebda_window, (ROM_SCAN_BASE, ROM_SCAN_LEN), buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake physical memory image: host "physical" addresses are
    /// offsets into a plain buffer (memops translates by identity in
    /// test builds — its own discipline, reused here). The store is
    /// u64-backed so every aligned `memops::read_u32`/`write_u32` this
    /// module performs lands inside the allocation; `put` plants bytes
    /// through the same word-merge arithmetic the kernel would use.
    struct Image {
        words: Vec<u64>,
    }

    impl Image {
        fn new(len_bytes: usize) -> Self {
            Image {
                words: vec![0u64; len_bytes.div_ceil(8)],
            }
        }
        /// "Physical" address of an offset (16-byte-aligned offsets
        /// keep the scan math honest).
        fn pa(&self, off: usize) -> u64 {
            self.words.as_ptr() as u64 + off as u64
        }
        fn put(&mut self, off: usize, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                let pa = self.pa(off + i);
                let base = pa & !3;
                let shift = 8 * (pa & 3);
                let word = crate::memops::read_u32(base);
                crate::memops::write_u32(base, (word & !(0xFF << shift)) | ((*b as u32) << shift));
            }
        }
    }

    fn fix_sum(bytes: &mut [u8], cksum_idx: usize) {
        let sum: u8 = bytes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != cksum_idx)
            .fold(0u8, |a, (_, b)| a.wrapping_add(*b));
        bytes[cksum_idx] = sum.wrapping_neg();
    }

    /// rev-0 RSDP pointing at `rsdt_pa` (the SeaBIOS shape).
    fn build_rsdp_rev0(rsdt_pa: u64) -> Vec<u8> {
        let mut r = vec![0u8; 20];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[9..15].copy_from_slice(b"BOCHS ");
        r[15] = 0;
        r[16..20].copy_from_slice(&(rsdt_pa as u32).to_le_bytes());
        fix_sum(&mut r, 8);
        r
    }

    /// rev-2 RSDP with an XSDT pointer.
    fn build_rsdp_rev2(rsdt_pa: u32, xsdt_pa: u64) -> Vec<u8> {
        let mut r = vec![0u8; 36];
        r[..8].copy_from_slice(b"RSD PTR ");
        r[9..15].copy_from_slice(b"BOCHS ");
        r[15] = 2;
        r[16..20].copy_from_slice(&rsdt_pa.to_le_bytes());
        r[20..24].copy_from_slice(&36u32.to_le_bytes());
        r[24..32].copy_from_slice(&xsdt_pa.to_le_bytes());
        fix_sum(&mut r, 8);
        r
    }

    /// A description-table header (36 bytes) with a fixed checksum.
    fn sdt_header(sig: &[u8; 4], length: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(sig);
        out.extend_from_slice(&length.to_le_bytes());
        out.push(1); // revision
        out.push(0); // checksum (fixed later)
        out.extend_from_slice(b"BOCHS ");
        out.extend_from_slice(b"BHYVE   ");
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(b"BXPC");
        out.extend_from_slice(&1u32.to_le_bytes());
    }

    /// An RSDT/XSDT whose entries are `addrs`.
    fn build_dir(sig: &[u8; 4], addrs: &[u64]) -> Vec<u8> {
        let stride = if sig == b"XSDT" { 8 } else { 4 };
        let mut t = vec![];
        sdt_header(sig, (36 + stride * addrs.len()) as u32, &mut t);
        for a in addrs {
            if stride == 8 {
                t.extend_from_slice(&a.to_le_bytes());
            } else {
                t.extend_from_slice(&(*a as u32).to_le_bytes());
            }
        }
        fix_sum(&mut t, 9);
        t
    }

    /// The measured QEMU q35 DMAR shape (one DRHD, 2 endpoint scopes).
    fn build_dmar() -> Vec<u8> {
        let mut t = vec![];
        sdt_header(b"DMAR", 48 + 32, &mut t); // header + one 32-byte DRHD
        t.push(47); // HAW raw: 48-bit
        t.push(0x01); // INTR_REMAP
        t.extend_from_slice(&[0u8; 10]);
        // DRHD: type 0, len 32, include_all=0, seg 0, base 0xFED90000,
        // two 8-byte endpoint scopes (00:1f.2 and 00:03.0).
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&32u16.to_le_bytes());
        t.push(0);
        t.push(0);
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&0xFED9_0000u64.to_le_bytes());
        t.extend_from_slice(&[1, 8, 0, 0, 0, 0x00, 0x1F, 2]);
        t.extend_from_slice(&[1, 8, 0, 0, 0, 0x00, 0x03, 0]);
        fix_sum(&mut t, 9);
        t
    }

    /// Plant the standard machine: rev-2 RSDP in the ROM window, XSDT
    /// with a DMAR (and one other table for realism). Offsets are
    /// 16-aligned relative to the scan base.
    fn plant(img: &mut Image) {
        let rom_off = 0x1000; // scan window base inside the image
        img.put(rom_off + 0x30, &build_rsdp_rev2(0, img.pa(rom_off + 0x200)));
        img.put(
            rom_off + 0x200,
            &build_dir(b"XSDT", &[img.pa(rom_off + 0x400), img.pa(rom_off + 0x600)]),
        );
        img.put(rom_off + 0x400, &build_dir(b"FACP", &[])); // a non-DMAR table
        img.put(rom_off + 0x600, &build_dmar());
    }

    const WIN: usize = 0x1000;
    const WIN_LEN: u64 = 0x800;

    fn discover_on(img: &Image, buf: &mut [u8]) -> Discovery {
        discover(None, (img.pa(WIN), WIN_LEN), buf)
    }

    // NOTE ON THE rev-0/RSDT (32-bit) PATH: a host fake image lives at
    // heap VAs (> 4 GiB) that cannot ride the RSDP's 32-bit RSDT
    // pointer, so the full-walk host tests below all use rev-2 RSDPs +
    // XSDT directories (64-bit everywhere). The rev-0/RSDT path is
    // exactly the SeaBIOS machine shape, and it is proven twice: by the
    // policy parser's own host tests (`aegis_os::dmar`: rev-0 RSDP
    // pin, RSDT six-entry pin, checksum/truncation) and end-to-end by
    // the q35 boot lane against real SeaBIOS firmware (rev 0, measured
    // RSDT @ 0x7FE23C9 — the `[IOMMU]` markers CI greps).

    #[test]
    fn read_byte_extracts_every_lane_of_the_word() {
        // The unaligned-byte trick this module stands on: a word write
        // read back byte-by-byte at all four sub-offsets.
        let img = Image::new(64);
        let pa = img.pa(0);
        crate::memops::write_u32(pa, 0x11_22_33_44);
        assert_eq!(read_byte(pa), 0x44);
        assert_eq!(read_byte(pa + 1), 0x33);
        assert_eq!(read_byte(pa + 2), 0x22);
        assert_eq!(read_byte(pa + 3), 0x11);
    }

    #[test]
    fn read_bytes_roundtrips_unaligned_ranges() {
        let img = Image::new(64);
        let pa = img.pa(3); // deliberately unaligned
        let src: Vec<u8> = (0u8..=19).collect();
        for (i, b) in src.iter().enumerate() {
            // byte-granular writes through aligned words: write_byte
            // does not exist (that is the point), so plant via masks.
            let w = crate::memops::read_u32((pa + i as u64) & !3);
            let shift = 8 * ((pa + i as u64) & 3);
            let cleared = w & !(0xFF << shift);
            crate::memops::write_u32((pa + i as u64) & !3, cleared | ((*b as u32) << shift));
        }
        let mut out = [0u8; 20];
        read_bytes(pa, &mut out);
        assert_eq!(&out, &src[..]);
    }

    #[test]
    fn ebda_base_reads_the_bda_segment_word() {
        // The BDA word at 0x40E is itself UNALIGNED on x86 (0x40E % 4
        // == 2) — cover both word lanes of the extraction.
        let img = Image::new(64);
        // Aligned lane: u16 0x9FC0 at offset 0 → linear 0x9FC00.
        crate::memops::write_u32(img.pa(0), 0x0000_9FC0);
        assert_eq!(ebda_base(img.pa(0)), 0x9_FC00);
        // Odd lane: the same u16 at offset 2 rides the word's high half.
        crate::memops::write_u32(img.pa(0), 0x9FC0_0000);
        assert_eq!(ebda_base(img.pa(2)), 0x9_FC00);
    }

    #[test]
    fn discover_finds_the_full_path() {
        let mut img = Image::new(0x2000);
        plant(&mut img);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        let d = discover_on(&img, &mut buf);
        let Discovery::Found {
            rsdp_pa,
            rsdp,
            dir_pa,
            dir_entries,
            dmar_pa,
            dmar,
        } = d
        else {
            panic!("expected Found, got {d:?}");
        };
        assert_eq!(rsdp_pa, img.pa(WIN + 0x30));
        assert_eq!(rsdp.revision, 2);
        assert_eq!(rsdp.xsdt_addr, dir_pa);
        assert_eq!(dir_pa, img.pa(WIN + 0x200));
        assert_eq!(dir_entries, 2, "FACP + DMAR");
        assert_eq!(dmar_pa, img.pa(WIN + 0x600));
        assert_eq!(dmar.haw_bits, 48);
        assert!(dmar.intr_remap);
        assert_eq!(dmar.structure_count, 1);
        assert!(
            dmar.find_drhd_for(0, 0, 0x03, 0).is_some(),
            "the virtio-blk scope"
        );
    }

    #[test]
    fn discover_skips_a_decoy_and_finds_the_real_rsdp() {
        // A stale/broken RSDP earlier in the window: signature matches,
        // checksum does not. The walk must continue to the valid one.
        let mut img = Image::new(0x2000);
        plant(&mut img);
        let mut decoy = build_rsdp_rev0(0);
        decoy[8] ^= 0x40; // break the checksum
        img.put(WIN + 0x10, &decoy);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        let Discovery::Found { rsdp_pa, .. } = discover_on(&img, &mut buf) else {
            panic!("resilient scan expected");
        };
        assert_eq!(rsdp_pa, img.pa(WIN + 0x30), "the decoy was skipped");
    }

    #[test]
    fn discover_without_dmar_is_no_dmar_not_failure() {
        let mut img = Image::new(0x2000);
        img.put(WIN + 0x30, &build_rsdp_rev2(0, img.pa(WIN + 0x200)));
        img.put(WIN + 0x200, &build_dir(b"XSDT", &[img.pa(WIN + 0x400)]));
        img.put(WIN + 0x400, &build_dir(b"FACP", &[]));
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        let Discovery::NoDmar { dir_entries, .. } = discover_on(&img, &mut buf) else {
            panic!("expected NoDmar");
        };
        assert_eq!(dir_entries, 1);
    }

    #[test]
    fn discover_with_no_rsdp_fails_no_rsdp() {
        let img = Image::new(0x2000);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        assert_eq!(
            discover_on(&img, &mut buf),
            Discovery::Failed(DiscoveryError::NoRsdp)
        );
    }

    #[test]
    fn discover_with_only_broken_rsdps_reports_bad_rsdp() {
        let mut img = Image::new(0x2000);
        let mut broken = build_rsdp_rev0(0);
        broken[8] ^= 0x40;
        img.put(WIN + 0x10, &broken);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        assert!(matches!(
            discover_on(&img, &mut buf),
            Discovery::Failed(DiscoveryError::BadRsdp(_))
        ));
    }

    #[test]
    fn discover_with_malformed_dir_reports_bad_dir() {
        let mut img = Image::new(0x2000);
        img.put(WIN + 0x30, &build_rsdp_rev2(0, img.pa(WIN + 0x200)));
        let mut bad = build_dir(b"XSDT", &[img.pa(WIN + 0x400)]);
        bad[9] ^= 0x20; // break the checksum
        img.put(WIN + 0x200, &bad);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        assert!(matches!(
            discover_on(&img, &mut buf),
            Discovery::Failed(DiscoveryError::BadDir(_))
        ));
    }

    #[test]
    fn discover_with_malformed_dmar_reports_bad_dmar() {
        let mut img = Image::new(0x2000);
        img.put(WIN + 0x30, &build_rsdp_rev2(0, img.pa(WIN + 0x200)));
        img.put(WIN + 0x200, &build_dir(b"XSDT", &[img.pa(WIN + 0x400)]));
        let mut bad = build_dmar();
        bad[9] ^= 0x20; // checksum: the parser refuses, we surface it
        img.put(WIN + 0x400, &bad);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        assert!(matches!(
            discover_on(&img, &mut buf),
            Discovery::Failed(DiscoveryError::BadDmar(_))
        ));
    }

    #[test]
    fn discover_walks_the_xsdt_path() {
        let mut img = Image::new(0x2000);
        img.put(WIN + 0x30, &build_rsdp_rev2(0, img.pa(WIN + 0x200)));
        img.put(WIN + 0x200, &build_dir(b"XSDT", &[img.pa(WIN + 0x600)]));
        img.put(WIN + 0x600, &build_dmar());
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        let Discovery::Found { dmar, dir_pa, .. } = discover_on(&img, &mut buf) else {
            panic!("expected Found via XSDT");
        };
        assert_eq!(dir_pa, img.pa(WIN + 0x200));
        assert_eq!(dmar.haw_bits, 48);
    }

    #[test]
    fn discover_tolerates_unaligned_tables_everywhere() {
        // The SeaBIOS reality (RSDT @ ...C9): plant every table at a
        // +9 offset. Only the RSDP itself must stay 16-aligned.
        let mut img = Image::new(0x2000);
        img.put(WIN + 0x30, &build_rsdp_rev2(0, img.pa(WIN + 0x200) + 9));
        img.put(
            WIN + 0x200 + 9,
            &build_dir(b"XSDT", &[img.pa(WIN + 0x400) + 9]),
        );
        img.put(WIN + 0x400 + 9, &build_dmar());
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        let Discovery::Found { dmar, .. } = discover_on(&img, &mut buf) else {
            panic!("unaligned tables must parse");
        };
        assert_eq!(dmar.haw_bits, 48);
    }

    #[test]
    fn discover_scans_the_ebda_window_first() {
        // RSDP in the "EBDA" window, none in the ROM window: found.
        let mut img = Image::new(0x2000);
        img.put(0x40, &build_rsdp_rev2(0, img.pa(0x300)));
        img.put(0x300, &build_dir(b"XSDT", &[img.pa(0x500)]));
        img.put(0x500, &build_dmar());
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        let d = discover(Some((img.pa(0), 0x400)), (img.pa(WIN), WIN_LEN), &mut buf);
        let Discovery::Found { rsdp_pa, .. } = d else {
            panic!("EBDA scan must find it, got {d:?}");
        };
        assert_eq!(rsdp_pa, img.pa(0x40));
    }

    #[test]
    fn scan_signature_checks_all_eight_bytes() {
        let mut img = Image::new(0x100);
        let base = img.pa(0);
        // "RSD PTX " — first byte matches, eighth does not.
        img.put(0, b"RSD PTX ");
        assert_eq!(scan_region(base, 0x100, 0), None);
        img.put(0, b"RSD PTR ");
        assert_eq!(scan_region(base, 0x100, 0), Some(base));
        // The `from` offset restarts past a rejected candidate.
        assert_eq!(scan_region(base, 0x100, 16), None);
    }

    #[test]
    fn read_table_enforces_the_declared_length_bounds() {
        let img = Image::new(0x100);
        let pa = img.pa(0);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        // Length 12: below the 36-byte header floor.
        crate::memops::write_u32(pa + 4, 12);
        assert!(matches!(
            read_table(pa, &mut buf),
            Err(DmarError::BadLength(12))
        ));
        // Length beyond any table we will ever parse.
        crate::memops::write_u32(pa + 4, 8192);
        assert!(matches!(
            read_table(pa, &mut buf),
            Err(DmarError::BadLength(8192))
        ));
    }

    // ── F12: the firmware-table validation gate ──

    #[test]
    fn checksum_ok_sums_to_zero() {
        assert!(checksum_ok(&[]));
        assert!(checksum_ok(&[0x41, 0x42, 0x43, 0x44, 0xF6])); // 0x10A + 0xF6 -> 0 (mod 256)
        assert!(!checksum_ok(&[1]));
        assert!(!checksum_ok(&[0x41, 0x42, 0x43, 0x44, 0xF7])); // one off
                                                                // wrapping: 0xFF + 0x01 = 0 (mod 256)
        assert!(checksum_ok(&[0xFF, 0x01]));
    }

    #[test]
    fn table_ok_accepts_a_valid_table() {
        let mut img = Image::new(0x1000);
        let off = 0x100;
        img.put(off, &build_dmar());
        let mut scratch = [0u8; 1024];
        assert_eq!(table_ok(img.pa(off), b"DMAR", &mut scratch), Some(48 + 32));
    }

    #[test]
    fn table_ok_refuses_broken_checksum() {
        let mut img = Image::new(0x1000);
        let off = 0x100;
        let mut dmar = build_dmar();
        dmar[20] ^= 0x40; // corrupt OEMID — checksum no longer sums to 0
        img.put(off, &dmar);
        let mut scratch = [0u8; 1024];
        assert_eq!(table_ok(img.pa(off), b"DMAR", &mut scratch), None);
    }

    #[test]
    fn table_ok_refuses_wrong_signature() {
        let mut img = Image::new(0x1000);
        let off = 0x100;
        img.put(off, &build_dmar());
        let mut scratch = [0u8; 1024];
        assert_eq!(table_ok(img.pa(off), b"HPET", &mut scratch), None);
    }

    #[test]
    fn table_ok_refuses_hostile_lengths() {
        let mut img = Image::new(0x1000);
        let off = 0x100;
        for bad in [0u32, 35, 1025, u32::MAX] {
            let mut dmar = build_dmar();
            dmar[4..8].copy_from_slice(&bad.to_le_bytes());
            // keep the whole-table checksum honest so ONLY the length
            // is under test
            let sum: u8 = dmar.iter().fold(0u8, |a, b| a.wrapping_add(*b));
            dmar[9] = dmar[9].wrapping_sub(sum);
            img.put(off, &dmar);
            let mut scratch = [0u8; 1024];
            assert_eq!(
                table_ok(img.pa(off), b"DMAR", &mut scratch),
                None,
                "len={bad}"
            );
        }
        // the minimum legal table (exactly the 36-byte header, honest
        // checksum) is accepted with its length.
        img.put(off, &build_dir(b"DMAR", &[]));
        let mut scratch = [0u8; 1024];
        assert_eq!(table_ok(img.pa(off), b"DMAR", &mut scratch), Some(36));
    }

    #[test]
    fn read_table_rejects_checksum_corruption() {
        // RED on the pre-F12 code: the DMAR path accepted any table
        // whose declared length fit the scratch — a bit-flipped table
        // was a parsed table.
        let mut img = Image::new(0x1000);
        let off = 0x100;
        let mut dmar = build_dmar();
        dmar[24] ^= 0x80; // corrupt a reserved byte
        img.put(off, &dmar);
        let mut buf = [0u8; dmar::MAX_TABLE_BYTES];
        assert!(matches!(
            read_table(img.pa(off), &mut buf),
            Err(DmarError::BadChecksum)
        ));
        // and the uncorrupted table still reads.
        img.put(off, &build_dmar());
        assert!(read_table(img.pa(off), &mut buf).is_ok());
    }
}
