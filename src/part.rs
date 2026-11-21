//! Partition tables: GPT (the UEFI world) and the protective MBR it
//! rides on. Until now the storage stack read raw LBAs and every
//! image was a filesystem at LBA 0 — this module gives the kernel the
//! on-disk structure that every real disk carries.
//!
//! Everything here is pure over sector bytes and host-tested against
//! hostile fixtures (bad signatures, stale CRCs, absurd geometries,
//! overlapping partitions): a corrupted table is a typed refusal,
//! never a read of a wrong LBA. The CRC is IEEE-802.3 CRC-32 (the
//! reflected 0xEDB88320 polynomial) — the one GPT specifies — with a
//! compile-time table.

// ── CRC-32 (IEEE, reflected) ──────────────────────────────────────────

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// The reflected CRC-32 table (compile-time — no runtime init, no
/// unsafe).
static CRC_TABLE: [u32; 256] = crc_table();

/// CRC-32 of `bytes` (the GPT checksum).
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    crc32_seed(bytes, 0xFFFF_FFFF) ^ 0xFFFF_FFFF
}

/// The incremental form: continue a CRC over another slice. GPT needs
/// it twice (header with its CRC field zeroed, then the entry array).
#[must_use]
pub fn crc32_seed(bytes: &[u8], seed: u32) -> u32 {
    let mut c = seed;
    for &b in bytes {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

// ── the protective MBR ────────────────────────────────────────────────

/// One sector.
pub const SECTOR: usize = 512;
/// The MBR signature at byte 510.
pub const MBR_SIG: u16 = 0xAA55;
/// Partition type 0xEE: the protective entry that says "GPT below".
pub const MBR_PROTECTIVE_TYPE: u8 = 0xEE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartError {
    Short,
    BadMbrSignature,
    BadGptSignature,
    BadHeaderSize(u32),
    BadHeaderCrc,
    BadEntriesCrc,
    BadEntrySize(u32),
    TooManyEntries(u32),
    BadGeometry,
    Overlap,
}

/// One MBR partition entry (the protective one only — classic MBR
/// booting is out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    pub type_: u8,
    pub start_lba: u32,
    pub sectors: u32,
}

/// Is the sector a valid MBR (signature in place)?
#[must_use]
pub fn mbr_signature_ok(sector: &[u8]) -> bool {
    sector.len() >= SECTOR
        && sector[510] == 0x55
        && sector[511] == 0xAA
}

/// Is it a PROTECTIVE MBR — the GPT handoff? (Signature + an 0xEE
/// entry.)
#[must_use]
pub fn is_protective_mbr(sector: &[u8]) -> bool {
    if !mbr_signature_ok(sector) {
        return false;
    }
    (0..4).any(|i| sector[446 + i * 16 + 4] == MBR_PROTECTIVE_TYPE)
}

/// Parse the four MBR entries (hostile: signature first).
pub fn parse_mbr(sector: &[u8]) -> Result<[Option<MbrPartition>; 4], PartError> {
    if sector.len() < SECTOR {
        return Err(PartError::Short);
    }
    if !mbr_signature_ok(sector) {
        return Err(PartError::BadMbrSignature);
    }
    let mut out = [None; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let e = 446 + i * 16;
        let type_ = sector[e + 4];
        if type_ == 0 {
            continue; // unused
        }
        let start = u32::from_le_bytes([sector[e + 8], sector[e + 9], sector[e + 10], sector[e + 11]]);
        let sectors =
            u32::from_le_bytes([sector[e + 12], sector[e + 13], sector[e + 14], sector[e + 15]]);
        // start + sectors must not wrap: the partition ends inside
        // the 32-bit LBA space.
        if start.checked_add(sectors).is_none() {
            return Err(PartError::BadGeometry);
        }
        *slot = Some(MbrPartition { type_, start_lba: start, sectors });
    }
    Ok(out)
}

// ── GPT ───────────────────────────────────────────────────────────────

/// The GPT header signature.
pub const GPT_SIG: &[u8; 8] = b"EFI PART";
/// The header size revision 1.0 carries (the CRC covers exactly this).
pub const GPT_HEADER_SIZE: usize = 92;
/// How many partitions this parser records (one sector of 128-byte
/// entries).
pub const MAX_PARTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptHeader {
    pub my_lba: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub entries_lba: u64,
    pub num_entries: u32,
    pub entry_size: u32,
}

/// One GPT partition entry (the name truncated to 36 ASCII bytes of
/// the UTF-16LE field — enough for the boot log, honest about it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartition {
    pub first_lba: u64,
    pub last_lba: u64,
    pub name: [u8; 36],
    pub name_len: usize,
}

impl GptPartition {
    /// The partition's name as a &str (lossy ASCII — the fixture
    /// names are ASCII).
    #[must_use]
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gpt {
    pub header: GptHeader,
    pub parts: [Option<GptPartition>; MAX_PARTS],
    pub count: usize,
}

/// The GPT header word reader (little-endian u32 at offset).
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

/// Parse and CRC-verify the GPT header from LBA1's bytes. The stored
/// CRC at +16 is verified against the header with that field ZEROED
/// (the spec's rule); header_size must be exactly 92 (rev 1.0) and
/// the geometry sane.
pub fn parse_gpt_header(sector: &[u8]) -> Result<GptHeader, PartError> {
    if sector.len() < GPT_HEADER_SIZE {
        return Err(PartError::Short);
    }
    if &sector[..8] != GPT_SIG {
        return Err(PartError::BadGptSignature);
    }
    let header_size = le32(sector, 12) as usize;
    if header_size != GPT_HEADER_SIZE {
        return Err(PartError::BadHeaderSize(header_size as u32));
    }
    // CRC: over bytes 0..92 with the CRC field (16..20) zeroed.
    let mut crc_bytes = [0u8; GPT_HEADER_SIZE];
    crc_bytes.copy_from_slice(&sector[..GPT_HEADER_SIZE]);
    crc_bytes[16..20].fill(0);
    if crc32(&crc_bytes) != le32(sector, 16) {
        return Err(PartError::BadHeaderCrc);
    }
    let hdr = GptHeader {
        my_lba: le64(sector, 24),
        first_usable: le64(sector, 40),
        last_usable: le64(sector, 48),
        entries_lba: le64(sector, 72),
        num_entries: le32(sector, 80),
        entry_size: le32(sector, 84),
    };
    // Geometry sanity: the usable window must order, the entry array
    // must sit before the usable window, entries must be 128-byte
    // aligned in size, and the table must fit what this parser reads
    // (one sector — more entries is a machine this parser refuses,
    // loudly).
    if hdr.first_usable > hdr.last_usable || hdr.first_usable == 0 {
        return Err(PartError::BadGeometry);
    }
    if hdr.entries_lba == 0 || hdr.entries_lba >= hdr.first_usable {
        return Err(PartError::BadGeometry);
    }
    if hdr.entry_size < 128 || hdr.entry_size as usize > SECTOR || hdr.entry_size % 128 != 0 {
        return Err(PartError::BadEntrySize(hdr.entry_size));
    }
    let table_bytes = hdr.num_entries as usize * hdr.entry_size as usize;
    if table_bytes == 0 || table_bytes > SECTOR {
        return Err(PartError::TooManyEntries(hdr.num_entries));
    }
    if hdr.my_lba != 1 {
        // This parser reads the PRIMARY header (LBA1); a header that
        // claims to be the backup is the wrong sector.
        return Err(PartError::BadGeometry);
    }
    Ok(hdr)
}

/// Parse + CRC-verify the entry array (the sector at
/// header.entries_lba). `stored_crc` is the header's entries-CRC field
/// (+88). Every recorded partition is bounds-checked against the
/// usable window, and partitions may not overlap.
pub fn parse_gpt_entries(
    bytes: &[u8],
    header: &GptHeader,
    stored_crc: u32,
) -> Result<Gpt, PartError> {
    let table_bytes = header.num_entries as usize * header.entry_size as usize;
    if bytes.len() < table_bytes {
        return Err(PartError::Short);
    }
    if crc32(&bytes[..table_bytes]) != stored_crc {
        return Err(PartError::BadEntriesCrc);
    }
    let mut parts = [None; MAX_PARTS];
    let mut count = 0usize;
    for i in 0..header.num_entries as usize {
        let e = i * header.entry_size as usize;
        // All-zero type GUID: an unused slot.
        if bytes[e..e + 16].iter().all(|&b| b == 0) {
            continue;
        }
        let first_lba = le64(bytes, e + 32);
        let last_lba = le64(bytes, e + 40);
        if first_lba < header.first_usable || last_lba > header.last_usable || first_lba > last_lba
        {
            return Err(PartError::BadGeometry);
        }
        // The name: 72 bytes of UTF-16LE at +56; keep the ASCII
        // prefix (a non-ASCII or overlong name truncates honestly).
        let mut name = [0u8; 36];
        let mut name_len = 0usize;
        let mut j = 0usize;
        while j < 72 && name_len < 36 {
            let lo = bytes[e + 56 + j];
            let hi = bytes[e + 56 + j + 1];
            if lo == 0 && hi == 0 {
                break;
            }
            if (0x20..0x7F).contains(&lo) && hi == 0 {
                name[name_len] = lo;
                name_len += 1;
            }
            j += 2;
        }
        if count == MAX_PARTS {
            return Err(PartError::TooManyEntries(count as u32));
        }
        parts[count] = Some(GptPartition { first_lba, last_lba, name, name_len });
        count += 1;
    }
    // Overlap: no two partitions may share an LBA.
    for a in 0..count {
        for b in (a + 1)..count {
            let pa = parts[a].expect("count covers");
            let pb = parts[b].expect("count covers");
            if pa.first_lba <= pb.last_lba && pb.first_lba <= pa.last_lba {
                return Err(PartError::Overlap);
            }
        }
    }
    Ok(Gpt { header: *header, parts, count })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classic CRC-32 check vector.
    #[test]
    fn crc32_matches_the_reference_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
        // Incremental == one-shot.
        let one = crc32(b"abcdefgh");
        let two = crc32_seed(b"abcd", 0xFFFF_FFFF);
        assert_eq!(crc32_seed(b"efgh", two) ^ 0xFFFF_FFFF, one);
    }

    fn protective_mbr() -> [u8; 512] {
        let mut m = [0u8; 512];
        m[510] = 0x55;
        m[511] = 0xAA;
        // Entry 0: type 0xEE, start 1, sectors 0xFFFFFFFF... sane:
        // start 1, sectors 289.
        m[446 + 4] = 0xEE;
        m[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        m[446 + 12..446 + 16].copy_from_slice(&289u32.to_le_bytes());
        m
    }

    #[test]
    fn the_protective_mbr_parses_and_detects() {
        let m = protective_mbr();
        assert!(mbr_signature_ok(&m));
        assert!(is_protective_mbr(&m));
        let parts = parse_mbr(&m).expect("valid MBR");
        assert_eq!(
            parts[0],
            Some(MbrPartition { type_: 0xEE, start_lba: 1, sectors: 289 })
        );
        assert_eq!(parts[1], None);
        // No signature: refuse.
        let mut bad = m;
        bad[510] = 0;
        assert_eq!(parse_mbr(&bad), Err(PartError::BadMbrSignature));
        assert!(!is_protective_mbr(&bad));
        // A valid MBR without the 0xEE entry is NOT protective.
        let mut plain = m;
        plain[446 + 4] = 0x83;
        assert!(!is_protective_mbr(&plain));
        // A wrapping entry (start + sectors overflows): refuse.
        let mut wrap = m;
        wrap[446 + 8..446 + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        wrap[446 + 12..446 + 16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse_mbr(&wrap), Err(PartError::BadGeometry));
    }

    /// A GPT fixture: header + one "aegis-root" partition at LBA
    /// 34..=289 — the exact picture mkgpt builds.
    fn gpt_fixture() -> ([u8; 512], [u8; 512]) {
        let mut h = [0u8; 512];
        h[..8].copy_from_slice(GPT_SIG);
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // rev 1.0
        h[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
        h[24..32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
        h[32..40].copy_from_slice(&291u64.to_le_bytes()); // backup
        h[40..48].copy_from_slice(&34u64.to_le_bytes()); // first usable
        h[48..56].copy_from_slice(&289u64.to_le_bytes()); // last usable
        h[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA
        h[80..84].copy_from_slice(&4u32.to_le_bytes()); // 4 entries
        h[84..88].copy_from_slice(&128u32.to_le_bytes()); // entry size
        // Entries: one partition.
        let mut e = [0u8; 512];
        e[0..16].copy_from_slice(&[
            0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47,
            0x7D, 0xE4,
        ]); // Linux fs type GUID
        e[32..40].copy_from_slice(&34u64.to_le_bytes());
        e[40..48].copy_from_slice(&289u64.to_le_bytes());
        let name = "aegis-root";
        for (i, ch) in name.bytes().enumerate() {
            e[56 + i * 2] = ch;
        }
        // Entries CRC covers all 4 entries (512 bytes) — written
        // FIRST: the header CRC (next) covers the whole 92 bytes
        // including this field.
        h[88..92].copy_from_slice(&crc32(&e).to_le_bytes());
        // Header CRC: the whole header with the CRC field zeroed.
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&h[..92]);
        hc[16..20].fill(0);
        h[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        (h, e)
    }

    #[test]
    fn the_gpt_fixture_parses_end_to_end() {
        let (h, e) = gpt_fixture();
        let hdr = parse_gpt_header(&h).expect("header parses");
        assert_eq!(hdr.first_usable, 34);
        assert_eq!(hdr.last_usable, 289);
        assert_eq!(hdr.entries_lba, 2);
        assert_eq!(hdr.num_entries, 4);
        assert_eq!(hdr.entry_size, 128);
        let gpt = parse_gpt_entries(&e, &hdr, le32(&h, 88)).expect("entries parse");
        assert_eq!(gpt.count, 1);
        let p = gpt.parts[0].expect("the partition");
        assert_eq!(p.first_lba, 34);
        assert_eq!(p.last_lba, 289);
        assert_eq!(p.name_str(), "aegis-root");
    }

    #[test]
    fn hostile_gpt_headers_refuse_typed() {
        let (h, e) = gpt_fixture();
        // Short.
        assert_eq!(parse_gpt_header(&h[..64]), Err(PartError::Short));
        // Signature.
        let mut bad = h;
        bad[0] = b'X';
        assert_eq!(parse_gpt_header(&bad), Err(PartError::BadGptSignature));
        // Header CRC.
        let mut bad = h;
        bad[80] ^= 0xFF; // num_entries corrupted → CRC mismatch
        assert_eq!(parse_gpt_header(&bad), Err(PartError::BadHeaderCrc));
        // Wrong header size.
        let mut bad = h;
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&bad[..92]);
        hc[16..20].fill(0);
        hc[12..16].copy_from_slice(&93u32.to_le_bytes());
        bad[12..16].copy_from_slice(&93u32.to_le_bytes());
        bad[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        assert!(matches!(
            parse_gpt_header(&bad),
            Err(PartError::BadHeaderSize(_))
        ));
        // Entry size < 128.
        let mut bad = h;
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&bad[..92]);
        hc[16..20].fill(0);
        hc[84..88].copy_from_slice(&64u32.to_le_bytes());
        bad[84..88].copy_from_slice(&64u32.to_le_bytes());
        bad[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        assert!(matches!(parse_gpt_header(&bad), Err(PartError::BadEntrySize(_))));
        // Too many entries for one sector.
        let mut bad = h;
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&bad[..92]);
        hc[16..20].fill(0);
        hc[80..84].copy_from_slice(&5u32.to_le_bytes());
        bad[80..84].copy_from_slice(&5u32.to_le_bytes());
        bad[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        assert!(matches!(
            parse_gpt_header(&bad),
            Err(PartError::TooManyEntries(_))
        ));
        // A backup header handed in as primary.
        let mut bad = h;
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&bad[..92]);
        hc[16..20].fill(0);
        hc[24..32].copy_from_slice(&291u64.to_le_bytes());
        bad[24..32].copy_from_slice(&291u64.to_le_bytes());
        bad[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        assert_eq!(parse_gpt_header(&bad), Err(PartError::BadGeometry));
        let _ = e;
    }

    #[test]
    fn hostile_gpt_entries_refuse_typed() {
        let (h, e) = gpt_fixture();
        let hdr = parse_gpt_header(&h).expect("header");
        let stored = le32(&h, 88);
        // Corrupt one entry byte: entries CRC fails.
        let mut bad = e;
        bad[40] ^= 0xFF; // last_lba
        assert_eq!(
            parse_gpt_entries(&bad, &hdr, stored),
            Err(PartError::BadEntriesCrc)
        );
        // Beyond the usable window (rebuild CRCs to isolate the
        // geometry check).
        let mut g = e;
        g[32..40].copy_from_slice(&2u64.to_le_bytes()); // first < first_usable
        let mut h2 = h;
        h2[88..92].copy_from_slice(&crc32(&g).to_le_bytes());
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&h2[..92]);
        hc[16..20].fill(0);
        h2[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        let hdr2 = parse_gpt_header(&h2).expect("re-headered");
        assert_eq!(
            parse_gpt_entries(&g, &hdr2, crc32(&g)),
            Err(PartError::BadGeometry)
        );
        // Overlapping partitions.
        let mut o = [0u8; 512];
        for slot in [0usize, 128] {
            o[slot..slot + 16].copy_from_slice(&[1u8; 16]);
            o[slot + 32..slot + 40].copy_from_slice(&34u64.to_le_bytes());
            o[slot + 40..slot + 48].copy_from_slice(&100u64.to_le_bytes());
        }
        let mut h3 = h;
        h3[88..92].copy_from_slice(&crc32(&o).to_le_bytes());
        let mut hc = [0u8; 92];
        hc.copy_from_slice(&h3[..92]);
        hc[16..20].fill(0);
        h3[16..20].copy_from_slice(&crc32(&hc).to_le_bytes());
        let hdr3 = parse_gpt_header(&h3).expect("re-headered");
        assert_eq!(
            parse_gpt_entries(&o, &hdr3, crc32(&o)),
            Err(PartError::Overlap)
        );
        // first > last.
        let mut f = e;
        f[32..40].copy_from_slice(&200u64.to_le_bytes());
        f[40..48].copy_from_slice(&100u64.to_le_bytes());
        assert_eq!(
            parse_gpt_entries(&f, &hdr, crc32(&f)),
            Err(PartError::BadGeometry)
        );
        // Truncated entries slice.
        assert_eq!(
            parse_gpt_entries(&e[..256], &hdr, stored),
            Err(PartError::Short)
        );
    }
}
