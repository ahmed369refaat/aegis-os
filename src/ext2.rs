//! Read-only ext2 parsing — the policy core (F13, ADR-0014's
//! hardening follow-up).
//!
//! The bytes here arrive from a DISK (through AHCI or any future
//! transport): every field is hostile until validated. The parser is
//! pure — byte slices in, results out, no panics, no allocation —
//! so the host tests run the identical code against the real image
//! (the `mkext2.py` layout, mirrored by the test builder) and a
//! deterministic fuzz corpus of corrupted images.
//!
//! What the kernel keeps: the transport (sector reads), the boot
//! markers, and the decision to refuse. What moves here: every
//! on-disk structure and every bounds decision.

/// The ext2 magic (offset 56 in the superblock).
pub const MAGIC: u16 = 0xEF53;

/// The root directory's inode number (fixed by the format).
pub const ROOT_INO: u32 = 2;

/// The demo image's geometry (mirrors `mkext2.py`; the parser takes
/// geometry from the superblock itself, these bound the sanity).
pub const MAX_INODE_SIZE: u16 = 256;

/// Every way a hostile image is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext2Error {
    /// Superblock magic is not 0xEF53 (carries the value read).
    BadMagic(u16),
    /// Inode size is 0, not a power of two, or beyond 256 bytes.
    BadInodeSize(u16),
    /// A block number reaches past the device's block count.
    BlockOutOfRange { block: u32, blocks: u32 },
    /// An inode number is 0 or past the inode count.
    InodeOutOfRange { ino: u32, inodes: u32 },
    /// A directory record could not be walked: rec_len < 8 + name_len,
    /// not 4-aligned, zero, or running past the directory's size.
    BadDirent { off: u64, rec_len: u16 },
    /// A slice shorter than the structure being parsed.
    Truncated { need: usize, have: usize },
}

/// The superblock fields the walk consumes (offsets within the
/// 1024-byte superblock; the fields we read reach +88).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub inode_size: u16,
}

impl Superblock {
    /// Parse from the superblock bytes (`sb` needs at least 90 bytes;
    /// the caller's sector covers the fields the format pins there).
    pub fn parse(sb: &[u8]) -> Result<Superblock, Ext2Error> {
        if sb.len() < 90 {
            return Err(Ext2Error::Truncated {
                need: 90,
                have: sb.len(),
            });
        }
        let magic = u16::from_le_bytes([sb[56], sb[57]]);
        if magic != MAGIC {
            return Err(Ext2Error::BadMagic(magic));
        }
        let inode_size = u16::from_le_bytes([sb[88], sb[89]]);
        if inode_size == 0 || inode_size > MAX_INODE_SIZE || !inode_size.is_power_of_two() {
            return Err(Ext2Error::BadInodeSize(inode_size));
        }
        let rd = |o: usize| u32::from_le_bytes([sb[o], sb[o + 1], sb[o + 2], sb[o + 3]]);
        Ok(Superblock {
            inodes_count: rd(0),
            blocks_count: rd(4),
            inode_size,
        })
    }

    /// The byte offset of inode `ino` on the device, given the group's
    /// inode-table block (1 KiB blocks, rev 1 layout). Inode numbers
    /// are 1-based; the whole inode must land inside the device.
    pub fn inode_byte(&self, itable_block: u32, ino: u32) -> Result<u64, Ext2Error> {
        if ino == 0 || ino > self.inodes_count {
            return Err(Ext2Error::InodeOutOfRange {
                ino,
                inodes: self.inodes_count,
            });
        }
        // (ino-1) * inode_size + itable_block * 1024, with every step
        // checked against the device's block count.
        let idx = u64::from(ino - 1);
        let within = idx
            .checked_mul(u64::from(self.inode_size))
            .and_then(|o| o.checked_add(u64::from(itable_block) * 1024))
            .ok_or(Ext2Error::BlockOutOfRange {
                block: itable_block,
                blocks: self.blocks_count,
            })?;
        let end = within + u64::from(self.inode_size);
        if end > u64::from(self.blocks_count) * 1024 {
            return Err(Ext2Error::BlockOutOfRange {
                block: itable_block,
                blocks: self.blocks_count,
            });
        }
        Ok(within)
    }
}

/// The inode fields the walk consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inode {
    pub mode: u16,
    pub size: u32,
    /// i_block\[0\] — the first direct block (all this demo reads).
    pub block0: u32,
}

impl Inode {
    /// Parse one inode at `off` in `buf` (a sector or larger slice);
    /// the whole `inode_size` must fit from `off`.
    pub fn parse(buf: &[u8], off: usize, inode_size: u16) -> Result<Inode, Ext2Error> {
        let need = off + inode_size as usize;
        if buf.len() < need || off < 44 {
            return Err(Ext2Error::Truncated {
                need,
                have: buf.len(),
            });
        }
        let mode = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let size = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let block0 =
            u32::from_le_bytes([buf[off + 40], buf[off + 41], buf[off + 42], buf[off + 43]]);
        Ok(Inode { mode, size, block0 })
    }

    /// Directory bit of `mode` (0x4000).
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
}

/// Walk a directory block looking for `name`; `Ok(Some(ino))` when
/// found, `Ok(None)` when the directory simply does not contain it,
/// and an error only when the DIRECTORY ITSELF is malformed (a
/// hostile rec_len/name_len is a refusal, never a skipped record).
pub fn find_dirent(block: &[u8], dir_size: u32, name: &[u8]) -> Result<Option<u32>, Ext2Error> {
    // The walk is bounded by the directory's declared size, the block
    // (1 KiB), and the slice we actually have.
    let limit = u64::from(dir_size).min(1024).min(block.len() as u64);
    let mut off = 0u64;
    while off + 8 <= limit {
        let base = off as usize;
        let ino = u32::from_le_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
        ]);
        let rec_len = u16::from_le_bytes([block[base + 4], block[base + 5]]);
        let name_len = block[base + 6];
        // A record must hold its own header plus its name, stay
        // 4-aligned, and make progress. Two DISTINCT bounds: the
        // header + name must be inside the slice we actually have
        // (the caller may hand us one sector of a 1 KiB block), while
        // the record itself is bounded by the 1 KiB block — the last
        // dirent of a block legitimately pads `rec_len` to the block
        // end, past a 512-byte slice.
        if rec_len < 8 || !rec_len.is_multiple_of(4) || 8 + name_len as u16 > rec_len {
            return Err(Ext2Error::BadDirent { off, rec_len });
        }
        if off + 8 + name_len as u64 > limit {
            return Err(Ext2Error::BadDirent { off, rec_len });
        }
        if off + u64::from(rec_len) > 1024 {
            return Err(Ext2Error::BadDirent { off, rec_len });
        }
        if ino != 0 && name_len as usize == name.len() {
            let n = &block[base + 8..base + 8 + name.len()];
            if n == name {
                return Ok(Some(ino));
            }
        }
        off += u64::from(rec_len);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mkext2.py layout, mirrored: 128 × 1 KiB blocks, 16 inodes,
    /// root dir block 20, hello.txt inode 12 block 21.
    fn build_image() -> Vec<u8> {
        let mut img = vec![0u8; 128 * 1024];
        let put = |img: &mut Vec<u8>, off: usize, bytes: &[u8]| {
            img[off..off + bytes.len()].copy_from_slice(bytes);
        };
        // superblock at byte 1024
        let mut sb = vec![0u8; 1024];
        sb[0..4].copy_from_slice(&16u32.to_le_bytes()); // inodes_count
        sb[4..8].copy_from_slice(&128u32.to_le_bytes()); // blocks_count
        sb[56..58].copy_from_slice(&MAGIC.to_le_bytes());
        sb[88..90].copy_from_slice(&128u16.to_le_bytes()); // inode_size
        put(&mut img, 1024, &sb);
        // group descriptor at byte 2048: bg_inode_table @+8 = block 5
        let mut gdt = vec![0u8; 32];
        gdt[8..12].copy_from_slice(&5u32.to_le_bytes());
        put(&mut img, 2048, &gdt);
        // inodes at 5*1024 + (n-1)*128
        let inode = |img: &mut Vec<u8>, n: u32, mode: u16, size: u32, block0: u32| {
            let off = 5 * 1024 + ((n - 1) * 128) as usize;
            let mut e = vec![0u8; 128];
            e[0..2].copy_from_slice(&mode.to_le_bytes());
            e[4..8].copy_from_slice(&size.to_le_bytes());
            e[40..44].copy_from_slice(&block0.to_le_bytes());
            img[off..off + 128].copy_from_slice(&e);
        };
        inode(&mut img, 2, 0x41ED, 1024, 20);
        inode(&mut img, 12, 0x81A4, 17, 21);
        // root dir block 20: ".", "..", "hello.txt"
        let mut d = vec![0u8; 1024];
        let mut o = 0usize;
        for name in [&b"."[..], &b".."[..]] {
            let rec = (8 + name.len() + 3) & !3;
            d[o..o + 4].copy_from_slice(&2u32.to_le_bytes());
            d[o + 4..o + 6].copy_from_slice(&(rec as u16).to_le_bytes());
            d[o + 6] = name.len() as u8;
            d[o + 8..o + 8 + name.len()].copy_from_slice(name);
            o += rec;
        }
        d[o..o + 4].copy_from_slice(&12u32.to_le_bytes());
        d[o + 4..o + 6].copy_from_slice(&((1024 - o) as u16).to_le_bytes());
        d[o + 6] = 9;
        d[o + 8..o + 17].copy_from_slice(b"hello.txt");
        put(&mut img, 20 * 1024, &d);
        put(&mut img, 21 * 1024, b"HELLO-AEGIS-EXT2\n");
        img
    }

    #[test]
    fn the_real_image_parses_end_to_end() {
        let img = build_image();
        let sb = Superblock::parse(&img[1024..]).unwrap();
        assert_eq!(sb.inodes_count, 16);
        assert_eq!(sb.blocks_count, 128);
        assert_eq!(sb.inode_size, 128);
        // root inode
        let root_off = sb.inode_byte(5, ROOT_INO).unwrap() as usize;
        assert_eq!(root_off, 5 * 1024 + 128);
        let root = Inode::parse(&img, root_off, sb.inode_size).unwrap();
        assert_eq!(root.mode, 0x41ED);
        assert!(root.is_dir());
        assert_eq!(root.size, 1024);
        // the root dir block holds hello.txt -> inode 12
        let ino = find_dirent(&img[20 * 1024..21 * 1024], root.size, b"hello.txt")
            .unwrap()
            .expect("hello.txt is in the root dir");
        assert_eq!(ino, 12);
        // hello's inode -> block 21, 17 bytes
        let f_off = sb.inode_byte(5, ino).unwrap() as usize;
        let f = Inode::parse(&img, f_off, sb.inode_size).unwrap();
        assert_eq!(f.size, 17);
        assert_eq!(
            &img[f.block0 as usize * 1024..][..17],
            b"HELLO-AEGIS-EXT2\n"
        );
    }

    #[test]
    fn hostile_superblocks_are_refused() {
        let img = build_image();
        for (what, bad) in [("magic", 56usize), ("inode_size", 88)] {
            let mut m = img.clone();
            m[1024 + bad] ^= 0xFF;
            let r = Superblock::parse(&m[1024..]);
            assert!(r.is_err(), "{what} corruption must refuse");
        }
        // inode_size 0 / 999 / 130 (not a power of two)
        for v in [0u16, 999, 130] {
            let mut m = img.clone();
            m[1024 + 88..1024 + 90].copy_from_slice(&v.to_le_bytes());
            assert!(
                matches!(
                    Superblock::parse(&m[1024..]),
                    Err(Ext2Error::BadInodeSize(_))
                ),
                "inode_size {v}"
            );
        }
        // truncated slice
        assert!(matches!(
            Superblock::parse(&img[1024..1024 + 80]),
            Err(Ext2Error::Truncated { .. })
        ));
    }

    #[test]
    fn hostile_inode_numbers_and_blocks_are_refused() {
        let img = build_image();
        let sb = Superblock::parse(&img[1024..]).unwrap();
        assert!(matches!(
            sb.inode_byte(5, 0),
            Err(Ext2Error::InodeOutOfRange { ino: 0, .. })
        ));
        assert!(matches!(
            sb.inode_byte(5, 17),
            Err(Ext2Error::InodeOutOfRange { ino: 17, .. })
        ));
        assert!(matches!(
            sb.inode_byte(200, 2),
            Err(Ext2Error::BlockOutOfRange { .. })
        ));
        // an inode whose extent runs off the device end
        assert!(matches!(
            sb.inode_byte(127, 16),
            Err(Ext2Error::BlockOutOfRange { .. })
        ));
    }

    #[test]
    fn hostile_dirents_are_refused_never_skipped() {
        let img = build_image();
        let mut d = img[20 * 1024..21 * 1024].to_vec();
        // rec_len < 8 + name_len at the first record
        d[4..6].copy_from_slice(&4u16.to_le_bytes());
        assert!(matches!(
            find_dirent(&d, 1024, b"hello.txt"),
            Err(Ext2Error::BadDirent { .. })
        ));
        // rec_len not 4-aligned
        let mut d2 = img[20 * 1024..21 * 1024].to_vec();
        d2[16..18].copy_from_slice(&13u16.to_le_bytes()); // ".." record's rec_len
        assert!(matches!(
            find_dirent(&d2, 1024, b"hello.txt"),
            Err(Ext2Error::BadDirent { .. })
        ));
        // a record running past the directory size
        let mut d3 = img[20 * 1024..21 * 1024].to_vec();
        d3[16..18].copy_from_slice(&2000u16.to_le_bytes());
        assert!(matches!(
            find_dirent(&d3, 1024, b"hello.txt"),
            Err(Ext2Error::BadDirent { .. })
        ));
        // name_len overrunning its own record
        let mut d4 = img[20 * 1024..21 * 1024].to_vec();
        d4[6] = 200; // "." record: name_len 1 -> 200
        assert!(matches!(
            find_dirent(&d4, 1024, b"hello.txt"),
            Err(Ext2Error::BadDirent { .. })
        ));
        // a clean directory without the name: Ok(None), not an error
        let mut d5 = img[20 * 1024..21 * 1024].to_vec();
        // ".." (at off 12) absorbs the rest of the block: 1024 - 12 = 1012
        d5[16 + 4..16 + 6].copy_from_slice(&1012u16.to_le_bytes());
        assert_eq!(find_dirent(&d5, 1024, b"nope.txt").unwrap(), None);
    }

    #[test]
    fn a_sector_sized_slice_finds_the_padded_last_record() {
        // The kernel hands the parser ONE 512-byte sector of the 1 KiB
        // directory block: the last record's rec_len pads to the block
        // end (1024), past the slice — the header + name must still be
        // found. This is the exact shape the boot lane exercises.
        let img = build_image();
        let sec = &img[20 * 1024..20 * 1024 + 512];
        assert_eq!(find_dirent(sec, 1024, b"hello.txt").unwrap(), Some(12));
        // and a record whose NAME would cross the sector edge refuses:
        // off 24 + 8 + 251 = 283 stays inside 512... the slice bound
        // needs name_len > 480, which does not fit a u8 — so shrink
        // the SLICE instead: a 64-byte slice with the same record.
        let mut m = img.clone();
        m[20 * 1024 + 24 + 6] = 250; // name_len 250: 24+8+250 = 282 > 64
        let tiny = &m[20 * 1024..20 * 1024 + 64];
        assert!(matches!(
            find_dirent(tiny, 1024, b"hello.txt"),
            Err(Ext2Error::BadDirent { .. })
        ));
    }

    /// Deterministic fuzz: 2000 seeded corruptions of the real image
    /// (byte flips + word-sized rewrites at format-relevant offsets).
    /// Every parse must return a Result — a panic here is the test
    /// failing, which is exactly what the kernel must never do.
    #[test]
    fn fuzzed_images_never_panic() {
        let img = build_image();
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut ok = 0usize;
        let mut refused = 0usize;
        for _ in 0..2000 {
            let mut m = img.clone();
            // 1-3 corruptions per iteration, biased to the structures
            // the parser walks (SB at 1024, GDT at 2048, inodes at
            // 5*1024.., dir block 20*1024..).
            for _ in 0..1 + (next() % 3) {
                let hot = [1024usize, 2048, 5120, 20 * 1024, 21 * 1024];
                let base = hot[(next() as usize) % hot.len()];
                let off = base + (next() as usize) % 1024;
                if off < m.len() {
                    m[off] = m[off].wrapping_add((next() % 256) as u8);
                }
            }
            // run the full parse chain; every step is Result-typed
            let sb = Superblock::parse(&m[1024..]);
            if let Ok(sb) = sb {
                if let Ok(root_off) = sb.inode_byte(5, ROOT_INO) {
                    if let Ok(root) = Inode::parse(&m, root_off as usize, sb.inode_size) {
                        if root.is_dir() && root.block0 < sb.blocks_count {
                            let dir = root.block0 as usize * 1024;
                            if dir + 1024 <= m.len() {
                                match find_dirent(&m[dir..dir + 1024], root.size, b"hello.txt") {
                                    Ok(Some(ino)) => {
                                        if let Ok(f_off) = sb.inode_byte(5, ino) {
                                            if Inode::parse(&m, f_off as usize, sb.inode_size)
                                                .is_ok()
                                            {
                                                ok += 1; // a fully-walked (possibly mutated) image
                                            } else {
                                                refused += 1;
                                            }
                                        } else {
                                            refused += 1;
                                        }
                                    }
                                    Ok(None) => refused += 1,
                                    Err(_) => refused += 1,
                                }
                                continue;
                            }
                        }
                        refused += 1;
                        continue;
                    }
                }
                refused += 1;
            } else {
                refused += 1;
            }
        }
        // The point is "no panic across 2000 hostile images"; the
        // split just sanity-checks that the corpus is not trivially
        // all-refused (the unmutated path must remain reachable).
        assert!(ok >= 1, "the fuzz corpus must include walkable images");
        assert_eq!(ok + refused, 2000);
    }
}
