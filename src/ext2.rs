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
    /// K20 (P0-3): the DIRECT block list i_block\[0..12\] — a
    /// multi-KiB file (the gcc userland image) spans several, and the
    /// boot's loader walks them in order. Indirect blocks are refused
    /// by the reader, not modeled here.
    pub direct: [u32; 12],
}

impl Inode {
    /// Parse one inode at `off` in `buf` (a sector or larger slice);
    /// the whole `inode_size` must fit from `off`. K20 (P0-3) fixed a
    /// live bug here: the old `off < 44` guard refused every inode
    /// that happens to START a sector (inodes 5, 9, 13, ... at
    /// inode_size 128 — one in four), even though the actual bounds
    /// check is `buf.len() < need` alone. The gcc userland image's
    /// inode landed exactly there and the boot refused it; the guard
    /// was a leftover, not a policy.
    pub fn parse(buf: &[u8], off: usize, inode_size: u16) -> Result<Inode, Ext2Error> {
        let need = off + inode_size as usize;
        if buf.len() < need {
            return Err(Ext2Error::Truncated {
                need,
                have: buf.len(),
            });
        }
        let mode = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let size = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let block0 =
            u32::from_le_bytes([buf[off + 40], buf[off + 41], buf[off + 42], buf[off + 43]]);
        let mut direct = [block0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i, slot) in direct.iter_mut().enumerate().skip(1) {
            let b = off + 40 + 4 * i;
            *slot = u32::from_le_bytes([buf[b], buf[b + 1], buf[b + 2], buf[b + 3]]);
        }
        Ok(Inode {
            mode,
            size,
            block0,
            direct,
        })
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

// ═══ Phase 6 S4: the WRITE path — buffer-backed, host-tested ═══
//
// The image here is the whole filesystem (FS-relative — the kernel
// adds the partition base; GPT-wrapping is the builder's business).
// The geometry is rev-1 dynamic as `mkext2.py` pins it, with ONE
// honesty upgrade the read-only demo did not need: the BLOCK and
// INODE bitmaps carry the REAL occupancy (the demo marked only the
// first 8 of each — harmless for reading, a lie a writer would
// allocate over). `mkext2-rw.py` and the test fixture below mirror
// the honest layout: used = {sb 1, gdt 2, bitmaps 3,4, inode table
// 5,6, root 20, hello 21} and inodes {2, 12}.
//
// Scope (M3, documented): DIRECT blocks only (i_block[0..11] — a
// file caps at 12 KiB), single group, the root directory as the only
// directory. The bitmaps are the allocation truth; the group's free
// counts ride the GDT (bg_free_blocks_count/bg_free_inodes_count)
// and are maintained best-effort for fsck-style readers.

/// Every way the write path refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext2WriteError {
    /// The inode bitmap has no clear bit.
    NoFreeInodes,
    /// The block bitmap has no clear bit.
    NoFreeBlocks,
    /// The root directory block cannot fit another record.
    DirFull,
    /// The name is empty, contains '/', or exceeds 255 bytes.
    BadName,
    /// offset+len passes the direct-block ceiling (12 * block size).
    TooLarge,
    /// A structure the writer maintains is absent/truncated.
    Truncated,
    /// The on-disk inode number is out of range.
    InodeOutOfRange { ino: u32, inodes: u32 },
}

/// The group descriptor's fields the writer maintains (block 2).
const GDT_BLOCK_BITMAP: usize = 0;
const GDT_INODE_BITMAP: usize = 4;
const GDT_INODE_TABLE: usize = 8;
const GDT_FREE_BLOCKS: usize = 12; // u16
const GDT_FREE_INODES: usize = 14; // u16

/// The superblock offsets the writer reads (block 1, byte 1024).
const SB_INODES_COUNT: usize = 0;
const SB_BLOCKS_COUNT: usize = 4;

/// The direct-block ceiling (M3 scope: no indirect blocks).
pub const DIRECT_BLOCKS: u32 = 12;

/// The byte-addressable backing the write path runs on. The host
/// tests drive a whole-image `&mut [u8]`; the kernel's persist lane
/// (Phase 6 S5) implements the same contract over pool frames
/// reached through PA accessors — no contiguous image buffer exists
/// there. Every structure this writer touches fits one block, so the
/// contract is exactly windowed reads and writes, never the whole
/// image at once.
pub trait ImageStore {
    /// Fill `out` from `off`. False when the span leaves the image.
    fn read_at(&self, off: usize, out: &mut [u8]) -> bool;
    /// Store `src` at `off`. False when the span leaves the image.
    fn write_at(&mut self, off: usize, src: &[u8]) -> bool;
}

impl ImageStore for [u8] {
    fn read_at(&self, off: usize, out: &mut [u8]) -> bool {
        match self.get(off..off + out.len()) {
            Some(s) => {
                out.copy_from_slice(s);
                true
            }
            None => false,
        }
    }
    fn write_at(&mut self, off: usize, src: &[u8]) -> bool {
        match self.get_mut(off..off + src.len()) {
            Some(d) => {
                d.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

/// Read one little-endian u32 at a byte offset (truncation-checked).
fn rd_u32(img: &(impl ImageStore + ?Sized), off: usize) -> Result<u32, Ext2WriteError> {
    let mut b = [0u8; 4];
    if !img.read_at(off, &mut b) {
        return Err(Ext2WriteError::Truncated);
    }
    Ok(u32::from_le_bytes(b))
}

/// Read one little-endian u16 at a byte offset.
fn rd_u16(img: &(impl ImageStore + ?Sized), off: usize) -> Result<u16, Ext2WriteError> {
    let mut b = [0u8; 2];
    if !img.read_at(off, &mut b) {
        return Err(Ext2WriteError::Truncated);
    }
    Ok(u16::from_le_bytes(b))
}

/// Write one little-endian u16 at a byte offset.
fn wr_u16(img: &mut (impl ImageStore + ?Sized), off: usize, v: u16) -> Result<(), Ext2WriteError> {
    if !img.write_at(off, &v.to_le_bytes()) {
        return Err(Ext2WriteError::Truncated);
    }
    Ok(())
}

/// The writer's geometry, read once from the image.
#[derive(Debug, Clone, Copy)]
struct RwGeom {
    bs: usize,
    inodes: u32,
    blocks: u32,
    block_bitmap_blk: u32,
    inode_bitmap_blk: u32,
    inode_table_blk: u32,
}

impl RwGeom {
    fn parse(img: &(impl ImageStore + ?Sized)) -> Result<RwGeom, Ext2WriteError> {
        // Validation-only parse: a bad superblock is a truncated image.
        // The 1 KiB superblock lands in a stack window — the store
        // never has to hand out the whole image.
        let mut sbb = [0u8; 1024];
        if !img.read_at(1024, &mut sbb) {
            return Err(Ext2WriteError::Truncated);
        }
        Superblock::parse(&sbb).map_err(|_| Ext2WriteError::Truncated)?;
        // 1 KiB blocks only (s_log_block_size 0 — the demo geometry;
        // the writer refuses anything else rather than guessing).
        let log_bs = rd_u32(img, 1024 + 24)? as usize;
        if log_bs != 0 {
            return Err(Ext2WriteError::Truncated);
        }
        let gdt = 2048;
        Ok(RwGeom {
            bs: 1024,
            inodes: rd_u32(img, 1024 + SB_INODES_COUNT)?,
            blocks: rd_u32(img, 1024 + SB_BLOCKS_COUNT)?,
            block_bitmap_blk: rd_u32(img, gdt + GDT_BLOCK_BITMAP)?,
            inode_bitmap_blk: rd_u32(img, gdt + GDT_INODE_BITMAP)?,
            inode_table_blk: rd_u32(img, gdt + GDT_INODE_TABLE)?,
        })
    }

    fn inode_byte(&self, ino: u32) -> Result<usize, Ext2WriteError> {
        if ino == 0 || ino > self.inodes {
            return Err(Ext2WriteError::InodeOutOfRange {
                ino,
                inodes: self.inodes,
            });
        }
        Ok(self.inode_table_blk as usize * self.bs + ((ino - 1) * 128) as usize)
    }
}

/// Find and set the first clear bit in a bitmap block. Returns the
/// bit index (inode numbers are index+1; block numbers ARE the index
/// for the block bitmap — ext2's block 0 does not exist in 1KiB
/// geometry, `s_first_data_block=1`, so the bitmap's bit `i` names
/// block `i` and bit 0 is a fixed-set placeholder).
fn alloc_bit(
    img: &mut (impl ImageStore + ?Sized),
    geom: &RwGeom,
    bitmap_blk: u32,
    limit: u32,
) -> Result<u32, Ext2WriteError> {
    let base = bitmap_blk as usize * geom.bs;
    for i in 0..(geom.bs * 8).min(limit as usize) {
        // One byte at a time through the store: the bitmap may live
        // anywhere the backing decides, and the RMW keeps the trait
        // to windowed access.
        let mut byte = [0u8; 1];
        if !img.read_at(base + i / 8, &mut byte) {
            return Err(Ext2WriteError::Truncated);
        }
        if byte[0] & (1 << (i % 8)) == 0 {
            byte[0] |= 1 << (i % 8);
            if !img.write_at(base + i / 8, &byte) {
                return Err(Ext2WriteError::Truncated);
            }
            return Ok(i as u32);
        }
    }
    Err(if limit == geom.inodes {
        Ext2WriteError::NoFreeInodes
    } else {
        Ext2WriteError::NoFreeBlocks
    })
}

/// Decrement the group's free counter (best-effort bookkeeping for
/// fsck-style readers; the bitmap is the truth).
fn count_allocated(
    img: &mut (impl ImageStore + ?Sized),
    free_off: usize,
) -> Result<(), Ext2WriteError> {
    let v = rd_u16(img, free_off)?;
    wr_u16(img, free_off, v.saturating_sub(1))
}

/// Create a regular 0o644 empty file in the ROOT directory, with an
/// honest dirent: the terminal record is shrunk to its real size and
/// the new record takes the remainder (the classic ext2 insert).
pub fn create_file(
    img: &mut (impl ImageStore + ?Sized),
    name: &[u8],
) -> Result<u32, Ext2WriteError> {
    if name.is_empty() || name.len() > 255 || name.contains(&b'/') {
        return Err(Ext2WriteError::BadName);
    }
    let geom = RwGeom::parse(img)?;
    // 1. an inode
    let bit = alloc_bit(img, &geom, geom.inode_bitmap_blk, geom.inodes)?;
    let ino = bit + 1; // inode numbers are 1-based
    count_allocated(img, 2048 + GDT_FREE_INODES)?;
    // 2. the inode record: mode 0o100644, zero size, zero blocks.
    let off = geom.inode_byte(ino)?;
    if !img.write_at(off, &[0u8; 128]) || !img.write_at(off, &0o100_644u16.to_le_bytes()) {
        return Err(Ext2WriteError::Truncated);
    }
    // 3. the dirent: the root block walks in ONE stack window (parse
    // pins bs = 1 KiB); only the bytes the insert touches go back.
    let root_off = geom.inode_byte(ROOT_INO)?;
    let mut rb = [0u8; 4];
    if !img.read_at(root_off + 40, &mut rb) {
        return Err(Ext2WriteError::Truncated);
    }
    let dir_blk = u32::from_le_bytes(rb);
    let dir_base = dir_blk as usize * geom.bs;
    let mut dir = [0u8; 1024];
    if !img.read_at(dir_base, &mut dir) {
        return Err(Ext2WriteError::Truncated);
    }
    let mut off = 0usize;
    loop {
        if off + 8 > geom.bs {
            return Err(Ext2WriteError::DirFull);
        }
        let rec_len = u16::from_le_bytes([dir[off + 4], dir[off + 5]]) as usize;
        if rec_len < 8 || !rec_len.is_multiple_of(4) || off + rec_len > geom.bs {
            return Err(Ext2WriteError::DirFull);
        }
        let name_len = dir[off + 6] as usize;
        let real = (8 + name_len + 3) & !3;
        // The terminal record: its rec_len reaches the block's end.
        if off + rec_len == geom.bs {
            let need = (8 + name.len() + 3) & !3;
            if rec_len - real < need {
                return Err(Ext2WriteError::DirFull);
            }
            // Shrink the terminal record to its real size.
            if !img.write_at(dir_base + off + 4, &(real as u16).to_le_bytes()) {
                return Err(Ext2WriteError::Truncated);
            }
            // The new record takes the remainder, built in place.
            let new_off = off + real;
            let mut rec = [0u8; 8 + 255];
            rec[0..4].copy_from_slice(&ino.to_le_bytes());
            rec[4..6].copy_from_slice(&((rec_len - real) as u16).to_le_bytes());
            rec[6] = name.len() as u8;
            rec[7] = 1; // EXT2_FT_REG_FILE
            rec[8..8 + name.len()].copy_from_slice(name);
            if !img.write_at(dir_base + new_off, &rec[..8 + name.len()]) {
                return Err(Ext2WriteError::Truncated);
            }
            return Ok(ino);
        }
        off += rec_len;
    }
}

/// Write `bytes` at `offset` into the inode's DIRECT blocks,
/// allocating and wiring any block the span touches that is not yet
/// allocated. i_size grows to cover the write end. M3 scope: the
/// span must fit `DIRECT_BLOCKS * bs` (12 KiB) — past that is
/// `TooLarge`, never a silent truncate.
pub fn write_file(
    img: &mut (impl ImageStore + ?Sized),
    ino: u32,
    offset: u32,
    bytes: &[u8],
) -> Result<(), Ext2WriteError> {
    let geom = RwGeom::parse(img)?;
    let ceiling = DIRECT_BLOCKS * geom.bs as u32;
    let end = offset
        .checked_add(bytes.len() as u32)
        .ok_or(Ext2WriteError::TooLarge)?;
    if end == 0 || end > ceiling {
        return Err(Ext2WriteError::TooLarge);
    }
    // Snapshot the direct blocks (48 bytes of i_block), allocate as
    // needed (alloc touches the bitmap — a second store pass), then
    // write the blocks and the inode back.
    let inode_off = geom.inode_byte(ino)?;
    let mut blocks = [0u32; DIRECT_BLOCKS as usize];
    {
        let mut rec = [0u8; 48];
        if !img.read_at(inode_off + 40, &mut rec) {
            return Err(Ext2WriteError::Truncated);
        }
        for (b, slot) in blocks.iter_mut().enumerate() {
            *slot = u32::from_le_bytes(rec[b * 4..b * 4 + 4].try_into().unwrap());
        }
    }
    let first_blk = (offset / geom.bs as u32) as usize;
    let last_blk = ((end - 1) / geom.bs as u32) as usize;
    let head = (offset % geom.bs as u32) as usize;
    for (i, slot) in blocks[first_blk..=last_blk].iter_mut().enumerate() {
        let b = first_blk + i;
        if *slot == 0 {
            let bit = alloc_bit(img, &geom, geom.block_bitmap_blk, geom.blocks)?;
            count_allocated(img, 2048 + GDT_FREE_BLOCKS)?;
            *slot = bit;
        }
        let in_off = if b == first_blk { head } else { 0 };
        let in_end = if b == last_blk {
            ((end - 1) % geom.bs as u32) as usize + 1
        } else {
            geom.bs
        };
        let n = in_end - in_off;
        // Byte i lands at absolute offset+i: block b's [in_off,
        // in_end) maps to bytes[(b*bs + in_off) - offset .. +n].
        let from = (b * geom.bs + in_off).saturating_sub(offset as usize);
        let src = bytes.get(from..from + n).unwrap_or(&[]);
        let dst_base = *slot as usize * geom.bs + in_off;
        if !img.write_at(dst_base, src) {
            return Err(Ext2WriteError::Truncated);
        }
    }
    // Write the wired blocks and the grown i_size back.
    let mut rec = [0u8; 48];
    for (b, slot) in blocks.iter().enumerate() {
        rec[b * 4..b * 4 + 4].copy_from_slice(&slot.to_le_bytes());
    }
    if !img.write_at(inode_off + 40, &rec) {
        return Err(Ext2WriteError::Truncated);
    }
    let mut size4 = [0u8; 4];
    if !img.read_at(inode_off + 4, &mut size4) {
        return Err(Ext2WriteError::Truncated);
    }
    let size = u32::from_le_bytes(size4);
    if end > size && !img.write_at(inode_off + 4, &end.to_le_bytes()) {
        return Err(Ext2WriteError::Truncated);
    }
    Ok(())
}

/// The group's free-block count (for fsck-style readers and tests).
pub fn free_blocks(img: &(impl ImageStore + ?Sized)) -> Result<u32, Ext2WriteError> {
    Ok(u32::from(rd_u16(img, 2048 + GDT_FREE_BLOCKS)?))
}

/// The group's free-inode count.
pub fn free_inodes(img: &(impl ImageStore + ?Sized)) -> Result<u32, Ext2WriteError> {
    Ok(u32::from(rd_u16(img, 2048 + GDT_FREE_INODES)?))
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

    /// The HONEST write-path fixture: the mkext2 layout with the real
    /// occupancy the read-only demo never needed — block bitmap
    /// {1..6, 20, 21}, inode bitmap {2, 12}, GDT free counts set.
    fn build_rw_image() -> Vec<u8> {
        let mut img = build_image();
        let put = |img: &mut Vec<u8>, off: usize, bytes: &[u8]| {
            img[off..off + bytes.len()].copy_from_slice(bytes);
        };
        // Bitmaps at blocks 3/4 (per the GDT). Mark honestly.
        let mut bb = vec![0u8; 1024];
        for b in [1u32, 2, 3, 4, 5, 6, 20, 21] {
            bb[(b / 8) as usize] |= 1 << (b % 8);
        }
        put(&mut img, 3 * 1024, &bb);
        let mut ib = vec![0u8; 1024];
        for i in [0u32, 1, 11] {
            // bit i = inode i+1: 1 reserved (bad-blocks inode), 2 root, 12 hello
            ib[(i / 8) as usize] |= 1 << (i % 8);
        }
        put(&mut img, 4 * 1024, &ib);
        // GDT free counts: blocks 128-8 used = 120 free; inodes 16-2 = 14.
        let mut gdt = vec![0u8; 32];
        gdt[0..4].copy_from_slice(&3u32.to_le_bytes());
        gdt[4..8].copy_from_slice(&4u32.to_le_bytes());
        gdt[8..12].copy_from_slice(&5u32.to_le_bytes());
        gdt[12..14].copy_from_slice(&120u16.to_le_bytes());
        gdt[14..16].copy_from_slice(&13u16.to_le_bytes());
        put(&mut img, 2048, &gdt);
        img
    }

    /// Phase 6 S4: create + multi-block write + parser read-back, with
    /// the free counters and the dirent honestly maintained.
    /// K20 (P0-3), the live bug the gcc userland image found: an
    /// inode that STARTS a sector (offset 0 — inodes 5, 9, 13, ...
    /// at inode_size 128) is legal, and the old `off < 44` guard
    /// refused exactly those. The parse must accept them.
    #[test]
    fn inode_starting_a_sector_parses() {
        let mut img = build_image();
        // Inode 5 sits at 5*1024 + 4*128 = 6656 → sector 13, offset 0.
        let e = [0u8; 128];
        img[6656..6656 + 128].copy_from_slice(&e);
        let sec = &img[6656..6656 + 512];
        let node = Inode::parse(sec, 0, 128).expect("offset 0 is legal");
        assert_eq!(node.mode, 0);
        assert_eq!(node.size, 0);
    }

    #[test]
    fn rw_create_write_and_read_back() {
        let mut img = build_rw_image();
        let ino = create_file(img.as_mut_slice(), b"persist.txt").unwrap();
        assert_ne!(ino, ROOT_INO);
        assert_ne!(ino, 12); // hello.txt stays live
        assert_eq!(free_inodes(img.as_slice()).unwrap(), 12);
        // A 3-block body crossing every boundary (256 bytes short of
        // 3 KiB, offset past 1 KiB to prove the head math).
        let body: Vec<u8> = (0..2560).map(|i| (i % 241) as u8).collect();
        write_file(img.as_mut_slice(), ino, 1000, &body).unwrap();
        assert_eq!(free_blocks(img.as_slice()).unwrap(), 120 - 4); // blocks 22..25
                                                                   // Read back through the READ-ONLY parser (the round-trip proof).
        let sb = Superblock::parse(&img[1024..]).unwrap();
        let root_off = sb.inode_byte(5, ROOT_INO).unwrap() as usize;
        let root_rec = &img[root_off..root_off + 128];
        let dir_blk = u32::from_le_bytes(root_rec[40..44].try_into().unwrap());
        let found = find_dirent(
            &img[dir_blk as usize * 1024..][..1024],
            1024,
            b"persist.txt",
        )
        .unwrap()
        .unwrap();
        assert_eq!(found, ino);
        let f_off = sb.inode_byte(5, ino).unwrap() as usize;
        let f_rec = &img[f_off..f_off + 128];
        let size = u32::from_le_bytes(f_rec[4..8].try_into().unwrap());
        assert_eq!(size, 1000 + 2560);
        // Verify the body byte-for-byte through the direct blocks.
        for (i, want) in body.iter().enumerate() {
            let abs = 1000 + i;
            let b = abs / 1024;
            let blk = u32::from_le_bytes(f_rec[40 + b * 4..44 + b * 4].try_into().unwrap());
            let byte = img[blk as usize * 1024 + (abs % 1024)];
            assert_eq!(byte, *want, "byte {i}");
        }
        // The root's dirent walk still parses clean (rec_len chain).
        let _ = find_dirent(&img[dir_blk as usize * 1024..][..1024], 1024, b"hello.txt")
            .unwrap()
            .unwrap();
    }

    /// Phase 6 S4: the refusals keep their identities.
    #[test]
    fn rw_refuses_bad_names_and_ceiling() {
        let mut img = build_rw_image();
        assert_eq!(
            create_file(img.as_mut_slice(), b""),
            Err(Ext2WriteError::BadName)
        );
        assert_eq!(
            create_file(img.as_mut_slice(), b"a/b"),
            Err(Ext2WriteError::BadName)
        );
        let ino = create_file(img.as_mut_slice(), b"ok").unwrap();
        // Past the direct-block ceiling: 12 KiB - 1 is fine, +1 is not.
        write_file(img.as_mut_slice(), ino, 0, &vec![0u8; 12 * 1024 - 1]).unwrap();
        let mut img2 = build_rw_image();
        let ino2 = create_file(img2.as_mut_slice(), b"big").unwrap();
        assert_eq!(
            write_file(img2.as_mut_slice(), ino2, 0, &vec![0u8; 12 * 1024 + 1]),
            Err(Ext2WriteError::TooLarge)
        );
        // Filling the inode bitmap: NoFreeInodes.
        let mut img3 = build_rw_image();
        for i in 0..13 {
            create_file(img3.as_mut_slice(), format!("f{i}").as_bytes()).unwrap();
        }
        assert_eq!(
            create_file(img3.as_mut_slice(), b"one-too-many"),
            Err(Ext2WriteError::NoFreeInodes)
        );
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
