#!/usr/bin/env python3
"""Build a minimal (but structurally honest) read-only ext2 image,
GPT-wrapped: protective MBR (LBA0) + GPT header (LBA1) + entries
(LBA2, partition 'aegis-root' at LBA 34..=289) + the filesystem
(LBA 34..) + the backup GPT at the tail. 1KiB blocks, rev 1, 26
inodes (the table spans blocks 5-7, still below the data at 20),
root dir with hello.txt, the gcc /bin/hello ELF, and — K23 — the
/pkgsrc directory carrying the K23 repo fixture (the seven
pkg-mkrepo outputs — trust, the repo config, the signed index, and
BOTH version-qualified packages — byte-exact reads of
kernel-x86_64/blob/
pkg-fixture/*): the kernel image stopped carrying package data."""
import struct
import zlib

BS = 1024
EXT2_SECTORS = 128 * BS // 512          # 256 sectors of filesystem
PART_FIRST, PART_LAST = 34, 33 + EXT2_SECTORS   # 34..=289
TOTAL = PART_LAST + 3                   # + backup entries + backup header + 1

img = bytearray(TOTAL * 512)

def put(off, data):
    img[off:off+len(data)] = data

def crc32(b):
    return zlib.crc32(bytes(b)) & 0xFFFFFFFF

# ── LBA 0: the protective MBR ──
mbr = bytearray(512)
mbr[446 + 0] = 0x00                     # boot indicator
mbr[446 + 4] = 0xEE                     # protective type
struct.pack_into('<I', mbr, 446 + 8, 1)     # start LBA
struct.pack_into('<I', mbr, 446 + 12, TOTAL - 1)  # sectors
mbr[510], mbr[511] = 0x55, 0xAA
put(0, mbr)

# ── LBA 2: the entry array (4 × 128B, one used) ──
ent = bytearray(512)
# Linux filesystem data type GUID (0FC63DAF-... mixed-endian form).
ent[0:16] = bytes([0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                   0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4])
ent[16:32] = bytes(range(0x11, 0x21))  # a unique GUID (any honest value)
struct.pack_into('<Q', ent, 32, PART_FIRST)
struct.pack_into('<Q', ent, 40, PART_LAST)
name = 'aegis-root'
for i, ch in enumerate(name.encode()):
    struct.pack_into('<H', ent, 56 + i * 2, ch)
put(2 * 512, ent)

# ── LBA 1 / LBA TOTAL-1: the primary + backup headers ──
def gpt_header(my_lba, backup_lba, entries_lba):
    h = bytearray(512)
    h[0:8] = b'EFI PART'
    struct.pack_into('<I', h, 8, 0x00010000)   # revision 1.0
    struct.pack_into('<I', h, 12, 92)          # header size
    struct.pack_into('<I', h, 16, 0)           # CRC (patched below)
    struct.pack_into('<Q', h, 24, my_lba)
    struct.pack_into('<Q', h, 32, backup_lba)
    struct.pack_into('<Q', h, 40, PART_FIRST)  # first usable
    struct.pack_into('<Q', h, 48, PART_LAST)   # last usable
    struct.pack_into('<Q', h, 72, entries_lba)
    struct.pack_into('<I', h, 80, 4)           # 4 entries
    struct.pack_into('<I', h, 84, 128)         # entry size
    struct.pack_into('<I', h, 88, crc32(ent))  # entries CRC
    # The header CRC covers bytes 0..92 with its own field zeroed.
    hc = bytearray(h[:92])
    hc[16:20] = b'\0\0\0\0'
    struct.pack_into('<I', h, 16, crc32(hc))
    return h

put(1 * 512, gpt_header(1, TOTAL - 1, 2))
put((TOTAL - 2) * 512, ent)                  # backup entries
put((TOTAL - 1) * 512, gpt_header(TOTAL - 1, 1, TOTAL - 2))

# ── the ext2 filesystem at LBA 34 ──
FS = PART_FIRST * 512

# Superblock at block 1 (byte 1024), for 1KiB blocks. K23 raised the
# inode count 16 -> 24; P1-2's sixth and seventh fixture files (the
# netcat and rust-hello packages) raised it to 26: /pkgsrc adds the
# directory inode 14 plus seven file inodes 15-21; 26 * 128 B = 4
# blocks (5-8), still clear of the
# data at 20.
sb = bytearray(1024)
struct.pack_into('<I', sb, 0, 26)      # s_inodes_count
struct.pack_into('<I', sb, 4, 128)     # s_blocks_count
struct.pack_into('<I', sb, 20, 1)      # s_first_data_block
struct.pack_into('<I', sb, 24, 0)      # s_log_block_size (1KiB)
struct.pack_into('<I', sb, 32, 128)    # s_blocks_per_group
struct.pack_into('<I', sb, 40, 24)     # s_inodes_per_group
struct.pack_into('<H', sb, 56, 0xEF53) # s_magic
struct.pack_into('<I', sb, 76, 1)      # s_rev_level (dynamic)
struct.pack_into('<H', sb, 88, 128)    # s_inode_size
put(FS + 1024, sb)

# Group descriptor at block 2.
gdt = bytearray(32)
struct.pack_into('<I', gdt, 0, 3)   # bg_block_bitmap
struct.pack_into('<I', gdt, 4, 4)   # bg_inode_bitmap
struct.pack_into('<I', gdt, 8, 5)   # bg_inode_table
put(FS + 2048, gdt)

# Bitmaps: block 3 (blocks) / block 4 (inodes); the occupancy is
# marked as the structures are laid out below, then both bitmaps are
# written ONCE at their own blocks (see the pkgsrc section).
bb = bytearray(BS); bb[0] = 0xFF
ib = bytearray(BS); ib[0] = 0xFF

def inode(n, mode, size, blocks):
    """One inode: `blocks` is the DIRECT block list (i_block[0..],
    12 direct entries fit a <= 12 KiB file; larger files refuse)."""
    assert len(blocks) <= 12, "direct blocks only"
    off = FS + 5*BS + (n-1)*128
    ent = bytearray(128)
    struct.pack_into('<H', ent, 0, mode)
    struct.pack_into('<I', ent, 4, size)
    for i, b in enumerate(blocks):
        struct.pack_into('<I', ent, 40 + 4*i, b)  # i_block[i]
    put(off, ent)

inode(2, 0x41ED, BS, [20])       # root dir
inode(12, 0x81A4, 17, [21])      # hello.txt

# K20 (P0-3): the gcc-built userland image, carried as a real file.
# Built by boot.sh step [0c] BEFORE this script runs; 8..12 KiB of
# ELF spans several direct blocks.
hello_elf = open('kernel-x86_64/blob/userland-hello.elf', 'rb').read()
hello_blocks = [22 + i for i in range((len(hello_elf) + BS - 1) // BS)]
assert 22 + len(hello_blocks) <= 128, "the image must fit the filesystem"
inode(13, 0o100755, len(hello_elf), hello_blocks)
# Mark the ELF's data blocks used in the block bitmap (honesty).
for b in range(22, 22 + len(hello_blocks)):
    bb[b >> 3] |= 1 << (b & 7)

# ── K23: /pkgsrc — the repo fixture rides the disk ──
# The K23 lane's SEVEN provisioning files (pkg-mkrepo's outputs, built
# by boot.sh step [0g] — P1-2: the three REAL-binary packages ride
# here too) as byte-exact reads of the blob copies: the
# kernel image stops carrying package data. The directory is
# root-owned 0755; the files are 0644 regular files (the manager READS
# its anchors, it can never rewrite them). Inode 14, data blocks after
# the ELF's — a running cursor, so a grown fixture stays honest
# without redesign, and each file is asserted under the reader's
# direct-block ceiling (12 KiB).
PKG_DIR_INO = 14
pkg_dir_blk = 22 + len(hello_blocks)      # 31 at today's 9-block ELF
pkg_files = []                            # (name, ino, data, first_blk, nblocks)
cursor = pkg_dir_blk + 1
for i, name in enumerate(
    ['trust', 'r1.repo', 'index.aki', 'r1.hello-1.0.0.akp', 'r1.hello-1.1.0.akp',
     'r1.netcat-1.0.0.akp', 'r1.rust-hello-1.0.0.akp']
):
    data = open(f'kernel-x86_64/blob/pkg-fixture/{name}', 'rb').read()
    assert len(data) <= 12 * BS, f'{name} exceeds the direct-block ceiling'
    nblk = (len(data) + BS - 1) // BS
    pkg_files.append((name, 15 + i, data, cursor, nblk))
    cursor += nblk
assert cursor <= 128, "the pkgsrc files must fit the filesystem"
inode(PKG_DIR_INO, 0o040755, BS, [pkg_dir_blk])
for name, ino, data, first, nblk in pkg_files:
    inode(ino, 0o100644, len(data), [first + j for j in range(nblk)])
# Honest bitmaps, both to their OWN blocks this time: the new dir +
# data blocks, the new inodes 14..18. (The old script wrote the
# updated BLOCK bitmap to the INODE bitmap's block 4 — the read-only
# path never reads bitmaps, so nothing noticed; with pkgsrc marking
# real occupancy the bitmaps go to their own homes.)
for b in range(pkg_dir_blk, cursor):
    bb[b >> 3] |= 1 << (b & 7)
for ino in range(PKG_DIR_INO, PKG_DIR_INO + 1 + len(pkg_files)):
    ib[(ino - 1) >> 3] |= 1 << ((ino - 1) & 7)
put(FS + 3*BS, bb)
put(FS + 4*BS, ib)

# Root dir block 20: ".", "..", "hello.txt", "hello", "pkgsrc" —
# "hello" shrinks to its real record size so "pkgsrc" takes the tail.
d = bytearray(BS)
o = 0
for name, ino, ftype in [(b'.', 2, 2), (b'..', 2, 2)]:
    rec = (8 + len(name) + 3) & ~3
    struct.pack_into('<IHBB', d, o, ino, rec, len(name), ftype)
    d[o+8:o+8+len(name)] = name
    o += rec
name, ino, ftype = b'hello.txt', 12, 1
rec = (8 + len(name) + 3) & ~3
struct.pack_into('<IHBB', d, o, ino, rec, len(name), ftype)
d[o+8:o+8+len(name)] = name
o += rec
name, ino, ftype = b'hello', 13, 1
rec = (8 + len(name) + 3) & ~3
struct.pack_into('<IHBB', d, o, ino, rec, len(name), ftype)
d[o+8:o+8+len(name)] = name
o += rec
name, ino, ftype = b'pkgsrc', PKG_DIR_INO, 2
struct.pack_into('<IHBB', d, o, ino, BS - o, len(name), ftype)
d[o+8:o+8+len(name)] = name
put(FS + 20*BS, d)

# The /pkgsrc directory block: ".", "..", then the seven files (the
# last record pads to the block end, exactly as the root's does).
pd = bytearray(BS)
o = 0
for name, ino, ftype in [(b'.', PKG_DIR_INO, 2), (b'..', 2, 2)]:
    rec = (8 + len(name) + 3) & ~3
    struct.pack_into('<IHBB', pd, o, ino, rec, len(name), ftype)
    pd[o+8:o+8+len(name)] = name
    o += rec
for k, (name, ino, data, first, nblk) in enumerate(pkg_files):
    nb = name.encode()
    rec = (BS - o) if k == len(pkg_files) - 1 else (8 + len(nb) + 3) & ~3
    struct.pack_into('<IHBB', pd, o, ino, rec, len(nb), 1)
    pd[o+8:o+8+len(nb)] = nb
    o += rec
put(FS + pkg_dir_blk*BS, pd)

# File data at block 21.
put(FS + 21*BS, b'HELLO-AEGIS-EXT2\n')
# The gcc ELF's blocks at 22...
for i in range(0, len(hello_elf), BS):
    put(FS + (22 + i//BS)*BS, hello_elf[i:i+BS])
# The pkgsrc files' blocks (one each at today's sizes).
for name, ino, data, first, nblk in pkg_files:
    for j in range(nblk):
        put(FS + (first + j)*BS, data[j*BS:(j+1)*BS])

open('target/sdisk0.img', 'wb').write(img)
print(f"GPT-wrapped ext2 image: {TOTAL} sectors, partition 'aegis-root' "
      f"LBA {PART_FIRST}..={PART_LAST}, hello.txt = HELLO-AEGIS-EXT2, "
      f"hello = {len(hello_elf)}-byte gcc ELF in {len(hello_blocks)} blocks, "
      f"/pkgsrc = {len(pkg_files)} repo-fixture files, {cursor - pkg_dir_blk - 1} data blocks "
      f"(inodes 14-{13 + len(pkg_files) + 1})")
