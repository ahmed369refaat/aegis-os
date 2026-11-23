#!/usr/bin/env python3
"""Build the PERSIST disk: the same honest mkext2 geometry as the
S4 host fixture (src/ext2.rs build_rw_image), but RAW — no protective
MBR, no GPT, the filesystem at LBA 0 (superblock block 1 = LBA 2).

Why raw when sdisk0.img is GPT-wrapped: the persist lane boots the
SAME image twice and asserts the file written by boot 1 is read back
by boot 2. The GPT layer exists to prove the partition parser on the
read-only demo disk; the persist lane's story is the write path, and
every layer it does not exercise is one more thing that could break
the two-boot proof. FS-relative addressing: byte 0 of the image is
byte 0 of the filesystem.

Honesty upgrade over mkext2.py (the read-only demo never needed it):
the BLOCK and INODE bitmaps carry the REAL occupancy and the group's
free counters ride the GDT — a writer allocating from a lying bitmap
would allocate over live structures.

  block bitmap: bits {1,2,3,4,5,6,20,21}   (sb, gdt, 2 bitmaps,
                                            inode table 5..6, root 20,
                                            hello 21) -> 120 free
  inode bitmap: bits {0,1,11}              (ino 1 reserved, 2 root,
                                            12 hello) -> 13 free

Build policy (Phase 6 S5): the image is built ONCE — if it already
exists the script leaves it untouched, because regenerating it would
reset the very persistence the lane proves (boot 1 would always be
the WRITTEN boot and PERSIST:VERIFIED would never happen). Pass
--force to rebuild deliberately (that resets the proof).
"""
import os
import struct
import sys

BS = 1024          # s_log_block_size = 0
BLOCKS = 128       # s_blocks_count (the demo geometry, 128 KiB)
INODES = 16        # s_inodes_count
SECTORS = BLOCKS * BS // 512   # 256 sectors

img = bytearray(BLOCKS * BS)

def put(off, data):
    img[off:off+len(data)] = data

# ── superblock at block 1 (byte 1024 = LBA 2) ──
sb = bytearray(BS)
struct.pack_into('<I', sb, 0, INODES)     # s_inodes_count
struct.pack_into('<I', sb, 4, BLOCKS)     # s_blocks_count
struct.pack_into('<I', sb, 20, 1)         # s_first_data_block
struct.pack_into('<I', sb, 24, 0)         # s_log_block_size (1 KiB)
struct.pack_into('<I', sb, 32, 128)       # s_blocks_per_group
struct.pack_into('<I', sb, 40, 16)        # s_inodes_per_group
struct.pack_into('<H', sb, 56, 0xEF53)    # s_magic
struct.pack_into('<I', sb, 76, 1)         # s_rev_level (dynamic)
struct.pack_into('<H', sb, 88, 128)       # s_inode_size
put(1024, sb)

# ── group descriptor at block 2, with the honest free counters ──
USED_BLOCKS = [1, 2, 3, 4, 5, 6, 20, 21]   # 8 of 128 -> 120 free
USED_INODES = [1, 2, 12]                   # 3 of 16  -> 13 free
gdt = bytearray(32)
struct.pack_into('<I', gdt, 0, 3)                        # bg_block_bitmap
struct.pack_into('<I', gdt, 4, 4)                        # bg_inode_bitmap
struct.pack_into('<I', gdt, 8, 5)                        # bg_inode_table
struct.pack_into('<H', gdt, 12, BLOCKS - len(USED_BLOCKS))  # bg_free_blocks_count
struct.pack_into('<H', gdt, 14, INODES - len(USED_INODES))  # bg_free_inodes_count
put(2048, gdt)

# ── the bitmaps, honestly occupied ──
bb = bytearray(BS)
for b in USED_BLOCKS:
    bb[b // 8] |= 1 << (b % 8)
put(3 * BS, bb)
ib = bytearray(BS)
for i in USED_INODES:
    ib[(i - 1) // 8] |= 1 << ((i - 1) % 8)   # bit i-1 = inode i
put(4 * BS, ib)

# ── inode table at block 5 (16 × 128B, spanning blocks 5..6) ──
def inode(n, mode, size, block0):
    off = 5 * BS + (n - 1) * 128
    ent = bytearray(128)
    struct.pack_into('<H', ent, 0, mode)
    struct.pack_into('<I', ent, 4, size)
    struct.pack_into('<I', ent, 40, block0)  # i_block[0]
    put(off, ent)

inode(2, 0x41ED, BS, 20)          # root dir
inode(12, 0x81A4, 17, 21)         # hello.txt

# ── root dir block 20: ".", "..", terminal "hello.txt" ──
d = bytearray(BS)
o = 0
for name, ino, ftype in [(b'.', 2, 2), (b'..', 2, 2)]:
    rec = (8 + len(name) + 3) & ~3
    struct.pack_into('<IHBB', d, o, ino, rec, len(name), ftype)
    d[o+8:o+8+len(name)] = name
    o += rec
name, ino, ftype = b'hello.txt', 12, 1
struct.pack_into('<IHBB', d, o, ino, BS - o, len(name), ftype)  # terminal
d[o+8:o+8+len(name)] = name
put(20 * BS, d)

# ── file data at block 21 ──
put(21 * BS, b'HELLO-AEGIS-EXT2\n')

# ── the self-check: the invariants the kernel's two-boot proof relies on ──
assert struct.unpack_from('<H', img, 1024 + 56)[0] == 0xEF53
assert struct.unpack_from('<H', img, 2048 + 12)[0] == 120
assert struct.unpack_from('<H', img, 2048 + 14)[0] == 13
first_free_block = next(b for b in range(BLOCKS)
                        if not (bb[b // 8] & (1 << (b % 8))))
first_free_ino = next(i for i in range(1, INODES + 1)
                      if not (ib[(i - 1) // 8] & (1 << ((i - 1) % 8))))
assert first_free_ino == 3, "boot 1's create_file must land on inode 3"

path = 'target/persist.img'
if os.path.exists(path) and '--force' not in sys.argv[1:]:
    print(f"{path}: already exists — NOT regenerated (the persistence "
          f"proof needs the image boot 1 wrote; --force resets it)")
else:
    os.makedirs('target', exist_ok=True)
    with open(path, 'wb') as f:
        f.write(img)
    print(f"raw ext2 persist image: {SECTORS} sectors at LBA 0, "
          f"free blocks {BLOCKS - len(USED_BLOCKS)} "
          f"(first free: {first_free_block}), "
          f"free inodes {INODES - len(USED_INODES)} "
          f"(first free: {first_free_ino}), hello.txt = HELLO-AEGIS-EXT2")
