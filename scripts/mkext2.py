#!/usr/bin/env python3
"""Build a minimal (but structurally honest) read-only ext2 image:
1KiB blocks, rev 1, 16 inodes, root dir with one file hello.txt."""
import struct

BS = 1024
img = bytearray(128 * BS)

def put(off, data):
    img[off:off+len(data)] = data

# Superblock at block 1 (byte 1024), for 1KiB blocks.
sb = bytearray(1024)
struct.pack_into('<I', sb, 0, 16)      # s_inodes_count
struct.pack_into('<I', sb, 4, 128)     # s_blocks_count
struct.pack_into('<I', sb, 20, 1)      # s_first_data_block
struct.pack_into('<I', sb, 24, 0)      # s_log_block_size (1KiB)
struct.pack_into('<I', sb, 32, 128)    # s_blocks_per_group
struct.pack_into('<I', sb, 40, 16)     # s_inodes_per_group
struct.pack_into('<H', sb, 56, 0xEF53) # s_magic
struct.pack_into('<I', sb, 76, 1)      # s_rev_level (dynamic)
struct.pack_into('<H', sb, 88, 128)    # s_inode_size
put(1024, sb)

# Group descriptor at block 2.
gdt = bytearray(32)
struct.pack_into('<I', gdt, 0, 3)   # bg_block_bitmap
struct.pack_into('<I', gdt, 4, 4)   # bg_inode_bitmap
struct.pack_into('<I', gdt, 8, 5)   # bg_inode_table
put(2048, gdt)

# Bitmaps: block 3 (blocks) / block 4 (inodes), mark used.
bb = bytearray(BS); bb[0] = 0xFF
put(3*BS, bb)
ib = bytearray(BS); ib[0] = 0xFF
put(4*BS, ib)

def inode(n, mode, size, block0):
    off = 5*BS + (n-1)*128
    ent = bytearray(128)
    struct.pack_into('<H', ent, 0, mode)
    struct.pack_into('<I', ent, 4, size)
    struct.pack_into('<I', ent, 40, block0)  # i_block[0]
    put(off, ent)

inode(2, 0x41ED, BS, 20)          # root dir
inode(12, 0x81A4, 17, 21)         # hello.txt

# Root dir block 20: ".", "..", "hello.txt".
d = bytearray(BS)
o = 0
for name, ino, ftype in [(b'.', 2, 2), (b'..', 2, 2)]:
    rec = (8 + len(name) + 3) & ~3
    struct.pack_into('<IHBB', d, o, ino, rec, len(name), ftype)
    d[o+8:o+8+len(name)] = name
    o += rec
name, ino, ftype = b'hello.txt', 12, 1
struct.pack_into('<IHBB', d, o, ino, BS - o, len(name), ftype)
d[o+8:o+8+len(name)] = name
put(20*BS, d)

# File data at block 21.
put(21*BS, b'HELLO-AEGIS-EXT2\n')

open('target/sdisk0.img', 'wb').write(img)
print("ext2 image: 128 blocks of 1KiB, hello.txt = HELLO-AEGIS-EXT2")
