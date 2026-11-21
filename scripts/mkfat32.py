#!/usr/bin/env python3
"""Grow the mkext2.py disk with a GPT partition 2 — an EFI System
Partition holding an honest FAT32 volume (65600 clusters ≥ the spec's
65525 minimum, so the type determination is FAT32 by the format's own
rule, never a misread FAT16). 8.3 names, one file: HELLO.ESP (1200
bytes across clusters 3→4→5 — the chain walk has real hops to walk).

The script POST-PROCESSES target/sdisk0.img (run mkext2.py first):
the protective MBR's size, the primary GPT (2 entries now), and the
backup GPT all move to the new tail; the old backup sectors are
zeroed so no stale GPT copy lingers. The FAT32 geometry matches the
policy core's fixture (src/fat32.rs tests): reserved 32, 2 FATs of
516 sectors, data at partition-relative LBA 1064."""
import struct
import zlib

IMG = 'target/sdisk0.img'
img = bytearray(open(IMG, 'rb').read())
OLD_TOTAL = len(img) // 512
assert OLD_TOTAL == 292, f'unexpected mkext2 image: {OLD_TOTAL} sectors'

# ── the new partition's geometry (mirrors src/fat32.rs) ──
ESP_FIRST = 296                          # 4-aligned after the ext2 tail
RESERVED, FATS, FAT_SIZE, DATA = 32, 2, 516, 65_600
ESP_LEN = RESERVED + FATS * FAT_SIZE + DATA   # 66_664 sectors
ESP_LAST = ESP_FIRST + ESP_LEN - 1            # 66_959
TOTAL = ESP_LAST + 3                          # backup entries + header
CLUSTERS = DATA                               # 1 sector per cluster

def put(lba, data):
    off = lba * 512
    img[off:off + len(data)] = data

def crc32(b):
    return zlib.crc32(bytes(b)) & 0xFFFFFFFF

# ── grow the image ──
img.extend(b'\0' * (TOTAL * 512 - len(img)))

# ── zero the stale GPT backup from the old tail ──
put(OLD_TOTAL - 2, b'\0' * 512)
put(OLD_TOTAL - 1, b'\0' * 512)

# ── the entries array: ext2 entry stays, the ESP joins at index 1 ──
ent = bytearray(512)
# Linux filesystem data GUID (copy of mkext2.py's entry 0 fields).
ent[0:16] = bytes([0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                   0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4])
ent[16:32] = bytes(range(0x11, 0x21))
struct.pack_into('<Q', ent, 32, 34)
struct.pack_into('<Q', ent, 40, 289)
for i, ch in enumerate('aegis-root'):
    struct.pack_into('<H', ent, 56 + i * 2, ord(ch))
esp = bytearray(128)
# EFI System Partition type GUID C12A7328-F81F-11D2-BA4B-00A0C93EC93B
# (mixed-endian: first 3 fields LE, the rest raw).
esp[0:16] = bytes([0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                   0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B])
esp[16:32] = bytes(range(0x31, 0x41))          # a unique GUID
struct.pack_into('<Q', esp, 32, ESP_FIRST)
struct.pack_into('<Q', esp, 40, ESP_LAST)
for i, ch in enumerate('aegis-esp'):
    struct.pack_into('<H', esp, 56 + i * 2, ord(ch))
ent[128:256] = esp

def gpt_header(my_lba, backup_lba, entries_lba):
    h = bytearray(512)
    h[0:8] = b'EFI PART'
    struct.pack_into('<I', h, 8, 0x00010000)   # revision 1.0
    struct.pack_into('<I', h, 12, 92)          # header size
    struct.pack_into('<I', h, 16, 0)           # CRC (patched below)
    struct.pack_into('<Q', h, 24, my_lba)
    struct.pack_into('<Q', h, 32, backup_lba)
    struct.pack_into('<Q', h, 40, 34)          # first usable
    struct.pack_into('<Q', h, 48, ESP_LAST)    # last usable
    struct.pack_into('<Q', h, 72, entries_lba)
    struct.pack_into('<I', h, 80, 4)           # 4 entries
    struct.pack_into('<I', h, 84, 128)         # entry size
    struct.pack_into('<I', h, 88, crc32(ent))  # entries CRC
    hc = bytearray(h[:92])
    hc[16:20] = b'\0\0\0\0'
    struct.pack_into('<I', h, 16, crc32(hc))
    return h

# ── primary + backup GPT, and the protective MBR's new size ──
put(2, ent)
put(1, gpt_header(1, TOTAL - 1, 2))
put(TOTAL - 2, ent)
put(TOTAL - 1, gpt_header(TOTAL - 1, 1, TOTAL - 2))
mbr = bytes(img[0:512])
img[0:512] = mbr
struct.pack_into('<I', img, 446 + 12, TOTAL - 1)  # protective size

# ── the FAT32 volume at partition LBA 0 (= disk LBA ESP_FIRST) ──
def put_fs(rel_lba, data):
    put(ESP_FIRST + rel_lba, data)

# The boot sector (BPB).
bs = bytearray(512)
bs[0:8] = b'AEGISOSP'                          # OEM name
struct.pack_into('<H', bs, 11, 512)            # bytes/sector
bs[13] = 1                                     # sectors/cluster
struct.pack_into('<H', bs, 14, RESERVED)       # reserved sectors
bs[16] = FATS                                  # FAT copies
struct.pack_into('<H', bs, 17, 0)              # root entries (FAT32: 0)
struct.pack_into('<H', bs, 19, 0)              # tot_sec16 (FAT32: 0)
bs[21] = 0xF8                                  # media
struct.pack_into('<H', bs, 22, 0)              # fat_size16 (FAT32: 0)
struct.pack_into('<H', bs, 24, 63)             # sectors/track
struct.pack_into('<H', bs, 26, 255)            # heads
struct.pack_into('<I', bs, 28, 0)              # hidden sectors
struct.pack_into('<I', bs, 32, ESP_LEN)        # tot_sec32
struct.pack_into('<I', bs, 36, FAT_SIZE)       # fat_size32
struct.pack_into('<H', bs, 40, 0)              # ext flags (both FATs)
struct.pack_into('<H', bs, 42, 0)              # fs version
struct.pack_into('<I', bs, 44, 2)              # root cluster
struct.pack_into('<H', bs, 48, 1)              # FSInfo sector
struct.pack_into('<H', bs, 50, 6)              # backup boot sector
bs[510], bs[511] = 0x55, 0xAA
put_fs(0, bs)
put_fs(6, bs)                                  # the backup boot sector

# The FSInfo sector (and its backup at 7): honest free-count accounting.
fsinfo = bytearray(512)
struct.pack_into('<I', fsinfo, 0, 0x41615252)   # lead signature
struct.pack_into('<I', fsinfo, 484, 0x61417272) # structure signature
struct.pack_into('<I', fsinfo, 488, CLUSTERS - 4)  # free clusters
struct.pack_into('<I', fsinfo, 492, 6)         # next free cluster
struct.pack_into('<I', fsinfo, 508, 0xAA550000) # trail signature
put_fs(1, fsinfo)
put_fs(7, fsinfo)

# FAT #0 and #1: media words, the root's EOC, and the file's chain.
fat = bytearray(FAT_SIZE * 512)
for c, v in [(0, 0x0FFFFFF8), (1, 0xFFFFFFFF), (2, 0x0FFFFFF8),
             (3, 4), (4, 5), (5, 0x0FFFFFF8)]:
    struct.pack_into('<I', fat, c * 4, v)
put_fs(RESERVED, fat)
put_fs(RESERVED + FAT_SIZE, fat)

# The root directory (cluster 2): HELLO.ESP, attr 0x20 (archive),
# first cluster 3, 1200 bytes; then the end-of-directory marker.
d = bytearray(512)
d[0:11] = b'HELLO   ESP'
d[11] = 0x20
struct.pack_into('<H', d, 20, 0)               # first cluster, high
struct.pack_into('<H', d, 26, 3)               # first cluster, low
struct.pack_into('<I', d, 28, 1200)            # size
d[32] = 0x00                                   # end of directory
put_fs(RESERVED + FATS * FAT_SIZE, d)

# The file: clusters 3→4→5, a head marker, a padded middle, a tail
# marker — the kernel prints head and tail, proving every hop.
content = b'HEAD:AEGIS-FAT32:' + b'0' * (1200 - 17 - 8) + b':TAIL-OK'
assert len(content) == 1200
DATA_REL = RESERVED + FATS * FAT_SIZE          # cluster 2 lives here
put_fs(DATA_REL + 1, content[:512])            # cluster 3
put_fs(DATA_REL + 2, content[512:1024])        # cluster 4
put_fs(DATA_REL + 3, content[1024:])           # cluster 5

open(IMG, 'wb').write(img)
print(f"GPT: partition 2 'aegis-esp' (ESP) LBA {ESP_FIRST}..={ESP_LAST}; "
      f"disk grew {OLD_TOTAL} -> {TOTAL} sectors")
print(f"FAT32: {CLUSTERS} clusters (>= 65525: FAT32 by the spec's rule), "
      f"FATs 2x{FAT_SIZE} sectors, HELLO.ESP = clusters 3->4->5, "
      f"{len(content)} bytes")
