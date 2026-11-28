#!/usr/bin/env python3
"""K23 host proof: the repo fixture rides the ext2 disk.

Run right after scripts/mkext2.py in boot.sh. Self-contained: it
re-parses target/sdisk0.img with the SAME ext2 logic the kernel's
reader runs (GPT partition 1 -> superblock -> group descriptor ->
root dir -> /pkgsrc -> each file's direct blocks) and asserts the
seven pkg-mkrepo fixture files (both version-qualified hello packages
and P1-2's three REAL-binary packages (netcat, rust-hello)
included) are on the image BYTE-EXACT against
kernel-x86_64/blob/pkg-fixture/*. The kernel image stopped carrying
package data, so this check is the build-time guarantee that the
disk (the bytes' only transport now) actually has them — a stale
blob, a botched mkext2 edit, or a block collision fails HERE, not
three minutes later inside QEMU at the K22 provisioning halt."""
import struct
import sys

IMG = 'target/sdisk0.img'
BLOB = 'kernel-x86_64/blob/pkg-fixture'
FILES = ['trust', 'r1.repo', 'index.aki', 'r1.hello-1.0.0.akp', 'r1.hello-1.1.0.akp', 'r1.netcat-1.0.0.akp', 'r1.rust-hello-1.0.0.akp']
BS = 1024

img = open(IMG, 'rb').read()
fail = []


def check(cond, msg):
    if not cond:
        fail.append(msg)
    return cond


# ── the partition layer: protective MBR + GPT entry 1 ──
mbr = img[0:512]
check(mbr[510:512] == b'\x55\xAA', 'protective MBR signature missing')
check(mbr[446 + 4] == 0xEE, 'MBR entry 0 is not the protective GPT type')
hdr = img[512:1024]
check(hdr[0:8] == b'EFI PART', 'GPT header signature missing')
ent = img[1024:1536]
check(struct.unpack_from('<Q', ent, 32)[0] == 34, 'partition 1 does not start at LBA 34')
FS = 34 * 512

# ── the ext2 layer (mirrors src/ext2.rs) ──
sb = img[FS + BS:FS + 2 * BS]
check(struct.unpack_from('<H', sb, 56)[0] == 0xEF53, 'ext2 magic missing')
inodes_count = struct.unpack_from('<I', sb, 0)[0]
blocks_count = struct.unpack_from('<I', sb, 4)[0]
inode_size = struct.unpack_from('<H', sb, 88)[0]
check(inodes_count == 26, f'inodes_count is {inodes_count}, not 26')
check(blocks_count == 128, f'blocks_count is {blocks_count}, not 128')
check(inode_size == 128, f'inode_size is {inode_size}, not 128')
gdt = img[FS + 2 * BS:FS + 2 * BS + 32]
itable = struct.unpack_from('<I', gdt, 8)[0]
check(5 <= itable <= 7, f'bg_inode_table block {itable} outside 5-7')


def inode(n):
    off = FS + itable * BS + (n - 1) * inode_size
    rec = img[off:off + inode_size]
    mode = struct.unpack_from('<H', rec, 0)[0]
    size = struct.unpack_from('<I', rec, 4)[0]
    direct = [struct.unpack_from('<I', rec, 40 + 4 * i)[0] for i in range(12)]
    return mode, size, direct


def find_dirent(block, name):
    """The same bounded walk find_dirent runs (one 1 KiB block)."""
    o = 0
    want = name.encode()
    while o + 8 <= BS:
        ino = struct.unpack_from('<I', block, o)[0]
        rec = struct.unpack_from('<H', block, o + 4)[0]
        nl = block[o + 6]
        if rec < 8 or rec % 4 or 8 + nl > rec:
            return None, f'malformed dirent at {o}'
        if ino != 0 and nl == len(want) and block[o + 8:o + 8 + nl] == want:
            return ino, None
        o += rec
    return None, None


# root -> pkgsrc
mode, size, direct = inode(2)
check(mode & 0xF000 == 0x4000, 'root inode is not a directory')
root_blk = img[FS + direct[0] * BS:FS + direct[0] * BS + BS]
pkg_ino, err = find_dirent(root_blk, 'pkgsrc')
check(err is None, f'root dir walk: {err}')
check(pkg_ino == 14, f'pkgsrc dirent resolved to inode {pkg_ino}, not 14')
# sanity: the rest of the root dir is still whole
for nm, ino in [('hello.txt', 12), ('hello', 13)]:
    got, _ = find_dirent(root_blk, nm)
    check(got == ino, f'root dirent {nm} lost (got {got})')

mode, size, direct = inode(pkg_ino)
check(mode & 0xF000 == 0x4000, 'pkgsrc inode is not a directory')
pkg_blk = img[FS + direct[0] * BS:FS + direct[0] * BS + BS]

# ── the seven files, byte-exact against the blob copies ──
sizes = []
for i, name in enumerate(FILES):
    want = open(f'{BLOB}/{name}', 'rb').read()
    got_ino, err = find_dirent(pkg_blk, name)
    if not check(err is None, f'pkgsrc walk for {name}: {err}') or got_ino is None:
        fail.append(f'{name}: no dirent in /pkgsrc')
        continue
    check(got_ino == 15 + i, f'{name}: inode {got_ino}, expected {15 + i}')
    fmode, fsize, fdirect = inode(got_ino)
    check(fmode == 0o100644, f'{name}: mode {fmode:o}, expected 0100644')
    check(fsize == len(want), f'{name}: size {fsize}, expected {len(want)}')
    check(fsize <= 12 * BS, f'{name}: over the direct-block ceiling')
    got = bytearray()
    for b in fdirect[:(fsize + BS - 1) // BS]:
        check(0 < b < blocks_count, f'{name}: block {b} out of range')
        got += img[FS + b * BS:FS + (b + 1) * BS]
    check(bytes(got[:fsize]) == want, f'{name}: NOT byte-exact on the image')
    sizes.append(f'{name} {len(want)} B')

if fail:
    for f in fail:
        print(f'PKGSRC IMAGE: FAIL — {f}')
    sys.exit(1)
print(f'PKGSRC IMAGE: PASS — /pkgsrc on {IMG} carries the {len(FILES)} fixture '
      f'files byte-exact ({", ".join(sizes)}), inodes 14-{13 + len(FILES)}, root 0755')
