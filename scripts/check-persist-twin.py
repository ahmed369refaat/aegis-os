#!/usr/bin/env python3
"""Cross-check: the persist image is the honest twin of the read-only
demo image — identical in every filesystem byte EXCEPT the two bitmap
blocks and the GDT free counters (exactly the honesty upgrade S4
made). Any other differing byte means the two builders drifted."""
import struct

persist = open('target/persist.img', 'rb').read()
demo = open('target/sdisk0.img', 'rb').read()
FS = 34 * 512                      # the demo image's partition base

diffs = []
for off in range(len(persist)):
    a = persist[off]
    b = demo[FS + off] if FS + off < len(demo) else 0
    if a != b:
        diffs.append(off)

allowed = set()
for blk in (2, 3, 4):              # GDT + both bitmaps
    allowed.update(range(blk * 1024, (blk + 1) * 1024))
stray = [o for o in diffs if o not in allowed]
print(f"differing bytes: {len(diffs)} (allowed range: blocks 2/3/4 "
      f"= {len(allowed & set(diffs))} of them), stray: {len(stray)}")
assert not stray, f"builders drifted at: {stray[:8]}"

# The allowed diffs must be exactly the honesty upgrade:
bb = persist[3*1024:4*1024]
ib = persist[4*1024:5*1024]
used_blocks = [b for b in range(128) if bb[b//8] & (1 << (b % 8))]
used_inodes = [i for i in range(1, 17) if ib[(i-1)//8] & (1 << ((i-1) % 8))]
print(f"persist bitmaps: blocks {used_blocks}, inodes {used_inodes}")
assert used_blocks == [1, 2, 3, 4, 5, 6, 20, 21]
assert used_inodes == [1, 2, 12]
assert struct.unpack_from('<H', persist, 2048 + 12)[0] == 120
assert struct.unpack_from('<H', persist, 2048 + 14)[0] == 13
# hello.txt round-trips in the persist image at the same blocks:
assert persist[20*1024 + 24 + 8 : 20*1024 + 24 + 8 + 9] == b'hello.txt'
assert persist[21*1024:21*1024+17] == b'HELLO-AEGIS-EXT2\n'
print("OK: persist.img = the demo FS + the honest bitmaps/counters, nothing else")
