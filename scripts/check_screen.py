#!/usr/bin/env python3
"""Pixel-level check of the QMP screendump against the pattern
gfx_step painted (bands, checker, AEGIS, background)."""
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/screen.ppm"
data = open(path, "rb").read()
if data[:2] != b"P6":
    print(f"SCREEN CHECK FAIL: {path} is not a binary PPM (mode set failed?)")
    sys.exit(1)
parts = data.split(b"\n", 3)
w, h = map(int, parts[1].split())
if (w, h) != (640, 480):
    print(f"SCREEN CHECK FAIL: unexpected mode {w}x{h} (VBE mode not engaged)")
    sys.exit(1)
px = parts[3]


def at(x, y):
    o = (y * w + x) * 3
    return tuple(px[o : o + 3])


checks = [
    ((100, 32), (255, 0, 0), "red band"),
    ((320, 32), (0, 255, 0), "green band"),
    ((560, 32), (0, 0, 255), "blue band"),
    ((4, 68), (0, 0, 0), "checker black"),
    ((12, 68), (255, 255, 255), "checker white"),
    ((133, 201), (255, 255, 255), "letter stroke"),
    ((320, 300), (0x20, 0x20, 0x30), "background"),
]
bad = []
for (x, y), want, name in checks:
    got = at(x, y)
    if got != want:
        bad.append(f"{name} @({x},{y}): want {want} got {got}")
if bad:
    print("SCREEN CHECK FAIL: " + "; ".join(bad))
    sys.exit(1)
print("SCREEN CHECK PASS: 7/7 pixels match the drawn pattern")
