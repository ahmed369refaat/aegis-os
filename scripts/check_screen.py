#!/usr/bin/env python3
"""Pixel-level checks of the QMP screendumps.

Default (pattern mode): the boot-splash gfx_step painted — bands,
checker, AEGIS logo, background — captured while the splash is still
on screen (the console arms only at the END of the driver phase).

--text mode: the text console's PERMANENT STATUS ROW (row 0, never
scrolled): "AEGIS TEXT CONSOLE - 80X30 DOUBLE-BUFFERED PLANE". The
sample points are derived from the kernel's own FONT table (MSB =
x=0, glyph rows doubled into 8x16 cells), so the check and the
renderer share one truth."""
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/screen.ppm"
INK = (0xE8, 0xE8, 0xE8)
BG_CONSOLE = (0x10, 0x10, 0x20)


def load(path):
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

    return at


def run(checks, label):
    at = load(path)
    good = True
    for (x, y), want, name in checks:
        got = at(x, y)
        if got != want:
            print(f"{label} FAIL: {name} @({x},{y}) = {got} != {want}")
            good = False
    if good:
        print(f"{label}: PASS")
    return good


# ── pattern mode (the boot splash) ───────────────────────────────────
PATTERN = [
    ((100, 32), (255, 0, 0), "red band"),
    ((320, 32), (0, 255, 0), "green band"),
    ((560, 32), (0, 0, 255), "blue band"),
    ((4, 68), (0, 0, 0), "checker black"),
    ((12, 68), (255, 255, 255), "checker white"),
    ((133, 201), (255, 255, 255), "letter stroke"),
    ((320, 300), (32, 32, 48), "background"),
]

# ── text mode (the status row) ───────────────────────────────────────
# "AEGIS TEXT CONSOLE - 80X30 DOUBLE-BUFFERED PLANE"
# 'A' cell 0: {0x0C,0x1E,0x33,0x33,0x3F,0x33,0x33,0x00}
# 'E' cell 1: {0x7F,0x60,0x60,0x7E,0x60,0x60,0x7F,0x00}
# 'T' cell 6: {0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x00}
# '-' cell 19: {0,0,0,0x7E,0,0,0,0}
TEXT = [
    ((5, 0), INK, "A r0 right stroke (0x0C -> x=4,5)"),
    ((3, 0), BG_CONSOLE, "A r0 left of the stroke"),
    ((4, 2), INK, "A r1 stroke (0x1E -> x=3..6)"),
    ((6, 6), INK, "A r3 leg (0x33 -> x=2,3,6,7)"),
    ((4, 6), BG_CONSOLE, "A r3 counter (the gap at x=4,5)"),
    ((2, 8), INK, "A crossbar (0x3F -> x=2..7)"),
    ((4, 14), BG_CONSOLE, "A r7 blank"),
    ((9, 0), INK, "E top bar (0x7F -> x=1..7)"),
    ((8, 0), BG_CONSOLE, "E's left margin"),
    ((9, 6), INK, "E middle bar (0x7E -> x=1..6)"),
    ((15, 6), BG_CONSOLE, "E middle bar's right edge (bit0 clear)"),
    ((44, 4), BG_CONSOLE, "the space between words (cell 5)"),
    ((50, 0), INK, "T top bar (0x7E -> x=1..6)"),
    ((48, 0), BG_CONSOLE, "T's left margin"),
    ((52, 2), INK, "T stem (0x18 -> x=3,4)"),
    ((155, 6), INK, "the hyphen's dash (cell 19, r3 0x7E)"),
    ((152, 6), BG_CONSOLE, "the hyphen's left margin"),
    ((155, 2), BG_CONSOLE, "above the hyphen"),
]

if len(sys.argv) > 2 and sys.argv[2] == "--text":
    sys.exit(0 if run(TEXT, "TEXT CHECK") else 1)
sys.exit(0 if run(PATTERN, "SCREEN CHECK") else 1)
