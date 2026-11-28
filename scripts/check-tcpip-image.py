#!/usr/bin/env python3
"""check-tcpip-image.py — pin the tcpip service image's link contract.

P1-1: the service ELF must hold EXACTLY the NETSVC memory contract the
kernel will spawn it under (mm/user_layout.rs::NETSVC):

- ET_EXEC, entry inside the image cage, exactly 3 PT_LOADs
  (text R+X / rodata R / data R+W) — one absent page between
  neighbours (the ten-check policy's GuardGap);
- every segment page-rounded inside [0x400000, 0x480000);
- the shared page: the data PT_LOAD's first page is 0x420000 (the
  config block the kernel patches at 0x420000, the report block at
  0x420400 — the pinned contract both sides build against);
- image pages + the 64-page stack + the trampoline fit the tcpip
  profile's 256-page quota.

A layout drift fails HERE, at build time, instead of inside
`spawn_user_elf` at boot. boot.sh runs this after the image build.
Exit status 0 = the image honors the contract.
"""
import re
import subprocess
import sys

CAGE_BASE = 0x400000
CAGE_END = 0x480000
SHARED_PAGE = 0x420000
STACK_PAGES = 96
TRAMPOLINE_PAGES = 1
QUOTA_PAGES = 256
PAGE = 4096

LOAD_RE = re.compile(
    r"^\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+([RWE ]{1,3})"
)
OTHER_RE = re.compile(r"^\s*(\S+)\s+0x")
ALLOWED_OTHER = {"NOTE", "PHDR", "GNU_STACK", "GNU_RELRO", "GNU_PROPERTY"}
WANT_FLAGS = ["RE", "R", "RW"]


def fail(msg):
    print(f"check-tcpip-image: FAIL: {msg}")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    elf = sys.argv[1]
    phdrs = subprocess.run(
        ["readelf", "-lW", elf], check=True, capture_output=True, text=True
    ).stdout
    header = subprocess.run(
        ["readelf", "-h", elf], check=True, capture_output=True, text=True
    ).stdout
    m = re.search(r"Entry point address:\s+0x([0-9a-f]+)", header)
    if not m:
        fail("no entry point")
    entry = int(m.group(1), 16)
    etype = re.search(r"Type:\s+(\S+)", header).group(1)
    if etype != "EXEC":
        fail(f"not ET_EXEC ({etype})")
    if not (CAGE_BASE <= entry < CAGE_END):
        fail(f"entry {entry:#x} outside the cage")

    loads, others = [], []
    for line in phdrs.splitlines():
        lm = LOAD_RE.match(line)
        if lm:
            _off, va, _pa, _filesz, memsz, flags = lm.groups()
            loads.append((int(va, 16), int(memsz, 16), flags.replace(" ", "")))
            continue
        om = OTHER_RE.match(line)
        if om:
            others.append(om.group(1))
    bad = [t for t in others if t not in ALLOWED_OTHER]
    if bad:
        fail(f"segments the kernel's loader refuses: {bad}")
    if len(loads) != 3:
        fail(f"{len(loads)} PT_LOADs (want 3: text/rodata/data)")
    if [f for (_v, _m, f) in loads] != WANT_FLAGS:
        fail(f"PT_LOAD flags {loads} (want {WANT_FLAGS})")

    prev_end = None
    image_pages = 0
    shared_ok = False
    for va, memsz, flags in loads:
        first = va & ~(PAGE - 1)
        last = (va + memsz + PAGE - 1) & ~(PAGE - 1)
        if first < CAGE_BASE or last > CAGE_END:
            fail(
                f"PT_LOAD [{first:#x},{last:#x}) outside the cage "
                f"[{CAGE_BASE:#x},{CAGE_END:#x})"
            )
        if prev_end is not None and first - prev_end < PAGE:
            fail(f"adjacent PT_LOADs at {first:#x} (GuardGap: one absent page)")
        prev_end = last
        image_pages += (last - first) // PAGE
        if flags == "RW" and va == SHARED_PAGE:
            shared_ok = True
    if not shared_ok:
        fail(f"the writable PT_LOAD does not start at the shared page {SHARED_PAGE:#x}")
    need = image_pages + STACK_PAGES + TRAMPOLINE_PAGES
    if need > QUOTA_PAGES:
        fail(f"image {need} pages > the tcpip profile's {QUOTA_PAGES}")
    print(
        f"check-tcpip-image: PASS (3 PT_LOADs, cage ok, shared page {SHARED_PAGE:#x}, "
        f"{image_pages} image pages + {STACK_PAGES} stack + {TRAMPOLINE_PAGES} trampoline "
        f"= {need} <= {QUOTA_PAGES})"
    )


if __name__ == "__main__":
    main()
