#!/usr/bin/env python3
"""P1-2: the rustc citizen's build contract check.

`ld -n` packs the two PT_LOADs at small file offsets (0xB0/0xD2), and
the link script pins the vaddrs to 0x4000B0/0x4030D2 so the loader's
congruence gate (`p_vaddr % 4096 == p_offset % 4096`, src/elf.rs —
the byte copy at [vaddr, vaddr+filesz) must be page-honest) holds BY
CONSTRUCTION. This script fails the build if that coupling drifts:
an ld layout change that moves a section would produce a
NotCongruent image, and the failure belongs HERE, at build time, not
in a boot lane.

Also pins the size budget: the whole point of the packed layout is a
citizen under the ramfs's 1-KiB INLINE window (no large-file spill
slot), so an image that outgrows it fails the build.
"""
import subprocess
import sys

IMG = 'kernel-x86_64/blob/rust-hello.elf'
PAGE = 4096
INLINE_MAX = 1024

out = subprocess.run(['readelf', '-lW', IMG], capture_output=True, text=True,
                     check=True).stdout
loads = [l.split() for l in out.splitlines() if l.strip().startswith('LOAD')]
if len(loads) != 2:
    sys.exit(f'citizen: expected 2 PT_LOADs, saw {len(loads)}')

size = int(subprocess.run(['stat', '-c', '%s', IMG], capture_output=True,
                          text=True, check=True).stdout.strip())
if size > INLINE_MAX:
    sys.exit(f'citizen: {size} B > the {INLINE_MAX}-B inline window — '
             'the packed layout lost its point')

for l in loads:
    # readelf -lW: LOAD offset vaddr paddr filesz memsz flags align
    off, vaddr = int(l[1], 16), int(l[2], 16)
    if vaddr % PAGE != off % PAGE:
        sys.exit(f'citizen: vaddr {vaddr:#x} (mod {PAGE} = {vaddr % PAGE:#x}) '
                 f'not congruent with offset {off:#x} (mod {off % PAGE:#x}) — '
                 'the loader would refuse NotCongruent')

flags = [' '.join(l[6:-1]) for l in loads]
if flags != ['R E', 'RW']:
    sys.exit(f'citizen: segment flags {flags}, expected R E / RW (W^X)')

print(f'CHECK-CITIZEN OK: {IMG} — 2 PT_LOADs congruent, {size} B '
      f'(inline), flags {flags}')
