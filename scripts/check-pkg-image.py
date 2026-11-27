#!/usr/bin/env python3
"""Check the package manager's linked image against its memory contract
(K22). Runs at EVERY image build (boot.sh step [0d]) so a layout shift
fails the build instead of failing inside execve.

The contract (kernel-x86_64/src/mm/user_layout.rs `SERVICE`):
  - three PT_LOADs — text R+X, rodata R, data R+W — and nothing the
    kernel's loader refuses (PT_INTERP, PT_DYNAMIC, unknown types);
  - every segment inside the image cage [0x400000, 0x480000);
  - one ABSENT page between neighbouring segments (the kernel's
    ten-check policy refuses adjacent regions — GuardGap);
  - the entry inside the executable segment;
  - image pages + the contract's overhead (64 stack + 1 trampoline)
    within the package manager's quota (192 pages);
  - the static worst direct-call stack chain under 80 KiB: the solver
    recurses ~3.4 KiB per level, and chain + recursion must fit the
    256 KiB stack (measured by scripts/pkg-stack-depth.py).

Exit status 0 = the image honors the contract.
"""
import re
import subprocess
import sys

CAGE_BASE = 0x400000
CAGE_END = 0x480000
STACK_PAGES = 64
TRAMPOLINE_PAGES = 1
QUOTA_PAGES = 192
STACK_BYTES = STACK_PAGES * 4096
CHAIN_BUDGET = 80 * 1024
PAGE = 4096

LOAD_RE = re.compile(
    r"^\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+([RWE ]{1,3})"
)
OTHER_RE = re.compile(r"^\s*(\S+)\s+0x")
ALLOWED_OTHER = {"NOTE", "PHDR", "GNU_STACK", "GNU_RELRO", "GNU_PROPERTY"}
WANT_FLAGS = ["RE", "R", "RW"]


def fail(msg):
    print(f"pkg-image: FAIL: {msg}")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    elf = sys.argv[1]
    phdrs = subprocess.run(
        ["readelf", "-lW", elf], check=True, capture_output=True, text=True
    ).stdout
    entry_line = subprocess.run(
        ["readelf", "-h", elf], check=True, capture_output=True, text=True
    ).stdout
    m = re.search(r"Entry point address:\s+0x([0-9a-f]+)", entry_line)
    if not m:
        fail("no entry point")
    entry = int(m.group(1), 16)
    etype = re.search(r"Type:\s+(\S+)", entry_line).group(1)
    if etype != "EXEC":
        fail(f"not ET_EXEC ({etype})")

    loads, others = [], []
    for line in phdrs.splitlines():
        lm = LOAD_RE.match(line)
        if lm:
            off, va, _pa, filesz, memsz, flags = lm.groups()
            # readelf pads the flag column ("R E") — compare letters.
            loads.append(
                (int(off, 16), int(va, 16), int(filesz, 16), int(memsz, 16), flags.replace(" ", ""))
            )
            continue
        om = OTHER_RE.match(line)
        if om:
            others.append(om.group(1))
    bad = [t for t in others if t not in ALLOWED_OTHER]
    if bad:
        fail(f"program header types the kernel's loader refuses: {bad}")
    if len(loads) != len(WANT_FLAGS):
        fail(f"expected {len(WANT_FLAGS)} PT_LOADs, found {len(loads)}")
    pages = 0
    prev_end = None
    for i, (off, va, filesz, memsz, flags) in enumerate(loads):
        if set(flags) != set(WANT_FLAGS[i]):
            fail(f"PT_LOAD {i} flags {flags!r}, expected {WANT_FLAGS[i]!r}")
        if "W" in flags and "E" in flags:
            fail(f"PT_LOAD {i} is W+X")
        if filesz > memsz:
            fail(f"PT_LOAD {i} filesz > memsz")
        if va % PAGE != off % PAGE:
            fail(f"PT_LOAD {i} not page-congruent (va {va:#x} off {off:#x})")
        first = va & ~(PAGE - 1)
        last = (va + memsz + PAGE - 1) & ~(PAGE - 1)
        if first < CAGE_BASE or last > CAGE_END:
            fail(f"PT_LOAD {i} [{first:#x}, {last:#x}) outside the cage [{CAGE_BASE:#x}, {CAGE_END:#x})")
        if prev_end is not None and first - prev_end < PAGE:
            fail(
                f"PT_LOAD {i} starts {first:#x} only {first - prev_end:#x} above the previous end "
                f"{prev_end:#x} — the policy needs one absent page"
            )
        if i == 0 and not (first <= entry < last):
            fail(f"entry {entry:#x} outside the executable segment")
        if i == 0 and "E" not in flags:
            fail("the first PT_LOAD is not executable")
        if "E" in flags and i != 0:
            fail(f"PT_LOAD {i} is executable — only the text may be")
        prev_end = last
        pages += (last - first) // PAGE

    need = pages + STACK_PAGES + TRAMPOLINE_PAGES
    if need > QUOTA_PAGES:
        fail(f"image needs {need} pages ({pages} + overhead), quota is {QUOTA_PAGES}")
    top = max((va + memsz for _, va, _, memsz, _ in loads), default=0)
    print(
        f"pkg-image: {len(loads)} PT_LOADs, {pages} pages + {STACK_PAGES + TRAMPOLINE_PAGES} overhead "
        f"= {need} of {QUOTA_PAGES}; cage [{CAGE_BASE:#x}, {CAGE_END:#x}), image ends {top:#x}"
    )

    # The stack budget: the static worst direct-call chain (from the
    # real entry, `_start`) plus the solver's recursion must fit.
    depth = subprocess.run(
        [
            sys.executable,
            "scripts/pkg-stack-depth.py",
            elf,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if depth.returncode != 0:
        fail(f"pkg-stack-depth.py failed: {depth.stderr.strip()[:200]}")
    dm = re.search(r"worst direct-call chain: (\d+) bytes", depth.stdout)
    if not dm:
        fail("pkg-stack-depth.py printed no chain")
    chain = int(dm.group(1))
    if chain > CHAIN_BUDGET:
        fail(
            f"worst direct-call stack chain {chain} bytes > budget {CHAIN_BUDGET} "
            f"(the solver's recursion needs the rest of the {STACK_BYTES} stack)"
        )
    print(
        f"pkg-image: worst direct-call stack chain {chain} bytes "
        f"({chain * 100 // STACK_BYTES}% of the {STACK_BYTES}-byte stack)"
    )


if __name__ == "__main__":
    main()
