#!/usr/bin/env bash
# F16 (ADR-0006): the IST stacks must live in a WRITABLE NOBITS section
# (.bss). As plain `static`s they landed in .data and only worked because
# the kernel image mapping was writable — once the image is W^X, exception
# entry would fault on its own stacks. Symbol names are Rust-mangled, so
# symbols are located by address.
set -euo pipefail
cd "$(dirname "$0")/.."
KELF="${1:-target/x86_64-unknown-none/release/aegis-kernel}"
if [ ! -f "$KELF" ]; then
  echo "FAIL: kernel ELF not found: $KELF — build first (cargo build -p aegis-kernel --release --target x86_64-unknown-none) or pass a path: scripts/check-ist-sections.sh <kernel-elf>" >&2
  exit 1
fi
exec python3 - "$KELF" <<'PY'
import re
import subprocess
import sys

kelf = sys.argv[1]
NAMES = ("IST_DF", "IST_NMI", "IST_MC", "IST_SS", "IST_PF")

nm_out = subprocess.run(["nm", kelf], capture_output=True, text=True).stdout
syms = []
for line in nm_out.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[2].endswith(NAMES):
        syms.append((int(parts[0], 16), parts[1], parts[2]))

secs = []
out = subprocess.run(["readelf", "-SW", kelf], capture_output=True, text=True).stdout
for m in re.finditer(
    r"\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", out
):
    name, typ = m.group(1), m.group(2)
    addr, size = int(m.group(3), 16), int(m.group(4), 16)
    if addr:
        secs.append((name, typ, addr, size))

fail = 0
seen = set()
for addr, nmtype, name in syms:
    short = name.split("IST_")[-1]
    seen.add(short)
    sec = next(((n, t) for n, t, a, sz in secs if a <= addr < a + sz), None)
    if sec is None:
        print(f"FAIL: {short} at {addr:#x} has no containing section")
        fail = 1
        continue
    n, t = sec
    if t != "NOBITS" or nmtype.lower() != "b":
        print(f"FAIL: {short} at {addr:#x} is in {n}/{t} (nm {nmtype}) — must be writable NOBITS (.bss)")
        fail = 1

short_names = {n.split("_")[1] for n in NAMES}
missing = short_names - seen
if missing:
    print(f"FAIL: IST symbols missing: {sorted(missing)}")
    fail = 1

# F15 (ADR-0006): general form — every *mutable* symbol (nm type d/D
# for .data, b/B for .bss) must live in a writable section, and no
# mutable symbol may hide inside .text/.rodata. This catches any future
# `static mut` that lands somewhere the W^X image maps read-only.
for line in nm_out.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1] in ("d", "D", "b", "B"):
        addr, nmtype, name = int(parts[0], 16), parts[1], parts[2]
        sec = next(((n, t) for n, t, a, sz in secs if a <= addr < a + sz), None)
        if sec is None:
            continue  # absolute/linker symbols (e.g. section bounds)
        n, t = sec
        if n in (".text", ".rodata"):
            print(f"FAIL: mutable symbol {name} ({nmtype}) at {addr:#x} is in {n} — the W^X image maps it read-only")
            fail = 1

if not fail:
    print("IST SECTIONS: PASS (all IST_* in writable NOBITS .bss; no mutable symbol in .text/.rodata)")
sys.exit(1 if fail else 0)
PY
