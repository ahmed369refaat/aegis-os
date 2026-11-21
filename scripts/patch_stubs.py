#!/usr/bin/env python3
"""Patch kernel-x86_64/src/arch/stubs.rs with the 64 broker-owned device
vectors (49..=112, ADR-0019): one naked stub per vector + the lookup
array + the vector_handler match arm. Idempotent: skips if already
patched."""

import sys

PATH = "/home/z/my-project/aegis-os/kernel-x86_64/src/arch/stubs.rs"

MARK = "// 49..=112: broker-owned device vectors (ADR-0019)."
with open(PATH) as f:
    src = f.read()

if MARK in src:
    print("stubs.rs already patched — nothing to do")
    sys.exit(0)

# ── 1. the 64 macro invocations, after the irq48 block ──
anchor = "vector_stub!(irq48, 48, noerr);\n"
assert anchor in src, "irq48 anchor missing"
invocations = [f"vector_stub!(irq{v}, {v}, noerr);" for v in range(49, 113)]
block1 = (
    anchor
    + MARK
    + " No CPU error code. These land in the dispatch's broker route\n"
    + "// (ADR-0019): an owned vector delivers to its device's mailbox, an\n"
    + "// unowned one is a NAMED halt — the ADR-0010 discipline extended\n"
    + "// from the legacy 8259 range to the device range.\n"
    + "\n".join(invocations)
    + "\n"
)
src = src.replace(anchor, block1, 1)

# ── 2. the lookup array + match arm in vector_handler ──
arr_anchor = "pub fn vector_handler(vector: u8) -> (u64, u8) {"
assert arr_anchor in src, "vector_handler anchor missing"
arr_items = [f"irq{v}," for v in range(49, 113)]
grouped = "\n".join(
    "    " + " ".join(arr_items[i : i + 4]) for i in range(0, len(arr_items), 4)
)
array = (
    "/// The broker-owned device-vector stubs (49..=112, ADR-0019) in\n"
    "/// vector order — the IDT wiring and the broker's slot arithmetic\n"
    "/// both index this table.\n"
    "const DEVICE_STUBS: [extern \"C\" fn(); 64] = [\n" + grouped + "\n];\n\n"
    + arr_anchor
)
src = src.replace(arr_anchor, array, 1)

match_anchor = "        48 => irq48,\n"
assert match_anchor in src, "match arm anchor missing"
src = src.replace(
    match_anchor,
    match_anchor
    + "        // 49..=112: the broker-owned device vectors (ADR-0019).\n"
    + "        49..=112 => (DEVICE_STUBS[(vector - 49) as usize] as usize as u64, 0),\n",
    1,
)

# the panic arm's doc must not lie about the wired range
src = src.replace(
    "255) — see `idt::load` for the wiring policy.",
    "255) and the broker-owned device vectors (49..=112) — see\n/// `idt::load` for the wiring policy.",
    1,
)

with open(PATH, "w") as f:
    f.write(src)
print("patched: 64 device-vector stubs, the DEVICE_STUBS array, and the match arm")
