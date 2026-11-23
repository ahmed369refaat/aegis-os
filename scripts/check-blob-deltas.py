#!/usr/bin/env python3
"""check-blob-deltas.py — pin the blob's hand-measured code deltas.

ADR-0030's round-X hunt artifact: ring3-preempt's mode 3 registers its
signal handler via `pop rsi; sub rsi, DELTA` — a hand-pinned constant,
because this toolchain's global_asm pre-parser rejects rip-relative
forms. sig_handler now lives IMMEDIATELY before mode 3 (the round-Y
relocation), so the delta spans only mode 3's own prologue — but the
pin must still hold at every build: any silent code change between the
handler and next_instr shifts the landing, and the kernel then delivers
SIGUSR1 into arbitrary code (round X: a debug loop in mode 7 moved the
handler +0xC, the stale delta delivered into the hex helper, and the
victim died writing through rdi=0xA — the "reproduction on demand" that
was actually an artifact).

This script disassembles the built flat blob and asserts the landing
address (next_instr - DELTA) is exactly the flag-writer
`mov $0x51515151,%rax; mov %rax,0x403060` — the handler's first bytes.
boot.sh runs it after the blob rebuild; a mismatch fails the build.
"""
import subprocess
import sys

BLOB = "kernel-x86_64/blob/ring3-preempt.bin"
DELTA = 0x1F  # sig_handler sits this many bytes BEFORE next_instr
# `mov $0x51515151,%rax` then `mov %rax,0x403060` (objdump-verified)
EXPECTED = bytes.fromhex("48 c7 c0 51 51 51 51 48 89 04 25 60 30 40 00")


def main() -> int:
    dis = subprocess.run(
        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
         "--adjust-vma=0x400000", BLOB],
        capture_output=True, text=True, check=True).stdout
    pops = [int(l.split(":")[0].strip(), 16) for l in dis.splitlines()
            if l.strip().endswith("pop    %rsi")]
    if len(pops) != 1:
        print(f"CHECK-BLOB-DELTA FAIL: expected exactly one `pop %rsi` "
              f"(next_instr), found {len(pops)}")
        return 1
    landing = pops[0] - DELTA
    # Flat blob at CODE_BASE=0x400000: the byte offset IS addr - base.
    # (objdump -s prints nothing for a flat binary — read the file.)
    with open(BLOB, "rb") as f:
        blob = f.read()
    off = landing - 0x400000
    got = blob[off:off + len(EXPECTED)]
    if got.startswith(EXPECTED):
        print(f"CHECK-BLOB-DELTA OK: handler landing 0x{landing:x} "
              f"= the flag-writer (delta 0x{DELTA:x} pinned)")
        return 0
    print(f"CHECK-BLOB-DELTA FAIL: landing 0x{landing:x} holds {got.hex()}, "
          f"expected {EXPECTED.hex()} — the hand-pinned delta in "
          f"examples/ring3-preempt/src/lib.rs is stale (re-measure "
          f"sig_handler's offset and update DELTA here and the blob)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
