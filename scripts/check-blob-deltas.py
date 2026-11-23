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
# Handler 1 (mode 3, the victim): sig_handler sits DELTA bytes before
# next_instr.
DELTA = 0x1F  # sig_handler sits this many bytes BEFORE next_instr
# `mov $0x51515151,%rax` then `mov %rax,0x403060` (objdump-verified)
EXPECTED = bytes.fromhex("48 c7 c0 51 51 51 51 48 89 04 25 60 30 40 00")
# Handler 2 (mode 14, the flag forger — ADR-0031): forge_handler sits
# DELTA14 bytes before next_instr14. First bytes: `mov 0x28(%rsp),%rax`
# (the frame's saved-rflags word, objdump-verified).
DELTA14 = 0x2D
EXPECTED14 = bytes.fromhex("48 8b 44 24 28")


def main() -> int:
    dis = subprocess.run(
        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
         "--adjust-vma=0x400000", BLOB],
        capture_output=True, text=True, check=True).stdout
    pops = [int(l.split(":")[0].strip(), 16) for l in dis.splitlines()
            if l.strip().endswith("pop    %rsi")]
    if len(pops) != 2:
        print(f"CHECK-BLOB-DELTA FAIL: expected exactly two `pop %rsi` "
              f"(next_instr + next_instr14), found {len(pops)}")
        return 1
    # Flat blob at CODE_BASE=0x400000: the byte offset IS addr - base.
    # (objdump -s prints nothing for a flat binary — read the file.)
    with open(BLOB, "rb") as f:
        blob = f.read()
    ok = True
    for name, addr, delta, expected in (
        ("sig_handler (mode 3)", pops[0], DELTA, EXPECTED),
        ("forge_handler (mode 14, ADR-0031)", pops[1], DELTA14, EXPECTED14),
    ):
        landing = addr - delta
        off = landing - 0x400000
        got = blob[off:off + len(expected)]
        if got.startswith(expected):
            print(f"CHECK-BLOB-DELTA OK: {name} landing 0x{landing:x} "
                  f"= the pinned bytes (delta 0x{delta:x} pinned)")
        else:
            print(f"CHECK-BLOB-DELTA FAIL: {name} landing 0x{landing:x} "
                  f"holds {got.hex()}, expected {expected.hex()} — the "
                  f"hand-pinned delta in examples/ring3-preempt/src/lib.rs "
                  f"is stale (re-measure the handler's offset and update "
                  f"the delta here and in the blob)")
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
