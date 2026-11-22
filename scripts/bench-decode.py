#!/usr/bin/env python3
"""ADR-0028: decode the blob's self-reported bench metrics.

The blob (mode 11) times every operation end-to-end with rdtsc —
syscall entry, park, wake, resume: what a real caller pays — and
self-reports the raw TSC deltas in hex through SYS_WRITE. The kernel
prints the ACPI-calibrated tsc_hz beside them. This script converts.

Usage:
    python3 scripts/bench-decode.py <boot-log>

The `[BENCH]` line: ten hex words, in order:
    yield_min yield_sum yield_cnt rtt_min rtt_sum rtt_cnt
    grant cow_min cow_sum cow_cnt
(The grant is a single sample; min/sum/cnt describe the loops.)
"""

import re
import sys

WORDS = [
    ("yield_min", "min"), ("yield_sum", "sum"), ("yield_cnt", "cnt"),
    ("rtt_min", "min"), ("rtt_sum", "sum"), ("rtt_cnt", "cnt"),
    ("grant", "one"), ("cow_min", "min"), ("cow_sum", "sum"),
    ("cow_cnt", "cnt"),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    data = open(sys.argv[1], "rb").read().decode("latin1")
    m = re.search(r"\[BENCH\] ((?:[0-9a-fA-F]{16} ){9,10}[0-9a-fA-F]{16})", data)
    if not m:
        print("no [BENCH] line found")
        return 1
    hz = re.search(r"bench: tsc_hz=(\d+)", data)
    if not hz:
        print("no tsc_hz line found")
        return 1
    hz = int(hz.group(1))
    vals = [int(w, 16) for w in m.group(1).split()]
    print(f"tsc_hz = {hz:,} Hz  (1 cycle = {1e9/hz:.3f} ns)")
    print(f"{'metric':<12}{'cycles':>14}{'ns':>14}{'us':>12}")
    v = dict(zip([w[0] for w in WORDS], vals))
    for name, kind in WORDS:
        cyc = v[name]
        ns = cyc * 1e9 / hz
        line = f"{name:<12}{cyc:>14,}{ns:>14,.0f}{ns/1000:>12.2f}"
        if kind in ("min", "sum") and name.endswith(("_min", "_sum")):
            base = name.rsplit("_", 1)[0]
            cnt = v.get(f"{base}_cnt")
            if kind == "sum" and cnt:
                avg = cyc / cnt
                line += f"   (avg {avg*1e9/hz:>10,.0f} ns over {cnt})"
        print(line)
    # the derived story
    print()
    print("derived:")
    if "rtt_sum" in v and v.get("rtt_cnt"):
        avg = v["rtt_sum"] / v["rtt_cnt"] * 1e9 / hz
        print(f"  call/reply RTT (avg)     : {avg:>10,.0f} ns")
    if "yield_sum" in v and v.get("yield_cnt"):
        avg = v["yield_sum"] / v["yield_cnt"] * 1e9 / hz
        print(f"  park+dispatch floor (avg): {avg:>10,.0f} ns")
    if "grant" in v:
        print(f"  grant syscall (one)      : {v['grant']*1e9/hz:>10,.0f} ns")
    if "cow_sum" in v and v.get("cow_cnt"):
        avg = v["cow_sum"] / v["cow_cnt"] * 1e9 / hz
        print(f"  CoW fault+copy (avg)     : {avg:>10,.0f} ns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
