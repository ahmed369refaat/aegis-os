#!/usr/bin/env python3
"""Static worst-case stack depth of a linked x86-64 ELF (K22 measurement).

The package manager is no_alloc by design: every buffer is a fixed
stack array, so the user stack — not the heap — is the resource that
decides whether the image can run. This tool answers "how much stack
does it need?" from the binary itself instead of a guess:

- per function: the frame = the high-water mark of rsp adjustments over
  the function's instruction stream (each push 8 bytes, `sub $n,%rsp`,
  minus pops / `add $n,%rsp`); Rust emits no alloca, so this is exact
  for its codegen;
- call edges: direct `call <addr>` to a function start; every indirect
  call site is listed (vtable / function-pointer edges are invisible
  to a static pass, so they are reported, never assumed small);
- the answer: the longest path through the call graph from the entry
  (a DAG; recursion — a non-trivial SCC — is reported explicitly and
  counted ONE level deep, because a static pass cannot bound it).

Usage: pkg-stack-depth.py <elf> [--entry SYMBOL] [--root SYMBOL ...]
"""
import argparse
import bisect
import collections
import re
import subprocess
import sys

FUNC_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
INSN_RE = re.compile(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$")
DIRECT_CALL_RE = re.compile(r"^([0-9a-f]+) <")
IMM_RE = re.compile(r"^\$0x([0-9a-f]+)")


def disassemble(elf):
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", elf],
        check=True, capture_output=True, text=True,
    ).stdout
    funcs = collections.OrderedDict()  # addr -> name
    insns = collections.defaultdict(list)  # addr -> [(mnemonic, operands)]
    cur = None
    for line in out.splitlines():
        m = FUNC_RE.match(line)
        if m:
            cur = int(m.group(1), 16)
            funcs[cur] = m.group(2)
            continue
        m = INSN_RE.match(line)
        if m and cur is not None:
            insns[cur].append((m.group(2), m.group(3).strip()))
    return funcs, insns


def frame_of(body):
    """High-water mark of stack growth inside one function, in bytes.

    Only an instruction whose DESTINATION is `%rsp` moves the stack:
    `add (%rsp),%rbp` reads through rsp and must not count (that false
    positive zeroed 20 real frames on the first run of this tool).
    """
    cur = peak = 0
    for mn, ops in body:
        if mn.startswith("push"):
            cur += 8
        elif mn.startswith("pop"):
            cur -= 8
        elif mn.rstrip("qwl") in ("sub", "add") and ops.endswith("%rsp"):
            m = IMM_RE.match(ops)
            if m:
                imm = int(m.group(1), 16)
                cur += imm if mn.startswith("sub") else -imm
            else:
                # A register-sized rsp adjustment — alloca-shaped.
                return None
        if cur > peak:
            peak = cur
    return peak


def analyse(elf, entry, roots):
    funcs, insns = disassemble(elf)
    starts = sorted(funcs)
    by_name = {name: addr for addr, name in funcs.items()}

    frame, callees, indirect = {}, collections.defaultdict(set), {}
    dyn = []
    for addr in starts:
        body = insns.get(addr, [])
        f = frame_of(body)
        if f is None:
            dyn.append(funcs[addr])
        frame[addr] = f or 0
        for mn, ops in body:
            if mn == "call":
                m = DIRECT_CALL_RE.match(ops)
                if m:
                    tgt = int(m.group(1), 16)
                    # Round to the enclosing function start (a call may
                    # target a symbol that objdump printed as a label).
                    i = bisect.bisect_right(starts, tgt) - 1
                    if i >= 0:
                        callees[addr].add(starts[i])
                else:
                    indirect[addr] = indirect.get(addr, 0) + 1

    # Tarjan SCC over the call graph.
    index, low, onstk, stack, sccs = {}, {}, set(), [], []
    counter = [0]
    sys.setrecursionlimit(max(10000, len(starts) * 4))

    def strong(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        onstk.add(v)
        for w in callees.get(v, ()):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in onstk:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                onstk.discard(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for v in starts:
        if v not in index:
            strong(v)
    comp_of = {}
    for ci, comp in enumerate(sccs):
        for v in comp:
            comp_of[v] = ci
    recursive = [comp for comp in sccs if len(comp) > 1 or any(v in callees.get(v, ()) for v in comp)]

    # Longest path over the condensation (memoised).
    memo = {}

    def depth(ci):
        if ci in memo:
            return memo[ci]
        memo[ci] = 0  # cycles are already collapsed
        best = 0
        for v in sccs[ci]:
            total = frame[v]
            for w in callees.get(v, ()):
                cj = comp_of[w]
                total = max(total, frame[v] + depth(cj))
            best = max(best, total)
        memo[ci] = best
        return best

    def path_from(v):
        """The heaviest chain starting at v: [(name, frame), ...]."""
        chain, seen = [], set()
        while v not in seen:
            seen.add(v)
            chain.append((funcs[v], frame[v]))
            nxt, best = None, -1
            for w in callees.get(v, ()):
                d = depth(comp_of[w])
                if d > best:
                    nxt, best = w, d
            if nxt is None:
                break
            v = nxt
        return chain

    return {
        "funcs": funcs, "frame": frame, "callees": callees, "indirect": indirect,
        "dyn": dyn, "recursive": recursive, "by_name": by_name, "depth": depth,
        "comp_of": comp_of, "path_from": path_from,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--entry", default="_start")
    ap.add_argument("--root", action="append", default=[],
                    help="extra function NAME counted as a root (e.g. the real entry)")
    a = ap.parse_args()
    r = analyse(a.elf, a.entry, a.root)

    names = [a.entry] + a.root
    roots = [r["by_name"][n] for n in names if n in r["by_name"]]
    missing = [n for n in names if n not in r["by_name"]]

    worst, worst_chain, worst_root = 0, [], None
    for v in roots:
        chain = r["path_from"](v)
        total = sum(f for _, f in chain)
        if total > worst:
            worst, worst_chain, worst_root = total, chain, v
    if not roots:
        # No entry symbol: take the global maximum over every function.
        for v in r["funcs"]:
            chain = r["path_from"](v)
            total = sum(f for _, f in chain)
            if total > worst:
                worst, worst_chain, worst_root = total, chain, v

    print(f"functions: {len(r['funcs'])}")
    print(f"entry roots: {[r['funcs'][v] for v in roots]}" +
          (f"  (MISSING: {missing})" if missing else ""))
    print(f"worst direct-call chain: {worst} bytes ({worst / 1024:.1f} KiB)")
    print("chain (frame bytes per function):")
    for name, f in worst_chain:
        print(f"  {f:7d}  {name[:96]}")

    # The largest single frames anywhere in the image.
    top = sorted(r["frame"].items(), key=lambda kv: -kv[1])[:8]
    print("largest single frames:")
    for v, f in top:
        print(f"  {f:7d}  {r['funcs'][v][:96]}")

    if r["dyn"]:
        print(f"register-sized rsp adjustments (alloca-shaped): {len(r['dyn'])}")
        for n in r["dyn"][:10]:
            print(f"          {n[:96]}")
    if r["recursive"]:
        print(f"recursive components (counted ONE level deep — a static pass cannot bound them): "
              f"{len(r['recursive'])}")
        for comp in r["recursive"][:10]:
            print("          " + ", ".join(r["funcs"][v][:60] for v in comp[:4]))
    # Indirect calls on the worst chain are the honest blind spots.
    on_chain = {n for n, _ in worst_chain}
    blind = [(n, r["indirect"][r["by_name"][n]]) for n in on_chain if n in r["indirect"]]
    print(f"indirect call sites in the image: {sum(r['indirect'].values())} "
          f"in {len(r['indirect'])} functions; on the worst chain: {len(blind)}")
    for n, c in blind[:12]:
        print(f"          {c} site(s) in {n[:88]}")
    # SysV red zone (leaf functions may use 128 bytes below rsp) is not
    # counted in frame sizes — callers add it in their budget.
    print("note: +128 bytes SysV red zone and the return address are NOT included")


if __name__ == "__main__":
    main()
