#!/usr/bin/env bash
# Risk treatment 1 (ADR-0008's implementation lesson): inline asm that
# saves RBX with push/pop must move the RESULT VALUE through the PUSHED
# STACK SLOT. An `out(reg)` temporary is allocation luck — if the
# allocator picks RBX itself, the restore-pop clobbers the result
# (observed as smep=off in one build, on in another: the SMEP/SMAP
# CPUID read went silently wrong). The value moved through the slot may
# be ANY register the asm wants to export (cpuid7_ebx stores %rbx,
# cpuid1_ecx stores %rcx) — the invariant is the store INTO the slot,
# not which register is stored. This guard makes the whole bug class
# CI-visible.
#
#   ./check-asm-patterns.sh             check kernel-x86_64/src
#   ./check-asm-patterns.sh --self-test prove the checker catches the bug
set -euo pipefail
cd "$(dirname "$0")/.."

# Every "push %rbx" must be followed by a store INTO (%rsp) — the mov
# DESTINATION, att_syntax puts it last — BEFORE any "pop". A bare load
# like "movq (%rsp), %rax" does not count as the bulletproof pattern.
check_file() {
    awk '
        # A store into the pushed slot: (%rsp) appears as a mov
        # destination (", (%rsp)" — after a comma, so reads do not match).
        function slot_store(line) {
            return index(line, ", (%rsp)") > 0
        }
        # Same-line case: the push and its pop share the line.
        state == 0 && /push[[:space:]]+%rbx/ {
            rest = substr($0, index($0, "push %rbx") + 9)
            pstore = slot_store(rest) ? index(rest, ", (%rsp)") : 0
            ppop = index(rest, "pop")
            if (ppop > 0) {
                if (!(pstore > 0 && pstore < ppop)) {
                    print FILENAME ":" FNR ": push %rbx with a pop and no store into the pushed slot on the same line — use the ADR-0008 bulletproof pattern (an out(reg) temporary can BE %rbx and the pop silently clobbers it)"
                    bad = 1
                }
                next
            }
            # Push without a pop on this line: multi-line block.
            state = 1; ok = 0; next
        }
        # Multi-line case: the store must appear before any pop.
        state == 1 {
            if (slot_store($0)) ok = 1
            if (/pop/) {
                if (!ok) {
                    print FILENAME ":" FNR ": push %rbx without a store into the pushed slot before pop — use the ADR-0008 bulletproof pattern (an out(reg) temporary can BE %rbx and the pop silently clobbers it)"
                    bad = 1
                }
                state = 0
            }
            next
        }
        END { exit bad ? 1 : 0 }
    ' "$1"
}

if [ "${1:-}" = "--self-test" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    # GOOD: the bulletproof pattern.
    cat > "$tmp/good.rs" <<'EOS'
fn good() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq %rbx, (%rsp)", "pop {b}", b = out(reg) b);
    }
}
EOS
    # BAD: the allocation-luck pattern that shipped the smep=off bug.
    cat > "$tmp/bad.rs" <<'EOS'
fn bad() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq %rbx, {b}", "pop %rbx", b = out(reg) b);
    }
}
EOS
    # GOOD: the same bulletproof pattern exporting a DIFFERENT register
    # (the cpuid1_ecx shape — the store through the slot is the
    # invariant, not which register is stored).
    cat > "$tmp/good-ecx.rs" <<'EOS'
fn good_ecx() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq %rcx, (%rsp)", "pop {c}", c = out(reg) c);
    }
}
EOS
    # BAD: reads the slot but never stores the result into it.
    cat > "$tmp/bad-load.rs" <<'EOS'
fn bad_load() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq (%rsp), %rax", "pop %rbx");
    }
}
EOS
    if ! check_file "$tmp/good.rs" 2>/dev/null; then
        echo "SELF-TEST FAIL: the good sample was rejected"; exit 1
    fi
    if ! check_file "$tmp/good-ecx.rs" 2>/dev/null; then
        echo "SELF-TEST FAIL: the good non-%rbx-slot store was rejected"; exit 1
    fi
    if check_file "$tmp/bad.rs" 2>/dev/null; then
        echo "SELF-TEST FAIL: the bad sample was NOT caught"; exit 1
    fi
    if check_file "$tmp/bad-load.rs" 2>/dev/null; then
        echo "SELF-TEST FAIL: the load-only sample was NOT caught"; exit 1
    fi
    echo "ASM PATTERN GUARD: self-test PASS (catches the allocation-luck push/pop %rbx pattern; accepts any store through the pushed slot)"
    exit 0
fi

fail=0
while IFS= read -r f; do
    if ! check_file "$f"; then
        fail=1
    fi
done < <(grep -rl 'push %rbx' kernel-x86_64/src --include='*.rs' 2>/dev/null || true)

if [ "$fail" -eq 0 ]; then
    echo "ASM PATTERN GUARD: PASS (every push/pop %rbx window stores through the pushed slot)"
fi
exit "$fail"
