#!/usr/bin/env bash
# Risk treatment 1 (ADR-0008's implementation lesson): inline asm that
# saves RBX with push/pop must move the value through the PUSHED STACK
# SLOT. An `out(reg)` temporary is allocation luck — if the allocator
# picks RBX itself, the restore-pop clobbers the result (observed as
# smep=off in one build, on in another: the SMEP/SMAP CPUID read went
# silently wrong). This guard makes the whole bug class CI-visible.
#
#   ./check-asm-patterns.sh             check kernel-x86_64/src
#   ./check-asm-patterns.sh --self-test prove the checker catches the bug
set -euo pipefail
cd "$(dirname "$0")/.."

# Every "push %rbx" must be followed by a store into (%rsp) BEFORE any
# "pop" — the bulletproof pattern (store-into-the-pushed-slot).
check_file() {
    awk '
        # Same-line case: the push and its pop share the line.
        state == 0 && /push[[:space:]]+%rbx/ {
            rest = substr($0, index($0, "push %rbx") + 9)
            pstore = index(rest, "(%rsp)")
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
            if (index($0, "(%rsp)") > 0 && /%rbx/) ok = 1
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
    if ! check_file "$tmp/good.rs" 2>/dev/null; then
        echo "SELF-TEST FAIL: the good sample was rejected"; exit 1
    fi
    if check_file "$tmp/bad.rs" 2>/dev/null; then
        echo "SELF-TEST FAIL: the bad sample was NOT caught"; exit 1
    fi
    echo "ASM PATTERN GUARD: self-test PASS (catches the allocation-luck push/pop %rbx pattern)"
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
