#!/usr/bin/env bash
# Risk treatment 1 (ADR-0008's implementation lesson), extended in round K.
#
# Rule 1 (round I): inline asm that saves RBX with push/pop must move the
# RESULT VALUE through the PUSHED STACK SLOT. An `out(reg)` temporary is
# allocation luck — if the allocator picks RBX itself, the restore-pop
# clobbers the result (observed as smep=off in one build, on in another:
# the SMEP/SMAP CPUID read went silently wrong). The value moved through
# the slot may be ANY register the asm wants to export — the invariant is
# the store INTO the slot, not which register is stored.
#
# Rule 2 (round K): an asm block that executes CPUID must not use
# `out(reg)`/`inout(reg)` template operands AT ALL. rustc 1.100.0 CAN
# allocate RBX to an out(reg) (verified: with 15 simultaneous out(reg)
# operands the allocator picks ... r11 rbx last), so any out(reg) in a
# block that must preserve RBX across CPUID is one audit away from the
# cpuid1_ecx bug — `push %rbx; cpuid; movq %rcx,{c}; pop %rbx` shipped
# exactly that and the pop silently overwrote the result. The round K
# shape uses ONLY fixed registers (RBX parked in fixed RSI, results
# exported from fixed eax/ecx/esi/edx operands), making the wrong
# allocation impossible instead of merely harmless. This guard makes
# the whole bug class CI-visible.
#
#   ./check-asm-patterns.sh             check kernel-x86_64/src
#   ./check-asm-patterns.sh --self-test prove the checker catches the bugs
set -euo pipefail
cd "$(dirname "$0")/.."

# Rule 1: every "push %rbx" must be followed by a store INTO (%rsp) —
# the mov DESTINATION, att_syntax puts it last — BEFORE any "pop". A
# bare load like "movq (%rsp), %rax" does not count.
check_pushpop() {
    awk '
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
                    print FILENAME ":" FNR ": push %rbx with a pop and no store into the pushed slot on the same line — move the result through the pushed slot (rule 1)"
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
                    print FILENAME ":" FNR ": push %rbx without a store into the pushed slot before pop — move the result through the pushed slot (rule 1)"
                    bad = 1
                }
                state = 0
            }
            next
        }
        END { exit bad ? 1 : 0 }
    ' "$1"
}

# Rule 2: an asm! statement that executes CPUID must not carry any
# out(reg)/inout(reg) template operand. The statement is tracked by
# paren depth from "asm!(" to its balancing close (line comments are
# stripped first so comment parens cannot unbalance the count).
check_cpuid_reg() {
    awk '
        # Strip // comments so their parens never skew the depth.
        { line = $0; sub(/\/\/.*/, "", line) }
        state == 0 && /asm!\(/ {
            state = 1
            depth = gsub(/\(/, "(", line) - gsub(/\)/, ")", line)
            has_cpuid = (line ~ /"cpuid"/)
            has_reg = (line ~ /(out|inout)\(reg\)/)
            next
        }
        state == 1 {
            if (line ~ /"cpuid"/) has_cpuid = 1
            if (line ~ /(out|inout)\(reg\)/) has_reg = 1
            depth += gsub(/\(/, "(", line) - gsub(/\)/, ")", line)
            if (depth <= 0) {
                if (has_cpuid && has_reg) {
                    print FILENAME ":" FNR ": asm block runs CPUID with an out(reg)/inout(reg) template operand — allocation luck (the allocator CAN pick %rbx); use only fixed registers (rule 2, round K)"
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
    # GOOD (rule 1, non-cpuid): the bulletproof stack-slot pattern for a
    # push/pop %rbx save that does not execute CPUID.
    cat > "$tmp/good.rs" <<'EOS'
fn good() {
    unsafe {
        core::arch::asm!("push %rbx", "movq %rbx, (%rsp)", "movq $5, %rbx", "pop {b}", b = out(reg) b);
    }
}
EOS
    # BAD (rule 1): the allocation-luck pattern that shipped the smep=off bug.
    cat > "$tmp/bad.rs" <<'EOS'
fn bad() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq %rbx, {b}", "pop %rbx", b = out(reg) b);
    }
}
EOS
    # GOOD (rule 1): the same bulletproof pattern exporting a DIFFERENT
    # register — the store through the slot is the invariant. Non-cpuid
    # block: under rule 2 a CPUID block with out(reg) is rejected.
    cat > "$tmp/good-ecx.rs" <<'EOS'
fn good_ecx() {
    unsafe {
        core::arch::asm!("push %rbx", "rdtsc", "movq %rcx, (%rsp)", "pop {c}", c = out(reg) c);
    }
}
EOS
    # BAD (rule 2): the round-I "bulletproof" cpuid shape — the value
    # DOES travel the pushed slot, but the out(reg) operand is still
    # allocation luck; round K bans out(reg) in CPUID blocks outright.
    cat > "$tmp/bad-ecx-slot.rs" <<'EOS'
fn round_i_shape_now_banned() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq %rcx, (%rsp)", "pop {c}", c = out(reg) c);
    }
}
EOS
    # BAD (rule 1, the EXACT round-K finding): cpuid1_ecx as it shipped —
    # the result stored into the out(reg) operand, not the slot, so a
    # pop into %rbx (if the allocator picks rbx) silently overwrites it.
    cat > "$tmp/bad-ecx-exact.rs" <<'EOS'
fn cpuid1_ecx_as_shipped() {
    unsafe {
        core::arch::asm!(
            "push %rbx",
            "cpuid",
            "movq %rcx, {c}",
            "pop %rbx",
            in("eax") 1u32,
            inout("ecx") 0u32 => _,
            c = out(reg) c,
            options(att_syntax),
        );
    }
}
EOS
    # BAD (rule 2, no push/pop at all): CPUID plus an out(reg) — the
    # allocation-luck class without any stack window to catch it.
    cat > "$tmp/bad-cpuid-reg.rs" <<'EOS'
fn bad_cpuid_reg() {
    unsafe {
        core::arch::asm!("cpuid", in("eax") 7u32, out("ecx") _, b = out(reg) b);
    }
}
EOS
    # GOOD (rules 1+2, round K shape): cpuid1_ecx rewritten — fixed
    # registers only, RBX parked in RSI, result from inout("ecx").
    cat > "$tmp/good-fixed.rs" <<'EOS'
fn cpuid1_ecx() {
    unsafe {
        core::arch::asm!(
            "movq %rbx, %rsi",
            "cpuid",
            "movq %rsi, %rbx",
            in("eax") 1u32,
            inout("ecx") 0u32 => c,
            lateout("eax") _,
            lateout("edx") _,
            out("rsi") _,
            options(att_syntax, nostack),
        );
    }
}
EOS
    # GOOD (rules 1+2, round K shape): cpuid7_ebx rewritten — the wanted
    # EBX exported from fixed ESI after the 64-bit xchg with parked RBX.
    cat > "$tmp/good-ebx-fixed.rs" <<'EOS'
fn cpuid7_ebx() {
    unsafe {
        core::arch::asm!(
            "movq %rbx, %rsi",
            "cpuid",
            "xchgq %rbx, %rsi",
            in("eax") 7u32,
            in("ecx") 0u32,
            lateout("eax") _,
            lateout("ecx") _,
            lateout("edx") _,
            out("esi") b,
            options(att_syntax, nostack),
        );
    }
}
EOS
    # GOOD (rule 2 not tripped by unrelated asm): rdrand with out(reg)
    # is fine — it does not execute CPUID and has no RBX window.
    cat > "$tmp/good-rdrand.rs" <<'EOS'
fn rdrand16() {
    unsafe {
        asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nostack))
    }
}
EOS
    # BAD (rule 1): reads the slot but never stores the result into it.
    cat > "$tmp/bad-load.rs" <<'EOS'
fn bad_load() {
    unsafe {
        core::arch::asm!("push %rbx", "cpuid", "movq (%rsp), %rax", "pop %rbx");
    }
}
EOS
    run_case() { # name, file, expect_ok(0/1)
        local rc=0
        check_pushpop "$2" >/dev/null 2>&1 || rc=1
        check_cpuid_reg "$2" >/dev/null 2>&1 || rc=1
        if [ "$3" -eq 0 ] && [ "$rc" -ne 0 ]; then
            echo "SELF-TEST FAIL: the good sample $1 was rejected"; exit 1
        fi
        if [ "$3" -eq 1 ] && [ "$rc" -eq 0 ]; then
            echo "SELF-TEST FAIL: the bad sample $1 was NOT caught"; exit 1
        fi
    }
    run_case good.rs            "$tmp/good.rs"            0
    run_case good-ecx.rs        "$tmp/good-ecx.rs"        0
    run_case good-fixed.rs      "$tmp/good-fixed.rs"      0
    run_case good-ebx-fixed.rs  "$tmp/good-ebx-fixed.rs"  0
    run_case good-rdrand.rs     "$tmp/good-rdrand.rs"     0
    run_case bad.rs             "$tmp/bad.rs"             1
    run_case bad-ecx-exact.rs   "$tmp/bad-ecx-exact.rs"   1
    run_case bad-ecx-slot.rs    "$tmp/bad-ecx-slot.rs"    1
    run_case bad-cpuid-reg.rs   "$tmp/bad-cpuid-reg.rs"   1
    run_case bad-load.rs        "$tmp/bad-load.rs"        1
    echo "ASM PATTERN GUARD: self-test PASS (rule 1: push/pop %rbx must store through the slot; rule 2: no out(reg) near CPUID; both catch the historical shapes)"
    exit 0
fi

fail=0
while IFS= read -r f; do
    if ! check_pushpop "$f"; then
        fail=1
    fi
done < <(grep -rl 'push %rbx' kernel-x86_64/src --include='*.rs' 2>/dev/null || true)

while IFS= read -r f; do
    if ! check_cpuid_reg "$f"; then
        fail=1
    fi
done < <(grep -rl '"cpuid"' kernel-x86_64/src --include='*.rs' 2>/dev/null || true)

if [ "$fail" -eq 0 ]; then
    echo "ASM PATTERN GUARD: PASS (every push/pop %rbx window stores through the pushed slot; every CPUID block uses fixed registers only)"
fi
exit "$fail"
