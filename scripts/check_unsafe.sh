#!/usr/bin/env bash
# Unsafe-code policy enforcement.
#
# 1. The policy core (src/) must contain zero unsafe — the compiler
#    enforces forbid(unsafe_code); this grep additionally catches any
#    accidental allow attribute or stray usage in comments meant as code.
# 2. The bootable kernel (kernel-x86_64/) may contain unsafe ONLY in the
#    documented allowlist: src/boot/ (entry asm, GDT, page tables),
#    src/hw.rs (port I/O, rdtsc, poweroff), src/memops.rs (volatile
#    memory primitives). Every item there carries a SAFETY note.
#
# Comment lines (//, ///, //! and /*) are ignored.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. Policy core: no unsafe at all.
while IFS= read -r line; do
  echo "FAIL: unsafe in the policy core: $line" >&2
  fail=1
done < <(grep -rn "unsafe" src/ --include="*.rs" \
  | grep -v "forbid(unsafe_code)" \
  | grep -vE ':[0-9]+:\s*(//|/\*|\*)' || true)

# 2. Kernel crate: unsafe only in the allowlist.
while IFS= read -r line; do
  file=${line%%:*}
  case "$file" in
    kernel-x86_64/src/arch/*|kernel-x86_64/src/boot/*|kernel-x86_64/src/hw.rs|kernel-x86_64/src/memops.rs)
      # allowlisted — and the module must actually carry the allow attribute
      ;;
    *)
      echo "FAIL: unsafe outside the allowlist: $line" >&2
      fail=1
      ;;
  esac
done < <(grep -rn "unsafe" kernel-x86_64/src/ --include="*.rs" \
  | grep -v "allow(unsafe_code)" \
  | grep -v "deny(unsafe_code)" \
  | grep -vE ':[0-9]+:\s*(//|/\*|\*)' || true)

# 3. The allowlisted modules must declare the allow (guards against
#    someone adding a new allowlisted path without the attribute).
for f in kernel-x86_64/src/arch/gdt.rs kernel-x86_64/src/arch/idt.rs kernel-x86_64/src/arch/stubs.rs kernel-x86_64/src/arch/percpu.rs \
         kernel-x86_64/src/arch/exceptions.rs kernel-x86_64/src/boot/mod.rs \
         kernel-x86_64/src/hw.rs kernel-x86_64/src/memops.rs; do
  grep -q "allow(unsafe_code)" "$f" || { echo "FAIL: $f lost its allow(unsafe_code) declaration" >&2; fail=1; }
done

# 4. Ratchet: the unsafe usage count in the allowlist must not grow
#    beyond scripts/unsafe-count.txt. Raising the baseline requires an
#    ADR reference in the PR that changes it; shrinking is always fine
#    (lower the file in the same PR).
BASELINE_FILE="scripts/unsafe-count.txt"
COUNT=$(grep -rn "unsafe" kernel-x86_64/src/arch/ kernel-x86_64/src/boot/ kernel-x86_64/src/hw.rs kernel-x86_64/src/memops.rs --include="*.rs" \
  | grep -v "allow(unsafe_code)" \
  | grep -v "deny(unsafe_code)" \
  | grep -vE ':[0-9]+:\s*(//|/\*|\*)' \
  | grep -vc "^$" || true)
BASELINE=$(grep -E '^[0-9]+$' "$BASELINE_FILE" | tail -1)
if [ -z "$BASELINE" ]; then
  echo "FAIL: $BASELINE_FILE missing or malformed" >&2; fail=1
elif [ "$COUNT" -gt "$BASELINE" ]; then
  echo "FAIL: unsafe count grew: $COUNT > baseline $BASELINE — raise the baseline only with an ADR reference" >&2; fail=1
fi

if [ "$fail" = 0 ]; then
  echo "UNSAFE POLICY: PASS (allowlist usage: ${COUNT:-?}/$BASELINE)"
fi
exit $fail
