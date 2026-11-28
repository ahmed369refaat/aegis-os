#!/bin/bash
# P1-4: the aarch64 boot smoke — the second architecture's first boot,
# as a gate. Two proofs:
#
#  1. THE SMOKE: rustc's bundled LLVM assembles the AArch64 stub
#     (--target aarch64-unknown-none-softfloat, --emit=obj — the
#     sandbox has no aarch64 binutils, and does not need them),
#     rust-lld links it at the virt board's kernel base, and
#     qemu-system-aarch64 -M virt boots it: the PL011 UART carries
#     the markers, semihosting SYS_EXIT ends the run with rc=0.
#     Both markers must print, and the exit must land — a hang times
#     out and fails.
#
#  2. THE HAL SEAM GUARD (ADR-0011): the policy core — 100% of the
#     kernel's platform-independent logic — must cross-build for
#     aarch64-unknown-none-softfloat. This is the guard that keeps
#     the seam honest while only the x86 boot stub exists.
#
# Honest skip: without qemu-system-aarch64 (a checkout whose toolchain
# was never extended), the smoke part reports SKIP loudly and the
# HAL guard still runs — the seam check never silently disappears.
set -u
cd "$(dirname "$0")/.."
QEMU=/home/z/my-project/tools/qemu-system-aarch64
rc=0

echo "== aa64: the HAL seam guard (cross-build the policy core) =="
if source /home/z/my-project/tools/env.sh 2>/dev/null; then
  if cargo build -p aegis-os --target aarch64-unknown-none-softfloat 2>&1 | tail -1; then
    echo "AA64 HAL GUARD: PASS — aegis-os builds for aarch64-unknown-none-softfloat"
  else
    echo "AA64 HAL GUARD: FAIL — the policy core broke the seam"; rc=1
  fi
else
  echo "AA64 HAL GUARD: FAIL — the toolchain env is missing"; rc=1
fi

echo "== aa64: the boot smoke (qemu-system-aarch64 -M virt) =="
if [ ! -x "$QEMU" ]; then
  echo "AA64 SMOKE: SKIP — no qemu-system-aarch64 in this toolchain (see tools/qemu-system-aarch64)"
  exit $rc
fi

GCC_LD=/home/z/my-project/.toolchain/rustup/toolchains/1.100.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld
rustc --edition 2021 --crate-type=lib --emit=obj \
      --target aarch64-unknown-none-softfloat -O \
      "examples/aarch64-smoke/src/lib.rs" -o "target/aa64-smoke.o" || { echo "AA64 SMOKE: FAIL — assemble"; exit 1; }
"$GCC_LD/ld.lld" -T "examples/aarch64-smoke/smoke.ld" \
      -o "target/aa64-smoke.elf" "target/aa64-smoke.o" || { echo "AA64 SMOKE: FAIL — link"; exit 1; }

OUT=/tmp/aa64-smoke.out
rm -f "$OUT"
timeout 30 "$QEMU" -M virt -cpu cortex-a57 -nographic -nic none -semihosting \
      -kernel target/aa64-smoke.elf > "$OUT" 2>&1
qrc=$?
if [ $qrc -ne 0 ]; then
  echo "AA64 SMOKE: FAIL — qemu rc=$qrc (expected the semihosting exit 0)"; cat "$OUT"; exit 1
fi
ok=1
grep -qF "[AA64] smoke live: PL011 uart, EL=" "$OUT" || { echo "AA64 SMOKE: FAIL — the PL011 marker missing"; ok=0; }
grep -qF "[AA64] semihosting SYS_EXIT" "$OUT" || { echo "AA64 SMOKE: FAIL — the exit marker missing"; ok=0; }
if [ $ok -eq 1 ]; then
  echo "AA64 SMOKE: PASS — $(head -1 "$OUT")"
  echo "AA64 SMOKE: PASS — $(sed -n 2p "$OUT")"
else
  cat "$OUT"; rc=1
fi
exit $rc
