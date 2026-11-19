#!/usr/bin/env bash
# AegisOS M1 — build the kernel and boot it in QEMU.
#
#   ./boot.sh            build + boot (serial on stdio)
#   ./boot.sh --verify   build + boot + assert the M1 exit-criteria
#                        markers in the serial log; exits non-zero on
#                        failure (used by CI and by humans who want proof)
#
# Requirements: rustup target x86_64-unknown-none, qemu-system-x86.
set -euo pipefail
cd "$(dirname "$0")"

KERNEL=target/x86_64-unknown-none/release/aegis-kernel

echo "==> building aegis-kernel (x86_64-unknown-none, release)"
cargo build -p aegis-kernel --release --target x86_64-unknown-none

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not found (Debian/Ubuntu: apt-get install qemu-system-x86)" >&2
  exit 127
fi

# -machine pc keeps the ACPI poweroff port (0x604) stable; -no-reboot
# turns a triple fault into a clean QEMU exit instead of a loop.
QEMU_ARGS=(-machine pc -cpu qemu64 -m 128M -kernel "$KERNEL" -display none -serial stdio -no-reboot)

if [ "${1:-}" = "--verify" ]; then
  LOG=$(mktemp)
  trap 'rm -f "$LOG"' EXIT
  echo "==> booting in QEMU (TCG) — M1 exit-criteria run"
  START=$(date +%s.%N)
  timeout 60 qemu-system-x86_64 "${QEMU_ARGS[@]}" | tee "$LOG"
  END=$(date +%s.%N)
  echo
  echo "boot wall-clock: $(awk -v e="$END" -v s="$START" 'BEGIN { printf "%.2f", e - s }') s (QEMU startup included)"
  ok=1
  grep -q "M1-EXIT-CRITERIA: PASS" "$LOG" || { echo "VERIFY FAIL: exit-criteria verdict missing or failed"; ok=0; }
  grep -q "Hello from AegisOS domain 1" "$LOG" || { echo "VERIFY FAIL: hello-domain marker missing"; ok=0; }
  grep -q "leaked-frames=0" "$LOG" || { echo "VERIFY FAIL: zero-leak assertion missing"; ok=0; }
  grep -q "scrub-verified=yes" "$LOG" || { echo "VERIFY FAIL: scrub verification missing"; ok=0; }
  grep -q "monitor-quarantined=yes" "$LOG" || { echo "VERIFY FAIL: monitor quarantine missing"; ok=0; }
  if [ "$ok" = 1 ]; then
    echo "BOOT VERIFY: PASS"
  else
    echo "BOOT VERIFY: FAIL"
    exit 1
  fi
else
  exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
fi
