#!/usr/bin/env bash
# AegisOS M1 — build the boot image and run it in QEMU.
#
# Two-stage boot (see boot-x86_64/stub.S for the rationale): QEMU's
# -kernel multiboot loader accepts ELF32 only, so we build
#   stage 1: an ELF32 multiboot stub (stub.S + stub.ld) that embeds
#            stage 2 and enters it in long mode, and
#   stage 2: the 64-bit kernel (kernel-x86_64, ELF64 linked at 2 MiB,
#            flattened with objcopy and .incbin'd into the stub at 2 MiB).
#
#   ./boot.sh              build + boot (serial on stdio)
#   ./boot.sh --verify     build + boot + assert the M1 exit-criteria
#                          markers in the serial log (CI proof mode)
#   ./boot.sh --build-only build the image, print its path, don't boot
#
# Requirements: rustup target x86_64-unknown-none; binutils (objcopy, ld,
# gcc/as); qemu-system-x86 (only for the boot modes).
set -euo pipefail
cd "$(dirname "$0")"

KELF=target/x86_64-unknown-none/release/aegis-kernel
KBIN=target/kernel.bin
STUB_OBJ=target/stub.o
IMAGE=target/aegis-boot.elf

echo "==> [1/4] building the 64-bit kernel (x86_64-unknown-none, release)"
cargo build -p aegis-kernel --release --target x86_64-unknown-none

echo "==> [2/4] flattening the kernel to a binary ($KBIN)"
objcopy -O binary "$KELF" "$KBIN"

ENTRY=$(readelf -h "$KELF" | awk '/Entry point address/ { print $4 }')
echo "==> [3/4] linking the ELF32 boot stub around it (kernel entry: $ENTRY)"
# -m32: assemble the stub as an i386 object (the output container QEMU's
# multiboot loader accepts); pure assembly, so no 32-bit libc is needed.
gcc -c -m32 -o "$STUB_OBJ" boot-x86_64/stub.S
ld -m elf_i386 -T boot-x86_64/stub.ld \
   --defsym=kernel_entry="$ENTRY" \
   -o "$IMAGE" "$STUB_OBJ"

if [ "${1:-}" = "--build-only" ]; then
  echo "image: $IMAGE"
  exit 0
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not found (Debian/Ubuntu: apt-get install qemu-system-x86)" >&2
  exit 127
fi

# -machine pc keeps the ACPI poweroff port (0x604) stable; -no-reboot
# turns a triple fault into a clean QEMU exit instead of a loop.
QEMU_ARGS=(-machine pc -cpu qemu64 -m 128M -kernel "$IMAGE" -display none -serial stdio -no-reboot)

if [ "${1:-}" = "--verify" ]; then
  LOG=$(mktemp)
  trap 'rm -f "$LOG"' EXIT
  echo "==> [4/4] booting in QEMU (TCG) — M1 exit-criteria run"
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
  echo "==> [4/4] booting in QEMU"
  exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
fi
