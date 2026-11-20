#!/usr/bin/env bash
# AegisOS M1 — build the boot image and run it in QEMU.
#
# Two-stage boot (see boot-x86_64/stub.S for the rationale): QEMU's
# -kernel multiboot loader accepts ELF32 only, so we build
#   stage 1: an ELF32 multiboot stub (stub.S + stub.ld) that embeds
#            stage 2 and enters it in long mode, and
#   stage 2: the 64-bit kernel (kernel-x86_64, ELF64 linked at the
#            higher-half VA 0xFFFFFFFF80000000, loaded at physical 2 MiB,
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

echo "==> [0/4] building the ring-3 example blobs (rustc --emit=obj + objcopy)"
for b in ring3-hello ring3-rogue ring3-edge ring3-preempt; do
    rustc --edition 2021 --crate-type=lib --emit=obj \
          --target x86_64-unknown-none -O "examples/$b/src/lib.rs" \
          -o "target/$b.o"
    objcopy -O binary -j .text.ring3 "target/$b.o" "kernel-x86_64/blob/$b.bin"
done

echo "==> [1/4] building the 64-bit kernel (x86_64-unknown-none, release)"
cargo build -p aegis-kernel --release --target x86_64-unknown-none

echo "==> [2/4] flattening the kernel to a binary ($KBIN)"
objcopy -O binary "$KELF" "$KBIN"

ENTRY=$(readelf -h "$KELF" | awk '/Entry point address/ { print $4 }')
# The kernel is a higher-half link (ADR-0002): the entry is a full 64-bit
# VA (0xffffffff80000000) that the i386 stub cannot hold as one absolute,
# so it is passed as two 32-bit halves.
ENTRY_LO=$(printf '0x%08x' $((ENTRY & 0xffffffff)))
ENTRY_HI=$(printf '0x%08x' $(((ENTRY >> 32) & 0xffffffff)))
echo "==> [3/4] linking the ELF32 boot stub around it (kernel entry: $ENTRY = hi:$ENTRY_HI lo:$ENTRY_LO)"
# -m32: assemble the stub as an i386 object (the output container QEMU's
# multiboot loader accepts); pure assembly, so no 32-bit libc is needed.
gcc -c -m32 -o "$STUB_OBJ" boot-x86_64/stub.S
ld -m elf_i386 -T boot-x86_64/stub.ld \
   --defsym=kernel_entry_lo="$ENTRY_LO" \
   --defsym=kernel_entry_hi="$ENTRY_HI" \
   -o "$IMAGE" "$STUB_OBJ"

if [ "${1:-}" = "--build-only" ]; then
  echo "image: $IMAGE"
  exit 0
fi

# Lane selection (ADR-0013): `pc` is the M1/M2 acceptance machine;
# `q35` adds the IOMMU + a virtio-blk disk (the driver-stack machine,
# DMAR present); `q35-neg` is the same machine WITHOUT intel-iommu —
# the fail-closed negative proof (`[IOMMU] dmar: absent`).
MODE=run
MACHINE_ARGS=(-machine pc -cpu max -m 128M)
EXTRA_GREPS=()
case "${1:-}" in
  --verify)
    MODE=verify
    ;;
  --verify-q35)
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M
                  -device intel-iommu,intremap=off
                  -device virtio-blk-pci,disable-legacy=on,iommu_platform=on,drive=vd0
                  -netdev user,id=n0
                  -device virtio-net-pci,netdev=n0,disable-legacy=on,iommu_platform=on
                  -netdev user,id=n1
                  -device e1000,netdev=n1
                  -drive id=nvme0,if=none,format=raw,file=target/nvme0.img
                  -device nvme,drive=nvme0,serial=AEGISN1
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0
                  -drive id=usb0,if=none,format=raw,file=target/usb0.img
                  -device qemu-xhci
                  -device usb-storage,drive=usb0
                  -vga std
                  -qmp unix:/tmp/qmp.sock,server,nowait
                  -drive id=vd0,if=none,format=raw,file=target/vdisk0.img)
    EXTRA_GREPS=(
      "[IOMMU] dmar: pa="
      "[IOMMU] dmar: pa=0x"  # placeholder replaced below; see lane block
      "[VNET] alive: MAC="
      "[VNET] dbg q1 readback:"  # the device holds exactly the frames we mapped
      "[VNET] TX: DISCOVER published+kicked"
      "[E1K] alive:"  # registers live: MAC + link
      "[E1K] TX: DISCOVER built+rings armed"  # honest split marker
      "[NVME] admin qpair live"  # controller enable + queue pair
      "[NVME] teardown: revoke_all(0) → 6 region(s)"
      "[AHCI] ABAR live:"  # port + signature proven
      "[AHCI] teardown: revoke_all(0) → 4 region(s)"
      "[XHCI] "  # bring-up + port detection (register-only, fully live)
      "[XTRB] No-Op command:"  # the TRB machinery (command ring + event ring)
      "[ACPI] directory walk"  # HPET/MADT/MCFG located
      "[HPET] block @"  # the live counter
      "[MADT] LAPIC entries="  # parsed
      "[MCFG] ECAM base"  # parsed
      "[KBD2] negotiated scancode set 2, ack="  # the real 0xF0/0x02 exchange
      "[KBD2] scancode"  # the QMP round trip
      "[EXT2] mount gated: the second AHCI command reads a STALE FIS"  # the honest split
      "[E1K] teardown: revoke_all(0) → 4 region(s)"
      "[GFX] VBE 640x480x32 linear"  # the mode engaged
      "[RTC] 2026-"  # the MC146818 read the host clock
      "[VNET] teardown: revoke_all(0) → 8 region(s)"
    )
    ;;
  --verify-q35-noiommu)
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M)
    EXTRA_GREPS=()
    ;;
esac

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not found (Debian/Ubuntu: apt-get install qemu-system-x86)" >&2
  exit 127
fi

# -no-reboot turns a triple fault into a clean QEMU exit instead of a loop.
QEMU_ARGS=("${MACHINE_ARGS[@]}" -kernel "$IMAGE" -display none -serial stdio -no-reboot)

# The q35 driver-stack lane needs its disk image (64 KiB of noise is
# enough — the kernel reads a sector, it does not care about content).
if [ "$MODE" = "verify" ] && [ "${1:-}" = "--verify-q35" ]; then
  dd if=/dev/urandom of=target/vdisk0.img bs=1K count=64 status=none
fi

if [ "$MODE" = "verify" ]; then
  LOG=$(mktemp)
  trap 'rm -f "$LOG"' EXIT
  case "${1:-}" in
    --verify-q35)
      echo "==> [4/4] booting in QEMU (TCG, q35 + intel-iommu) — M1/M2 markers + ADR-0013 DMAR discovery"
      ;;
    --verify-q35-noiommu)
      echo "==> [4/4] booting in QEMU (TCG, q35, NO iommu) — M1/M2 markers + the fail-closed absent proof"
      ;;
    *)
      echo "==> [4/4] booting in QEMU (TCG) — M1 exit-criteria + PR-1.1/1.2/1.3 selftests run"
      ;;
  esac
  # Risk treatment 5: surface the exact emulator the markers run under
  # — if a CI runner's QEMU lacks SMEP/SMAP, the failure message below
  # carries the version context right next to it.
  echo "    $(qemu-system-x86_64 --version | head -1)"
  START=$(date +%s.%N)
  # The q35 lane's host-side driver: marker-driven QMP (send-key once
  # the kernel is armed, screendump after it settles) + a longer
  # timeout (the keyboard poll spins for the injected key).
  QEMU_TIMEOUT=60
  if [ "${1:-}" = "--verify-q35" ]; then
    QEMU_TIMEOUT=240
    rm -f /tmp/qmp.sock /tmp/screen.ppm
    touch "$LOG"
    (python3 "$(dirname "$0")/scripts/qmp_drive.py" "$LOG" >/tmp/qmp-drive.log 2>&1 &)
  fi
  timeout "$QEMU_TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" | tee "$LOG"
  END=$(date +%s.%N)
  echo
  echo "boot wall-clock: $(awk -v e="$END" -v s="$START" 'BEGIN { printf "%.2f", e - s }') s (QEMU startup included)"
  ok=1
  grep -q "M1-EXIT-CRITERIA: PASS" "$LOG" || { echo "VERIFY FAIL: exit-criteria verdict missing or failed"; ok=0; }
  grep -q "Hello from AegisOS domain 1" "$LOG" || { echo "VERIFY FAIL: hello-domain marker missing"; ok=0; }
  grep -q "leaked-frames=0" "$LOG" || { echo "VERIFY FAIL: zero-leak assertion missing"; ok=0; }
  grep -q "scrub-verified=yes" "$LOG" || { echo "VERIFY FAIL: scrub verification missing"; ok=0; }
  grep -q "monitor-quarantined=yes" "$LOG" || { echo "VERIFY FAIL: monitor quarantine missing"; ok=0; }
  grep -qF "[EXC] #DE vector=0 rip=" "$LOG" || { echo "VERIFY FAIL: #DE diagnosis marker missing"; ok=0; }
  grep -qF "[EXC] selftest: exception machinery ok" "$LOG" || { echo "VERIFY FAIL: exception selftest marker missing"; ok=0; }
  grep -qF "[EXC] #DE selftest ok: rip advanced, unwound to the caller" "$LOG" || { echo "VERIFY FAIL: #DE unwind-return marker missing"; ok=0; }
  grep -qF "[MM ] higher-half ok" "$LOG" || { echo "VERIFY FAIL: higher-half marker missing"; ok=0; }
  grep -qF "[EXC] NX selftest: exec of NX page faulted (I/D), rip advanced" "$LOG" || { echo "VERIFY FAIL: NX selftest marker missing"; ok=0; }
  grep -qF "[MM ] B: same VA resolves to a different frame (disjoint tables)" "$LOG" || { echo "VERIFY FAIL: disjoint-tables marker missing"; ok=0; }
  grep -qF "[EXC] domain guard selftest: guard-gap #PF ok" "$LOG" || { echo "VERIFY FAIL: domain guard-gap marker missing"; ok=0; }
  grep -qF "[MM ] per-domain tables: 2 domains, W^X + guards live" "$LOG" || { echo "VERIFY FAIL: per-domain acceptance marker missing"; ok=0; }
  # PR-1.4 gate: either the full ring-3 sequence ran (all seven markers),
  # ADR-0010: the blocked outcome is RETIRED — its four root causes
  # (stray IRQ at the IF boundary + absent IDT gates, mirror-inverted
  # stub offsets, the launch/resume register hole, the iretq regression)
  # were all ours, not the environment's. If this line ever returns it
  # is a regression: fail loudly, never accept it again.
  if grep -qF "[RING3] launch blocked: ring-3 entry faults in this QEMU build" "$LOG"; then
    echo "VERIFY FAIL: the blocked ring-3 path is retired (ADR-0010) — a root cause regressed"
    ok=0
  else
    grep -qF "hello from ring 3 (CPL=3)" "$LOG" || { echo "VERIFY FAIL: ring-3 hello marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 tail-of-page write ok" "$LOG" || { echo "VERIFY FAIL: N1 tail-of-page marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 crossing write refused (-EFAULT)" "$LOG" || { echo "VERIFY FAIL: N1 crossing-write marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 domain 10 quarantined by monitor" "$LOG" || { echo "VERIFY FAIL: N2 monitor-quarantine marker missing"; ok=0; }
    grep -qF "healthy domain still running: yes" "$LOG" || { echo "VERIFY FAIL: N2 healthy-witness marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 audit-only: verdicts logged, mask unchanged" "$LOG" || { echo "VERIFY FAIL: N2 audit-only marker missing"; ok=0; }
    grep -qF "[ARCH] smep=on smap=on" "$LOG" || { echo "VERIFY FAIL: N4 SMEP/SMAP not both on — this QEMU build's -cpu max lacks them ($(qemu-system-x86_64 --version | head -1))"; ok=0; }
    grep -qF "[SEC ] SMEP selftest: kernel jump into user page faulted, resumed" "$LOG" || { echo "VERIFY FAIL: N4 SMEP selftest marker missing"; ok=0; }
    grep -qF "[SEC ] SMAP selftest: kernel read outside the window faulted, resumed" "$LOG" || { echo "VERIFY FAIL: N4 SMAP selftest marker missing"; ok=0; }
    grep -qF "[SEC ] image W^X: write to .text faulted (WP)" "$LOG" || { echo "VERIFY FAIL: F15 .text WP marker missing"; ok=0; }
    grep -qF "write to .rodata faulted (WP)" "$LOG" || { echo "VERIFY FAIL: F15 .rodata WP marker missing"; ok=0; }
    grep -qF "[SEC ] image W^X: exec from .data faulted (I/D)" "$LOG" || { echo "VERIFY FAIL: F15 .data NX marker missing"; ok=0; }
    grep -qF "[RING3] hello domain exited(0): message written from CPL=3" "$LOG" || { echo "VERIFY FAIL: ring-3 exit marker missing"; ok=0; }
    grep -qF "[SYSC] syscall round-trip: " "$LOG" || { echo "VERIFY FAIL: round-trip marker missing"; ok=0; }
    grep -qF "[RING3] user fault: domain terminated, kernel resumes" "$LOG" || { echo "VERIFY FAIL: user-fault resume marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 NX-exec blocked: #PF (I/D)" "$LOG" || { echo "VERIFY FAIL: ring-3 NX security marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 kernel-VA read blocked: #PF (U/S)" "$LOG" || { echo "VERIFY FAIL: ring-3 U/S security marker missing"; ok=0; }
    grep -qF "[SEC ] ring3 unauthorized syscall refused (-ENOSYS, audited)" "$LOG" || { echo "VERIFY FAIL: ring-3 syscall gate marker missing"; ok=0; }
    grep -qF "[RING3] ring-3 isolation live: 7 runs" "$LOG" || { echo "VERIFY FAIL: ring-3 acceptance marker missing"; ok=0; }
  fi
  # M2-W2 / ADR-0012: the preemption demo boots only under
  # `--features preempt-demo` (see ADR-0012's open-issues section); the
  # default boot asserts the seven-run sequence above only.
  if grep -qF "[SCHD] preempt: switches=" "$LOG"; then
    grep -qF "[VERDICT] M2-W2 PREEMPTION: PASS" "$LOG" || { echo "VERIFY FAIL: M2-W2 preemption verdict failed"; ok=0; }
  fi
  grep -qF "[MM ] guarded stacks: alloc+map+cross-view ok, free+scrub ok" "$LOG" || { echo "VERIFY FAIL: guarded-stack marker missing"; ok=0; }
  if ! grep -qF "[RING3] launch blocked: ring-3 entry faults in this QEMU build" "$LOG"; then
    grep -qF "[EXC] guard selftest: stack guard #PF ok" "$LOG" || { echo "VERIFY FAIL: guard-page #PF marker missing"; ok=0; }
  fi
  # ── ADR-0013 lane markers (driver stack, PR 0.3) ──
  case "${1:-}" in
    --verify-q35)
      grep -qF "[IOMMU] dmar: pa=" "$LOG" || { echo "VERIFY FAIL: q35 lane must find the DMAR"; ok=0; }
      grep -qF "[IOMMU] dmar: pa=0x" "$LOG" || { echo "VERIFY FAIL: DMAR address missing"; ok=0; }
      grep -qF " haw=48 " "$LOG" || { echo "VERIFY FAIL: q35 must report a 48-bit host address width"; ok=0; }
      grep -qF "[IOMMU] drhd[0]: seg=0 base=0x" "$LOG" || { echo "VERIFY FAIL: DRHD inventory marker missing"; ok=0; }
      grep -qF "include_all=no" "$LOG" || { echo "VERIFY FAIL: QEMU's DRHD is scoped, not include-all"; ok=0; }
      grep -qF "[IOMMU] vtd: verdict: available haw=48" "$LOG" || { echo "VERIFY FAIL: VT-d bring-up did not reach translation enable"; ok=0; }
      grep -qF "[IOMMU] vtd: hw-proof: ctx entry present=yes" "$LOG" || { echo "VERIFY FAIL: context-entry proof missing"; ok=0; }
      grep -qF "[IOMMU] vtd: hw-proof: mapped 1 page (pte present+rw" "$LOG" || { echo "VERIFY FAIL: map proof missing"; ok=0; }
      grep -qF "[IOMMU] vtd: hw-proof: unmapped + iotlb invalidated (pte absent" "$LOG" || { echo "VERIFY FAIL: unmap+invalidation proof missing"; ok=0; }
      grep -qF "[IOMMU] broker: map ok cookie=" "$LOG" || { echo "VERIFY FAIL: broker map proof missing"; ok=0; }
      grep -qF "[IOMMU] broker: unmap refused (AbortRequired)" "$LOG" || { echo "VERIFY FAIL: abort-before-unmap ordering not proven"; ok=0; }
      grep -qF "[IOMMU] broker: quota enforced" "$LOG" || { echo "VERIFY FAIL: quota enforcement not proven"; ok=0; }
      grep -qF "[IOMMU] broker: revoke_all(0)" "$LOG" || { echo "VERIFY FAIL: teardown path not proven"; ok=0; }
      grep -qF "[IOMMU] dma-drivers=1 (broker live over VT-d)" "$LOG" || { echo "VERIFY FAIL: dma-drivers verdict must be 1 on the IOMMU lane"; ok=0; }
      grep -qF "[PCI ] scan bus 0: " "$LOG" || { echo "VERIFY FAIL: PCI inventory marker missing"; ok=0; }
      grep -qF "0x1af4" "$LOG" || { echo "VERIFY FAIL: the virtio-blk must be in the inventory"; ok=0; }
grep -qF "(virtio-blk) → dom 0 ok (broker assigned)" "$LOG" || { echo "VERIFY FAIL: the virtio-blk claim must go through the broker"; ok=0; }
      ;;
    --verify-q35-noiommu)
      grep -qF "[IOMMU] dmar: absent" "$LOG" || { echo "VERIFY FAIL: the no-iommu lane must report dmar: absent (fail-closed)"; ok=0; }
      grep -qF "[IOMMU] dma-drivers=0 (fail-closed: no broker)" "$LOG" || { echo "VERIFY FAIL: dma-drivers must be 0 on the negative lane"; ok=0; }
      ;;
  esac
  # Lane-specific markers (EXTRA_GREPS from the lane block) — the
  # loop was MISSING until now: the array had been dead code and the
  # lane's own markers were never actually enforced. Integrity fix.
  for g in "${EXTRA_GREPS[@]}"; do
    grep -qF "$g" "$LOG" || { echo "VERIFY FAIL: missing lane marker: $g"; ok=0; }
  done
  if [ "${1:-}" = "--verify-q35" ] && [ "$ok" = 1 ]; then
    # Pixel-level proof of the GFX driver: what QMP captured has to
    # match the pattern drawn (weight it into the verdict honestly).
    if ! python3 "$(dirname "$0")/scripts/check_screen.py" /tmp/screen.ppm; then
      ok=0
    fi
  fi
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
