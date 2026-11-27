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
#   ./boot.sh --verify-persist
#                          build + boot TWICE on the same persist image:
#                          boot 1 writes persist.txt (PERSIST:WRITTEN),
#                          boot 2 must read it back (PERSIST:VERIFIED) —
#                          the Phase 6 S5 / M3 exit-criterion lane
#   ./boot.sh --verify-shell
#                          build + boot the M3 shell session: a lean q35
#                          with the IRQ-driven TTY, stdin fed from
#                          scripts/shell-session.txt — PID 1 execve's
#                          /bin/sh and the shell runs the command set
#                          (echo/ls/cat/mkdir/rm/cp/mv/exit) live
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
for b in ring3-hello ring3-rogue ring3-edge ring3-preempt ring3-files ring3-init ring3-netd ring3-vblk ring3-rogue-drv ring3-exec-caller ring3-pkg-caller ring3-vnetd; do
    rustc --edition 2021 --crate-type=lib --emit=obj \
          --target x86_64-unknown-none -O "examples/$b/src/lib.rs" \
          -o "target/$b.o"
    objcopy -O binary -j .text.ring3 "target/$b.o" "kernel-x86_64/blob/$b.bin"
done
# ADR-0030's lesson: ring3-preempt registers its signal handler via a
# hand-pinned code delta — assert the landing at EVERY build so a silent
# layout shift fails the build instead of delivering SIGUSR1 into
# arbitrary code.
python3 scripts/check-blob-deltas.py || exit 1

echo "==> [0b/4] linking the exec target (a REAL ELF64 — not a flat blob)"
# execve's first image: PT_LOADs at their declared vaddrs (text RX at
# 0x400000, data RW at 0x403000 with the bss tail at 0x403800), entry
# _start from e_entry. The kernel's exec registry embeds THESE bytes;
# the slice-4 loader parses them at runtime (see exec_registry.rs).
rustc --edition 2021 --crate-type=lib --emit=obj \
      --target x86_64-unknown-none -O "examples/ring3-exec-target/src/lib.rs" \
      -o "target/ring3-exec-target.o"
ld -T "examples/ring3-exec-target/exec.ld" \
   -o "kernel-x86_64/blob/ring3-exec-target.bin" "target/ring3-exec-target.o"
# K20 (P0-3): the gcc userland citizen — a REAL compiler's ELF.
# -ffreestanding -nostdlib: no libc, no startup files; the program is
# the whole image. Linked at the exec cage's declared vaddrs; carried
# on the ext2 root as the file "hello" (scripts/mkext2.py reads THIS
# file), read back off the AHCI disk at boot, and execve'd by a
# ring-3 caller — see exec_registry.rs's disk slot + kmain's [USER]
# step.
echo "==> [0c/4] building the gcc userland image (/bin/hello)"
gcc -ffreestanding -nostdlib -nostartfiles -static -O2 \
    -T "examples/userland-hello/hello.ld" \
    -o "kernel-x86_64/blob/userland-hello.elf" \
    "examples/userland-hello/hello.c" 2>&1 | grep -v "build-id" || true
[ -s "kernel-x86_64/blob/userland-hello.elf" ] || { echo "FATAL: gcc userland image build failed"; exit 1; }

echo "==> [0c/4] linking the shell (a REAL ELF64 — /bin/sh, opt-level=z + gc-sections)"
rustc --edition 2021 --crate-type=bin -C panic=abort -C opt-level=z -C codegen-units=1 \
      -C debug-assertions=off -C overflow-checks=off \
      -C linker=ld -C link-arg=-Texamples/ring3-sh/sh.ld -C link-arg=--gc-sections \
      -C link-arg=-s -C relocation-model=static \
      --target x86_64-unknown-none examples/ring3-sh/src/lib.rs \
      -o kernel-x86_64/blob/ring3-sh.bin

# K22: the package manager's own image (/bin/pkg) — a REAL ELF64 under
# the SERVICE memory contract (text RX / rodata R / data RW, one absent
# page between them, the 8 MiB no_alloc stack above the cage). Built with the
# size recipe the K22 measurements were taken with, then checked against
# the contract at EVERY build: a layout shift fails here instead of
# inside execve (scripts/check-pkg-image.py).
echo "==> [0d/4] linking the package manager (/bin/pkg — the SERVICE contract, opt-level=z)"
cargo build -p aegis-pkg --bin pkg --profile pkg-image --target x86_64-unknown-none
python3 scripts/check-pkg-image.py target/x86_64-unknown-none/pkg-image/pkg
# The kernel embeds the FILE, and the kernel has ONE 2 MiB page to live
# in: the symbol table goes (the stack-depth check above needed it; the
# kernel's loader reads only the ELF header and the program headers).
strip --strip-all target/x86_64-unknown-none/pkg-image/pkg -o kernel-x86_64/blob/pkg.bin
[ "$(readelf -lW kernel-x86_64/blob/pkg.bin | grep -c '^  LOAD')" = 3 ] \
    || { echo "FATAL: the stripped /bin/pkg image lost a PT_LOAD"; exit 1; }

# K22: the signed local repo fixture — the host-side repo builder
# (pkg-mkrepo, signer feature; TEST-ONLY fixed seeds — see
# pkg/src/bin/pkg-mkrepo.rs). Five files, each ≤ 8 KiB (the ramfs
# spill-window bound — the tool fails the build if one crosses it):
# the trust anchors, the repo config, the signed index, and BOTH
# version-qualified packages (the repo layout is version-qualified
# now — the upgrade round has something to move TO). K23: the
# fixture feeds ONLY THE DISK — scripts/mkext2.py
# writes these bytes into the ext2 image's /pkgsrc and the boot's
# ext2 walk reads them back (the kernel image no longer embeds
# package data); scripts/check-pkgsrc-image.py proves them
# byte-exact on the image at every build.
echo "==> [0e/4] building the signed local repo fixture (pkg-mkrepo)"
cargo build -p aegis-pkg --bin pkg-mkrepo --features signer
target/debug/pkg-mkrepo kernel-x86_64/blob/pkg-fixture

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
# K23: the repo fixture rides the ext2 disk (target/sdisk0.img —
# built for every boot mode below), so the BASE pc machine carries
# an AHCI controller with the disk on port 0: the driver stack's PCI
# scan finds a plain -device ahci on bus 0 (the NoDmar arm drives
# it in identity mode), and the K22 lane's [PKG] greps stay green
# without the kernel image carrying package data. The q35-family
# lanes attach the same image to their BUILT-IN SATA port instead
# (bus=ide.0 — see each lane's MACHINE_ARGS).
MACHINE_ARGS=(-machine pc -cpu max -m 128M
              -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
              -device ahci,id=ahci0
              -device ide-hd,drive=sd0,bus=ahci0.0)
EXTRA_GREPS=()
# Every QEMU run's stdin is EXPLICIT: /dev/null unless a lane feeds a
# session. Hermetic lanes (and CI without a terminal) never hang on a
# inherited tty, and the shell's idle-exit contract stays honest.
STDIN_FILE=/dev/null
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
                  -device virtio-rng-pci,disable-legacy=on,iommu_platform=on
                  -netdev user,id=n1
                  -device e1000,netdev=n1
                  -drive id=nvme0,if=none,format=raw,file=target/nvme0.img
                  -device nvme,serial=AEGISN1,num_queues=2 -device nvme-ns,drive=nvme0
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0
                  -drive id=usb0,if=none,format=raw,file=target/usb0.img
                  -device qemu-xhci
                  -device usb-kbd
                  -device usb-storage,drive=usb0
                  -vga std
                  -qmp unix:/tmp/qmp.sock,server,nowait
                  -drive id=vd0,if=none,format=raw,file=target/vdisk0.img
                  -device pcie-root-port,id=rp0,bus=pcie.0
                  -drive id=vd1,if=none,format=raw,file=target/vdisk1.img
                  -device virtio-blk-pci,bus=rp0,disable-legacy=on,drive=vd1
                  -device i6300esb
                  -chardev file,id=vc0,path=target/console.out
                  -device virtio-serial-pci,disable-legacy=on,iommu_platform=on
                  -device virtconsole,chardev=vc0
                  -device virtio-balloon-pci,disable-legacy=on,iommu_platform=on)
    EXTRA_GREPS=(
      "[IOMMU] dmar: pa="
      "[IOMMU] dmar: pa=0x"  # placeholder replaced below; see lane block
      "[PCI ] config access: ECAM @"  # ADR-0020: the MCFG window drives the scan
      "[PCI ] ECAM window mapped: 1 GiB page(s)"  # round I: the third-GiB direct-map hole the ECAM reads faulted on (the round-6 seam never mapped it)
      "[PCI ] bridge at this slot — traversed"  # ADR-0020: the root port was walked
      "[PCI ] 1:0.0 "  # ADR-0020: the virtio-blk BEHIND the root port, enumerated on bus 1
      "[PCI ] claim: virtio-rng → dom"  # round I: the unclaimed-device fix — rng/console/balloon DMAd through dom 0 (fail-closed) since G
      "[RNG ] rdrand: "  # the CPU entropy source probed (present or absent, honestly)
      "[RNG ] virtio-rng alive: qsize="  # the bus entropy source through the broker
      "[RNG ] virtio-rng: 16 bytes harvested"  # real device entropy → the pool
      "[RNG ] pool: mixes="  # the health feed + two live draws
      "[TSC ] calibrated: "  # HPET-sourced TSC frequency (the tick stops being a guess)
      "[PWR ] FADT: PM1a control @"  # the power paths read the firmware's own addresses
      # The C0-idle proof moved OUT of EXTRA_GREPS (round I): under
      # load the delivery races the monitor arming, and any of the
      # three honest wake paths proves the window + the real IRQ —
      # the OR-check lives below with the console file proof.
      "[GPT ] partition 1 'aegis-root' LBA 34..=289"  # the partition layer under the ext2 mount
      "[WDT ] iTCO live: PMBASE 0x"  # the ICH9 TCO watchdog: registers live, NO_REBOOT gate read
      "[WDT ] iTCO: programmed 10s → read-back"  # the write path, proven by read-back under NO_REBOOT
      "[WDT ] i6300esb driven: unlock×3"  # the PCI watchdog: unlock/preload/ping sequence, reboot masked
      "[VCON] virtio-console alive: tx qsize="  # port 0's transmit queue through the broker
      "[VCON] TX complete: "  # the guest half of the round trip (the host file is the other half)
      "[VBAL] virtio-balloon alive: config num_pages="  # the memory device's config layout
      "[VBAL] cycle done: inflated=yes deflated=yes"  # K13, closed: the buffer is a real 4-byte PFN list (not 4096 zero bytes), the used ring is the completion, and `actual` is the DRIVER's field — QEMU's set_config only reads it. Both halves green
      "[IVRS] absent (no AMD-Vi on this machine"  # the honest AMD-Vi absence (QEMU does not emulate it)
      "[VNET] alive: MAC="
      "[VNET] dbg q1 readback:"  # the device holds exactly the frames we mapped
      "[VNET] TX: DHCP DISCOVER sent"
      # K20 (P0-2): the ring-3 data path — the brokered socket's
      # send/receive syscall arms, driven by a real CPL=3 domain.
      "[VNET] ring-3 NET_SEND:"  # the DISCOVER left ring-3 through SYS_NET_SEND
      "[VNET] ring-3 NET_RECV:"  # the OFFER returned to ring-3 through SYS_NET_RECV
      "[VNET] ring-3 round trip:"  # ring-3 → policy gate → broker ring → slirp → rx → ring-3
      "[VNET] ring-3 throttle:"  # the bucket: 1+20 sends fit, the next EAGAIN; 1515B → EMSGSIZE
      "[E1K] alive:"  # registers live: MAC + link
      "[E1K] TX: DHCP DISCOVER sent"  # the NIC egress works
      "[E1K] RX: "  # the OFFER parsed: full round trip through the IOMMU
      "[VNET] RX: "  # both NICs live
      "[NVME] admin qpair live"  # controller enable + queue pair
      "[NVME] Identify: serial=\"AEGISN1 \""  # F11: the identify data page arrives (not PA 0)
      "[NVME] I/O qpair QID1 created (CQ+SQ)"  # F11: entry sizes + PRP both accepted
      "[NVME] read LBA0:"  # F11: a 512-byte read through the IOMMU
      "[NVME] teardown dom"  # ADR-0018: scoped, truthful counts (count varies with how far the ext2 helper mapped)
      "[AHCI] ABAR live:"  # port + signature proven
      "[AHCI] teardown dom"  # same, ADR-0018
      "[XHCI] "  # bring-up + port detection (register-only, fully live)
      "[XTRB] No-Op command:"  # the TRB machinery (command ring + event ring)
      "[ACPI] directory walk"  # HPET/MADT/MCFG located
      "[HPET] block @"  # the live counter
      "[MADT] LAPIC entries="  # parsed
      "[MCFG] ECAM base"  # parsed
      "[IRQ ] ioapic live @"  # ADR-0019: the IOAPIC probed from the MADT
      "[IRQ ] armed: isa irq 1 → gsi"  # ADR-0019: GSI 1 → a broker vector, RTE read-back ok
      # (the IRQ DELIVERED pin moved to the dedicated --verify-ps2
      # lane: on THIS machine send-key routes to the USB keyboard, so
      # the key's PS/2 edge never comes — the old grep passed on the
      # self-test's stale IRQ1 edge, a false positive, now drained
      # before the window opens.)
      "[MSIX] armed: entries="  # ADR-0019: the NIC's MSI-X table pointed at a broker vector
      # Round two: the DELIVERY grep is BACK — the round-one silence
      # was never QEMU's: the queues' vectors were never BOUND
      # (queue_msix_vector / config_vector unwritten), so no
      # completion ever fired a message. The step now binds
      # config→entry 0, RX→entry 1, TX→entry 2 BEFORE DRIVER_OK
      # (grant read back), the DHCP completions fire real messages,
      # and one delivers through the bounded window.
      "[MSIX] DELIVERED: vector"  # the message-signaled interrupt, compat format on this lane
      "[MSIX] disabled + vector released"  # the teardown discipline (disable → drain → release)
      # ADR-0017's first migration (K19): the SAME virtio-blk driven
      # again as a ring-3 driver domain — the register accesses are
      # SYS_DEVREG messages through the windowed device core, the read
      # is verified byte-identical to the ring-0 path's, and a rogue
      # domain's channel is closed by the core's refusal ladder.
      "[VBLKD] driver-domains=1"  # the migrated driver ran its whole proof at CPL=3
      "[VBLKD] read sector 0 at CPL=3"  # byte-identical to the ring-0 path's read
      "[VBLKD] rogue driver domain contained"  # the quarantine: a bad driver loses its device, the boot continues
      "[KBD2] negotiated scancode set 2, ack="  # the real 0xF0/0x02 exchange
      "[EXT2] hello.txt (inode 12, 17 bytes): \"HELLO-AEGIS-EXT2.\" ← read-only ext2 over AHCI"  # the mount LIVE (ADR-0014: the stale FIS was three driver bugs)
      "[EXT2] /bin/hello: "  # K20 (P0-3): the gcc ELF read off the disk into the exec registry
      "[USER] /bin/hello: gcc 14.2 -ffreestanding -nostdlib ELF, read off the ext2 disk, execve'd at CPL=3"  # K20 (P0-3): the userland bootstrap
      "[USER] the image ran: exit_group(42)"  # K20 (P0-3): the loader, cage, quota and policy gates on a REAL compiler's output
      "[VNETD] driver-domains=2: the ring-3 domain brought the NIC up on its OWN rings through the devreg channel ("  # K20 (P0-4): the second migrated driver
      "[VNETD] DHCP at CPL=3 through the domain's OWN rings: 290-byte DISCOVER out, 590-byte OFFER back"  # K20 (P0-4): device ownership proven by the exchange itself
      "[VNETD] rogue driver domain contained: "  # K20 (P0-4): the quarantine, NIC edition
      "[FAT32] HELLO.ESP (cluster 3, 1200 bytes, 3 clusters): \"HEAD:AEGIS-FAT32:\"…\":TAIL-OK\" ← read-only FAT32 over AHCI"  # the ESP mount LIVE on the same port (GPT partition 2, the chain walk proven)
      "[E1K] teardown dom"  # ADR-0018
      "[GFX] VBE 640x480x32 linear"  # the mode engaged
      "[RTC] 2026-"  # the MC146818 read the host clock
      "[VNET] teardown dom"  # ADR-0018
      "cross-device DMA FAULTED (FSTS.PPF set)"  # ADR-0018: the negative probe — the lane FAILS if cross-device DMA does not fault
    )
    ;;
  --verify-ps2)
    # ADR-0019's dedicated PS/2 lane (K18): a lean q35 with NO USB
    # keyboard — QEMU's send-key has exactly one keyboard to route to
    # (the i8042), so the IRQ1 chain's DELIVERED pin means the KEY'S
    # own edge: the self-test's stale edge is drained before the
    # window, the window accepts only the keyboard's vector, and the
    # captured byte must be KEYBOARD-TAGGED in the console-in ring
    # (a serial byte is never the proof). The machine keeps the IOMMU
    # so the full MADT → IOAPIC → broker chain runs; nothing else.
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M
                  -device intel-iommu,intremap=off
                  # K23: the repo fixture's disk (the K22 [PKG] greps
                  # run on this lane too — the common verify block).
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0
                  -qmp unix:/tmp/qmp.sock,server,nowait)
    EXTRA_GREPS=(
      "[IRQ ] ioapic live @"  # the interrupt view probed from the MADT
      "[IRQ ] armed: isa irq 1"  # the keyboard's GSI routed to a broker vector, RTE read back
      "[IRQ ] DELIVERED: vector"  # THE end-to-end line-interrupt chain — the key's own IRQ1 edge (EOI + mailbox)
      "[KBD] i8042 self-test passed (0x55)"
      "[KBD2] scancode decoded: byte 0x"  # the decoded key, keyboard-tagged, in the console-in ring
      "[KBD2] negotiated scancode set 2, ack=0x"  # the real 0xF0/0x02 protocol exchange
    )
    ;;
  --verify-q35-noiommu)
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M
                  -netdev user,id=n1
                  -device e1000,netdev=n1
                  -object filter-dump,id=f1,netdev=n1,file=/tmp/e1k-noiommu.pcap
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0
                  -d guest_errors -trace enable=e1000* -trace enable=e1000x*)
    EXTRA_GREPS=(
      "[E1K] identity mode:"  # the control lane: same driver, no IOMMU
      "[E1K] TX: DHCP DISCOVER sent"
      "[E1K] RX:"
      "[AHCI] identity mode:"  # ADR-0014 step 5: the stale-FIS control
      "[AHCI] IDENTIFY completed:"  # command 1 must complete here too
      "[GPT ] partition 1 'aegis-root' LBA 34..=289"  # the partition layer: protective MBR + GPT CRCs verified, ext2 at the partition base
      "[EXT2] hello.txt (inode 12, 17 bytes): \"HELLO-AEGIS-EXT2.\" ← read-only ext2 over AHCI"  # ADR-0014: the mount works on BOTH lanes
      "[EXT2] /bin/hello: "  # K20 (P0-3): the disk-sourced image loads on BOTH lanes
      "[USER] the image ran: exit_group(42)"  # K20 (P0-3): the exec path on real-compiler output
      "[FAT32] GPT partition 2 'aegis-esp' LBA 296..=66959"  # the multi-partition GPT walk (the ESP is a GPT citizen)
      "[FAT32] BPB ok: 65600 clusters"  # the FAT32 type determination, honest (>= 65525 by the spec's rule)
      "[FAT32] HELLO.ESP (cluster 3, 1200 bytes, 3 clusters): \"HEAD:AEGIS-FAT32:\"…\":TAIL-OK\" ← read-only FAT32 over AHCI"  # the ESP mount works on BOTH lanes
    )
    ;;
  --verify-q35-ir)
    # ADR-0019's IR lane: the SAME machine with interrupt remapping
    # ON — every device MSI must arrive in the remapped format through
    # its IRTE or the IOMMU faults it. A focused lane (the two virtio
    # devices + the e1000, which joined in K18 so the ADR-0018
    # cross-device fault probe is producible HERE too; the keyboard's
    # IOAPIC compat-RTE proof lives on the dedicated --verify-ps2
    # lane now, where the key really routes to the i8042).
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M
                  -device intel-iommu,intremap=on
                  -device virtio-blk-pci,disable-legacy=on,iommu_platform=on,drive=vd0
                  -netdev user,id=n0
                  -device virtio-net-pci,netdev=n0,disable-legacy=on,iommu_platform=on
                  -netdev user,id=n1
                  -device e1000,netdev=n1
                  -drive id=vd0,if=none,format=raw,file=target/vdisk0.img
                  # K23: the repo fixture's disk — the K22 [PKG] greps
                  # are in the COMMON verify block, so this lane needs
                  # the /pkgsrc bytes as much as the base one does.
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0)
    EXTRA_GREPS=(
      "[IOMMU] dmar: pa="
      "[IOMMU] dmar: "  # the struct markers (drhd line)
      "[IR  ] enabled: 256 IRTEs"  # IRTA + SIRTP + IRE, the broker owns the table
      "[VBLK] alive"  # the block device still drives through the IOMMU
      "[VNET] alive: MAC="
      "[VNET] TX: DHCP DISCOVER sent"
      "[VNET] RX: "  # the full round trip with IR live
      "[E1K] alive:"  # K18: the e1000 joined this machine — registers live through the IOMMU with IR on
      "[E1K] TX: DHCP DISCOVER sent"  # the NIC egress under IR
      "[E1K] RX: "  # the FULL TX→slirp→RX DHCP round trip under IR (proven this round, then pinned)
      "[E1K] teardown dom"  # the scoped, counted teardown
      "[MSIX] format: remapped"  # the message went through the IRTE, not compat
      "[MSIX] armed: entries="
      # Round two: the DELIVERY grep is live here too — the REMAPPED
      # message lands through this device's IRTE (the vectors are
      # bound before DRIVER_OK; see the q35 lane's comment).
      "[MSIX] DELIVERED: vector"  # the message-signaled interrupt, remapped format
      "[MSIX] disabled + vector released"
      "cross-device DMA FAULTED (FSTS.PPF set)"  # the ADR-0018 negative probe still faults with IR on
    )
    ;;
  --verify-shell)
    # Phase 7 (M3): the shell session. A lean q35 — the IOMMU so the
    # full MADT -> IOAPIC -> broker chain runs and the TTY takes its
    # interrupt (isa irq 4), and NOTHING else: no vblk, no NIC — the
    # machine exists for the console. stdin IS the session (the typed
    # commands); every other lane pins stdin to /dev/null so the
    # shell's idle exit keeps them green.
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M
                  -device intel-iommu,intremap=off
                  # K23: the repo fixture's disk (the K22 [PKG] greps
                  # run on this lane too — the common verify block).
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0)
    STDIN_FILE=scripts/shell-session.txt
    EXTRA_GREPS=(
      "[TTY] armed: isa irq 4"  # the IRQ-driven TTY (the interrupt -> ring chain, live)
      "[SH] up"  # init execve'd /bin/sh; the shell banner
      "[SH] e hello from aegis-sh"  # echo: write(2) to fd 1
      "[SH] mkdir /pub/shdir: ok"  # mkdir(83)
      "[SH] cp /pub/round-j.txt /pub/shdir/copy.txt 21 bytes"  # open+read+write(O_CREAT)
      "[SH] c /pub/shdir/copy.txt: aegis file roundtrip"  # the copy round-trips byte-exact
      "[SH] l /pub: "  # getdents64(259): the names line
      " shdir"  # ...including the directory the shell just made
      "[SH] mv /pub/shdir/copy.txt /pub/shdir/moved.txt 21 bytes"  # copy + unlink
      "[SH] rm /pub/shdir/moved.txt: ok"  # unlink(87)
      "[SH] x"  # the clean session end
    )
    ;;
  --verify-persist)
    # Phase 6 S5 (the M3 exit criterion): the two-boot persistence
    # proof. Lean machine — the IOMMU, the demo vblk on bus 0 (its
    # enforcement probe stays OFF the persist disk), and the PERSIST
    # disk behind a root port (bus 1). The same image boots TWICE:
    # boot 1 writes persist.txt, boot 2 must read it back byte-exact.
    # cache=writethrough: the 256 sector flushes must be in the host
    # file before boot 2 starts, whatever kills boot 1's QEMU.
    MODE=verify
    MACHINE_ARGS=(-machine q35 -cpu max -m 128M
                  -device intel-iommu,intremap=off
                  # K23: the repo fixture's disk (the K22 [PKG] greps
                  # run on this lane too — the common verify block).
                  -drive id=sd0,if=none,format=raw,file=target/sdisk0.img
                  -device ide-hd,drive=sd0,bus=ide.0
                  -drive id=vd0,if=none,format=raw,file=target/vdisk0.img
                  -device virtio-blk-pci,disable-legacy=on,iommu_platform=on,drive=vd0
                  -device pcie-root-port,id=rp1,bus=pcie.0
                  -drive id=vd2,if=none,format=raw,file=target/persist.img,cache=writethrough
                  -device virtio-blk-pci,bus=rp1,disable-legacy=on,iommu_platform=on,drive=vd2)
    EXTRA_GREPS=(
      "[IOMMU] vtd: verdict: available haw=48"  # the broker is live (the persist session rides it)
      "[VBLK] alive"  # the bus-0 demo disk still drives through the IOMMU
      "[VBLK] enforcement: PPF=yes"  # translation is REAL on this machine too (ADR-0014)
      "[PCI ] 1:0.0 "  # the persist disk enumerated behind the root port (ADR-0020)
      "[PERSIST] claim: bus="  # its OWN IOMMU domain (ADR-0018)
      "[PERSIST] session up: rings broker-mapped"  # the second vblk handshake
      "[PERSIST] image read: 256 sectors into 32 frames"  # the whole disk into pool frames
      "[PERSIST] image frames freed: 32"  # the teardown discipline (every path)
      "[PERSIST] vfs: /persist.txt imported"  # the file is a node in THIS boot's tree
    )
    ;;
esac

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "error: qemu-system-x86_64 not found (Debian/Ubuntu: apt-get install qemu-system-x86)" >&2
  exit 127
fi

# -no-reboot turns a triple fault into a clean QEMU exit instead of a loop.
QEMU_ARGS=("${MACHINE_ARGS[@]}" -kernel "$IMAGE" -display none -serial stdio -no-reboot)

# The q35 driver-stack lane needs its disk images (64 KiB of noise is
# enough — the kernel reads a sector, it does not care about content —
# except sdisk0, which must be the REAL image the mounts read: ext2
# on GPT partition 1, the FAT32 ESP on partition 2).
# They are generated here so the lane is self-contained in CI (they
# used to exist only on one dev machine — a latent CI break).
if [ "$MODE" = "verify" ] && { [ "${1:-}" = "--verify-q35" ] || [ "${1:-}" = "--verify-q35-noiommu" ] || [ "${1:-}" = "--verify-q35-ir" ]; }; then
  dd if=/dev/urandom of=target/vdisk0.img bs=1K count=64 status=none
  dd if=/dev/urandom of=target/vdisk1.img bs=1K count=64 status=none  # the bus-1 disk behind rp0
fi
if [ "$MODE" = "verify" ] && [ "${1:-}" = "--verify-q35" ]; then
  dd if=/dev/zero of=target/nvme0.img bs=1K count=128 status=none
  dd if=/dev/zero of=target/usb0.img  bs=1K count=64  status=none
fi
if [ "$MODE" = "verify" ] && [ "${1:-}" = "--verify-persist" ]; then
  dd if=/dev/urandom of=target/vdisk0.img bs=1K count=64 status=none
  # The persist image: reset BEFORE boot 1, then built once — the
  # two boots that follow share it untouched (regenerating BETWEEN
  # them would reset the very persistence under proof). The reset
  # makes the lane repeatable: without it, a second run's boot 1
  # would VERIFY the file the first run left instead of WRITING it.
  rm -f target/persist.img
  python3 "$(dirname "$0")/scripts/mkext2-rw.py"
fi
# K23: the repo fixture rides the ext2 disk — sdisk0 is built for
# EVERY boot mode (run included: a plain `./boot.sh` needs the
# /pkgsrc bytes or the K22 lane halts on provisioning), then proven
# on the host: check-pkgsrc-image.py re-parses the image with the
# same ext2 logic the kernel runs and asserts the five fixture
# files byte-exact (both version-qualified packages included). mkfat32.py still grows the SAME image for the
# q35/noiommu lanes only (GPT partition 2, the ESP) — it runs AFTER
# the check, appending past the ext2 partition (LBA 296 > 289) so
# the /pkgsrc bytes survive untouched.
if [ "$MODE" = "verify" ] || [ "$MODE" = "run" ]; then
  python3 "$(dirname "$0")/scripts/mkext2.py"
  python3 "$(dirname "$0")/scripts/check-pkgsrc-image.py"
fi
if [ "$MODE" = "verify" ] && { [ "${1:-}" = "--verify-q35" ] || [ "${1:-}" = "--verify-q35-noiommu" ]; }; then
  # The ESP slice: mkfat32.py grows the SAME disk with GPT partition 2
  # (an honest FAT32 volume — see its header for the geometry).
  python3 "$(dirname "$0")/scripts/mkfat32.py"
fi

if [ "$MODE" = "verify" ]; then
  LOG=$(mktemp)
  TRACE_LOG=""
  trap 'rm -f "$LOG" "$TRACE_LOG"' EXIT
  case "${1:-}" in
    --verify-q35)
      echo "==> [4/4] booting in QEMU (TCG, q35 + intel-iommu) — M1/M2 markers + ADR-0013 DMAR discovery"
      ;;
    --verify-q35-ir)
      echo "==> [4/4] booting in QEMU (TCG, q35 + intel-iommu intremap=on) — ADR-0019: MSI-X through the IRTE"
      ;;
    --verify-q35-noiommu)
      echo "==> [4/4] booting in QEMU (TCG, q35, NO iommu) — M1/M2 markers + the fail-closed absent proof"
      ;;
    --verify-persist)
      echo "==> [4/4] booting in QEMU (TCG, q35 + intel-iommu) — Phase 6 S5: the two-boot persistence proof"
      ;;
    *)
      echo "==> [4/4] booting in QEMU (TCG) — M1 exit-criteria + PR-1.1/1.2/1.3 selftests run"
      ;;
  esac
  # Risk treatment 5: surface the exact emulator the markers run under
  # — if a CI runner's QEMU lacks SMEP/SMAP, the failure message below
  # carries the version context right next to it.
  echo "    $(qemu-system-x86_64 --version | head -1)"
  # Phase 6 S5: the persist lane boots the SAME image twice — boot 1
  # writes persist.txt, boot 2 verifies it survived. Every other lane
  # runs once. `ok` accumulates across boots; the loop body below is
  # the whole per-boot check sequence (delimited by the BOOT loop
  # comments), unchanged in indentation on purpose — the diff stays
  # about the loop, not 140 re-indented lines.
  RUNS=1
  if [ "${1:-}" = "--verify-persist" ]; then
    RUNS=2
  fi
  ok=1
  for BOOT in $(seq "$RUNS"); do
  : > "$LOG"
  if [ "${1:-}" = "--verify-persist" ]; then
    if [ "$BOOT" = "1" ]; then
      echo "── boot 1/$RUNS: this boot WRITES persist.txt ──"
    else
      echo "── boot 2/$RUNS: this boot must VERIFY what boot 1 wrote (same image, no regeneration) ──"
    fi
  fi
  START=$(date +%s.%N)
  # The q35 lane's host-side driver: marker-driven QMP (send-key once
  # the kernel is armed, screendump after it settles) + a longer
  # timeout (the keyboard poll spins for the injected key).
  # 600s, raised from 240 (measured 2026-11-21): the M2 syscall
  # audit phase alone emits ~390k serial lines before the driver
  # stack even starts, and q35 + intel-iommu under TCG on a loaded
  # dev box ran past 240s without reaching [PCI ] — the lane was
  # red on the GPT marker since round 6, so the regression hid.
  QEMU_TIMEOUT=60
  if [ "${1:-}" = "--verify-q35" ]; then
    QEMU_TIMEOUT=600
    rm -f /tmp/qmp.sock /tmp/screen.ppm
    touch "$LOG"
    (python3 "$(dirname "$0")/scripts/qmp_drive.py" "$LOG" >/tmp/qmp-drive.log 2>&1 &)
  fi
  # The PS/2 lane's own driver run: lean QMP mode — one key at the
  # kernel's armed marker, no GFX to capture, no USB window.
  if [ "${1:-}" = "--verify-ps2" ]; then
    QEMU_TIMEOUT=180
    rm -f /tmp/qmp.sock
    touch "$LOG"
    (python3 "$(dirname "$0")/scripts/qmp_drive.py" "$LOG" ps2 >/tmp/qmp-drive.log 2>&1 &)
  fi
  # The IR lane waits out the same keyboard poll budget (no QMP key is
  # injected there — the IOAPIC proof belongs to the base lane).
  if [ "${1:-}" = "--verify-q35-ir" ]; then
    QEMU_TIMEOUT=600
  fi
  # The persist lane runs the full M3 suite + the driver stack + the
  # two-boot proof under TCG with the IOMMU on — same budget as q35.
  if [ "${1:-}" = "--verify-persist" ]; then
    QEMU_TIMEOUT=600
  fi
  # The shell lane carries the SAME kernel image as every other lane
  # (all the kmain phases, the ~390k-line syscall audit) before init
  # ever forks the shell — the 60s default killed QEMU mid-session
  # once (K13, live): the shell had printed [SH] up and was executing
  # commands when the budget expired. Same 600s budget as q35/persist.
  if [ "${1:-}" = "--verify-shell" ]; then
    QEMU_TIMEOUT=600
  fi
  # ADR-0014: the q35 lane runs with the VT-d trace on, so the lane
  # can PROVE no device takes the pass-through fast path. The trace
  # (log backend) lands on stderr; the serial log stays on stdout.
  # set -euo pipefail (line 30) would kill this script on the
  # pipeline's rc — including the 124 of a BUDGET KILL: the shell
  # lane's kernel can end in M3's ERROR-halting path (init halts on a
  # failed session command), QEMU then sits in the halted state until
  # the timeout TERMs it, and the wall-clock echo + the verify greps
  # never ran — the lane printed no verdict at all (found live, rc=124
  # at exactly QEMU_TIMEOUT+8s). A budget-kill is not a verify
  # failure: the session markers are already in the log. Capture the
  # rc, restore -e, keep going.
  QEMU_RC=0
  if [ "${1:-}" = "--verify-q35" ]; then
    TRACE_LOG=$(mktemp)
    set +e
    timeout "$QEMU_TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" \
      -trace enable=vtd_* 2>"$TRACE_LOG" < "$STDIN_FILE" | tee "$LOG"
    QEMU_RC=$?
  else
    set +e
    timeout "$QEMU_TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" < "$STDIN_FILE" | tee "$LOG"
    QEMU_RC=$?
  fi
  set -e
  if [ "$QEMU_RC" = 124 ]; then
    echo "QEMU hit its ${QEMU_TIMEOUT}s budget (the kernel halted without exiting) — the verify greps still run"
  fi
  END=$(date +%s.%N)
  echo
  echo "boot $BOOT wall-clock: $(awk -v e="$END" -v s="$START" 'BEGIN { printf "%.2f", e - s }') s (QEMU startup included)"
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
    grep -qF "[RING3] files domain exited(42): pipe+dup+file lifecycle + the S1 directory dance verified from CPL=3" "$LOG" || { echo "VERIFY FAIL: round-J files marker missing"; ok=0; }
    grep -qF "[RING3] ring-3 syscall surface: OPEN/READ/WRITE/CLOSE/PIPE/DUP + the Phase-6 MKDIR/UNLINK arms live on the lib kernel" "$LOG" || { echo "VERIFY FAIL: round-J syscall-surface marker missing"; ok=0; }
    grep -qF "J:pipe ok" "$LOG" || { echo "VERIFY FAIL: round-J pipe marker (from CPL=3) missing"; ok=0; }
    grep -qF "J:dup ok" "$LOG" || { echo "VERIFY FAIL: round-J dup marker (from CPL=3) missing"; ok=0; }
    grep -qF "J:file ok" "$LOG" || { echo "VERIFY FAIL: round-J file marker (from CPL=3) missing"; ok=0; }
    grep -qF "J:neg ok" "$LOG" || { echo "VERIFY FAIL: round-J negative-probe marker (from CPL=3) missing"; ok=0; }
    grep -qF "[RING3] ring-3 isolation live: 8 runs" "$LOG" || { echo "VERIFY FAIL: ring-3 acceptance marker missing"; ok=0; }
  # ADR-0023 (M3 Phase 2): the ungated two-run preemption proof —
  # two ring-3 processes interleaved, the CPU-hog starved nobody.
  grep -qF "[M3] preempt: 2 runs interleaved" "$LOG" || { echo "VERIFY FAIL: M3 preemption-interleave marker missing"; ok=0; }
  # ADR-0031 section A: the flag-forge proof — a REAL delivered frame
  # rewritten to IF=0+AC=1 must restore sanitized (IF forced on, AC
  # stripped), the forger must stay preemptible (the slow writer
  # finishes first), and a plain AC-set + copy-free syscall excursion
  # must not weaken the SMAP self-test (the re-probe still faults).
  grep -qF "[SEC ] ADR-0031 forge: IF=0+AC=1 frame sanitized" "$LOG" || { echo "VERIFY FAIL: ADR-0031 flag-forge marker missing"; ok=0; }
  grep -qF "[SEC ] ADR-0031 AC-setter: entry clac held — the SMAP re-probe still faulted" "$LOG" || { echo "VERIFY FAIL: ADR-0031 AC-setter/SMAP re-probe marker missing"; ok=0; }
  # ADR-0031 section B: the flag rogues — the kernel survives a DF/TF/AC
  # rogue (the TF one dies by its own trap in either reading, never a
  # kernel halt), the 64-byte payloads arrive byte-exact, the
  # measurement slots print, and the FMASK readback is on record.
  grep -qF "[ARCH] FMASK readback: " "$LOG" || { echo "VERIFY FAIL: ADR-0031 FMASK readback marker missing"; ok=0; }
  grep -qF "[SEC] ADR-0031 measure: DF rogue" "$LOG" || { echo "VERIFY FAIL: ADR-0031 DF-rogue measure marker missing"; ok=0; }
  grep -qF "[SEC] ADR-0031 measure: TF rogue" "$LOG" || { echo "VERIFY FAIL: ADR-0031 TF-rogue measure marker missing"; ok=0; }
  grep -qF "[SEC] ADR-0031 measure: AC rogue" "$LOG" || { echo "VERIFY FAIL: ADR-0031 AC-rogue measure marker missing"; ok=0; }
  grep -qF "ROGUE-DF: the kernel copy must run forwards, byte-exact !!!!!!!" "$LOG" || { echo "VERIFY FAIL: ADR-0031 DF payload not byte-exact"; ok=0; }
  grep -qF "ROGUE-TF: the trap must never reach the kernel death path !!!!!" "$LOG" || { echo "VERIFY FAIL: ADR-0031 TF payload not byte-exact"; ok=0; }
  grep -qF "ROGUE-AC: the SMAP window must hold with AC in user image !!!!!" "$LOG" || { echo "VERIFY FAIL: ADR-0031 AC payload not byte-exact"; ok=0; }
  # round N2: the exec image quota — a five-page domain's exec of the
  # six-page sh image is refused before the point of no return, and
  # the old image proves it survived (marker + clean exit).
  grep -qF "[SEC] N2: the over-quota exec refused, the old image intact, pool conserved" "$LOG" || { echo "VERIFY FAIL: N2 quota-refused-exec marker missing"; ok=0; }
  grep -qF "quota-refused exec: the old image lives" "$LOG" || { echo "VERIFY FAIL: N2 old-image marker not byte-exact"; ok=0; }
  # ADR-0023: the sleep/idle proof (self-park + guarded idle + the
  # calibrated clock read from ring 3).
  grep -qF "[M3] sleep: idle engaged" "$LOG" || { echo "VERIFY FAIL: M3 sleep/idle marker missing"; ok=0; }
  grep -qF "[M3] clock: ring-3 clock_gettime verified by the blob" "$LOG" || { echo "VERIFY FAIL: M3 clock marker missing"; ok=0; }
  # ADR-0023 D8: the signal-frame proof (delivery + sigreturn + the
  # forged-frame refusal).
  grep -qF "[M3] signal: handler ran, sigreturn resumed, forged frame refused" "$LOG" || { echo "VERIFY FAIL: M3 signal marker missing"; ok=0; }
  # ADR-0024 D1: the mmap proof (two windows, a real munmap, the
  # freed read faulting).
  grep -qF "[M3] mmap: 2 windows mapped+verified" "$LOG" || { echo "VERIFY FAIL: M3 mmap marker missing"; ok=0; }
  # ADR-0024 D2: the fork/CoW proof (demote, two private copies,
  # clean exits, full reclaim).
  grep -qF "[M3] cow: fork shared" "$LOG" || { echo "VERIFY FAIL: M3 cow marker missing"; ok=0; }
  # ADR-0025: the async IPC proof (caps, bounded queues, both ends).
  grep -qF "[M3] ipc: 8+ messages over 2 channels" "$LOG" || { echo "VERIFY FAIL: M3 ipc marker missing"; ok=0; }
  # ADR-0026: the sync call/reply proof (rendezvous + queued, both).
  grep -qF "[M3] sync: 2 round-trips" "$LOG" || { echo "VERIFY FAIL: M3 sync marker missing"; ok=0; }
  # ADR-0027: the page-grant proof (bidirectional shared memory).
  grep -qF "[M3] grants: 1 page RW" "$LOG" || { echo "VERIFY FAIL: M3 grants marker missing"; ok=0; }
  # ADR-0027 (the ADR-0024 D2 fix): NO domain may leave owned frames
  # behind at teardown — the mismatch line is the loud accounting
  # catch (it printed "freed 5 of 9" every boot since the fork round).
  grep -q "MM ] teardown" "$LOG" && { echo "VERIFY FAIL: frame accounting leaked at teardown"; ok=0; }
  # ADR-0028: the bench — the blob's self-reported metrics + the
  # kernel's calibration line (the two halves of one measurement).
  grep -q "\[BENCH\] " "$LOG" || { echo "VERIFY FAIL: BENCH metrics line missing"; ok=0; }
  grep -qF "[M3] bench: 6 clean exits" "$LOG" || { echo "VERIFY FAIL: M3 bench marker missing"; ok=0; }
  grep -qF "[M3] bench: tsc_hz=" "$LOG" || { echo "VERIFY FAIL: bench calibration line missing"; ok=0; }
  # ADR-0029: the pipe proof — 64 bytes cross-domain over the byte
  # channel (the rendezvous wake AND the fast path), the live
  # refusals, and the rerouted fd path.
  grep -qF "[M3] pipe: 64 bytes cross-domain byte-exact" "$LOG" || { echo "VERIFY FAIL: M3 pipe marker missing"; ok=0; }
  grep -qF "[M3] linux-abi: v1 entry live" "$LOG" || { echo "VERIFY FAIL: M3 linux-abi marker missing"; ok=0; }
  grep -qF "[M3] init: PID 1's wait4 loop drained" "$LOG" || { echo "VERIFY FAIL: init wait4-loop marker missing (Phase 7)"; ok=0; }
  # Slice 4: the exec'd image's OWN serial marker — printed by the
  # ELF's code through the SURVIVING fd-1 console alias (fds cross
  # exec by design, ADR-0022 D4), parsed by the loader, mapped at its
  # declared vaddrs, entered at e_entry, bss zero-filled.
  grep -qF "[M3] exec-target: bss-clean entry live" "$LOG" || { echo "VERIFY FAIL: M3 exec slice marker missing (execve/ELF path)"; ok=0; }
  # K23: the repo fixture rides the ext2 disk — the driver stack's
  # /pkgsrc walk must have printed its source lines on EVERY lane
  # (the disks are attached above; the K22 [PKG] greps below depend
  # on this store being full).
  grep -qF "[PKGSRC] repo source: " "$LOG" || { echo "VERIFY FAIL: K23 pkgsrc marker missing (the repo fixture must ride the disk)"; ok=0; }
  # K22: the package manager domain — /bin/pkg at CPL=3, installing
  # from the signed local repo (the registry's SERVICE-contract image).
  grep -qF "[PKG] /bin/pkg: execve'd at CPL=3 under the SERVICE contract" "$LOG" || { echo "VERIFY FAIL: K22 pkg exec marker missing"; ok=0; }
  grep -qF "[PKG] install r1/hello@1.0.0: resolved from the signed local repo" "$LOG" || { echo "VERIFY FAIL: K22 pkg install marker missing"; ok=0; }
  grep -qF "[PKG] the installed tree: /usr/bin/pkg-hello byte-exact" "$LOG" || { echo "VERIFY FAIL: K22 pkg tree marker missing"; ok=0; }
  grep -qF "[PKG] live mask after exec == package_manager_profile" "$LOG" || { echo "VERIFY FAIL: K22 pkg live-mask marker missing"; ok=0; }
  grep -qF "[PKG] stack high-water: " "$LOG" || { echo "VERIFY FAIL: K22 pkg stack high-water marker missing"; ok=0; }
  grep -qF "[PKG] ERROR" "$LOG" && { echo "VERIFY FAIL: K22 pkg lane reported an ERROR"; ok=0; }
  # K23: the lifecycle rounds. The upgrade must be a real MOVE — the
  # solver resolves 1.1.0 ABOVE the installed 1.0.0 and the 17-B v1.1
  # payload replaces the 12-B 1.0.0 one (the old structural no-op
  # printed "done" and kept the bytes); the remove must take the
  # payload (ENOENT), the db record and the state entry away. The
  # rounds share ONE caller blob (a kernel-written selector byte in
  # its data page picks install/upgrade/remove).
  grep -qF "[PKG] upgrade r1/hello: 1.1.0 resolved ABOVE the installed 1.0.0, Ed25519-verified, committed (exit 0)" "$LOG" || { echo "VERIFY FAIL: K23 pkg upgrade marker missing"; ok=0; }
  grep -qF "[PKG] the upgraded tree: /usr/bin/pkg-hello == 17-B \"hello world v1.1\" payload, byte-exact — the payload moved" "$LOG" || { echo "VERIFY FAIL: K23 pkg upgraded-tree marker missing"; ok=0; }
  grep -qF "[PKG] remove r1/hello: the payload, the db record and the state entry uninstalled (exit 0)" "$LOG" || { echo "VERIFY FAIL: K23 pkg remove marker missing"; ok=0; }
  grep -qF "[PKG] the removed tree: stat /usr/bin/pkg-hello = ENOENT, /pkg/db/r1.hello gone, no r1/hello in /pkg/db/state" "$LOG" || { echo "VERIFY FAIL: K23 pkg removed-tree marker missing"; ok=0; }
  # K23: both markers must carry REAL values — a regression to the
  # K22 "unavailable (parked handover)" placeholders fails the verify.
  # The mask: the verdict must be "verified" (not MISMATCH, not
  # unavailable) AND the bits line must print the live bitset + the
  # arm set. The high-water: nonzero, page-aligned, and strictly
  # under the 8 MiB service stack — deliberately NOT asserted against
  # the static 7,589,376 B chain measure (a real run may be shallower).
  grep -qF "no fork/exec/mmap/net/ipc): verified" "$LOG" || { echo "VERIFY FAIL: K23 pkg live-mask verdict is not 'verified' (mismatch or unavailable)"; ok=0; }
  grep -qF "[PKG] live mask bits: 0x" "$LOG" || { echo "VERIFY FAIL: K23 pkg live mask bits line missing (regressed to unavailable?)"; ok=0; }
  grep -qF "(arms: " "$LOG" || { echo "VERIFY FAIL: K23 pkg live mask arm-set missing"; ok=0; }
  if grep "\[PKG\].*unavailable" "$LOG" >/dev/null 2>&1; then
    echo "VERIFY FAIL: K23 a [PKG] marker regressed to 'unavailable' (the parked handover must carry the exit facts)"; ok=0
  fi
  hw_bytes="$(sed -n 's/^\[PKG\] stack high-water: \([0-9][0-9]*\) of 8388608 B below the 8 MiB stack top$/\1/p' "$LOG" | head -n1)"
  if [ -z "$hw_bytes" ]; then
    echo "VERIFY FAIL: K23 pkg stack high-water did not parse as '<bytes> of 8388608 B' (regressed?)"; ok=0
  else
    [ "$hw_bytes" -gt 0 ] || { echo "VERIFY FAIL: K23 pkg stack high-water is zero (no pages touched?)"; ok=0; }
    [ $((hw_bytes % 4096)) -eq 0 ] || { echo "VERIFY FAIL: K23 pkg stack high-water ($hw_bytes) is not page-aligned"; ok=0; }
    [ "$hw_bytes" -lt 8388608 ] || { echo "VERIFY FAIL: K23 pkg stack high-water ($hw_bytes) is not below the 8 MiB service stack"; ok=0; }
  fi
  fi
  # M2-W2 / ADR-0012: the preemption demo boots only under
  # `--features preempt-demo` (see ADR-0012's open-issues section); the
  # default boot asserts the seven-run sequence above only.
  if grep -qF "[SCHD] preempt: switches=" "$LOG"; then
    grep -qF "[VERDICT] M2-W2 PREEMPTION: PASS" "$LOG" || { echo "VERIFY FAIL: M2-W2 preemption verdict failed"; ok=0; }
  fi
  grep -qF "[MM ] guarded stacks: alloc+map+cross-view ok, free+scrub ok" "$LOG" || { echo "VERIFY FAIL: guarded-stack marker missing"; ok=0; }
  # K20 (P0-1): the capacity selftest — the limits line, the fill/refuse
  # markers, and the all-layers-honest verdict (docs/capacity.md).
  grep -qF "[CAP] limits: domains=" "$LOG" || { echo "VERIFY FAIL: capacity limits line missing"; ok=0; }
  grep -qF "[CAP] limits: inodes=" "$LOG" || { echo "VERIFY FAIL: capacity limits line 2 missing"; ok=0; }
  grep -qF "[CAP] selftest: domains fill=" "$LOG" || { echo "VERIFY FAIL: capacity fill/refuse marker missing"; ok=0; }
  grep -qF "[CAP] selftest: fill/refuse/drain/reuse ok (all layers honest)" "$LOG" || { echo "VERIFY FAIL: capacity selftest verdict missing"; ok=0; }
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
      grep -qF "[PCI ] scan (bridge walk): " "$LOG" || { echo "VERIFY FAIL: PCI inventory marker missing"; ok=0; }
      grep -qF "0x1af4" "$LOG" || { echo "VERIFY FAIL: the virtio-blk must be in the inventory"; ok=0; }
grep -qF "(virtio-blk) → dom" "$LOG" || { echo "VERIFY FAIL: the virtio-blk claim must go through the broker (ADR-0018: its own domain)"; ok=0; }
      # ── ADR-0014: translation is REAL or the lane fails ──
      # (a) No device may take the pass-through fast path. Under the
      #     old TT=0b10 this fired 8x for six devices.
      if grep -q vtd_pt_enable_fast_path "$TRACE_LOG" 2>/dev/null; then
        echo "VERIFY FAIL: vtd_pt_enable_fast_path fired $(grep -c vtd_pt_enable_fast_path "$TRACE_LOG")x — a device is in pass-through (ADR-0014)"
        ok=0
      fi
      # (b) The enforcement probe must prove the IOMMU faults DMA to a
      #     broker-unmapped page (PPF) and that the SLPTE read back
      #     after unmap is absent (P=0).
      grep -qF "[VBLK] enforcement: PPF=yes" "$LOG" || { echo "VERIFY FAIL: the enforcement probe must print PPF=yes (ADR-0014)"; ok=0; }
      grep -qF "[VBLK] enforcement: slpte P=0 after unmap" "$LOG" || { echo "VERIFY FAIL: the SLPTE read-back after unmap must be absent (ADR-0014)"; ok=0; }
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
  # ── Phase 6 S5: the two-boot proof's own pair. Boot 1 writes, boot
  # 2 verifies — and each must NOT print the other's marker: boot 1
  # "verifying" a file that cannot exist yet, or boot 2 "writing"
  # again, both mean the image was reset or the branch is lying.
  if [ "${1:-}" = "--verify-persist" ]; then
    if [ "$BOOT" = "1" ]; then
      grep -qF "PERSIST:WRITTEN" "$LOG" || { echo "VERIFY FAIL: boot 1 must write persist.txt (PERSIST:WRITTEN)"; ok=0; }
      if grep -qF "PERSIST:VERIFIED" "$LOG"; then
        echo "VERIFY FAIL: boot 1 verified a file that cannot exist yet — the branch is lying"
        ok=0
      fi
    else
      grep -qF "PERSIST:VERIFIED" "$LOG" || { echo "VERIFY FAIL: boot 2 must read back what boot 1 wrote (PERSIST:VERIFIED)"; ok=0; }
      if grep -qF "PERSIST:WRITTEN" "$LOG"; then
        echo "VERIFY FAIL: boot 2 re-wrote the file — was the image regenerated between boots?"
        ok=0
      fi
    fi
  fi
  done  # ── end of the per-boot block (the persist lane's second iteration starts the verify greps fresh on a truncated LOG) ──
  # ADR-0017's transport made audible: the virtio-console round trip's
  # HOST half — the guest marker above proves the driver, the file
  # below proves the bytes actually LEFT the machine.
  if [ "${1:-}" = "--verify-q35" ]; then
    # Round I: the C0-idle proof accepts any of the three honest wake
    # paths — under load the delivery races the monitor arming, and
    # every one of them proves the same thing (the interrupt-open
    # window + the real IRQ delivered).
    grep -qa "\[IDLE\] mwait woke on the delivery store\|\[IDLE\] mwait armed late\|\[IDLE\] delivery landed before mwait slept" "$LOG" || {
      echo "VERIFY FAIL: no C0-idle proof line (mwait woke / armed late / loop top)"
      ok=0
    }
    if [ ! -s target/console.out ] || ! grep -q "AEGIS-VIRTIO-CONSOLE-ROUNDTRIP" target/console.out; then
      echo "VERIFY FAIL: the console round trip never reached the host file"
      ok=0
    fi
  fi
  if [ "${1:-}" = "--verify-q35" ] && [ "$ok" = 1 ]; then
    # Pixel-level proof of the GFX driver: what QMP captured has to
    # match the pattern drawn (weight it into the verdict honestly).
    if ! python3 "$(dirname "$0")/scripts/check_screen.py" /tmp/screen.ppm; then
      ok=0
    fi
    # Phase 4 (the text console): the SECOND capture — the banner's
    # glyphs, pixel-exact, on the 80x30 double-buffered text plane.
    if [ ! -s /tmp/screen2.ppm ] || ! python3 "$(dirname "$0")/scripts/check_screen.py" /tmp/screen2.ppm --text; then
      ok=0
    fi
    # The keyboard round trip's new shape: the decoded BYTE in the
    # console-in ring (the IRQ bottom half fed it).
    # USB (item 12, slice 1 of the completion): the SILENT REGRESSION
    # FIX — the session teardown discipline had cut bus mastering and
    # the xHCI TRB layer died with it ("DMA memory access failed",
    # HCE-sticky); the No-Op's completion is a PINNED grep now (it
    # silently broke once already). The enumeration slice's current
    # Full proof: the enumeration's three markers — device enumerated,
    # the HID boot keyboard's interrupt-IN endpoint parsed, and the 'a'
    # report delivered through the xHCI interrupt-IN pipe (QMP key).
    grep -qa "No-Op command: event-ring slot0 type=33 = COMMAND COMPLETION" "$LOG" || {
      echo "VERIFY FAIL: the xHCI TRB machinery (the No-Op) is dead"
      ok=0
    }
    grep -qa "device enumerated: vid=" "$LOG" || {
      echo "VERIFY FAIL: the USB enumeration never completed (Address Device + Get Descriptor)"
      ok=0
    }
    grep -qa "HID keyboard: interrupt-IN EP" "$LOG" || {
      echo "VERIFY FAIL: no HID boot keyboard endpoint was parsed"
      ok=0
    }
    grep -qaE "HID report: key 0x0000000000000004 decoded \\('a'\\)" "$LOG" || {
      echo "VERIFY FAIL: the USB keyboard round trip never landed"
      ok=0
    }
    grep -qa "\[GFX2\] text console: 80x30 cells live" "$LOG" || {
      echo "VERIFY FAIL: the text console marker missing"
      ok=0
    }
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
