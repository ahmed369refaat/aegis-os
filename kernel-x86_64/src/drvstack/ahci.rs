//! AHCI: ABAR/port bring-up, IDENTIFY, DMA reads + the ext2 mount entry.

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

// ── AHCI/SATA (checklist item 7): the q35's built-in ich9-ahci —
// port bring-up, command list + FIS rx + PRDT via broker frames, an
// IDENTIFY DEVICE issue. Same cluster caveat as e1000/nvme for the
// data phase; every register step is proven ──

/// The pool owner tag for AHCI frames (cmd list, cmd table, FIS rx,
/// data page).
pub const AHCI_OWNER: u32 = 47;

/// Build header 0 + the READ DMA EXT (0x25) command table — the
/// ADR-0014 layout QEMU actually parses: FIS bytes 4-6 LBA 0-23,
/// byte 7 device, bytes 8-10 LBA 24-47, byte 12 the sector count, and
/// the PRDT's byte count in the entry's LAST dword (+0x8C). Every
/// field offset here was once wrong (the "stale FIS" was three
/// driver bugs) — the tests pin them. Pure PA writes.
fn build_read_dma_cmdtable(clb: u64, ctba: u64, buf: u64, lba: u64) {
    // Header 0: CFL=5, PRDTL=1, table at ctba.
    crate::memops::write_u32(clb, 5 | (1 << 16));
    crate::memops::write_u32(clb + 4, 0);
    crate::memops::write_u32(clb + 8, ctba as u32);
    crate::memops::write_u32(clb + 12, 0);
    // H2D FIS: READ DMA EXT (0x25, 48-bit LBA).
    crate::memops::write_u32(ctba, 0x27 | (0x80 << 8) | (0x25 << 16));
    // dword 1 (bytes 4-7): LBA low 24 bits, device 0x40 (LBA select).
    crate::memops::write_u32(
        ctba + 4,
        ((lba & 0xFF) as u32)
            | ((((lba >> 8) & 0xFF) as u32) << 8)
            | ((((lba >> 16) & 0xFF) as u32) << 16)
            | (0x40u32 << 24),
    );
    // dword 2 (bytes 8-11): LBA bits 24-47, feature 15:8 = 0.
    crate::memops::write_u32(
        ctba + 8,
        (((lba >> 24) & 0xFF) as u32)
            | ((((lba >> 32) & 0xFF) as u32) << 8)
            | ((((lba >> 40) & 0xFF) as u32) << 16),
    );
    // dword 3 (bytes 12-15): sector count 7:0 = 1 at byte 12.
    crate::memops::write_u32(ctba + 12, 1);
    crate::memops::write_u64(ctba + 16, 0);
    crate::memops::write_u64(ctba + 24, 0);
    crate::memops::write_u64(ctba + 32, 0);
    // PRDT: buf at +0x80, byte count in the LAST dword (+0x8C).
    crate::memops::write_u64(ctba + 0x80, buf);
    crate::memops::write_u32(ctba + 0x88, 0);
    crate::memops::write_u32(ctba + 0x8C, 511);
}

/// Build header 0 + the IDENTIFY DEVICE (0xEC) command table.
fn build_identify_cmdtable(clb: u64, ctba: u64, data: u64) {
    crate::memops::write_u32(clb, 5 | (1 << 16));
    crate::memops::write_u32(clb + 4, 0);
    crate::memops::write_u32(clb + 8, ctba as u32);
    crate::memops::write_u32(clb + 12, 0);
    // H2D FIS: 0x27 | C | 0xEC (IDENTIFY DEVICE) | dev 0xE0.
    crate::memops::write_u64(ctba, 0x27 | (0x80 << 8) | (0xEC << 16) | (0xE0 << 24));
    crate::memops::write_u64(ctba + 8, 0);
    crate::memops::write_u64(ctba + 16, 0);
    crate::memops::write_u64(ctba + 24, 0);
    crate::memops::write_u64(ctba + 32, 0);
    crate::memops::write_u64(ctba + 40, 0);
    crate::memops::write_u64(ctba + 48, 0);
    crate::memops::write_u64(ctba + 56, 0);
    // PRDT entry 0 at ctba+0x80: data page; byte count in the LAST
    // dword (+0x8C, zero-based DBC).
    crate::memops::write_u64(ctba + 0x80, data);
    crate::memops::write_u32(ctba + 0x88, 0);
    crate::memops::write_u32(ctba + 0x8C, 511);
}

#[cfg(not(test))]
pub(crate) fn ahci_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x8086, 0x01) else {
        line(out, &["[AHCI] no AHCI to drive on this machine"]);
        return;
    };
    // The no-IOMMU control lane (ADR-0014 step 5): the SAME two-command
    // IDENTIFY→READ sequence with unbrokered frames. If the stale-FIS
    // signature disappears here, it is a vIOMMU emulation artifact; if
    // it reproduces, the driver owns it (see drivers.md).
    let identity = matches!(broker.verdict(), DmaVerdict::Absent { .. });
    if identity {
        line(
            out,
            &["[AHCI] identity mode: no IOMMU on this machine — same two-command sequence, unbrokered frames (the stale-FIS control lane)"],
        );
    }
    let Some(bar) = crate::pci::mem_bar(dev, 5) else {
        line(out, &["[AHCI] ABAR (BAR5) unresolved — refusing"]);
        return;
    };
    // ADR-0016: one window for the ABAR; port 0's registers reach
    // 0x100+0x38 (CI) — the door check makes that a claim, and the
    // per-access refusals below are defense-in-depth.
    let Some(bus) = crate::mmio::BarMmio::new(bar.base, bar.size) else {
        line(
            out,
            &["[AHCI] ABAR window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    if bus.window().len() < 0x100 + 0x38 + 4 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[AHCI] ABAR window too small for port 0's registers (len=",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    // F9e: MEM now; BME after the port frames are broker-mapped.
    crate::pci::enable_mem(dev);
    use crate::mmio::MmioBus;
    let (Some(ghc), Some(pi), Some(sig)) =
        (bus.read32(0x04), bus.read32(0x0C), bus.read32(0x100 + 0x24))
    else {
        line(
            out,
            &["[AHCI] register window refused a GHC/PI/SIG read — refusing"],
        );
        return;
    };
    let ghc_ae = ghc & 0x8000_0000 != 0;
    let mut h = [0u8; 18];
    let mut h2 = [0u8; 18];
    line(
        out,
        &[
            "[AHCI] ABAR live: GHC.AE=",
            if ghc_ae { "1" } else { "0" },
            " PI=",
            strutil::hex(u64::from(pi), &mut h),
            " port0 SIG=",
            strutil::hex(u64::from(sig), &mut h2),
            " (0x101 = SATA disk)",
        ],
    );
    if pi & 1 == 0 {
        line(out, &["[AHCI] port 0 not implemented — refusing"]);
        return;
    }

    // ADR-0016/F10: the session owns the port frames — identity or
    // brokered; every exit below is one close().
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        AHCI_OWNER,
        dev.dom,
        identity,
        "[AHCI] teardown",
        "[AHCI] teardown (identity): frames freed, no broker regions",
    );
    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[AHCI] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [clb, ctba, fis, data] = frames;
    if !identity {
        for &pa in frames.iter() {
            if session.map(pa).is_none() {
                line(out, &["[AHCI] broker refused a frame — refusing"]);
                return;
            }
        }
        line(
            out,
            &["[AHCI] port 0: CLB/FB/CTBA/data mapped via broker (4 regions)"],
        );
        // F9e: port frames mapped — now it may DMA.
        crate::pci::enable_bus_master(dev);
    } else {
        line(
            out,
            &["[AHCI] port 0: CLB/FB/CTBA/data straight from the pool (identity, 0 regions)"],
        );
        // F9e, identity lane: there are no broker mappings to gate
        // on — the device needs bus mastering right away.
        crate::pci::enable_bus_master(dev);
    }

    // Stop the engine, reprogram CLB/FB, restart with FRE|ST. The
    // frames are mapped and the device has BME — a refused write here
    // is a full teardown.
    let Some(cmd) = bus.read32(0x100 + 0x18) else {
        line(
            out,
            &["[AHCI] register window refused a PxCMD read — teardown"],
        );
        session.close(out);
        return;
    };
    if !bus.write32(0x100 + 0x18, cmd & !1) {
        line(
            out,
            &["[AHCI] register window refused a PxCMD write — teardown"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(0x100 + 0x20).is_some_and(|v| v & 0x88 != 0) && spins < 4_000_000 {
        spins += 1;
    } // TFD.BSY|DRQ
    let port_prog = [
        (0x100u64, clb as u32),
        (0x100 + 0x04, 0),
        (0x100 + 0x08, fis as u32),
        (0x100 + 0x0C, 0),
        (0x100 + 0x18, 0x11 /* FRE | ST */),
    ];
    for &(off, v) in port_prog.iter() {
        if !bus.write32(off, v) {
            line(
                out,
                &["[AHCI] register window refused a port write — teardown"],
            );
            session.close(out);
            return;
        }
    }

    // Command header 0: CFL=5, PRDTL=1; table at ctba.
    crate::memops::write_u32(clb, 5 | (1 << 16));
    crate::memops::write_u32(clb + 4, 0); // PRDBC
    build_identify_cmdtable(clb, ctba, data);

    // Issue and poll CI bit 0.
    if !bus.write32(0x100 + 0x38, 1) {
        line(
            out,
            &["[AHCI] register window refused the CI write — teardown"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(0x100 + 0x38).is_some_and(|v| v & 1 != 0) && spins < 10_000_000 {
        spins += 1;
    }
    let ci_done = bus.read32(0x100 + 0x38).is_some_and(|v| v & 1 == 0)
        && bus.read32(0x100 + 0x20).is_some_and(|v| v & 0x88 == 0);
    if ci_done {
        let w0 = crate::virtio::read_u16_pa(data);
        let sn = crate::memops::read_u64(data + 20); // serial words 10-11
        let mut hs = [0u8; 18];
        line(
            out,
            &[
                "[AHCI] IDENTIFY completed: word0=",
                strutil::hex(u64::from(w0), &mut h),
                " serial[0..8]=",
                strutil::hex(sn, &mut hs),
                if identity {
                    " (512 bytes, identity lane)"
                } else {
                    " (512 bytes through the IOMMU)"
                },
            ],
        );
        // The block layer's first slice rides the LIVE port: read-only
        // ext2 (superblock → root dir → hello.txt) via READ DMA.
        super::ext2::ext2_over_ahci(out, &bus, clb, ctba, fis, data);
        // The ESP slice follows on the same port: GPT partition 2,
        // read-only FAT32 (BPB → root dirent → cluster chain).
        super::fat32::fat32_over_ahci(out, &bus, clb, ctba, fis, data);
    } else {
        line(
            out,
            &["[AHCI] IDENTIFY issued, no completion on this lane (open: the device-DMA cluster; see drivers.md)"],
        );
    }
    // Teardown: the identity lane frees with BME cut first; the
    // broker path runs the shared revoke discipline (ADR-0016/F10).
    session.close(out);
}

// ── USB xHCI bring-up (checklist item 12): caps, halt, reset, DCBAAP
// + MaxSlotsEn + CRCR, RUN — and port-scan the attached usb-kbd. The
// bring-up path is register-only (no device DMA), so it is FULLY
// proven here; enumeration/TRB rings are the next slice ──

/// One AHCI READ-DMA exchange: rebuild command slot 0 for `lba`
/// (1 sector) into `buf` and wait for CI to clear. Returns false if
/// the command never completes.
#[cfg(not(test))]
pub(crate) fn ahci_read_dma(
    bus: &crate::mmio::BarMmio,
    clb: u64,
    ctba: u64,
    buf: u64,
    lba: u64,
) -> bool {
    use crate::mmio::MmioBus;
    build_read_dma_cmdtable(clb, ctba, buf, lba);
    crate::memops::write_u32(ctba + 0x8C, 511);
    // QEMU's handle_cmd silently SKIPS the command when the IDE
    // engine still reports BSY/DRQ (the tail of the previous PIO
    // command — measured: CI stays set, no FIS, no data; ahci.c:1317
    // "Engine currently busy, try again later"). Wait TFD clean first.
    let mut spins = 0u64;
    while bus.read32(0x100 + 0x20).is_some_and(|v| v & 0x88 != 0) && spins < 8_000_000 {
        spins += 1;
    }
    if !bus.read32(0x100 + 0x20).is_some_and(|v| v & 0x88 == 0) {
        return false; // engine stuck busy (or window refused) — honest failure
    }
    if !bus.write32(0x100 + 0x38, 1) {
        return false; // CI write refused — honest failure
    }
    let mut spins = 0u64;
    while bus.read32(0x100 + 0x38).is_some_and(|v| v & 1 != 0) && spins < 10_000_000 {
        spins += 1;
    }
    bus.read32(0x100 + 0x38).is_some_and(|v| v & 1 == 0)
        && bus.read32(0x100 + 0x20).is_some_and(|v| v & 0x88 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ADR-0014 offsets, pinned: every field offset here was once
    /// wrong and cost a session of debugging ("the stale FIS").
    #[test]
    fn read_dma_cmdtable_pins_the_fis_and_prdt_layout() {
        let phys = crate::drvstack::testharness::FakePhys::new(4);
        let clb = phys.pa(0);
        let ctba = phys.pa(4096);
        let buf = phys.pa(8192);
        let lba: u64 = 0x0123_4567_89AB;
        build_read_dma_cmdtable(clb, ctba, buf, lba);
        // header: CFL=5, PRDTL=1, table address
        assert_eq!(crate::memops::read_u32(clb), 5 | (1 << 16));
        // CTBA is a 32-bit field (the AHCI command-table address)
        assert_eq!(crate::memops::read_u32(clb + 8), ctba as u32);
        // FIS: H2D | C | READ DMA EXT
        assert_eq!(
            crate::memops::read_u32(ctba),
            0x27 | (0x80 << 8) | (0x25 << 16)
        );
        // LBA bytes 4-6 (low 24), device 0x40 at byte 7 (byte-level)
        // LBA 0x0123456789AB: LSB-first bytes AB 89 67 | 45 23 01
        assert_eq!(crate::virtio::read_u8_pa(ctba + 4), 0xAB);
        assert_eq!(crate::virtio::read_u8_pa(ctba + 5), 0x89);
        assert_eq!(crate::virtio::read_u8_pa(ctba + 6), 0x67);
        assert_eq!(
            crate::virtio::read_u8_pa(ctba + 7),
            0x40,
            "device = LBA select"
        );
        // LBA bytes 8-10 (bits 24-47)
        assert_eq!(crate::virtio::read_u8_pa(ctba + 8), 0x45);
        assert_eq!(crate::virtio::read_u8_pa(ctba + 9), 0x23);
        assert_eq!(crate::virtio::read_u8_pa(ctba + 10), 0x01);
        // sector count at byte 12 (the never-written-byte-12 bug)
        assert_eq!(crate::virtio::read_u8_pa(ctba + 12), 1);
        // PRDT: buffer at +0x80, byte count in the LAST dword (+0x8C)
        assert_eq!(crate::memops::read_u64(ctba + 0x80), buf);
        assert_eq!(
            crate::memops::read_u32(ctba + 0x88),
            0,
            "the reserved dword stays 0"
        );
        assert_eq!(
            crate::memops::read_u32(ctba + 0x8C),
            511,
            "zero-based DBC in the last dword"
        );
    }

    #[test]
    fn read_dma_survives_hostile_lbas_without_panicking() {
        let phys = crate::drvstack::testharness::FakePhys::new(4);
        let clb = phys.pa(0);
        let ctba = phys.pa(4096);
        let mut rng = crate::drvstack::testharness::XorShift(0xFEED);
        for _ in 0..1000 {
            let lba = rng.next();
            build_read_dma_cmdtable(clb, ctba, phys.pa(8192), lba);
            // every FIS byte lands in its documented field: the low 48
            // bits distribute across bytes 4-6 and 8-10, count stays 1.
            let b4 = crate::virtio::read_u8_pa(ctba + 4) as u64;
            let b5 = crate::virtio::read_u8_pa(ctba + 5) as u64;
            let b6 = crate::virtio::read_u8_pa(ctba + 6) as u64;
            let b8 = crate::virtio::read_u8_pa(ctba + 8) as u64;
            let b9 = crate::virtio::read_u8_pa(ctba + 9) as u64;
            let b10 = crate::virtio::read_u8_pa(ctba + 10) as u64;
            let rebuilt = b4 | (b5 << 8) | (b6 << 16) | (b8 << 24) | (b9 << 32) | (b10 << 40);
            assert_eq!(
                rebuilt,
                lba & ((1 << 48) - 1),
                "the 48-bit LBA survives the roundtrip"
            );
        }
    }

    #[test]
    fn identify_cmdtable_pins_the_ec_fis() {
        let phys = crate::drvstack::testharness::FakePhys::new(4);
        let clb = phys.pa(0);
        let ctba = phys.pa(4096);
        let data = phys.pa(8192);
        build_identify_cmdtable(clb, ctba, data);
        assert_eq!(
            crate::memops::read_u64(ctba),
            0x27 | (0x80 << 8) | (0xEC << 16) | (0xE0u64 << 24)
        );
        assert_eq!(crate::memops::read_u32(ctba + 0x8C), 511);
    }
}
