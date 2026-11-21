//! AHCI: ABAR/port bring-up, IDENTIFY, DMA reads + the ext2 mount entry.

use super::ext2::ext2_over_ahci;
use super::{line, revoke_or_quarantine};
use crate::frames::FramePool;
use crate::strutil;

// ── AHCI/SATA (checklist item 7): the q35's built-in ich9-ahci —
// port bring-up, command list + FIS rx + PRDT via broker frames, an
// IDENTIFY DEVICE issue. Same cluster caveat as e1000/nvme for the
// data phase; every register step is proven ──

/// The pool owner tag for AHCI frames (cmd list, cmd table, FIS rx,
/// data page).
pub const AHCI_OWNER: u32 = 47;

#[cfg(not(test))]
pub(crate) fn ahci_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::{DmaDir, DmaVerdict};

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
    let Some(abar) = crate::pci::mem_bar_base(dev, 5) else {
        line(out, &["[AHCI] ABAR (BAR5) unresolved — refusing"]);
        return;
    };
    // F9e: MEM now; BME after the port frames are broker-mapped.
    crate::pci::enable_mem(dev);
    let r32 = |off: u64| crate::memops::read_u32(abar + off);
    let w32 = |off: u64, v: u32| crate::memops::write_u32(abar + off, v);
    let ghc_ae = r32(0x04) & 0x8000_0000 != 0;
    let pi = r32(0x0C);
    let sig = r32(0x100 + 0x24);
    let mut h = [0u8; 18];
    let mut h2 = [0u8; 18];
    line(
        out,
        &[
            "[AHCI] ABAR live: GHC.AE=",
            if ghc_ae { "1" } else { "0" },
            " PI=0x",
            strutil::hex(u64::from(pi), &mut h),
            " port0 SIG=0x",
            strutil::hex(u64::from(sig), &mut h2),
            " (0x101 = SATA disk)",
        ],
    );
    if pi & 1 == 0 {
        line(out, &["[AHCI] port 0 not implemented — refusing"]);
        return;
    }

    let mut frames = [0u64; 4];
    for slot in frames.iter_mut() {
        match pool.alloc_for(&mut k.frames, AHCI_OWNER) {
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
            if broker
                .map_region(0, pa, 4096, DmaDir::Bidirectional)
                .is_err()
            {
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

    // Stop the engine, reprogram CLB/FB, restart with FRE|ST.
    let cmd = r32(0x100 + 0x18);
    w32(0x100 + 0x18, cmd & !1); // ~ST
    let mut spins = 0u64;
    while r32(0x100 + 0x20) & 0x88 != 0 && spins < 4_000_000 {
        spins += 1;
    } // TFD.BSY|DRQ
    w32(0x100, clb as u32);
    w32(0x100 + 0x04, 0);
    w32(0x100 + 0x08, fis as u32);
    w32(0x100 + 0x0C, 0);
    w32(0x100 + 0x18, 0x11); // FRE | ST

    // Command header 0: CFL=5, PRDTL=1; table at ctba.
    crate::memops::write_u32(clb, 5 | (1 << 16));
    crate::memops::write_u32(clb + 4, 0); // PRDBC
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
    // dword (+0x8C, zero-based DBC — see ahci_read_dma's note).
    crate::memops::write_u64(ctba + 0x80, data);
    crate::memops::write_u32(ctba + 0x88, 0);
    crate::memops::write_u32(ctba + 0x8C, 511);

    // Issue and poll CI bit 0.
    w32(0x100 + 0x38, 1);
    let mut spins = 0u64;
    while r32(0x100 + 0x38) & 1 != 0 && spins < 10_000_000 {
        spins += 1;
    }
    if r32(0x100 + 0x38) & 1 == 0 && r32(0x100 + 0x20) & 0x88 == 0 {
        let w0 = crate::virtio::read_u16_pa(data);
        let sn = crate::memops::read_u64(data + 20); // serial words 10-11
        let mut hs = [0u8; 18];
        line(
            out,
            &[
                "[AHCI] IDENTIFY completed: word0=0x",
                strutil::hex(u64::from(w0), &mut h),
                " serial[0..8]=0x",
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
        ext2_over_ahci(out, abar, clb, ctba, fis, data);
    } else {
        line(
            out,
            &["[AHCI] IDENTIFY issued, no completion on this lane (open: the device-DMA cluster; see drivers.md)"],
        );
    }
    if identity {
        line(
            out,
            &["[AHCI] teardown (identity): frames freed, no broker regions"],
        );
        for &pa in frames.iter() {
            let _ = pool.free(&mut k.frames, pa, AHCI_OWNER);
        }
    } else {
        // The helper owns frame freeing on the broker path — and on
        // poison, quarantines them (ADR-0015 F2).
        revoke_or_quarantine(
            k,
            pool,
            out,
            broker,
            AHCI_OWNER,
            &frames,
            Some(dev),
            "[AHCI] teardown: revoke_all(0) → ",
        );
    }
}

// ── USB xHCI bring-up (checklist item 12): caps, halt, reset, DCBAAP
// + MaxSlotsEn + CRCR, RUN — and port-scan the attached usb-kbd. The
// bring-up path is register-only (no device DMA), so it is FULLY
// proven here; enumeration/TRB rings are the next slice ──

/// One AHCI READ-DMA exchange: rebuild command slot 0 for `lba`
/// (1 sector) into `buf` and wait for CI to clear. Returns false if
/// the command never completes.
#[cfg(not(test))]
pub(crate) fn ahci_read_dma(abar: u64, clb: u64, ctba: u64, buf: u64, lba: u64) -> bool {
    let r32 = |off: u64| crate::memops::read_u32(abar + off);
    let w32 = |off: u64, v: u32| crate::memops::write_u32(abar + off, v);
    // Header 0: CFL=5, PRDTL=1, table at ctba.
    crate::memops::write_u32(clb, 5 | (1 << 16));
    crate::memops::write_u32(clb + 4, 0);
    crate::memops::write_u32(clb + 8, ctba as u32);
    crate::memops::write_u32(clb + 12, 0);
    // H2D FIS: READ DMA EXT (0x25, 48-bit LBA) — the modern AHCI
    // path Linux uses; the 28-bit 0xC8 completed as a no-op on this
    // QEMU build (measured: TFD=0x50, no data, no D2H FIS).
    // ADR-0014 step 5, the layout QEMU actually parses (ahci.c
    // handle_reg_h2d_fis): bytes 4-6 LBA 0-23, byte 7 device, bytes
    // 8-10 LBA 24-47, bytes 12-13 sector count. The original code put
    // the LBA at bytes 9-11 and NEVER wrote byte 12 (0 = 65536
    // sectors, measured as prepare_buf limit=32 MiB, so LBA 2 read as
    // LBA 2<<24 — off the image): the "stale FIS" was this driver
    // bug, not QEMU's FIS cache — the cmd-table read-back showed the
    // driver's bytes present in RAM all along.
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
    // dword 3 (bytes 12-15): sector count 7:0 = 1 at byte 12; count
    // 15:8 and control zero.
    crate::memops::write_u32(ctba + 12, 1);
    crate::memops::write_u64(ctba + 16, 0);
    crate::memops::write_u64(ctba + 24, 0);
    crate::memops::write_u64(ctba + 32, 0);
    // PRDT: buf at +0x80; the byte count lives in the entry's LAST
    // dword (+0x8C — QEMU's AHCI_SG { addr, reserved, flags_size },
    // zero-based DBC at bits 21:0, I at bit 31). Writing it at +0x88
    // (the reserved dword) made every entry "1 byte" (measured:
    // prepare_buf prepared=1, no DMA transfer).
    crate::memops::write_u64(ctba + 0x80, buf);
    crate::memops::write_u32(ctba + 0x88, 0);
    crate::memops::write_u32(ctba + 0x8C, 511);
    // QEMU's handle_cmd silently SKIPS the command when the IDE
    // engine still reports BSY/DRQ (the tail of the previous PIO
    // command — measured: CI stays set, no FIS, no data; ahci.c:1317
    // "Engine currently busy, try again later"). Wait TFD clean first.
    let mut spins = 0u64;
    while r32(0x100 + 0x20) & 0x88 != 0 && spins < 8_000_000 {
        spins += 1;
    }
    if r32(0x100 + 0x20) & 0x88 != 0 {
        return false; // engine stuck busy — honest failure
    }
    w32(0x100 + 0x38, 1); // CI bit 0
    let mut spins = 0u64;
    while r32(0x100 + 0x38) & 1 != 0 && spins < 10_000_000 {
        spins += 1;
    }
    r32(0x100 + 0x38) & 1 == 0 && r32(0x100 + 0x20) & 0x88 == 0
}
