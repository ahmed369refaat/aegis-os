//! Read-only ext2 over AHCI (ADR-0014): superblock -> dirent -> file data.

use super::ahci::ahci_read_dma;
use super::line;
use crate::strutil;

/// The pool owner tag for the ext2 slice's AHCI frames.
pub const EXT2_OWNER: u32 = 49;

/// ext2 first slice: mount the SATA disk's superblock, walk the root
/// directory, read hello.txt through AHCI READ DMA.
#[cfg(not(test))]
pub(crate) fn ext2_over_ahci(
    out: &mut dyn FnMut(&str),
    abar: u64,
    clb: u64,
    ctba: u64,
    fis: u64,
    data: u64,
) {
    // Runs on the LIVE port ahci_step owns — no restart, no second
    // frame set (the restart path was measured broken: even with the
    // FRE=0 rule honored, the re-issued commands complete with no
    // data on this QEMU build).
    let port = abar + 0x100;
    let mut h = [0u8; 18];
    // Superblock: LBA 2 (byte 1024, 1KiB blocks).
    if !ahci_read_dma(abar, clb, ctba, data, 2) {
        line(out, &["[EXT2] superblock read did not complete — refusing"]);
        return;
    }
    let magic = crate::virtio::read_u16_pa(data + 56);
    let inode_size = crate::virtio::read_u16_pa(data + 88);
    if magic != 0xEF53 {
        let tfd = crate::memops::read_u32(port + 0x20);
        let d0 = crate::memops::read_u64(data);
        let f0 = crate::memops::read_u64(fis);
        let mut hd = [0u8; 18];
        let mut hd2 = [0u8; 18];
        let mut hd3 = [0u8; 18];
        line(
            out,
            &[
                "[EXT2] superblock read failed: the sector did not land (the ADR-0014 forensics line below carries the command-table state; the historical stale-FIS reading was three driver bugs — see drivers.md)",
            ],
        );
        line(
            out,
            &[
                "[EXT2] dbg read LBA2: TFD=0x",
                strutil::hex(u64::from(tfd), &mut h),
                " data[0]=0x",
                strutil::hex(d0, &mut hd),
                " d2h_fis[0]=0x",
                strutil::hex(f0, &mut hd2),
                " — magic 0x",
                strutil::hex(u64::from(magic), &mut hd3),
                " != 0xef53 — refusing",
            ],
        );
        // ADR-0014 step 5 forensics: what did the driver actually leave
        // in the header and the command table?
        let mut hc = [0u8; 18];
        let mut ht = [0u8; 18];
        let mut t0 = [0u8; 18];
        let mut t1 = [0u8; 18];
        let mut t2 = [0u8; 18];
        let mut pd = [0u8; 18];
        let mut pc = [0u8; 18];
        line(
            out,
            &[
                "[EXT2] dbg cmdtbl: hdr0=0x",
                strutil::hex(u64::from(crate::memops::read_u32(clb)), &mut hc),
                " hdr_ctba=0x",
                strutil::hex(u64::from(crate::memops::read_u32(clb + 8)), &mut ht),
                " fis_d0=0x",
                strutil::hex(u64::from(crate::memops::read_u32(ctba)), &mut t0),
                " fis_d1=0x",
                strutil::hex(u64::from(crate::memops::read_u32(ctba + 4)), &mut t1),
                " fis_d2=0x",
                strutil::hex(u64::from(crate::memops::read_u32(ctba + 8)), &mut t2),
                " prdt_dba=0x",
                strutil::hex(crate::memops::read_u64(ctba + 0x80), &mut pd),
                " prdt_dbc=0x",
                strutil::hex(u64::from(crate::memops::read_u32(ctba + 0x88)), &mut pc),
            ],
        );
        return;
    }
    line(
        out,
        &[
            "[EXT2] superblock ok (magic 0xef53, inode_size=",
            strutil::dec(u64::from(inode_size), &mut [0u8; 20]),
            "); ",
        ],
    );
    // Group descriptor: LBA 4 (block 2), bg_inode_table u32 @+8.
    if !ahci_read_dma(abar, clb, ctba, data, 4) {
        line(out, &["[EXT2] group-descriptor read failed — refusing"]);
        return;
    }
    let itable = crate::memops::read_u32(data + 8); // block number
                                                    // Root inode (2): at itable*1024 + 128 → its sector + offset.
    let root_byte = u64::from(itable) * 1024 + 128;
    if !ahci_read_dma(abar, clb, ctba, data, root_byte / 512) {
        line(out, &["[EXT2] root-inode read failed — refusing"]);
        return;
    }
    let roff = root_byte % 512;
    let rmode = crate::virtio::read_u16_pa(data + roff);
    let rsize = crate::memops::read_u32(data + roff + 4);
    let rblock = crate::memops::read_u32(data + roff + 40);
    if rmode != 0x41ED {
        let mut hm = [0u8; 18];
        line(
            out,
            &[
                "[EXT2] root inode mode 0x",
                strutil::hex(u64::from(rmode), &mut hm),
                " not a directory — refusing",
            ],
        );
        return;
    }
    // Directory block: walk dirents, find "hello.txt".
    if !ahci_read_dma(abar, clb, ctba, data, u64::from(rblock) * 2) {
        line(out, &["[EXT2] root-dir read failed — refusing"]);
        return;
    }
    let mut off = 0u64;
    let mut hello_ino: u32 = 0;
    while off + 8 <= u64::from(rsize).min(1024) {
        let ino = crate::memops::read_u32(data + off);
        let rec = crate::virtio::read_u16_pa(data + off + 4);
        let nlen = crate::virtio::read_u8_pa(data + off + 6) as u64;
        if rec == 0 {
            break;
        }
        if nlen == 9 && ino != 0 {
            let mut name = [0u8; 9];
            for i in 0..9u64 {
                name[i as usize] = crate::virtio::read_u8_pa(data + off + 8 + i);
            }
            if &name == b"hello.txt" {
                hello_ino = ino;
            }
        }
        off += u64::from(rec);
    }
    if hello_ino == 0 {
        line(
            out,
            &["[EXT2] hello.txt not found in the root directory — refusing"],
        );
        return;
    }
    // hello.txt's inode: at itable*1024 + (ino-1)*inode_size.
    let f_byte = u64::from(itable) * 1024 + u64::from(hello_ino - 1) * u64::from(inode_size);
    if !ahci_read_dma(abar, clb, ctba, data, f_byte / 512) {
        line(out, &["[EXT2] file-inode read failed — refusing"]);
        return;
    }
    let foff = f_byte % 512;
    let fsize = crate::memops::read_u32(data + foff + 4);
    let fblock = crate::memops::read_u32(data + foff + 40);
    if !ahci_read_dma(abar, clb, ctba, data, u64::from(fblock) * 2) {
        line(out, &["[EXT2] file-data read failed — refusing"]);
        return;
    }
    let n = u64::from(fsize).min(24);
    let mut content = [0u8; 24];
    for i in 0..n {
        let b = crate::virtio::read_u8_pa(data + i);
        content[i as usize] = if (0x20..0x7F).contains(&b) { b } else { b'.' };
    }
    let mut hn = [0u8; 20];
    line(
        out,
        &[
            "[EXT2] hello.txt (inode ",
            strutil::dec(u64::from(hello_ino), &mut hn),
            ", ",
            strutil::dec(u64::from(fsize), &mut [0u8; 20]),
            " bytes): \"",
            core::str::from_utf8(&content[..n as usize]).unwrap_or("?"),
            "\" ← read-only ext2 over AHCI",
        ],
    );
}

// ── xHCI TRB machinery (item 12, second slice): event ring + the
// No-Op command — the command-ring doorbell, CRCR advance, and the
// completion event are exactly what device enumeration rides on ──
