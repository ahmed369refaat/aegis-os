//! Read-only ext2 over AHCI (ADR-0014): superblock -> dirent -> file data.

use super::ahci::ahci_read_dma;
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for the ext2 slice's AHCI frames.
pub const EXT2_OWNER: u32 = 49;

/// One-line names for the policy refusals (the markers stay honest).
fn err_name(e: &aegis_os::ext2::Ext2Error) -> &'static str {
    use aegis_os::ext2::Ext2Error as E;
    match e {
        E::BadMagic(_) => "bad magic",
        E::BadInodeSize(_) => "bad inode size",
        E::BlockOutOfRange { .. } => "block out of range",
        E::InodeOutOfRange { .. } => "inode out of range",
        E::BadDirent { .. } => "malformed dirent",
        E::Truncated { .. } => "truncated",
    }
}

/// ext2 first slice: mount the SATA disk's superblock, walk the root
/// directory, read hello.txt through AHCI READ DMA.
#[cfg(not(test))]
pub(crate) fn ext2_over_ahci(
    out: &mut dyn FnMut(&str),
    bus: &crate::mmio::BarMmio,
    clb: u64,
    ctba: u64,
    fis: u64,
    data: u64,
) {
    // Runs on the LIVE port ahci_step owns — no restart, no second
    // frame set (the restart path was measured broken: even with the
    // FRE=0 rule honored, the re-issued commands complete with no
    // data on this QEMU build).
    let port = 0x100u64; // window-relative (the bus carries the ABAR base)
    let mut h = [0u8; 18];
    // F13: the on-disk bytes are hostile until the policy core
    // validates them — the transport stays here, every structure and
    // bound moves to aegis_os::ext2. One sector at a time is copied
    // into a stack buffer the parser can slice.
    let mut sec = [0u8; 512];
    let load = |lba: u64, sec: &mut [u8; 512]| -> bool {
        if !ahci_read_dma(bus, clb, ctba, data, lba) {
            return false;
        }
        for (i, b) in sec.iter_mut().enumerate() {
            *b = crate::virtio::read_u8_pa(data + i as u64);
        }
        true
    };
    // Superblock: LBA 2 (byte 1024, 1KiB blocks).
    if !load(2, &mut sec) {
        line(out, &["[EXT2] superblock read did not complete — refusing"]);
        return;
    }
    let sb = match aegis_os::ext2::Superblock::parse(&sec) {
        Ok(sb) => sb,
        Err(aegis_os::ext2::Ext2Error::BadMagic(magic)) => {
            // ADR-0016: the TFD debug read goes through the same window as
            // every other register access; a refusal is printed, never a
            // silent 0 without a note.
            use crate::mmio::MmioBus;
            let tfd = bus.read32(port + 0x20);
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
                    strutil::hex(u64::from(tfd.unwrap_or(0)), &mut h),
                    if tfd.is_none() {
                        " (read refused by the register window)"
                    } else {
                        ""
                    },
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
        Err(e) => {
            line(
                out,
                &[
                    "[EXT2] superblock refused by the policy core (hostile fields) — refusing: ",
                    err_name(&e),
                ],
            );
            return;
        }
    };
    line(
        out,
        &[
            "[EXT2] superblock ok (magic 0xef53, inode_size=",
            strutil::dec(u64::from(sb.inode_size), &mut [0u8; 20]),
            "); ",
        ],
    );
    // Group descriptor: LBA 4 (block 2), bg_inode_table u32 @+8.
    if !load(4, &mut sec) {
        line(out, &["[EXT2] group-descriptor read failed — refusing"]);
        return;
    }
    let itable = u32::from_le_bytes([sec[8], sec[9], sec[10], sec[11]]);
    // Root inode (2): the policy core owns the geometry math.
    let root_byte = match sb.inode_byte(itable, aegis_os::ext2::ROOT_INO) {
        Ok(b) => b,
        Err(e) => {
            line(
                out,
                &[
                    "[EXT2] root-inode geometry refused (hostile table) — refusing: ",
                    err_name(&e),
                ],
            );
            return;
        }
    };
    if !load(root_byte / 512, &mut sec) {
        line(out, &["[EXT2] root-inode read failed — refusing"]);
        return;
    }
    let root = match aegis_os::ext2::Inode::parse(&sec, (root_byte % 512) as usize, sb.inode_size) {
        Ok(i) => i,
        Err(e) => {
            line(
                out,
                &["[EXT2] root-inode parse refused — refusing: ", err_name(&e)],
            );
            return;
        }
    };
    if !root.is_dir() {
        let mut hm = [0u8; 18];
        line(
            out,
            &[
                "[EXT2] root inode mode 0x",
                strutil::hex(u64::from(root.mode), &mut hm),
                " not a directory — refusing",
            ],
        );
        return;
    }
    // Directory block: walk dirents, find "hello.txt" (the policy
    // core validates every record — hostile rec_len/name_len is a
    // refusal, never a skipped record).
    if root.block0 >= sb.blocks_count || !load(u64::from(root.block0) * 2, &mut sec) {
        line(
            out,
            &["[EXT2] root-dir read failed (or block out of range) — refusing"],
        );
        return;
    }
    let hello_ino = match aegis_os::ext2::find_dirent(&sec, root.size, b"hello.txt") {
        Ok(Some(ino)) => ino,
        Ok(None) => {
            line(
                out,
                &["[EXT2] hello.txt not found in the root directory — refusing"],
            );
            return;
        }
        Err(e) => {
            line(
                out,
                &[
                    "[EXT2] root directory malformed (hostile dirent) — refusing: ",
                    err_name(&e),
                ],
            );
            return;
        }
    };
    // hello.txt's inode.
    let f_byte = match sb.inode_byte(itable, hello_ino) {
        Ok(b) => b,
        Err(e) => {
            line(
                out,
                &[
                    "[EXT2] file-inode geometry refused — refusing: ",
                    err_name(&e),
                ],
            );
            return;
        }
    };
    if !load(f_byte / 512, &mut sec) {
        line(out, &["[EXT2] file-inode read failed — refusing"]);
        return;
    }
    let fnode = match aegis_os::ext2::Inode::parse(&sec, (f_byte % 512) as usize, sb.inode_size) {
        Ok(i) => i,
        Err(e) => {
            line(
                out,
                &["[EXT2] file-inode parse refused — refusing: ", err_name(&e)],
            );
            return;
        }
    };
    let fsize = fnode.size;
    if fnode.block0 >= sb.blocks_count || !load(u64::from(fnode.block0) * 2, &mut sec) {
        line(
            out,
            &["[EXT2] file-data read failed (or block out of range) — refusing"],
        );
        return;
    }
    let n = u64::from(fsize).min(24);
    let mut content = [0u8; 24];
    for i in 0..n {
        let b = sec[i as usize];
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
