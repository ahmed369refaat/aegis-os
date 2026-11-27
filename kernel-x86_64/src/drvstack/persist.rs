//! The persistence lane (Phase 6 S5 — the M3 exit criterion): files
//! that survive the reboot.
//!
//! A SECOND virtio-blk session — the disk BEHIND a root port, not
//! the one on bus 0 that virtio_step's demo and enforcement probe
//! own — reads the whole mkext2-rw image into kernel pool frames.
//! The ext2 write path (S4) runs on it through the `ImageStore`
//! impl over PA accessors: no contiguous buffer, no new unsafe
//! (drvstack lives outside the allowlist).
//!
//! ONE branch, no build flag: `persist.txt` absent → this is boot 1,
//! create it, round-trip it through the read-only parser IN RAM, and
//! flush the image back; present → this is boot 2, verify it
//! byte-for-byte and flush NOTHING (nothing changed). The lane boots
//! the same image twice and greps `PERSIST:WRITTEN` then
//! `PERSIST:VERIFIED` — that pair is the criterion.
//!
//! The verified content is then imported into THIS boot's VFS tree
//! through the live syscall path (the supervisor pattern: uid 0
//! prepares, then dies) — the file the previous boot wrote becomes a
//! node this boot's shell story can see.

// Host-test builds compile this module without its boot-only step;
// its imports stay (used by the boot build).
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;
use aegis_os::ext2::ImageStore as _;

/// The pool owner tag for the persist image frames and the session's
/// rings — the ledger names the M3 proof's holder.
pub const PERSIST_OWNER: u32 = 50;

/// The mkext2-rw geometry: 128 blocks × 1 KiB = 256 sectors = 128 KiB.
const PERSIST_SECTORS: usize = 256;
/// 32 pool frames hold the image (4 KiB each).
const PERSIST_FRAMES: usize = 32;
const PERSIST_BYTES: usize = PERSIST_SECTORS * 512;

/// The file the two-boot proof lives by. One block (99 bytes) — the
/// write path's direct-block scope covers it without any head math.
const PERSIST_NAME: &[u8] = b"persist.txt";
const PERSIST_BODY: &[u8] = b"AEGIS-PERSIST-V1\nthe file that survived the reboot: written by one boot, byte-verified by the next.\n";

/// The image as the ext2 write path sees it: 32 pool frames behind
/// the same windowed contract the host tests drive over a slice.
struct PersistImage {
    frames: [u64; PERSIST_FRAMES],
}

impl aegis_os::ext2::ImageStore for PersistImage {
    fn read_at(&self, off: usize, out: &mut [u8]) -> bool {
        let Some(end) = off.checked_add(out.len()) else {
            return false;
        };
        if end > PERSIST_BYTES {
            return false;
        }
        for (i, b) in out.iter_mut().enumerate() {
            let o = off + i;
            *b = crate::virtio::read_u8_pa(self.frames[o / 4096] + (o % 4096) as u64);
        }
        true
    }
    fn write_at(&mut self, off: usize, src: &[u8]) -> bool {
        let Some(end) = off.checked_add(src.len()) else {
            return false;
        };
        if end > PERSIST_BYTES {
            return false;
        }
        for (i, b) in src.iter().enumerate() {
            let o = off + i;
            crate::virtio::write_u8_pa(self.frames[o / 4096] + (o % 4096) as u64, *b);
        }
        true
    }
}

/// Store one 8-aligned image word (both DMA copy directions are
/// 8-aligned: the data page is page-aligned, the image offset rides
/// a 512-sector boundary).
fn img_store_u64(img: &PersistImage, off: usize, w: u64) {
    let pa = img.frames[off / 4096] + (off % 4096) as u64;
    crate::memops::write_u64(pa, w);
}

/// Load one 8-aligned image word.
fn img_load_u64(img: &PersistImage, off: usize) -> u64 {
    let pa = img.frames[off / 4096] + (off % 4096) as u64;
    crate::memops::read_u64(pa)
}

/// DMA sector in: device wrote the data page; copy it into the image.
fn sector_in(img: &PersistImage, sector: usize, data_pa: u64) {
    for c in 0..64 {
        let w = crate::memops::read_u64(data_pa + (c * 8) as u64);
        img_store_u64(img, sector * 512 + c * 8, w);
    }
}

/// DMA sector out: copy from the image into the data page for BLK_T_OUT.
fn sector_out(img: &PersistImage, sector: usize, data_pa: u64) {
    for c in 0..64 {
        let w = img_load_u64(img, sector * 512 + c * 8);
        crate::memops::write_u64(data_pa + (c * 8) as u64, w);
    }
}

/// One-line names for the write path's refusals (the markers stay
/// honest).
fn werr_name(e: &aegis_os::ext2::Ext2WriteError) -> &'static str {
    use aegis_os::ext2::Ext2WriteError as E;
    match e {
        E::NoFreeInodes => "no free inodes",
        E::NoFreeBlocks => "no free blocks",
        E::DirFull => "root directory full",
        E::BadName => "bad name",
        E::TooLarge => "past the direct-block ceiling",
        E::Truncated => "truncated structure",
        E::InodeOutOfRange { .. } => "inode out of range",
    }
}

/// Walk the image through the READ-ONLY parser (the same one the
/// AHCI demo trusts) and answer: is `persist.txt` there, and if so
/// (ino, size, block0)? Err = the disk is not a parseable mkext2-rw
/// image — an honest refusal, never a guess.
fn find_persist_file(img: &PersistImage) -> Result<Option<(u32, u32, u32)>, &'static str> {
    let mut sbw = [0u8; 1024];
    if !img.read_at(1024, &mut sbw) {
        return Err("truncated superblock");
    }
    let sb = aegis_os::ext2::Superblock::parse(&sbw).map_err(|_| "bad superblock")?;
    let mut it = [0u8; 4];
    if !img.read_at(2048 + 8, &mut it) {
        return Err("truncated group descriptor");
    }
    let itable = u32::from_le_bytes(it);
    let root_byte = sb
        .inode_byte(itable, aegis_os::ext2::ROOT_INO)
        .map_err(|_| "root inode out of range")? as usize;
    let mut iw = [0u8; 1024];
    if !img.read_at(root_byte & !1023, &mut iw) {
        return Err("truncated inode table");
    }
    let root = aegis_os::ext2::Inode::parse(&iw, root_byte % 1024, sb.inode_size)
        .map_err(|_| "malformed root inode")?;
    let mut dir = [0u8; 1024];
    if !img.read_at(root.block0 as usize * 1024, &mut dir) {
        return Err("truncated root directory");
    }
    match aegis_os::ext2::find_dirent(&dir, root.size, PERSIST_NAME) {
        Err(_) => Err("malformed root directory"),
        Ok(None) => Ok(None),
        Ok(Some(ino)) => {
            let f_byte = sb
                .inode_byte(itable, ino)
                .map_err(|_| "file inode out of range")? as usize;
            if !img.read_at(f_byte & !1023, &mut iw) {
                return Err("truncated inode table");
            }
            let f = aegis_os::ext2::Inode::parse(&iw, f_byte % 1024, sb.inode_size)
                .map_err(|_| "malformed file inode")?;
            Ok(Some((ino, f.size, f.block0)))
        }
    }
}

/// Read the file body from its (single) block and compare with the
/// expected body. False = mismatch (size or bytes).
fn body_matches(img: &PersistImage, size: u32, block0: u32) -> bool {
    if size as usize != PERSIST_BODY.len() || size as usize > 1024 {
        return false;
    }
    let mut body = [0u8; 1024];
    if !img.read_at(block0 as usize * 1024, &mut body[..size as usize]) {
        return false;
    }
    body[..size as usize] == *PERSIST_BODY
}

/// The outcome the work block reports back.
enum PersistOutcome {
    /// Boot 1: created, verified in RAM, flushed to the disk.
    Written,
    /// Boot 2: the file was there and matched byte-for-byte.
    Verified,
    /// Every refusal path (already printed).
    Refused,
}

/// Phase 6 S5: the persist step — claim the root-port virtio-blk,
/// read the image, run the absent/present branch, flush when
/// mutated, and hand everything back.
#[cfg(not(test))]
pub(crate) fn persist_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &mut crate::pci::Inventory,
    domains: &mut crate::session::DomainIds,
    dmar: &aegis_os::dmar::Dmar,
) {
    use crate::virtio as v;

    // ── the persist disk is the virtio-blk BEHIND a root port ──
    // (bus != 0). The one on bus 0 belongs to virtio_step's demo and
    // its enforcement probe — the persist image must never be the
    // disk that probe writes its pattern into.
    let found = inv.devices[..inv.count]
        .iter()
        .find(|d| {
            d.vendor == 0x1AF4
                && (d.class >> 8) as u8 == 0x01
                && d.bus != 0
                && crate::pci::has_virtio_cap(d)
        })
        .copied();
    let mut pdev = match found {
        Some(d) => d,
        None => {
            line(
                out,
                &["[PERSIST] no virtio-blk behind a root port — the two-boot proof needs its own disk"],
            );
            return;
        }
    };
    let mut nb = [0u8; 20];
    let mut nd = [0u8; 20];
    line(
        out,
        &[
            "[PERSIST] second virtio-blk found: bus=",
            strutil::dec(u64::from(pdev.bus), &mut nb),
            " dev=",
            strutil::dec(u64::from(pdev.dev), &mut nd),
        ],
    );

    // ── the claim (ADR-0018): this device gets its OWN domain ──
    if matches!(broker.verdict(), aegis_os::dma::DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[PERSIST] broker verdict absent — refusing to claim"],
        );
        return;
    }
    let rmrr = dmar.rmrr_covers(0, pdev.bus, pdev.dev, pdev.func);
    match crate::pci::check_claim(&pdev, broker.verdict(), rmrr) {
        Err(e) => {
            line(
                out,
                &[
                    "[PERSIST] claim REFUSED (",
                    super::pci::describe_claim_error(e),
                    ")",
                ],
            );
            return;
        }
        Ok(()) => {
            let (bus, d, f) = (pdev.bus, pdev.dev, pdev.func);
            match domains
                .alloc()
                .map(|dom| (dom, broker.assign_device(dom, 0, bus, (d, f))))
            {
                None => {
                    line(
                        out,
                        &["[PERSIST] claim REFUSED (no free IOMMU domain — ADR-0018)"],
                    );
                    return;
                }
                Some((dom, Ok(()))) => {
                    inv.set_dom_bdf(bus, d, f, dom);
                    pdev.dom = dom;
                    let mut ndm = [0u8; 20];
                    line(
                        out,
                        &[
                            "[PERSIST] claim: bus=",
                            strutil::dec(u64::from(bus), &mut nb),
                            " dev=",
                            strutil::dec(u64::from(d), &mut nd),
                            " → dom ",
                            strutil::dec(u64::from(dom), &mut ndm),
                            " ok (broker assigned, ADR-0018)",
                        ],
                    );
                }
                Some((dom, Err(e))) => {
                    domains.release(dom);
                    line(
                        out,
                        &[
                            "[PERSIST] broker refused the assignment (",
                            super::hw_code(&e),
                            ")",
                        ],
                    );
                    return;
                }
            }
        }
    }

    // ── the handshake (virtio_step's proven sequence) ──
    let Some(caps) = v::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(&pdev, off)) else {
        line(out, &["[PERSIST] vendor caps incomplete — refusing"]);
        return;
    };
    // F9e claim order: MEMORY-SPACE now; BUS-MASTER only after the
    // broker has mapped the rings.
    crate::pci::enable_mem(&pdev);
    let resolved = match caps.resolve(&pdev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[PERSIST] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };
    let mmio = v::MmioVirtio::from_resolved(&resolved);
    mmio.set_status(0);
    let feat_low = mmio.device_features(0);
    let feat_high = mmio.device_features(1);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER);
    let negotiated = match v::negotiate_features(feat_low, feat_high) {
        Ok(n) => n,
        Err(why) => {
            line(
                out,
                &[
                    "[PERSIST] feature negotiation refused: ",
                    why,
                    " — refusing",
                ],
            );
            return;
        }
    };
    mmio.set_driver_features(0, negotiated.low);
    mmio.set_driver_features(1, negotiated.high);
    mmio.set_status(v::STATUS_ACK | v::STATUS_DRIVER | v::STATUS_FEATURES_OK);
    if mmio.status() & v::STATUS_FEATURES_OK == 0 {
        line(out, &["[PERSIST] FEATURES_OK not accepted — refusing"]);
        return;
    }
    let (qsize_raw, notify_off) = mmio.select_queue(0);
    let qsize = if qsize_raw > 256 {
        mmio.set_queue_size(256)
    } else {
        qsize_raw
    };
    if qsize == 0 || qsize > 2048 {
        line(
            out,
            &["[PERSIST] queue size out of the supported band — refusing"],
        );
        return;
    }

    // ── the image frames: pool-owned directly (the session caps at
    // 16 frames; the image needs 32 + the 5 ring frames) ──
    let mut img = PersistImage {
        frames: [0; PERSIST_FRAMES],
    };
    let mut nimg = 0usize;
    for slot in img.frames.iter_mut() {
        match pool.alloc_for(&mut k.frames, PERSIST_OWNER) {
            Ok(pa) => {
                *slot = pa;
                nimg += 1;
            }
            Err(_) => {
                let mut b = [0u8; 20];
                line(
                    out,
                    &[
                        "[PERSIST] pool exhausted at image frame ",
                        strutil::dec(nimg as u64, &mut b),
                        " — refusing",
                    ],
                );
                break;
            }
        }
    }
    if nimg == PERSIST_FRAMES {
        let mut nf = [0u8; 20];
        line(
            out,
            &[
                "[PERSIST] image frames acquired: ",
                strutil::dec(PERSIST_FRAMES as u64, &mut nf),
                " (128 KiB, PERSIST_OWNER in the ledger)",
            ],
        );
    }

    // ── the session block: everything that borrows k/pool/broker
    // lives HERE so the image frames can go home after it ──
    let outcome = if nimg == PERSIST_FRAMES {
        let mut session = crate::session::DriverSession::new(
            k,
            pool,
            broker,
            Some(&pdev),
            PERSIST_OWNER,
            pdev.dom,
            false,
            "[PERSIST] teardown",
            "",
        );
        let work = 'work: {
            let mut frames = [0u64; 5];
            for (i, slot) in frames.iter_mut().enumerate() {
                match session.frame() {
                    Ok(pa) => *slot = pa,
                    Err(_) => {
                        let mut b = [0u8; 20];
                        line(
                            out,
                            &[
                                "[PERSIST] pool exhausted at ring frame ",
                                strutil::dec(i as u64, &mut b),
                                " — refusing",
                            ],
                        );
                        break 'work PersistOutcome::Refused;
                    }
                }
            }
            let [desc_pa, avail_pa, used_pa, ctrl_pa, data_pa] = frames;
            let mut cookies = [0u64; 5];
            for (i, &pa) in frames.iter().enumerate() {
                match session.map(pa) {
                    Some(cookie) => cookies[i] = cookie,
                    None => {
                        let mut b = [0u8; 20];
                        line(
                            out,
                            &[
                                "[PERSIST] broker refused ring frame ",
                                strutil::dec(i as u64, &mut b),
                                " — refusing",
                            ],
                        );
                        break 'work PersistOutcome::Refused;
                    }
                }
            }
            // F9e: rings mapped — NOW the device may DMA.
            crate::pci::enable_bus_master(&pdev);
            mmio.setup_queue(desc_pa, avail_pa, used_pa);
            mmio.set_status(v::live_status());
            if mmio.status() != v::live_status() {
                line(out, &["[PERSIST] DRIVER_OK path failed — refusing"]);
                break 'work PersistOutcome::Refused;
            }
            let capacity = mmio.capacity_sectors();
            if (capacity as usize) < PERSIST_SECTORS {
                let mut c = [0u8; 20];
                line(
                    out,
                    &[
                        "[PERSIST] disk too small (",
                        strutil::dec(capacity, &mut c),
                        " sectors < 256) — this is not the mkext2-rw image",
                    ],
                );
                break 'work PersistOutcome::Refused;
            }
            let queue = super::vblk::VblkQueue {
                qsize,
                notify_off,
                desc_pa,
                avail_pa,
                used_pa,
                ctrl_pa,
                cookies: [cookies[0], cookies[1], cookies[2], cookies[3]],
            };
            let mut n = [0u8; 20];
            line(
                out,
                &[
                    "[PERSIST] session up: rings broker-mapped, capacity=",
                    strutil::dec(capacity, &mut n),
                    " sectors",
                ],
            );

            // ── read the whole image in (256 DMA-ins, u64 copies) ──
            for sector in 0..PERSIST_SECTORS {
                let want = super::vblk::submit(&queue, data_pa, sector as u64, v::BLK_T_IN);
                if !mmio.notify(0, notify_off) {
                    line(out, &["[PERSIST] notify refused — refusing (F5)"]);
                    break 'work PersistOutcome::Refused;
                }
                match super::vblk::poll_used(&queue, want) {
                    super::vblk::UsedOutcome::Timeout => {
                        let mut b = [0u8; 20];
                        line(
                            out,
                            &[
                                "[PERSIST] read FAILED at sector ",
                                strutil::dec(sector as u64, &mut b),
                                " — refusing",
                            ],
                        );
                        break 'work PersistOutcome::Refused;
                    }
                    super::vblk::UsedOutcome::Poisoned(why) => {
                        line(out, &["[PERSIST] used-ring POISON: ", why, " — refusing"]);
                        break 'work PersistOutcome::Refused;
                    }
                    super::vblk::UsedOutcome::Completed => {}
                }
                if v::read_u8_pa(ctrl_pa + 512) != v::BLK_S_OK {
                    let mut b = [0u8; 20];
                    line(
                        out,
                        &[
                            "[PERSIST] read status not OK at sector ",
                            strutil::dec(sector as u64, &mut b),
                            " — refusing",
                        ],
                    );
                    break 'work PersistOutcome::Refused;
                }
                sector_in(&img, sector, data_pa);
            }
            let mut ns = [0u8; 20];
            line(
                out,
                &[
                    "[PERSIST] image read: ",
                    strutil::dec(PERSIST_SECTORS as u64, &mut ns),
                    " sectors into ",
                    strutil::dec(PERSIST_FRAMES as u64, &mut n),
                    " frames",
                ],
            );

            // ── THE branch: absent → write; present → verify ──
            match find_persist_file(&img) {
                Err(why) => {
                    line(
                        out,
                        &[
                            "[PERSIST] image refused (",
                            why,
                            ") — this disk is not the mkext2-rw image; nothing to prove",
                        ],
                    );
                    PersistOutcome::Refused
                }
                Ok(None) => {
                    // Boot 1: the write path runs.
                    let ino = match aegis_os::ext2::create_file(&mut img, PERSIST_NAME) {
                        Ok(i) => i,
                        Err(e) => {
                            line(
                                out,
                                &["[PERSIST] create_file refused (", werr_name(&e), ")"],
                            );
                            break 'work PersistOutcome::Refused;
                        }
                    };
                    if let Err(e) = aegis_os::ext2::write_file(&mut img, ino, 0, PERSIST_BODY) {
                        line(out, &["[PERSIST] write_file refused (", werr_name(&e), ")"]);
                        break 'work PersistOutcome::Refused;
                    }
                    // Round-trip IN RAM before any disk byte moves.
                    match find_persist_file(&img) {
                        Ok(Some((vino, vsize, vblock)))
                            if vino == ino && body_matches(&img, vsize, vblock) => {}
                        _ => {
                            line(
                                out,
                                &["[PERSIST] in-RAM round trip FAILED — NOT flushing (INVESTIGATE)"],
                            );
                            break 'work PersistOutcome::Refused;
                        }
                    }
                    // Flush the mutated image back (whole-image: the
                    // writer reports no dirty map — 256 sectors is
                    // the honest bound).
                    for sector in 0..PERSIST_SECTORS {
                        sector_out(&img, sector, data_pa);
                        let want =
                            super::vblk::submit(&queue, data_pa, sector as u64, v::BLK_T_OUT);
                        if !mmio.notify(0, notify_off) {
                            line(out, &["[PERSIST] flush notify refused — INVESTIGATE (F5)"]);
                            break 'work PersistOutcome::Refused;
                        }
                        match super::vblk::poll_used(&queue, want) {
                            super::vblk::UsedOutcome::Timeout => {
                                let mut b = [0u8; 20];
                                line(
                                    out,
                                    &[
                                        "[PERSIST] flush FAILED at sector ",
                                        strutil::dec(sector as u64, &mut b),
                                        " — INVESTIGATE",
                                    ],
                                );
                                break 'work PersistOutcome::Refused;
                            }
                            super::vblk::UsedOutcome::Poisoned(why) => {
                                line(out, &["[PERSIST] flush POISON: ", why, " — INVESTIGATE"]);
                                break 'work PersistOutcome::Refused;
                            }
                            super::vblk::UsedOutcome::Completed => {}
                        }
                        if v::read_u8_pa(ctrl_pa + 512) != v::BLK_S_OK {
                            let mut b = [0u8; 20];
                            line(
                                out,
                                &[
                                    "[PERSIST] flush status not OK at sector ",
                                    strutil::dec(sector as u64, &mut b),
                                    " — INVESTIGATE",
                                ],
                            );
                            break 'work PersistOutcome::Refused;
                        }
                    }
                    let mut ni = [0u8; 20];
                    let mut sz = [0u8; 20];
                    line(
                        out,
                        &[
                            "[PERSIST] PERSIST:WRITTEN: persist.txt (inode ",
                            strutil::dec(u64::from(ino), &mut ni),
                            ", ",
                            strutil::dec(PERSIST_BODY.len() as u64, &mut sz),
                            " bytes, image flushed) — the next boot must read it back",
                        ],
                    );
                    PersistOutcome::Written
                }
                Ok(Some((_ino, size, block0))) => {
                    // Boot 2: byte-for-byte, and flush NOTHING (the
                    // image never changed this boot).
                    if body_matches(&img, size, block0) {
                        let mut sz = [0u8; 20];
                        line(
                            out,
                            &[
                                "[PERSIST] PERSIST:VERIFIED: persist.txt byte-exact (",
                                strutil::dec(size as u64, &mut sz),
                                " bytes, nothing flushed — the file survived the reboot)",
                            ],
                        );
                        PersistOutcome::Verified
                    } else {
                        line(
                            out,
                            &["[PERSIST] PERSIST:MISMATCH: persist.txt differs — INVESTIGATE"],
                        );
                        PersistOutcome::Refused
                    }
                }
            }
        };
        session.close(out);
        work
    } else {
        PersistOutcome::Refused
    };

    // ── the image frames go home (scrubbed by pool.free) ──
    for pa in img.frames.iter().take(nimg) {
        let _ = pool.free(&mut k.frames, *pa, PERSIST_OWNER);
    }
    let mut nfr = [0u8; 20];
    line(
        out,
        &[
            "[PERSIST] image frames freed: ",
            strutil::dec(nimg as u64, &mut nfr),
        ],
    );

    // ── the VFS import (only on a proven image): the file becomes a
    // node in THIS boot's tree, through the live syscall path ──
    if matches!(outcome, PersistOutcome::Written | PersistOutcome::Verified) {
        vfs_import(k, out);
    }
}

/// The supervisor pattern (kmain's boot-tree seeding): uid 0 opens,
/// writes, closes; a second open reads it back through the VFS.
#[cfg(not(test))]
fn vfs_import<const N: usize>(k: &mut aegis_os::Kernel<N>, out: &mut dyn FnMut(&str)) {
    const SUP: u32 = 50;
    use aegis_os::sys::{SysRequest, SysValue};
    if !matches!(
        k.create_domain_with(SUP, aegis_os::profile::service_profile(), 0, 0, 0),
        Ok(())
    ) {
        line(out, &["[PERSIST] vfs import: supervisor domain refused"]);
        return;
    }
    let ok = (|| -> bool {
        // write it
        let fd = match k.syscall(
            SUP,
            SysRequest::Open {
                path: "/persist.txt",
                mode: aegis_os::vfs::Mode(0o644),
                create: true,
                read: false,
                write: true,
                truncate: true,
                excl: false,
            },
        ) {
            Ok(SysValue::Fd(fd)) => fd,
            _ => return false,
        };
        let wrote = matches!(
            k.syscall(SUP, SysRequest::Write { fd, bytes: PERSIST_BODY }),
            Ok(SysValue::Count(n)) if n == PERSIST_BODY.len()
        );
        let _ = k.syscall(SUP, SysRequest::Close { fd });
        if !wrote {
            return false;
        }
        // read it back through a fresh descriptor
        let fd2 = match k.syscall(
            SUP,
            SysRequest::Open {
                path: "/persist.txt",
                mode: aegis_os::vfs::Mode(0o644),
                create: false,
                read: true,
                write: false,
                truncate: false,
                excl: false,
            },
        ) {
            Ok(SysValue::Fd(fd)) => fd,
            _ => return false,
        };
        let mut rb = [0u8; 256];
        let read_back = match k.syscall(
            SUP,
            SysRequest::Read {
                fd: fd2,
                buf: &mut rb,
            },
        ) {
            Ok(SysValue::Count(n)) => rb[..n] == *PERSIST_BODY,
            _ => false,
        };
        let _ = k.syscall(SUP, SysRequest::Close { fd: fd2 });
        read_back
    })();
    let _ = k.destroy_domain(SUP);
    if ok {
        let mut nb = [0u8; 20];
        line(
            out,
            &[
                "[PERSIST] vfs: /persist.txt imported and read back byte-exact (",
                strutil::dec(PERSIST_BODY.len() as u64, &mut nb),
                " bytes through the live syscall path)",
            ],
        );
    } else {
        line(out, &["[PERSIST] vfs import FAILED — INVESTIGATE"]);
    }
}
