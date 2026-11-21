//! Read-only FAT32 over AHCI — the EFI System Partition slice
//! (the roadmap's sanctioned "FAT32 read-only later if wanted").
//!
//! Same split as ext2 (F13/ADR-0014): the transport here owns the
//! sector reads and the boot markers; EVERY structure, bound, and the
//! cluster-chain walk itself live in the policy core
//! (`aegis_os::fat32`), host-tested against the `mkfat32.py` layout
//! and a 2000-image fuzz corpus. The disk is the SAME one ext2
//! mounts — GPT partition 1 is the ext2 root, partition 2 is the
//! ESP, so the GPT layer is walked again here (three sector reads on
//! the proven port; the ext2 path is untouched).
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::strutil;
use crate::strutil::line;
use aegis_os::fat32::{Bpb, Fat32Error};

/// One-line names for the policy refusals (the markers stay honest).
fn fat32_err_name(e: &Fat32Error) -> &'static str {
    use aegis_os::fat32::Fat32Error as E;
    match e {
        E::Truncated { .. } => "truncated",
        E::BadBytesPerSector(_) => "bad bytes/sector",
        E::BadSectorsPerCluster(_) => "bad sectors/cluster",
        E::BadReserved(_) => "bad reserved sectors",
        E::BadFatCount(_) => "bad FAT count",
        E::BadFatSize(_) => "bad FAT size",
        E::BadTotalSectors(_) => "bad total sectors",
        E::Fat16Layout { .. } => "FAT12/16-shaped fields",
        E::NotFat32 { .. } => "not FAT32 by the cluster-count rule",
        E::BadRootCluster(_) => "bad root cluster",
        E::ClusterOutOfRange { .. } => "cluster out of range",
        E::BadFatEntry { .. } => "hostile FAT entry",
        E::ChainTooLong { .. } => "chain longer than the volume",
        E::ChainTooShort { .. } => "chain shorter than the file",
        E::BadDirent { .. } => "malformed dirent",
        E::ReadFailed { .. } => "sector read did not land",
    }
}

/// The FAT32 slice: mount the ESP (GPT partition 2), find HELLO.ESP
/// in the root directory, and walk its cluster chain through the
/// policy core — the head bytes come from the first cluster, the
/// tail from the last, so the marker proves every hop.
#[cfg(not(test))]
pub(crate) fn fat32_over_ahci(
    out: &mut dyn FnMut(&str),
    bus: &crate::mmio::BarMmio,
    clb: u64,
    ctba: u64,
    // The port's FIS base rides along for signature parity with
    // ext2_over_ahci (the FAT32 walk needs only the command + data
    // frames).
    _fis: u64,
    data: u64,
) {
    // Runs on the LIVE port ahci_step owns (same rule as ext2: no
    // restart, no second frame set — the re-init path is measured
    // broken on this QEMU build). One sector at a time into a stack
    // buffer the policy core slices.
    let load = |lba: u64, sec: &mut [u8; 512]| -> bool {
        if !super::ahci::ahci_read_dma(bus, clb, ctba, data, lba) {
            return false;
        }
        for (i, b) in sec.iter_mut().enumerate() {
            *b = crate::virtio::read_u8_pa(data + i as u64);
        }
        true
    };

    // ── the GPT walk, again, for partition 2 (the ESP) ──
    let mut sec = [0u8; 512];
    let mut base = None;
    if load(0, &mut sec) && aegis_os::part::is_protective_mbr(&sec) {
        let mut hsec = [0u8; 512];
        if load(1, &mut hsec) {
            match aegis_os::part::parse_gpt_header(&hsec) {
                Ok(hdr) => {
                    let stored_crc = u32::from_le_bytes([hsec[88], hsec[89], hsec[90], hsec[91]]);
                    if load(hdr.entries_lba, &mut sec) {
                        match aegis_os::part::parse_gpt_entries(&sec, &hdr, stored_crc) {
                            Ok(gpt) if gpt.count >= 2 => {
                                let p = gpt.parts[1].expect("count checked");
                                let mut b1 = [0u8; 20];
                                let mut b2 = [0u8; 20];
                                base = Some(p.first_lba);
                                line(
                                    out,
                                    &[
                                        "[FAT32] GPT partition 2 '",
                                        p.name_str(),
                                        "' LBA ",
                                        strutil::dec(p.first_lba, &mut b1),
                                        "..=",
                                        strutil::dec(p.last_lba, &mut b2),
                                        " — the ESP mounts at the partition base",
                                    ],
                                );
                            }
                            Ok(_) => line(
                                out,
                                &["[FAT32] no second partition (table valid) — refusing"],
                            ),
                            Err(e) => line(
                                out,
                                &[
                                    "[FAT32] GPT entries refused (hostile table): ",
                                    super::ext2::part_err_name(&e),
                                    " — refusing",
                                ],
                            ),
                        }
                    } else {
                        line(out, &["[FAT32] GPT entries sector did not read — refusing"]);
                    }
                }
                Err(e) => line(
                    out,
                    &[
                        "[FAT32] GPT header refused: ",
                        super::ext2::part_err_name(&e),
                        " — refusing",
                    ],
                ),
            }
        } else {
            line(out, &["[FAT32] GPT header sector did not read — refusing"]);
        }
    } else {
        line(
            out,
            &["[FAT32] no GPT on this disk — refusing (an ESP is a GPT citizen)"],
        );
    }
    let Some(base) = base else { return };

    // ── the boot sector: the policy core validates every field ──
    if !load(base, &mut sec) {
        line(
            out,
            &["[FAT32] boot-sector read did not complete — refusing"],
        );
        return;
    }
    let bpb = match Bpb::parse(&sec) {
        Ok(b) => b,
        Err(e) => {
            line(
                out,
                &[
                    "[FAT32] BPB refused by the policy core (hostile fields) — refusing: ",
                    fat32_err_name(&e),
                ],
            );
            return;
        }
    };
    let mut c1 = [0u8; 20];
    let mut c2 = [0u8; 20];
    line(
        out,
        &[
            "[FAT32] BPB ok: ",
            strutil::dec(u64::from(bpb.cluster_count), &mut c1),
            " clusters (>= 65525: FAT32 by the spec's rule), FATs ",
            strutil::dec(u64::from(bpb.fat_count), &mut [0u8; 20]),
            "x",
            strutil::dec(u64::from(bpb.fat_size), &mut c2),
            " sectors, root cluster ",
            strutil::dec(u64::from(bpb.root_cluster), &mut [0u8; 20]),
        ],
    );

    // ── the root directory (cluster 2 by the fixture's geometry) ──
    let root_lba = match bpb.cluster_lba(bpb.root_cluster) {
        Ok(l) => l,
        Err(e) => {
            line(
                out,
                &[
                    "[FAT32] root-cluster geometry refused — refusing: ",
                    fat32_err_name(&e),
                ],
            );
            return;
        }
    };
    if !load(base + root_lba, &mut sec) {
        line(
            out,
            &["[FAT32] root-directory read did not complete — refusing"],
        );
        return;
    }
    let dent = match aegis_os::fat32::find_file(&sec, b"HELLO   ESP") {
        Ok(Some(d)) => d,
        Ok(None) => {
            line(
                out,
                &["[FAT32] HELLO.ESP not found in the root directory — refusing"],
            );
            return;
        }
        Err(e) => {
            line(
                out,
                &[
                    "[FAT32] root directory malformed (hostile dirent) — refusing: ",
                    fat32_err_name(&e),
                ],
            );
            return;
        }
    };
    if dent.is_dir() {
        line(
            out,
            &["[FAT32] HELLO.ESP is a directory, not a file — refusing"],
        );
        return;
    }

    // ── the chain walk, in the policy core: the loader adds the
    // partition base, the visit captures head (first cluster) and
    // tail (last cluster) — every hop between them is proven by the
    // tail coming from a different sector than the head ──
    let mut head = [0u8; 17];
    let mut tail = [0u8; 8];
    let size = dent.size;
    let mut wl = |lba: u64, s: &mut [u8; 512]| load(base + lba, s);
    let mut visit = |idx: u32, off: u64, s: &[u8; 512]| {
        if idx == 0 {
            head.copy_from_slice(&s[..17]);
        }
        if off + 512 >= u64::from(size) {
            let end = u64::from(size) - off;
            tail.copy_from_slice(&s[end as usize - 8..end as usize]);
        }
    };
    let walked = match aegis_os::fat32::walk_file_chain(
        &bpb,
        dent.first_cluster,
        dent.size,
        &mut wl,
        &mut visit,
    ) {
        Ok(n) => n,
        Err(e) => {
            line(
                out,
                &[
                    "[FAT32] chain walk refused (hostile chain) — refusing: ",
                    fat32_err_name(&e),
                ],
            );
            return;
        }
    };
    let mut hn = [0u8; 20];
    let mut cn = [0u8; 20];
    let mut wn = [0u8; 20];
    line(
        out,
        &[
            "[FAT32] HELLO.ESP (cluster ",
            strutil::dec(u64::from(dent.first_cluster), &mut cn),
            ", ",
            strutil::dec(u64::from(dent.size), &mut hn),
            " bytes, ",
            strutil::dec(u64::from(walked), &mut wn),
            " clusters): \"",
            core::str::from_utf8(&head).unwrap_or("?"),
            "\"…\"",
            core::str::from_utf8(&tail).unwrap_or("?"),
            "\" ← read-only FAT32 over AHCI",
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::fat32_err_name;
    use aegis_os::fat32::Fat32Error as E;

    /// The marker vocabulary must name every refusal the policy core
    /// can produce — a new variant without a name fails here first.
    #[test]
    fn every_refusal_has_a_marker_name() {
        let all = [
            E::Truncated { need: 1, have: 0 },
            E::BadBytesPerSector(4096),
            E::BadSectorsPerCluster(3),
            E::BadReserved(0),
            E::BadFatCount(0),
            E::BadFatSize(0),
            E::BadTotalSectors(0),
            E::Fat16Layout {
                root_entries: 1,
                tot_sec16: 1,
                fat_size16: 1,
            },
            E::NotFat32 { clusters: 65524 },
            E::BadRootCluster(1),
            E::ClusterOutOfRange { cluster: 0, max: 0 },
            E::BadFatEntry {
                cluster: 0,
                entry: 0,
            },
            E::ChainTooLong { needed: 0, have: 0 },
            E::ChainTooShort {
                walked: 0,
                needed: 0,
            },
            E::BadDirent { off: 0 },
            E::ReadFailed { lba: 0 },
        ];
        for e in &all {
            let name = fat32_err_name(e);
            assert!(!name.is_empty());
            assert!(name.is_ascii(), "marker names stay ASCII");
        }
    }
}
