//! Read-only FAT32 parsing — the policy core for the EFI System
//! Partition (the roadmap's sanctioned "FAT32 read-only later if
//! wanted", riding the same F13 discipline as ext2/part: the bytes
//! arrive from a DISK, every field is hostile until validated, the
//! parser is pure — byte slices in, results out, no panics, no
//! allocation — so the host tests run the identical code against the
//! `mkfat32.py` layout and a deterministic fuzz corpus).
//!
//! What the kernel keeps: the sector transport (AHCI reads), the boot
//! markers, and the decision to refuse. What lives here: the BPB
//! validation, the FAT type determination (an honest FAT32 needs
//! ≥ 65525 clusters — a smaller count is a FAT12/FAT16 volume and is
//! REFUSED as `NotFat32`, never silently misread), the cluster-chain
//! walk with its termination proof, and every dirent bound.
//!
//! Honest scope, stated: 512-byte sectors only (the transport's
//! width — other widths refuse with `BadBytesPerSector`); 8.3 names
//! only (long-name records are legal FAT and are skipped, not
//! interpreted); one FAT inspected (the mirror copy is the writer's
//! consistency domain); no FSInfo consumption (free-space accounting
//! is a writer concern). The BPB's `total_sectors` claim is checked
//! for internal consistency only — the medium's true size is
//! enforced by the transport (a read past the end is `ReadFailed`).

/// The minimum cluster count that makes a volume FAT32 by the spec's
/// determination rule (Microsoft EFI FAT32 spec §FAT Type
/// Determination: below 65525 the volume is FAT12/FAT16-shaped).
pub const MIN_FAT32_CLUSTERS: u32 = 65_525;

/// The last valid FAT entry value (anything ≥ this is end-of-chain).
pub const EOC_MIN: u32 = 0x0FFF_FFF8;

/// Every way a hostile volume is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fat32Error {
    /// A slice shorter than the structure being parsed.
    Truncated { need: usize, have: usize },
    /// `bytes_per_sector` is not 512 (the transport's honest width).
    BadBytesPerSector(u16),
    /// `sectors_per_cluster` is not a power of two in 1..=128.
    BadSectorsPerCluster(u8),
    /// `reserved_sectors` is zero.
    BadReserved(u16),
    /// `fat_count` is not 1 or 2.
    BadFatCount(u8),
    /// `fat_size32` is zero, or the FAT region swallows the volume.
    BadFatSize(u32),
    /// `total_sectors32` leaves no data region at all.
    BadTotalSectors(u32),
    /// FAT12/FAT16-shaped BPB fields (nonzero root_entries /
    /// tot_sec16 / fat_size16 — a FAT32 volume pins all three to 0).
    Fat16Layout {
        root_entries: u16,
        tot_sec16: u16,
        fat_size16: u16,
    },
    /// The cluster count is below the FAT32 minimum: this volume is
    /// FAT12/FAT16 by the spec's own determination (carries the count).
    NotFat32 { clusters: u32 },
    /// `root_cluster` is 0 or 1 (reserved cluster numbers).
    BadRootCluster(u32),
    /// A cluster number outside 2..=count+1 (carries the bound hit).
    ClusterOutOfRange { cluster: u32, max: u32 },
    /// A FAT entry value that cannot continue an allocated chain:
    /// free (0), reserved (1), bad (0x0FFFFFF7), or past the volume.
    BadFatEntry { cluster: u32, entry: u32 },
    /// The file's byte length needs more clusters than the volume has.
    ChainTooLong { needed: u32, have: u32 },
    /// The chain hit end-of-chain before covering the dirent's length.
    ChainTooShort { walked: u32, needed: u32 },
    /// A dirent whose declared size has no cluster behind it (size > 0
    /// with first cluster 0 or 1).
    BadDirent { off: usize },
    /// The transport's sector load failed (the medium's honest bound).
    ReadFailed { lba: u64 },
}

/// The validated BPB — every field the walk consumes, with the
/// region LBAs precomputed (partition-relative; the transport adds
/// the partition base).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bpb {
    pub sectors_per_cluster: u8,
    pub fat_count: u8,
    pub fat_size: u32,
    pub total_sectors: u32,
    pub root_cluster: u32,
    /// Data clusters available (valid cluster numbers: 2..=count+1).
    pub cluster_count: u32,
    /// Partition-relative LBA of FAT #0.
    pub fat_lba: u64,
    /// Partition-relative LBA of cluster 2 (the data region).
    pub data_lba: u64,
}

impl Bpb {
    /// Parse the 512-byte boot sector (BPB). Offsets per the spec:
    /// bps@11, spc@13, reserved@14, fats@16, root_entries@17,
    /// tot_sec16@19, fat_size16@22, tot_sec32@32, fat_size32@36,
    /// root_cluster@44.
    pub fn parse(bs: &[u8]) -> Result<Bpb, Fat32Error> {
        if bs.len() < 512 {
            return Err(Fat32Error::Truncated {
                need: 512,
                have: bs.len(),
            });
        }
        let r16 = |o: usize| u16::from_le_bytes([bs[o], bs[o + 1]]);
        let r32 = |o: usize| u32::from_le_bytes([bs[o], bs[o + 1], bs[o + 2], bs[o + 3]]);
        if r16(11) != 512 {
            return Err(Fat32Error::BadBytesPerSector(r16(11)));
        }
        let spc = bs[13];
        if spc == 0 || spc > 128 || !spc.is_power_of_two() {
            return Err(Fat32Error::BadSectorsPerCluster(spc));
        }
        let reserved = r16(14);
        if reserved == 0 {
            return Err(Fat32Error::BadReserved(0));
        }
        let fat_count = bs[16];
        if !(1..=2).contains(&fat_count) {
            return Err(Fat32Error::BadFatCount(fat_count));
        }
        // FAT32 pins the three FAT12/16 fields to zero — a nonzero
        // one means the volume is not what the driver claims to read.
        let (root_entries, tot_sec16, fat_size16) = (r16(17), r16(19), r16(22));
        if root_entries != 0 || tot_sec16 != 0 || fat_size16 != 0 {
            return Err(Fat32Error::Fat16Layout {
                root_entries,
                tot_sec16,
                fat_size16,
            });
        }
        let fat_size = r32(36);
        if fat_size == 0 {
            return Err(Fat32Error::BadFatSize(0));
        }
        let total_sectors = r32(32);
        // reserved + fats×fat_size must leave at least one cluster.
        let meta = u64::from(reserved) + u64::from(fat_count) * u64::from(fat_size);
        let data_sectors = u64::from(total_sectors)
            .checked_sub(meta)
            .ok_or(Fat32Error::BadTotalSectors(total_sectors))?;
        let clusters = (data_sectors / u64::from(spc)) as u32;
        if clusters < MIN_FAT32_CLUSTERS {
            return Err(Fat32Error::NotFat32 { clusters });
        }
        let root_cluster = r32(44);
        if root_cluster < 2 {
            return Err(Fat32Error::BadRootCluster(root_cluster));
        }
        Ok(Bpb {
            sectors_per_cluster: spc,
            fat_count,
            fat_size,
            total_sectors,
            root_cluster,
            cluster_count: clusters,
            fat_lba: u64::from(reserved),
            data_lba: meta,
        })
    }

    /// The partition-relative LBA of cluster `c` (2..=count+1).
    /// Cluster N sits at data_lba + (N-2)·spc — checked.
    pub fn cluster_lba(&self, c: u32) -> Result<u64, Fat32Error> {
        if c < 2 || c > self.cluster_count + 1 {
            return Err(Fat32Error::ClusterOutOfRange {
                cluster: c,
                max: self.cluster_count + 1,
            });
        }
        let rel = u64::from(c - 2) * u64::from(self.sectors_per_cluster);
        Ok(self
            .data_lba
            .checked_add(rel)
            .ok_or(Fat32Error::ClusterOutOfRange {
                cluster: c,
                max: self.cluster_count + 1,
            })?)
    }

    /// The partition-relative LBA of the FAT sector holding cluster
    /// `c`'s entry (128 entries per 512-byte sector).
    #[must_use]
    pub fn fat_sector_lba(&self, c: u32) -> u64 {
        self.fat_lba + u64::from(c / 128)
    }
}

/// Read cluster `c`'s entry out of its (loaded) FAT sector.
pub fn fat_entry(fat_sec: &[u8; 512], c: u32) -> Result<u32, Fat32Error> {
    let off = (c % 128) as usize * 4;
    if off + 4 > fat_sec.len() {
        return Err(Fat32Error::Truncated {
            need: off + 4,
            have: fat_sec.len(),
        });
    }
    Ok(u32::from_le_bytes([
        fat_sec[off],
        fat_sec[off + 1],
        fat_sec[off + 2],
        fat_sec[off + 3],
    ]))
}

/// Classify a FAT entry for an ALLOCATED chain: `Ok(None)` is
/// end-of-chain, `Ok(Some(next))` follows, everything else refuses
/// (free/reserved/bad-cluster values, or a cluster past the volume).
pub fn validate_entry(
    cluster: u32,
    entry: u32,
    max_cluster: u32,
) -> Result<Option<u32>, Fat32Error> {
    if entry >= EOC_MIN {
        return Ok(None); // end-of-chain (0x0FFFFFF8..=0xFFFFFFFF)
    }
    if (2..=max_cluster).contains(&entry) {
        return Ok(Some(entry));
    }
    // 0 (free), 1 (reserved), 0x0FFFFFF7 (bad), the reserved gap
    // 0x0FFFFFF0..=0x0FFFFFF6, and anything past the volume's max.
    Err(Fat32Error::BadFatEntry { cluster, entry })
}

/// A directory record the walk matched (8.3 names only; long-name
/// records are skipped unread — stated scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dirent {
    pub first_cluster: u32,
    pub size: u32,
    pub attr: u8,
}

impl Dirent {
    /// Directory bit of `attr` (0x10).
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }
}

/// Walk 32-byte dirent records looking for `name` (the 11-byte 8.3
/// name, space-padded: `b"HELLO   ESP"`). `Ok(None)` when the
/// directory simply does not hold it; an error only when the
/// directory ITSELF is malformed (a size>0 record with no cluster
/// behind it is a refusal, never a skipped record). Deleted (0xE5),
/// long-name (attr 0x0F), and volume-label (attr 0x08) records are
/// skipped per the format.
pub fn find_file(dir: &[u8], name: &[u8; 11]) -> Result<Option<Dirent>, Fat32Error> {
    let mut off = 0usize;
    while off + 32 <= dir.len() {
        let rec = &dir[off..off + 32];
        if rec[0] == 0x00 {
            return Ok(None); // the format's end-of-directory marker
        }
        let attr = rec[11];
        if rec[0] != 0xE5 && attr != 0x0F && attr & 0x08 == 0 && &rec[0..11] == name {
            let hi = u16::from_le_bytes([rec[20], rec[21]]) as u32;
            let lo = u16::from_le_bytes([rec[26], rec[27]]) as u32;
            let first_cluster = lo | (hi << 16);
            let size = u32::from_le_bytes([rec[28], rec[29], rec[30], rec[31]]);
            if size > 0 && first_cluster < 2 {
                return Err(Fat32Error::BadDirent { off });
            }
            return Ok(Some(Dirent {
                first_cluster,
                size,
                attr,
            }));
        }
        off += 32;
    }
    Ok(None)
}

/// Walk a file's cluster chain, visiting every cluster in file
/// order. ALL the security-relevant logic lives here, tested on the
/// host: the loader closure is the transport's only job (it adds the
/// partition base and reads one sector; `false` = the medium's
/// honest bound → `ReadFailed`), and `visit(cluster_idx, file_off,
/// &sector)` sees each 512-byte sector.
///
/// Termination is structural, not budgetary: each iteration covers
/// exactly one cluster's bytes, so the walk ends after
/// ceil(len / cluster_bytes) iterations — a loop-back FAT entry just
/// re-reads a bounded cluster and still terminates. A chain that
/// ends before the dirent's length is covered refuses with
/// `ChainTooShort`; a length the whole volume cannot hold refuses
/// up front with `ChainTooLong`.
pub fn walk_file_chain(
    bpb: &Bpb,
    first_cluster: u32,
    len: u32,
    load: &mut dyn FnMut(u64, &mut [u8; 512]) -> bool,
    visit: &mut dyn FnMut(u32, u64, &[u8; 512]),
) -> Result<u32, Fat32Error> {
    if len == 0 {
        return Ok(0);
    }
    let cluster_bytes = u64::from(bpb.sectors_per_cluster) * 512;
    let needed = ((u64::from(len) + cluster_bytes - 1) / cluster_bytes) as u32;
    if needed > bpb.cluster_count {
        return Err(Fat32Error::ChainTooLong {
            needed,
            have: bpb.cluster_count,
        });
    }
    let mut cluster = first_cluster;
    // The entry cluster gets the explicit range check (FAT entries
    // are validated by validate_entry on every hop).
    let first_lba = bpb.cluster_lba(cluster)?;
    let mut walked = 0u32;
    let mut file_off = 0u64;
    let mut sec = [0u8; 512];
    loop {
        let lba = if walked == 0 {
            first_lba
        } else {
            bpb.cluster_lba(cluster)?
        };
        if !load(lba, &mut sec) {
            return Err(Fat32Error::ReadFailed { lba });
        }
        visit(walked, file_off, &sec);
        walked += 1;
        file_off += cluster_bytes;
        if file_off >= u64::from(len) {
            return Ok(walked);
        }
        // Follow the chain: the FAT sector for `cluster`, then its entry.
        let flba = bpb.fat_sector_lba(cluster);
        let mut fsec = [0u8; 512];
        if !load(flba, &mut fsec) {
            return Err(Fat32Error::ReadFailed { lba: flba });
        }
        let entry = fat_entry(&fsec, cluster)?;
        match validate_entry(cluster, entry, bpb.cluster_count + 1)? {
            None => {
                return Err(Fat32Error::ChainTooShort { walked, needed });
            }
            Some(next) => cluster = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mkfat32.py layout, mirrored: reserved 32 sectors (boot@0,
    /// FSInfo@1, backup boot@6), FAT#0@32 and FAT#1@548 (516 sectors
    /// each), data@1064; 65600 declared clusters (tot_sec32 66664);
    /// root dir = cluster 2; HELLO.ESP = clusters 3→4→5, 1200 bytes.
    /// The fixture Vec carries only the sectors the walk reads — the
    /// declared volume is 34 MiB, the medium's true bound is the
    /// loader's job (exactly the transport's contract).
    fn build_image() -> Vec<u8> {
        let mut img = vec![0u8; 1068 * 512];
        let put = |img: &mut Vec<u8>, sec: usize, bytes: &[u8]| {
            let off = sec * 512;
            img[off..off + bytes.len()].copy_from_slice(bytes);
        };
        // The boot sector (BPB).
        let mut bs = [0u8; 512];
        bs[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
        bs[13] = 1; // sectors/cluster
        bs[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved
        bs[16] = 2; // fats
        bs[21] = 0xF8; // media
        bs[32..36].copy_from_slice(&66_664u32.to_le_bytes()); // tot_sec32
        bs[36..40].copy_from_slice(&516u32.to_le_bytes()); // fat_size32
        bs[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        bs[510] = 0x55;
        bs[511] = 0xAA;
        put(&mut img, 0, &bs);
        // FAT#0 (sector 32): [0]=media/EOC, [1]=EOC, [2]=EOC (root),
        // [3]=4, [4]=5, [5]=EOC.
        let mut fat = [0u8; 512];
        for (c, v) in [(0u32, 0x0FFF_FFF8u32), (1, 0xFFFF_FFFF), (2, 0x0FFF_FFF8)] {
            fat[c as usize * 4..c as usize * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        for (c, v) in [(3u32, 4u32), (4, 5), (5, 0x0FFF_FFF8)] {
            fat[c as usize * 4..c as usize * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        put(&mut img, 32, &fat);
        // Root dir (cluster 2 = sector 1064): HELLO.ESP, attr 0x20,
        // first cluster 3, size 1200; then the end marker.
        let mut d = [0u8; 512];
        d[0..11].copy_from_slice(b"HELLO   ESP");
        d[11] = 0x20;
        d[20..22].copy_from_slice(&0u16.to_le_bytes()); // cluster hi
        d[26..28].copy_from_slice(&3u16.to_le_bytes()); // cluster lo
        d[28..32].copy_from_slice(&1200u32.to_le_bytes());
        d[32] = 0x00; // end of directory
        put(&mut img, 1064, &d);
        // The file: clusters 3,4,5 = sectors 1065..1067. The head
        // marker is 17 bytes ("HEAD:AEGIS-FAT32:"), the tail 8.
        let mut content = Vec::with_capacity(1200);
        content.extend_from_slice(b"HEAD:AEGIS-FAT32:");
        content.extend(std::iter::repeat(b'0').take(1200 - 17 - 8));
        content.extend_from_slice(b":TAIL-OK");
        assert_eq!(content.len(), 1200);
        put(&mut img, 1065, &content[..512]);
        put(&mut img, 1066, &content[512..1024]);
        put(&mut img, 1067, &content[1024..]);
        img
    }

    fn loader<'a>(img: &'a [u8]) -> impl FnMut(u64, &mut [u8; 512]) -> bool + 'a {
        |lba: u64, sec: &mut [u8; 512]| {
            let off = lba as usize * 512;
            if off + 512 > img.len() {
                return false;
            }
            sec.copy_from_slice(&img[off..off + 512]);
            true
        }
    }

    #[test]
    fn the_real_image_parses_end_to_end() {
        let img = build_image();
        let bpb = Bpb::parse(&img[0..512]).unwrap();
        assert_eq!(bpb.sectors_per_cluster, 1);
        assert_eq!(bpb.fat_count, 2);
        assert_eq!(bpb.fat_size, 516);
        assert_eq!(bpb.cluster_count, 65_600);
        assert_eq!(bpb.fat_lba, 32);
        assert_eq!(bpb.data_lba, 1064);
        assert_eq!(bpb.root_cluster, 2);
        // The root directory (cluster 2).
        let d = find_file(&img[1064 * 512..1065 * 512], b"HELLO   ESP")
            .unwrap()
            .expect("HELLO.ESP is in the root dir");
        assert_eq!(d.first_cluster, 3);
        assert_eq!(d.size, 1200);
        assert!(!d.is_dir());
        // The chain walk: head 16 bytes from cluster 0, tail 8 from
        // the last visited cluster — the exact kernel capture.
        let mut head = [0u8; 17];
        let mut tail = [0u8; 8];
        let mut visits = 0u32;
        let mut l = loader(&img);
        let walked = walk_file_chain(
            &bpb,
            d.first_cluster,
            d.size,
            &mut l,
            &mut |idx: u32, off: u64, sec: &[u8; 512]| {
                if idx == 0 {
                    head.copy_from_slice(&sec[..17]);
                }
                if off + 512 >= u64::from(d.size) {
                    let end = d.size as u64 - off;
                    tail.copy_from_slice(&sec[end as usize - 8..end as usize]);
                }
                visits += 1;
            },
        )
        .unwrap();
        assert_eq!(walked, 3);
        assert_eq!(visits, 3);
        assert_eq!(&head, b"HEAD:AEGIS-FAT32:");
        assert_eq!(&tail, b":TAIL-OK");
    }

    #[test]
    fn the_fat32_boundary_is_honest() {
        let img = build_image();
        // Exactly at the minimum: 65525 clusters is FAT32 (tot_sec32
        // = reserved 32 + 2 FATs × 516 + 65525 data sectors).
        let mut m = img.clone();
        let total = 32u32 + 2 * 516 + 65_525; // 66_589
        m[32..36].copy_from_slice(&total.to_le_bytes());
        assert!(Bpb::parse(&m[0..512]).is_ok());
        // One cluster short: FAT16 by the spec's own rule — refused.
        let total16 = 32u32 + 2 * 516 + 65_524;
        m[32..36].copy_from_slice(&total16.to_le_bytes());
        assert_eq!(
            Bpb::parse(&m[0..512]),
            Err(Fat32Error::NotFat32 { clusters: 65_524 })
        );
    }

    #[test]
    fn hostile_bpbs_are_refused() {
        let img = build_image();
        let mut m = |f: fn(&mut Vec<u8>)| {
            let mut img = img.clone();
            f(&mut img);
            Bpb::parse(&img[0..512])
        };
        assert!(matches!(
            m(|i| i[11..13].copy_from_slice(&4096u16.to_le_bytes())),
            Err(Fat32Error::BadBytesPerSector(4096))
        ));
        assert!(matches!(
            m(|i| i[13] = 3),
            Err(Fat32Error::BadSectorsPerCluster(3))
        ));
        assert!(matches!(
            m(|i| i[13] = 0),
            Err(Fat32Error::BadSectorsPerCluster(0))
        ));
        assert!(matches!(
            m(|i| i[14..16].copy_from_slice(&0u16.to_le_bytes())),
            Err(Fat32Error::BadReserved(0))
        ));
        assert!(matches!(m(|i| i[16] = 0), Err(Fat32Error::BadFatCount(0))));
        assert!(matches!(m(|i| i[16] = 3), Err(Fat32Error::BadFatCount(3))));
        assert!(matches!(
            m(|i| i[36..40].copy_from_slice(&0u32.to_le_bytes())),
            Err(Fat32Error::BadFatSize(0))
        ));
        // The FAT region swallows the volume.
        assert!(matches!(
            m(|i| i[36..40].copy_from_slice(&60_000u32.to_le_bytes())),
            Err(Fat32Error::BadTotalSectors(_))
        ));
        // FAT12/16-shaped fields, one at a time.
        assert!(matches!(
            m(|i| i[17..19].copy_from_slice(&512u16.to_le_bytes())),
            Err(Fat32Error::Fat16Layout {
                root_entries: 512,
                ..
            })
        ));
        assert!(matches!(
            m(|i| i[19..21].copy_from_slice(&65535u16.to_le_bytes())),
            Err(Fat32Error::Fat16Layout {
                tot_sec16: 65535,
                ..
            })
        ));
        assert!(matches!(
            m(|i| i[22..24].copy_from_slice(&64u16.to_le_bytes())),
            Err(Fat32Error::Fat16Layout { fat_size16: 64, .. })
        ));
        assert!(matches!(
            m(|i| i[44..48].copy_from_slice(&1u32.to_le_bytes())),
            Err(Fat32Error::BadRootCluster(1))
        ));
        // A truncated boot sector.
        assert!(matches!(
            Bpb::parse(&img[0..511]),
            Err(Fat32Error::Truncated {
                need: 512,
                have: 511
            })
        ));
    }

    #[test]
    fn hostile_fat_entries_are_refused() {
        let max = 65_601u32; // cluster_count + 1
                             // The legal follow and EOC.
        assert_eq!(validate_entry(3, 4, max), Ok(Some(4)));
        assert_eq!(validate_entry(3, EOC_MIN, max), Ok(None));
        assert_eq!(validate_entry(3, 0xFFFF_FFFF, max), Ok(None));
        // Free, reserved, bad-cluster, reserved-gap, past-the-volume.
        for bad in [0u32, 1, 0x0FFF_FFF7, 0x0FFF_FFF5, 70_000] {
            assert!(
                validate_entry(3, bad, max).is_err(),
                "entry {bad:#x} must refuse"
            );
        }
    }

    #[test]
    fn chain_bounds_cycles_and_shorts_are_refused_or_bounded() {
        let img = build_image();
        let bpb = Bpb::parse(&img[0..512]).unwrap();
        let d = find_file(&img[1064 * 512..1065 * 512], b"HELLO   ESP")
            .unwrap()
            .unwrap();
        // (a) EOC one hop early: the chain ends before 1200 bytes.
        let mut m = img.clone();
        m[32 * 512 + 4 * 4..32 * 512 + 4 * 4 + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // FAT[4] = EOC
        let mut l = loader(&m);
        assert_eq!(
            walk_file_chain(&bpb, d.first_cluster, d.size, &mut l, &mut |_, _, _| {}),
            Err(Fat32Error::ChainTooShort {
                walked: 2,
                needed: 3
            })
        );
        // (b) A FAT hop past the volume: hostile entry, refused.
        let mut m = img.clone();
        m[32 * 512 + 4 * 4..32 * 512 + 4 * 4 + 4].copy_from_slice(&70_000u32.to_le_bytes()); // FAT[4] = 70000
        let mut l = loader(&m);
        assert!(matches!(
            walk_file_chain(&bpb, d.first_cluster, d.size, &mut l, &mut |_, _, _| {}),
            Err(Fat32Error::BadFatEntry {
                cluster: 4,
                entry: 70_000
            })
        ));
        // (c) A dirent-first cluster past the volume.
        let mut l = loader(&img);
        assert!(matches!(
            walk_file_chain(&bpb, 70_000, 512, &mut l, &mut |_, _, _| {}),
            Err(Fat32Error::ClusterOutOfRange {
                cluster: 70_000,
                ..
            })
        ));
        // (d) A length the whole volume cannot hold: ceil(400e6/512)
        // = 781250 clusters needed, 65600 exist.
        let mut l = loader(&img);
        assert!(matches!(
            walk_file_chain(&bpb, 3, 400_000_000, &mut l, &mut |_, _, _| {}),
            Err(Fat32Error::ChainTooLong {
                needed: 781_250,
                have: 65_600
            })
        ));
        // (e) A self-loop is BOUNDED, not infinite: the walk covers
        // the dirent's length and stops (documented tolerance — the
        // re-read is in-bounds and deterministic).
        let mut m = img.clone();
        m[32 * 512 + 3 * 4..32 * 512 + 3 * 4 + 4].copy_from_slice(&3u32.to_le_bytes()); // FAT[3] = 3
        let mut l = loader(&m);
        let mut visits = 0u32;
        assert_eq!(
            walk_file_chain(&bpb, d.first_cluster, d.size, &mut l, &mut |_, _, _| {
                visits += 1;
            })
            .unwrap(),
            3
        );
        assert_eq!(visits, 3);
        // (f) A read past the medium: the loader's honest bound (a
        // one-sector "disk": the first data read cannot land).
        let tiny: Vec<u8> = img[..512].to_vec();
        let mut lt = loader(&tiny);
        assert!(matches!(
            walk_file_chain(&bpb, 3, 512, &mut lt, &mut |_, _, _| {}),
            Err(Fat32Error::ReadFailed { .. })
        ));
        // (g) An empty file walks nothing.
        let mut l = loader(&img);
        assert_eq!(
            walk_file_chain(&bpb, 3, 0, &mut l, &mut |_, _, _| {}).unwrap(),
            0
        );
    }

    #[test]
    fn hostile_dirents_are_refused_never_skipped() {
        let img = build_image();
        let dir = &img[1064 * 512..1065 * 512];
        // (a) size > 0 with first cluster 0: refused.
        let mut d = dir.to_vec();
        d[26..28].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            find_file(&d, b"HELLO   ESP"),
            Err(Fat32Error::BadDirent { off: 0 })
        ));
        // (b) size > 0 with the reserved cluster 1: refused.
        let mut d = dir.to_vec();
        d[26..28].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            find_file(&d, b"HELLO   ESP"),
            Err(Fat32Error::BadDirent { .. })
        ));
        // (c) Deleted, long-name, and volume-label records are
        // skipped; the end marker ends the walk as a clean None.
        let mut d = [0u8; 96];
        d[0..11].copy_from_slice(b"DELETE  TXT");
        d[0] = 0xE5; // deleted
        d[32..43].copy_from_slice(b"LONGNAME   ");
        d[32 + 11] = 0x0F; // long-name record
        d[64..75].copy_from_slice(b"VOLLABEL   ");
        d[64 + 11] = 0x08; // volume label
        assert_eq!(find_file(&d, b"HELLO   ESP"), Ok(None));
        // (d) A clean miss is Ok(None), and the name must match all
        // 11 bytes (the extension included).
        assert_eq!(find_file(dir, b"HELLO   TXT"), Ok(None));
        assert_eq!(find_file(dir, b"HELLP   ESP"), Ok(None));
        assert_eq!(
            find_file(dir, b"HELLO   ESP"),
            Ok(Some(Dirent {
                first_cluster: 3,
                size: 1200,
                attr: 0x20,
            }))
        );
    }

    /// Deterministic fuzz: 2000 seeded corruptions of the real image
    /// (byte flips at format-relevant offsets). Every parse, lookup,
    /// and walk must return a Result — a panic here is the test
    /// failing, which is exactly what the kernel must never do.
    #[test]
    fn fuzzed_images_never_panic() {
        let img = build_image();
        let mut state = 0xC0FF_EE01_BADC_0DEu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut ok = 0usize;
        let mut refused = 0usize;
        for _ in 0..2000 {
            let mut m = img.clone();
            // 1-3 corruptions, biased to the structures the parser
            // walks: boot sector (0), FAT#0 (32), root dir (1064),
            // file data (1065..1067).
            for _ in 0..1 + (next() % 3) {
                let hot = [0usize, 32, 1064, 1065, 1066, 1067];
                let base = hot[(next() as usize) % hot.len()];
                let off = base * 512 + (next() as usize) % 512;
                if off < m.len() {
                    m[off] = m[off].wrapping_add((next() % 256) as u8);
                }
            }
            // The full chain: BPB → root dirent → cluster walk. Plain
            // match statements (not a closure chain) so the counters
            // are simple increments, never double-borrowed.
            let mut l = loader(&m);
            let bpb = match Bpb::parse(&m[0..512]) {
                Ok(b) => b,
                Err(_) => {
                    refused += 1;
                    continue;
                }
            };
            let d = match find_file(&m[1064 * 512..1065 * 512], b"HELLO   ESP") {
                Ok(Some(d)) if !d.is_dir() => d,
                Ok(_) => {
                    refused += 1;
                    continue;
                }
                Err(_) => {
                    refused += 1;
                    continue;
                }
            };
            match walk_file_chain(&bpb, d.first_cluster, d.size, &mut l, &mut |_, _, _| {}) {
                Ok(_) => ok += 1,
                Err(_) => refused += 1,
            }
        }
        // The point is "no panic across 2000 hostile images"; the
        // split sanity-checks that the corpus is not trivially
        // all-refused (the unmutated path stays reachable).
        assert!(ok >= 1, "the fuzz corpus must include walkable images");
        assert_eq!(ok + refused, 2000);
    }
}
