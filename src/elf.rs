//! ELF64 static executable plans — the pure half of `execve`.
//!
//! ADR-0022 D4: `Kernel::exec_replace` runs after the kernel's
//! loader "validates the ELF". That validation is POLICY, not
//! mechanics: deciding which headers an image may present, which
//! program headers carry mapping semantics, where every byte must
//! sit, and which shapes this kernel refuses to approximate — all of
//! it is pure computation over a byte slice, so it lives here, in
//! the host-tested core, where every refusal gets a test.
//!
//! The discipline is the open(2) one (ABI-VERSION, slice 2): a
//! feature this loader cannot honor is REFUSED with a typed error,
//! never silently dropped. A PIE image answered with a fake fixed
//! base, a W^X segment mapped writable, two segments sharing a page
//! with different permissions — each would "sort of run", and each
//! is an honest load-bearing refusal instead:
//!
//! - Only `ET_EXEC` + `EM_X86_64` + 64-bit + little-endian. PIE
//!   (`ET_DYN`) needs a relocation base this loader does not compute
//!   — `ElfError::PieUnsupported`, not a guess.
//! - `PT_LOAD` segments map; `PT_DYNAMIC`/`PT_INTERP` mean dynamic
//!   linkage we do not perform — refused; `PT_NULL`, `PT_PHDR`,
//!   `PT_NOTE` and the `PT_GNU_*` family carry no mapping semantics
//!   for a static image — ignored, documented; anything else is an
//!   unknown future header — refused (the O_EXCL rule: an ELF type
//!   we never heard of might carry semantics we would be silently
//!   dropping).
//! - `p_vaddr ≡ p_offset (mod PAGE_SIZE)` — the congruence the
//!   page-granular copy actually needs, checked directly instead of
//!   trusting `p_align`.
//! - W+X segments refuse (the kernel's W^X invariant is not
//!   negotiable at load time); zero-perm loads refuse (address-space
//!   reservation is mmap's job, not exec's).
//! - Two `PT_LOAD`s whose PAGE ranges overlap refuse: x86-64 cannot
//!   hold two permission sets in one page, and no correctly-linked
//!   static ELF64 asks it.
//! - The entry point must fall inside a `PT_LOAD`'s `[vaddr,
//!   vaddr+memsz)` — an image that enters outside its own mapped
//!   segments is corrupt, not a loader limit.

use crate::memory::PAGE_SIZE;

/// ELF64 magic: `0x7f 'E' 'L' 'F'`.
const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// `EI_CLASS`: 64-bit.
const ELFCLASS64: u8 = 2;
/// `EI_DATA`: little-endian.
const ELFDATA2LSB: u8 = 1;
/// `EV_CURRENT`.
const EV_CURRENT: u8 = 1;
/// `e_type`: a static executable with fixed vaddrs.
const ET_EXEC: u16 = 2;
/// `e_machine`: x86-64.
const EM_X86_64: u16 = 62;
/// `sizeof(Elf64_Ehdr)`.
const EHDR_SIZE: usize = 64;
/// `e_phentsize` — `sizeof(Elf64_Phdr)` or the table cannot be walked.
const PHENTSIZE: u16 = 56;

/// `p_type` values with mapping or refusal semantics we honor.
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;

/// `p_flags` bits (`PF_R|PF_W|PF_X`).
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Plan capacity: a static ELF64 with more PT_LOAD segments than
/// this is refused, not truncated (a real image has 2–5; the bound
/// exists so the plan is a fixed array, no heap in the kernel).
pub const MAX_SEGMENTS: usize = 8;

/// The user ceiling this loader accepts: canonical lower-half
/// userspace only. The kernel's own ceiling (guard gaps, the higher
/// half) is enforced where it is known — at the kernel's map gate —
/// but vaddr 0 and the kernel half are refused HERE, at the
/// validation that has the error context.
pub const USER_ADDR_TOP: u64 = 1 << 47;

/// One accepted `PT_LOAD`, as the kernel's map loop needs it.
///
/// `vaddr`/`memsz` describe the mapped extent the loader requests;
/// the kernel page-aligns downward/upward around them. `offset`/
/// `filesz` describe the image bytes to copy into the front of that
/// extent; the `memsz - filesz` tail is the zero-fill (`bss`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentPlan {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl SegmentPlan {
    /// The page range this segment occupies: `[first, last)` with
    /// both ends page-aligned — what two segments must not share.
    pub fn page_range(&self) -> (u64, u64) {
        (
            self.vaddr & !(PAGE_SIZE as u64 - 1),
            page_end(self.vaddr, self.memsz),
        )
    }
}

/// The validated load plan: the segments in program-header order,
/// the entry point, and the total page bytes the image will demand
/// (the kernel checks it against the domain's quota before touching
/// a single frame — ENOMEM must not land mid-copy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    pub entry: u64,
    pub segments: [SegmentPlan; MAX_SEGMENTS],
    pub n_segments: usize,
    /// Sum of every segment's page-rounded mapping, in bytes.
    pub map_bytes: u64,
}

/// Every way an image is refused. Each variant names the rule it
/// enforces — the kernel turns these into `-ENOEXEC`/`-ENOMEM` at the
/// arm; the distinction lives HERE so tests can hold every refusal
/// to account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Fewer bytes than an `Elf64_Ehdr`, or fewer than the header
    /// says the program header table needs.
    Truncated,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    BadIdentVersion,
    /// Not `ET_EXEC`. `ET_DYN` (PIE) arrives here too — the variant
    /// says so, because "PIE would work at the right base" is the
    /// most tempting wrong answer.
    PieUnsupported,
    WrongMachine,
    BadEhdrVersion,
    /// `e_phentsize != 56`: walking the table would misparse it.
    BadPhentsize,
    /// More `PT_LOAD`s than the plan holds — refused, not truncated.
    TooManySegments,
    /// No `PT_LOAD` at all — nothing to map, nothing to run.
    NoLoadableSegments,
    /// `PT_INTERP`: dynamic linkage is not performed.
    InterpreterUnsupported,
    /// `PT_DYNAMIC` in a static image: the dynamic linker's table.
    DynamicUnsupported,
    /// A program header type outside the honored/ignored set — the
    /// future-feature refusal.
    UnknownHeaderType,
    BadPHeaderVersion,
    /// `p_filesz > p_memsz` — the header contradicts itself.
    FileszOverMemsz,
    /// `p_offset + p_filesz` runs past the image's end.
    SegmentPastEof,
    /// `p_memsz == 0` — address-space reservation is mmap's job.
    EmptySegment,
    /// `PF_W|PF_X` — the W^X invariant, refused at load time.
    WriteExecuteSegment,
    /// No `PF_R|PF_W|PF_X` bit at all — nothing to map.
    NoPermissions,
    /// `p_vaddr % PAGE != p_offset % PAGE` — the page-granular copy
    /// cannot honor the header.
    NotCongruent,
    /// `p_vaddr` is 0, the kernel half, or non-canonical.
    BadAddress,
    /// Two `PT_LOAD`s share a page — unrepresentable permissions.
    OverlappingPages,
    /// `e_entry` falls outside every `PT_LOAD`.
    EntryOutsideSegments,
}

/// Validate `image` and produce the kernel's load plan.
///
/// Pure: no allocation, no I/O, every branch visible to a host test.
pub fn build_exec_plan(image: &[u8]) -> Result<ExecPlan, ElfError> {
    // The fixed-layout reads below are safe: every one is guarded by
    // a length check, and `core`'s slice accesses panic on overrun —
    // but no overrun is reachable once Truncated is out of the way.
    if image.len() < EHDR_SIZE {
        return Err(ElfError::Truncated);
    }
    if image[0..4] != MAGIC {
        return Err(ElfError::BadMagic);
    }
    // e_ident[4] class, [5] endianness, [6] version.
    if image[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }
    if image[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if image[6] != EV_CURRENT {
        return Err(ElfError::BadIdentVersion);
    }
    let e_type = le16(image, 16);
    if e_type != ET_EXEC {
        // ET_DYN is the PIE case; everything else (ET_REL, ET_CORE,
        // ET_NONE) is not an executable at all.
        return Err(ElfError::PieUnsupported);
    }
    let e_machine = le16(image, 18);
    if e_machine != EM_X86_64 {
        return Err(ElfError::WrongMachine);
    }
    let e_version = le32(image, 20);
    if e_version != u32::from(EV_CURRENT) {
        return Err(ElfError::BadEhdrVersion);
    }
    let e_entry = le64(image, 24);
    let e_phentsize = le16(image, 54);
    let e_phnum = le16(image, 56);
    if e_phentsize != PHENTSIZE {
        return Err(ElfError::BadPhentsize);
    }
    let e_phnum = e_phnum as usize;
    let table_end = EHDR_SIZE + e_phnum * PHENTSIZE as usize;
    if image.len() < table_end {
        return Err(ElfError::Truncated);
    }

    let mut segments = [SegmentPlan {
        vaddr: 0,
        offset: 0,
        filesz: 0,
        memsz: 0,
        readable: false,
        writable: false,
        executable: false,
    }; MAX_SEGMENTS];
    let mut n_segments = 0usize;
    for i in 0..e_phnum {
        let p = EHDR_SIZE + i * PHENTSIZE as usize;
        let p_type = le32(image, p);
        match p_type {
            PT_NULL => continue,
            PT_LOAD => {}
            PT_NOTE | PT_PHDR | PT_GNU_STACK | PT_GNU_RELRO | PT_GNU_PROPERTY => continue,
            PT_INTERP => return Err(ElfError::InterpreterUnsupported),
            PT_DYNAMIC => return Err(ElfError::DynamicUnsupported),
            _ => return Err(ElfError::UnknownHeaderType),
        }
        let p_flags = le32(image, p + 4);
        if p_flags & !(PF_R | PF_W | PF_X) != 0 {
            // Bits beyond R/W/X are future flags — the O_EXCL rule.
            return Err(ElfError::UnknownHeaderType);
        }
        let (readable, writable, executable) = (
            p_flags & PF_R != 0,
            p_flags & PF_W != 0,
            p_flags & PF_X != 0,
        );
        if writable && executable {
            return Err(ElfError::WriteExecuteSegment);
        }
        if !readable && !writable && !executable {
            return Err(ElfError::NoPermissions);
        }
        let p_offset = le64(image, p + 8);
        let p_vaddr = le64(image, p + 16);
        let p_filesz = le64(image, p + 32);
        let p_memsz = le64(image, p + 40);
        // p_vaddr % PAGE must equal p_offset % PAGE, or the byte copy
        // at [vaddr, vaddr+filesz) cannot be made page-honest.
        if p_vaddr % PAGE_SIZE as u64 != p_offset % PAGE_SIZE as u64 {
            return Err(ElfError::NotCongruent);
        }
        if p_filesz > p_memsz {
            return Err(ElfError::FileszOverMemsz);
        }
        if p_memsz == 0 {
            return Err(ElfError::EmptySegment);
        }
        if p_offset
            .checked_add(p_filesz)
            .is_none_or(|e| e > image.len() as u64)
        {
            return Err(ElfError::SegmentPastEof);
        }
        if p_vaddr
            .checked_add(p_memsz)
            .is_none_or(|e| e > USER_ADDR_TOP)
        {
            return Err(ElfError::BadAddress);
        }
        if p_vaddr == 0 {
            return Err(ElfError::BadAddress);
        }
        if n_segments == MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        let plan = SegmentPlan {
            vaddr: p_vaddr,
            offset: p_offset,
            filesz: p_filesz,
            memsz: p_memsz,
            readable,
            writable,
            executable,
        };
        // Page-overlap against every segment already accepted — real
        // images arrive sorted, but a validator that ASSUMES order is
        // one crafted header away from a wrong answer.
        for prior in &segments[..n_segments] {
            let (a0, a1) = plan.page_range();
            let (b0, b1) = prior.page_range();
            if a0 < b1 && b0 < a1 {
                return Err(ElfError::OverlappingPages);
            }
        }
        segments[n_segments] = plan;
        n_segments += 1;
    }
    if n_segments == 0 {
        return Err(ElfError::NoLoadableSegments);
    }
    if !segments[..n_segments]
        .iter()
        .any(|s| s.vaddr <= e_entry && e_entry < s.vaddr + s.memsz)
    {
        return Err(ElfError::EntryOutsideSegments);
    }
    let map_bytes = segments[..n_segments]
        .iter()
        .map(|s| page_end(s.vaddr, s.memsz) - (s.vaddr & !(PAGE_SIZE as u64 - 1)))
        .sum();
    Ok(ExecPlan {
        entry: e_entry,
        segments,
        n_segments,
        map_bytes,
    })
}

/// The first page-aligned address at or after `vaddr + len` — the
/// mapping's last page boundary.
fn page_end(vaddr: u64, len: u64) -> u64 {
    let end = vaddr + len;
    end.div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64
}

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le64(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal hand-built ELF64 image: a fixed `ET_EXEC` header and
    /// a caller-supplied program-header table. Every test mutates one
    /// field at a time, so each refusal names ITS rule — the same
    /// discipline the open(2) flag tests use.
    struct Image {
        bytes: Vec<u8>,
    }

    #[derive(Clone)]
    struct PhdrSpec {
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    }

    impl PhdrSpec {
        /// The canonical text segment: one page RX at 0x400000.
        fn text() -> Self {
            PhdrSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_X,
                p_offset: 0x1000,
                p_vaddr: 0x400000,
                p_filesz: 0x80,
                p_memsz: 0x80,
            }
        }
        /// The canonical data segment: one page RW with a bss tail.
        fn data() -> Self {
            PhdrSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_W,
                p_offset: 0x2000,
                p_vaddr: 0x401000,
                p_filesz: 0x100,
                p_memsz: 0x300,
            }
        }
    }

    impl Image {
        /// 0x9000 bytes: room for two file-backed segments plus slack.
        fn new(entry: u64, phdrs: &[PhdrSpec]) -> Self {
            let mut b = vec![0u8; 0x9000];
            b[0..4].copy_from_slice(&MAGIC);
            b[4] = ELFCLASS64;
            b[5] = ELFDATA2LSB;
            b[6] = EV_CURRENT;
            b[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
            b[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
            b[20..24].copy_from_slice(&1u32.to_le_bytes());
            b[24..32].copy_from_slice(&entry.to_le_bytes());
            b[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
            b[54..56].copy_from_slice(&PHENTSIZE.to_le_bytes());
            b[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
            for (i, p) in phdrs.iter().enumerate() {
                let o = EHDR_SIZE + i * PHENTSIZE as usize;
                b[o..o + 4].copy_from_slice(&p.p_type.to_le_bytes());
                b[o + 4..o + 8].copy_from_slice(&p.p_flags.to_le_bytes());
                b[o + 8..o + 16].copy_from_slice(&p.p_offset.to_le_bytes());
                b[o + 16..o + 24].copy_from_slice(&p.p_vaddr.to_le_bytes());
                b[o + 32..o + 40].copy_from_slice(&p.p_filesz.to_le_bytes());
                b[o + 40..o + 48].copy_from_slice(&p.p_memsz.to_le_bytes());
            }
            Image { bytes: b }
        }
    }

    #[test]
    fn accepts_the_canonical_two_segment_static_image() {
        let img = Image::new(0x400040, &[PhdrSpec::text(), PhdrSpec::data()]);
        let plan = build_exec_plan(&img.bytes).expect("canonical image must plan");
        assert_eq!(plan.entry, 0x400040);
        assert_eq!(plan.n_segments, 2);
        let t = &plan.segments[0];
        assert_eq!((t.vaddr, t.filesz, t.memsz), (0x400000, 0x80, 0x80));
        assert!(t.readable && t.executable && !t.writable);
        let d = &plan.segments[1];
        assert_eq!((d.vaddr, d.filesz, d.memsz), (0x401000, 0x100, 0x300));
        assert!(d.readable && d.writable && !d.executable);
        // text: one full page; data: one page (0x300 fits inside it)
        assert_eq!(plan.map_bytes, 2 * PAGE_SIZE as u64);
    }

    #[test]
    fn map_bytes_counts_page_rounding_not_memsz() {
        // A 0x1a00-byte memsz starting mid-page demands THREE pages.
        let img = Image::new(
            0x400800,
            &[PhdrSpec {
                p_type: PT_LOAD,
                p_flags: PF_R,
                p_offset: 0x800,
                p_vaddr: 0x400800,
                p_filesz: 0x100,
                p_memsz: 0x1a00,
            }],
        );
        let plan = build_exec_plan(&img.bytes).unwrap();
        assert_eq!(plan.map_bytes, 3 * PAGE_SIZE as u64);
    }

    #[test]
    fn ignores_note_phdr_and_gnu_headers() {
        let img = Image::new(
            0x400040,
            &[
                PhdrSpec {
                    p_type: PT_NOTE,
                    ..PhdrSpec::text()
                },
                PhdrSpec {
                    p_type: PT_PHDR,
                    ..PhdrSpec::text()
                },
                PhdrSpec {
                    p_type: PT_GNU_STACK,
                    ..PhdrSpec::text()
                },
                PhdrSpec {
                    p_type: PT_GNU_RELRO,
                    ..PhdrSpec::text()
                },
                PhdrSpec {
                    p_type: PT_GNU_PROPERTY,
                    ..PhdrSpec::text()
                },
                PhdrSpec::text(),
            ],
        );
        assert_eq!(build_exec_plan(&img.bytes).unwrap().n_segments, 1);
    }

    #[test]
    fn refuses_the_header_family_loudly() {
        let img = Image::new(0x400000, &[PhdrSpec::text()]);
        // Truncated: shorter than an Ehdr.
        assert_eq!(build_exec_plan(&[]), Err(ElfError::Truncated));
        // Truncated: the program-header table runs past the end.
        let mut t = img.bytes.clone();
        t.truncate(0x40);
        assert_eq!(build_exec_plan(&t), Err(ElfError::Truncated));
        for (off, bad, err) in [
            (0, 0x00, ElfError::BadMagic),     // magic byte 0
            (4, 1, ElfError::Not64Bit),        // EI_CLASS: 32-bit
            (5, 2, ElfError::NotLittleEndian), // EI_DATA: MSB
            (6, 0, ElfError::BadIdentVersion), // EI_VERSION
            (16, 3, ElfError::PieUnsupported), // e_type: ET_DYN (the PIE)
            (18, 8, ElfError::WrongMachine),   // e_machine: MIPS
            (54, 32, ElfError::BadPhentsize),  // phentsize != 56
        ] {
            let mut m = img.bytes.clone();
            m[off] = bad;
            assert_eq!(build_exec_plan(&m), Err(err), "off {off}");
        }
        let mut m = img.bytes.clone();
        m[20] = 0; // e_version low byte
        assert_eq!(build_exec_plan(&m), Err(ElfError::BadEhdrVersion));
    }

    #[test]
    fn refuses_every_unimplementable_segment_shape() {
        let cases: &[(PhdrSpec, ElfError)] = &[
            // filesz > memsz contradicts itself.
            (
                PhdrSpec {
                    p_filesz: 0x200,
                    p_memsz: 0x100,
                    ..PhdrSpec::text()
                },
                ElfError::FileszOverMemsz,
            ),
            // offset + filesz past the image's end.
            (
                PhdrSpec {
                    p_offset: 0x9000,
                    p_filesz: 0x80,
                    ..PhdrSpec::text()
                },
                ElfError::SegmentPastEof,
            ),
            // memsz == 0: reservation is mmap's job, not exec's.
            (
                PhdrSpec {
                    p_filesz: 0,
                    p_memsz: 0,
                    ..PhdrSpec::text()
                },
                ElfError::EmptySegment,
            ),
            // W^X at load time.
            (
                PhdrSpec {
                    p_flags: PF_R | PF_W | PF_X,
                    ..PhdrSpec::text()
                },
                ElfError::WriteExecuteSegment,
            ),
            // Zero-perm load.
            (
                PhdrSpec {
                    p_flags: 0,
                    ..PhdrSpec::text()
                },
                ElfError::NoPermissions,
            ),
            // Future flag bits beyond R/W/X.
            (
                PhdrSpec {
                    p_flags: PF_R | 0x100,
                    ..PhdrSpec::text()
                },
                ElfError::UnknownHeaderType,
            ),
            // Congruence: offset and vaddr disagree within the page.
            (
                PhdrSpec {
                    p_offset: 0x1080,
                    p_vaddr: 0x400000,
                    ..PhdrSpec::text()
                },
                ElfError::NotCongruent,
            ),
            // vaddr 0: the null page.
            (
                PhdrSpec {
                    p_offset: 0,
                    p_vaddr: 0,
                    ..PhdrSpec::text()
                },
                ElfError::BadAddress,
            ),
            // The kernel half / non-canonical user address.
            (
                PhdrSpec {
                    p_offset: 0,
                    p_vaddr: 0xffff_8000_0000_0000,
                    ..PhdrSpec::text()
                },
                ElfError::BadAddress,
            ),
        ];
        for (spec, err) in cases {
            let spec = spec.clone();
            let img = Image::new(0x400000, &[spec]);
            assert_eq!(build_exec_plan(&img.bytes), Err(*err), "case {err:?}");
        }
    }

    #[test]
    fn refuses_pie_dyn_and_unknown_headers_individually() {
        for (p_type, err) in [
            (PT_INTERP, ElfError::InterpreterUnsupported),
            (PT_DYNAMIC, ElfError::DynamicUnsupported),
            (0x7000_0001, ElfError::UnknownHeaderType), // vendor header
        ] {
            let img = Image::new(
                0x400000,
                &[
                    PhdrSpec::text(),
                    PhdrSpec {
                        p_type,
                        ..PhdrSpec::data()
                    },
                ],
            );
            assert_eq!(build_exec_plan(&img.bytes), Err(err), "type {p_type:#x}");
        }
        // A lone PT_NOTE is not an image: nothing loadable.
        let img = Image::new(
            0x400000,
            &[PhdrSpec {
                p_type: PT_NOTE,
                ..PhdrSpec::text()
            }],
        );
        assert_eq!(
            build_exec_plan(&img.bytes),
            Err(ElfError::NoLoadableSegments)
        );
    }

    #[test]
    fn refuses_two_segments_sharing_a_page() {
        // Same page, different permissions: x86 cannot represent it.
        let img = Image::new(
            0x400000,
            &[
                PhdrSpec::text(),
                PhdrSpec {
                    p_offset: 0x800,
                    p_vaddr: 0x400800, // inside text's page
                    p_flags: PF_R | PF_W,
                    p_filesz: 0x10,
                    p_memsz: 0x10,
                    p_type: PT_LOAD,
                },
            ],
        );
        assert_eq!(build_exec_plan(&img.bytes), Err(ElfError::OverlappingPages));
        // The same vaddr+memsz as text but read-only: still an overlap.
        let img2 = Image::new(
            0x400000,
            &[
                PhdrSpec::text(),
                PhdrSpec {
                    p_offset: 0x1000,
                    p_vaddr: 0x400000,
                    p_flags: PF_R,
                    p_filesz: 0x80,
                    p_memsz: 0x80,
                    p_type: PT_LOAD,
                },
            ],
        );
        assert_eq!(
            build_exec_plan(&img2.bytes),
            Err(ElfError::OverlappingPages)
        );
    }

    #[test]
    fn adjacent_pages_do_not_overlap() {
        // End of one on a page boundary, start of the next on it.
        let img = Image::new(
            0x400040,
            &[
                PhdrSpec::text(),
                PhdrSpec {
                    p_offset: 0x2000,
                    p_vaddr: 0x401000,
                    p_filesz: 0x10,
                    p_memsz: 0x10,
                    p_type: PT_LOAD,
                    p_flags: PF_R | PF_W,
                },
            ],
        );
        let plan = build_exec_plan(&img.bytes).expect("adjacent pages are fine");
        assert_eq!(plan.n_segments, 2);
    }

    #[test]
    fn refuses_entry_outside_every_loadable_segment() {
        let img = Image::new(0x500000, &[PhdrSpec::text()]);
        assert_eq!(
            build_exec_plan(&img.bytes),
            Err(ElfError::EntryOutsideSegments)
        );
        // Entry inside the bss TAIL (filesz..memsz) is still inside
        // the segment — accepted (data: filesz 0x100, memsz 0x300).
        let img2 = Image::new(0x401000 + 0x200, &[PhdrSpec::data()]);
        assert!(build_exec_plan(&img2.bytes).is_ok());
    }

    #[test]
    fn refuses_beyond_capacity_not_truncating() {
        let nine: Vec<PhdrSpec> = (0..9)
            .map(|i: u64| PhdrSpec {
                p_offset: 0x1000,
                p_vaddr: 0x400000 + i * 0x1000,
                p_filesz: 0x10,
                p_memsz: 0x10,
                p_type: PT_LOAD,
                p_flags: PF_R,
            })
            .collect();
        let img = Image::new(0x400000, &nine);
        assert_eq!(build_exec_plan(&img.bytes), Err(ElfError::TooManySegments));
        // Exactly MAX_SEGMENTS is fine.
        let eight: Vec<PhdrSpec> = nine[..8].to_vec();
        let img = Image::new(0x400000, &eight);
        assert_eq!(
            build_exec_plan(&img.bytes).unwrap().n_segments,
            MAX_SEGMENTS
        );
    }

    #[test]
    fn phnum_zero_is_no_loadable_segments() {
        let img = Image::new(0x400000, &[]);
        assert_eq!(
            build_exec_plan(&img.bytes),
            Err(ElfError::NoLoadableSegments)
        );
    }
}
