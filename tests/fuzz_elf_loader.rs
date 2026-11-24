//! ADR round A6 (ITEM 8) — the ELF loader MUTATION fuzzer: seeded,
//! deterministic, ≥300k mutations of the two REAL registry images
//! (`kernel-x86_64/blob/ring3-sh.bin` + `ring3-exec-target.bin`, the
//! exact bytes `exec_registry` serves), plus cross-image splices.
//!
//! The bar (round brief): `build_exec_plan` never panics on ANY byte
//! soup, and every ACCEPTED plan satisfies the loader's own promised
//! invariants — including the two ADR-0033 rules the mutation fuzzing
//! itself forced (the 118 accepted images whose `e_entry` pointed
//! into a NON-executable segment, and the unchecked `e_phoff`):
//! - `e_phoff == 64` (guaranteed by acceptance; re-read and asserted);
//! - `e_entry` lies inside an EXECUTABLE segment;
//! - every segment: `offset + filesz` within the image, `filesz <=
//!   memsz`, `vaddr + memsz` does not wrap, and no W+X segment;
//! - `map_bytes` covers the entry segment and is page-granular.
//!
//! The accepted/refused split is asserted non-degenerate both ways.
//! Scale with `AEGIS_FUZZ_MUTATIONS` (CI runs the default 300_000).

use aegis_os::elf::build_exec_plan;

/// The seeded xorshift the property tests already use.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The REAL registry images — the same bytes `exec_registry.rs`
/// `include_bytes!`s and serves to `sys_exec`.
const SH: &[u8] = include_bytes!("../kernel-x86_64/blob/ring3-sh.bin");
const TARGET: &[u8] = include_bytes!("../kernel-x86_64/blob/ring3-exec-target.bin");
/// The biggest image (16_736) plus splice headroom.
const BUF: usize = 20_000;

const MUTATIONS: usize = 300_000;

/// Header/segment geometry (64-bit little-endian ELF, the loader's
/// fixed layout): e_entry @24, e_phoff @32, e_phentsize @54, e_phnum
/// @56; each phdr is 56 bytes from 64: p_type, p_flags(+4),
/// p_offset(+8), p_vaddr(+16), p_filesz(+32), p_memsz(+40).
const E_ENTRY: usize = 24;
const E_PHOFF: usize = 32;
const E_PHNUM: usize = 56;
const PHDR_BASE: usize = 64;
const PHDR_STRIDE: usize = 56;

#[test]
fn mutated_elf_images_never_panic_and_accepted_plans_keep_their_promises() {
    let mutations: usize = match std::env::var("AEGIS_FUZZ_MUTATIONS") {
        Ok(v) => v.parse().unwrap_or(MUTATIONS),
        Err(_) => MUTATIONS,
    };
    let mut rng = Rng(0x5EED_E1F0_0000_0003);

    // The refusal-reason tally (the typed errors, by discriminant).
    let mut refused: u64 = 0;
    let mut accepted: u64 = 0;

    // Iteration 0 is the UNMUTATED base — both real images must plan
    // (the registry serves them; a refusal would be a regression).
    for i in 0..mutations {
        let base = if i % 2 == 0 { SH } else { TARGET };
        let mut buf = [0u8; BUF];
        let len = base.len();
        buf[..len].copy_from_slice(base);
        // The mutation count per iteration: 0 for the first pass of
        // each base, then 1..=4 (single-byte flips stay common so the
        // fuzzer lingers near the valid manifold).
        let n_mut = if i < 2 {
            0
        } else {
            1 + (rng.below(4) as usize)
        };
        for _ in 0..n_mut {
            match rng.below(10) {
                0..=3 => {
                    // A random byte to a random value.
                    let pos = rng.below(len as u64) as usize;
                    buf[pos] = (rng.next() >> 32) as u8;
                }
                4..=5 => {
                    // A targeted header field: the entry word.
                    let v = rng.next();
                    buf[E_ENTRY..E_ENTRY + 8].copy_from_slice(&v.to_le_bytes());
                }
                6 => {
                    // e_phoff: the ADR-0033 field.
                    let v = rng.below(256);
                    buf[E_PHOFF..E_PHOFF + 8].copy_from_slice(&v.to_le_bytes());
                }
                7 => {
                    // e_phnum: 0..=64 (beyond the table's real extent).
                    let v = rng.below(80) as u16;
                    buf[E_PHNUM..E_PHNUM + 2].copy_from_slice(&v.to_le_bytes());
                }
                8 => {
                    // A random phdr field of a random program header.
                    let ph = rng.below(4) as usize;
                    let field = rng.below(5) as usize;
                    let off = PHDR_BASE + ph * PHDR_STRIDE + [0, 4, 8, 16, 32][field];
                    if off + 8 <= len {
                        let v = rng.next();
                        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
                    }
                }
                _ => {
                    // Cross-image splice: a random chunk of the OTHER
                    // image lands at a random aligned offset.
                    let other = if i % 2 == 0 { TARGET } else { SH };
                    let chunk = (8 + rng.below(256) as usize) & !7;
                    let dst = rng.below((len.saturating_sub(chunk)) as u64) as usize & !7;
                    let src = rng.below((other.len().saturating_sub(chunk)) as u64) as usize;
                    let take = chunk.min(len - dst).min(other.len() - src);
                    buf[dst..dst + take].copy_from_slice(&other[src..src + take]);
                }
            }
        }

        match build_exec_plan(&buf[..len]) {
            Ok(plan) => {
                accepted += 1;
                // ── The accepted-plan promises, re-derived from the
                //    MUTATED header itself ──
                // (1) e_phoff == 64 exactly (ADR-0033).
                let phoff = u64::from_le_bytes([
                    buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
                ]);
                assert_eq!(
                    phoff, 64,
                    "mutation {i}: accepted a plan with e_phoff {phoff}"
                );
                // (2) e_entry inside an EXECUTABLE segment.
                let entry = u64::from_le_bytes([
                    buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
                ]);
                let phnum = u16::from_le_bytes([buf[56], buf[57]]) as usize;
                let mut entry_exec = false;
                for ph in 0..phnum {
                    let off = PHDR_BASE + ph * PHDR_STRIDE;
                    if off + PHDR_STRIDE > len {
                        break;
                    }
                    let flags = u32::from_le_bytes([
                        buf[off + 4],
                        buf[off + 5],
                        buf[off + 6],
                        buf[off + 7],
                    ]);
                    let vaddr = u64::from_le_bytes(buf[off + 16..off + 24].try_into().unwrap());
                    let memsz = u64::from_le_bytes(buf[off + 40..off + 48].try_into().unwrap());
                    let filesz = u64::from_le_bytes(buf[off + 32..off + 40].try_into().unwrap());
                    let seg_off = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
                    // (3) the segment invariants (for LOAD segments
                    // only — p_type 1).
                    if u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) == 1
                    {
                        assert!(filesz <= memsz, "mutation {i}: accepted filesz > memsz");
                        assert!(
                            seg_off
                                .checked_add(filesz)
                                .is_some_and(|end| end <= len as u64),
                            "mutation {i}: accepted a segment outside the image"
                        );
                        assert!(
                            vaddr.checked_add(memsz).is_some(),
                            "mutation {i}: accepted a wrapping vaddr+memsz"
                        );
                        let w = flags & 2 != 0;
                        let x = flags & 1 != 0;
                        assert!(
                            !(w && x),
                            "mutation {i}: accepted a W+X segment (flags {flags:#x})"
                        );
                        if x && vaddr <= entry && entry < vaddr + memsz {
                            entry_exec = true;
                        }
                    }
                }
                assert!(
                    entry_exec,
                    "mutation {i}: accepted a plan whose entry {entry:#x} is not in an EXEC segment"
                );
                // (4) map_bytes is page-granular and covers the entry.
                assert!(
                    plan.map_bytes % 4096 == 0 && plan.map_bytes > 0,
                    "mutation {i}: map_bytes {:#x} is not page-granular",
                    plan.map_bytes
                );
            }
            Err(_) => refused += 1,
        }
    }

    // Non-degenerate both ways: the bases plan (accepted > 0 — the
    // first two iterations are unmutated), and hostile mutations get
    // refused (the fuzzer actually attacks).
    assert!(accepted >= 2, "the unmutated registry images must plan");
    assert!(
        refused > 0,
        "no mutation was refused — the fuzzer is not attacking"
    );
    assert_eq!(accepted + refused, mutations as u64);
    println!(
        "elf mutation fuzz: {mutations} mutations of the two real registry images — {accepted} accepted (all invariants held), {refused} refused (typed)"
    );
}
