//! The virtual address space layout of the booted kernel (ADR-0002).
//!
//! Pure constants and translation arithmetic — host-tested. The
//! bring-up mapping itself is built by the boot stub and torn down /
//! extended by `mm::init`, `mm::stacks`, and `mm::page_table` on the
//! target.
//!
//! ```text
//!   0x0000_0000_0000_0000 ┌────────────────────────────────────────┐
//!                         │ USER HALF — per-domain tables (PR-1.3):│
//!                         │ the ten-check policy gates every region;│
//!                         │ its decisions become real PTEs. The    │
//!                         │ stub's identity window is torn down in │
//!                         │ mm::init; guard gaps are absent PTEs.  │
//!   0xFFFF_8880_0000_0000 ├────────────────────────────────────────┤ PML4[273]
//!                         │ direct map: PA 0..1 GiB, RW+NX, G      │
//!   0xFFFF_FFFF_4000_0000 ├────────────────────────────────────────┤ PML4[511]·PDPT[509]
//!                         │ guarded kernel stacks (mm/stacks.rs)   │
//!   0xFFFF_FFFF_8000_0000 ├────────────────────────────────────────┤ PML4[511]·PDPT[510]
//!                         │ kernel image: RX text, RO data, RW     │
//!                         │ data+bss+boot stack (two 2 MiB huge    │
//!                         │ leaves @ PA 2..6 MiB)                  │
//!                         └────────────────────────────────────────┘
//! ```

pub mod direct_map;
pub mod image;
pub mod page_table;
pub mod pte;

/// ADR-0024 D2: the share-aware frame paths (fork, munmap, teardown)
/// — boot-only: they reach the live share table through the context
/// slot, which host builds do not install.
#[cfg(not(test))]
pub mod shares;
pub mod stacks;
pub mod user;
pub mod user_layout;
pub mod user_range;

/// The kernel link base (two 2 MiB huge pages, PA 2..6 MiB).
pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Page/frame size in bytes.
pub const PAGE: u64 = 4096;

/// Present | Write (the flag bits every table mapping here uses).
pub const PTE_P_RW: u64 = 0x3;

/// Mask off flag bits to get a table/frame physical address from an entry.
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Tear down the stub's low identity window, arm the ISA features the
/// per-domain tables need (EFER.NXE, CR4.PGE), mark the shared kernel
/// leaves global (+ the direct map non-executable), and set up the
/// per-CPU state.
///
/// After this returns, low virtual addresses are UNMAPPED, W^X and NX
/// are hardware-enforced, and kernel entries survive CR3 switches. The
/// only ways to reach physical memory are the direct map and the kernel
/// window. Called once from `kmain`, right after `arch::init` (so any
/// fault in here is diagnosed, not triple-faulted).
#[cfg(not(test))]
pub fn init() {
    use crate::{arch, hw, memops, serial};

    // PML4[0] = 0: the identity window the stub needed for bring-up
    // dies here. The write itself goes through the direct map, which is
    // unaffected — PML4[273] is a different entry.
    let pml4_pa = hw::read_cr3() & ADDR_MASK;
    memops::write_u64(pml4_pa, 0);

    // EFER.NXE (bit 11): the XD bit in every PTE starts meaning
    // "instruction fetch denied" — W^X becomes a hardware property.
    const MSR_EFER: u32 = 0xC000_0080;
    let efer = hw::rdmsr(MSR_EFER);
    hw::wrmsr(MSR_EFER, efer | (1 << 11));

    // CR4.PGE (bit 7): global leaf entries survive CR3 switches, so the
    // kernel half stops thrashing the TLB the moment domains exist.
    let cr4 = hw::read_cr4();
    hw::write_cr4(cr4 | (1 << 7));

    // Mark the shared kernel leaves global, and the direct map
    // non-executable (ADR-0002: RW only, never X):
    //   pml4[273] → pdpt_dm[0]   (1 GiB direct map)        |= G | NX
    //   pml4[511] → pdpt_hh[510] → pd_hh[0..1] (the kernel
    //   image's two 2 MiB leaves, PA 2..6 MiB — K22)        |= G
    let dm = memops::read_u64(pml4_pa + 273 * 8) & ADDR_MASK;
    memops::write_u64(dm, memops::read_u64(dm) | pte::PTE_G | pte::PTE_NX);
    let hh = memops::read_u64(pml4_pa + 511 * 8) & ADDR_MASK;
    let pd = memops::read_u64(hh + 510 * 8) & ADDR_MASK;
    memops::write_u64(pd, memops::read_u64(pd) | pte::PTE_G);
    // K22: the second leaf (PA 4 MiB) is a shared kernel leaf too.
    memops::write_u64(pd + 8, memops::read_u64(pd + 8) | pte::PTE_G);

    // F15 (ADR-0006): replace the image's two RWX 2 MiB leaves with
    // per-4KiB PTEs (.text RX, .rodata RO+NX, .data/.bss RW+NX, gaps
    // and the boot-stack guard absent) and set CR0.WP — BEFORE the CR3
    // reload below, so one flush covers both.
    arch::image_map::install();

    // Reload CR3 (same value): flushes every non-global entry and
    // rebuilds the TLB under the new NXE/PGE semantics.
    hw::write_cr3(pml4_pa);
    // Prove the teardown through the direct map — if the write or the
    // flush were wrong, this is the loud place to fail (panic prints
    // its location and halts; formatted panic messages need core::fmt,
    // which the boot-path panic handler deliberately does without).
    assert!(memops::read_u64(pml4_pa) == 0);

    arch::percpu::init();

    let cpu = arch::percpu::get().cpu_id;
    let mut b = [0u8; 18];
    serial::write_str("[MM ] higher-half ok: base=");
    serial::write_str(crate::strutil::hex(KERNEL_BASE, &mut b));
    serial::write_str(" identity=pml4[0]:0 nx=on pge=on percpu:cpu=");
    let mut b2 = [0u8; 20];
    serial::write_str(crate::strutil::dec(cpu as u64, &mut b2));
    serial::write_str("\n");
}

// ── MMIO GiB windows in the direct map ──────────────────────────────
//
// The direct map ships with ONE GiB (RAM); the LAPIC/VT-d window
// maps the FOURTH (0xC000_0000.., arch::lapic / arch::vtd). Round 6's
// ADR-0020 added the ECAM seam but never mapped the GiB the MCFG
// window lives in — on q35 that is the THIRD (0x8000_0000..0xBFFF_FFFF
// at PCIEXBAR 0xB000_0000), so the first config read through the
// direct map #PF'd and the kernel halted ("unexpected fault"). The
// lane never reached it (the GPT marker bug kept it red earlier), so
// the gap hid until the FAT32 round ran the lane to the end.

/// The 1-GiB direct-map PDPT indices spanned by [pa, pa+len) —
/// pure, host-tested. `None` on zero length, arithmetic overflow, or
/// a range beyond the 512-GiB PML4[273] slot (a wrong address must
/// refuse, never fault).
#[must_use]
pub fn gib_span(pa: u64, len: u64) -> Option<(u64, u64)> {
    if len == 0 {
        return None;
    }
    let end = pa.checked_add(len - 1)?;
    if end >= 1u64 << 39 {
        return None;
    }
    Some((pa >> 30, end >> 30))
}

/// Map the spanned 1-GiB PDPT entries as RW+NX huge pages (the
/// LAPIC-window trick, generalized). Idempotent: entries that are
/// already present are left alone (the fourth GiB belongs to the
/// LAPIC/VT-d window; the first to RAM). Returns how many entries it
/// wrote — the caller's marker prints it, and the first access
/// through the window is the boot-lane proof.
#[cfg(not(test))]
pub fn map_gib_windows(pa: u64, len: u64) -> u32 {
    use crate::{arch::lapic::PTE_PS, hw, memops};
    let Some((first, last)) = gib_span(pa, len) else {
        return 0;
    };
    // The direct map's PDPT: PML4[273] → pdpt_dm (init() built it).
    let pml4 = hw::read_cr3() & ADDR_MASK;
    let pdpt = memops::read_u64(pml4 + 273 * 8) & ADDR_MASK;
    let mut mapped = 0u32;
    for gib in first..=last {
        let slot = pdpt + gib * 8;
        if memops::read_u64(slot) & pte::PTE_P != 0 {
            continue; // already mapped — LAPIC/VT-d/RAM own it
        }
        let pte_val = (gib << 30) | pte::PTE_P | pte::PTE_W | PTE_PS | pte::PTE_G | pte::PTE_NX;
        memops::write_u64(slot, pte_val);
        mapped += 1;
    }
    // Same-value CR3 reload: the new global entries enter the TLB
    // under the same discipline as every other window mapping.
    hw::write_cr3(pml4);
    mapped
}

#[cfg(test)]
mod tests {
    use super::gib_span;

    #[test]
    fn spans_are_the_covered_gib_indices() {
        // q35's ECAM window: 256 MiB at 0xB000_0000 — one GiB (index 2).
        assert_eq!(gib_span(0xB000_0000, 256 << 20), Some((2, 2)));
        // A window straddling a GiB boundary.
        assert_eq!(gib_span(0xBFF0_0000, 32 << 20), Some((2, 3)));
        // The RAM direct map's own GiB.
        assert_eq!(gib_span(0, 1 << 30), Some((0, 0)));
        // Unaligned base and length still land on the right indices.
        assert_eq!(gib_span(0x7FFF_F000, 0x2000), Some((1, 2)));
    }

    #[test]
    fn hostile_spans_refuse() {
        assert_eq!(gib_span(0xB000_0000, 0), None, "zero length");
        assert_eq!(gib_span(u64::MAX, 1), None, "end overflow");
        assert_eq!(
            gib_span(1u64 << 39, 1),
            None,
            "beyond the 512-GiB direct-map slot"
        );
        assert_eq!(gib_span(1u64 << 38, u64::MAX), None, "length overflow");
    }
}
