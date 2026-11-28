//! The repo-fixture store (K23): the package manager's provisioning
//! bytes, read off the ext2 disk at boot.
//!
//! K22 carried the signed repo fixture inside the kernel image
//! (`include_bytes!` of the pkg-mkrepo outputs) — the kernel
//! binary was the package data's only transport, and every lane paid
//! the image size whether it ran the package lane or not. K23 moves
//! the bytes to where the rest of the boot's data lives: the ext2
//! root disk's `/pkgsrc` directory (scripts/mkext2.py writes it from
//! the same blob copies), the driver stack's ext2 walk READS them at
//! CPL=0 in the same boot (see `drvstack/ext2.rs`), and this store
//! hands them to the K22 provisioning probe — the kernel image
//! stopped carrying package data.
//!
//! The discipline is the exec registry's disk slot (K20/P0-3), times
//! five: a zero-initialized `.bss` static written ONCE at boot
//! (driver stack, IF=0, before any domain that could read it
//! exists), a per-slot write-once claim, a length published after
//! the bytes (Release/Acquire), and read-only access forever after.
//! The slot count and the file order are a named const pair — the
//! K23 integration added the v1.1 package as exactly that two-line
//! change, and a later round's sixth file would too.
//!
//! Honesty about failure: an empty store is not an error HERE — the
//! ext2 walk prints its own skip markers, and the K22 lane fails
//! LOUDLY at provisioning time (`[PKG] ERROR: boot provisioning
//! failed`) if the store is incomplete. This module never guesses,
//! never pads, never synthesizes bytes: `file(idx)` is either the
//! disk's exact bytes or nothing.

// SAFETY discipline (module-level): the ONE static-mut array below
// (the five-slot store) is written once per slot at boot — driver
// stack, IF=0, before any domain that could read it exists — and
// read only afterwards; every access is documented at the site.
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The number of fixture files the store holds — the named half of
/// the const pair with [`FILE_ORDER`]. `mkext2.py` writes the same
/// seven files to `/pkgsrc` and `drvstack/ext2.rs` walks them in
/// order; an eighth file extends BOTH consts and nothing else changes
/// (P1-2 added the sixth and seventh — the netcat and rust-hello
/// packages — as exactly that two-line change, the way the doc
/// promised).
pub const SLOT_COUNT: usize = 7;

/// One slot's capacity. The ext2 reader's direct-block ceiling is
/// 12 KiB; the repo fixture's builder bound (pkg-mkrepo's spill
/// window) mirrors it — P1-2's REAL-binary packages (the 8,670-B
/// hello 1.1.0 and the 8,748-B netcat) ride the same ceiling, so a
/// fixture file that outgrows its slot is a BUILD failure long
/// before it is a boot one.
pub const SLOT_MAX: usize = 12 * 1024;

/// The fixture file names in slot order — exactly the set
/// `scripts/mkext2.py` writes into `/pkgsrc` (trust, the repo
/// config, the signed index, and BOTH version-qualified packages:
/// the repo layout is version-qualified now, so the upgrade round
/// has something to move TO). The order is part of
/// the contract: slot `i` always holds the file this names.
pub const FILE_ORDER: [&str; SLOT_COUNT] = [
    "trust",
    "r1.repo",
    "index.aki",
    "r1.hello-1.0.0.akp",
    "r1.hello-1.1.0.akp",
    "r1.netcat-1.0.0.akp",
    "r1.rust-hello-1.0.0.akp",
];

/// Slot 0: the trust anchors (`/pkg/trust` at provisioning).
pub const IDX_TRUST: usize = 0;
/// Slot 1: the repo config (`/pkg/repos/r1.repo`).
pub const IDX_REPO: usize = 1;
/// Slot 2: the signed index (`/r1/index.aki`).
pub const IDX_INDEX: usize = 2;
/// Slot 3: the 1.0.0 signed package (`/r1/r1.hello-1.0.0.akp` — the
/// install round pins 1.0.0, so the upgrade has something to move).
pub const IDX_PKG_V10: usize = 3;
/// Slot 4: the 1.1.0 signed package (`/r1/r1.hello-1.1.0.akp` — the
/// upgrade round's transaction reads this one; P1-2: its payload is
/// the REAL stripped gcc userland ELF).
pub const IDX_PKG_V11: usize = 4;
/// Slot 5: the netcat client's signed package (`/r1/r1.netcat-1.0.0.akp`
/// — P1-2's third package, a REAL third-party static binary).
pub const IDX_NETCAT: usize = 5;
/// Slot 6: the rustc citizen's signed package (`/r1/r1.rust-hello-1.0.0.akp`
/// — P1-2's fourth package, the Rust compiler path's REAL ELF).
pub const IDX_RUSTHELLO: usize = 6;

static mut SLOTS: [[u8; SLOT_MAX]; SLOT_COUNT] = [[0; SLOT_MAX]; SLOT_COUNT];
static INSTALLED: [AtomicBool; SLOT_COUNT] = [const { AtomicBool::new(false) }; SLOT_COUNT];
static LENS: [AtomicUsize; SLOT_COUNT] = [const { AtomicUsize::new(0) }; SLOT_COUNT];

/// Install `bytes` into slot `idx`. One write, ever: an out-of-range
/// slot, empty or over-long bytes, or a second install is refused
/// (false) — never a silent overwrite, exactly the registry's disk
/// slot contract.
pub fn install(idx: usize, bytes: &[u8]) -> bool {
    if idx >= SLOT_COUNT || bytes.is_empty() || bytes.len() > SLOT_MAX {
        return false;
    }
    if INSTALLED[idx].swap(true, Ordering::AcqRel) {
        return false; // one write per slot, ever
    }
    // SAFETY: the sole write to this slot happens here, once, at
    // boot (driver stack, IF=0, before any domain that could read
    // the store exists); the claim above guarantees no second writer,
    // and the length is published after the bytes (Release below)
    // so no reader sees them half-written. Single CPU — no
    // concurrent access exists to exclude.
    unsafe {
        SLOTS[idx][..bytes.len()].copy_from_slice(bytes);
    }
    LENS[idx].store(bytes.len(), Ordering::Release);
    true
}

/// Is every slot installed — the store the K22 provisioning expects?
/// `complete()` gating the probe chain is what makes a missing disk
/// a LOUD provisioning failure instead of half-written repo files.
#[must_use]
pub fn complete() -> bool {
    INSTALLED.iter().all(|f| f.load(Ordering::Acquire))
}

/// The installed bytes of slot `idx` (`None` when the slot is out of
/// range or was never installed). The slice borrows a static: the
/// bytes are the disk's own, read-only for the boot's life.
#[must_use]
pub fn file(idx: usize) -> Option<&'static [u8]> {
    if idx >= SLOT_COUNT || !INSTALLED[idx].load(Ordering::Acquire) {
        return None;
    }
    let len = LENS[idx].load(Ordering::Acquire);
    if len == 0 {
        return None; // claim without bytes — unreachable by the
                     // writer's contract, refused anyway
    }
    // SAFETY: the slot was written once at install time (before any
    // domain that could read it existed) and never written again;
    // the length was published after the bytes (Release/Acquire).
    // The slice borrows a static — read-only for the boot's life.
    Some(unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(SLOTS[idx]) as *const u8, len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store's own contract, driven on the host: a round trip
    /// through `install`/`file`, the write-once refusal, and the
    /// bounds refusals. Slot 2 only — the statics are per-process
    /// and the host test threads share them.
    #[test]
    fn a_slot_round_trips_and_never_rewrites() {
        let body: Vec<u8> = (0..700usize).map(|i| (i % 253) as u8).collect();
        assert!(install(IDX_INDEX, &body));
        assert_eq!(file(IDX_INDEX), Some(&body[..]));
        // Write-once: the same slot refuses a second install, and the
        // ORIGINAL bytes are what stays.
        assert!(!install(IDX_INDEX, b"overwriter"));
        assert_eq!(file(IDX_INDEX), Some(&body[..]));
        // Bounds: an out-of-range slot, empty bytes, over-long bytes.
        assert!(!install(SLOT_COUNT, b"x"));
        assert!(!install(IDX_TRUST, b""));
        assert!(!install(IDX_TRUST, &[0u8; SLOT_MAX + 1]));
        // An untouched slot reads as nothing (never zeros).
        assert_eq!(file(IDX_TRUST), None);
        // The named const pair stays a pair: FILE_ORDER drives the
        // walk, SLOT_COUNT bounds it.
        assert_eq!(FILE_ORDER.len(), SLOT_COUNT);
    }
}
