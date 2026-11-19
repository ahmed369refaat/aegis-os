//! # aegis-kernel (x86_64)
//!
//! The bootable AegisOS **M1** kernel: multiboot bring-up, the transition to
//! 64-bit long mode with identity paging, a real physical frame pool behind
//! the policy core's buddy allocator (scrubbed on every free), and the M1
//! exit-criteria sequence: a hello domain scheduled by CFS, the behavior
//! monitor escalating a misbehaving parser live, and a 1000-cycle
//! create/destroy stress with zero-leak and scrub assertions.
//!
//! ## Unsafe policy (enforced by CI)
//!
//! The policy core (`aegis_os`) is `#![forbid(unsafe_code)]`. This crate is
//! `#![deny(unsafe_code)]` at the root, and exactly three modules carry an
//! inner `#![allow(unsafe_code)]` with per-item `SAFETY` documentation:
//!
//! - [`boot`] — entry assembly, GDT, page tables: raw CPU control that only
//!   exists at bring-up time.
//! - [`hw`] — port I/O, `rdtsc`, halt/poweroff: single-instruction wrappers.
//! - [`memops`] — volatile reads/writes over (identity-mapped) physical
//!   addresses, i.e. scrubbing.
//!
//! Every other line of this crate is safe Rust. `scripts/check_unsafe.sh`
//! fails the build if `unsafe` appears anywhere else in the repository.
//!
//! ## M1 scope (stated honestly)
//!
//! Domains at this stage are kernel-resident objects: their region mappings
//! pass the full ten-check memory policy and their pages are real, tracked,
//! scrubbed pool frames — but there are no per-domain page tables and no
//! ring-3 execution yet. Those are M2 work. See `docs/M1-PLAN.md`.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_code)]

#[cfg(not(test))]
pub mod boot;
#[cfg(not(test))]
pub mod kmain;
#[cfg(not(test))]
pub mod serial;

pub mod frames;
#[cfg(not(test))]
pub mod hw;
pub mod memops;
pub mod multiboot;
pub mod runtime;
pub mod strutil;

/// Boot-path panic handler: print what we can over serial and halt.
/// Panics after serial init produce a visible message; panics before it
/// simply halt (nothing is observable anyway).
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    crate::serial::write_str("\n[PANIC] ");
    if let Some(s) = info.message().as_str() {
        crate::serial::write_str(s);
    }
    if let Some(loc) = info.location() {
        crate::serial::write_str(" @ ");
        crate::serial::write_str(loc.file());
        crate::serial::write_str(":");
        let mut buf = [0u8; 20];
        crate::serial::write_str(crate::strutil::dec(loc.line() as u64, &mut buf));
    }
    crate::serial::write_str("\n[PANIC] system halted.\n");
    crate::hw::halt_forever()
}
