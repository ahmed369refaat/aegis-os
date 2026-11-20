//! # aegis-kernel (x86_64)
//!
//! The bootable AegisOS kernel (M1 complete, Stage 1 in progress):
//! multiboot bring-up, the transition to 64-bit long mode, a real
//! physical frame pool behind the policy core's buddy allocator
//! (scrubbed on every free), the M1 exit-criteria sequence (a hello
//! domain scheduled by CFS, the behavior monitor escalating a
//! misbehaving parser live, a 1000-cycle create/destroy stress with
//! zero-leak and scrub assertions) — and, since PR-1.1/PR-1.2, a
//! kernel-owned GDT/TSS/IDT with a uniform exception entry path, a
//! higher-half kernel over a direct map with the bring-up identity
//! window torn down, guarded kernel stacks, and per-CPU state (ADR-0002).
//!
//! ## Unsafe policy (enforced by CI)
//!
//! The policy core (`aegis_os`) is `#![forbid(unsafe_code)]`. This crate is
//! `#![deny(unsafe_code)]` at the root, and exactly four module groups
//! carry an inner `#![allow(unsafe_code)]` with per-item `SAFETY`
//! documentation:
//!
//! - [`arch`] — CPU tables and exception entry: GDT/TSS/IDT/GS-base
//!   setup, naked entry stubs, the fault dispatch (PR-1.1 onward; see
//!   `docs/adr/0005-exception-machinery.md`).
//! - [`boot`] — entry assembly, page-table handoff: raw CPU control that
//!   only exists at bring-up time.
//! - [`hw`] — port I/O, `rdtsc`, `cr2`/`cr3`, `invlpg`, MSRs,
//!   halt/poweroff: single-instruction wrappers.
//! - [`memops`] — volatile reads/writes; physical addresses reach RAM
//!   through the direct map.
//!
//! Notably **unsafe-free by design**: [`mm`] (the memory-layout layer —
//! all its raw access goes through `memops`/`hw`) and the whole policy
//! core. `scripts/check_unsafe.sh` fails the build if `unsafe` appears
//! anywhere else in the repository.
//!
//! ## Stage-1 scope (stated honestly)
//!
//! Domains are still kernel-resident objects: their region mappings pass
//! the full ten-check memory policy and their pages are real, tracked,
//! scrubbed pool frames — but there are no per-domain page tables and no
//! ring-3 execution yet (PR-1.3..1.5, see `docs/ROADMAP.md` and
//! `docs/STAGE1-PR-PLAN.md`).

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_code)]

pub mod arch;
#[cfg(not(test))]
pub mod boot;
#[cfg(not(test))]
pub mod kmain;
pub mod mm;
#[cfg(not(test))]
pub mod serial;

pub mod frames;
#[cfg(not(test))]
pub mod hw;
pub mod memops;
pub mod multiboot;
pub mod runtime;
pub mod sched;
pub mod strutil;
#[cfg(not(test))]
pub mod syscall;

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
