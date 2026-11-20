//! # aegis-kernel (x86_64)
//!
//! The bootable AegisOS kernel (M1 + Stage 1 complete, M2 in progress):
//! multiboot bring-up, the transition to 64-bit long mode, a real
//! physical frame pool behind the policy core's buddy allocator
//! (scrubbed on every free), the M1 exit-criteria sequence, per-domain
//! page tables with SMEP/SMAP and kernel-image W^X (PR-1.3, ADR-0006/
//! 0008), SYSCALL/SYSRET ring-3 execution with the full seven-run
//! isolation sequence (PR-1.4 + ADR-0010), and — since M2-W2 — the
//! LAPIC timer driving interrupt-driven CFS preemption between parked
//! ring-3 runs (ADR-0012).
//!
//! ## Unsafe policy (enforced by CI)
//!
//! The policy core (`aegis_os`) is `#![forbid(unsafe_code)]`. This crate is
//! `#![deny(unsafe_code)]` at the root, and exactly five module groups
//! carry an inner `#![allow(unsafe_code)]` with per-item `SAFETY`
//! documentation:
//!
//! - [`arch`] — CPU tables and exception entry: GDT/TSS/IDT/GS-base
//!   setup, naked entry stubs, the fault dispatch, the LAPIC timer's
//!   IDT wiring (PR-1.1 onward; see `docs/adr/0005-exception-machinery.md`).
//! - [`boot`] — entry assembly, page-table handoff: raw CPU control that
//!   only exists at bring-up time.
//! - [`hw`] — port I/O, `rdtsc`, `cr2`/`cr3`, `invlpg`, MSRs,
//!   halt/poweroff: single-instruction wrappers.
//! - [`memops`] — volatile reads/writes; physical addresses reach RAM
//!   through the direct map.
//! - [`sched`] — the ring-3 launch/resume pair, the parked-run table,
//!   and the timer's context switch (PR-1.4 / ADR-0012).
//!
//! Notably **unsafe-free by design**: [`mm`] (the memory-layout layer —
//! all its raw access goes through `memops`/`hw`), the LAPIC driver
//! (`arch::lapic` — same discipline), the tick orchestration
//! (`sched::preempt`), and the whole policy core.
//! `scripts/check_unsafe.sh` fails the build if `unsafe` appears
//! anywhere else in the repository.
//!
//! ## Scope (stated honestly)
//!
//! Ring-3 execution, per-domain page tables, and timer preemption are
//! LIVE (seven-run isolation sequence + the starvation-freedom proof,
//! asserted by `boot.sh --verify`). Not yet: the full ring-3 syscall
//! surface (WRITE/EXIT today), SMP, demand paging/COW, the ELF loader
//! — see `docs/GAP-ANALYSIS-v2.md` for the honest full-scope picture.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_code)]

pub mod arch;
#[cfg(not(test))]
pub mod boot;
#[cfg(not(test))]
pub mod drvstack;
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
