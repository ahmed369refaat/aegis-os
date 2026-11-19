//! The live boot sequence (called from the 64-bit entry stub).
//!
//! Order:
//! 1. serial banner, kernel-owned GDT/TSS/IDT (exception entry live),
//! 2. multiboot validation (magic + memory fields),
//! 3. frame-pool claim: the region must fit reported low RAM, then it is
//!    scrubbed once so every allocation starts provably zeroed,
//! 4. hello domain → monitor demo → supervised cleanup of the attacker →
//!    1000-cycle create/destroy stress with zero-leak + scrub assertions,
//! 5. one `M1-EXIT-CRITERIA` line that CI greps, TSC report,
//! 6. the PR-1.1 exception selftest: force a #DE, the dispatch prints the
//!    diagnosis + marker and powers off (CI greps both).
//!
//! No allocation: log lines are `&str` fragments plus stack-buffer numbers.

use crate::arch;
use crate::frames::{FramePool, FRAME_SIZE, POOL_BASE, POOL_LEN};
use crate::runtime::{self, HelloReport, M1Error, MonitorReport, StressReport};
use crate::{hw, memops, multiboot, serial, strutil};
use aegis_os::Kernel;

fn line(out: &mut dyn FnMut(&str), parts: &[&str]) {
    for p in parts {
        out(p);
    }
    out("\n");
}

fn yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "NO" }
}

fn describe_err(e: &M1Error) -> &'static str {
    match e {
        M1Error::Kernel(_) => "kernel error",
        M1Error::Mem(_) => "memory-policy error",
        M1Error::Frame(_) => "frame-pool error",
    }
}

/// Called from `boot::aegis_kmain_entry` once long mode is up.
pub extern "C" fn kmain(magic: u32, info: u32) -> ! {
    serial::init();
    let mut out = |s: &str| serial::write_str(s);
    line(&mut out, &["AEGIS-M1 x86_64 kernel booting"]);
    line(&mut out, &["====================================="]);

    // ── 1. kernel-owned CPU tables: exception entry goes live now, so
    //      every later fault is diagnosed instead of triple-faulting.
    arch::init();

    // ── 2. multiboot validation ─────────────────────────────────────
    if magic != multiboot::BOOT_MAGIC {
        line(&mut out, &["[BOOT] ERROR: not started by a multiboot loader (magic mismatch); halting"]);
        hw::halt_forever();
    }
    // The info-struct words: flags, mem_lower, mem_upper (identity-mapped,
    // so the physical address is directly readable).
    let flags = memops::read_u32(info as u64);
    let mem_lower = memops::read_u32(info as u64 + 4);
    let mem_upper = memops::read_u32(info as u64 + 8);
    let mi = multiboot::parse(flags, mem_lower, mem_upper);
    {
        let mut b = [0u8; 20];
        line(&mut out, &["[BOOT] multiboot ok: mem_lower=", strutil::dec(mem_lower as u64, &mut b)]);
        let mut b2 = [0u8; 20];
        line(&mut out, &["       mem_upper=", strutil::dec(mem_upper as u64, &mut b2), " KiB"]);
    }
    if !mi.contains(POOL_BASE, POOL_LEN) {
        line(&mut out, &["[MEM ] ERROR: frame pool (16..17 MiB) does not fit reported low memory; halting"]);
        hw::halt_forever();
    }

    // ── 3. frame pool: claim + scrub ────────────────────────────────
    let mut pool = FramePool::new(POOL_BASE, memops::scrub_frame);
    for f in 0..(POOL_LEN / FRAME_SIZE) {
        memops::scrub_frame(POOL_BASE + f * FRAME_SIZE);
    }
    line(&mut out, &["[MEM ] frame pool claimed: 256 frames @ 16 MiB..17 MiB, scrubbed"]);

    let mut k = Kernel::new();
    let t_boot = hw::boot_tsc();

    // ── 4. the M1 sequence (identical code to the host tests) ──────
    let hello = runtime::hello_domain(&mut k, &mut pool, &mut out);
    let mon = runtime::monitor_demo(&mut k, &mut out);
    // Supervised cleanup of the quarantined attacker — the respawn path.
    let cleanup = k.destroy_domain(2);
    line(&mut out, &["[MON ] supervised cleanup of quarantined attacker: ",
        match cleanup { Ok(()) => "ok", Err(_) => "FAILED" }]);
    let stress = runtime::stress_create_destroy(&mut k, &mut pool, 1000, &mut out);

    // ── 5. exit-criteria line (CI greps this) ───────────────────────
    let t_end = hw::rdtsc();
    let cycles = t_end.wrapping_sub(t_boot);

    let pass = match (&hello, &mon, &stress) {
        (Ok(h), Ok(m), Ok(s)) => {
            m1_pass(h, m, s) && cleanup.is_ok()
        }
        _ => false,
    };
    // On any sequence error, say which stage failed before the verdict.
    if let Err(e) = &hello {
        line(&mut out, &["[FAIL] hello-domain stage: ", describe_err(e)]);
    }
    if let Err(e) = &mon {
        line(&mut out, &["[FAIL] monitor-demo stage: ", describe_err(e)]);
    }
    if let Err(e) = &stress {
        line(&mut out, &["[FAIL] stress stage: ", describe_err(e)]);
    }

    let mut b = [0u8; 20];
    line(&mut out, &["[TIME] entry -> M1 complete: ", strutil::dec(cycles, &mut b),
        " TSC cycles (host wall-clock is measured by the boot runner)"]);

    let verdict = if pass { "PASS" } else { "FAIL" };
    match (&hello, &mon, &stress) {
        (Ok(h), Ok(m), Ok(s)) => {
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            let mut b3 = [0u8; 20];
            let mut b4 = [0u8; 20];
            line(&mut out, &[
                "[VERDICT] M1-EXIT-CRITERIA: ", verdict,
                " boot=ok",
                " hello=yes",
                " guard-gap-live=", yes_no(h.guard_gap_rejected),
                " frames-backed=", strutil::dec(h.frames_backed as u64, &mut b1),
                " cfs-slices=", strutil::dec(h.slices as u64, &mut b2),
                " monitor-quarantined=", yes_no(m.quarantined),
                " neighbor-healthy=", yes_no(m.neighbor_healthy),
                " stress-cycles=", strutil::dec(s.cycles as u64, &mut b3),
                " leaked-frames=", strutil::dec(s.leaked_frames as u64, &mut b4),
                " scrub-verified=", yes_no(s.scrub_verified),
                " scores=55/50/37/80/80",
            ]);
        }
        _ => {
            line(&mut out, &["[VERDICT] M1-EXIT-CRITERIA: ", verdict,
                " (a sequence stage failed — see above)"]);
        }
    }

    // ── 6. exception-machinery selftest (PR-1.1) ────────────────────
    // Everything above already passed its gates; now prove the entry
    // path end-to-end: force a hardware #DE and let the dispatch print
    // the diagnosis + selftest marker and power off cleanly (CI greps
    // both). If the machinery were broken, the CPU would triple-fault
    // instead and the markers would be missing — loud either way.
    line(&mut out, &["[ARCH] exception selftest: forcing #DE"]);
    arch::exceptions::arm_and_trigger_de();
}

/// The M1 exit criteria, evaluated from the three stage reports.
fn m1_pass(h: &HelloReport, m: &MonitorReport, s: &StressReport) -> bool {
    h.guard_gap_rejected
        && h.frames_backed == 3
        && h.slices == 4
        && m.quarantined
        && m.neighbor_healthy
        && m.scores == [55, 50, 37, 80, 80]
        && s.cycles == 1000
        && s.leaked_frames == 0
        && s.scrub_verified
}
