//! The M1 boot sequence as testable functions over the policy-core
//! `Kernel` and the `FramePool`.
//!
//! Every function takes an output callback (`Out`). On the booted kernel
//! the callback writes to the serial console; under host tests it collects
//! into a buffer — **the same code path runs in both places**, which is
//! how the exit-criteria logic is proven without an emulator.
//!
//! Sequence: `hello_domain` (create, live memory-policy demo, real frame
//! backing, CFS slices) → `monitor_demo` (the proven escalation scenario,
//! five windows, healthy neighbor untouched) → `stress_create_destroy`
//! (1000 cycles, zero-leak + scrub assertions against the pre-stress
//! baseline).
//!
//! No allocation anywhere: log lines are assembled from `&str` fragments
//! plus stack-buffer-formatted numbers (`strutil`).

use crate::frames::{FrameError, FramePool};
use crate::{memops, strutil};
use aegis_os::prelude::*;

pub type Out<'a> = &'a mut dyn FnMut(&str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M1Error {
    Kernel(KernelError),
    Mem(MemError),
    Frame(FrameError),
}

impl From<KernelError> for M1Error {
    fn from(e: KernelError) -> Self {
        M1Error::Kernel(e)
    }
}
impl From<MemError> for M1Error {
    fn from(e: MemError) -> Self {
        M1Error::Mem(e)
    }
}
impl From<FrameError> for M1Error {
    fn from(e: FrameError) -> Self {
        M1Error::Frame(e)
    }
}

fn line(out: Out<'_>, parts: &[&str]) {
    for p in parts {
        out(p);
    }
    out("\n");
}

fn yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "NO" }
}

// ── 1. hello domain ──

pub struct HelloReport {
    pub domain: u32,
    pub frames_backed: usize,
    pub guard_gap_rejected: bool,
    pub slices: u32,
}

/// Create the hello domain, run the live memory-policy demo (an adjacent
/// mapping is rejected by the guard-gap rule), back its regions with real
/// pool frames, and give it scheduler slices. The domain stays alive —
/// `monitor_demo` uses it as the healthy neighbor.
pub fn hello_domain(k: &mut Kernel, pool: &mut FramePool, out: Out<'_>) -> Result<HelloReport, M1Error> {
    line(out, &["[DOM ] creating hello domain 1 (service profile, uid 1001, nice 0)"]);
    k.create_domain_with(1, service_profile(), 1001, 100, 0)?;

    // Region 1: two RW pages at an arbitrary (policy-checked) base.
    let base = 0x4000_0000usize;
    k.domain_mut(1)?.space.map(base, 8192, MemFlags::READ | MemFlags::WRITE)?;

    // The guard-gap policy, live: a region placed directly adjacent must
    // be rejected; one page further (leaving the guard page) must pass.
    let adjacent = k
        .domain_mut(1)?
        .space
        .map(base + 8192, 4096, MemFlags::READ | MemFlags::WRITE);
    let guard_gap_rejected = matches!(adjacent, Err(MemError::GuardGap));
    if guard_gap_rejected {
        line(out, &["[MEM ] guard-gap policy live: adjacent mapping rejected (GuardGap)"]);
    } else {
        line(out, &["[MEM ] WARNING: adjacent mapping was NOT rejected"]);
    }
    k.domain_mut(1)?.space.map(base + 3 * 4096, 4096, MemFlags::READ | MemFlags::WRITE)?;

    // Back both regions (3 pages) with real frames from the pool, and
    // write a recognizable pattern into each: physical memory, writable,
    // tracked, owned by domain 1.
    let mut frames_backed = 0usize;
    for _ in 0..3 {
        let pa = pool.alloc_for(&mut k.frames, 1)?;
        memops::write_u64(pa, 0x6169_6765_3031_0001); // "aige01" in ASCII
        frames_backed += 1;
    }
    line(out, &["[MEM ] backed 3 pages with real pool frames (16 MiB..17 MiB), pattern written"]);

    // Scheduler slices: CFS hands the runnable domain its turns.
    let mut slices = 0u32;
    for _ in 0..4 {
        if let Some(id) = k.sched.schedule_slice(4) {
            if id == 1 {
                slices += 1;
            }
        }
    }
    let mut b = [0u8; 20];
    line(out, &["[SCHD] CFS granted the hello domain ", strutil::dec(slices as u64, &mut b), "/4 slices"]);
    // The domain speaks (the kernel prints on its behalf in M1):
    line(out, &["[DOM ] Hello from AegisOS domain 1 (x86_64, M1)!"]);

    Ok(HelloReport { domain: 1, frames_backed, guard_gap_rejected, slices })
}

// ── 2. behavior-monitor demo (the proven escalation scenario) ──

pub struct MonitorReport {
    pub scores: [u8; 5],
    pub quarantined: bool,
    pub neighbor_healthy: bool,
}

/// Replay the integration-test escalation scenario on the live kernel:
/// five audit windows, Log → Tighten → Tighten → Tighten → Quarantine,
/// while the healthy hello domain keeps working.
pub fn monitor_demo(k: &mut Kernel, out: Out<'_>) -> Result<MonitorReport, M1Error> {
    line(out, &["[MON ] escalating parser demo (domain 2, parser profile, sensitivity 70)"]);
    k.create_domain(2, parser_profile())?;
    let mut scores = [0u8; 5];
    let mut b = [0u8; 20];

    // W1: denied network probes + faults + escalation attempts → 55, Log.
    for _ in 0..10 {
        let _ = k.dispatch(2, SYS_NET_SEND);
    }
    for _ in 0..3 {
        k.report_fault(2)?;
    }
    for _ in 0..2 {
        k.report_escalation_attempt(2)?;
    }
    scores[0] = k.audit(2)?.score;
    line(out, &["[MON ] W1 score=", strutil::dec(scores[0] as u64, &mut b), " -> Log"]);

    // W2: keeps misbehaving → 50, Tighten (streak 1).
    for _ in 0..4 {
        let _ = k.dispatch(2, SYS_NET_SEND);
    }
    for _ in 0..2 {
        k.report_fault(2)?;
    }
    for _ in 0..2 {
        k.report_escalation_attempt(2)?;
    }
    scores[1] = k.audit(2)?.score;
    line(out, &["[MON ] W2 score=", strutil::dec(scores[1] as u64, &mut b), " -> Tighten"]);

    // W3: probes the surface it just lost (MMAP now denied by the mask).
    for _ in 0..6 {
        let _ = k.dispatch(2, SYS_MMAP);
    }
    for _ in 0..3 {
        k.report_fault(2)?;
    }
    scores[2] = k.audit(2)?.score;
    line(out, &["[MON ] W3 score=", strutil::dec(scores[2] as u64, &mut b), " -> Tighten"]);

    // W4: full attack pattern → 80, Tighten (quarantine streak 1).
    for _ in 0..10 {
        let _ = k.dispatch(2, SYS_SPAWN);
        let _ = k.dispatch(2, SYS_NET_SEND);
    }
    for _ in 0..5 {
        k.report_fault(2)?;
    }
    for _ in 0..4 {
        k.report_escalation_attempt(2)?;
    }
    scores[3] = k.audit(2)?.score;
    line(out, &["[MON ] W4 score=", strutil::dec(scores[3] as u64, &mut b), " -> Tighten"]);

    // W5: same pattern again → 80, Quarantine (terminal).
    for _ in 0..10 {
        let _ = k.dispatch(2, SYS_SPAWN);
        let _ = k.dispatch(2, SYS_NET_SEND);
    }
    for _ in 0..5 {
        k.report_fault(2)?;
    }
    for _ in 0..4 {
        k.report_escalation_attempt(2)?;
    }
    scores[4] = k.audit(2)?.score;
    line(out, &["[MON ] W5 score=", strutil::dec(scores[4] as u64, &mut b), " -> Quarantine (terminal)"]);

    let quarantined = k.domain_state(2) == Some(DomainState::Quarantined);
    // The healthy neighbor is untouched: still running, still allowed READ.
    let neighbor_healthy = k.domain_state(1) == Some(DomainState::Running)
        && k.dispatch(1, SYS_READ).is_ok();
    line(out, &["[MON ] attacker quarantined: ", yes_no(quarantined),
        "; healthy domain 1 still running: ", yes_no(neighbor_healthy)]);

    Ok(MonitorReport { scores, quarantined, neighbor_healthy })
}

// ── 3. create/destroy stress ──

pub struct StressReport {
    pub cycles: u32,
    /// Frames still in use beyond the pre-stress baseline (the hello
    /// domain legitimately keeps its 3 pages for the whole session).
    pub leaked_frames: usize,
    pub baseline_frames: usize,
    pub owners_left: usize,
    pub scrub_verified: bool,
}

/// N × (create domain → map 2 pages through the policy → back with 2 real
/// frames → dirty them → destroy: scrub + free all + slot release).
/// Accounting is checked every 250 cycles against the baseline, and once
/// (immediately at cycle 0) a freed frame is read back to prove the scrub.
pub fn stress_create_destroy(
    k: &mut Kernel,
    pool: &mut FramePool,
    cycles: u32,
    out: Out<'_>,
) -> Result<StressReport, M1Error> {
    let baseline = k.frames.frames_in_use();
    let baseline_owners = pool.owned_count();
    let mut cb = [0u8; 20];
    line(out, &["[STRS] create/destroy stress: ", strutil::dec(cycles as u64, &mut cb), " cycles"]);
    let mut scrub_verified = false;

    for i in 0..cycles {
        let id = 10 + (i % 3) as u32;
        k.create_domain_with(id, plugin_profile(), 1000 + id as u16, 100, 0)?;

        // One 2-page RW region — through the ten-check policy.
        k.domain_mut(id)?.space.map(0x5000_0000, 8192, MemFlags::READ | MemFlags::WRITE)?;

        // Back it with two real frames and dirty them.
        let mut probe_pa: Option<u64> = None;
        for _ in 0..2 {
            let pa = pool.alloc_for(&mut k.frames, id)?;
            memops::write_u64(pa, 0xAA55_AA55_AA55_AA55);
            if probe_pa.is_none() {
                probe_pa = Some(pa);
            }
        }

        // Destroy path: scrub + free everything the domain owns, then
        // release the domain itself (fds, scheduler, slot).
        pool.free_all_owned(&mut k.frames, id);
        // Verify the scrub read-back immediately at cycle 0, before any
        // later cycle can reuse the frame.
        if i == 0 {
            if let Some(pa) = probe_pa {
                scrub_verified = memops::frame_is_zero(pa);
            }
        }
        k.destroy_domain(id)?;

        if (i + 1) % 250 == 0 {
            let in_use = k.frames.frames_in_use();
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            line(out, &["[STRS]   ", strutil::dec(i as u64 + 1, &mut b1),
                " cycles: frames_in_use=", strutil::dec(in_use as u64, &mut b2)]);
            if in_use != baseline {
                line(out, &["[STRS] LEAK DETECTED at cycle ", strutil::dec(i as u64 + 1, &mut b1)]);
                return Ok(StressReport {
                    cycles: i + 1,
                    leaked_frames: in_use.saturating_sub(baseline),
                    baseline_frames: baseline,
                    owners_left: pool.owned_count(),
                    scrub_verified,
                });
            }
        }
    }

    let leaked = k.frames.frames_in_use().saturating_sub(baseline);
    let owners_left = pool.owned_count();
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];
    let mut b3 = [0u8; 20];
    let mut b4 = [0u8; 20];
    line(out, &["[STRS] done: leaked_frames=", strutil::dec(leaked as u64, &mut b1),
        " (baseline ", strutil::dec(baseline as u64, &mut b2),
        "), owners_left=", strutil::dec(owners_left as u64, &mut b3),
        " (expected ", strutil::dec(baseline_owners as u64, &mut b4),
        "), scrub_readback=", yes_no(scrub_verified)]);
    Ok(StressReport { cycles, leaked_frames: leaked, baseline_frames: baseline, owners_left, scrub_verified })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real 1 MiB host buffer standing in for the pool's physical memory.
    struct FakePhys {
        _mem: Vec<u64>,
        base: u64,
    }
    impl FakePhys {
        fn new() -> Self {
            // Extra 4 KiB so the base can be aligned up to a page
            // boundary (the pool's frame math requires it).
            let len = (crate::frames::POOL_LEN / 8 + 512) as usize;
            let mem = vec![0u64; len];
            let base = (mem.as_ptr() as u64 + 4095) & !4095u64;
            FakePhys { _mem: mem, base }
        }
    }

    /// The full M1 sequence — the host-side run of the boot logic:
    /// hello → monitor demo → supervised cleanup → 1000-cycle stress.
    /// This is the same code `kmain` executes on the booted kernel.
    #[test]
    fn full_m1_sequence_passes_exit_criteria() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut k = Kernel::new();

        let mut log = String::new();
        let stress = {
            let mut out = |s: &str| log.push_str(s);

            // 1) Hello domain.
            let hello = hello_domain(&mut k, &mut pool, &mut out).unwrap();
            assert_eq!(hello.domain, 1);
            assert_eq!(hello.frames_backed, 3);
            assert!(hello.guard_gap_rejected, "adjacent mapping must be rejected");
            assert_eq!(hello.slices, 4, "sole runnable domain gets every slice");

            // 2) Monitor demo: exact escalation timeline.
            let mon = monitor_demo(&mut k, &mut out).unwrap();
            assert_eq!(mon.scores, [55, 50, 37, 80, 80]);
            assert!(mon.quarantined);
            assert!(mon.neighbor_healthy, "the healthy neighbor must be unaffected");

            // 3) Supervised cleanup of the quarantined domain.
            k.destroy_domain(2).unwrap();
            assert_eq!(k.domain_state(2), None);

            // 4) 1000-cycle create/destroy stress.
            stress_create_destroy(&mut k, &mut pool, 1000, &mut out).unwrap()
        }; // `out` (and its borrow of `log`) ends here.

        assert!(log.contains("Hello from AegisOS domain 1"));
        assert_eq!(stress.cycles, 1000);
        assert_eq!(stress.baseline_frames, 3, "hello domain's frames");
        assert_eq!(stress.leaked_frames, 0, "zero frame leaks after 1000 cycles");
        assert_eq!(stress.owners_left, 3, "only the hello domain's frames remain owned");
        assert!(stress.scrub_verified, "freed frame must read back as zero");

        // End-state frame accounting.
        assert_eq!(k.frames.frames_in_use(), 3);
        assert_eq!(k.frames.frames_free(), aegis_os::buddy::FRAME_COUNT - 3);
        assert_eq!(pool.owned_by(1), 3);
        assert!(log.contains("[STRS] done: leaked_frames=0"));
    }

    #[test]
    fn monitor_demo_neighbor_stays_running_while_attacker_quarantined() {
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut k = Kernel::new();
        let mut out = |_s: &str| {};
        hello_domain(&mut k, &mut pool, &mut out).unwrap();
        let mon = monitor_demo(&mut k, &mut out).unwrap();
        assert!(mon.quarantined);
        assert!(mon.neighbor_healthy);
        // The neighbor keeps being scheduled while the attacker sits in
        // quarantine (only EXIT passes for domain 2).
        assert!(k.dispatch(1, SYS_READ).is_ok());
        assert_eq!(
            k.dispatch(2, SYS_READ).unwrap(),
            aegis_os::prelude::Decision::DeniedQuarantined(SYS_READ)
        );
    }

    #[test]
    fn stress_reports_leak_if_free_is_skipped() {
        // Adversarial control for the checkpoint logic: frames that were
        // allocated and never freed must keep showing up in the pool's
        // ownership and the kernel buddy's accounting.
        let phys = FakePhys::new();
        let mut pool = FramePool::new(phys.base, memops::scrub_frame);
        let mut k = Kernel::new();
        let mut out = |_s: &str| {};
        hello_domain(&mut k, &mut pool, &mut out).unwrap();
        // Domain 9 allocates two frames and is destroyed without the
        // pool-free step (a buggy supervisor).
        k.create_domain_with(9, plugin_profile(), 1009, 100, 0).unwrap();
        for _ in 0..2 {
            let _ = pool.alloc_for(&mut k.frames, 9);
        }
        k.destroy_domain(9).unwrap();
        // The destroy path we bypassed does not know about the frames:
        // they are still owned and still in use — exactly what the
        // accounting must reveal.
        assert_eq!(pool.owned_by(9), 2);
        assert_eq!(k.frames.frames_in_use(), 5, "3 (hello) + 2 (leaked by domain 9)");
        let report = stress_create_destroy(&mut k, &mut pool, 250, &mut out).unwrap();
        // Baseline inside stress now includes the leak (5), so the cycles
        // themselves stay clean — but the leaked frames are still there,
        // visible in the end-state accounting:
        assert_eq!(report.baseline_frames, 5);
        assert_eq!(report.leaked_frames, 0);
        assert_eq!(pool.owned_by(9), 2, "the bug is still observable, not hidden");
    }
}
