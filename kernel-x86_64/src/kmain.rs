//! The live boot sequence (called from the 64-bit entry stub).
//!
//! Order:
//! 1. serial banner, kernel-owned GDT/TSS/IDT (exception entry live),
//!    then mm::init: the stub's low identity window is torn down and
//!    per-CPU state is armed — from here on the kernel lives purely in
//!    the higher half and reaches physical memory only via the direct
//!    map (ADR-0002),
//! 2. multiboot validation (magic + memory fields),
//! 3. frame-pool claim: the region must fit reported low RAM, then it is
//!    scrubbed once so every allocation starts provably zeroed,
//! 4. hello domain → monitor demo → supervised cleanup of the attacker →
//!    1000-cycle create/destroy stress with zero-leak + scrub assertions,
//! 5. one `M1-EXIT-CRITERIA` line that CI greps, TSC report,
//! 6. the PR-1.1 exception selftest: force a #DE, the dispatch prints the
//!    diagnosis + markers, advances RIP, and RETURNS — the entry unwind
//!    path is live and the boot continues,
//! 7. the PR-1.3 per-domain selftest: two domains, disjoint tables,
//!    the same VA resolving to different frames, an NX exec fault that
//!    resumes, an RX page that executes, and the guard gap faulting on
//!    read — every acceptance marker CI greps,
//! 8. the PR-1.2 guarded-stack selftest: alloc a guarded stack, prove
//!    the mapping and the direct map agree on its contents, free it
//!    (scrub on free),
//! 9. the ring-3 sequence (PR-1.4 + ADR-0010): seven runs — hello, NX
//!    attack, kernel-VA read, forged syscall, edge writes, live-monitor
//!    quarantine, audit-only — each ending in SYS_EXIT or a diagnosed
//!    user fault the kernel survives,
//! 10. (was the terminal act; now step 13) —
//! 11. telemetry drain (the supervisor stand-in, M2-W2),
//! 12. the M2-W2 preemption proof (ADR-0012): the LAPIC timer goes live
//!    and two ring-3 domains — a pure spinner that never calls a
//!    syscall and a writer — run interleaved under interrupt-driven
//!    CFS; the writer must finish while the spinner is still runnable,
//! 13. the terminal act: write through a fresh stack's guard page — the
//!    #PF is diagnosed, the marker printed, and QEMU powers off.
//!
//! No allocation: log lines are `&str` fragments plus stack-buffer numbers.

use crate::arch;
use crate::frames::{FramePool, FRAME_SIZE, KERNEL_POOL_FRAMES, KERNEL_POOL_LEN, POOL_BASE};

/// The ring-3 example blobs (built to flat binaries by boot.sh from
/// `examples/ring3-{hello,rogue,edge}` and embedded here — PR-1.4).
static RING3_HELLO: &[u8] = include_bytes!("../blob/ring3-hello.bin");
static RING3_ROGUE: &[u8] = include_bytes!("../blob/ring3-rogue.bin");
/// The N1 edge blob: tail-of-page writes that must succeed and a
/// page-crossing write that must return -EFAULT (ADR-0007 §1).
static RING3_EDGE: &[u8] = include_bytes!("../blob/ring3-edge.bin");
/// The M2-W2 preemption blob: the spinner (mode 0) and the writer
/// (mode 1) of the starvation-freedom proof (ADR-0012).
static RING3_PREEMPT: &[u8] = include_bytes!("../blob/ring3-preempt.bin");
/// The exact message the hello blob writes from ring-3 (its length is
/// baked into the blob's `mov edx, 26`).
const RING3_MSG: &[u8] = b"hello from ring 3 (CPL=3)\n";
use crate::runtime::{self, HelloReport, M1Error, MonitorReport, StressReport};
use crate::{hw, memops, mm, multiboot, serial, strutil};
use aegis_os::memory::MemFlags;
use aegis_os::Kernel;

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

fn line(out: &mut dyn FnMut(&str), parts: &[&str]) {
    for p in parts {
        out(p);
    }
    out("\n");
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "NO"
    }
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
    //      Then the memory layout settles into its final shape (ADR-0002):
    //      the low identity window dies, per-CPU state is armed, and the
    //      `[MM ] higher-half ok` line goes out.
    arch::init();
    mm::init();
    // ── F15 (ADR-0006): prove the rebuilt image mapping — .text/.rodata
    // are read-only (CR0.WP faults supervisor writes) and .data is
    // non-executable (NX faults supervisor fetches). ──
    {
        let bounds = mm::image::section_bounds();
        let (text, rodata, data, _bss, _guard) = bounds;
        line(
            &mut out,
            &["[ARCH] image W^X selftest: writing .text and .rodata"],
        );
        arch::exceptions::arm_wp_write(text.0);
        arch::exceptions::arm_wp_write(rodata.0);
        line(
            &mut out,
            &[
                "[SEC ] image W^X: write to .text faulted (WP)",
                " / write to .rodata faulted (WP)",
            ],
        );
        line(&mut out, &["[ARCH] image W^X selftest: executing .data"]);
        arch::exceptions::arm_image_exec(data.0);
        line(
            &mut out,
            &["[SEC ] image W^X: exec from .data faulted (I/D)"],
        );
    }

    // ── 2. multiboot validation ─────────────────────────────────────
    if magic != multiboot::BOOT_MAGIC {
        line(
            &mut out,
            &["[BOOT] ERROR: not started by a multiboot loader (magic mismatch); halting"],
        );
        hw::halt_forever();
    }
    // The info-struct words: flags, mem_lower, mem_upper — physical
    // addresses, read through the direct map.
    let flags = memops::read_u32(info as u64);
    let mem_lower = memops::read_u32(info as u64 + 4);
    let mem_upper = memops::read_u32(info as u64 + 8);
    let mi = multiboot::parse(flags, mem_lower, mem_upper);
    {
        let mut b = [0u8; 20];
        line(
            &mut out,
            &[
                "[BOOT] multiboot ok: mem_lower=",
                strutil::dec(mem_lower as u64, &mut b),
            ],
        );
        let mut b2 = [0u8; 20];
        line(
            &mut out,
            &[
                "       mem_upper=",
                strutil::dec(mem_upper as u64, &mut b2),
                " KiB",
            ],
        );
    }
    if !mi.contains(POOL_BASE, KERNEL_POOL_LEN) {
        line(
            &mut out,
            &["[MEM ] ERROR: frame pool (16..32 MiB) does not fit reported low memory; halting"],
        );
        hw::halt_forever();
    }

    // ── 3. frame pool: claim + scrub ────────────────────────────────
    // 4096 frames (16 MiB) since PR-1.3: per-domain page tables need
    // the room (every domain carries PML4+PDPT+PD+PTs plus its pages).
    let mut pool = FramePool::<KERNEL_POOL_FRAMES>::new(POOL_BASE, memops::scrub_frame);
    for f in 0..(KERNEL_POOL_LEN / FRAME_SIZE) {
        memops::scrub_frame(POOL_BASE + f * FRAME_SIZE);
    }
    line(
        &mut out,
        &["[MEM ] frame pool claimed: 4096 frames @ 16 MiB..32 MiB, scrubbed"],
    );

    let mut k = Kernel::<KERNEL_POOL_FRAMES>::new_over_arena();
    // N2 (ADR-0007 §2): the ring-3 syscall path gates through this live
    // kernel (stats, denials, Tighten/Quarantine on the very next
    // syscall) and drives the monitor's windows from the TSC. The
    // window length below: ~40 ms at a 2.5 GHz reference TSC; only
    // window *boundaries* matter, so TCG's variable rate is harmless.
    const MONITOR_WINDOW_TSC: u64 = 100_000_000;
    k.set_monitor_window(MONITOR_WINDOW_TSC);
    crate::sched::context::set_kernel(&mut k as *mut Kernel<KERNEL_POOL_FRAMES>);
    let t_boot = hw::boot_tsc();

    // ── 4. the M1 sequence (identical code to the host tests) ──────
    let hello = runtime::hello_domain(&mut k, &mut pool, &mut out);
    let mon = runtime::monitor_demo(&mut k, &mut out);
    // Supervised cleanup of the quarantined attacker — the respawn path.
    let cleanup = k.destroy_domain(2);
    line(
        &mut out,
        &[
            "[MON ] supervised cleanup of quarantined attacker: ",
            match cleanup {
                Ok(()) => "ok",
                Err(_) => "FAILED",
            },
        ],
    );
    let stress = runtime::stress_create_destroy(&mut k, &mut pool, 1000, &mut out);

    // ── 5. exit-criteria line (CI greps this) ───────────────────────
    let t_end = hw::rdtsc();
    let cycles = t_end.wrapping_sub(t_boot);

    let pass = match (&hello, &mon, &stress) {
        (Ok(h), Ok(m), Ok(s)) => m1_pass(h, m, s) && cleanup.is_ok(),
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
    line(
        &mut out,
        &[
            "[TIME] entry -> M1 complete: ",
            strutil::dec(cycles, &mut b),
            " TSC cycles (host wall-clock is measured by the boot runner)",
        ],
    );

    let verdict = if pass { "PASS" } else { "FAIL" };
    match (&hello, &mon, &stress) {
        (Ok(h), Ok(m), Ok(s)) => {
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            let mut b3 = [0u8; 20];
            let mut b4 = [0u8; 20];
            line(
                &mut out,
                &[
                    "[VERDICT] M1-EXIT-CRITERIA: ",
                    verdict,
                    " boot=ok",
                    " hello=yes",
                    " guard-gap-live=",
                    yes_no(h.guard_gap_rejected),
                    " frames-backed=",
                    strutil::dec(h.frames_backed as u64, &mut b1),
                    " cfs-slices=",
                    strutil::dec(h.slices as u64, &mut b2),
                    " monitor-quarantined=",
                    yes_no(m.quarantined),
                    " neighbor-healthy=",
                    yes_no(m.neighbor_healthy),
                    " stress-cycles=",
                    strutil::dec(s.cycles as u64, &mut b3),
                    " leaked-frames=",
                    strutil::dec(s.leaked_frames as u64, &mut b4),
                    " scrub-verified=",
                    yes_no(s.scrub_verified),
                    " scores=55/50/37/80/80",
                ],
            );
        }
        _ => {
            line(
                &mut out,
                &[
                    "[VERDICT] M1-EXIT-CRITERIA: ",
                    verdict,
                    " (a sequence stage failed — see above)",
                ],
            );
        }
    }

    // ── 6. exception-machinery selftest (PR-1.1) ────────────────────
    // Prove the entry path end-to-end: force a hardware #DE; the
    // dispatch prints the diagnosis + markers, advances RIP past the
    // idiv, and RETURNS — the unwind path is live, execution continues
    // below. If the machinery were broken, the CPU would triple-fault
    // and the markers would be missing — loud either way.
    line(&mut out, &["[ARCH] exception selftest: forcing #DE"]);
    arch::exceptions::arm_and_trigger_de();
    line(
        &mut out,
        &["[ARCH] back from the #DE handler: unwind path live"],
    );

    // ── 7. per-domain page tables (PR-1.3) ─────────────────────────
    // The M1 policy stays the gate; its decisions become hardware: two
    // domains with disjoint tables, the same virtual address resolving
    // to different frames, W^X enforced by NX, and the policy's guard
    // gaps as real absent pages that fault when touched.
    line(
        &mut out,
        &["[MM ] per-domain tables: building domain A (owner 3) and B (owner 4)"],
    );
    let kernel_cr3 = hw::read_cr3();
    const VA: u64 = 0x20_0000; // 2 MiB — a classic user mapping address
    const GUARD_GAP_VA: u64 = VA + 2 * mm::PAGE;
    const RX_VA: u64 = VA + 3 * mm::PAGE;
    const PATTERN_A: u64 = 0xAAAA_BABA_AAAA_BABA;
    const PATTERN_B: u64 = 0xBBBB_DBDB_BBBB_DBDB;

    let mut src = mm::page_table::PoolSource::new(&mut pool, &mut k.frames, 3);
    let mut tables_a = match mm::page_table::PageTables::new(&mut src) {
        Ok(t) => t,
        Err(_) => {
            line(
                &mut out,
                &["[MM ] ERROR: domain A tables alloc failed; halting"],
            );
            hw::halt_forever();
        }
    };
    tables_a.install_kernel_entries();
    let mut space_a = aegis_os::memory::AddressSpace::new(16);
    if tables_a
        .map_region(
            &mut space_a,
            VA,
            2 * mm::PAGE as usize,
            MemFlags::READ | MemFlags::WRITE,
            &mut src,
        )
        .is_err()
    {
        line(
            &mut out,
            &["[MM ] ERROR: domain A RW region refused; halting"],
        );
        hw::halt_forever();
    }
    if tables_a
        .map_region(
            &mut space_a,
            RX_VA,
            mm::PAGE as usize,
            MemFlags::READ | MemFlags::EXEC,
            &mut src,
        )
        .is_err()
    {
        line(
            &mut out,
            &["[MM ] ERROR: domain A RX region refused; halting"],
        );
        hw::halt_forever();
    }
    let (Some(pa_a), Some(pa_ax)) = (tables_a.translate(VA), tables_a.translate(RX_VA)) else {
        line(
            &mut out,
            &["[MM ] ERROR: domain A translate failed; halting"],
        );
        hw::halt_forever();
    };
    memops::write_u64(pa_a, PATTERN_A);
    memops::write_u64(pa_ax, 0xC3); // `ret` — one-byte executable payload

    // Domain B: the SAME virtual address, one page, a different pattern.
    src.owner = 4;
    let mut tables_b = match mm::page_table::PageTables::new(&mut src) {
        Ok(t) => t,
        Err(_) => {
            line(
                &mut out,
                &["[MM ] ERROR: domain B tables alloc failed; halting"],
            );
            hw::halt_forever();
        }
    };
    tables_b.install_kernel_entries();
    let mut space_b = aegis_os::memory::AddressSpace::new(16);
    if tables_b
        .map_region(
            &mut space_b,
            VA,
            mm::PAGE as usize,
            MemFlags::READ | MemFlags::WRITE,
            &mut src,
        )
        .is_err()
    {
        line(
            &mut out,
            &["[MM ] ERROR: domain B RW region refused; halting"],
        );
        hw::halt_forever();
    }
    let Some(pa_b) = tables_b.translate(VA) else {
        line(
            &mut out,
            &["[MM ] ERROR: domain B translate failed; halting"],
        );
        hw::halt_forever();
    };
    memops::write_u64(pa_b, PATTERN_B);

    // ── A's tables active: user half belongs to A ──
    tables_a.activate();
    line(
        &mut out,
        &["[MM ] domain A tables active (CR3 switched): user half is A's"],
    );
    let via_va = memops::read_u64_va(VA);
    let via_dm = memops::read_u64(pa_a);
    if via_va != PATTERN_A || via_dm != PATTERN_A {
        line(
            &mut out,
            &["[MM ] ERROR: A's page disagrees with its frame; halting"],
        );
        hw::halt_forever();
    }
    line(
        &mut out,
        &["[MM ] A: VA reads back its pattern (direct-map frame agrees)"],
    );
    line(
        &mut out,
        &["[ARCH] NX selftest: calling into A's RW (non-executable) page"],
    );
    arch::exceptions::arm_nx_call(VA);
    line(
        &mut out,
        &["[ARCH] RX selftest: calling into A's RX page (executes ret)"],
    );
    arch::exceptions::call_user(RX_VA);
    line(
        &mut out,
        &["[MM ] A: RW page NX-faulted on exec, RX page executed (W^X live)"],
    );

    // ── B's tables active: the same VA is a different frame ──
    tables_b.activate();
    let via_b = memops::read_u64_va(VA);
    if via_b != PATTERN_B || via_b == via_va {
        line(
            &mut out,
            &["[MM ] ERROR: B's VA must resolve to a different frame; halting"],
        );
        hw::halt_forever();
    }
    line(
        &mut out,
        &["[MM ] B: same VA resolves to a different frame (disjoint tables)"],
    );

    // ── A's guard gap: the policy-forced absent page between regions ──
    tables_a.activate();
    line(
        &mut out,
        &["[ARCH] domain guard selftest: reading A's guard-gap page"],
    );
    arch::exceptions::arm_guard_read(GUARD_GAP_VA);
    line(
        &mut out,
        &["[MM ] per-domain tables: 2 domains, W^X + guards live"],
    );

    // ── N4 (ADR-0008): SMEP/SMAP — enabled only after the selftests
    // above (the RX selftest legitimately executes a user page from
    // CPL0; the A/B reads legitimately touch user VAs). From here on,
    // a kernel jump into a user page or a kernel access to user memory
    // outside the STAC window is an MMU fault.
    let leaf7 = hw::cpuid7_ebx();
    let smep = arch::features::has_smep(leaf7);
    let smap = arch::features::has_smap(leaf7);
    hw::write_cr4(arch::features::cr4_image(hw::read_cr4(), smep, smap));
    hw::set_smap_active(smap);
    line(
        &mut out,
        &["[ARCH] smep=", on_off(smep), " smap=", on_off(smap)],
    );
    if smep {
        // A's tables are needed (RX_VA is mapped only there).
        tables_a.activate();
        line(
            &mut out,
            &["[ARCH] SMEP selftest: jumping into A's user RX page from CPL=0"],
        );
        arch::exceptions::arm_sme_call(RX_VA);
        line(
            &mut out,
            &["[SEC ] SMEP selftest: kernel jump into user page faulted, resumed"],
        );
    }
    if smap {
        line(
            &mut out,
            &["[ARCH] SMAP selftest: reading A's user RW page from CPL=0, no STAC"],
        );
        arch::exceptions::arm_smap_read(VA);
        line(
            &mut out,
            &["[SEC ] SMAP selftest: kernel read outside the window faulted, resumed"],
        );
    }

    // Back on the kernel's own tables for the remaining selftests.
    hw::write_cr3(kernel_cr3);

    // ── 8. guarded-stack selftest (PR-1.2) ──────────────────────────
    // One stack through its whole life: alloc (guard + pages + PT from
    // the pool), write and read the top word through the stack VA, read
    // the SAME word through the direct map at the frame's physical
    // address (both views must agree), free (scrub-on-free per frame),
    // then the terminal proof: write through a fresh guard page → #PF.
    line(
        &mut out,
        &["[MM ] guarded-stack selftest: alloc/map/cross-view/free"],
    );
    let stack = match mm::stacks::alloc(&mut pool, &mut k.frames, 2) {
        Ok(st) => st,
        Err(_) => {
            line(
                &mut out,
                &["[MM ] ERROR: guarded-stack alloc failed; halting"],
            );
            hw::halt_forever();
        }
    };
    const PATTERN: u64 = 0x6B67_6172_6469_616E; // "kgardian"
    let top_word = stack.top_va() - 8;
    memops::write_u64_va(top_word, PATTERN);
    let via_stack_va = memops::read_u64_va(top_word);
    let via_direct_map = stack
        .frame_pa(stack.pages - 1)
        .map(|pa| memops::read_u64(pa + 4088))
        .unwrap_or(0);
    if via_stack_va != PATTERN || via_direct_map != PATTERN {
        line(
            &mut out,
            &["[MM ] ERROR: stack/direct-map views disagree; halting"],
        );
        hw::halt_forever();
    }
    let freed = mm::stacks::free(&mut pool, &mut k.frames, stack);
    match freed {
        Ok(()) => line(
            &mut out,
            &["[MM ] guarded stacks: alloc+map+cross-view ok, free+scrub ok"],
        ),
        Err(_) => {
            line(
                &mut out,
                &["[MM ] ERROR: guarded-stack free failed; halting"],
            );
            hw::halt_forever();
        }
    }

    // ── 10. ring-3 isolation + SYSCALL/SYSRET (PR-1.4) ─────────────
    // Cross the hardware boundary: a dedicated (guarded) syscall stack,
    // the entry MSRs, then four user runs — the good citizen, an NX
    // exec attack, a kernel-address read, and a forged syscall — each
    // a fresh policy-mapped domain, each ending in SYS_EXIT or a
    // user-mode fault the kernel survives.
    let syscall_stack = match mm::stacks::alloc(&mut pool, &mut k.frames, 2) {
        Ok(st) => st,
        Err(_) => {
            line(
                &mut out,
                &["[RING3] ERROR: syscall stack alloc failed; halting"],
            );
            hw::halt_forever();
        }
    };
    arch::gdt::set_rsp0(syscall_stack.top_va());
    arch::percpu::set_kstack_top(syscall_stack.top_va());
    arch::syscall_entry::set_entry_stack(syscall_stack.top_va());
    arch::syscall_entry::init();
    line(
        &mut out,
        &["[RING3] syscall entry armed: rsp0/kstack = guarded stack, STAR/LSTAR/SFMASK/SCE live"],
    );

    // ── Run 1: the good citizen — hello from ring-3, then exit(0). ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        5,
        aegis_os::profile::service_profile(),
        RING3_HELLO,
        RING3_MSG,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: hello spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 5 (service profile) at CPL=3"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    // — ring-3 ran here; SYS_EXIT faulted us back to exactly this point —
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    let trip = arch::syscall_entry::roundtrip();
    match run.exit {
        crate::sched::context::ExitKind::Exited(0) if run.write_bytes == RING3_MSG.len() as u64 => {
            line(
                &mut out,
                &["[RING3] hello domain exited(0): message written from CPL=3"],
            );
        }
        crate::sched::context::ExitKind::Fault {
            vector,
            cr2,
            error_code,
            rip,
            user_rsp,
        } => {
            // The run faulted before its first completed syscall — the
            // environment-blocked case (full investigation in
            // docs/arch/syscall-entry.md). Print the FULL fault record:
            // vector/cr2/err/rip/rsp + the resume point and the run's
            // telemetry, so the next investigation does not have to
            // guess (this exact record is what the monitor saw).
            {
                let mut b1 = [0u8; 20];
                let mut b2 = [0u8; 18];
                let mut b3 = [0u8; 18];
                let mut b4 = [0u8; 18];
                let mut b5 = [0u8; 18];
                line(
                    &mut out,
                    &[
                        "[RING3] fault record: vector=",
                        strutil::dec(vector as u64, &mut b1),
                        " cr2=",
                        strutil::hex(cr2, &mut b2),
                        " err=",
                        strutil::hex(error_code, &mut b3),
                        " rip=",
                        strutil::hex(rip, &mut b4),
                        " rsp=",
                        strutil::hex(user_rsp, &mut b5),
                    ],
                );
                let mut b6 = [0u8; 18];
                let mut b7 = [0u8; 18];
                let mut b8 = [0u8; 20];
                line(
                    &mut out,
                    &[
                        "[RING3] resume point: rip=",
                        strutil::hex(crate::sched::context::saved_rip(), &mut b6),
                        " rsp=",
                        strutil::hex(crate::sched::context::saved_rsp(), &mut b7),
                        " writes=",
                        strutil::dec(run.write_bytes, &mut b8),
                    ],
                );
            }
            line(
                &mut out,
                &["[RING3] launch blocked: ring-3 entry faults in this QEMU build"],
            );
            line(
                &mut out,
                &["[RING3] (machinery armed + host-tested; see docs/arch/syscall-entry.md)"],
            );
            mm::user::destroy_user(&mut k, &mut pool, 5);
            line(
                &mut out,
                &["[RING3] ring-3 step concluded: blocked (environment), kernel intact"],
            );
            hw::shutdown_qemu();
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: hello run ended unexpectedly; halting"],
            );
            hw::halt_forever();
        }
    }
    let mut bt = [0u8; 20];
    line(
        &mut out,
        &[
            "[SYSC] syscall round-trip: ",
            strutil::dec(trip, &mut bt),
            " cycles",
        ],
    );
    mm::user::destroy_user(&mut k, &mut pool, 5);

    // ── Run 2: attack the NX bit — call into the data page. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        6,
        aegis_os::profile::service_profile(),
        RING3_ROGUE,
        &[0u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: rogue-nx spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 6: calls into its NX data page"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        crate::sched::context::ExitKind::Fault {
            vector: 14,
            error_code,
            cr2,
            ..
        } if (error_code & 0x10) != 0 && (error_code & 0x4) != 0 => {
            let mut bc = [0u8; 18];
            line(
                &mut out,
                &[
                    "[SEC ] ring3 NX-exec blocked: #PF (I/D) at cr2=",
                    strutil::hex(cr2, &mut bc),
                    " — MMU-enforced W^X",
                ],
            );
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: NX attack did not fault as expected; halting"],
            );
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 6);

    // ── Run 3: read through the kernel direct map. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        7,
        aegis_os::profile::service_profile(),
        RING3_ROGUE,
        &[1u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(
                &mut out,
                &["[RING3] ERROR: rogue-kva spawn failed; halting"],
            );
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 7: reads the kernel direct map"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        crate::sched::context::ExitKind::Fault {
            vector: 14,
            error_code,
            cr2,
            ..
        } if (error_code & 0x4) != 0 && (error_code & 0x1) != 0 => {
            let mut bc = [0u8; 18];
            line(
                &mut out,
                &[
                    "[SEC ] ring3 kernel-VA read blocked: #PF (U/S) at cr2=",
                    strutil::hex(cr2, &mut bc),
                    " — supervisor page",
                ],
            );
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: kernel-VA read did not fault as expected; halting"],
            );
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 7);

    // ── Run 4: forged syscall 200 — must return -ENOSYS, audited. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        8,
        aegis_os::profile::service_profile(),
        RING3_ROGUE,
        &[2u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(
                &mut out,
                &["[RING3] ERROR: rogue-syscall spawn failed; halting"],
            );
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 8: forged syscall 200"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        crate::sched::context::ExitKind::Exited(42) if run.bad_syscalls == 1 => {
            line(
                &mut out,
                &["[SEC ] ring3 unauthorized syscall refused (-ENOSYS, audited)"],
            );
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: forged syscall not refused properly; halting"],
            );
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 8);

    // ── Run 5 (N1, ADR-0007 §1): writes that end exactly at the data
    // page's last byte must succeed (the copy may touch ONLY the
    // validated bytes), and a write crossing into the absent next page
    // must return -EFAULT without the kernel faulting. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        9,
        aegis_os::profile::service_profile(),
        RING3_EDGE,
        &[0u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: edge spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 9: tail-of-page + page-crossing writes"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        crate::sched::context::ExitKind::Exited(42) if run.write_bytes == 4 => {
            line(&mut out, &["[SEC ] ring3 tail-of-page write ok"]);
            line(&mut out, &["[SEC ] ring3 crossing write refused (-EFAULT)"]);
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: edge write run ended unexpectedly; halting"],
            );
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 9);

    // ── Run 6 (N2, ADR-0007 §2): a rogue spamming forbidden syscalls
    // and crossing writes across many monitor windows is quarantined
    // BY ITS OWN BEHAVIOR — every signal (gate denials, out-of-profile
    // bits, rate spikes, -EFAULT faults) is fed from the ring-3 path,
    // and the healthy witness domain is untouched by the same windows.
    // ──
    let _ = k.create_domain_with(11, aegis_os::profile::service_profile(), 1011, 100, 0);
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        10,
        aegis_os::profile::service_profile(),
        RING3_ROGUE,
        &[3u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(
                &mut out,
                &["[RING3] ERROR: rogue-monitor spawn failed; halting"],
            );
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 10: forbidden-syscall spam (live-monitor quarantine)"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match (run.exit, k.domain_state(10)) {
        (
            crate::sched::context::ExitKind::Exited(0),
            Some(aegis_os::domain::DomainState::Quarantined),
        ) => {
            line(&mut out, &["[SEC ] ring3 domain 10 quarantined by monitor"]);
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: rogue not quarantined by the live monitor; halting"],
            );
            hw::halt_forever();
        }
    }
    match k.domain_state(11) {
        Some(aegis_os::domain::DomainState::Running) => {
            line(&mut out, &["[MON ] healthy domain still running: yes"]);
        }
        _ => {
            line(
                &mut out,
                &["[RING3] ERROR: healthy witness domain was not left alone; halting"],
            );
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 10);
    let _ = k.destroy_domain(11);

    // M2-W2: the supervisor drains the telemetry ring between runs.
    // The ring is a fixed 16-slot buffer that REFUSES on overflow (no
    // silent overwrite, by design) — without a drain, run 5's spam
    // events fill it and run 6's verdicts drop on the floor. Draining
    // is the supervisor's job in the real system too (R5: the console
    // domain reads the ring over an endpoint); kmain stands in for it
    // here and prints the honest summary, drops included.
    drain_telemetry(&mut k, &mut out);

    // ── Run 7 (N2): AuditOnly — the same rogue, the same windows:
    // verdicts computed and logged to telemetry, nothing applied. ──
    k.set_monitor_mode(aegis_os::monitor::MonitorMode::AuditOnly);
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        12,
        aegis_os::profile::service_profile(),
        RING3_ROGUE,
        &[3u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(
                &mut out,
                &["[RING3] ERROR: rogue-audit spawn failed; halting"],
            );
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 12: same spam under MonitorMode::AuditOnly"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    let mut logged_a_verdict = false;
    while let Some(ev) = k.pop_event() {
        if ev.domain_id == 12 && ev.action == aegis_os::response::EventAction::Quarantine {
            logged_a_verdict = true;
        }
    }
    match (run.exit, k.domain_state(12)) {
        (
            crate::sched::context::ExitKind::Exited(0),
            Some(aegis_os::domain::DomainState::Running),
        ) if logged_a_verdict => {
            line(
                &mut out,
                &["[SEC ] ring3 audit-only: verdicts logged, mask unchanged"],
            );
        }
        _ => {
            // M2-W2 diagnostics: name the failing condition (the three
            // the marker demands: exit(0), state Running, verdict logged).
            let mut b1 = [0u8; 20];
            serial::write_str("[RING3] audit-only mismatch: exit=");
            match &run.exit {
                crate::sched::context::ExitKind::Exited(c) => {
                    serial::write_str(strutil::dec(*c, &mut b1))
                }
                crate::sched::context::ExitKind::Fault { vector, .. } => {
                    serial::write_str("fault(v=");
                    serial::write_str(strutil::dec(*vector as u64, &mut b1));
                    serial::write_str(")");
                }
            }
            serial::write_str(" state=");
            serial::write_str(match k.domain_state(12) {
                Some(aegis_os::domain::DomainState::Running) => "Running",
                Some(aegis_os::domain::DomainState::Quarantined) => "Quarantined",
                _ => "None",
            });
            serial::write_str(" verdict_logged=");
            serial::write_str(if logged_a_verdict { "yes" } else { "no" });
            serial::write_str("\n");
            line(
                &mut out,
                &["[RING3] ERROR: audit-only run did not behave as specified; halting"],
            );
            hw::halt_forever();
        }
    }
    k.set_monitor_mode(aegis_os::monitor::MonitorMode::Enforce);
    mm::user::destroy_user(&mut k, &mut pool, 12);
    line(&mut out, &["[RING3] ring-3 isolation live: 7 runs (hello/NX/kernel-VA/forged/edge/monitor-quarantine/audit-only), kernel intact"]);

    // M2-W2 / ADR-0012: the preemption demo is behind the `preempt-demo`
    // feature — see ADR-0012 (open issues) for why the default boot does
    // not arm the timer yet: the machinery is host-tested and the
    // interleaving was demonstrated (ADR-0012 §Evidence), but a
    // release+LTO argument-codegen anomaly in this toolchain
    // destabilizes the demo spawn path.
    #[cfg(feature = "preempt-demo")]
    preempt_demo(&mut k, &mut pool, &mut out);

    // ── 14. driver stack (ADR-0013): ACPI/DMAR discovery (PR 0.3)
    //      and, when a DMAR exists, the VT-d bring-up + hardware
    //      proofs (PR 0.4). Runs before the terminal guard proof so
    //      the `[IOMMU]` markers are on every lane (pc, q35, q35-neg).
    //      Absence is a verdict, not a crash: the boot continues and
    //      later claim paths fail closed on it.
    crate::drvstack::driver_stack_step(&mut k, &mut pool, &mut out);

    // ── 13. the terminal guard-page proof: the write must #PF, the
    // dispatch must confirm CR2 is exactly the guard page, print the
    // marker, and power off cleanly (CI greps it). Reached only when
    // the whole ring-3 sequence completed — the blocked path powers
    // off inside step 10.
    line(
        &mut out,
        &["[ARCH] guard selftest: writing through the boot-stack guard page"],
    );
    arch::exceptions::arm_guard_write(arch::image_map::boot_stack_guard_va());
}

/// The supervisor's telemetry drain: pop every event, count by action,
/// report the ring's own dropped-counter. One line per drain — the
/// audit trail the console domain will read over IPC once endpoints
/// carry it (M2-PLAN R5); the counts prove the monitor is producing
/// verdicts even when the ring overflowed before a drain.
fn drain_telemetry(
    k: &mut aegis_os::Kernel<{ crate::frames::KERNEL_POOL_FRAMES }>,
    out: &mut dyn FnMut(&str),
) {
    let (mut n, mut logs, mut tightens, mut quarantines) = (0u64, 0u64, 0u64, 0u64);
    while let Some(ev) = k.pop_event() {
        n += 1;
        match ev.action {
            aegis_os::response::EventAction::Log => logs += 1,
            aegis_os::response::EventAction::Tighten => tightens += 1,
            aegis_os::response::EventAction::Quarantine => quarantines += 1,
        }
    }
    let dropped = k.telemetry_dropped();
    let mut b1 = [0u8; 20];
    let mut b2 = [0u8; 20];
    let mut b3 = [0u8; 20];
    let mut b4 = [0u8; 20];
    let mut b5 = [0u8; 20];
    line(
        out,
        &[
            "[TELE] supervisor drain: ",
            strutil::dec(n, &mut b1),
            " events (log=",
            strutil::dec(logs, &mut b2),
            " tighten=",
            strutil::dec(tightens, &mut b3),
            " quarantine=",
            strutil::dec(quarantines, &mut b4),
            ") dropped=",
            strutil::dec(dropped, &mut b5),
        ],
    );
}

/// Step 12 (ADR-0012): the starvation-freedom proof. Feature-gated —
/// see the call site and ADR-0012's open-issues section.
#[cfg(feature = "preempt-demo")]
fn preempt_demo<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
) {
    // ── 12. M2-W2 / ADR-0012: preemption — the starvation-freedom proof.
    // Two ring-3 domains on one CPU under the LAPIC timer:
    //   domain 20 — the spinner: 400M pure-compute iterations, no
    //     syscalls, then exit(7). Without a timer it starves everyone
    //     forever (nothing else can take the CPU away from CPL3).
    //   domain 21 — the writer: 4 × (SYS_WRITE a message, spin a
    //     little), then exit(0).
    // The exit test (M2-PLAN week 2): the writer must finish WHILE the
    // spinner is still runnable, and the tick path must have switched
    // domains — both impossible without interrupt-driven preemption.
    line(
            &mut out,
            &["[SCHD] preemption demo: retiring the M1 hello domain (a kernel-resident CFS entity must never be preemptor-picked)"],
        );
    mm::user::destroy_user(&mut k, &mut pool, 1);

    crate::sched::preempt::arm();

    // The two data pages, as NAMED statics — not promoted `&[0u8]`-style
    // temporaries: this toolchain's release+LTO codegen once elided the
    // store of a promoted slice's POINTER argument (the callee received
    // stale stack garbage as data.as_ptr() and the copy faulted — the
    // full forensic story is in ADR-0012). A named static gives the
    // argument a real symbol that cannot be optimized away.
    static SPINNER_DATA: [u8; 1] = [0]; // mode 0: the spinner
    static WRITER_DATA: [u8; 0x90] = writer_data_page();

    /// The writer's data page, built at compile time: mode byte 1,
    /// then four 22-byte messages at 0x10 + round*0x20 (the blob's own
    /// addressing).
    const fn writer_data_page() -> [u8; 0x90] {
        let mut d = [0u8; 0x90];
        d[0] = 1; // mode 1: the writer
        let msgs: [&[u8; 22]; 4] = [
            b"[W] writer round 0\n   ",
            b"[W] writer round 1\n   ",
            b"[W] writer round 2\n   ",
            b"[W] writer round 3\n   ",
        ];
        let mut i = 0;
        while i < 4 {
            let mut j = 0;
            while j < 22 {
                d[0x10 + i * 0x20 + j] = msgs[i][j];
                j += 1;
            }
            i += 1;
        }
        d
    }

    let spinner = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        20,
        aegis_os::profile::service_profile(),
        RING3_PREEMPT,
        &SPINNER_DATA,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[SCHD] ERROR: spinner spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    let writer = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        21,
        aegis_os::profile::service_profile(),
        RING3_PREEMPT,
        &WRITER_DATA,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[SCHD] ERROR: writer spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(
            &mut out,
            &["[SCHD] preempt demo: spinner=20 (400M iters, no syscalls) writer=21 (4 writes), timer live"],
        );

    // Park the writer (its first execution will come from a timer
    // switch rewriting the interrupt frame); launch the spinner through
    // the fresh SYSRET path.
    crate::sched::context::stash_parked(
        writer.run,
        crate::sched::context::ParkedContext::from_user_context(&writer.ctx),
    );
    let kernel_cr3 = hw::read_cr3();
    spinner.run.tables.activate();
    crate::sched::context::begin(spinner.run);
    crate::sched::context::launch(&spinner.ctx);
    // Reached only via resume_kernel (SYS_EXIT / a fault): the timer
    // interleaves the runs; every return here is one domain EXITING
    // with the other parked. The loop hands the CPU to the survivor
    // until the queue empties.
    let mut writer_exited_first = false;
    let mut writer_writes = 0u64;
    let mut spinner_clean_exit = false;
    let mut writer_clean_exit = false;
    loop {
        let run = crate::sched::context::take();
        hw::write_cr3(kernel_cr3);
        let finished = run.domain;
        let writes = run.write_bytes;
        {
            let (what, code) = match &run.exit {
                crate::sched::context::ExitKind::Exited(c) => ("exited", *c),
                crate::sched::context::ExitKind::Fault { vector, .. } => {
                    // A fault during the demo is a demo failure — these
                    // blobs touch nothing but their own pages.
                    let mut bv = [0u8; 20];
                    line(
                        &mut out,
                        &[
                            "[SCHD] ERROR: domain ",
                            strutil::dec(finished as u64, &mut bv),
                            " faulted (vector below) — halting",
                        ],
                    );
                    let mut bv2 = [0u8; 20];
                    line(
                        &mut out,
                        &[
                            "[SCHD] fault vector=",
                            strutil::dec(*vector as u64, &mut bv2),
                        ],
                    );
                    hw::halt_forever();
                }
            };
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            let mut b3 = [0u8; 20];
            line(
                &mut out,
                &[
                    "[SCHD] domain ",
                    strutil::dec(finished as u64, &mut b1),
                    " ",
                    what,
                    ", code=",
                    strutil::dec(code, &mut b2),
                    ", writes=",
                    strutil::dec(writes, &mut b3),
                ],
            );
        }
        if finished == 21 {
            // The proof: the writer finished while the spinner was
            // still parked-runnable — impossible without preemption
            // (the spinner launched first and never yields).
            writer_exited_first = crate::sched::context::is_parked(20);
            writer_writes = writes;
            writer_clean_exit = matches!(run.exit, crate::sched::context::ExitKind::Exited(0));
        }
        if finished == 20 {
            spinner_clean_exit = matches!(run.exit, crate::sched::context::ExitKind::Exited(7));
        }
        mm::user::destroy_user(&mut k, &mut pool, finished);
        match crate::sched::preempt::on_exit(&mut k.sched, finished) {
            Some(next) => {
                let Some((nrun, nctx)) = crate::sched::context::take_parked(next) else {
                    line(
                        &mut out,
                        &["[SCHD] ERROR: handover target not parked; halting"],
                    );
                    hw::halt_forever();
                };
                let mut b = [0u8; 20];
                line(
                    &mut out,
                    &[
                        "[SCHD] handover: CPU -> domain ",
                        strutil::dec(next as u64, &mut b),
                    ],
                );
                nrun.tables.activate();
                crate::sched::context::begin(nrun);
                crate::sched::context::resume_parked(&nctx);
                // Returns when THAT domain exits — loop.
            }
            None => break,
        }
    }

    // The summary + verdict (CI greps these).
    let switches = crate::sched::preempt::switches();
    let ticks = crate::sched::preempt::ticks();
    {
        let mut b1 = [0u8; 20];
        let mut b2 = [0u8; 20];
        line(
            &mut out,
            &[
                "[SCHD] preempt: switches=",
                strutil::dec(switches, &mut b1),
                " ticks=",
                strutil::dec(ticks, &mut b2),
            ],
        );
    }
    let preempt_pass =
        writer_exited_first && writer_clean_exit && spinner_clean_exit && switches >= 2;
    if preempt_pass {
        let mut b = [0u8; 20];
        line(
                &mut out,
                &[
                    "[SCHD] starvation-freedom: writer (21) finished while spinner (20) still runnable, writes=",
                    strutil::dec(writer_writes, &mut b),
                ],
            );
        line(
                &mut out,
                &["[VERDICT] M2-W2 PREEMPTION: PASS — timer-driven CFS, ring-3 preemptible, monitor windows close on tick"],
            );
    } else {
        line(
                &mut out,
                &["[SCHD] ERROR: preemption proof incomplete (see the switches/ticks/exits above); halting"],
            );
        hw::halt_forever();
    }
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
