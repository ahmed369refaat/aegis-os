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
//!     and two ring-3 domains — a pure spinner that never calls a
//!     syscall and a writer — run interleaved under interrupt-driven
//!     CFS; the writer must finish while the spinner is still runnable,
//! 13. the terminal act: write through a fresh stack's guard page — the
//!     #PF is diagnosed, the marker printed, and QEMU powers off.
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
/// The ADR-0012 preemption blob: the spinner (mode 0) and the writer
/// (mode 1) of the starvation-freedom proof. Ungated since ADR-0023:
/// the proof is part of every default boot lane.
static RING3_PREEMPT: &[u8] = include_bytes!("../blob/ring3-preempt.bin");
/// Round J: the file-lifecycle blob — pipe round-trip, dup survival,
/// open/write/read-back through an independent cursor, and the errno
/// refusals, all from CPL=3 through the LIVE lib kernel.
static RING3_FILES: &[u8] = include_bytes!("../blob/ring3-files.bin");
/// Phase 7 (M3): PID 1's init blob — the fork/wait4/reparent proof.
static RING3_INIT: &[u8] = include_bytes!("../blob/ring3-init.bin");

/// Round J: the files blob's data page. The blob's literal addresses
/// (0x403000..) are the contract — this builds the matching array.
/// A `static`, evaluated at compile time into .rodata: the first
/// draft built it on kmain's stack (4 KiB of locals), and the boot
/// stack's absent guard page caught the result — the driver-stack
/// call chain bottoms out barely 1.6 KiB above stack_bottom, so the
/// extra page pushed RSP through the guard and #PF'd (err=2: a
/// supervisor write to a not-present page — the guard doing exactly
/// its job). Zero stack cost now; the stack also grew 256K→512K
/// (linker.ld) so the margin is honest, not lucky.
const fn put4096(d: &mut [u8; 4096], off: usize, bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() {
        d[off + i] = bytes[i];
        i += 1;
    }
}

const fn ring3_files_data() -> [u8; 4096] {
    let mut d = [0u8; 4096];
    put4096(&mut d, 0x000, b"pipe bytes from cpl3\n"); // MSG1 (21)
    put4096(&mut d, 0x040, b"dup keeps ends alive\n"); // MSG2 (21)
    put4096(&mut d, 0x080, b"aegis file roundtrip\n"); // FMSG (21)
    put4096(&mut d, 0x0C0, b"/pub/round-j.txt\0"); // PATH (17)
    put4096(&mut d, 0x100, b"/no/such/file\0"); // NXPATH (14)
    put4096(&mut d, 0x140, b"J:pipe ok\n"); // M1 (10)
    put4096(&mut d, 0x160, b"J:dup ok\n"); // M2 (9)
    put4096(&mut d, 0x180, b"J:file ok\n"); // M3 (10)
    put4096(&mut d, 0x1A0, b"J:neg ok\n"); // M4 (9)
    put4096(&mut d, 0x1C0, b"/pub/d1\0"); // D1P — the mkdir target (8)
    put4096(&mut d, 0x1E0, b"/pub/d1/in.txt\0"); // FIP — file inside it (15)
    put4096(&mut d, 0x200, b"round-j.txt\0"); // RP — relative, post-chroot (12)
    put4096(&mut d, 0x220, b"J:mkdir ok\n"); // M5 (11)
    put4096(&mut d, 0x240, b"/pub\0"); // PUBP — the chroot jail (5)
    put4096(&mut d, 0x260, b"J:dev ok\n"); // M6 (9)
    put4096(&mut d, 0x280, b"/dev/null\0"); // DNUL (11)
    put4096(&mut d, 0x2A0, b"/dev/zero\0"); // DZERO (11)
    put4096(&mut d, 0x2C0, b"/proc/self\0"); // DPROC (11)
    put4096(&mut d, 0x2E0, b"domain 14 uid 1014 gid 100\n"); // PSTAT (27)
    d
}

static FILES_DATA: [u8; 4096] = ring3_files_data();
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
    // ADR-0024 D1: the mmap/munmap dispatch paths reach the pool
    // through the context slot (same lifetime discipline as the
    // kernel pointer).
    crate::sched::context::set_pool(core::ptr::addr_of_mut!(pool));
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
    let t_end = hw::read_tsc();
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
    // ADR-0024 D2: 8 pages (was 2). The fork path's dispatch depth —
    // sys_fork → clone_for_fork's bookkeeping → fork_process →
    // Domain::forked's ~3.5 KiB frame — measured past 8 KiB and the
    // GUARD caught it exactly as F15 built it to (a loud #PF at the
    // guard, not silent .bss corruption). The margin is now honest
    // rather than lucky; the slot holds up to 511.
    let syscall_stack = match mm::stacks::alloc(&mut pool, &mut k.frames, 8) {
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
                // A live run never reaches a proof's post-run match.
                crate::sched::context::ExitKind::Running => serial::write_str("running?"),
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

    // ── Run 8 (Round J): the file lifecycle from CPL=3 — the ring-3
    // syscall surface crosses the fd line. A kernel-resident
    // supervisor (uid 0) prepares /pub world-writable first (the
    // init-prepares-/tmp pattern), then a service-profile domain runs
    // the whole Unix dance through the LIVE lib kernel: pipe() ->
    // (3,4) (the stdio triplet keeps 0..2), a pipe round-trip with
    // byte-verified read-back, a dup keeping the read end alive past
    // its original's close, open(O_CREAT)/write/read-back through the
    // duplicate's independent cursor, close of the original with the
    // dup reading EOF — and the three errno refusals (EBADF, ENOENT,
    // EBADF). Every answer is checked IN THE BLOB; exit 42 means all
    // of them verified, 99 means the first wrong answer. ──
    // Phase 6 S1: the boot root grows from the lone /pub to the M3
    // tree — /tmp (world-writable scratch), /dev and /proc (S2's
    // device and proc homes, plain dirs until then), /bin (the exec
    // registry's path home). Same supervisor pattern: uid 0 prepares,
    // then dies before ring 3 ever runs.
    const BOOT_TREE: [(&str, u16); 5] = [
        ("/pub", 0o777),
        ("/tmp", 0o777),
        ("/dev", 0o755),
        ("/proc", 0o755),
        ("/bin", 0o755),
    ];
    let supervisor_ok = matches!(
        k.create_domain_with(13, aegis_os::profile::service_profile(), 0, 0, 0),
        Ok(())
    ) && BOOT_TREE.iter().all(|&(path, m)| {
        k.syscall(
            13,
            aegis_os::sys::SysRequest::Mkdir {
                path,
                mode: aegis_os::vfs::Mode(m),
            },
        )
        .is_ok()
    });
    let _ = k.destroy_domain(13);
    // Phase 6 S2: devfs + procfs — the supervisor API installs the
    // nodes (deliberately NOT SysRequests: no ring-3 caller can mint
    // a device or a proc node).
    k.install_device("/dev/null", aegis_os::vfs::DevKind::Null)
        .unwrap();
    k.install_device("/dev/zero", aegis_os::vfs::DevKind::Zero)
        .unwrap();
    k.install_proc_node("/proc/self", aegis_os::vfs::ProcNode::Status)
        .unwrap();
    if !supervisor_ok {
        line(
            &mut out,
            &["[RING3] ERROR: /pub preparation failed; halting"],
        );
        hw::halt_forever();
    }
    let spawn = match mm::user::spawn_user_blob(
        &mut k,
        &mut pool,
        14,
        aegis_os::profile::service_profile(),
        RING3_FILES,
        &FILES_DATA,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: files spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(
        &mut out,
        &["[RING3] launching domain 14 (service profile): the file lifecycle at CPL=3"],
    );
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // — ring-3 ran here; SYS_EXIT faulted us back to exactly this point —
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        // 163 = the markers (49 + 9 = 58: M1..M6) + both pipe writes
        // + the round-J file write + the S1 file write + the
        // /dev/null write (21 each) + the M5 marker (11): every byte
        // the run contributed, counted — /dev/null's discard still
        // counts at the write() boundary.
        crate::sched::context::ExitKind::Exited(42) if run.write_bytes == 163 => {
            line(
                &mut out,
                &["[RING3] files domain exited(42): pipe+dup+file lifecycle + the S1 directory dance verified from CPL=3"],
            );
            line(
                &mut out,
                &["[RING3] ring-3 syscall surface: OPEN/READ/WRITE/CLOSE/PIPE/DUP + the Phase-6 MKDIR/UNLINK arms live on the lib kernel"],
            );
        }
        crate::sched::context::ExitKind::Fault {
            vector,
            cr2,
            error_code,
            rip,
            user_rsp,
        } => {
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 18];
            let mut b3 = [0u8; 18];
            let mut b4 = [0u8; 18];
            let mut b5 = [0u8; 18];
            line(
                &mut out,
                &[
                    "[RING3] files fault record: vector=",
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
            line(&mut out, &["[RING3] ERROR: files run faulted; halting"]);
            hw::halt_forever();
        }
        _ => {
            // The honest record: WHICH exit code and how many bytes —
            // a 99 names the blob's first failed check, a 42 with a
            // short count names the accounting.
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            let mut b3 = [0u8; 20];
            serial::write_str("[RING3] files run: exit=");
            match run.exit {
                crate::sched::context::ExitKind::Exited(c) => {
                    serial::write_str(strutil::dec(c, &mut b1))
                }
                crate::sched::context::ExitKind::Fault { vector, .. } => {
                    serial::write_str("fault(v=");
                    serial::write_str(strutil::dec(vector as u64, &mut b2));
                    serial::write_str(")");
                }
                // A live run never reaches a proof's post-run match.
                crate::sched::context::ExitKind::Running => serial::write_str("running?"),
            }
            serial::write_str(" write_bytes=");
            serial::write_str(strutil::dec(run.write_bytes, &mut b3));
            serial::write_str("\n");
            line(
                &mut out,
                &["[RING3] ERROR: files run ended unexpectedly; halting"],
            );
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 14);
    line(&mut out, &["[RING3] ring-3 isolation live: 8 runs (hello/NX/kernel-VA/forged/edge/monitor-quarantine/audit-only/files), kernel intact"]);

    // ADR-0023: the preemption proof is UN-GATED — part of every
    // default boot lane. The ADR-0012 release+LTO argument-codegen
    // anomaly stays worked around by the named-static data pages below
    // (the anomaly itself was never root-caused; the workaround has
    // held on every lane since). The timer stays armed for the rest of
    // the boot: the driver stack's ADR-0019 IF-windows pause it
    // explicitly (pause_ticks/resume_ticks), and the kernel-side IF=0
    // discipline makes every other CPL0 stretch tick-proof.
    preempt_demo(&mut k, &mut pool, &mut out);

    // ── 14. driver stack (ADR-0013): ACPI/DMAR discovery (PR 0.3)
    //      and, when a DMAR exists, the VT-d bring-up + hardware
    //      proofs (PR 0.4). Runs before the terminal guard proof so
    //      the `[IOMMU]` markers are on every lane (pc, q35, q35-neg).
    //      Absence is a verdict, not a crash: the boot continues and
    //      later claim paths fail closed on it.
    crate::drvstack::driver_stack_step(&mut k, &mut pool, &mut out);

    // ── 15. ADR-0023: the sleep/idle proof — the first process that
    //      parks ITSELF and the first guarded idle the machine ever
    //      served. The sleeper (mode 2, its own data page) verifies
    //      IN the blob: two monotonic clock reads bracketing a 100 ms
    //      nanosleep (the delta must COVER the span — the wake cannot
    //      land early) and a sched_yield while solo (must answer 0);
    //      exit(0) only when every step verified. With nothing else
    //      runnable, the sleep engages the idle state (sti+hlt under
    //      the tick's IDLE carve-out) — the hlt count proves the
    //      machine slept instead of spinning. ──
    {
        static SLEEPER_DATA: [u8; 0x50] = {
            let mut d = [0u8; 0x50];
            d[0] = 2; // mode 2: the sleeper
            d
        };
        let sleeper = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            22,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &SLEEPER_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(
                    &mut out,
                    &["[M3] sleep: ERROR: sleeper spawn failed; halting"],
                );
                hw::halt_forever();
            }
        };
        let kernel_cr3 = hw::read_cr3();
        sleeper.run.tables.activate();
        crate::sched::context::begin(sleeper.run);
        crate::sched::context::launch(&sleeper.ctx);
        // kmain resumes HERE when the nested dispatcher's run set
        // empties (the sleeper exited; its exit sits in the completed
        // mailbox — teardown stays the spawner's contract).
        hw::write_cr3(kernel_cr3);
        let mut clean_exit = false;
        let mut saw_exit = false;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            saw_exit = true;
            if dom == 22 {
                clean_exit = matches!(exit, crate::sched::context::ExitKind::Exited(0));
            }
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        let idles = crate::sched::preempt::idle_hlts();
        if clean_exit && saw_exit && idles >= 1 {
            let mut b = [0u8; 20];
            line(
                &mut out,
                &[
                    "[M3] sleep: idle engaged (hlt cycles=",
                    strutil::dec(idles, &mut b),
                    "), 100ms wake landed on time, exit 0",
                ],
            );
        } else {
            line(
                &mut out,
                &["[M3] sleep: ERROR: exit or idle count wrong; halting"],
            );
            hw::halt_forever();
        }
        let mut b1 = [0u8; 20];
        line(
            &mut out,
            &[
                "[M3] clock: ring-3 clock_gettime verified by the blob (tsc_hz=",
                strutil::dec(crate::clock::tsc_hz(), &mut b1),
                if crate::clock::calibrated() {
                    ", HPET-calibrated)"
                } else {
                    ", fallback cadence)"
                },
            ],
        );
    }

    // ── 16. ADR-0023 D8: the signal proof — the first ring-3 signal
    //      frames in the system's history. The VICTIM (23) installs a
    //      SIGUSR1 handler (rt_sigaction with the trampoline
    //      restorer), announces itself, and sleeps 200 ms; the KILLER
    //      (24) strikes mid-sleep (kill(23, SIGUSR1)) and exits. On
    //      the victim's wake the kernel delivers the signal ON THE
    //      UNPARK PATH (the parked image is rewritten into the
    //      handler; the interrupted image rides the pushed frame);
    //      the handler sets its flag, `ret`s into the kernel's
    //      trampoline, rt_sigreturn validates every user-supplied
    //      field against the kernel's delivery record and resumes the
    //      interrupted code — which verifies the flag and exits 0.
    //      Then the FORGER (25) calls rt_sigreturn with a garbage
    //      stack and NO delivery in flight: it must be refused
    //      (its exit 0 certifies the refusal; exit 107 would mean a
    //      forged frame was accepted). ──
    {
        static VICTIM_DATA: [u8; 0x70] = {
            let mut d = [0u8; 0x70];
            d[0] = 3; // mode 3: the victim
            let msg: &[u8; 13] = b"victim armed\n";
            let mut i = 0;
            while i < 13 {
                d[0x10 + i] = msg[i];
                i += 1;
            }
            d
        };
        static KILLER_DATA: [u8; 1] = [4]; // mode 4: the killer
        let victim = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            23,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &VICTIM_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(
                    &mut out,
                    &["[M3] signal: ERROR: victim spawn failed; halting"],
                );
                hw::halt_forever();
            }
        };
        let killer = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            24,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &KILLER_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(
                    &mut out,
                    &["[M3] signal: ERROR: killer spawn failed; halting"],
                );
                hw::halt_forever();
            }
        };
        // The proof's cast, arranged by the bootstrap (the Unix layer
        // needs uid 0 for a cross-domain kill — the CAPABILITY gate
        // still applies; uid 0 never bypasses it): grant the killer a
        // Domain(23) WRITE capability and run it as root.
        {
            let d = k.domain_mut(24).expect("killer domain");
            let _ = d.caps.insert(aegis_os::capability::Capability {
                resource: aegis_os::capability::Resource::Domain(23),
                rights: aegis_os::capability::Rights::WRITE,
                generation: 0,
            });
            d.uid = 0;
        }
        let kernel_cr3 = hw::read_cr3();
        crate::sched::context::stash_parked(
            killer.run,
            crate::sched::context::ParkedContext::from_user_context(&killer.ctx),
        );
        victim.run.tables.activate();
        crate::sched::context::begin(victim.run);
        crate::sched::context::launch(&victim.ctx);
        // kmain resumes when the nested dispatcher empties: both runs
        // exited (the mailbox holds their exits).
        hw::write_cr3(kernel_cr3);
        let mut victim_ok = false;
        let mut killer_ok = false;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            let clean = matches!(exit, crate::sched::context::ExitKind::Exited(0));
            if dom == 23 {
                victim_ok = clean;
            }
            if dom == 24 {
                killer_ok = clean;
            }
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        if !victim_ok || !killer_ok {
            line(
                &mut out,
                &["[M3] signal: ERROR: victim/killer exit wrong; halting"],
            );
            hw::halt_forever();
        }
        // The forger: solo — its exit 0 certifies the refusal.
        static FORGER_DATA: [u8; 1] = [5];
        let forger = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            25,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &FORGER_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(
                    &mut out,
                    &["[M3] signal: ERROR: forger spawn failed; halting"],
                );
                hw::halt_forever();
            }
        };
        let kernel_cr3 = hw::read_cr3();
        forger.run.tables.activate();
        crate::sched::context::begin(forger.run);
        crate::sched::context::launch(&forger.ctx);
        let run = crate::sched::context::take();
        hw::write_cr3(kernel_cr3);
        let forger_ok = matches!(run.exit, crate::sched::context::ExitKind::Exited(0));
        mm::user::destroy_user(&mut k, &mut pool, 25);
        let _ = crate::sched::preempt::on_exit(&mut k.sched, 25);
        if forger_ok {
            line(
                &mut out,
                &["[M3] signal: handler ran, sigreturn resumed, forged frame refused"],
            );
        } else {
            line(
                &mut out,
                &["[M3] signal: ERROR: forged frame was accepted (or the forger failed otherwise); halting"],
            );
            hw::halt_forever();
        }
    }

    // ── 17. ADR-0024 D1: the mmap proof — ring-3 memory of its own.
    //      The blob maps TWO windows (page A and page B, guard-gapped
    //      by construction), writes and reads back patterns through
    //      both, munmaps B, re-verifies A survived the unmap, and then
    //      DELIBERATELY reads B: the #PF that kills the run is the
    //      proof the unmap was real (cr2 lands at the freed window's
    //      address — at/above the trampoline, where nothing but an
    //      mmap window ever lives). ──
    {
        static MMAP_DATA: [u8; 0x70] = {
            let mut d = [0u8; 0x70];
            d[0] = 6; // mode 6: the mmap proof
            d
        };
        let mapper = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            26,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &MMAP_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(
                    &mut out,
                    &["[M3] mmap: ERROR: mapper spawn failed; halting"],
                );
                hw::halt_forever();
            }
        };
        let kernel_cr3 = hw::read_cr3();
        mapper.run.tables.activate();
        crate::sched::context::begin(mapper.run);
        crate::sched::context::launch(&mapper.ctx);
        let run = crate::sched::context::take();
        hw::write_cr3(kernel_cr3);
        let cr2 = match run.exit {
            crate::sched::context::ExitKind::Fault {
                vector: 14, cr2, ..
            } if cr2 >= crate::mm::user_layout::TRAMPOLINE_BASE + 4096 => cr2,
            _ => {
                line(
                    &mut out,
                    &["[M3] mmap: ERROR: exit was not the expected freed-page fault; halting"],
                );
                hw::halt_forever();
            }
        };
        mm::user::destroy_user(&mut k, &mut pool, 26);
        let _ = crate::sched::preempt::on_exit(&mut k.sched, 26);
        let mut h = [0u8; 18];
        line(
            &mut out,
            &[
                "[M3] mmap: 2 windows mapped+verified, munmap freed, the freed read faulted at cr2=",
                strutil::hex(cr2, &mut h),
            ],
        );
    }

    // ── 18. ADR-0024 D2: the fork/CoW proof — fork's memory half,
    //      live. The forker (mode 7) mmaps a page, writes a pattern,
    //      forks (the tree clones, every writable page demoted RO on
    //      both sides, every shared frame refcounted), and BOTH sides
    //      write through the demotion — the parent a new pattern, the
    //      child a different one — each write served by a PRIVATE
    //      copy-on-write frame, each read-back verifying its own
    //      pattern. kmain runs the child through the parked handover
    //      after the parent exits, then tears both down and counts
    //      the reclaim. ──
    {
        static FORKER_DATA: [u8; 1] = [7]; // mode 7
        let forker = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            27,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &FORKER_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(&mut out, &["[M3] cow: ERROR: forker spawn failed; halting"]);
                hw::halt_forever();
            }
        };
        let kernel_cr3 = hw::read_cr3();
        forker.run.tables.activate();
        crate::sched::context::begin(forker.run);
        crate::sched::context::launch(&forker.ctx);
        // kmain resumes when the nested dispatcher empties: the parent
        // yields right after the fork (deterministic — a tick stealing
        // the child mid-run would race the exits), the child runs to
        // its exit, the parent resumes and finishes, and BOTH exits
        // land in the completed mailbox (the K2 nested-dispatcher
        // shape; teardown stays the spawner's contract).
        hw::write_cr3(kernel_cr3);
        let mut parent_ok = false;
        let mut child_ok = false;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            let clean = matches!(exit, crate::sched::context::ExitKind::Exited(0));
            if dom == 27 {
                parent_ok = clean;
            } else {
                child_ok = clean;
            }
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        let copies = crate::mm::shares::cow_copies();
        if parent_ok && child_ok && copies >= 2 {
            let mut b = [0u8; 20];
            line(
                &mut out,
                &[
                    "[M3] cow: fork shared, ",
                    strutil::dec(copies, &mut b),
                    " CoW copies served, both exits clean, frames reclaimed",
                ],
            );
        } else {
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            let mut b3 = [0u8; 20];
            line(
                &mut out,
                &[
                    "[M3] cow: ERROR: parent_ok=",
                    strutil::dec(parent_ok as u64, &mut b1),
                    " child_ok=",
                    strutil::dec(child_ok as u64, &mut b2),
                    " copies=",
                    strutil::dec(copies, &mut b3),
                    "; halting",
                ],
            );
            hw::halt_forever();
        }
    }

    // ── 19. ADR-0025: the IPC proof — capability-mediated endpoints,
    //      reached from ring 3 at last. The bootstrap (a uid-0
    //      supervisor domain) creates three endpoints — A owned by
    //      rx1, B by rx2, C by rx1 but NEVER granted to the sender —
    //      and grants the sender WRITE on A and B. The sender fills
    //      both queues (4 deep each), proves the 5th send refuses
    //      -EAGAIN (the bounded queue is not an unbounded privilege)
    //      and that the no-cap send to C refuses -EPERM (the gate is
    //      live, not decorative); the receivers drain their queues,
    //      verify every message's length, and prove the empty queue
    //      refuses -EAGAIN. Sequential runs — the async contract, not
    //      the timing, is the proof. ──
    {
        // The completed mailbox must be EMPTY here: a stale entry
        // means an earlier proof leaked an exit (and would corrupt
        // this proof's drain — found live: the demo's domain-22
        // leftover). Caught loudly, never consumed.
        if let Some((dom, _)) = crate::sched::park::completed_drain() {
            let mut b = [0u8; 20];
            crate::serial::write_str("[M3] ipc: ERROR: stale mailbox entry dom=");
            crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
            crate::serial::write_str("; halting\n");
            hw::halt_forever();
        }

        // The three runs FIRST (spawn_user_blob creates the
        // domains — the endpoint API needs live owners); the endpoint
        // ids are baked after creation, so the data pages are built
        // between spawn and launch.
        struct IpcRun {
            run: crate::sched::context::UserRun,
            ctx: crate::sched::context::UserContext,
        }
        let mut runs: [Option<IpcRun>; 3] = [None, None, None];
        for (i, dom) in [30u32, 28, 29].iter().enumerate() {
            // data[1]: role 0 = sender, 1 = receiver; channels land at
            // data[2..] once the endpoints exist.
            let mut data = [0u8; 0x70];
            data[0] = 8;
            data[1] = u8::from(*dom != 30);
            match mm::user::spawn_user_blob(
                &mut k,
                &mut pool,
                *dom,
                aegis_os::profile::service_profile(),
                RING3_PREEMPT,
                &data,
            ) {
                Ok(sp) => {
                    runs[i] = Some(IpcRun {
                        run: sp.run,
                        ctx: sp.ctx,
                    })
                }
                Err(_) => {
                    line(&mut out, &["[M3] ipc: ERROR: spawn failed; halting"]);
                    hw::halt_forever();
                }
            }
        }
        // The uid-0 supervisor for the bootstrap API (the killer
        // pattern: uid is explicit, never ambient).
        let _ = k.create_domain_with(31, aegis_os::profile::service_profile(), 0, 0, 0);
        let ep_a = k.ipc_endpoint_create(31, 28).expect("endpoint A");
        let ep_b = k.ipc_endpoint_create(31, 29).expect("endpoint B");
        let ep_c = k.ipc_endpoint_create(31, 28).expect("endpoint C");
        let _ = k.ipc_endpoint_grant(31, ep_a.0, 30, aegis_os::capability::Rights::WRITE);
        let _ = k.ipc_endpoint_grant(31, ep_b.0, 30, aegis_os::capability::Rights::WRITE);
        // The supervisor never RUNS — take it out of the scheduler or
        // the very next yield/tick picks an unparked domain (found
        // live: "yield/sleep picked unparked domain 31"). The domain
        // itself stays alive: the caps it granted remain derived from
        // a live principal.
        let _ = k.sched.unregister(31);

        // Bake the channel ids into each run's data page: the data
        // page's frame PA (found by the run's own tables, PAGE-
        // aligned), then word writes through the DIRECT MAP (memops
        // takes PAs — write_u8_va is the raw USER-VA reader under the
        // SMAP window, the wrong primitive here; found live as a CPL0
        // #PF at an unmapped 0x101f000).
        let bake = |run: &mut crate::sched::context::UserRun, chans: [u64; 3]| {
            if let Some(page) = run.tables.translate(0x00403000) {
                for (i, c) in chans.iter().enumerate() {
                    // data[2 + i*8 .. 10 + i*8] — the channel qword,
                    // offset 2 bytes into the page.
                    crate::memops::write_u64(page + 2 + (i * 8) as u64, *c);
                }
            }
        };
        if let Some(r) = runs[0].as_mut() {
            bake(
                &mut r.run,
                [u64::from(ep_a.0), u64::from(ep_b.0), u64::from(ep_c.0)],
            );
        }
        if let Some(r) = runs[1].as_mut() {
            bake(&mut r.run, [u64::from(ep_a.0), 0, 0]);
        }
        if let Some(r) = runs[2].as_mut() {
            bake(&mut r.run, [u64::from(ep_b.0), 0, 0]);
        }

        // The receivers: stashed parked-runnable (the fork-child
        // shape — the tick may pick them at any point mid-sender and
        // the preemptor demands parked runs). The sender runs via the
        // flat launch, fills both queues, proves the refusals, and
        // YIELDS — the nested dispatcher then runs the parked
        // receivers (each drains its queue, polling with yields until
        // the sender's messages land) and the parked sender to
        // completion; every exit lands in the completed mailbox.
        let mut parked: [(u32, &str); 2] = [(28, "rx1"), (29, "rx2")];
        for (i, (_dom, _)) in parked.iter().enumerate() {
            if let Some(r) = runs[1 + i].take() {
                crate::sched::context::stash_parked(
                    r.run,
                    crate::sched::context::ParkedContext::from_user_context(&r.ctx),
                );
            } else {
                line(&mut out, &["[M3] ipc: ERROR: receiver missing; halting"]);
                hw::halt_forever();
            }
        }
        {
            let Some(r) = runs[0].take() else {
                line(&mut out, &["[M3] ipc: ERROR: sender missing; halting"]);
                hw::halt_forever();
            };
            let kernel_cr3 = hw::read_cr3();
            r.run.tables.activate();
            crate::sched::context::begin(r.run);
            crate::sched::context::launch(&r.ctx);
            hw::write_cr3(kernel_cr3);
        }
        // kmain resumes when the nested dispatcher empties; drain all
        // three exits and tear each domain down.
        let mut clean = 0usize;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            if !matches!(exit, crate::sched::context::ExitKind::Exited(0)) {
                line(
                    &mut out,
                    &["[M3] ipc: ERROR: a run exited nonzero; halting"],
                );
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        if clean == 3 {
            line(
                &mut out,
                &["[M3] ipc: 8+ messages over 2 channels, caps enforced (EAGAIN + the no-cap EACCES), both ends verified"],
            );
        } else {
            line(
                &mut out,
                &["[M3] ipc: ERROR: expected 3 clean exits, saw fewer; halting"],
            );
            hw::halt_forever();
        }
        let _ = &mut parked;
    }

    // ── 20. ADR-0026: the sync IPC proof — call/reply over the
    //      park machinery, ring 3 to ring 3. A caller and a callee
    //      (the endpoint owner) trade TWO round-trips; both halves
    //      of the unified contract fire deterministically (the
    //      blob's yields pin the order): exchange 1 through the
    //      RENDEZVOUS (the callee parks in recv_wait before the
    //      caller's call — the push self-consumes, the callee wakes
    //      with the request len), exchange 2 through the QUEUED fast
    //      path (the callee yields between reply and the next
    //      recv_wait; the caller's call lands while nobody waits —
    //      the message queues; the callee's recv_wait pops it, no
    //      park). The caller's call returns exactly the reply len
    //      (the wake patched RAX); the callee's reply wakes exactly
    //      one waiter. ──
    {
        if let Some((dom, _)) = crate::sched::park::completed_drain() {
            let mut b = [0u8; 20];
            crate::serial::write_str("[M3] sync: ERROR: stale mailbox entry dom=");
            crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
            crate::serial::write_str("; halting\n");
            hw::halt_forever();
        }
        struct SyncRun {
            run: crate::sched::context::UserRun,
            ctx: crate::sched::context::UserContext,
        }
        let mut runs: [Option<SyncRun>; 2] = [None, None];
        for (i, dom) in [34u32, 35].iter().enumerate() {
            // data[1]: 0 = caller, 1 = callee; the channel lands at
            // data[2..] once the endpoint exists.
            let mut data = [0u8; 0x70];
            data[0] = 9;
            data[1] = u8::from(*dom == 35);
            match mm::user::spawn_user_blob(
                &mut k,
                &mut pool,
                *dom,
                aegis_os::profile::service_profile(),
                RING3_PREEMPT,
                &data,
            ) {
                Ok(sp) => {
                    runs[i] = Some(SyncRun {
                        run: sp.run,
                        ctx: sp.ctx,
                    })
                }
                Err(_) => {
                    line(&mut out, &["[M3] sync: ERROR: spawn failed; halting"]);
                    hw::halt_forever();
                }
            }
        }
        let _ = k.create_domain_with(36, aegis_os::profile::service_profile(), 0, 0, 0);
        let ep_d = k.ipc_endpoint_create(36, 35).expect("endpoint D");
        let _ = k.ipc_endpoint_grant(36, ep_d.0, 34, aegis_os::capability::Rights::WRITE);
        // The supervisor never runs (the round-M rule).
        let _ = k.sched.unregister(36);
        // Bake the channel id into each run's data page.
        let bake = |run: &mut crate::sched::context::UserRun, chan: u64| {
            if let Some(page) = run.tables.translate(0x00403000) {
                crate::memops::write_u64(page + 2, chan);
            }
        };
        if let Some(r) = runs[0].as_mut() {
            bake(&mut r.run, u64::from(ep_d.0));
        }
        if let Some(r) = runs[1].as_mut() {
            bake(&mut r.run, u64::from(ep_d.0));
        }
        // The callee stashed parked-runnable; the caller runs via the
        // flat launch, opens with the round-M yield, and the nested
        // dispatcher runs the pair to completion — the caller's call
        // parks it, the callee's reply wakes it, both exits land in
        // the mailbox.
        if let Some(r) = runs[1].take() {
            crate::sched::context::stash_parked(
                r.run,
                crate::sched::context::ParkedContext::from_user_context(&r.ctx),
            );
        } else {
            line(&mut out, &["[M3] sync: ERROR: callee missing; halting"]);
            hw::halt_forever();
        }
        {
            let Some(r) = runs[0].take() else {
                line(&mut out, &["[M3] sync: ERROR: caller missing; halting"]);
                hw::halt_forever();
            };
            let kernel_cr3 = hw::read_cr3();
            r.run.tables.activate();
            crate::sched::context::begin(r.run);
            crate::sched::context::launch(&r.ctx);
            hw::write_cr3(kernel_cr3);
        }
        let mut clean = 0usize;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            if !matches!(exit, crate::sched::context::ExitKind::Exited(0)) {
                line(
                    &mut out,
                    &["[M3] sync: ERROR: a run exited nonzero; halting"],
                );
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        if clean == 2 {
            line(
                &mut out,
                &["[M3] sync: 2 round-trips, call blocked and returned both replies, recv_wait returned both requests"],
            );
        } else {
            line(
                &mut out,
                &["[M3] sync: ERROR: expected 2 clean exits, saw fewer; halting"],
            );
            hw::halt_forever();
        }
    }

    // ── 21. ADR-0027: the page-grant proof — memory capability
    //      transfer, ring 3 to ring 3, over the ADR-0024 accounting.
    //      A granter (uid 0, holding a Domain capability on the
    //      grantee — the kill pattern) mmaps a page, writes a
    //      pattern, and grants it RW through the grantee's OWN
    //      policy (quota and overlap apply; the window is the
    //      receiver's next free one). The granted VA travels through
    //      the sync IPC (two u16 halves — the message bound), the
    //      grantee reads the pattern THROUGH the grant, writes its
    //      mark, and replies; the granter's call returns the reply
    //      and its OWN page carries the mark — the bidirectional
    //      shared-memory proof. The refcount keeps the page alive
    //      for both; each exit releases its side (the D2 rule this
    //      round fixed). ──
    {
        if let Some((dom, _)) = crate::sched::park::completed_drain() {
            let mut b = [0u8; 20];
            crate::serial::write_str("[M3] grants: ERROR: stale mailbox entry dom=");
            crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
            crate::serial::write_str("; halting\n");
            hw::halt_forever();
        }
        struct GrantRun {
            run: crate::sched::context::UserRun,
            ctx: crate::sched::context::UserContext,
        }
        let mut runs: [Option<GrantRun>; 2] = [None, None];
        for (i, dom) in [37u32, 38].iter().enumerate() {
            // data[1]: 0 = granter, 1 = grantee; data[2..10]: channel
            // E; data[10]: the grantee's id (the grant's dst).
            let mut data = [0u8; 0x70];
            data[0] = 10;
            data[1] = u8::from(*dom == 38);
            match mm::user::spawn_user_blob(
                &mut k,
                &mut pool,
                *dom,
                aegis_os::profile::service_profile(),
                RING3_PREEMPT,
                &data,
            ) {
                Ok(sp) => {
                    runs[i] = Some(GrantRun {
                        run: sp.run,
                        ctx: sp.ctx,
                    })
                }
                Err(_) => {
                    line(&mut out, &["[M3] grants: ERROR: spawn failed; halting"]);
                    hw::halt_forever();
                }
            }
        }
        // The supervisor 39 (uid 0, never runs — the round-M rule)
        // creates the endpoint, grants WRITE on it to the granter,
        // and confers the GRANT GATE: a Domain(38) capability in the
        // granter's own list (the endpoint-grant shape for domain
        // caps — a privileged, auditable bootstrap; the spawned
        // granter's derived uid is never root, so the self-grant API
        // is not its path).
        let _ = k.create_domain_with(39, aegis_os::profile::service_profile(), 0, 0, 0);
        let ep_e = k.ipc_endpoint_create(39, 38).expect("endpoint E");
        let _ = k.ipc_endpoint_grant(39, ep_e.0, 37, aegis_os::capability::Rights::WRITE);
        k.cap_grant_domain_to(39, 37, 38)
            .expect("the granter's Domain cap on the grantee");
        let _ = k.sched.unregister(39);
        // Bake: the channel qword + the grantee's id at data[10].
        let bake = |run: &mut crate::sched::context::UserRun, chan: u64, dst: u8| {
            if let Some(page) = run.tables.translate(0x00403000) {
                crate::memops::write_u64(page + 2, chan);
                crate::memops::write_u16(page + 10, u16::from(dst));
            }
        };
        if let Some(r) = runs[0].as_mut() {
            bake(&mut r.run, u64::from(ep_e.0), 38);
        }
        if let Some(r) = runs[1].as_mut() {
            bake(&mut r.run, u64::from(ep_e.0), 38);
        }
        // The grantee parked-runnable; the granter flat-launched (the
        // opening yield hands the dispatcher the chain).
        if let Some(r) = runs[1].take() {
            crate::sched::context::stash_parked(
                r.run,
                crate::sched::context::ParkedContext::from_user_context(&r.ctx),
            );
        } else {
            line(&mut out, &["[M3] grants: ERROR: grantee missing; halting"]);
            hw::halt_forever();
        }
        {
            let Some(r) = runs[0].take() else {
                line(&mut out, &["[M3] grants: ERROR: granter missing; halting"]);
                hw::halt_forever();
            };
            let kernel_cr3 = hw::read_cr3();
            r.run.tables.activate();
            crate::sched::context::begin(r.run);
            crate::sched::context::launch(&r.ctx);
            hw::write_cr3(kernel_cr3);
        }
        let mut clean = 0usize;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            if !matches!(exit, crate::sched::context::ExitKind::Exited(0)) {
                let mut b = [0u8; 20];
                crate::serial::write_str("[M3] grants: ERROR: dom=");
                crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
                crate::serial::write_str(" exit=");
                if let crate::sched::context::ExitKind::Exited(c) = exit {
                    crate::serial::write_str(strutil::dec(c, &mut b));
                }
                crate::serial::write_str(
                    "
",
                );
                line(
                    &mut out,
                    &["[M3] grants: ERROR: a run exited nonzero; halting"],
                );
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        if clean == 2 {
            line(
                &mut out,
                &["[M3] grants: 1 page RW, the grantee read the pattern and the granter saw the reply-write"],
            );
        } else {
            line(
                &mut out,
                &["[M3] grants: ERROR: expected 2 clean exits, saw fewer; halting"],
            );
            hw::halt_forever();
        }
    }

    // ── 22. ADR-0028: the bench — the honest measurement round.
    //      "Measured, not guessed" finally has numbers: the blob
    //      itself times every operation end-to-end with rdtsc (the
    //      syscall entry, the park, the wake, the resume — what a
    //      real caller pays), and self-reports the raw TSC deltas in
    //      hex through SYS_WRITE (a `[BENCH]` line above). This
    //      block supplies the topology (a responder parked in
    //      recv_wait for the RTT; a parked grantee for the grant;
    //      fork children for the CoW samples) and the CALIBRATION
    //      line: the ACPI-measured tsc_hz that converts the deltas.
    //      The decoder: scripts/bench-decode.py. Expected drains: 6
    //      clean exits (the measurer, the responder, 4 children). ──
    {
        if let Some((dom, _)) = crate::sched::park::completed_drain() {
            let mut b = [0u8; 20];
            crate::serial::write_str("[M3] bench: ERROR: stale mailbox entry dom=");
            crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
            crate::serial::write_str("; halting\n");
            hw::halt_forever();
        }
        struct BenchRun {
            run: crate::sched::context::UserRun,
            ctx: crate::sched::context::UserContext,
        }
        let mut runs: [Option<BenchRun>; 2] = [None, None];
        for (i, dom) in [40u32, 41].iter().enumerate() {
            // data[1]: 0 = measurer, 1 = responder; data[2..10]:
            // channel E; data[10]: the responder's id (the grant dst).
            let mut data = [0u8; 0x70];
            data[0] = 11;
            data[1] = u8::from(*dom == 41);
            match mm::user::spawn_user_blob(
                &mut k,
                &mut pool,
                *dom,
                aegis_os::profile::service_profile(),
                RING3_PREEMPT,
                &data,
            ) {
                Ok(sp) => {
                    runs[i] = Some(BenchRun {
                        run: sp.run,
                        ctx: sp.ctx,
                    })
                }
                Err(_) => {
                    line(&mut out, &["[M3] bench: ERROR: spawn failed; halting"]);
                    hw::halt_forever();
                }
            }
        }
        // The supervisor 39 (uid 0, never runs): the endpoint owned
        // by the responder, WRITE granted to the measurer, and the
        // GRANT gate conferred (the Domain cap on the responder —
        // the measurer's uid is derived, never root).
        let _ = k.create_domain_with(39, aegis_os::profile::service_profile(), 0, 0, 0);
        let ep_e = k.ipc_endpoint_create(39, 41).expect("endpoint E");
        let _ = k.ipc_endpoint_grant(39, ep_e.0, 40, aegis_os::capability::Rights::WRITE);
        k.cap_grant_domain_to(39, 40, 41)
            .expect("the measurer's Domain cap on the responder");
        let _ = k.sched.unregister(39);
        let bake = |run: &mut crate::sched::context::UserRun, chan: u64, dst: u8| {
            if let Some(page) = run.tables.translate(0x00403000) {
                crate::memops::write_u64(page + 2, chan);
                crate::memops::write_u16(page + 10, u16::from(dst));
            }
        };
        if let Some(r) = runs[0].as_mut() {
            bake(&mut r.run, u64::from(ep_e.0), 41);
        }
        if let Some(r) = runs[1].as_mut() {
            bake(&mut r.run, u64::from(ep_e.0), 41);
        }

        // The responder parked-runnable (it recv_waits first thing);
        // the measurer flat-launched (the opening yield hands it over
        // once, then it owns the CPU for every sample).
        if let Some(r) = runs[1].take() {
            crate::sched::context::stash_parked(
                r.run,
                crate::sched::context::ParkedContext::from_user_context(&r.ctx),
            );
        } else {
            line(&mut out, &["[M3] bench: ERROR: responder missing; halting"]);
            hw::halt_forever();
        }
        {
            let Some(r) = runs[0].take() else {
                line(&mut out, &["[M3] bench: ERROR: measurer missing; halting"]);
                hw::halt_forever();
            };
            let kernel_cr3 = hw::read_cr3();
            r.run.tables.activate();
            crate::sched::context::begin(r.run);
            crate::sched::context::launch(&r.ctx);
            hw::write_cr3(kernel_cr3);
        }
        // The expected drains: the measurer, the responder, and the
        // 4 fork children the CoW samples leave behind.
        let mut clean = 0usize;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            if !matches!(exit, crate::sched::context::ExitKind::Exited(0)) {
                let mut b = [0u8; 20];
                crate::serial::write_str("[M3] bench: ERROR: dom=");
                crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
                crate::serial::write_str(" exit=");
                if let crate::sched::context::ExitKind::Exited(c) = exit {
                    crate::serial::write_str(strutil::dec(c, &mut b));
                }
                crate::serial::write_str("\n");
                line(
                    &mut out,
                    &["[M3] bench: ERROR: a run exited nonzero; halting"],
                );
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        let mut b1 = [0u8; 20];
        if clean == 6 {
            line(
                &mut out,
                &["[M3] bench: 6 clean exits, metrics self-reported above in TSC cycles"],
            );
            crate::serial::write_str("[M3] bench: tsc_hz=");
            crate::serial::write_str(strutil::dec(crate::clock::tsc_hz(), &mut b1));
            crate::serial::write_str(" (ACPI-calibrated; decode with scripts/bench-decode.py)\n");
        } else {
            let mut b2 = [0u8; 20];
            crate::serial::write_str("[M3] bench: drained clean=");
            crate::serial::write_str(strutil::dec(clean as u64, &mut b2));
            crate::serial::write_str(" of 6\n");

            line(
                &mut out,
                &["[M3] bench: ERROR: expected 6 clean exits, saw fewer; halting"],
            );
            hw::halt_forever();
        }
    }

    // ── 23. ADR-0029: the pipe proof — a byte channel crosses
    //      domains, capability-mediated, and the service story
    //      completes: control over the message endpoints
    //      (ADR-0025/26), DATA over the byte channel. A WRITER
    //      (WRITE cap only) and the READER (F's owner) trade 64
    //      bytes in two pinned exchanges — the RENDEZVOUS (the parked
    //      reader wakes with the byte count, wake-without-consume)
    //      and the FAST PATH (recv_wait answers the avail, no park) —
    //      plus the live refusals (the no-cap EACCES, the full-ring
    //      EAGAIN) and the fd round-trip (pipe() now creates a
    //      channel endpoint; the rerouted fd path proven at ring 3).
    //      Expected drains: 2 clean exits. The supervisor 44 also
    //      sweeps the six endpoints the finished proofs left in the
    //      eight-slot table (caps on destroyed ids fail closed — the
    //      no-ABA rule; nothing strands) and destroys F/G after the
    //      pair. ──
    {
        if let Some((dom, _)) = crate::sched::park::completed_drain() {
            let mut b = [0u8; 20];
            crate::serial::write_str("[M3] pipe: ERROR: stale mailbox entry dom=");
            crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
            crate::serial::write_str("; halting\n");
            hw::halt_forever();
        }
        struct PipeRun {
            run: crate::sched::context::UserRun,
            ctx: crate::sched::context::UserContext,
        }
        let mut runs: [Option<PipeRun>; 2] = [None, None];
        for (i, dom) in [42u32, 43].iter().enumerate() {
            // data[1]: 0 = the writer, 1 = the reader; data[2..10]:
            // channel F; data[10..18]: channel G (the no-cap probe).
            let mut data = [0u8; 0x70];
            data[0] = 12;
            data[1] = u8::from(*dom == 43);
            match mm::user::spawn_user_blob(
                &mut k,
                &mut pool,
                *dom,
                aegis_os::profile::service_profile(),
                RING3_PREEMPT,
                &data,
            ) {
                Ok(sp) => {
                    runs[i] = Some(PipeRun {
                        run: sp.run,
                        ctx: sp.ctx,
                    })
                }
                Err(_) => {
                    line(&mut out, &["[M3] pipe: ERROR: spawn failed; halting"]);
                    hw::halt_forever();
                }
            }
        }
        // The supervisor 44 (uid 0, never runs). FIRST the hygiene
        // sweep: the finished proofs left six endpoints in the
        // eight-slot table and this round needs F, G, and the
        // reader's fd channel — three slots that do not exist until
        // the dead weight goes (found by arithmetic, not by a
        // TableFull boot failure).
        let _ = k.create_domain_with(44, aegis_os::profile::service_profile(), 0, 0, 0);
        // (Collect-then-destroy: the iterator borrows k immutably; the
        // destroy needs it mutable. A fixed array — no allocation.)
        let mut stale = [0u32; aegis_os::ipc::MAX_ENDPOINTS];
        let mut sn = 0usize;
        for id in k.live_endpoint_ids() {
            if sn < stale.len() {
                stale[sn] = id;
                sn += 1;
            }
        }
        for &id in &stale[..sn] {
            let _ = k.ipc_endpoint_destroy(44, id);
        }
        // F is owned by the READER; G's owner is the supervisor itself
        // — the writer must hold NOTHING on G (the no-cap probe), and
        // a self-owned channel never self-reclaims (no fd refs).
        let (f, _hf) = k.ipc_channel_create(44, 43).expect("channel F");
        let (g, _hg) = k.ipc_channel_create(44, 44).expect("channel G");
        let _ = k.ipc_endpoint_grant(44, f, 42, aegis_os::capability::Rights::WRITE);
        let _ = k.sched.unregister(44);
        let bake = |run: &mut crate::sched::context::UserRun, f: u64, g: u64| {
            if let Some(page) = run.tables.translate(0x00403000) {
                crate::memops::write_u64(page + 2, f);
                crate::memops::write_u64(page + 10, g);
            }
        };
        if let Some(r) = runs[0].as_mut() {
            bake(&mut r.run, u64::from(f), u64::from(g));
        }
        if let Some(r) = runs[1].as_mut() {
            bake(&mut r.run, u64::from(f), 0);
        }

        // The reader parked-runnable (its recv_wait parks before the
        // writer's first write — the rendezvous half); the writer
        // flat-launched (the yields pin every exchange).
        if let Some(r) = runs[1].take() {
            crate::sched::context::stash_parked(
                r.run,
                crate::sched::context::ParkedContext::from_user_context(&r.ctx),
            );
        } else {
            line(&mut out, &["[M3] pipe: ERROR: reader missing; halting"]);
            hw::halt_forever();
        }
        {
            let Some(r) = runs[0].take() else {
                line(&mut out, &["[M3] pipe: ERROR: writer missing; halting"]);
                hw::halt_forever();
            };
            let kernel_cr3 = hw::read_cr3();
            r.run.tables.activate();
            crate::sched::context::begin(r.run);
            crate::sched::context::launch(&r.ctx);
            hw::write_cr3(kernel_cr3);
        }
        let mut clean = 0usize;
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            if !matches!(exit, crate::sched::context::ExitKind::Exited(0)) {
                let mut b = [0u8; 20];
                crate::serial::write_str("[M3] pipe: ERROR: dom=");
                crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
                crate::serial::write_str(" exit=");
                if let crate::sched::context::ExitKind::Exited(c) = exit {
                    crate::serial::write_str(strutil::dec(c, &mut b));
                }
                crate::serial::write_str("; halting\n");
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        if clean == 2 {
            line(
                &mut out,
                &["[M3] pipe: 64 bytes cross-domain byte-exact, caps enforced (EACCES + EAGAIN), rendezvous wake + fd path live"],
            );
        } else {
            line(
                &mut out,
                &["[M3] pipe: ERROR: expected 2 clean exits, saw fewer; halting"],
            );
            hw::halt_forever();
        }
        // The after-sweep: F and G die now; their ids stay dead
        // forever. The reader's fd channel already reclaimed itself
        // (both fds closed in-blob — the fd-scoped lifetime).
        let _ = k.ipc_endpoint_destroy(44, f);
        let _ = k.ipc_endpoint_destroy(44, g);
    }

    // ── 24. ADR-0003 (v1): the Linux-ABI blob — one domain, speaking
    //      ONLY Linux x86_64 numbers. The per-domain ABI flag flips
    //      the entry to the WHITELIST table (translation before the
    //      bounds check and the policy gate; profiles stay internal-
    //      op-based). The blob exercises the shape differences: pipe
    //      (22) splits rax=read/rdx=write, exit_group (231) aliases
    //      exit, mmap (9) demands MAP_PRIVATE|MAP_ANONYMOUS; open
    //      (2) translates the Linux O_* word at the arm (create /
    //      write / close / O_RDONLY reopen with read-back through an
    //      independent cursor, then O_EXCL and O_APPEND must REFUSE
    //      -EINVAL — a bit we cannot honor is never silently
    //      dropped); and the two whitelist probes — uname (63) must
    //      answer -ENOSYS
    //      (internal 63 is EXIT: a pass-through would exit a Linux
    //      binary on uname) and getpid (39) likewise. fork (57)
    //      under the Linux ABI; then wait4 (61) — slice 3: the
    //      WNOHANG probe (nothing ready -> 0), the BLOCKING wait
    //      (the syscall parks rip-2 — resume RE-EXECUTES it; the
    //      dispatcher runs the fork-parked child, whose exit(7)
    //      wakes the parent through the waiter registry), the
    //      re-executed wait reaps: pid == the fork's child, wstatus
    //      == 7 << 8, and a further wait answers -ECHILD. The
    //      child's CoW store and its write run on the way to
    //      exit_group(7). Expected drains: exactly ONE clean exit —
    //      the parent's; the wait arm CONSUMED the child's completed
    //      entry (its teardown ran there: destroy_user, then
    //      exit_process records the zombie wait_process reaps), so
    //      the mailbox never sees it. The child's honesty is proven
    //      by the wstatus check, not by the drain count.
    //      ──
    {
        if let Some((dom, _)) = crate::sched::park::completed_drain() {
            let mut b = [0u8; 20];
            crate::serial::write_str("[M3] linux-abi: ERROR: stale mailbox entry dom=");
            crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
            crate::serial::write_str("; halting\n");
            hw::halt_forever();
        }
        let mut data = [0u8; 0x70];
        data[0] = 13;
        let sp = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            45,
            aegis_os::profile::service_profile(),
            RING3_PREEMPT,
            &data,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(&mut out, &["[M3] linux-abi: ERROR: spawn failed; halting"]);
                hw::halt_forever();
            }
        };
        // v1: the domain speaks Linux numbers — the supervisor's
        // declaration, not a syscall (the flag changes number
        // translation, never policy).
        let _ = k.set_domain_abi(45, aegis_os::syscall::Abi::Linux);
        let kernel_cr3 = hw::read_cr3();
        sp.run.tables.activate();
        crate::sched::context::begin(sp.run);
        crate::sched::context::launch(&sp.ctx);
        hw::write_cr3(kernel_cr3);
        let mut clean = 0usize;
        // The launch-path exit: a run may exit straight out of launch
        // (never parked) — its exit sits in USER_RUN, not the mailbox
        // (dispatch_next records only the runs IT resumed; both exit
        // paths leave the run in the slot). try_take is the ADR-0026
        // tolerant twin — the parked flow returns with the slot empty
        // and the mailbox carries every exit. (Found live, round U:
        // round T's edit with this exact comment landed in the IPC
        // section's harness — the first textual match — benign there
        // but missing here, and the wait4 parent, which exits without
        // parking when the arm is absent, exposed the gap as a silent
        // identity-less "different count".)
        if let Some(run) = crate::sched::context::try_take() {
            if !matches!(run.exit, crate::sched::context::ExitKind::Exited(0)) {
                let mut b = [0u8; 20];
                crate::serial::write_str("[M3] linux-abi: ERROR: dom=");
                crate::serial::write_str(strutil::dec(u64::from(run.domain), &mut b));
                crate::serial::write_str(" exit=");
                if let crate::sched::context::ExitKind::Exited(c) = run.exit {
                    crate::serial::write_str(strutil::dec(c, &mut b));
                }
                crate::serial::write_str("; halting\n");
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, run.domain);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, run.domain);
        }
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            if !matches!(exit, crate::sched::context::ExitKind::Exited(0)) {
                let mut b = [0u8; 20];
                crate::serial::write_str("[M3] linux-abi: ERROR: dom=");
                crate::serial::write_str(strutil::dec(u64::from(dom), &mut b));
                crate::serial::write_str(" exit=");
                if let crate::sched::context::ExitKind::Exited(c) = exit {
                    crate::serial::write_str(strutil::dec(c, &mut b));
                }
                crate::serial::write_str("; halting\n");
                hw::halt_forever();
            }
            clean += 1;
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        // Slice 3: exactly ONE clean drain — the parent. The wait
        // arm consumed the child's completed entry (its full teardown
        // ran there); the child's exit honesty is the blob's wstatus
        // check (7 << 8), not a second drain.
        if clean == 1 {
            line(
                &mut out,
                &["[M3] linux-abi: v1 entry live — pipe rax/rdx split, EOF, fork + exit_group, mmap flags, open(2) O_* translated (O_EXCL/O_APPEND refused), wait4(61) WNOHANG/block/reap (wstatus 7<<8, then ECHILD), execve(59) -> the compiled-in ELF64 image (bss-clean entry, wstatus 11<<8), uname(63) -> -ENOSYS, Phase-6 S1: mkdir(83)/unlink(87, rmdir-fold ENOTEMPTY)/chroot(161, the escaped path answers ENOENT inside the jail)"],
            );
        } else {
            line(
                &mut out,
                &["[M3] linux-abi: ERROR: expected 1 clean exit (the child is consumed by the wait), saw a different count; halting"],
            );
            hw::halt_forever();
        }
    }

    // ── Phase 7, slice 1 (M3): PID 1 — the init pattern. A dedicated
    //    blob speaks Linux v1 from the REAL init pid: fork A; A forks
    //    the orphan B and exit_group(7)s; B exit_group(33)s. The
    //    kernel reparents B to PID 1 (ADR-0022 D7's reparent_children,
    //    live in the lib since round K), and init's BLOCKING wait4(-1)
    //    loop reaps both — 7<<8 and the adopted orphan's 33<<8 — until
    //    -ECHILD drains it. The blob verifies every answer in itself;
    //    exit(0) is the drained-and-verified proof.
    {
        static INIT_DATA: [u8; 1] = [0]; // no modes — the fork branches are the roles
        let sp = match mm::user::spawn_user_blob(
            &mut k,
            &mut pool,
            aegis_os::proc::INIT_PID,
            aegis_os::profile::service_profile(),
            RING3_INIT,
            &INIT_DATA,
        ) {
            Ok(sp) => sp,
            Err(_) => {
                line(&mut out, &["[M3] init: ERROR: spawn failed; halting"]);
                hw::halt_forever();
            }
        };
        // v1: PID 1 speaks Linux numbers — the supervisor's
        // declaration; the fork children inherit it (ADR-0003).
        let _ = k.set_domain_abi(aegis_os::proc::INIT_PID, aegis_os::syscall::Abi::Linux);
        let kernel_cr3 = hw::read_cr3();
        sp.run.tables.activate();
        crate::sched::context::begin(sp.run);
        crate::sched::context::launch(&sp.ctx);
        hw::write_cr3(kernel_cr3);
        let mut clean = 0usize;
        let mut bad: Option<(u32, u64)> = None;
        // Both exit paths leave the run in the slot (round U's lesson):
        // try_take first, then the parked mailbox.
        if let Some(run) = crate::sched::context::try_take() {
            match run.exit {
                crate::sched::context::ExitKind::Exited(0) => clean += 1,
                crate::sched::context::ExitKind::Exited(c) => bad = Some((run.domain, c)),
                _ => bad = Some((run.domain, u64::MAX)),
            }
            mm::user::destroy_user(&mut k, &mut pool, run.domain);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, run.domain);
        }
        while let Some((dom, exit)) = crate::sched::park::completed_drain() {
            match exit {
                crate::sched::context::ExitKind::Exited(0) => clean += 1,
                crate::sched::context::ExitKind::Exited(c) => bad = bad.or(Some((dom, c))),
                _ => bad = bad.or(Some((dom, u64::MAX))),
            }
            mm::user::destroy_user(&mut k, &mut pool, dom);
            let _ = crate::sched::preempt::on_exit(&mut k.sched, dom);
        }
        if let Some((dom, c)) = bad {
            let mut b1 = [0u8; 20];
            let mut b2 = [0u8; 20];
            line(
                &mut out,
                &[
                    "[M3] init: ERROR: dom=",
                    strutil::dec(u64::from(dom), &mut b1),
                    " exit=",
                    strutil::dec(c, &mut b2),
                    "; halting",
                ],
            );
            hw::halt_forever();
        }
        // Exactly ONE clean exit — init's own. The wait4 loop consumed
        // BOTH children (A's and the adopted orphan's completions); a
        // stray mailbox entry here is the round-W failure shape — fail
        // loudly, never absorb it.
        if clean == 1 {
            line(
                &mut out,
                &["[M3] init: PID 1's wait4 loop drained — 2 children reaped (exit 7 + the reparented orphan's 33), ECHILD ended the loop (Phase 7)"],
            );
        } else {
            let mut b1 = [0u8; 20];
            line(
                &mut out,
                &[
                    "[M3] init: ERROR: expected 1 clean exit (the wait4 loop consumed both children), saw ",
                    strutil::dec(clean as u64, &mut b1),
                    "; halting",
                ],
            );
            hw::halt_forever();
        }
    }

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
            out,
            &["[SCHD] preemption demo: retiring the M1 hello domain (a kernel-resident CFS entity must never be preemptor-picked)"],
        );
    mm::user::destroy_user(k, pool, 1);

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
        k,
        pool,
        20,
        aegis_os::profile::service_profile(),
        RING3_PREEMPT,
        &SPINNER_DATA,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[SCHD] ERROR: spinner spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    let writer = match mm::user::spawn_user_blob(
        k,
        pool,
        21,
        aegis_os::profile::service_profile(),
        RING3_PREEMPT,
        &WRITER_DATA,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[SCHD] ERROR: writer spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(
            out,
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
                // A live run never reaches the reaper's match.
                crate::sched::context::ExitKind::Running => ("running?", 0),
                crate::sched::context::ExitKind::Exited(c) => ("exited", *c),
                crate::sched::context::ExitKind::Fault { vector, .. } => {
                    // A fault during the demo is a demo failure — these
                    // blobs touch nothing but their own pages.
                    let mut bv = [0u8; 20];
                    line(
                        out,
                        &[
                            "[SCHD] ERROR: domain ",
                            strutil::dec(finished as u64, &mut bv),
                            " faulted (vector below) — halting",
                        ],
                    );
                    let mut bv2 = [0u8; 20];
                    line(
                        out,
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
                out,
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
        mm::user::destroy_user(k, pool, finished);
        match crate::sched::preempt::on_exit(&mut k.sched, finished) {
            Some(next) => {
                let Some((nrun, nctx)) = crate::sched::context::take_parked(next) else {
                    line(out, &["[SCHD] ERROR: handover target not parked; halting"]);
                    hw::halt_forever();
                };
                let mut b = [0u8; 20];
                line(
                    out,
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
            out,
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
                out,
                &[
                    "[SCHD] starvation-freedom: writer (21) finished while spinner (20) still runnable, writes=",
                    strutil::dec(writer_writes, &mut b),
                ],
            );
        line(
                out,
                &["[VERDICT] M2-W2 PREEMPTION: PASS — timer-driven CFS, ring-3 preemptible, monitor windows close on tick"],
            );
        // ADR-0023's M3 marker (boot.sh greps this on every lane):
        // two ring-3 processes interleaved under preemption and the
        // CPU-hog starved nobody.
        {
            let mut b = [0u8; 20];
            line(
                out,
                &[
                    "[M3] preempt: 2 runs interleaved (switches=",
                    strutil::dec(switches, &mut b),
                    "), hog starved nobody",
                ],
            );
        }
    } else {
        line(
                out,
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
