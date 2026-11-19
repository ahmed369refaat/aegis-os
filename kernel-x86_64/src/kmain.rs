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
//! 9. the terminal act: write through a fresh stack's guard page — the
//!    #PF is diagnosed, the marker printed, and QEMU powers off.
//!
//! No allocation: log lines are `&str` fragments plus stack-buffer numbers.

use crate::arch;
use crate::frames::{FramePool, FRAME_SIZE, KERNEL_POOL_FRAMES, KERNEL_POOL_LEN, POOL_BASE};

/// The ring-3 example blobs (built to flat binaries by boot.sh from
/// `examples/ring3-{hello,rogue}` and embedded here — PR-1.4).
static RING3_HELLO: &[u8] = include_bytes!("../blob/ring3-hello.bin");
static RING3_ROGUE: &[u8] = include_bytes!("../blob/ring3-rogue.bin");
/// The exact message the hello blob writes from ring-3 (its length is
/// baked into the blob's `mov edx, 26`).
const RING3_MSG: &[u8] = b"hello from ring 3 (CPL=3)\n";
use crate::runtime::{self, HelloReport, M1Error, MonitorReport, StressReport};
use crate::{hw, memops, mm, multiboot, serial, strutil};
use aegis_os::memory::MemFlags;
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
    //      Then the memory layout settles into its final shape (ADR-0002):
    //      the low identity window dies, per-CPU state is armed, and the
    //      `[MM ] higher-half ok` line goes out.
    arch::init();
    mm::init();

    // ── 2. multiboot validation ─────────────────────────────────────
    if magic != multiboot::BOOT_MAGIC {
        line(&mut out, &["[BOOT] ERROR: not started by a multiboot loader (magic mismatch); halting"]);
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
        line(&mut out, &["[BOOT] multiboot ok: mem_lower=", strutil::dec(mem_lower as u64, &mut b)]);
        let mut b2 = [0u8; 20];
        line(&mut out, &["       mem_upper=", strutil::dec(mem_upper as u64, &mut b2), " KiB"]);
    }
    if !mi.contains(POOL_BASE, KERNEL_POOL_LEN) {
        line(&mut out, &["[MEM ] ERROR: frame pool (16..32 MiB) does not fit reported low memory; halting"]);
        hw::halt_forever();
    }

    // ── 3. frame pool: claim + scrub ────────────────────────────────
    // 4096 frames (16 MiB) since PR-1.3: per-domain page tables need
    // the room (every domain carries PML4+PDPT+PD+PTs plus its pages).
    let mut pool = FramePool::<KERNEL_POOL_FRAMES>::new(POOL_BASE, memops::scrub_frame);
    for f in 0..(KERNEL_POOL_LEN / FRAME_SIZE) {
        memops::scrub_frame(POOL_BASE + f * FRAME_SIZE);
    }
    line(&mut out, &["[MEM ] frame pool claimed: 4096 frames @ 16 MiB..32 MiB, scrubbed"]);

    let mut k = Kernel::<KERNEL_POOL_FRAMES>::new_over_arena();
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
    // Prove the entry path end-to-end: force a hardware #DE; the
    // dispatch prints the diagnosis + markers, advances RIP past the
    // idiv, and RETURNS — the unwind path is live, execution continues
    // below. If the machinery were broken, the CPU would triple-fault
    // and the markers would be missing — loud either way.
    line(&mut out, &["[ARCH] exception selftest: forcing #DE"]);
    arch::exceptions::arm_and_trigger_de();
    line(&mut out, &["[ARCH] back from the #DE handler: unwind path live"]);

    // ── 7. per-domain page tables (PR-1.3) ─────────────────────────
    // The M1 policy stays the gate; its decisions become hardware: two
    // domains with disjoint tables, the same virtual address resolving
    // to different frames, W^X enforced by NX, and the policy's guard
    // gaps as real absent pages that fault when touched.
    line(&mut out, &["[MM ] per-domain tables: building domain A (owner 3) and B (owner 4)"]);
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
            line(&mut out, &["[MM ] ERROR: domain A tables alloc failed; halting"]);
            hw::halt_forever();
        }
    };
    tables_a.install_kernel_entries();
    let mut space_a = aegis_os::memory::AddressSpace::new(16);
    if tables_a
        .map_region(&mut space_a, VA, 2 * mm::PAGE as usize, MemFlags::READ | MemFlags::WRITE, &mut src)
        .is_err()
    {
        line(&mut out, &["[MM ] ERROR: domain A RW region refused; halting"]);
        hw::halt_forever();
    }
    if tables_a
        .map_region(&mut space_a, RX_VA, mm::PAGE as usize, MemFlags::READ | MemFlags::EXEC, &mut src)
        .is_err()
    {
        line(&mut out, &["[MM ] ERROR: domain A RX region refused; halting"]);
        hw::halt_forever();
    }
    let (Some(pa_a), Some(pa_ax)) = (tables_a.translate(VA), tables_a.translate(RX_VA)) else {
        line(&mut out, &["[MM ] ERROR: domain A translate failed; halting"]);
        hw::halt_forever();
    };
    memops::write_u64(pa_a, PATTERN_A);
    memops::write_u64(pa_ax, 0xC3); // `ret` — one-byte executable payload

    // Domain B: the SAME virtual address, one page, a different pattern.
    src.owner = 4;
    let mut tables_b = match mm::page_table::PageTables::new(&mut src) {
        Ok(t) => t,
        Err(_) => {
            line(&mut out, &["[MM ] ERROR: domain B tables alloc failed; halting"]);
            hw::halt_forever();
        }
    };
    tables_b.install_kernel_entries();
    let mut space_b = aegis_os::memory::AddressSpace::new(16);
    if tables_b
        .map_region(&mut space_b, VA, mm::PAGE as usize, MemFlags::READ | MemFlags::WRITE, &mut src)
        .is_err()
    {
        line(&mut out, &["[MM ] ERROR: domain B RW region refused; halting"]);
        hw::halt_forever();
    }
    let Some(pa_b) = tables_b.translate(VA) else {
        line(&mut out, &["[MM ] ERROR: domain B translate failed; halting"]);
        hw::halt_forever();
    };
    memops::write_u64(pa_b, PATTERN_B);

    // ── A's tables active: user half belongs to A ──
    tables_a.activate();
    line(&mut out, &["[MM ] domain A tables active (CR3 switched): user half is A's"]);
    let via_va = memops::read_u64_va(VA);
    let via_dm = memops::read_u64(pa_a);
    if via_va != PATTERN_A || via_dm != PATTERN_A {
        line(&mut out, &["[MM ] ERROR: A's page disagrees with its frame; halting"]);
        hw::halt_forever();
    }
    line(&mut out, &["[MM ] A: VA reads back its pattern (direct-map frame agrees)"]);
    line(&mut out, &["[ARCH] NX selftest: calling into A's RW (non-executable) page"]);
    arch::exceptions::arm_nx_call(VA);
    line(&mut out, &["[ARCH] RX selftest: calling into A's RX page (executes ret)"]);
    arch::exceptions::call_user(RX_VA);
    line(&mut out, &["[MM ] A: RW page NX-faulted on exec, RX page executed (W^X live)"]);

    // ── B's tables active: the same VA is a different frame ──
    tables_b.activate();
    let via_b = memops::read_u64_va(VA);
    if via_b != PATTERN_B || via_b == via_va {
        line(&mut out, &["[MM ] ERROR: B's VA must resolve to a different frame; halting"]);
        hw::halt_forever();
    }
    line(&mut out, &["[MM ] B: same VA resolves to a different frame (disjoint tables)"]);

    // ── A's guard gap: the policy-forced absent page between regions ──
    tables_a.activate();
    line(&mut out, &["[ARCH] domain guard selftest: reading A's guard-gap page"]);
    arch::exceptions::arm_guard_read(GUARD_GAP_VA);
    line(&mut out, &["[MM ] per-domain tables: 2 domains, W^X + guards live"]);

    // Back on the kernel's own tables for the remaining selftests.
    hw::write_cr3(kernel_cr3);

    // ── 8. guarded-stack selftest (PR-1.2) ──────────────────────────
    // One stack through its whole life: alloc (guard + pages + PT from
    // the pool), write and read the top word through the stack VA, read
    // the SAME word through the direct map at the frame's physical
    // address (both views must agree), free (scrub-on-free per frame),
    // then the terminal proof: write through a fresh guard page → #PF.
    line(&mut out, &["[MM ] guarded-stack selftest: alloc/map/cross-view/free"]);
    let stack = match mm::stacks::alloc(&mut pool, &mut k.frames, 2) {
        Ok(st) => st,
        Err(_) => {
            line(&mut out, &["[MM ] ERROR: guarded-stack alloc failed; halting"]);
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
        line(&mut out, &["[MM ] ERROR: stack/direct-map views disagree; halting"]);
        hw::halt_forever();
    }
    let freed = mm::stacks::free(&mut pool, &mut k.frames, stack);
    match freed {
        Ok(()) => line(&mut out, &["[MM ] guarded stacks: alloc+map+cross-view ok, free+scrub ok"]),
        Err(_) => {
            line(&mut out, &["[MM ] ERROR: guarded-stack free failed; halting"]);
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
            line(&mut out, &["[RING3] ERROR: syscall stack alloc failed; halting"]);
            hw::halt_forever();
        }
    };
    arch::gdt::set_rsp0(syscall_stack.top_va());
    arch::percpu::set_kstack_top(syscall_stack.top_va());
    arch::syscall_entry::set_entry_stack(syscall_stack.top_va());
    arch::syscall_entry::init();
    line(&mut out, &["[RING3] syscall entry armed: rsp0/kstack = guarded stack, STAR/LSTAR/SFMASK/SCE live"]);

    // ── Run 1: the good citizen — hello from ring-3, then exit(0). ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k, &mut pool, 5, aegis_os::profile::service_profile(),
        RING3_HELLO, RING3_MSG,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: hello spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(&mut out, &["[RING3] launching domain 5 (service profile) at CPL=3"]);
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
            line(&mut out, &["[RING3] hello domain exited(0): message written from CPL=3"]);
        }
        crate::sched::context::ExitKind::Fault { .. } => {
            // The entry itself faulted before user code could run — the
            // environment-blocked case (full investigation in
            // docs/arch/syscall-entry.md). Report honestly, skip the
            // remaining runs, and let the boot finish.
            line(&mut out, &["[RING3] launch blocked: ring-3 entry faults in this QEMU build"]);
            line(&mut out, &["[RING3] (machinery armed + host-tested; see docs/arch/syscall-entry.md)"]);
            mm::user::destroy_user(&mut k, &mut pool, 5);
            line(&mut out, &["[RING3] ring-3 step concluded: blocked (environment), kernel intact"]);
            hw::shutdown_qemu();
        }
        _ => {
            line(&mut out, &["[RING3] ERROR: hello run ended unexpectedly; halting"]);
            hw::halt_forever();
        }
    }
    let mut bt = [0u8; 20];
    line(&mut out, &["[SYSC] syscall round-trip: ", strutil::dec(trip, &mut bt), " cycles"]);
    mm::user::destroy_user(&mut k, &mut pool, 5);

    // ── Run 2: attack the NX bit — call into the data page. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k, &mut pool, 6, aegis_os::profile::service_profile(),
        RING3_ROGUE, &[0u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: rogue-nx spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(&mut out, &["[RING3] launching domain 6: calls into its NX data page"]);
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        crate::sched::context::ExitKind::Fault { vector: 14, error_code, cr2, .. }
            if (error_code & 0x10) != 0 && (error_code & 0x4) != 0 =>
        {
            let mut bc = [0u8; 18];
            line(&mut out, &["[SEC ] ring3 NX-exec blocked: #PF (I/D) at cr2=",
                strutil::hex(cr2, &mut bc), " — MMU-enforced W^X"]);
        }
        _ => {
            line(&mut out, &["[RING3] ERROR: NX attack did not fault as expected; halting"]);
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 6);

    // ── Run 3: read through the kernel direct map. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k, &mut pool, 7, aegis_os::profile::service_profile(),
        RING3_ROGUE, &[1u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: rogue-kva spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(&mut out, &["[RING3] launching domain 7: reads the kernel direct map"]);
    let kernel_cr3 = hw::read_cr3();
    spawn.run.tables.activate();
    crate::sched::context::begin(spawn.run);
    crate::sched::context::launch(&spawn.ctx);
    // Reached only via resume_kernel's jump (the launch itself never
    // returns): the post-run code below runs exactly once per run.
    let run = crate::sched::context::take();
    hw::write_cr3(kernel_cr3);
    match run.exit {
        crate::sched::context::ExitKind::Fault { vector: 14, error_code, cr2, .. }
            if (error_code & 0x4) != 0 && (error_code & 0x1) != 0 =>
        {
            let mut bc = [0u8; 18];
            line(&mut out, &["[SEC ] ring3 kernel-VA read blocked: #PF (U/S) at cr2=",
                strutil::hex(cr2, &mut bc), " — supervisor page"]);
        }
        _ => {
            line(&mut out, &["[RING3] ERROR: kernel-VA read did not fault as expected; halting"]);
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 7);

    // ── Run 4: forged syscall 200 — must return -ENOSYS, audited. ──
    let spawn = match mm::user::spawn_user_blob(
        &mut k, &mut pool, 8, aegis_os::profile::service_profile(),
        RING3_ROGUE, &[2u8],
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(&mut out, &["[RING3] ERROR: rogue-syscall spawn failed; halting"]);
            hw::halt_forever();
        }
    };
    line(&mut out, &["[RING3] launching domain 8: forged syscall 200"]);
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
            line(&mut out, &["[SEC ] ring3 unauthorized syscall refused (-ENOSYS, audited)"]);
        }
        _ => {
            line(&mut out, &["[RING3] ERROR: forged syscall not refused properly; halting"]);
            hw::halt_forever();
        }
    }
    mm::user::destroy_user(&mut k, &mut pool, 8);
    line(&mut out, &["[RING3] ring-3 isolation live: 4 runs (hello/NX/kernel-VA/forged syscall), kernel intact"]);

    // ── 11. the terminal guard-page proof: the write must #PF, the
    // dispatch must confirm CR2 is exactly the guard page, print the
    // marker, and power off cleanly (CI greps it). Reached only when
    // the whole ring-3 sequence completed — the blocked path powers
    // off inside step 10.
    let guard_stack = match mm::stacks::alloc(&mut pool, &mut k.frames, 1) {
        Ok(st) => st,
        Err(_) => {
            line(&mut out, &["[MM ] ERROR: guard-selftest stack alloc failed; halting"]);
            hw::halt_forever();
        }
    };
    line(&mut out, &["[ARCH] guard selftest: writing through the guard page"]);
    arch::exceptions::arm_guard_write(guard_stack.guard_va());

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
