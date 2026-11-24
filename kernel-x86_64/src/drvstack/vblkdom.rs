//! ADR-0017's first migration: virtio-blk as a RING-3 DRIVER DOMAIN.
//!
//! The kernel keeps the minimal ring-0 half — the claim, the four
//! registered device-core windows (the `SYS_DEVREG` routing: every
//! register access is a message, window-checked by
//! [`crate::ipc_mmio`]), the broker mapping of the domain's own ring
//! page into the device's IOMMU domain, the run, and the teardown.
//! Everything that USED to be driver logic — the modern handshake,
//! the feature negotiation, the queue setup, the request build, the
//! kick, the completion poll — runs at CPL=3 in
//! `examples/ring3-vblk` (a flat blob like every ring-3 example,
//! spawned with the driver profile: DEVREG+EXIT, nothing else).
//!
//! **The proof shape:** the domain reports its read of sector 0; the
//! kernel verifies it against the RING-0 path's own read of the same
//! sector ([`crate::drvstack::vblk::sector0_truth`]) — two
//! independent paths through the same device must agree byte-for-
//! byte, so neither side's claim stands alone. The core's counters
//! (served/refused) print with the marker: the organic monitor feed.
//!
//! **The ring page IS the domain's data page:** qsize 8 keeps the
//! header, three descriptors, both rings, the 512-byte buffer and
//! the status byte inside one 4 KiB page — the same page the spawn
//! maps user-side and the broker maps device-side. The domain writes
//! its queue through its user mapping; the device reads it through
//! the IOMMU domain scoped to exactly this driver. A confused-deputy
//! domain can only corrupt its own request.

// Host-test builds compile this module without its boot-only step
// (the spawn machinery is target-only).
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The driver domain's id (distinct from every frame-owner tag and
/// every ring-3 demo domain the boot spawns).
pub(crate) const VBLK_DOMAIN: u32 = 61;

/// The domain image, built with the kernel like every ring-3 blob.
#[cfg(not(test))]
static VBLK_DOM_BLOB: &[u8] = include_bytes!("../../blob/ring3-vblk.bin");

/// The rogue domain image (the quarantine proof).
#[cfg(not(test))]
static VBLK_ROGUE_BLOB: &[u8] = include_bytes!("../../blob/ring3-rogue-drv.bin");

/// The report block the kernel verifies (the blob's data-page
/// offsets; the layout is documented in the blob's module doc).
#[cfg(not(test))]
mod report {
    pub(crate) const HANDSHAKE: u64 = 0x20;
    pub(crate) const USED_LEN: u64 = 0x28;
    pub(crate) const DEVICE_STATUS: u64 = 0x30;
    pub(crate) const DATA0: u64 = 0x38;
    pub(crate) const PROGRESS: u64 = 0x40;
}

/// ADR-0017's first migrated driver: run the virtio-blk bring-up +
/// one sector read as a ring-3 domain, prove it against the ring-0
/// path's read of the same sector, then tear the whole grant down —
/// channel first (unregister), broker mapping second (session close),
/// domain last (frames + identity). Refuses closed (loud markers,
/// full cleanup) at every step.
#[cfg(not(test))]
pub(crate) fn vblkdom_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::ipc_mmio;
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv
        .find_by(0x1AF4, 0x01)
        .filter(|d| crate::pci::has_virtio_cap(d))
    else {
        line(
            out,
            &["[VBLKD] no virtio-blk on this machine — the domain path skips"],
        );
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(
            out,
            &["[VBLKD] broker verdict absent — refusing to run the domain"],
        );
        return;
    }
    let Some(truth) = crate::drvstack::vblk::sector0_truth() else {
        line(
            out,
            &["[VBLKD] the ring-0 proof did not run (no sector-0 truth) — the domain path skips"],
        );
        return;
    };
    let Some(caps) = crate::virtio::parse_virtio_caps(&mut |off| crate::pci::read_cfg32(dev, off))
    else {
        line(out, &["[VBLKD] vendor caps incomplete — refusing"]);
        return;
    };
    crate::pci::enable_mem(dev);
    let resolved = match caps.resolve(dev) {
        Ok(r) => r,
        Err(e) => {
            line(
                out,
                &[
                    "[VBLKD] capability regions refused (",
                    e.describe(),
                    ") — refusing",
                ],
            );
            return;
        }
    };

    // ── the spawn: the domain with its boot info (patched below) ──
    let boot: [u8; 64] = [0; 64];
    let spawn = match crate::mm::user::spawn_user_blob(
        k,
        pool,
        VBLK_DOMAIN,
        aegis_os::profile::driver_profile(),
        VBLK_DOM_BLOB,
        &boot,
    ) {
        Ok(sp) => sp,
        Err(_) => {
            line(out, &["[VBLKD] domain spawn refused — refusing closed"]);
            return;
        }
    };
    // Patch the boot info: the data page's own physical address (the
    // ONE pa this driver ever holds — its page, broker-mapped for the
    // device below) and the notify multiplier for the kick's slot.
    let Some(data_pa) = spawn
        .run
        .tables
        .translate(crate::mm::user_layout::DATA_BASE)
    else {
        line(out, &["[VBLKD] data page unresolved — refusing closed"]);
        pool.free_all_owned(&mut k.frames, VBLK_DOMAIN);
        let _ = k.destroy_domain(VBLK_DOMAIN);
        return;
    };
    crate::memops::write_u64(data_pa, data_pa);
    crate::memops::write_u64(data_pa + 8, u64::from(resolved.notify_multiplier));

    // ── the session + the cores + the run, scoped so the session's
    // k/pool/broker borrows END before the domain's frames + identity
    // are reclaimed; every refusal breaks out of the scope, the
    // session's Drop still revokes, and the structured teardown below
    // runs on every path — nothing leaks, nothing widens. ──
    let mut proved = false;
    let mut refused = false;
    'scope: {
        let mut session = crate::session::DriverSession::new(
            k,
            pool,
            broker,
            Some(dev),
            VBLK_DOMAIN,
            dev.dom,
            false,
            "[VBLKD] teardown",
            "",
        );
        if session.map(data_pa).is_none() {
            line(
                out,
                &["[VBLKD] broker refused the ring page — refusing closed"],
            );
            refused = true;
            break 'scope;
        }
        crate::pci::enable_bus_master(dev);

        // ── the cores: the four region windows, registered for THIS
        // domain — the SYS_DEVREG routing table. Region 0 = common,
        // 1 = notify, 2 = isr, 3 = device-config (the blob's
        // convention). ──
        let regions: [(u8, u64, u64); 4] = [
            (0, resolved.common_pa, u64::from(caps.common.length)),
            (1, resolved.notify_base_pa, u64::from(resolved.notify_len)),
            (2, resolved.isr_pa, u64::from(caps.isr.length)),
            (3, resolved.device_cfg_pa, u64::from(caps.device.length)),
        ];
        for &(region, base, len) in &regions {
            if !ipc_mmio::register_core(VBLK_DOMAIN, region, base, len) {
                line(
                    out,
                    &["[VBLKD] core registration refused (region/full) — refusing closed"],
                );
                ipc_mmio::unregister_domain(VBLK_DOMAIN);
                refused = true;
                break 'scope;
            }
        }

        // ── the run (the kmain ring-3 pattern, verbatim) ──
        let kernel_cr3 = crate::hw::read_cr3();
        spawn.run.tables.activate();
        crate::sched::context::begin(spawn.run);
        crate::sched::context::launch(&spawn.ctx);
        // Reached only via resume_kernel's jump: the domain ran to
        // SYS_EXIT (or faulted) and the kernel owns the CPU again.
        let run = crate::sched::context::take();
        crate::hw::write_cr3(kernel_cr3);

        // ── the verification: the report block vs the ring-0 truth ──
        let (served, refused_cnt) = ipc_mmio::core_counters(VBLK_DOMAIN);
        let handshake = crate::memops::read_u64(data_pa + report::HANDSHAKE);
        let used_len = crate::memops::read_u64(data_pa + report::USED_LEN);
        let dev_status = crate::memops::read_u64(data_pa + report::DEVICE_STATUS);
        let data0 = crate::memops::read_u64(data_pa + report::DATA0);
        let mut hs = [0u8; 18];
        let mut ns = [0u8; 20];
        let mut ns2 = [0u8; 20];
        let mut nr = [0u8; 20];
        match run.exit {
            crate::sched::context::ExitKind::Exited(0)
                if handshake == 0x0F && used_len == 513 && dev_status == 0 && data0 == truth =>
            {
                line(
                    out,
                    &[
                        "[VBLKD] driver-domains=1: the ring-3 domain ran the whole virtio-blk bring-up + read through the devreg channel (",
                        strutil::dec(served, &mut ns),
                        " ops served, ",
                        strutil::dec(refused_cnt, &mut nr),
                        " refused) — the first migrated driver",
                    ],
                );
                line(
                    out,
                    &[
                        "[VBLKD] read sector 0 at CPL=3: status=OK len=513 (512 data + the status byte) data[0..8]=",
                        strutil::hex(data0, &mut hs),
                        " — byte-identical to the ring-0 path's read of the same sector",
                    ],
                );
                proved = true;
            }
            crate::sched::context::ExitKind::Exited(0) => {
                // A clean exit whose verification FAILED: dump the whole
                // report so the mismatch is diagnosable, never a bare
                // "did not complete".
                line(
                    out,
                    &[
                        "[VBLKD] domain exited 0 but the verification mismatched (progress ",
                        strutil::dec(
                            crate::memops::read_u64(data_pa + report::PROGRESS),
                            &mut ns2,
                        ),
                        "): handshake=",
                        strutil::hex(handshake, &mut hs),
                        " used_len=",
                        strutil::dec(used_len, &mut ns),
                        " dev_status=",
                        strutil::dec(dev_status, &mut nr),
                        " data0=",
                        strutil::hex(data0, &mut [0u8; 18]),
                        " truth=",
                        strutil::hex(truth, &mut [0u8; 18]),
                        " — LOUD",
                    ],
                );
            }
            crate::sched::context::ExitKind::Exited(code) => {
                line(
                    out,
                    &[
                        "[VBLKD] domain exited ",
                        strutil::dec(code, &mut ns),
                        " (progress ",
                        strutil::dec(
                            crate::memops::read_u64(data_pa + report::PROGRESS),
                            &mut ns2,
                        ),
                        ") — LOUD: the migrated driver did not complete its proof",
                    ],
                );
            }
            crate::sched::context::ExitKind::Fault { vector, .. } => {
                let mut nv = [0u8; 20];
                line(
                    out,
                    &[
                        "[VBLKD] domain faulted (vector ",
                        strutil::dec(u64::from(vector), &mut nv),
                        ", progress ",
                        strutil::dec(
                            crate::memops::read_u64(data_pa + report::PROGRESS),
                            &mut ns2,
                        ),
                        ") — LOUD: the migrated driver crashed, the boot continues",
                    ],
                );
            }
            crate::sched::context::ExitKind::Running => {
                // take() after a resume_kernel jump always carries a
                // terminal exit kind; anything else is a kernel bug —
                // loud, never silent.
                line(
                    out,
                    &["[VBLKD] domain still marked Running after the launch returned — LOUD kernel bug"],
                );
            }
        }

        // ── the teardown's channel + mapping halves, in order: the
        // channel dies FIRST (no message can reach a device about to
        // lose its mapping), then the broker mapping. ──
        ipc_mmio::unregister_domain(VBLK_DOMAIN);
        session.close(out);
    } // the session (and its k/pool/broker borrows) end here

    // The domain's frames + identity, LAST — after every borrow ends.
    pool.free_all_owned(&mut k.frames, VBLK_DOMAIN);
    let _ = k.destroy_domain(VBLK_DOMAIN);
    if refused {
        line(
            out,
            &["[VBLKD] refused closed — the domain is fully torn down"],
        );
        return;
    }
    if proved {
        line(
            out,
            &["[VBLKD] domain torn down: channel, mapping, identity"],
        );
    } else {
        line(
            out,
            &["[VBLKD] domain torn down after an incomplete proof: channel, mapping, identity"],
        );
    }

    // ── ADR-0017's QUARANTINE proof: a second domain, deliberately
    // bad. It is registered over the device-config window (harmless —
    // reads only, and the rogue never reaches a register either way),
    // then hammers out-of-window offsets: the core refuses every one
    // (COUNTED — the organic monitor feed), the refusal ladder closes
    // the channel, and the rogue's own report proves a LEGAL offset
    // refuses afterwards. A bad driver loses its device; the boot
    // continues. ──
    const ROGUE_DOMAIN: u32 = 62;
    let boot2: [u8; 64] = [0; 64];
    let Ok(spawn2) = crate::mm::user::spawn_user_blob(
        k,
        pool,
        ROGUE_DOMAIN,
        aegis_os::profile::driver_profile(),
        VBLK_ROGUE_BLOB,
        &boot2,
    ) else {
        line(
            out,
            &["[VBLKD] rogue spawn refused — the quarantine proof cannot run"],
        );
        return;
    };
    if !ipc_mmio::register_core(
        ROGUE_DOMAIN,
        3,
        resolved.device_cfg_pa,
        u64::from(caps.device.length),
    ) {
        line(out, &["[VBLKD] rogue core registration refused"]);
        pool.free_all_owned(&mut k.frames, ROGUE_DOMAIN);
        let _ = k.destroy_domain(ROGUE_DOMAIN);
        return;
    }
    // The rogue's report page (its data page — the blob writes 5 there
    // when every hostile message was refused and the closure probe
    // confirmed; 0xDEAD = something was served, loudly).
    let rogue_pa = spawn2
        .run
        .tables
        .translate(crate::mm::user_layout::DATA_BASE)
        .unwrap_or(0);
    let kernel_cr3 = crate::hw::read_cr3();
    spawn2.run.tables.activate();
    crate::sched::context::begin(spawn2.run);
    crate::sched::context::launch(&spawn2.ctx);
    let run2 = crate::sched::context::take();
    crate::hw::write_cr3(kernel_cr3);
    let (_served2, refused2) = ipc_mmio::core_counters(ROGUE_DOMAIN);
    let rogue_report = crate::memops::read_u64(rogue_pa);
    let rogue_exit_ok = matches!(run2.exit, crate::sched::context::ExitKind::Exited(0));
    ipc_mmio::unregister_domain(ROGUE_DOMAIN);
    pool.free_all_owned(&mut k.frames, ROGUE_DOMAIN);
    let _ = k.destroy_domain(ROGUE_DOMAIN);
    let mut b = [0u8; 20];
    if rogue_exit_ok && rogue_report == 5 && refused2 == 5 {
        line(
            out,
            &[
                "[VBLKD] rogue driver domain contained: ",
                strutil::dec(refused2, &mut b),
                " out-of-window messages refused and COUNTED, the ladder CLOSED the channel (a legal read refuses too) — a bad driver loses its device, the boot continues",
            ],
        );
    } else {
        line(
            out,
            &[
                "[VBLKD] rogue containment NOT proven (report=",
                strutil::hex(rogue_report, &mut [0u8; 18]),
                ", refused=",
                strutil::dec(refused2, &mut b),
                ") — LOUD",
            ],
        );
    }
}
