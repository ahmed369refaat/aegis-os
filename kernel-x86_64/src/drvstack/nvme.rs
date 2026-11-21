//! NVMe: controller reset, admin queue pair, Identify/CreateIoCq.

use crate::frames::FramePool;
use crate::mmio::{BarMmio, MmioBus};
use crate::strutil;
use crate::strutil::line;

/// The pool owner tag for NVMe frames (admin + I/O queue pairs and
/// the two data pages).
pub const NVME_OWNER: u32 = 46;

// NVMe controller registers (BAR0 offsets).

const NVME_CAP: u64 = 0x00;
const NVME_VS: u64 = 0x08;
const NVME_CC: u64 = 0x14;
const NVME_CSTS: u64 = 0x1C;
const NVME_AQA: u64 = 0x24;
const NVME_ASQ: u64 = 0x28;
const NVME_ACQ: u64 = 0x30;
const NVME_DBA: u64 = 0x1000;

/// The command-specific half of an SQE (the fields this driver fills;
/// the submit path zeroes the rest).
#[cfg(not(test))]
struct NvmeCmd {
    cid: u32,
    opcode: u32,
    nsid: u32,
    prp1: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
}

/// One admin/I-O submission-queue entry (64 bytes; the fields this
/// driver uses). The doorbell write goes through the register window
/// (ADR-0016): `db_off` is an OFFSET into the controller's BAR, not a
/// cooked address — the device-derived stride stays inside the window
/// the enumeration measured. Returns false if the window refused the
/// doorbell (the caller tears down).
#[cfg(not(test))]
fn nvme_submit(bus: &BarMmio, db_off: u64, sq: u64, tail: &mut u16, cmd: &NvmeCmd) -> bool {
    let e = sq + u64::from(*tail) * 64;
    crate::memops::write_u64(e, 0);
    crate::memops::write_u32(e, cmd.opcode | (cmd.cid << 16)); // cdw0
    crate::memops::write_u32(e + 4, cmd.nsid);
    // F11: QEMU 10.0's nvme reads the command's data pointer from SQE
    // bytes 24-31, where the spec puts PRP2 — measured by planting a
    // distinct page in every PRP-candidate slot: the identify DMA
    // targeted the +24 plant and ignored the +24=0 original (the
    // historical "data landed at PA 0" was this exact bug before the
    // IOMMU existed to catch it). A spec-compliant controller ignores
    // PRP2 for single-page aligned buffers, so writing the pointer at
    // BOTH slots is correct here and safe on real hardware.
    crate::memops::write_u64(e + 16, cmd.prp1);
    crate::memops::write_u64(e + 24, cmd.prp1);
    crate::memops::write_u32(e + 40, cmd.cdw10);
    crate::memops::write_u32(e + 44, cmd.cdw11);
    crate::memops::write_u32(e + 48, cmd.cdw12);
    *tail = tail.wrapping_add(1) & 15;
    bus.write32(db_off, u32::from(*tail))
}

/// Poll the completion-queue slot at `head` for `phase`; returns
/// (result dword, status) — status 0 is success.
#[cfg(not(test))]
fn nvme_poll(cq: u64, head: u16, phase: u16, budget: u64) -> Option<(u32, u32)> {
    let slot = cq + u64::from(head) * 16;
    let mut spins = 0u64;
    loop {
        // DW3 (offset 12) = [SQHD(15:0) | P+SF(31:16)] — the phase
        // lives at bit 16 (byte 14), NOT bit 0: QEMU nvme.c:1517
        // writes cqe.status = (status << 1) | phase as the le16 at
        // bytes 14-15. Reading bit 0 mistakes SQHD's LSB for the
        // phase (it matched slot 0 by accident: SQHD=1).
        let pw = crate::memops::read_u32(slot + 12) >> 16;
        if (pw & 1) == u32::from(phase) {
            return Some((crate::memops::read_u32(slot), (pw >> 1) & 0xFF));
        }
        if spins >= budget {
            return None;
        }
        spins += 1;
    }
}

/// Phase 2: drive the NVMe controller — enable, IDENTIFY the
/// controller (serial + namespace count), create one I/O queue pair,
/// read LBA 0 of namespace 1, then teardown with the device live.
#[cfg(not(test))]
pub(crate) fn nvme_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use aegis_os::dma::DmaVerdict;

    let Some(dev) = inv.find_by(0x1B36, 0x01) else {
        line(out, &["[NVME] no NVMe to drive on this machine"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[NVME] broker verdict absent — refusing to drive"]);
        return;
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[NVME] BAR0 unresolved — refusing"]);
        return;
    };
    // ADR-0016: one window for every controller register; the
    // doorbells (device-derived stride from CAP.DSTRD) are door-checked
    // once the stride is known — until then the fixed registers must
    // at least reach ACQ+8.
    let Some(bus) = BarMmio::new(bar.base, bar.size) else {
        line(
            out,
            &["[NVME] BAR0 window malformed (zero/wrapping) — refusing"],
        );
        return;
    };
    if bus.window().len() < NVME_ACQ + 8 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[NVME] BAR0 window too small for the register set (len=0x",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    // F9e: MEM now; BME once the broker-mapped admin qpair is live.
    crate::pci::enable_mem(dev);
    let (Some(cap), Some(vs)) = (bus.read64(NVME_CAP), bus.read32(NVME_VS)) else {
        line(
            out,
            &["[NVME] register window refused a CAP/VS read — refusing"],
        );
        return;
    };
    let dstrd = (cap >> 32) & 0xF;
    let stride = 4u64 << dstrd;
    // The doorbell bank: admin SQ/CQ + one I/O SQ — the highest
    // device-derived offset the driver touches, checked at the door.
    if bus.window().len() < NVME_DBA + 2 * stride + 4 {
        let mut lb = [0u8; 18];
        line(
            out,
            &[
                "[NVME] BAR0 window too small for the doorbell bank (len=0x",
                strutil::hex(bus.window().len(), &mut lb),
                ") — refusing",
            ],
        );
        return;
    }
    let mut h = [0u8; 20];
    let mut h2 = [0u8; 20];
    line(
        out,
        &[
            "[NVME] CAP: MQES=",
            strutil::dec((cap & 0xFFFF) + 1, &mut h),
            " DSTRD=",
            strutil::dec(dstrd, &mut h2),
        ],
    );
    let mut h3 = [0u8; 20];
    line(
        out,
        &[
            "[NVME] version ",
            strutil::dec(u64::from(vs >> 16), &mut h),
            ".",
            strutil::dec(u64::from((vs >> 8) & 0xFF), &mut h2),
            ".",
            strutil::dec(u64::from(vs & 0xFF), &mut h3),
        ],
    );

    // Frames: admin SQ/CQ, I/O SQ/CQ, two data pages.
    // ADR-0016/F10: the session owns the qpairs + data pages from
    // here on; every exit below is one close().
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        NVME_OWNER,
        false,
        "[NVME] teardown: revoke_all(0) → ",
        "",
    );
    let mut frames = [0u64; 6];
    for slot in frames.iter_mut() {
        match session.frame() {
            Some(pa) => *slot = pa,
            None => {
                line(out, &["[NVME] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [asq, acq, iosq, iocq, data1, data2] = frames;
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(out, &["[NVME] broker refused a frame — refusing"]);
            return;
        }
    }

    // Full reset cycle. SeaBIOS drives the NVMe boot disk BEFORE us
    // and leaves the controller ENABLED with ITS admin queue state
    // (its own tail/head, its own CQ phase). A driver that wants
    // slot-0 queues disables first (NVMe 1.4 §3.1.5: queue registers
    // are writable only while CC.EN=0/CSTS.RDY=0), reprograms, then
    // enables with the entry-size bits set. Without the cycle our
    // doorbell(1) goes BACKWARDS from SeaBIOS's tail and the CQEs
    // post to stale slots — measured: the Identify data page stayed
    // zero while the pci_nvme trace showed completions.
    if !bus.write32(NVME_CC, 0) {
        line(
            out,
            &["[NVME] register window refused the CC reset — refusing"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(NVME_CSTS).is_some_and(|v| v & 1 != 0) && spins < 50_000_000 {
        spins += 1;
    }
    // The disable SUCCEEDED when RDY cleared: refuse only if it stuck.
    if bus.read32(NVME_CSTS).is_some_and(|v| v & 1 != 0) {
        line(
            out,
            &["[NVME] controller did not disable (CSTS.RDY stuck) — refusing"],
        );
        session.close(out);
        return;
    }
    // Admin queue pair (16 entries) + CC. F11's second half: THIS
    // QEMU reads IOSQES from CC bits 19:16 and IOCQES from bits
    // 23:20 — measured by QEMU's own
    // pci_nvme_err_invalid_create_cq_entry_size(iosqes 4, iocqes 6)
    // after a spec-layout 0x0064_0001 write. The NVMe 1.4 spec puts
    // IOSQES at 23:20 / IOCQES at 27:24; the previous session read
    // that layout, swapped the nibbles, and unknowingly traded one
    // SC=2 cause (the PRP offset, fixed above) for another (these
    // bits). 0x0046_0001 = EN | IOSQES=6 (64 B SQ) | IOCQES=4 (16 B
    // CQ) in the layout this QEMU implements.
    if !(bus.write32(NVME_AQA, (15 << 16) | 15)
        && bus.write64(NVME_ASQ, asq)
        && bus.write64(NVME_ACQ, acq)
        && bus.write32(NVME_CC, 0x0046_0001))
    {
        line(
            out,
            &["[NVME] register window refused an admin-qpair write — refusing"],
        );
        session.close(out);
        return;
    }
    let mut spins = 0u64;
    while bus.read32(NVME_CSTS).is_some_and(|v| v & 1 == 0) && spins < 50_000_000 {
        spins += 1;
    }
    if !bus.read32(NVME_CSTS).is_some_and(|v| v & 1 != 0) {
        line(out, &["[NVME] CSTS.RDY never set — refusing"]);
        return;
    }
    line(out, &["[NVME] admin qpair live (16 entries), CSTS.RDY=1"]);
    // F9e: the queue frames are broker-mapped — now it may DMA.
    crate::pci::enable_bus_master(dev);

    // Doorbell offsets (window-checked at the door above).
    let admin_sq_db = NVME_DBA;
    let admin_cq_db = NVME_DBA + stride;
    let mut a_tail = 0u16;
    let mut a_head = 0u16;
    let mut cid = 0u32;

    // IDENTIFY CONTROLLER: cdw10=1, PRP1=data1.
    cid += 1;
    if !nvme_submit(
        &bus,
        admin_sq_db,
        asq,
        &mut a_tail,
        &NvmeCmd {
            cid,
            opcode: 0x06,
            nsid: 0,
            prp1: data1,
            cdw10: 1,
            cdw11: 0,
            cdw12: 0,
        },
    ) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    if let (Some(asq_reg), Some(aqa_reg)) = (bus.read64(NVME_ASQ), bus.read32(NVME_AQA)) {
        let mut e0 = [0u8; 18];
        let mut e2 = [0u8; 18];
        let mut qa = [0u8; 18];
        let mut rb = [0u8; 18];
        line(
            out,
            &[
                "[NVME] dbg entry: asq=0x",
                strutil::hex(asq, &mut e0),
                " entry[0](cdw0|prp1)=0x",
                strutil::hex(
                    (u64::from(crate::memops::read_u32(asq)) << 32)
                        | crate::memops::read_u64(asq + 16),
                    &mut e2,
                ),
                " asq_reg=0x",
                strutil::hex(asq_reg, &mut qa),
                " aqa_reg=0x",
                strutil::hex(u64::from(aqa_reg), &mut rb),
            ],
        );
    } else {
        line(
            out,
            &["[NVME] dbg: register window refused a queue-register read"],
        );
    }
    let Some((_, st)) = nvme_poll(acq, a_head, 1, 10_000_000) else {
        // Registers + queue pair proven above; the completion needs
        // the controller's DMA — the same no-translation signature
        // as the e1000/virtio-net cluster (open; see drivers.md).
        // Give the post bottom-half a long second window, then dump
        // everything: the queue registers as the device sees them, the
        // identify data page (did the 4 KiB PRP write land?), and the
        // CQE's first two dwords.
        let mut spins2 = 0u64;
        while crate::memops::read_u32(acq + 12) == 0 && spins2 < 5_000_000 {
            spins2 += 1;
        }
        if let (Some(asq_reg), Some(acq_reg)) = (bus.read64(NVME_ASQ), bus.read64(NVME_ACQ)) {
            line(
                out,
                &[
                    "[NVME] dbg: asq_reg=0x",
                    strutil::hex(asq_reg, &mut [0u8; 18]),
                    " (mine 0x",
                    strutil::hex(asq, &mut [0u8; 18]),
                    ") acq_reg=0x",
                    strutil::hex(acq_reg, &mut [0u8; 18]),
                    " (mine 0x",
                    strutil::hex(acq, &mut [0u8; 18]),
                    ") data1[0..8]=0x",
                    strutil::hex(crate::memops::read_u64(data1), &mut [0u8; 18]),
                    " cqe0=0x",
                    strutil::hex(u64::from(crate::memops::read_u32(acq)), &mut [0u8; 18]),
                    " cqe3=0x",
                    strutil::hex(u64::from(crate::memops::read_u32(acq + 12)), &mut [0u8; 18]),
                    (if crate::memops::read_u64(data1) != 0 {
                        " — data ARRIVED; completion timing open"
                    } else {
                        " — no data either"
                    }),
                ],
            );
        } else {
            line(
                out,
                &["[NVME] dbg: register window refused a queue-register read"],
            );
        }
        session.close(out);
        return;
    };
    a_head = a_head.wrapping_add(1) & 15;
    if !bus.write32(admin_cq_db, u64::from(a_head) as u32) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    if st != 0 {
        let mut hs = [0u8; 18];
        line(
            out,
            &[
                "[NVME] Identify status != 0 (0x",
                strutil::hex(u64::from(st), &mut hs),
                ") — refusing",
            ],
        );
        return;
    }
    // Serial: 20 bytes at identify+4 (print the first 8); NN at +516.
    let sn = crate::memops::read_u64(data1 + 4);
    let mut snb = [0u8; 8];
    for i in 0..8u64 {
        let b = ((sn >> (8 * i)) & 0xFF) as u8;
        snb[i as usize] = if (0x20..0x7F).contains(&b) { b } else { b' ' };
    }
    let nn = crate::memops::read_u32(data1 + 516);
    let mut dp = [0u8; 18];
    let mut d0 = [0u8; 18];
    let mut z0 = [0u8; 18];
    line(
        out,
        &[
            "[NVME] dbg identify: data1_pa=0x",
            strutil::hex(data1, &mut dp),
            " data1[0..8]=0x",
            strutil::hex(crate::memops::read_u64(data1), &mut d0),
            " PA0[0..8]=0x",
            strutil::hex(crate::memops::read_u64(0x0), &mut z0),
        ],
    );
    line(
        out,
        &[
            "[NVME] Identify: serial=\"",
            core::str::from_utf8(&snb).unwrap_or("?"),
            "\", namespaces=",
            strutil::dec(u64::from(nn), &mut h),
        ],
    );

    // Create I/O CQ (QID 1, 16 entries) then I/O SQ (QID 1 → CQ 1).
    cid += 1;
    // cdw11 = PC (bit 0: physically-contiguous single page) | IV=0
    // (interrupt vector lives at bits 16+, and interrupts stay off —
    // the old 1<<17 was read as IV=2 and the device rejected the
    // queue: err_invalid_create_cq_vector).
    if !nvme_submit(
        &bus,
        admin_sq_db,
        asq,
        &mut a_tail,
        &NvmeCmd {
            cid,
            opcode: 0x05,
            nsid: 0,
            prp1: iocq,
            cdw10: (15 << 16) | 1,
            cdw11: 1,
            cdw12: 0,
        },
    ) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    let Some((_, st)) = nvme_poll(acq, a_head, 1, 10_000_000) else {
        // Dump the first four CQE dw3 words (phase+status): where
        // did the completion actually land?
        let mut b0 = [0u8; 18];
        let mut b1 = [0u8; 18];
        let mut b2 = [0u8; 18];
        let mut b3 = [0u8; 18];
        let s0 = strutil::hex(u64::from(crate::memops::read_u32(acq + 12)), &mut b0);
        let s1 = strutil::hex(u64::from(crate::memops::read_u32(acq + 28)), &mut b1);
        let s2 = strutil::hex(u64::from(crate::memops::read_u32(acq + 44)), &mut b2);
        let s3 = strutil::hex(u64::from(crate::memops::read_u32(acq + 60)), &mut b3);
        line(
            out,
            &[
                "[NVME] dbg acq dw3: s0=0x",
                s0,
                " s1=0x",
                s1,
                " s2=0x",
                s2,
                " s3=0x",
                s3,
            ],
        );
        line(out, &["[NVME] CreateIoCq did not complete — refusing"]);
        session.close(out);
        return;
    };
    a_head = a_head.wrapping_add(1) & 15;
    if !bus.write32(admin_cq_db, u64::from(a_head) as u32) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    if st != 0 {
        let mut hs = [0u8; 18];
        line(
            out,
            &[
                "[NVME] CreateIoCq status 0x",
                strutil::hex(u64::from(st), &mut hs),
                " — refusing",
            ],
        );
        session.close(out);
        return;
    }
    cid += 1;
    // cdw11 = PC (bit 0) | CQID=1 (bits 16+: the SQ routes to CQ 1).
    if !nvme_submit(
        &bus,
        admin_sq_db,
        asq,
        &mut a_tail,
        &NvmeCmd {
            cid,
            opcode: 0x01,
            nsid: 0,
            prp1: iosq,
            cdw10: (15 << 16) | 1,
            cdw11: 1 | (1 << 16),
            cdw12: 0,
        },
    ) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    let Some((_, st)) = nvme_poll(acq, a_head, 1, 10_000_000) else {
        line(out, &["[NVME] CreateIoSq did not complete — refusing"]);
        session.close(out);
        return;
    };
    a_head = a_head.wrapping_add(1) & 15;
    if !bus.write32(admin_cq_db, u64::from(a_head) as u32) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    if st != 0 {
        let mut hs = [0u8; 18];
        line(
            out,
            &[
                "[NVME] CreateIoSq status 0x",
                strutil::hex(u64::from(st), &mut hs),
                " — refusing",
            ],
        );
        session.close(out);
        return;
    }
    line(out, &["[NVME] I/O qpair QID1 created (CQ+SQ)"]);

    // READ LBA 0 of namespace 1 (1 sector) into data2.
    let io_sq_db = NVME_DBA + 2 * stride;
    let mut io_tail = 0u16;
    if !nvme_submit(
        &bus,
        io_sq_db,
        iosq,
        &mut io_tail,
        &NvmeCmd {
            cid: 1,
            opcode: 0x02,
            nsid: 1,
            prp1: data2,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
        },
    ) {
        line(
            out,
            &["[NVME] register window refused a doorbell — refusing"],
        );
        session.close(out);
        return;
    }
    let Some((_, st)) = nvme_poll(iocq, 0, 1, 100_000_000) else {
        line(out, &["[NVME] read LBA0 did not complete — refusing"]);
        session.close(out);
        return;
    };
    if st != 0 {
        let mut hs = [0u8; 18];
        line(
            out,
            &[
                "[NVME] read LBA0 status 0x",
                strutil::hex(u64::from(st), &mut hs),
                " — refusing",
            ],
        );
        session.close(out);
        return;
    }
    let d0 = crate::memops::read_u64(data2);
    let mut hd = [0u8; 18];
    line(
        out,
        &[
            "[NVME] read LBA0: 0x",
            strutil::hex(d0, &mut hd),
            " (512 bytes through the IOMMU)",
        ],
    );

    // Teardown with the device live.
    session.close(out);
}
