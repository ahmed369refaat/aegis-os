//! P0-1 (K20): measured capacity accounting for the raised limits.
//!
//! Every "toy limit" in the policy core is a fixed-size array embedded
//! (directly or one level deep) in `Kernel<N>`, and the bootable kernel
//! keeps its `Kernel<4096>` as a stack local on the 512 KiB boot stack
//! (linker.ld, Round J). That makes the struct's `size_of` the number
//! that must stay inside a budget: the deep driver-stack call chains
//! bottomed out ~1.6 KiB above `stack_bottom` on the old 256 KiB stack,
//! so the margin for growth is the stack budget minus this struct minus
//! the deepest chain.
//!
//! This test pins the *budget*, not the exact sizes: the limits may be
//! raised again, but only while the whole kernel state stays under
//! `KERNEL_STATE_BUDGET`. The printed table is the measured input for
//! docs/capacity.md (run with --nocapture to see it).

use aegis_os::Kernel;

/// The whole `Kernel<4096>` state must stay under this. The bootable
/// kernel's stack is 768 KiB (linker.ld, K20/P0-1); the deepest
/// measured call chain is ~40 KiB, so this budget keeps >= 200 KiB of
/// slack between the state, the chains and the F15 guard page.
const KERNEL_STATE_BUDGET: usize = 512 * 1024;

/// The arena the bootable kernel uses (16 MiB, PR-1.3).
const KERNEL_POOL_FRAMES: usize = 4096;

#[test]
fn kernel_state_fits_the_documented_budget() {
    let k = core::mem::size_of::<Kernel<KERNEL_POOL_FRAMES>>();
    let d = core::mem::size_of::<aegis_os::domain::Domain>();
    let sched = core::mem::size_of::<aegis_os::sched::Scheduler>();
    let vfs = core::mem::size_of::<aegis_os::vfs::Vfs>();
    let procs = core::mem::size_of::<aegis_os::proc::ProcTable>();
    let ipc = core::mem::size_of::<aegis_os::ipc::EndpointTable>();
    let fd = core::mem::size_of::<aegis_os::fd::FdTable>();
    let caps = core::mem::size_of::<aegis_os::capability::CapabilityTable>();
    println!(
        "measured: Kernel<{KERNEL_POOL_FRAMES}>={k} B ({:.1} KiB), Domain={d} B, \
         Scheduler={sched} B, Vfs={vfs} B, ProcTable={procs} B, \
         EndpointTable={ipc} B, FdTable={fd} B, CapabilityTable={caps} B",
        k as f64 / 1024.0
    );
    assert!(
        k <= KERNEL_STATE_BUDGET,
        "Kernel state grew to {k} B, over the {KERNEL_STATE_BUDGET} B budget — \
         the boot stack has no room for this; shrink a limit or move storage off-stack"
    );
}
