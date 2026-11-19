//! Spawning a ring-3 user domain from a flat code blob (PR-1.4).
//!
//! The bridge between the policy core and the hardware context: a lib
//! `Domain` (the identity the monitor audits and the gate snapshots)
//! plus per-domain page tables (PR-1.3) holding policy-mapped code
//! (RX), data (RW+NX), and stack (RW+NX) regions with real guard gaps
//! between them.
//!
//! Invariants:
//! - **Every region passes the ten-check policy first** — `map_region`
//!   is the only mapping path, so the user layout is gated exactly like
//!   any kernel-resident domain's memory.
//! - **Frames are pool-owned by the domain id**: a destroy
//!   (`pool.free_all_owned` + `Kernel::destroy_domain`) reclaims
//!   tables, pages, and the lib side in one sweep.
//! - **The blob never touches anything but its own code page**: it is
//!   copied through the direct map into the frame `map_region`
//!   allocated, before the first instruction of it can run.
//! - This module is unsafe-free: all raw access lives in `memops` and
//!   the allowlisted arch/sched modules.

use aegis_os::memory::AddressSpace;
use aegis_os::profile::DomainProfile;
use aegis_os::Kernel;

use crate::frames::{FrameError, FramePool};
use crate::memops;
use crate::mm::page_table::{MapError, PageTables, PoolSource};
use crate::mm::user_layout as layout;
use crate::sched::context::{UserContext, UserRun};

/// Why a spawn failed. All failures happen *before* any launch: either
/// the lib refused the domain, or the policy/pool refused a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// The lib refused the domain (duplicate id, table full, ...).
    Domain,
    /// The ten-check policy or the page-table walk refused a region.
    Map(MapError),
    /// The blob does not fit its code page.
    BlobTooLarge { len: usize, capacity: usize },
}

impl From<MapError> for SpawnError {
    fn from(e: MapError) -> Self {
        SpawnError::Map(e)
    }
}

/// Everything kmain needs to run one user domain: the lib identity,
/// the entry context, and the run state to install before launching.
pub struct UserSpawn {
    pub domain: u32,
    pub ctx: UserContext,
    pub run: UserRun,
}

/// Create lib domain `id`, build its page tables, map the canonical
/// user layout (code RX, data RW, stack RW), copy `blob` into the code
/// page and `data` into the data page, and assemble the launch context.
/// The kernel entries are installed in the fresh PML4 (shared kernel
/// half), and the gate snapshot is taken from the profile's syscall
/// mask — the same mask `create_domain` built the domain's live mask
/// from.
#[cfg(not(test))]
pub fn spawn_user_blob<const N: usize>(
    k: &mut Kernel<N>,
    pool: &mut FramePool<N>,
    id: u32,
    profile: DomainProfile,
    blob: &[u8],
    data: &[u8],
) -> Result<UserSpawn, SpawnError> {
    if blob.len() > layout::CODE_PAGES * 4096 {
        return Err(SpawnError::BlobTooLarge {
            len: blob.len(),
            capacity: layout::CODE_PAGES * 4096,
        });
    }
    if data.len() > layout::DATA_PAGES * 4096 {
        return Err(SpawnError::BlobTooLarge {
            len: data.len(),
            capacity: layout::DATA_PAGES * 4096,
        });
    }
    // Lib identity first (audit/accounting; the frame owner tag below
    // matches this id so a destroy reclaims everything at once).
    k.create_domain(id, profile).map_err(|_| SpawnError::Domain)?;
    // Gate snapshot: the live mask starts as the profile's mask, and a
    // freshly created domain is never quarantined.
    let mask = profile.syscalls;
    let quarantined = false;

    // Hardware side: fresh tables, kernel half shared in, layout mapped
    // through the policy gate, blob/data copied in via the direct map.
    let mut src = PoolSource::new(pool, &mut k.frames, id);
    let mut tables = PageTables::new(&mut src)?;
    tables.install_kernel_entries();
    let mut space = AddressSpace::new(16);
    tables.map_region(
        &mut space,
        layout::CODE_BASE,
        layout::CODE_PAGES * 4096,
        layout::code_flags(),
        &mut src,
    )?;
    tables.map_region(
        &mut space,
        layout::DATA_BASE,
        layout::DATA_PAGES * 4096,
        layout::data_flags(),
        &mut src,
    )?;
    tables.map_region(
        &mut space,
        layout::STACK_BASE,
        layout::STACK_PAGES * 4096,
        layout::stack_flags(),
        &mut src,
    )?;
    copy_into_frame(&tables, layout::CODE_BASE, blob);
    copy_into_frame(&tables, layout::DATA_BASE, data);

    Ok(UserSpawn {
        domain: id,
        ctx: UserContext::new(layout::CODE_BASE, layout::STACK_TOP),
        run: UserRun::new(tables, space, id, mask, quarantined),
    })
}

/// Free every frame the domain owns (tables + pages; the pool scrubs
/// each one) and withdraw the lib identity. The post-run cleanup,
/// called from kmain after `resume_kernel`.
#[cfg(not(test))]
pub fn destroy_user<const N: usize>(k: &mut Kernel<N>, pool: &mut FramePool<N>, id: u32) {
    pool.free_all_owned(&mut k.frames, id);
    let _ = k.destroy_domain(id);
}

/// Write `bytes` into the page mapped at `base` (zero-padded, one u64
/// at a time through the direct map). `base` must be a mapped region
/// start; the caller only ever passes layout bases whose regions were
/// just mapped.
#[cfg(not(test))]
fn copy_into_frame(tables: &PageTables, base: u64, bytes: &[u8]) {
    let pa = match tables.translate(base) {
        Some(p) => p,
        None => return, // unreachable: we just mapped this region
    };
    let mut off = 0usize;
    while off < bytes.len() {
        let mut word = [0u8; 8];
        let n = core::cmp::min(8, bytes.len() - off);
        word[..n].copy_from_slice(&bytes[off..off + n]);
        memops::write_u64(pa + off as u64, u64::from_le_bytes(word));
        off += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_capacity_covers_the_examples() {
        // The examples are a few dozen bytes of asm; one code page is
        // orders of magnitude more than enough.
        assert!(layout::CODE_PAGES * 4096 >= 128);
    }
}
