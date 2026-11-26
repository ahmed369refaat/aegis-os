//! The execve registry (ADR-0003 v1 slice 4): the kernel's compiled-in
//! executable images, keyed by absolute path.
//!
//! execve(2) resolves `path` against THIS table, not a filesystem —
//! Phase 6 (tmpfs/devfs/procfs, the ext2 read-write mount) has not
//! landed, and the honest refusal for a path with no backing image is
//! `-ENOENT`, exactly as Linux answers a path no filesystem resolves.
//! The registry is the same "static root filesystem" the flat spawn
//! blobs have always been: kernel-owned, immutable at runtime,
//! writable by no syscall (a child cannot exec into existence an
//! image the kernel never carried). When the Phase 6 VFS arrives,
//! `resolve` becomes a VFS lookup and every other execve guarantee in
//! this slice is unchanged.
//!
//! The registry entry's second element is the IMAGE BYTES — a full
//! ELF64 file, not a flat blob: the slice-4 loader parses it
//! (`aegis_os::elf::build_exec_plan`) and maps its PT_LOADs at their
//! DECLARED vaddrs. The first entry is `ring3-exec-target` — the
//! bss-probing, entry-honoring, exit_group(11) image the linux-abi
//! lane's fork + execve + wait4 round-trip runs.

// SAFETY discipline (module-level): the ONE static-mut slot below
// (the disk-sourced exec image) is written once at boot — driver
// stack, IF=0, before any exec-capable domain exists — and read
// only afterwards; every access is documented at the site.
#![allow(unsafe_code)]
/// The exec target: ELF64, text RX at 0x400000, data RW at 0x403000
/// with the bss tail at 0x403800 (the zero-fill probe), entry
/// `_start` = 0x400000. Built by boot.sh (rustc --emit=obj + ld -T
/// exec.ld — see the script's step [0]).
pub const EXEC_TARGET_ELF: &[u8] = include_bytes!("../blob/ring3-exec-target.bin");

/// The registry: (absolute path, ELF image). Lookup is exact-match —
/// no prefix games, no wildcards; a path either names an image or it
/// does not.
pub const EXEC_SH_ELF: &[u8] = include_bytes!("../blob/ring3-sh.bin");

/// Phase 7: the registry's second citizen — the shell init execve's.
pub const REGISTRY: &[(&str, &[u8])] = &[
    ("/bin/exec-target", EXEC_TARGET_ELF),
    ("/bin/sh", EXEC_SH_ELF),
];

// ── K20 (P0-3): the disk-sourced extension slot ──
//
// The registry above is compile-time: the kernel binary carries the
// bytes. P0-3's userland citizen arrives differently — the gcc-built
// ELF rides the ext2 root DISK IMAGE, and the boot READS it off the
// AHCI drive into this slot (once, at IF=0 in the driver stack,
// before the first exec-capable domain exists). One slot, fixed
// path, fixed capacity, write-once: the honest middle step
// between "the kernel binary is the filesystem" and the Phase-6 VFS
// — the bytes are real disk bytes at boot, immutable from ring 3
// after registration, and the arm answers ENOENT for every path but
// this one until the registration happened.

/// The one disk-sourced image this slot holds (the gcc userland
/// citizen). 16 KiB = the exec cage's whole extent — an image that
/// cannot fit the cage cannot fit the slot either.
pub const DISK_IMAGE_PATH: &str = "/bin/hello";
pub const DISK_IMAGE_MAX: usize = 16 * 1024;

static mut DISK_IMAGE: [u8; DISK_IMAGE_MAX] = [0; DISK_IMAGE_MAX];
static DISK_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static DISK_INSTALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Register the disk image for `DISK_IMAGE_PATH`. Fails (false) when
/// the bytes are empty, over-long, or a registration already
/// happened — never silently overwritten.
pub fn register_disk_image(bytes: &[u8]) -> bool {
    use core::sync::atomic::Ordering;
    if bytes.is_empty() || bytes.len() > DISK_IMAGE_MAX {
        return false;
    }
    if DISK_INSTALLED.swap(true, Ordering::AcqRel) {
        return false; // one registration, ever
    }
    // SAFETY: the sole write happens here, once, at boot (driver
    // stack, IF=0, before any domain that could exec exists); every
    // later reader goes through `resolve`, which only reads. Single
    // CPU — no concurrent access exists to exclude.
    unsafe {
        DISK_IMAGE[..bytes.len()].copy_from_slice(bytes);
    }
    DISK_LEN.store(bytes.len(), Ordering::Release);
    true
}

/// Resolve `path` to its image bytes. `None` is `-ENOENT` at the arm.
/// The compiled-in table first, then the disk slot — a path either
/// names an image or it does not.
#[must_use]
pub fn resolve(path: &str) -> Option<&'static [u8]> {
    use core::sync::atomic::Ordering;
    if let Some(image) = REGISTRY
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, image)| *image)
    {
        return Some(image);
    }
    if path == DISK_IMAGE_PATH {
        let len = DISK_LEN.load(Ordering::Acquire);
        if !DISK_INSTALLED.load(Ordering::Acquire) || len == 0 {
            return None;
        }
        // SAFETY: the buffer was written once at registration (before
        // any exec-capable domain existed) and never written again;
        // the length is published after the bytes (Release/Acquire).
        // The slice borrows a static — read-only for the boot's life.
        unsafe {
            return Some(core::slice::from_raw_parts(
                core::ptr::addr_of!(DISK_IMAGE) as *const u8,
                len,
            ));
        }
    }
    None
}

/// K20 (P0-3): is the disk image for `DISK_IMAGE_PATH` installed?
#[must_use]
pub fn disk_image_installed() -> bool {
    DISK_INSTALLED.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_resolves_exact_paths_only() {
        assert!(resolve("/bin/exec-target").is_some());
        // No prefix games, no trailing-slash mercy, no directories.
        assert!(resolve("/bin").is_none());
        assert!(resolve("/bin/exec-target/").is_none());
        assert!(resolve("exec-target").is_none());
        assert!(resolve("").is_none());
    }

    #[test]
    fn the_embedded_image_plans_as_a_valid_exec() {
        // The strongest registry test there is: the EMBEDDED bytes
        // (exactly what exec_tables will parse in the kernel) plan
        // through the slice-4 loader — the entry inside a PT_LOAD,
        // page-congruent offsets, no W+X, no overlap, cage-shaped.
        let plan = aegis_os::elf::build_exec_plan(EXEC_TARGET_ELF)
            .expect("the embedded target must be a loadable ELF");
        assert_eq!(plan.entry, 0x400000);
        assert_eq!(plan.n_segments, 2);
        assert!(plan.segments[0].executable && !plan.segments[0].writable);
        assert!(plan.segments[1].writable && !plan.segments[1].executable);
        assert_eq!(plan.map_bytes, 2 * 4096);
        // The bss probe's byte lies in the RW segment's memsz tail,
        // beyond filesz — the zero-fill contract has a real byte to
        // honor at 0x403800.
        let d = &plan.segments[1];
        assert!(d.vaddr + d.filesz <= 0x403800 && 0x403800 < d.vaddr + d.memsz);
    }
}

/// The scratch ownership tag the SYS_EXEC arm builds the new image
/// under while the old image's frames are still live: free-by-owner
/// id (the old image) cannot reach scratch-tagged frames, and after
/// the handover the finished image re-tags to the domain
/// (`FramePool::retag_owner`). Exec is single-CPU one-at-a-time;
/// the tag never collides with a domain id (the domain table is far
/// smaller than 0x5AFE_0000).
pub const EXEC_SCRATCH_OWNER: u32 = 0x5AFE_0E0E;

#[cfg(test)]
mod adr0032_tests {
    use super::*;

    /// ADR-0032 section B: alias paths canonicalize to one registry
    /// entry, and the resolved image carries ONE identity — the
    /// declared policy cannot be dodged by spelling.
    #[test]
    fn aliases_canonicalize_to_the_same_image_and_identity() {
        let canon = |input: &str| -> String {
            let mut out = [0u8; 64];
            let n = aegis_os::proc::canonicalize_path(input, &mut out).expect("canonical");
            core::str::from_utf8(&out[..n]).unwrap().to_string()
        };
        assert_eq!(canon("//bin/./sh"), "/bin/sh");
        assert_eq!(canon("/bin/../bin/sh"), "/bin/sh");
        assert_eq!(canon("/bin//exec-target/"), "/bin/exec-target");
        // The canonical paths resolve to the same bytes, hence the
        // same identity — one policy entry for every spelling.
        assert_eq!(
            aegis_os::proc::image_id(resolve(&canon("//bin/./sh")).unwrap()),
            aegis_os::proc::image_id(EXEC_SH_ELF)
        );
        assert_eq!(
            aegis_os::proc::image_id(resolve(&canon("/bin/../bin/exec-target")).unwrap()),
            aegis_os::proc::image_id(EXEC_TARGET_ELF)
        );
        // Different bytes, different identity — a policy declared for
        // one never applies to the other.
        assert_ne!(
            aegis_os::proc::image_id(EXEC_SH_ELF),
            aegis_os::proc::image_id(EXEC_TARGET_ELF)
        );
    }
}

/// ADR round N2 (the exec image quota): the typed refusal of the
/// pure pre-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecQuotaError {
    /// The image's mapped pages + stack + trampoline exceed the
    /// caller's LIVE quota. Checked before the point of no return —
    /// zero side effects (the old image keeps running, the mask
    /// untouched, no frame spent).
    OverQuota { need: usize, quota: usize },
}

/// ADR round N2: can this image exec under this quota? Pure
/// arithmetic, host-tested: `map_bytes` is the plan's page-rounded
/// byte count; the stack and trampoline pages ride with every image.
pub fn exec_quota_check(
    map_bytes: u64,
    stack_pages: usize,
    trampoline_pages: usize,
    quota_pages: usize,
) -> Result<(), ExecQuotaError> {
    // Checked end to end: a hostile map_bytes near u64::MAX must
    // refuse, never wrap.
    let image_pages = map_bytes
        .checked_add(4095)
        .and_then(|rounded| rounded.checked_div(4096))
        .ok_or(ExecQuotaError::OverQuota {
            need: usize::MAX,
            quota: quota_pages,
        })?;
    let need = image_pages as usize + stack_pages + trampoline_pages;
    if need > quota_pages {
        return Err(ExecQuotaError::OverQuota {
            need,
            quota: quota_pages,
        });
    }
    Ok(())
}

#[cfg(test)]
mod n2_tests {
    use super::*;

    /// The round's exact numbers: a 20-page image.
    const P20: u64 = 20 * 4096;

    #[test]
    fn a_20_page_image_fits_quota_64() {
        assert_eq!(exec_quota_check(P20, 1, 1, 64), Ok(()));
        // The boundary is exact: need = 22.
        assert_eq!(exec_quota_check(P20, 1, 1, 22), Ok(()));
    }

    #[test]
    fn a_20_page_image_is_refused_under_quota_8() {
        assert_eq!(
            exec_quota_check(P20, 1, 1, 8),
            Err(ExecQuotaError::OverQuota { need: 22, quota: 8 })
        );
        // One page short is still refused.
        assert_eq!(
            exec_quota_check(P20, 1, 1, 21),
            Err(ExecQuotaError::OverQuota {
                need: 22,
                quota: 21
            })
        );
    }

    #[test]
    fn a_hostile_map_bytes_refuses_instead_of_wrapping() {
        assert_eq!(
            exec_quota_check(u64::MAX, 1, 1, 64),
            Err(ExecQuotaError::OverQuota {
                need: usize::MAX,
                quota: 64
            })
        );
    }

    #[test]
    fn the_real_registry_images_pass_their_own_spawn_footprints() {
        // The embedded images' plans, checked against the quotas the
        // boot actually runs them under (service = 256).
        for (image, name) in [(EXEC_TARGET_ELF, "exec-target"), (EXEC_SH_ELF, "sh")] {
            let plan = aegis_os::elf::build_exec_plan(image).unwrap();
            assert!(
                exec_quota_check(plan.map_bytes, 1, 1, 256).is_ok(),
                "{name} must exec under the service quota"
            );
        }
    }
}
