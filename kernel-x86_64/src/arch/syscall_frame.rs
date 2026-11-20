//! The syscall-entry frame: the register image the naked stub parks,
//! and the post-push RSP-relative slot offsets (M2-W2).
//!
//! Host-visible on purpose: the OFF_* table is the single source of
//! truth the naked asm reads via const operands, and the host test
//! below pins it against the struct — the M2-W2 bug was exactly this
//! table mirror-inverted as literals in the stub (nr was read from the
//! RBX slot, making every user syscall a garbage-nr -ENOSYS).

/// The register image the stub parks on the syscall stack, listed in
/// the stub's PUSH order — which is the HIGHEST stack address first:
/// the last push lands at [rsp+0], so field i of this struct sits at
/// `88 - 8*i` from the post-push RSP.
#[repr(C)]
pub struct SyscallFrame {
    _pad0: u64,   // stack alignment (12 slots = 96 bytes)
    pub rax: u64, // syscall number in; result out
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rcx: u64, // user rip (SYSRET target)
    pub r11: u64, // user rflags (SYSRET restores)
    pub rbx: u64, // borrowed for the TSC measurement, restored
    _pad1: u64,   // alignment
}

/// Post-push RSP-relative slot offsets — the mirror of `SyscallFrame`
/// (push order → descending stack slots; the last push is at +0).
pub const OFF_PAD1: u64 = 0; // the final alignment push
pub const OFF_RBX: u64 = 8;
pub const OFF_R11: u64 = 16;
pub const OFF_RCX: u64 = 24;
pub const OFF_R9: u64 = 32;
pub const OFF_R8: u64 = 40;
pub const OFF_R10: u64 = 48;
pub const OFF_RDX: u64 = 56;
pub const OFF_RSI: u64 = 64;
pub const OFF_RDI: u64 = 72;
pub const OFF_RAX: u64 = 80; // the syscall number in; the result out
pub const OFF_PAD0: u64 = 88; // the first (highest) push

#[cfg(test)]
mod tests {
    use super::*;

    /// The consts the asm reads must equal the mirror of the struct's
    /// declared order: slot(f) = 88 - struct_offset(f). This is the
    /// regression guard for the M2-W2 mirror-inversion bug — any edit
    /// that desynchronizes the push list, the struct, or the OFF_*
    /// table fails here, on the host, before a boot is needed.
    #[test]
    fn stub_offsets_mirror_the_frame_struct() {
        let mirror = |struct_off: usize| 88 - struct_off as u64;
        assert_eq!(OFF_PAD0, mirror(core::mem::offset_of!(SyscallFrame, _pad0)));
        assert_eq!(OFF_RAX, mirror(core::mem::offset_of!(SyscallFrame, rax)));
        assert_eq!(OFF_RDI, mirror(core::mem::offset_of!(SyscallFrame, rdi)));
        assert_eq!(OFF_RSI, mirror(core::mem::offset_of!(SyscallFrame, rsi)));
        assert_eq!(OFF_RDX, mirror(core::mem::offset_of!(SyscallFrame, rdx)));
        assert_eq!(OFF_R10, mirror(core::mem::offset_of!(SyscallFrame, r10)));
        assert_eq!(OFF_R8, mirror(core::mem::offset_of!(SyscallFrame, r8)));
        assert_eq!(OFF_R9, mirror(core::mem::offset_of!(SyscallFrame, r9)));
        assert_eq!(OFF_RCX, mirror(core::mem::offset_of!(SyscallFrame, rcx)));
        assert_eq!(OFF_R11, mirror(core::mem::offset_of!(SyscallFrame, r11)));
        assert_eq!(OFF_RBX, mirror(core::mem::offset_of!(SyscallFrame, rbx)));
        assert_eq!(OFF_PAD1, mirror(core::mem::offset_of!(SyscallFrame, _pad1)));
        // The load-bearing ones, spelled out: nr comes from the RAX
        // slot, SYSRET's RIP/RFLAGS from RCX/R11.
        assert_eq!((OFF_RAX, OFF_RCX, OFF_R11), (80, 24, 16));
        // And the frame is exactly the 12 pushed quadwords.
        assert_eq!(core::mem::size_of::<SyscallFrame>(), 96);
    }
}
