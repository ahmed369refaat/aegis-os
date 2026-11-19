//! x86_64 architecture layer: CPU tables and exception entry (PR-1.1).
//!
//! SAFETY POLICY: `gdt`, `idt`, `stubs` and `exceptions` join the
//! documented unsafe allowlist (`docs/adr/0005-exception-machinery.md`):
//! they program raw CPU structures (GDT/TSS/IDT) and own the assembly
//! entry path. Every unsafe item carries a `SAFETY` note; the descriptor
//! and frame encodings are pure and host-tested.
//!
//! Host builds compile the pure parts (`frame`, `gdt`, `idt` encodings) so
//! their layouts are unit-tested; the runtime modules (`stubs`,
//! `exceptions`, the `load` fns) are target-only.

pub mod frame;
pub mod gdt;
pub mod idt;

#[cfg(not(test))]
pub mod exceptions;
#[cfg(not(test))]
pub mod stubs;

/// Load the kernel-owned GDT (+TSS) and IDT, arming the exception entry
/// path. Called once from `kmain`, before anything is allowed to fault.
#[cfg(not(test))]
pub fn init() {
    gdt::load();
    idt::load();
    crate::serial::write_str("[ARCH] gdt/tss/idt armed: exception entry live\n");
}
