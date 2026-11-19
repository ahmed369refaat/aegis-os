//! Boot layer: the 64-bit kernel entry.
//!
//! SAFETY POLICY: this module (and only this module, plus `hw` and
//! `memops`) is allowed to contain `unsafe`. It runs single-threaded at
//! bring-up, before any kernel invariant exists.
//!
//! ## The two-stage boot (why this looks like this)
//!
//! QEMU's `-kernel` multiboot loader only accepts **ELF32** images, while
//! the kernel proper is 64-bit and links as ELF64. So booting is
//! two-stage:
//!
//! 1. **`boot-x86_64/stub.S`** — a tiny ELF32 multiboot-v1 stub (pure
//!    assembly, no logic). QEMU/GRUB loads it at 1 MiB; it stashes the
//!    multiboot registers and an early TSC stamp, loads its own GDT,
//!    builds identity page tables for the first 1 GiB, switches to long
//!    mode, and jumps to this kernel's entry (address passed at link
//!    time via `--defsym=kernel_entry=…`; the kernel blob itself is
//!    embedded in the stub's image at its 2 MiB link base).
//! 2. **`aegis_entry_64`** (below) — the kernel's first 64-bit
//!    instruction: zero `.bss` (the stub cannot know the kernel's bss
//!    extent across link units), store the boot TSC, switch to the
//!    kernel stack, and call `aegis_kmain_entry` with the multiboot
//!    registers as arguments.
//!
//! The stub is the machine-state trust base (no logic, ~150 lines,
//! heavily commented); everything after it is Rust under the unsafe
//! allowlist. Symbols referenced from the asm below are either
//! `#[unsafe(no_mangle)]` Rust items or linker-script globals
//! (`_bss_start`, `_bss_end`, `stack_top`).

#![allow(unsafe_code)]

use core::arch::naked_asm;

/// The kernel's first 64-bit instruction.
///
/// Stub contract: `RDI` = multiboot magic, `RSI` = multiboot info
/// physical address, `RDX` = TSC at the stub's first instruction.
///
/// SAFETY: naked function — the body is raw assembly with no Rust
/// prologue; it must not be called from Rust and must not return.
#[unsafe(no_mangle)]
#[link_section = ".text.entry"]
#[unsafe(naked)]
pub extern "C" fn aegis_entry_64() {
    naked_asm!(
        // AT&T syntax: every operand is explicit about immediate vs memory.
        // (1) Save the stub-passed values in callee-saved registers while
        //     .bss is still unsafe to touch (it is about to be zeroed).
        "movl    %edi, %ebx",          // magic
        "movl    %esi, %r12d",         // info address
        "movq    %rdx, %rbp",          // boot TSC
        // 2. Zero .bss: [ _bss_start, _bss_end ), 8 bytes at a time.
        //    The multiboot loader zeroed the *stub's* bss only; the
        //    kernel's .bss (beyond the embedded blob) is ours to clear.
        "cld",
        "lea     _bss_start(%rip), %rdi",
        "lea     _bss_end(%rip), %rcx",
        "subq    %rdi, %rcx",
        "shrq    $3, %rcx",
        "xorq    %rax, %rax",
        "rep     stosq",
        // 3. Now that .bss is zero, store the boot TSC stamp.
        "movl    %ebp, BOOT_TSC_LO",
        "movq    %rbp, %rax",
        "shrq    $32, %rax",
        "movl    %eax, BOOT_TSC_HI",
        // 4. Switch to the kernel stack (defined in linker.ld).
        "lea     stack_top(%rip), %rsp",
        // 5. aegis_kmain_entry(magic, info) — SysV: rdi, rsi.
        "movl    %ebx, %edi",
        "movl    %r12d, %esi",
        "call    aegis_kmain_entry",
        // Unreachable: kmain never returns.
        "1:",
        "cli",
        "hlt",
        "jmp     1b",
        options(att_syntax),
    );
}

/// The exported entry called by the 64-bit boot stub. Forwards to the
/// Rust kmain (see kmain.rs).
#[unsafe(no_mangle)]
pub extern "C" fn aegis_kmain_entry(magic: u32, info: u32) -> ! {
    crate::kmain::kmain(magic, info)
}
