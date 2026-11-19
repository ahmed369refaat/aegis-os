//! Boot layer: raw CPU control at bring-up.
//!
//! SAFETY POLICY: this module (and only this module, plus `hw` and
//! `memops`) is allowed to contain `unsafe`. Everything here runs
//! single-threaded before the kernel has any concurrency. Every unsafe
//! item carries a `SAFETY` note explaining its exact invariant.

#![allow(unsafe_code)]

pub mod asm;
pub mod paging;

/// The exported kernel entry called by the 64-bit stub in `asm.rs`.
/// Living here (the allowlisted boot module) keeps `kmain.rs` pure safe
/// Rust: `#[unsafe(no_mangle)]` is an ABI declaration, and this module is
/// exactly where ABI-level declarations belong.
#[unsafe(no_mangle)]
pub extern "C" fn aegis_kmain_entry(magic: u32, info: u32) -> ! {
    crate::kmain::kmain(magic, info)
}
