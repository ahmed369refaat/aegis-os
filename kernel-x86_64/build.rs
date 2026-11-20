//! Build script for the aegis-kernel binary.
//!
//! Emits the custom linker script (and freestanding link flags) **only**
//! when compiling for the bare-metal target, so host test builds
//! (`cargo test -p aegis-kernel`) link normally.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("linker.ld").display()
    );
    println!("cargo:rerun-if-changed=build.rs");

    if target == "x86_64-unknown-none" {
        println!(
            "cargo:rustc-link-arg=-T{}",
            manifest.join("linker.ld").display()
        );
        // Freestanding, position-fixed binary: no PIE, no startup files,
        // no libc. compiler-builtins (provided by rustc) still covers the
        // arithmetic helpers the core needs (e.g. 128-bit division used by
        // the monitor's scoring math).
        println!("cargo:rustc-link-arg=-no-pie");
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=-z");
        println!("cargo:rustc-link-arg=norelro");
    }
}
