//! Build script for the `pkg` binary: the freestanding link recipe
//! for the AegisOS target ONLY. Host builds — the test suite, the host
//! binary, clippy — link normally (no link argument is emitted).
//!
//! The image is linked for the SERVICE memory contract (the kernel's
//! `mm::user_layout::SERVICE`, K22): three PT_LOADs inside the image
//! cage [0x400000, 0x480000) with one absent page between neighbours
//! — `pkg.ld` places them, and the kernel's exec arm checks the plan
//! against the contract before a frame is spent.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("pkg.ld").display()
    );
    println!("cargo:rerun-if-changed=build.rs");

    if target == "x86_64-unknown-none" {
        println!(
            "cargo:rustc-link-arg=-T{}",
            manifest.join("pkg.ld").display()
        );
        // Freestanding, position-fixed: no PIE, no startup files, no
        // libc (the entry is the `_start` shim in src/main.rs).
        println!("cargo:rustc-link-arg=-no-pie");
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=--gc-sections");
        println!("cargo:rustc-link-arg=-z");
        println!("cargo:rustc-link-arg=norelro");
        // The script is written in 4 KiB pages; never let a default
        // 2 MiB "common page size" pad a section onto another page.
        println!("cargo:rustc-link-arg=-z");
        println!("cargo:rustc-link-arg=max-page-size=4096");
    }
}
