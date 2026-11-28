//! Build script for the `tcpipd` image: the freestanding link recipe
//! for the AegisOS target ONLY (host builds — tests, clippy — link
//! normally; no link argument is emitted).
//!
//! The image is linked for the NETSVC memory contract (the kernel's
//! `mm::user_layout::NETSVC`, P1-1): three PT_LOADs inside the image
//! cage [0x400000, 0x480000) with one absent page between neighbours;
//! `tcpipd.ld` places them, the shared config/report page pins at
//! 0x420000, and the kernel's `spawn_user_elf` checks the plan
//! against the contract before a frame is spent.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("tcpipd.ld").display()
    );
    println!("cargo:rerun-if-changed=build.rs");

    if target == "x86_64-unknown-none" {
        println!(
            "cargo:rustc-link-arg=-T{}",
            manifest.join("tcpipd.ld").display()
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
