//! The `tcpipd` binary entry point.
//!
//! Two shapes, exactly the `pkg` discipline:
//!
//! * **Host** (development, the workspace's clippy/test gates): a
//!   normal `main` that prints what this crate is — the service
//!   logic itself lives in the library and is fully checked there.
//! * **AegisOS target** (`x86_64-unknown-none`): `#![no_main]`, a
//!   `_start` shim that runs `service_main`, and a panic handler
//!   that exits with code 9 (loud: a service panic is a service bug).

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

// ── host build ──

#[cfg(not(target_os = "none"))]
fn main() {
    println!(
        "aegis-tcpip: the AegisOS ring-3 TCP/IP service image \
(host build: logic-only — run boot.sh for the real image)"
    );
}

// ── AegisOS target ──

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let code = aegis_tcpip::service_main();
    aegis_tcpip::sys::exit(i64::from(code))
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // A panic in the service is a service bug: exit 9, loud.
    aegis_tcpip::sys::exit(9)
}
