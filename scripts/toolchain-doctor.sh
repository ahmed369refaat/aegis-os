#!/usr/bin/env bash
# Toolchain doctor — diagnose the dev environment in one run.
#
# The sandbox that builds this kernel gets recycled between work
# sessions, and three recycles have now produced THREE DIFFERENT
# truncation modes: (1) the cargo binary vanished while clippy stayed;
# (2) cargo AND the extracted qemu-root vanished; (3) cargo LOOKED
# intact but every host std rlib was a metadata stub, so the very
# first `cargo test` failed with 2956 errors from a CLEAN checkout.
# Each failure cost a long manual hunt; this script compresses that
# hunt to one command that names the broken piece and its repair.
#
# What it checks (each with a fast, honest probe):
#   1. rustc + cargo + clippy + rustfmt respond to --version
#   2. the HOST std actually LINKS — a Vec-using hello compiled AND
#      run (the metadata-stub mode passes any file-existence check)
#   3. the KERNEL target (x86_64-unknown-none) core links — a
#      #![no_std] staticlib probe (the kernel lanes' first hard stop)
#   4. QEMU answers --version AND the seabios blobs exist in the
#      extracted root (a broken symlink boots nothing)
#
# Usage:  scripts/toolchain-doctor.sh          — diagnose only
#         scripts/toolchain-doctor.sh --fix    — attempt the repairs
# The tool locations default to this sandbox's layout and move with
# AEGIS_TOOLS (the tools dir) and CARGO/RUSTC from the environment.
#
# This file is part of the baseline ritual: run it first on any
# fresh/recycled sandbox BEFORE believing any gate result.
set -uo pipefail
cd "$(dirname "$0")/.."

TOOLS="${AEGIS_TOOLS:-/home/z/my-project/tools}"
DIST_BASE="https://static.rust-lang.org/dist/2026-11-12"
RUST_VER="1.100.0"
QEMU_ROOT="$TOOLS/qemu-root"

# Self-discovery: a recycled sandbox starts with a bare PATH. The
# doctor must find the toolchain the way the env scripts do — source
# the tools env if present, else the rustup toolchain bin directly —
# BEFORE any probe, or it reports a healthy environment as broken.
if ! command -v rustc >/dev/null 2>&1; then
    [ -f "$TOOLS/env.sh" ] && . "$TOOLS/env.sh"
fi
if ! command -v rustc >/dev/null 2>&1; then
    for tc_bin in "${RUSTUP_HOME:-/home/z/my-project/.toolchain/rustup}"/toolchains/*/bin; do
        [ -x "$tc_bin/rustc" ] && PATH="$tc_bin:$PATH" && break
    done
fi
# QEMU runs through the durable wrapper when it exists (it carries
# LD_LIBRARY_PATH + the root); the raw qemu-root binary is the fallback.
if [ -x "$TOOLS/qemu-system-x86_64" ]; then
    QEMU_BIN="$TOOLS/qemu-system-x86_64"
else
    QEMU_BIN="$QEMU_ROOT/usr/bin/qemu-system-x86_64"
fi

fail=0
section() { printf '\n== %s ==\n' "$1"; }
pass() { printf '  [PASS] %s\n' "$1"; }
bad() { printf '  [FAIL] %s\n' "$1"; fail=1; }

section "rust binaries"
for tool in rustc cargo rustfmt; do
    if "$tool" --version >/dev/null 2>&1; then
        pass "$tool $($tool --version 2>/dev/null | head -1)"
    else
        bad "$tool missing from PATH"
    fi
done
if cargo clippy --version >/dev/null 2>&1; then
    pass "clippy $(cargo clippy --version 2>/dev/null | head -1)"
else
    bad "clippy missing (cargo-clippy / clippy-driver)"
fi

section "host std links (the metadata-stub trap)"
probe_dir="$(mktemp -d)"
trap 'rm -rf "$probe_dir"' EXIT
cat >"$probe_dir/host.rs" <<'EOF'
fn main() {
    let v: Vec<u8> = Vec::new();
    println!("host-std-ok {}", v.capacity());
}
EOF
if rustc --edition 2024 "$probe_dir/host.rs" -o "$probe_dir/host.bin" 2>"$probe_dir/host.err" \
    && "$probe_dir/host.bin" | grep -q "host-std-ok" 2>/dev/null; then
    pass "host std compiles, links, and runs"
else
    bad "host std is broken (metadata stubs?): $(head -1 "$probe_dir/host.err")"
    [ "${1:-}" = "--fix" ] && {
        echo "  ..fix: reinstalling the rust-std component for $RUST_VER"
        if curl -sSL -o "$probe_dir/rstd.tar.xz" \
            "$DIST_BASE/rust-std-$RUST_VER-x86_64-unknown-linux-gnu.tar.xz" \
            && tar -xf "$probe_dir/rstd.tar.xz" -C "$probe_dir"; then
            stdsrc="$probe_dir/rust-std-$RUST_VER-x86_64-unknown-linux-gnu/rust-std-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib"
            stdlibdir="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib"
            cp -f "$stdsrc"/*.rlib "$stdsrc"/*.rmeta "$stdlibdir"/ 2>/dev/null
            if rustc --edition 2024 "$probe_dir/host.rs" -o "$probe_dir/host.bin" \
                && "$probe_dir/host.bin" | grep -q "host-std-ok"; then
                pass "host std repaired from the dist component"
            else
                bad "host std repair did not take — reinstall the toolchain"
            fi
        else
            bad "could not fetch the rust-std component (network?)"
        fi
    }
fi

section "kernel target links (x86_64-unknown-none)"
cat >"$probe_dir/kern.rs" <<'EOF'
#![no_std]
const XS: [u8; 4] = [core::hint::black_box(1u8); 4];
pub fn probe() -> u8 {
    XS.iter().fold(0u8, |a, b| a ^ b)
}
EOF
panic_stub='
#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }'
printf '%s' "$panic_stub" >>"$probe_dir/kern.rs"
if rustc --edition 2024 --crate-type staticlib --target x86_64-unknown-none \
    "$probe_dir/kern.rs" -o "$probe_dir/kern.rlib" 2>"$probe_dir/kern.err"; then
    pass "no_std staticlib for the kernel target links"
else
    bad "kernel target std/core is broken: $(head -1 "$probe_dir/kern.err")"
    [ "${1:-}" = "--fix" ] && {
        echo "  ..fix: reinstalling rust-std for the TARGET triple"
        if curl -sSL -o "$probe_dir/tstd.tar.xz" \
            "$DIST_BASE/rust-std-$RUST_VER-x86_64-unknown-none.tar.xz" \
            && tar -xf "$probe_dir/tstd.tar.xz" -C "$probe_dir"; then
            tsrc="$probe_dir/rust-std-$RUST_VER-x86_64-unknown-none/rust-std-x86_64-unknown-none/lib/rustlib/x86_64-unknown-none/lib"
            tlibdir="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-none/lib"
            cp -f "$tsrc"/*.rlib "$tsrc"/*.rmeta "$tlibdir"/ 2>/dev/null
            if rustc --edition 2024 --crate-type staticlib --target x86_64-unknown-none \
                "$probe_dir/kern.rs" -o "$probe_dir/kern.rlib"; then
                pass "kernel target repaired from the dist component"
            else
                bad "kernel target repair did not take — reinstall the toolchain"
            fi
        else
            bad "could not fetch the target rust-std component (network?)"
        fi
    }
fi

section "QEMU + firmware"
if [ -x "$QEMU_BIN" ]; then
    if "$QEMU_BIN" --version >/dev/null 2>&1; then
        pass "qemu at tools/qemu-root answers --version"
    else
        bad "qemu binary exists but does not run (loader/libs?)"
    fi
else
    bad "qemu binary missing at $QEMU_BIN"
    [ "${1:-}" = "--fix" ] && {
        echo "  ..fix: re-extracting the debs from $TOOLS/qemu-pkgs"
        mkdir -p "$QEMU_ROOT"
        for d in "$TOOLS"/qemu-pkgs/*.deb; do dpkg-deb -x "$d" "$QEMU_ROOT/"; done
        [ -x "$QEMU_BIN" ] && pass "qemu re-extracted from the cached debs" \
            || bad "re-extraction failed (are the debs present?)"
    }
fi
share="$QEMU_ROOT/usr/share/qemu"
firmware_ok=1
for fw in bios-256k.bin vgabios-stdvga.bin; do
    if [ -s "$share/$fw" ]; then
        pass "firmware present: $fw"
    else
        bad "firmware missing/broken: $share/$fw"
        firmware_ok=0
    fi
done
if [ "$firmware_ok" -eq 0 ] && [ "${1:-}" = "--fix" ]; then
    echo "  ..fix: relinking the seabios blobs"
    (cd "$share" && for f in ../seabios/*.bin; do ln -sf "$f" .; done)
    [ -s "$share/bios-256k.bin" ] && pass "seabios links repaired" \
        || bad "seabios sources absent from the extraction"
fi

section "verdict"
if [ "$fail" -eq 0 ]; then
    echo "TOOLCHAIN DOCTOR: PASS (all probes green — the baseline is real)"
    exit 0
fi
echo "TOOLCHAIN DOCTOR: FAIL (see above; rerun with --fix to attempt repairs)"
exit 1
