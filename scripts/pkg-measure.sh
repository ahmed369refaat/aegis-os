#!/usr/bin/env bash
# K22 measurement: how big is the package manager as a REAL linked
# image for x86_64-unknown-none (the shell's exact codegen recipe:
# panic=abort, opt-level=z, one codegen unit, gc-sections, static
# relocation)? The numbers decide the cage contract — nothing is
# guessed. Output goes under target/pkg-measure/ (never the tree).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=target/pkg-measure
mkdir -p "$OUT"
COMMON=(-C panic=abort -C opt-level=z -C codegen-units=1
        -C debug-assertions=off -C overflow-checks=off
        --target x86_64-unknown-none)
rustc --edition 2021 --crate-type=rlib "${COMMON[@]}" \
      -C relocation-model=static pkg/src/lib.rs -o "$OUT/libaegis_pkg.rlib"
rustc --edition 2021 --crate-type=bin "${COMMON[@]}" \
      -C linker=ld -C link-arg=--gc-sections -C link-arg=--entry=pkg_main \
      -C relocation-model=static \
      --extern aegis_pkg="$OUT/libaegis_pkg.rlib" \
      pkg/src/main.rs -o "$OUT/pkg-default.elf"
echo "== section sizes (default link, for measurement only)"
size -A "$OUT/pkg-default.elf" | grep -E "^\.(text|rodata|data|bss|data.rel.ro|tdata|tbss)" || true
echo "== totals"
size "$OUT/pkg-default.elf"
echo "== program headers"
readelf -lW "$OUT/pkg-default.elf" | grep -E "^  LOAD"
