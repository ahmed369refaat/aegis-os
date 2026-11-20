#!/usr/bin/env bash
# Repo hygiene guard (incident: an 8 MiB ELF core dump of the build
# machine's kernel build — environment block included — was committed
# as kernel-x86_64/core; see docs/incident-core-dump.md).
#
# Fails the build on, for every file TRACKED IN GIT:
#   1. any ELF core dump (ELF e_type == 4 / ET_CORE) — a core embeds
#      the crashing process's memory, and with it every credential
#      that was in its environment at crash time;
#   2. any file larger than 1 MiB that is not on the explicit
#      oversize allowlist below (the ring-3 example blobs are tiny but
#      allowed to grow — they are build inputs the boot stub embeds);
#   3. any TEXT file matching a credential pattern (assignment-shaped
#      token/secret/api-key variables, GitHub/AWS key prefixes, or a
#      private-key PEM header).
#
#   ./check-no-binaries.sh             check the tracked tree
#   ./check-no-binaries.sh --self-test prove the checker catches each
#                                     case (fixtures generated at test
#                                     time under mktemp -d, never
#                                     committed)
#
# Known limitation, stated honestly: the secret scan covers TEXT files
# only (grep -I skips binaries). A credential hidden inside a committed
# binary blob is out of this checker's scope — the ELF-core and
# oversize rules are what keep accidental binaries out in the first
# place.
set -euo pipefail
cd "$(dirname "$0")/.."

# ── rule 2: the oversize allowlist (globs, matched against the
# repo-root-relative path). Add entries ONLY with an ADR reference.
OVERSIZE_ALLOWLIST=(
    "kernel-x86_64/blob/*.bin" # ring-3 example payloads embedded by boot-x86_64/stub.S
)
OVERSIZE_LIMIT=1048576 # 1 MiB

allowlisted() {
    local p=$1 g
    for g in "${OVERSIZE_ALLOWLIST[@]}"; do
        # shellcheck disable=SC2053 # glob match, not equality
        [[ $p == $g ]] && return 0
    done
    return 1
}

# ── rule 1: ELF core detection. Prints the decimal e_type of $1 when
# $1 is an ELF file with a complete header, nothing otherwise.
elf_e_type() {
    local f=$1 magic size
    size=$(stat -c%s -- "$f")
    [ "$size" -ge 18 ] || return 1
    magic=$(head -c 4 -- "$f" | od -An -tx1 | tr -d ' \n')
    [ "$magic" = "7f454c46" ] || return 1
    od -An -tu2 -j16 -N2 -- "$f" | tr -d ' '
}

is_elf_core() {
    local t
    t=$(elf_e_type "$1") || return 1
    [ "$t" = "4" ] # ET_CORE
}

# ── rule 3: credential patterns in text files. NOTE: this script is
# itself excluded from the scan — the pattern literals below would
# self-trigger. That exclusion is the only one; do not grow it.
SECRET_PATTERNS=(
    '_TOKEN='
    '_SECRET='
    'API_KEY='
    'ghp_'
    'github_pat_'
    'AKIA[0-9A-Z]{16}' # AWS access-key ID shape (AKIA + 16 uppercase alnum); bare "AKIA" would false-positive on prose
    '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
)
SECRET_SCAN_EXCLUDE=(
    'scripts/check-no-binaries.sh' # this file: it defines the patterns
)

# Prints the paths among "$@" that are text files matching a pattern.
secret_text_matches() {
    local args=()
    args+=(-I -l -E)
    local p
    for p in "${SECRET_PATTERNS[@]}"; do
        args+=(-e "$p")
    done
    [ "$#" -gt 0 ] || return 0
    grep "${args[@]}" -- "$@" </dev/null || true
}

# ── self-test: fixtures built at test time, deleted on exit.
if [ "${1:-}" = "--self-test" ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    # ELF fixture factory: $1 = e_type (LE u16 at offset 16), $2 = path.
    make_elf() {
        mkdir -p "$(dirname "$2")"
        {
            printf '\x7fELF'
            head -c 12 /dev/zero
            printf '%b' "$(printf '\\x%02x\\x%02x' "$(( $1 & 0xff ))" "$(( ($1 >> 8) & 0xff ))")"
            printf 'payload-payload-payload'
        } > "$2"
    }
    make_elf 4 "$tmp/core.fixture"   # ET_CORE — must be caught
    make_elf 2 "$tmp/exec.fixture"   # ET_EXEC — a normal ELF, not a core
    printf 'plain text, not an elf' > "$tmp/notelf.fixture"
    printf 'elf?' > "$tmp/short.fixture" # < 18 bytes, no full header

    # Oversize fixtures: strictly over the limit; one on the allowlist.
    mkdir -p "$tmp/kernel-x86_64/blob" "$tmp/big"
    head -c $((OVERSIZE_LIMIT + 1)) /dev/zero > "$tmp/big/other.bin"
    head -c $((OVERSIZE_LIMIT + 1)) /dev/zero > "$tmp/kernel-x86_64/blob/ring3-hello.bin"
    printf 'small' > "$tmp/small.txt"

    # Secret fixtures: one per pattern class, one benign, one binary.
    printf 'Z_CODE_ENDPOINT_TOKEN=0123456789abcdef\n' > "$tmp/s1.txt"
    printf 'DB_SECRET=hunter2\n' > "$tmp/s2.txt"
    printf 'API_KEY=AIzaSYexample\n' > "$tmp/s3.txt"
    printf 'auth = ghp_ABCdefGHIjklMNO\n' > "$tmp/s4.txt"
    printf 'auth = github_pat_11ABCdefGHI\n' > "$tmp/s5.txt"
    printf 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n' > "$tmp/s6.txt"
    printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----\n' > "$tmp/s7.txt"
    printf 'rotate the token at the provider; the AKIARY note aside, no key here\n' > "$tmp/benign.txt"
    { printf '\000\001\002'; printf 'API_KEY=hidden-in-a-binary'; } > "$tmp/binary.fixture"

    fail=0
    expect_core()  { if is_elf_core "$1"; then echo "SELF-TEST ok: core detected: $1"; else echo "SELF-TEST FAIL: not detected as ELF core: $1"; fail=1; fi; }
    expect_nocore() { if is_elf_core "$1"; then echo "SELF-TEST FAIL: false ELF-core positive: $1"; fail=1; else echo "SELF-TEST ok: not a core: $1"; fi; }
    expect_oversize() { # $1 = path (repo-relative shape for the glob), $2 = real file
        local rel=$1 real=$2
        if [ "$(stat -c%s -- "$real")" -gt "$OVERSIZE_LIMIT" ] && ! allowlisted "$rel"; then
            echo "SELF-TEST ok: oversize caught: $rel"
        else
            echo "SELF-TEST FAIL: oversize file accepted: $rel"; fail=1
        fi
    }
    expect_allowed() {
        local rel=$1 real=$2
        if [ "$(stat -c%s -- "$real")" -gt "$OVERSIZE_LIMIT" ] && allowlisted "$rel"; then
            echo "SELF-TEST ok: allowlisted blob accepted: $rel"
        else
            echo "SELF-TEST FAIL: allowlisted blob rejected: $rel"; fail=1
        fi
    }

    expect_core "$tmp/core.fixture"
    expect_nocore "$tmp/exec.fixture"
    expect_nocore "$tmp/notelf.fixture"
    expect_nocore "$tmp/short.fixture"
    expect_oversize "big/other.bin" "$tmp/big/other.bin"
    expect_allowed "kernel-x86_64/blob/ring3-hello.bin" "$tmp/kernel-x86_64/blob/ring3-hello.bin"

    # Secret scan: run over all fixtures with RELATIVE paths so the
    # function under test sees exactly what main mode would see.
    (cd "$tmp" && secret_text_matches \
        core.fixture exec.fixture notelf.fixture short.fixture \
        big/other.bin kernel-x86_64/blob/ring3-hello.bin small.txt \
        s1.txt s2.txt s3.txt s4.txt s5.txt s6.txt s7.txt benign.txt binary.fixture \
        > caught.txt) || true
    for s in s1 s2 s3 s4 s5 s6 s7; do
        if grep -q "^$s.txt$" "$tmp/caught.txt"; then
            echo "SELF-TEST ok: secret pattern caught: $s.txt"
        else
            echo "SELF-TEST FAIL: secret fixture NOT caught: $s.txt"; fail=1
        fi
    done
    for b in benign.txt binary.fixture small.txt core.fixture; do
        if grep -q "^$b$" "$tmp/caught.txt"; then
            echo "SELF-TEST FAIL: false positive on: $b"; fail=1
        else
            echo "SELF-TEST ok: not flagged: $b"
        fi
    done
    if [ "$fail" -eq 0 ]; then
        echo "NO-BINARIES GUARD: self-test PASS (ELF core, oversize, allowlist glob and every secret pattern caught; no false positives)"
    fi
    exit "$fail"
fi

# ── main: check every tracked file.
mapfile -d '' -t tracked < <(git ls-files -z)
[ "${#tracked[@]}" -gt 0 ] || { echo "NO-BINARIES GUARD: PASS (no tracked files?)"; exit 0; }

fail=0
for f in "${tracked[@]}"; do
    if is_elf_core "$f"; then
        echo "HYGIENE FAIL: $f is an ELF core dump — untrack it (git rm), rotate anything its environment may have leaked, see docs/incident-core-dump.md"
        fail=1
    fi
    if [ "$(stat -c%s -- "$f")" -gt "$OVERSIZE_LIMIT" ] && ! allowlisted "$f"; then
        echo "HYGIENE FAIL: $f is larger than 1 MiB and not on the oversize allowlist (scripts/check-no-binaries.sh)"
        fail=1
    fi
done

# Secret scan over tracked text files minus the checker itself.
scan=()
for f in "${tracked[@]}"; do
    skip=0
    for e in "${SECRET_SCAN_EXCLUDE[@]}"; do
        [ "$f" = "$e" ] && skip=1
    done
    [ "$skip" -eq 0 ] && scan+=("$f")
done
if [ "${#scan[@]}" -gt 0 ]; then
    hits=$(secret_text_matches "${scan[@]}")
    if [ -n "$hits" ]; then
        while IFS= read -r h; do
            echo "HYGIENE FAIL: $h matches a credential pattern (rotation needed: see docs/incident-core-dump.md)"
        done <<< "$hits"
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "NO-BINARIES GUARD: PASS (no tracked ELF cores, no oversize files outside the allowlist, no credential patterns in text files)"
fi
exit "$fail"
