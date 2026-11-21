#!/usr/bin/env bash
# check-history-clean.sh (round 5, Phase C): scan ALL REACHABLE HISTORY
# for the classes the incident runbook cares about —
#   1. any blob that is an ELF core dump (e_type == 4 / ET_CORE),
#   2. any blob over 1 MiB outside the known-good blob allowlist,
#   3. any blob matching the credential patterns check-no-binaries.sh
#      uses on the working tree.
# check-no-binaries.sh guards the TREE at HEAD; this script guards the
# HISTORY (every ref, every commit). It is REPORT-ONLY by default: a
# failure means the HUMAN purge step of docs/incident-core-dump.md is
# still pending — the core dump (with its environment block) is still
# reachable in history. After the purge, flip the CI invocation to
# `--strict` so a recurrence fails the build (the runbook documents
# this).
#
# Exit codes: 0 always without --strict; 1 on findings with --strict.
set -uo pipefail
cd "$(dirname "$0")/.."

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

# The oversize allowlist mirrors check-no-binaries.sh (the ring-3
# example blobs are the only intentional binaries).
ALLOWLIST_REGEX='^kernel-x86_64/blob/[^/]+\.bin$'
MAX_BYTES=$((1024 * 1024))

# Credential patterns — the same ASSIGNMENT-SHAPED patterns
# check-no-binaries.sh uses on the working tree (a bare variable NAME
# in documentation is not a secret; NAME=value is). The two files
# that define these literals are excluded, exactly like
# check-no-binaries.sh excludes itself — those are the only exclusions.
SECRET_REGEX='(_TOKEN=|_SECRET=|API_KEY=|ghp_|github_pat_|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)'
SECRET_SCAN_EXCLUDE_REGEX='^scripts/(check-no-binaries|check-history-clean)\.sh$'

findings=0

# Every unique object reachable from any ref, with a path hint.
# Format: <sha> <path>  (path may be empty for unreferenced-by-tree).
while read -r sha path; do
    [ -n "$sha" ] || continue
    type=$(git cat-file -t "$sha" 2>/dev/null) || continue
    [ "$type" = "blob" ] || continue
    size=$(git cat-file -s "$sha" 2>/dev/null) || continue

    # Rule 1: ELF core in history (read only the 20-byte header).
    if [ "$size" -ge 20 ]; then
        hdr=$(git cat-file blob "$sha" 2>/dev/null | head -c 20 | od -An -tu1 | tr -s ' ')
        if echo "$hdr" | grep -qE '^\s*127\s+69\s+76\s+70'; then
            # ELF magic — e_type is bytes 16-17 (little endian).
            et=$(git cat-file blob "$sha" 2>/dev/null | head -c 20 | od -An -td2 -j16 -N2 | tr -d ' ')
            if [ "$et" = "4" ]; then
                echo "HISTORY FINDING: ELF core dump (e_type=4) in history: $sha  ${path:-(no path)}"
                findings=$((findings + 1))
            fi
        fi
    fi

    # Rule 2: oversize blob outside the allowlist.
    if [ "$size" -gt "$MAX_BYTES" ]; then
        if ! echo "$path" | grep -qE "$ALLOWLIST_REGEX"; then
            echo "HISTORY FINDING: blob over 1 MiB in history ($size bytes): $sha  ${path:-(no path)}"
            findings=$((findings + 1))
        fi
    fi

    # Rule 3: credential patterns in small text-ish blobs (a huge
    # binary match is covered by rule 1/2; patterns are for text).
    if [ "$size" -le "$MAX_BYTES" ] && [ "$size" -gt 0 ]; then
        if ! echo "$path" | grep -qE "$SECRET_SCAN_EXCLUDE_REGEX" \
           && git cat-file blob "$sha" 2>/dev/null | grep -aEq "$SECRET_REGEX"; then
            echo "HISTORY FINDING: credential pattern in history: $sha  ${path:-(no path)}"
            findings=$((findings + 1))
        fi
    fi
done < <(git rev-list --all --objects | awk '{print $1, substr($0, length($1) + 2)}')

if [ "$findings" -gt 0 ]; then
    echo ""
    echo "HISTORY-CLEAN: FAIL ($findings finding(s))."
    echo "  This is EXPECTED until the HUMAN purge of docs/incident-core-dump.md"
    echo "  runs (rotate the credential FIRST, then filter-repo + force-push —"
    echo "  see that runbook). This check is report-only so the repository stays"
    echo "  buildable in the meantime. After the purge, run with --strict (and"
    echo "  flip the CI invocation) so any recurrence fails the build."
    [ "$STRICT" = "1" ] && exit 1
    exit 0
fi

echo "HISTORY-CLEAN: PASS (no reachable ELF cores, no oversize blobs, no credential patterns)"
exit 0
