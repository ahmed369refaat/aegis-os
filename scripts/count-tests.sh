#!/usr/bin/env bash
# G (review round 2): the single source of truth for test counts. Run
# with --update to rewrite the README numbers/badge so they cannot
# drift (they disagreed across docs before: 93/196/219/261/265).
set -euo pipefail
cd "$(dirname "$0")/.."

LIB=$(cargo test 2>/dev/null | grep "test result" | awk '{s+=$4} END {print s}')
KERNEL=$(cargo test -p aegis-kernel 2>/dev/null | grep "test result" | awk '{s+=$4} END {print s}')
TOTAL=$((LIB + KERNEL))

echo "lib=$LIB kernel=$KERNEL total=$TOTAL"

if [ "${1:-}" = "--update" ]; then
  sed -i "s/tests-[0-9]\+%20passing/tests-${TOTAL}%20passing/; s/Tests: [0-9]\+/Tests: ${TOTAL}/" README.md
  sed -i "s/\*\*[0-9]\+ tests\.\*\*/**${LIB} tests.**/" README.md
  sed -i "s|# [0-9]\+ policy-core tests|# ${LIB} policy-core tests|" README.md
  sed -i "s|# [0-9]\+ host tests: boot|# ${KERNEL} host tests: boot|" README.md
  echo "README updated: lib=${LIB} kernel=${KERNEL} total=${TOTAL}"
fi
