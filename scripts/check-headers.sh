#!/usr/bin/env bash
set -euo pipefail
# Verify every tracked Rust source file carries the Apache-2.0 SPDX header.
fail=0
mapfile -t files < <(git ls-files '*.rs' 2>/dev/null || true)
if [ ${#files[@]} -eq 0 ]; then
  mapfile -t files < <(find . -name '*.rs' -not -path './target/*' 2>/dev/null || true)
fi
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  if ! head -n 3 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
    echo "MISSING license header: $f"
    fail=1
  fi
done
if [ "$fail" -eq 0 ]; then echo "license headers OK"; else exit 1; fi
