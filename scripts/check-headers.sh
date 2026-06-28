#!/usr/bin/env bash
set -euo pipefail
# Verify every tracked Rust source file carries the Apache-2.0 SPDX header.
# Uses a here-string (not a pipe) so an early `grep -q` cannot SIGPIPE `head`
# and wrongly report a missing header under `pipefail`.
fail=0
mapfile -t files < <(git ls-files '*.rs' 2>/dev/null || true)
if [ ${#files[@]} -eq 0 ]; then
  mapfile -t files < <(find . -name '*.rs' -not -path './target/*' 2>/dev/null || true)
fi
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  hdr="$(head -n 3 "$f")"
  if ! grep -q 'SPDX-License-Identifier: Apache-2.0' <<<"$hdr"; then
    echo "MISSING license header: $f"
    fail=1
  fi
done
if [ "$fail" -eq 0 ]; then echo "license headers OK"; else exit 1; fi
