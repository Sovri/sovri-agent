#!/usr/bin/env bash
set -euo pipefail
# Every workflow `uses:` reference must be pinned to a full 40-hex commit SHA.
fail=0
mapfile -t wfs < <(git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml' 2>/dev/null || true)
if [ ${#wfs[@]} -eq 0 ]; then
  mapfile -t wfs < <(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null || true)
fi
for wf in "${wfs[@]}"; do
  [ -f "$wf" ] || continue
  while IFS= read -r ref; do
    case "$ref" in ./*|docker://*|"") continue ;; esac
    sha="${ref##*@}"
    if ! printf '%s' "$sha" | grep -qE '^[0-9a-f]{40}$'; then
      echo "NOT SHA-PINNED: $wf -> $ref"
      fail=1
    fi
  done < <(grep -hoE 'uses:[[:space:]]*[^[:space:]]+' "$wf" | sed -E 's/uses:[[:space:]]*//')
done
if [ "$fail" -eq 0 ]; then echo "action pins OK"; else exit 1; fi
