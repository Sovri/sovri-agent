#!/usr/bin/env bash
set -uo pipefail
# Reject build/run instructions that mint and store a credential on disk, which
# would break the air-gapped, credential-free guarantee (R-06).
if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  mapfile -t FILES < <(printf '%s\n' README.md CONTRIBUTING.md; git ls-files 'docs/*.md' 2>/dev/null || true)
fi
pat='(generat|mint|creat)[a-z]*.{0,60}(api[ _-]?token|api[ _-]?key|credential|secret).{0,60}(stor|sav|writ|persist|>>?|~/|\./)'
bad=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  matches="$(grep -niE "$pat" "$f" || true)"
  if [ -n "$matches" ]; then
    echo "REJECTED ($f): building or running must not require generating and storing a credential"
    printf '%s\n' "$matches" | sed -n '1,2{s/^/    /;p}'
    bad=1
  fi
done
if [ "$bad" -eq 0 ]; then echo "offline-setup OK"; else exit 1; fi
