#!/usr/bin/env bash
set -euo pipefail
# Reject files that look like secrets or local credentials.
# Modes: --staged (default, pre-commit), --tracked (CI), or explicit file args.
SECRET_PATTERNS='\.(env|pem|key|p12|pfx|secret|creds|netrc|npmrc|pypirc)$|(^|/)\.(env|secrets|aws)/|(^|/)\.env\.[^/]+$'
mode="${1:---staged}"
case "$mode" in
  --tracked) mapfile -t FILES < <(git ls-files) ;;
  --staged)  mapfile -t FILES < <(git diff --cached --diff-filter=d --name-only) ;;
  *)         FILES=("$@") ;;
esac
[ ${#FILES[@]} -eq 0 ] && { echo "no-secrets OK (no files)"; exit 0; }
offend=()
for f in "${FILES[@]}"; do
  case "$f" in *.env.example|*.env.*.example) continue ;; esac
  if printf '%s\n' "$f" | grep -qiE "$SECRET_PATTERNS"; then offend+=("$f"); fi
done
if [ ${#offend[@]} -gt 0 ]; then
  echo "BLOCKED: files possibly containing secrets:"
  printf '  - %s\n' "${offend[@]}"
  exit 1
fi
echo "no-secrets OK"
