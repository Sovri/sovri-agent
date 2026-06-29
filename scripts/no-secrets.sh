#!/usr/bin/env bash
set -uo pipefail
# Reject secret-like files by name AND obvious API-key/private-key material by
# content. Modes: --staged (default), --tracked (CI), or explicit file args.
SECRET_PATTERNS='\.(env|pem|key|p12|pfx|secret|creds|netrc|npmrc|pypirc)$|(^|/)\.(env|secrets|aws)/|(^|/)\.env\.[^/]+$'
KEY_PATTERNS='AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
mode="${1:---staged}"
case "$mode" in
  --tracked) mapfile -t FILES < <(git ls-files) ;;
  --staged)  mapfile -t FILES < <(git diff --cached --diff-filter=d --name-only) ;;
  *)         FILES=("$@") ;;
esac
[ ${#FILES[@]} -eq 0 ] && { echo "no-secrets OK (no files)"; exit 0; }
rc=0
offend=()
for f in "${FILES[@]}"; do
  case "$f" in *.env.example|*.env.*.example) continue ;; esac
  if printf '%s\n' "$f" | grep -qiE "$SECRET_PATTERNS"; then offend+=("$f"); fi
done
if [ ${#offend[@]} -gt 0 ]; then
  echo "BLOCKED: files possibly containing secrets:"
  printf '  - %s\n' "${offend[@]}"
  rc=1
fi
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  # Skip lockfiles, binaries, and the secret-detector scripts themselves
  # (they contain the patterns above as regexes, not real secrets).
  case "$f" in *.lock|scripts/no-secrets.sh|scripts/check-offline-setup.sh|*.png|*.jpg|*.gif|*.pdf) continue ;; esac
  if grep -ElI "$KEY_PATTERNS" "$f" >/dev/null 2>&1; then
    echo "BLOCKED: API key / private key pattern detected in: $f"
    rc=1
  fi
done
[ "$rc" -eq 0 ] && echo "no-secrets OK"
exit "$rc"
