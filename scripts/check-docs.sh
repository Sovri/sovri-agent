#!/usr/bin/env bash
set -euo pipefail
# Verify the README documents the required commands (R-01) and the
# Community/Open Core boundary + air-gap sections (R-05). Names what is missing.
README="${1:-README.md}"
fail=0
needf() { grep -qF -- "$1" "$README" || { echo "MISSING: $2"; fail=1; }; }
grep -qE '^##[[:space:]]+Development' "$README" || { echo "MISSING: ## Development section"; fail=1; }
needf 'cargo build' 'build command "cargo build"'
needf 'cargo test' 'test command "cargo test"'
needf 'cargo fmt --check && cargo clippy --all-targets -- -D warnings' 'lint command "cargo fmt --check && cargo clippy --all-targets -- -D warnings"'
grep -qiE '^##[[:space:]]+Community and Open Core' "$README" || { echo "MISSING: Community and Open Core section"; fail=1; }
needf 'Apache-2.0' 'Apache-2.0 license statement'
grep -qiE '^##[[:space:]]+Air.?gap' "$README" || { echo "MISSING: air-gap section"; fail=1; }
if [ "$fail" -eq 0 ]; then echo "docs OK"; else exit 1; fi
