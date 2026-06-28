# Branch protection — `main`

`main` is the protected trunk. Recommended GitHub settings (they back the CI
gates and follow ADR-012 reciprocity between local hooks and CI):

- Require a pull request before merging; require at least 1 approval; require
  review from Code Owners (`.github/CODEOWNERS`).
- Require status checks to pass before merging, and require branches to be up to
  date:
  - `rust-checks` (fmt, clippy, build, test)
  - `supply-chain` (cargo-deny)
  - `secrets-scan`
  - `license-headers`
  - `docs-check`
  - `action-pins`
  - `Dependency Review`
- Require conversation resolution before merging.
- Block force pushes and branch deletion.
- Include administrators.

These mirror `.github/workflows/ci.yml`; a green local commit predicts a green
CI run.
