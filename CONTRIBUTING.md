# Contributing

Thanks for contributing to Sovri Community (Apache-2.0).

## Local setup

No secrets or network access are required to build or test.

```sh
cargo build
cargo test
cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

Install the local Git hooks (they mirror CI, per ADR-012):

```sh
lefthook install
```

## Gates

Every pull request must pass the CI gates in `.github/workflows/`: format,
lint, test, build, `cargo-deny`, secrets scan, license headers, docs, action-pin
check, and dependency review. Do not bypass hooks (`--no-verify` is forbidden).

## Branch protection

See `docs/branch-protection.md` for the `main` protection settings these gates
back.
