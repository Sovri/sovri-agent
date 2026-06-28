# sovri-agent

The Sovri compliance agent — Rust workspace for rule execution and local,
air-gapped operation. Placeholder scaffold from MAT-81; real rule execution
lands with MAT-85.

## Status

Foundational scaffold. The agent exposes a `selftest` placeholder command that
proves air-gapped operation: it runs with no network, no environment
configuration, and no secrets.

```sh
cargo run -- selftest
# sovri-agent 0.0.0: selftest ok (offline, no external services)
```

## Development

This crate builds, tests, and lints with the standard Rust toolchain. No network
access and no secrets are required; the crate has zero external dependencies, so
a fresh clone builds offline.

- Build: `cargo build`
- Test: `cargo test`
- Lint: `cargo fmt --check && cargo clippy --all-targets -- -D warnings`

The same gates run in CI (`.github/workflows/ci.yml`) on every pull request.
Local Git hooks mirroring them are declared in `lefthook.yml`.

## Community and Open Core

Sovri follows an open-core model: an Apache-2.0 Community edition plus a
proprietary managed Cloud edition.

- This repository is **Community**, licensed under **Apache-2.0** (see
  `LICENSE`). Every source file carries an `SPDX-License-Identifier: Apache-2.0`
  header.
- Proprietary Cloud code lives in separate private repositories and never ships
  here. Cloud may depend on the agent's public contracts; this repository never
  depends on Cloud.

## Air-gap and offline execution

The agent is built to run in regulated, frequently air-gapped environments.

- `sovri-agent selftest` exits 0 with no network connectivity, makes no outbound
  connection, and needs no environment variables beyond the operating-system
  defaults.
- `cargo build` and `cargo test` succeed offline with no secrets configured.
- The agent reads framework text from versioned catalogs (`sovri-frameworks`),
  never from an external API at runtime.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
