# sovri-agent

The Sovri compliance agent — a Rust crate for air-gapped compliance rule
execution. It runs the `sovri-sdk` rule engine locally, with no network and no
secrets.

## Status

Bootstrapped on the `sovri-sdk` engine (`bin + lib`). The library exposes the
seam the V0.4 Linux scanners plug into; the binary keeps the offline `selftest`
command. Real host scanners land in MAT-88…91.

```sh
cargo run -- selftest
# sovri-agent 0.0.0: selftest ok (offline, no external services)
cargo run -- --version
# sovri-agent 0.0.0 (sovri-sdk 0.1.0)
```

## Library

The `sovri_agent` library wires the agent to the SDK engine:

- `scanners` — a `Scanner` trait that splits host acquisition from pure
  evaluation, and a rule-id `Registry` that dispatches each rule to its scanner
  behind a `sovri_sdk::RuleEvaluator`.
- `controls` — the self-contained selftest control proving the engine seam via
  `sovri_sdk::Engine::execute`.
- `evidence` — a relay re-exporting the SDK evidence contract.
- `sdk_version()` — the linked SDK contract version.

## Development

This crate builds, tests, and lints with the standard Rust toolchain. Its only
dependency is the first-party `sovri-sdk`, pinned by git tag; there are no
third-party runtime crates and no secrets are required. CI fetches the SDK from
its pinned tag. To co-develop against a sibling `sovri-sdk-rust` checkout, copy
`.cargo/config.toml.example` to `.cargo/config.toml` and the build uses that path
instead.

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
- Once dependencies are fetched, `cargo build` and `cargo test` run offline with
  no secrets configured; the built agent makes no runtime network calls.
- The agent reads framework text from versioned catalogs (`sovri-frameworks`),
  never from an external API at runtime.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
