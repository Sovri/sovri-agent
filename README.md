# sovri-agent

The Sovri compliance agent — a Rust crate for air-gapped compliance rule
execution. It runs the `sovri-sdk` rule engine locally, with no network and no
secrets.

## Status

v0.6.0 — the V0.6 reporting track on the `sovri-sdk` engine (`bin + lib`).
The agent scans Linux host posture offline, persists evidence, and exports the
persisted compliance corpus as deterministic PDF reports, SpreadsheetML
workbooks, and offline-verifiable signed JSON. Host scanners — system, user, SSH,
and Docker — capture the host's effective posture offline and grade it through
the SDK engine, reporting an absent subsystem as `SKIPPED` rather than a false
pass. The binary keeps the offline `selftest` command.

```sh
cargo run -- selftest
# sovri-agent 0.6.0: selftest ok (offline, no external services)
cargo run -- --version
# sovri-agent 0.6.0 (sovri-sdk 0.3.0)
```

## Library

The `sovri_agent` library wires the agent to the SDK engine:

- `scanners` — a `Scanner` trait that splits host acquisition from pure
  evaluation, and a rule-id `Registry` that dispatches each rule to its scanner
  behind a `sovri_sdk::RuleEvaluator`.
- `controls` — the self-contained selftest control proving the engine seam via
  `sovri_sdk::Engine::execute`.
- `evidence` — a relay re-exporting the SDK evidence contract.
- `report` — deterministic PDF compliance reporting from a persisted corpus.
- `matrix` — SpreadsheetML compliance matrix export.
- `signed_json` — canonical signed JSON export and offline verification.
- `sdk_version()` — the linked SDK contract version.

## Development

This crate builds, tests, and lints with the standard Rust toolchain. Runtime
dependencies are limited to the first-party `sovri-sdk`, pinned by git revision,
and `ed25519-dalek` for signed JSON. PDF and SpreadsheetML export remain
hand-emitted with no third-party runtime dependency, and no secrets are required.
CI fetches the SDK from its pinned revision. To co-develop against a sibling
`sovri-sdk-rust` checkout, copy
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
