# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Agent crate bootstrap (MAT-122): the crate is now `bin + lib` on the pinned
  first-party `sovri-sdk` engine. Adds a `Scanner` trait with a host-acquisition
  / pure-evaluation split, a rule-id `Registry` that dispatches each rule to its
  scanner behind a `RuleEvaluator`, a self-contained selftest control that proves
  the engine seam through `Engine::execute`, an SDK contract-version relay, and an
  evidence relay re-exporting the SDK evidence contract. No third-party runtime
  dependencies.
- Initial agent scaffold: offline `selftest` placeholder command (no network, no
  env, no secrets), Apache-2.0 licensing and headers, SHA-pinned CI gates
  (fmt, clippy, test, build, cargo-deny, secrets, headers, docs, action-pins,
  dependency review), and Community/Open Core + air-gap docs. Scaffolds MAT-81.
