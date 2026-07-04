# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- System scanner (MAT-88): the agent's first scanner. `SystemScanner` captures the
  Linux host's base posture — hostname/FQDN identity, OS support read from
  os-release, the installed-package inventory via the distro package manager, and
  running services — into a `SystemSnapshot`, then evaluates it through the engine
  as a `RuleEvaluator`. An end-of-support release FAILs and a version the policy
  does not know WARNs (a fail-policy and a warn-policy rule on the OS-support
  control); a present package manager PASSes carrying a bounded, hashed Command
  evidence while a missing one is an ERROR; an active service on the catalogue
  interdiction list WARNs; and the services rule is SKIPPED when no service
  manager is present. Acquisition
  reads the host offline; evaluation is a pure, deterministic function of the
  captured snapshot and asserts no legal conclusion. The pinned `sovri-sdk` now
  includes `Evaluation::not_applicable` (SKIPPED).
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
