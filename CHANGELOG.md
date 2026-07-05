# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.4.0] - 2026-07-05

### Added
- `scan` command (MAT-125): `sovri-agent scan` turns the four V0.4 scanners into a
  runnable command. It loads a `--catalog <dir>`, validates it, resolves a
  `--framework <id>` or `--control <id,...>` selection (exactly one; unknown ids
  and empty entries are usage errors, duplicates run once), builds the host
  registry from the docker, ssh, system, and user scanners under baseline policies,
  runs the selected controls on the SDK engine, and prints a listing — one line per
  result with its control id, rule id, status, reason, and evidence references —
  followed by the compliance gaps projected from the FAIL and WARNING results. The
  exit code reflects the posture: `0` when clean, `2` on a FAIL or execution error,
  `64` on a usage, catalog-load, or validation error, with `--fail-on
  fail|warning|never` tuning the threshold. The report carries no wall-clock value,
  so a fixed host state renders byte-identically across runs, and the command reads
  only the catalog directory and its flags — no network, no environment. Sourcing
  the real CIS baseline policies is deferred to MAT-124.
- Docker scanner (MAT-91): the agent's fourth and final V0.4 scanner.
  `DockerScanner` reads the host's effective Docker daemon posture offline —
  `docker version` / `docker info` for the engine version and effective flags, and
  `/etc/docker/daemon.json` for the persisted configuration — into a
  `DockerSnapshot`, then evaluates it through the SDK engine as a `RuleEvaluator`.
  The daemon version splits across two rules — an end-of-life release FAILs and a
  merely-obsolete one WARNs — alongside insecure-registry, TLS-less TCP socket, and
  daemon-hardening checks. A host with no daemon (absent, unreachable, or a
  permission-denied probe) is `not_applicable` → SKIPPED for every rule, never PASS
  and, by decision, never ERROR; it is the card that most visibly exercises the
  MAT-123 extension. A small hand-rolled JSON-subset reader parses `daemon.json`
  with no dependency, and a present-but-invalid file never panics. A secret on the
  daemon surface (a `log-opts` credential) is redacted and the config summary emits
  keys, not values, so a fixed host state renders byte-identically across runs.
  Standard-library only.
- SSH scanner (MAT-90): the agent's third scanner. `SshScanner` reads the host's
  effective `sshd` configuration — the resolved `sshd -T` dump with includes and
  defaults folded in, falling back to parsing `sshd_config` and its `sshd_config.d`
  drop-ins when `sshd -T` is unavailable — into an `SshSnapshot`, then evaluates it
  through the engine as a `RuleEvaluator`. `PermitRootLogin yes` FAILs while the
  non-password paths (`prohibit-password`, `forced-commands-only`, the
  `without-password` alias) WARN under the default catalogue and FAIL under a
  hardened one; `PasswordAuthentication yes` FAILs, catching an unconfigured host at
  the effective default; a legacy cipher, MAC, or key-exchange algorithm WARNs
  naming each, and an explicit `Protocol 1` FAILs as a guard-rail; a host with no
  SSH server is SKIPPED rather than a false PASS, while a present-but-unreadable
  server ERRORs. On the fallback path an unresolved `Include` carries a WARNING
  caveat — a directive still readable is graded, one that could hide inside the
  unreadable include ERRORs rather than pass. Every non-PASS result carries a
  Command evidence quoting the effective directive, anchored on the config file;
  evaluation is a pure, deterministic function of the captured dump and asserts no
  legal conclusion.
- User scanner (MAT-89): the agent's second scanner. `UserScanner` captures the
  host's account state — the `passwd` base, the `shadow` lock / password / expiry
  state, and `group` / `sudoers` privilege grants — into a `UserSnapshot`, then
  evaluates it through the engine as a `RuleEvaluator`. More than one uid-0 account
  FAILs and an unlocked login account with an empty `shadow` password field FAILs;
  an eligible account (login shell, not locked) that is dormant beyond the
  catalogue threshold, has never logged in, or is past its expiry WARNs; a
  privileged account (uid 0, sudo / wheel, sudoers grant) outside the expected set
  WARNs; and an unreadable `shadow` ERRORs the password rule rather than passing,
  while the uid-0 count sourced from `passwd` still evaluates. Account evidence is
  classified `Sensitive` and `shadow` evidence `Secret`; both drop the raw excerpt,
  so account identity travels as evidence keys and no password hash ever appears in
  any evidence or gap explanation. Acquisition reads the host offline; evaluation
  is a pure, deterministic function of the captured snapshot and asserts no legal
  conclusion.
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
