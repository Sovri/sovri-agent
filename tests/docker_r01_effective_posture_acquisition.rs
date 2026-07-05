// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-01 — the scan captures the daemon posture from two offline
//! sources: `docker info` / `docker version` (Command evidence) and
//! `/etc/docker/daemon.json` (Config evidence, anchored on the file). A missing
//! `daemon.json` falls back to the effective flags; a malformed one warns without
//! panicking; and a signal recoverable only from the unparsable file errors rather
//! than passing.
//!
//! Mirrors `specs/mat-91-docker-scanner/r01-effective-posture-acquisition.feature`.

mod docker_support;

use docker_support::{
    reachable_json, registries_catalog, result_for, run, scanner, REGISTRIES_CONTROL,
};

use sovri_agent::scanners::docker::{
    DockerSnapshot, DAEMON_JSON_EVIDENCE_ID, DAEMON_JSON_LOCATOR, EFFECTIVE_INFO_EVIDENCE_ID,
    INSECURE_REGISTRIES_RULE,
};
use sovri_sdk::{EvidenceKind, Status};

/// Scenario: Both sources are read and attached as evidence.
#[test]
fn both_sources_are_read_and_attached_as_evidence() {
    let scanner = reachable_json(r#"{"insecure-registries": ["registry.internal:5000"]}"#);
    let log = scanner.evidence_log();

    let command = log
        .resolve(EFFECTIVE_INFO_EVIDENCE_ID)
        .expect("a Command evidence record");
    assert_eq!(command.kind(), EvidenceKind::Command);

    let config = log
        .resolve(DAEMON_JSON_EVIDENCE_ID)
        .expect("a Config evidence record");
    assert_eq!(config.kind(), EvidenceKind::Config);
    assert_eq!(
        config.locator(),
        DAEMON_JSON_LOCATOR,
        "the Config evidence is anchored on the daemon.json file"
    );
    assert!(
        config
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("registry.internal:5000")),
        "the Config evidence carries the daemon.json settings"
    );
}

/// Scenario: A missing daemon.json falls back to the effective flags.
#[test]
fn a_missing_daemon_json_falls_back_to_the_effective_flags() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .server_version("27.3.1")
            .build(),
    );
    let log = scanner.evidence_log();

    assert!(
        scanner.acquisition_caveat().is_none(),
        "an absent daemon.json is not a caveat"
    );
    let command = log
        .resolve(EFFECTIVE_INFO_EVIDENCE_ID)
        .expect("a Command evidence record from the effective flags");
    assert_eq!(command.kind(), EvidenceKind::Command);
    assert!(
        log.resolve(DAEMON_JSON_EVIDENCE_ID).is_none(),
        "no Config evidence when daemon.json is absent"
    );
}

/// Scenario: A malformed daemon.json warns and never panics.
#[test]
fn a_malformed_daemon_json_warns_and_never_panics() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .daemon_json("{ insecure-registries: ")
            .build(),
    );

    let caveat = scanner
        .acquisition_caveat()
        .expect("a warning caveat about the unparsable daemon.json");
    assert!(
        caveat.contains("daemon.json") && caveat.contains("not valid JSON"),
        "the caveat names the unparsable daemon.json: {caveat}"
    );
    // The effective flags are still usable: a Command record is present and evaluation
    // does not panic.
    assert!(
        scanner
            .evidence_log()
            .resolve(EFFECTIVE_INFO_EVIDENCE_ID)
            .is_some(),
        "the docker info effective flags are still used"
    );
    let results = run(&scanner, &registries_catalog(), &[REGISTRIES_CONTROL]);
    assert_eq!(
        result_for(&results, INSECURE_REGISTRIES_RULE).status(),
        Status::Pass,
        "with no insecure registry in the effective flags the control passes without panicking"
    );
}

/// Scenario: With the daemon reachable, a signal available only from the unparsable
/// file errors, never passes.
#[test]
fn a_signal_only_in_the_unparsable_file_errors_never_passes() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .daemon_json("{ insecure-registries: ")
            .config_unconfirmable()
            .build(),
    );
    let results = run(&scanner, &registries_catalog(), &[REGISTRIES_CONTROL]);
    let result = result_for(&results, INSECURE_REGISTRIES_RULE);

    assert_eq!(result.status(), Status::Error);
    assert_ne!(result.status(), Status::Pass);
}

/// Scenario: A daemon.json carrying a malformed JSON number is rejected as unparsable,
/// not accepted as valid. A lax number scanner that swallowed `1e` would mark the file
/// present and skip the R-01 caveat, so the tightened parser is what keeps a malformed
/// file on the caveat path.
#[test]
fn a_daemon_json_with_a_malformed_number_is_treated_as_malformed() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .daemon_json(r#"{"max-concurrent-downloads": 1e}"#)
            .build(),
    );

    assert!(
        scanner.acquisition_caveat().is_some(),
        "an invalid JSON number makes daemon.json malformed and carries the caveat"
    );
    assert!(
        scanner
            .evidence_log()
            .resolve(DAEMON_JSON_EVIDENCE_ID)
            .is_none(),
        "a malformed daemon.json yields no Config evidence"
    );
}
