// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-03 — a non-empty `insecure-registries` list FAILs; an empty
//! or absent list PASSes. The signal is read from the effective configuration —
//! `daemon.json` when present, the `docker info` effective flags otherwise — and the
//! offending list is quoted in evidence anchored on the daemon config file.
//!
//! Mirrors `specs/mat-91-docker-scanner/r03-insecure-registries.feature`.

mod docker_support;

use docker_support::{
    asserts_legal_conclusion, reachable_json, registries_catalog, result_for, run, scanner,
    REGISTRIES_CONTROL,
};

use sovri_agent::scanners::docker::{
    DockerSnapshot, DAEMON_JSON_LOCATOR, INSECURE_REGISTRIES_RULE,
};
use sovri_sdk::{EvidenceKind, Status, Target};

/// Scenario: No insecure registries passes.
#[test]
fn no_insecure_registries_passes() {
    let scanner = reachable_json(r#"{"insecure-registries": []}"#);
    let results = run(&scanner, &registries_catalog(), &[REGISTRIES_CONTROL]);
    assert_eq!(
        result_for(&results, INSECURE_REGISTRIES_RULE).status(),
        Status::Pass
    );
}

/// Scenario: A configured insecure registry fails, quoting it in anchored Config
/// evidence.
#[test]
fn a_configured_insecure_registry_fails() {
    let scanner = reachable_json(r#"{"insecure-registries": ["registry.internal:5000"]}"#);
    let results = run(&scanner, &registries_catalog(), &[REGISTRIES_CONTROL]);
    let result = result_for(&results, INSECURE_REGISTRIES_RULE);

    assert_eq!(result.status(), Status::Fail);
    assert!(
        result
            .targets()
            .iter()
            .any(|target| *target == Target::file(DAEMON_JSON_LOCATOR)),
        "the FAIL is anchored on the daemon.json file"
    );

    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Config);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("registry.internal:5000")),
        "a Config evidence quotes the offending registry"
    );

    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(
        !asserts_legal_conclusion(reason),
        "the reason asserts no legal conclusion: {reason}"
    );
}

/// Scenario: An insecure registry reported only by docker info still fails, quoted in
/// Command evidence.
#[test]
fn an_insecure_registry_reported_only_by_docker_info_still_fails() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .info_insecure_registries(["registry.internal:5000"])
            .build(),
    );
    let results = run(&scanner, &registries_catalog(), &[REGISTRIES_CONTROL]);
    let result = result_for(&results, INSECURE_REGISTRIES_RULE);

    assert_eq!(result.status(), Status::Fail);
    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("registry.internal:5000")),
        "a Command evidence quotes the offending registry"
    );
}

/// Scenario Outline: The empty-to-one boundary decides the verdict.
#[test]
fn the_empty_to_one_boundary_decides_the_verdict() {
    for (raw, expected) in [
        (r#"{"insecure-registries": []}"#, Status::Pass),
        (
            r#"{"insecure-registries": ["10.0.0.5:5000"]}"#,
            Status::Fail,
        ),
    ] {
        let scanner = reachable_json(raw);
        let results = run(&scanner, &registries_catalog(), &[REGISTRIES_CONTROL]);
        assert_eq!(
            result_for(&results, INSECURE_REGISTRIES_RULE).status(),
            expected,
            "config {raw}"
        );
    }
}
