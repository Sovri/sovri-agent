// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-02 — the daemon version is graded against a catalogue
//! baseline: below minimum-supported is end-of-life and FAILs (`daemon-version-eol`),
//! at or above minimum-supported but below minimum-recommended is obsolete and WARNs
//! (`daemon-version-obsolete`), and a current version PASSes. The verdict comes from
//! the catalogue, never the wall clock, and the effective version is quoted in
//! Command evidence.
//!
//! Mirrors `specs/mat-91-docker-scanner/r02-daemon-version.feature`.

mod docker_support;

use docker_support::{
    asserts_legal_conclusion, reachable_version, result_for, run, version_status,
    DAEMON_VERSION_CONTROL,
};

use sovri_agent::scanners::docker::{DAEMON_VERSION_EOL_RULE, DAEMON_VERSION_OBSOLETE_RULE};
use sovri_sdk::{EvidenceKind, Status};

/// Scenario: A current version passes, quoting the effective version.
#[test]
fn a_current_version_passes_quoting_the_effective_version() {
    let scanner = reachable_version("27.3.1");
    let (ids, catalog) = version_catalog_ids();
    let results = run(&scanner, &catalog, &ids);
    assert_eq!(version_status(&results), Status::Pass);

    let result = result_for(&results, DAEMON_VERSION_EOL_RULE);
    let log = scanner.evidence_log();
    let ref_id = result
        .evidence_refs()
        .first()
        .expect("the PASS carries a Command evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("27.3.1")),
        "a Command evidence quotes the effective 27.3.1 version"
    );
}

/// Scenario: An end-of-life version fails, naming the EOL rule and quoting the value.
#[test]
fn an_end_of_life_version_fails() {
    let scanner = reachable_version("19.03.15");
    let (ids, catalog) = version_catalog_ids();
    let results = run(&scanner, &catalog, &ids);

    assert_eq!(version_status(&results), Status::Fail);
    let result = result_for(&results, DAEMON_VERSION_EOL_RULE);
    assert_eq!(
        result.status(),
        Status::Fail,
        "the eol rule is the one that fails"
    );
    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(
        reason.contains("19.03.15"),
        "the reason quotes the effective version: {reason}"
    );
    assert!(
        !asserts_legal_conclusion(reason),
        "the reason asserts no legal conclusion: {reason}"
    );
}

/// Scenario: An obsolete but still supported version warns via the obsolete rule.
#[test]
fn an_obsolete_but_supported_version_warns() {
    let scanner = reachable_version("25.0.5");
    let (ids, catalog) = version_catalog_ids();
    let results = run(&scanner, &catalog, &ids);

    assert_eq!(version_status(&results), Status::Warning);
    assert_eq!(
        result_for(&results, DAEMON_VERSION_OBSOLETE_RULE).status(),
        Status::Warning,
        "the obsolete rule is the one that warns"
    );
    assert_eq!(
        result_for(&results, DAEMON_VERSION_EOL_RULE).status(),
        Status::Pass,
        "a supported version does not trip the eol rule"
    );
}

/// Scenario Outline: The version tiers are decided at the catalogue boundaries.
#[test]
fn the_version_tiers_are_decided_at_the_catalogue_boundaries() {
    for (version, expected) in [
        ("27.0.0", Status::Pass),
        ("26.1.4", Status::Warning),
        ("24.0.0", Status::Warning),
        ("23.0.6", Status::Fail),
    ] {
        let scanner = reachable_version(version);
        let (ids, catalog) = version_catalog_ids();
        let results = run(&scanner, &catalog, &ids);
        assert_eq!(version_status(&results), expected, "version {version}");
    }
}

/// Scenario: The verdict does not depend on the wall clock — two evaluations of the
/// same version yield identical WARNING results and identical Command evidence.
#[test]
fn the_verdict_does_not_depend_on_the_wall_clock() {
    let first = reachable_version("25.0.5");
    let second = reachable_version("25.0.5");
    let (ids, catalog) = version_catalog_ids();

    let first_results = run(&first, &catalog, &ids);
    let second_results = run(&second, &catalog, &ids);

    assert_eq!(version_status(&first_results), Status::Warning);
    assert_eq!(version_status(&second_results), Status::Warning);
    assert_eq!(
        first_results, second_results,
        "the same version and baseline always yield the same result"
    );
    assert_eq!(
        first.evidence_log().records(),
        second.evidence_log().records(),
        "both results carry identical Command evidence"
    );
}

/// The daemon-version control ids and catalog, paired so each scenario runs the whole
/// two-rule control.
fn version_catalog_ids() -> ([&'static str; 1], sovri_sdk::Catalog) {
    ([DAEMON_VERSION_CONTROL], docker_support::version_catalog())
}
