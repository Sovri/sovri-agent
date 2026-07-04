// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-02 — OS support status is read from os-release and
//! evaluated against the catalogue policy: supported PASSes, end-of-support FAILs
//! with a technical reason and Config evidence, an unknown version WARNs, and a
//! version that cannot be extracted is an ERROR.
//!
//! Mirrors `specs/mat-88-system-scanner/r02-os-support.feature`.

mod system_support;

use system_support::{
    asserts_legal_conclusion, os_support_catalog, policy, result_for, run, status_of,
    OS_SUPPORT_CONTROL,
};

use sovri_agent::scanners::system::{
    SystemScanner, SystemSnapshot, OS_EOL_RULE, OS_RELEASE_LOCATOR, OS_SUPPORT_UNDETERMINED_RULE,
};
use sovri_sdk::{ControlResult, EvidenceKind, Status};

/// A scanner whose only acquired fact is the given os-release content.
fn os_scanner(raw: &str) -> SystemScanner {
    SystemScanner::new(SystemSnapshot::builder().os_release(raw).build(), policy())
}

/// A scanner whose os-release file could not be read.
fn unreadable_os_scanner() -> SystemScanner {
    SystemScanner::new(
        SystemSnapshot::builder().os_release_unreadable().build(),
        policy(),
    )
}

fn run_os(scanner: &SystemScanner) -> Vec<ControlResult> {
    run(scanner, &os_support_catalog(), &[OS_SUPPORT_CONTROL])
}

/// Scenario Outline: A supported OS version passes, carrying Config evidence.
#[test]
fn a_supported_os_version_passes_with_config_evidence() {
    let cases = [
        "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
        "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
    ];
    for raw in cases {
        let scanner = os_scanner(raw);
        let results = run_os(&scanner);
        let result = result_for(&results, OS_EOL_RULE);

        assert_eq!(result.status(), Status::Pass, "supported OS for {raw:?}");

        let log = scanner.evidence_log();
        let ref_id = result
            .evidence_refs()
            .first()
            .expect("the PASS carries an os-release evidence ref");
        let evidence = log.resolve(ref_id).expect("evidence resolves");
        assert_eq!(evidence.kind(), EvidenceKind::Config);
        assert_eq!(evidence.locator(), OS_RELEASE_LOCATOR);
    }
}

/// Scenario Outline: An end-of-support OS version fails with a technical reason.
#[test]
fn an_end_of_support_os_version_fails_with_a_technical_reason() {
    let cases = [
        "ID=ubuntu\nVERSION_ID=\"18.04\"\nPRETTY_NAME=\"Ubuntu 18.04.6 LTS\"\n",
        "ID=debian\nVERSION_ID=\"10\"\nPRETTY_NAME=\"Debian GNU/Linux 10 (buster)\"\n",
    ];
    for raw in cases {
        let scanner = os_scanner(raw);
        let results = run_os(&scanner);
        let result = result_for(&results, OS_EOL_RULE);

        assert_eq!(result.status(), Status::Fail, "EOL OS for {raw:?}");

        let log = scanner.evidence_log();
        let ref_id = result
            .evidence_refs()
            .first()
            .expect("the FAIL carries an os-release evidence ref");
        let evidence = log.resolve(ref_id).expect("evidence resolves");
        assert_eq!(evidence.kind(), EvidenceKind::Config);
        assert_eq!(evidence.locator(), OS_RELEASE_LOCATOR);

        let reason = result.reason().expect("a FAIL carries a reason");
        assert!(
            reason.to_lowercase().contains("out of support"),
            "the reason states the OS is out of support: {reason}"
        );
        assert!(
            reason.to_lowercase().contains("security"),
            "the reason notes missing security updates: {reason}"
        );
        assert!(
            !asserts_legal_conclusion(reason),
            "the reason asserts no legal conclusion: {reason}"
        );
    }
}

/// Scenario: A version absent from the support policy cannot be determined.
#[test]
fn a_version_absent_from_the_policy_warns_as_undetermined() {
    let scanner = os_scanner("ID=ubuntu\nVERSION_ID=\"30.10\"\nPRETTY_NAME=\"Ubuntu 30.10\"\n");
    let results = run_os(&scanner);

    let result = result_for(&results, OS_SUPPORT_UNDETERMINED_RULE);
    assert_eq!(result.status(), Status::Warning);

    let reason = result.reason().expect("a WARNING carries a reason");
    assert!(
        reason.to_lowercase().contains("could not be determined")
            || reason.to_lowercase().contains("support status"),
        "the reason notes support could not be determined: {reason}"
    );
    assert!(!asserts_legal_conclusion(reason));
}

/// Scenario: A malformed os-release that yields no version is an error.
#[test]
fn a_malformed_os_release_with_no_version_is_an_error() {
    let scanner = os_scanner("ID=ubuntu\nPRETTY_NAME=\"Ubuntu\"\n");
    let results = run_os(&scanner);

    // Both os-support rules can only ERROR: no version could be extracted.
    assert_eq!(status_of(&results, OS_EOL_RULE), Status::Error);
    assert_eq!(
        status_of(&results, OS_SUPPORT_UNDETERMINED_RULE),
        Status::Error
    );
    let reason = result_for(&results, OS_EOL_RULE)
        .reason()
        .expect("an ERROR carries a reason");
    assert!(!asserts_legal_conclusion(reason), "no conclusion is drawn");
}

/// Scenario: An unreadable os-release yields an execution error.
#[test]
fn an_unreadable_os_release_yields_an_error() {
    let scanner = unreadable_os_scanner();
    let results = run_os(&scanner);

    assert_eq!(status_of(&results, OS_EOL_RULE), Status::Error);
    let reason = result_for(&results, OS_EOL_RULE)
        .reason()
        .expect("an ERROR carries a reason");
    assert!(
        reason.to_lowercase().contains("os-release"),
        "the reason names the unreadable os-release: {reason}"
    );
    assert!(!asserts_legal_conclusion(reason), "no conclusion is drawn");
}
