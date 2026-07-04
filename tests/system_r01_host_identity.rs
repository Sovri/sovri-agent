// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-01 — the scanned host's identity (hostname, and FQDN
//! when it resolves) is carried on every control result as environment metadata.
//!
//! Mirrors `specs/mat-88-system-scanner/r01-host-identity.feature`.

mod system_support;

use system_support::{
    healthy_snapshot, policy, EXECUTED_AT, OS_SUPPORT_CONTROL, PACKAGES_CONTROL, SERVICES_CONTROL,
};

use sovri_agent::scanners::system::SystemScanner;
use sovri_sdk::{ControlResult, Engine, Selection, Status};

/// Evaluate the whole host with the given identity, carrying it as the engine's
/// execution metadata the way the agent would.
fn results_with_identity(hostname: Option<&str>, fqdn: Option<&str>) -> Vec<ControlResult> {
    let scanner = SystemScanner::new(healthy_snapshot(hostname, fqdn), policy());
    let engine = Engine::new(EXECUTED_AT, scanner.identity_metadata()).expect("valid timestamp");
    engine
        .execute(
            &system_support::full_catalog(),
            &Selection::controls([OS_SUPPORT_CONTROL, PACKAGES_CONTROL, SERVICES_CONTROL]),
            &scanner,
        )
        .expect("execution succeeds")
}

/// Scenario: Hostname and locally-resolved FQDN are carried on results.
#[test]
fn hostname_and_resolved_fqdn_are_carried_on_every_result() {
    let results = results_with_identity(Some("web-01"), Some("web-01.corp.example"));

    assert!(!results.is_empty(), "the scan produces results");
    for result in &results {
        assert!(
            result.execution_metadata().contains("web-01"),
            "every result carries the hostname identity: {:?}",
            result.execution_metadata()
        );
        assert!(
            result.execution_metadata().contains("web-01.corp.example"),
            "every result carries the FQDN identity: {:?}",
            result.execution_metadata()
        );
    }
}

/// Scenario: An unresolved FQDN leaves the hostname as the identity.
#[test]
fn an_unresolved_fqdn_leaves_the_hostname_as_the_identity() {
    let results = results_with_identity(Some("db-02"), None);

    assert!(!results.is_empty(), "the scan produces results");
    for result in &results {
        assert!(
            result.execution_metadata().contains("db-02"),
            "every result carries the hostname identity"
        );
        assert!(
            !result.execution_metadata().contains("fqdn="),
            "the FQDN identity is absent: {:?}",
            result.execution_metadata()
        );
        assert_ne!(
            result.status(),
            Status::Fail,
            "no result fails because the FQDN was unresolved"
        );
        assert_ne!(
            result.status(),
            Status::Error,
            "no result errors because the FQDN was unresolved"
        );
    }
}

/// Scenario: An unavailable hostname does not fail the scan.
#[test]
fn an_unavailable_hostname_does_not_fail_the_scan() {
    let results = results_with_identity(None, None);

    assert!(
        !results.is_empty(),
        "control results are still produced when the identity is unavailable"
    );
    for result in &results {
        assert!(
            !result.execution_metadata().contains("host="),
            "the hostname identity is absent: {:?}",
            result.execution_metadata()
        );
        assert!(
            !result.execution_metadata().contains("fqdn="),
            "the FQDN identity is absent"
        );
        assert_ne!(
            result.status(),
            Status::Fail,
            "no result fails because the identity was unavailable"
        );
        assert_ne!(
            result.status(),
            Status::Error,
            "no result errors because the identity was unavailable"
        );
    }
}
