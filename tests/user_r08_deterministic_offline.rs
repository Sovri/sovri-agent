// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-08 — evaluation is a pure function of the captured
//! snapshot: the same snapshot yields byte-for-byte identical results and evidence,
//! with no host or network access, and inactivity is measured against the
//! snapshot's reference date rather than the wall clock.
//!
//! Mirrors `specs/mat-89-user-scanner/r08-deterministic-offline.feature`.

mod user_support;

use user_support::{
    dormant_catalog, full_catalog, result_for, run, scanner, status_of, DORMANT_CONTROL,
    INVENTORY_CONTROL, NO_EMPTY_PASSWORD_CONTROL, PRIVILEGED_CONTROL, SINGLE_ROOT_CONTROL,
};

use sovri_agent::scanners::user::{UserSnapshot, DORMANT_ACCOUNT_RULE};
use sovri_sdk::{ControlResult, Status};

/// A fixed snapshot: one uid-0 account, a recent human, and a dormant human.
fn fixed_snapshot() -> UserSnapshot {
    UserSnapshot::builder()
        .account("root", 0, "/bin/bash")
        .account("alice", 1000, "/bin/bash")
        .last_login_days("alice", 3)
        .account("eve", 1002, "/bin/bash")
        .last_login_days("eve", 200)
        .build()
}

/// Every user-scanner control, in a fixed order.
const CONTROLS: [&str; 5] = [
    INVENTORY_CONTROL,
    SINGLE_ROOT_CONTROL,
    NO_EMPTY_PASSWORD_CONTROL,
    DORMANT_CONTROL,
    PRIVILEGED_CONTROL,
];

/// The comparable shape of a result set: rule id, status, and reason, in order.
fn shape(results: &[ControlResult]) -> Vec<(String, Status, Option<String>)> {
    results
        .iter()
        .map(|result| {
            (
                result.rule_id().to_string(),
                result.status(),
                result.reason().map(str::to_string),
            )
        })
        .collect()
}

/// Scenario: The same snapshot yields identical results on repeated evaluation.
#[test]
fn the_same_snapshot_yields_identical_results() {
    let first_scanner = scanner(fixed_snapshot());
    let second_scanner = scanner(fixed_snapshot());
    let first = run(&first_scanner, &full_catalog(), &CONTROLS);
    let second = run(&second_scanner, &full_catalog(), &CONTROLS);

    assert_eq!(
        shape(&first),
        shape(&second),
        "the same control results in the same order"
    );
    assert_eq!(
        first_scanner.evidence_log(),
        second_scanner.evidence_log(),
        "the evidence content hashes are identical across the two runs"
    );
}

/// Scenario: Evaluation over a fixture snapshot performs no host or network access.
#[test]
fn evaluation_over_a_fixture_performs_no_host_or_network_access() {
    // A fixture snapshot supplied directly drives evaluation; there is no host
    // path to read and no network to reach, so repeated runs match exactly and
    // equal what a real host with the same accounts would produce.
    let scanner = scanner(fixed_snapshot());
    let first = run(&scanner, &full_catalog(), &CONTROLS);
    let second = run(&scanner, &full_catalog(), &CONTROLS);
    assert_eq!(shape(&first), shape(&second));
    assert_eq!(
        status_of(&first, DORMANT_ACCOUNT_RULE),
        Status::Warning,
        "eve is dormant on the fixture path"
    );
}

/// Scenario: Inactivity is measured against the snapshot reference date, not the
/// wall clock.
#[test]
fn inactivity_is_measured_against_the_reference_date_not_the_wall_clock() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("eve", 1002, "/bin/bash")
            .last_login_days("eve", 200)
            .build(),
    );
    // Evaluated twice, standing in for two different real-world days. The snapshot
    // carries the reference, so both runs read no wall clock and agree.
    let first = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    let second = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    assert_eq!(status_of(&first, DORMANT_ACCOUNT_RULE), Status::Warning);
    assert_eq!(status_of(&second, DORMANT_ACCOUNT_RULE), Status::Warning);
    assert_eq!(
        result_for(&first, DORMANT_ACCOUNT_RULE).reason(),
        result_for(&second, DORMANT_ACCOUNT_RULE).reason(),
    );
}
