// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-06 — evaluation is a pure function of the captured
//! snapshot: the same snapshot yields byte-for-byte identical results and
//! evidence across runs, and an injected snapshot drives the outcome rather than
//! the real host.
//!
//! Mirrors `specs/mat-88-system-scanner/r06-deterministic-offline.feature`.

mod system_support;

use system_support::{
    full_catalog, healthy_snapshot, policy, run, scanner, status_of, OS_SUPPORT_CONTROL,
    PACKAGES_CONTROL, SERVICES_CONTROL,
};

use sovri_agent::scanners::system::{Manager, SystemScanner, SystemSnapshot, OS_EOL_RULE};
use sovri_sdk::Status;

const CONTROLS: [&str; 3] = [OS_SUPPORT_CONTROL, PACKAGES_CONTROL, SERVICES_CONTROL];

/// Scenario: The same snapshot yields identical results on repeated evaluation.
#[test]
fn the_same_snapshot_yields_identical_results_and_evidence() {
    let first_scan = scanner(healthy_snapshot(
        Some("web-01"),
        Some("web-01.corp.example"),
    ));
    let second_scan = scanner(healthy_snapshot(
        Some("web-01"),
        Some("web-01.corp.example"),
    ));

    let first = run(&first_scan, &full_catalog(), &CONTROLS);
    let second = run(&second_scan, &full_catalog(), &CONTROLS);

    assert_eq!(
        first, second,
        "both runs produce the same results in the same order"
    );

    // Compare the full evidence records — excerpt, size, locator, and hash — not
    // just the placeholder content hash, so the check is sensitive to the payload.
    let first_log = first_scan.evidence_log();
    let second_log = second_scan.evidence_log();
    assert_eq!(
        first_log.records(),
        second_log.records(),
        "the evidence records are byte-for-byte identical across the two runs"
    );
}

/// Scenario: Evaluation over a fixture snapshot performs no host or network
/// access — the injected snapshot alone drives the results.
#[test]
fn evaluation_reads_only_the_injected_snapshot() {
    // A supported-OS fixture passes; an end-of-support fixture fails. Same binary,
    // same host, different injected snapshots yield different results, so
    // evaluation consulted the snapshot rather than the real host.
    let supported = SystemScanner::new(
        SystemSnapshot::builder()
            .os_release("ID=ubuntu\nVERSION_ID=\"24.04\"\n")
            .package_manager(Manager::Dpkg)
            .inventory("nginx\t1.24.0-2")
            .build(),
        policy(),
    );
    let end_of_support = SystemScanner::new(
        SystemSnapshot::builder()
            .os_release("ID=ubuntu\nVERSION_ID=\"18.04\"\n")
            .package_manager(Manager::Dpkg)
            .inventory("nginx\t1.24.0-2")
            .build(),
        policy(),
    );

    assert_eq!(
        status_of(&run(&supported, &full_catalog(), &CONTROLS), OS_EOL_RULE),
        Status::Pass
    );
    assert_eq!(
        status_of(
            &run(&end_of_support, &full_catalog(), &CONTROLS),
            OS_EOL_RULE
        ),
        Status::Fail
    );
}
