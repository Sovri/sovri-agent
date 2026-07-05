// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — `sovri-agent scan` prints one line per control result, ordered by
//! control id then rule id. Covers issues #58-#62.

mod scan_support;

use scan_support::{
    canonical_host, catalog, catalog_with_audit, catalog_with_empty_fw, control_ids, listing_line,
    listing_section, run, status_of, DOCKER_CONTROL, EMPTY_FRAMEWORK_ID, FRAMEWORK_ID, OS_CONTROL,
    ROOT_CONTROL, SSH_PASSWORD_CONTROL, SSH_ROOT_CONTROL,
};
use sovri_agent::scan::FailOn;
use sovri_sdk::{Selection, Status};

// #58 @nominal — the report lists every control result ordered by control id then rule id.
#[test]
fn the_report_lists_every_control_result_ordered_by_control_id_then_rule_id() {
    let catalog = catalog();
    let registry = canonical_host();
    let outcome = run(
        &catalog,
        &Selection::framework(FRAMEWORK_ID),
        &registry,
        FailOn::Fail,
    );
    let results = outcome.results();

    // The listing is exactly the five controls, in control-id order.
    assert_eq!(
        control_ids(results),
        vec![
            DOCKER_CONTROL,
            ROOT_CONTROL,
            OS_CONTROL,
            SSH_PASSWORD_CONTROL,
            SSH_ROOT_CONTROL,
        ],
    );
    assert_eq!(status_of(results, DOCKER_CONTROL), Status::Skipped);
    assert_eq!(status_of(results, ROOT_CONTROL), Status::Pass);
    assert_eq!(status_of(results, OS_CONTROL), Status::Fail);
    assert_eq!(status_of(results, SSH_PASSWORD_CONTROL), Status::Warning);
    assert_eq!(status_of(results, SSH_ROOT_CONTROL), Status::Fail);

    // Each line shows the control id, rule id, status, and a reason.
    let report = outcome.report();
    for result in results {
        let line = listing_line(report, result.control_id())
            .unwrap_or_else(|| panic!("a listing line for {}", result.control_id()));
        assert!(line.contains(result.rule_id()), "line shows the rule id");
        assert!(
            line.contains(result.status().label()),
            "line shows the status",
        );
        let reason = result
            .reason()
            .unwrap_or_else(|| result.status().description());
        assert!(line.contains(reason), "line shows a reason");
    }

    // Lines that carry evidence show their references; the FAIL ssh line cites the
    // SSH effective-configuration evidence.
    let ssh_line = listing_line(report, SSH_ROOT_CONTROL).expect("the ssh line");
    assert!(
        ssh_line.contains("host.ssh.effective-config"),
        "the FAIL ssh line shows its evidence reference",
    );

    // A line with no evidence references still renders: the SKIPPED docker line.
    let docker_line = listing_line(report, DOCKER_CONTROL).expect("the docker line");
    assert!(docker_line.contains(Status::Skipped.label()));
    assert!(
        !docker_line.contains('['),
        "the SKIPPED docker line has no evidence bracket",
    );
}

// #59 @violation — an unmet control renders with its FAIL status, reason and evidence.
#[test]
fn an_unmet_control_is_rendered_with_its_fail_status_reason_and_evidence() {
    let catalog = catalog();
    let registry = canonical_host();
    let outcome = run(
        &catalog,
        &Selection::controls([SSH_ROOT_CONTROL]),
        &registry,
        FailOn::Fail,
    );

    assert_eq!(status_of(outcome.results(), SSH_ROOT_CONTROL), Status::Fail);
    let line = listing_line(outcome.report(), SSH_ROOT_CONTROL).expect("the ssh root line");
    assert!(line.contains(SSH_ROOT_CONTROL));
    assert!(line.contains("host.ssh.permit-root-login"));
    assert!(line.contains(Status::Fail.label()));

    let result = &outcome.results()[0];
    let reason = result.reason().expect("a FAIL result carries a reason");
    assert!(!reason.trim().is_empty(), "the reason is non-empty");
    assert!(line.contains(reason), "the line renders the reason");
    assert!(
        line.contains("host.ssh.effective-config"),
        "the line cites the SSH effective-configuration evidence",
    );
}

// #60 @technical — a selected rule with no registered scanner renders as ERROR, not omitted.
#[test]
fn a_selected_rule_with_no_registered_scanner_is_rendered_as_error_not_omitted() {
    let catalog = catalog_with_audit();
    let registry = canonical_host(); // no scanner registered for host.audit.enabled
    let outcome = run(
        &catalog,
        &Selection::controls(["host.audit.trail"]),
        &registry,
        FailOn::Fail,
    );

    assert_eq!(
        outcome.results().len(),
        1,
        "the rule is executed, not omitted"
    );
    assert_eq!(
        status_of(outcome.results(), "host.audit.trail"),
        Status::Error
    );

    let line = listing_line(outcome.report(), "host.audit.trail").expect("the audit line");
    assert!(line.contains("host.audit.enabled"));
    assert!(line.contains(Status::Error.label()));
    assert!(
        line.to_ascii_lowercase().contains("execution failed"),
        "the line states that execution failed",
    );
    assert!(
        !line.contains('['),
        "the ERROR line shows no evidence references",
    );
}

// #61 @limit — selecting a single control prints only that control's rule line.
#[test]
fn selecting_a_single_control_prints_only_that_controls_rule_line() {
    let catalog = catalog();
    let registry = canonical_host();
    let outcome = run(
        &catalog,
        &Selection::controls([ROOT_CONTROL]),
        &registry,
        FailOn::Fail,
    );

    assert_eq!(control_ids(outcome.results()), vec![ROOT_CONTROL]);
    assert_eq!(status_of(outcome.results(), ROOT_CONTROL), Status::Pass);
    let line = listing_line(outcome.report(), ROOT_CONTROL).expect("the root line");
    assert!(line.contains("host.account.single-root"));
    assert!(line.contains(Status::Pass.label()));
}

// #62 @limit — a known framework that maps no controls prints an empty listing and exits 0.
#[test]
fn a_known_framework_that_maps_no_controls_prints_an_empty_listing_and_exits_0() {
    let catalog = catalog_with_empty_fw();
    let registry = canonical_host();
    let outcome = run(
        &catalog,
        &Selection::framework(EMPTY_FRAMEWORK_ID),
        &registry,
        FailOn::Fail,
    );

    assert!(outcome.results().is_empty(), "no control result is listed");
    assert!(
        listing_section(outcome.report()).contains("No controls were executed"),
        "the report states that no controls were executed",
    );
    assert_eq!(outcome.exit_code(), 0);
}
