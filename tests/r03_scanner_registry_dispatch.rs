// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-03 — the `Scanner` registry dispatches rules to
//! scanners by id.
//!
//! Mirrors `specs/mat-122-agent-crate-bootstrap/r03-scanner-registry-dispatch.feature`.

use sovri_agent::controls::{
    selftest_catalog, ENGINE_WIRING_CONTROL, PRODUCES_RESULT_RULE, REPORTS_FINDING_RULE,
    UNWIRED_RULE,
};
use sovri_agent::scanners::selftest::{SelftestScanner, SelftestSnapshot};
use sovri_agent::scanners::Registry;
use sovri_sdk::{ControlResult, Engine, Selection, Status};

const EXECUTED_AT: &str = "2026-07-03T09:00:00Z";

// Background: three rules on one control; two mapped to their own scanner
// (satisfied vs finding, the latter with result policy "fail"), one unregistered.
fn run() -> Vec<ControlResult> {
    let catalog = selftest_catalog(&[PRODUCES_RESULT_RULE, REPORTS_FINDING_RULE, UNWIRED_RULE]);

    let mut registry = Registry::new();
    registry.register_with_snapshot(
        PRODUCES_RESULT_RULE,
        SelftestScanner,
        SelftestSnapshot::present(),
    );
    registry.register_with_snapshot(
        REPORTS_FINDING_RULE,
        SelftestScanner,
        SelftestSnapshot::absent(),
    );
    // "agent.selftest.unwired" is intentionally left unregistered.

    let engine = Engine::new(EXECUTED_AT, "sovri-agent selftest").expect("valid timestamp");
    engine
        .execute(
            &catalog,
            &Selection::controls([ENGINE_WIRING_CONTROL]),
            &registry,
        )
        .expect("execution succeeds")
}

fn status_for(results: &[ControlResult], rule_id: &str) -> Status {
    results
        .iter()
        .find(|r| r.rule_id() == rule_id)
        .unwrap_or_else(|| panic!("a result for rule {rule_id}"))
        .status()
}

/// Scenario Outline row: agent.selftest.produces-result -> PASS.
#[test]
fn dispatches_produces_result_to_its_scanner_yielding_pass() {
    assert_eq!(status_for(&run(), PRODUCES_RESULT_RULE), Status::Pass);
}

/// Scenario Outline row: agent.selftest.reports-finding -> FAIL.
#[test]
fn dispatches_reports_finding_to_its_scanner_yielding_fail() {
    assert_eq!(status_for(&run(), REPORTS_FINDING_RULE), Status::Fail);
}

/// Scenario: An unregistered rule becomes an ERROR result without aborting the run.
#[test]
fn an_unregistered_rule_becomes_an_error_result_without_aborting_the_run() {
    let results = run();

    // Then the result for rule "agent.selftest.unwired" has status "ERROR"
    let unwired = results
        .iter()
        .find(|r| r.rule_id() == UNWIRED_RULE)
        .expect("a result for the unwired rule");
    assert_eq!(unwired.status(), Status::Error);

    // And the ERROR result carries a reason naming the unregistered rule
    assert!(
        unwired.reason().unwrap_or_default().contains(UNWIRED_RULE),
        "reason should name the unregistered rule, got: {:?}",
        unwired.reason()
    );

    // And the result for rule "agent.selftest.produces-result" has status "PASS"
    // (the run continued past the error).
    assert_eq!(status_for(&results, PRODUCES_RESULT_RULE), Status::Pass);
}
