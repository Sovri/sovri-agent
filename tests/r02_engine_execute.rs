// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-02 — a minimal scanner produces a real `ControlResult`
//! through `Engine::execute`.
//!
//! Mirrors
//! `specs/mat-122-agent-crate-bootstrap/r02-engine-execute-produces-control-result.feature`.

use sovri_agent::controls::{selftest_catalog, ENGINE_WIRING_CONTROL, PRODUCES_RESULT_RULE};
use sovri_agent::scanners::selftest::SelftestScanner;
use sovri_agent::scanners::Registry;
use sovri_sdk::{Engine, ExecutionError, Selection, Status};

const EXECUTED_AT: &str = "2026-07-03T09:00:00Z";

fn engine() -> Engine {
    Engine::new(EXECUTED_AT, "sovri-agent selftest").expect("timestamp is timezone-qualified")
}

// Background: the rule is served by a scanner that reports the control satisfied.
// This uses the live host-acquire path (`register`): `SelftestScanner::acquire`
// reads `current_exe`, which always resolves for the running test binary, so it
// deterministically reports satisfied. R-04 covers the acquisition/eval split.
fn satisfying_registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(PRODUCES_RESULT_RULE, SelftestScanner);
    registry
}

/// Scenario: Executing the selftest control yields a PASS result for its rule.
#[test]
fn executing_the_selftest_control_yields_a_pass_result_for_its_rule() {
    let catalog = selftest_catalog(&[PRODUCES_RESULT_RULE]);

    // When the engine executes the selection of controls ["agent.selftest.engine-wiring"]
    let results = engine()
        .execute(
            &catalog,
            &Selection::controls([ENGINE_WIRING_CONTROL]),
            &satisfying_registry(),
        )
        .expect("execution succeeds");

    // Then the run returns exactly one result for rule "agent.selftest.produces-result"
    let for_rule: Vec<_> = results
        .iter()
        .filter(|r| r.rule_id() == PRODUCES_RESULT_RULE)
        .collect();
    assert_eq!(for_rule.len(), 1);

    // And that result has control "agent.selftest.engine-wiring" and status "PASS"
    let result = for_rule[0];
    assert_eq!(result.control_id(), ENGINE_WIRING_CONTROL);
    assert_eq!(result.status(), Status::Pass);

    // And that result carries the execution timestamp "2026-07-03T09:00:00Z"
    assert_eq!(result.executed_at(), EXECUTED_AT);
}

/// Scenario: An empty selection executes nothing.
#[test]
fn an_empty_selection_executes_nothing() {
    let catalog = selftest_catalog(&[PRODUCES_RESULT_RULE]);

    // When the engine executes the selection of controls []
    let results = engine()
        .execute(
            &catalog,
            &Selection::Controls(vec![]),
            &satisfying_registry(),
        )
        .expect("execution succeeds");

    // Then the run returns no control results
    assert!(results.is_empty());
}

/// Scenario: Selecting a control the catalog does not define is refused.
#[test]
fn selecting_a_control_the_catalog_does_not_define_is_refused() {
    let catalog = selftest_catalog(&[PRODUCES_RESULT_RULE]);

    // When the engine executes the selection of controls ["agent.unknown.control"]
    let error = engine()
        .execute(
            &catalog,
            &Selection::controls(["agent.unknown.control"]),
            &satisfying_registry(),
        )
        .expect_err("an unknown control is refused");

    // Then the run fails with an unknown-control error naming "agent.unknown.control"
    // And no control results are returned (the error carries no results).
    let ExecutionError::UnknownControl { control_id } = error;
    assert_eq!(control_id, "agent.unknown.control");
}
