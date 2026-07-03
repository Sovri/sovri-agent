// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-04 — acquisition and evaluation are separable, and
//! evaluation is host-free in test.
//!
//! Mirrors `specs/mat-122-agent-crate-bootstrap/r04-acquisition-evaluation-split.feature`.

use sovri_agent::scanners::selftest::{SelftestScanner, SelftestSnapshot};
use sovri_agent::scanners::{Scanner, Verdict};

/// Scenario: Evaluation runs over an injected snapshot without touching the host.
#[test]
fn evaluation_runs_over_an_injected_snapshot_without_touching_the_host() {
    // Given a captured host snapshot fixture with the engine-wiring sentinel present
    let snapshot = SelftestSnapshot::present();

    // When the scanner evaluates the snapshot
    // Then the evaluation reports the control satisfied
    assert_eq!(SelftestScanner.evaluate(&snapshot), Verdict::Satisfied);

    // And the evaluation reads only the injected snapshot, not the real host:
    // an "absent" snapshot yields a finding even though the real host (the
    // running executable acquisition would observe) is present — so evaluate
    // cannot have consulted the host.
    assert_eq!(
        SelftestScanner.evaluate(&SelftestSnapshot::absent()),
        Verdict::Finding
    );
}

/// Scenario: A snapshot missing the sentinel evaluates to a finding.
#[test]
fn a_snapshot_missing_the_sentinel_evaluates_to_a_finding() {
    // Given a captured host snapshot fixture with the engine-wiring sentinel absent
    let snapshot = SelftestSnapshot::absent();

    // When the scanner evaluates the snapshot
    // Then the evaluation reports a finding
    assert_eq!(SelftestScanner.evaluate(&snapshot), Verdict::Finding);
}

/// Scenario Outline: Evaluation is a pure, deterministic function of the snapshot.
#[test]
fn evaluation_is_a_pure_deterministic_function_of_the_snapshot() {
    for (snapshot, expected) in [
        (SelftestSnapshot::present(), Verdict::Satisfied),
        (SelftestSnapshot::absent(), Verdict::Finding),
    ] {
        // When the scanner evaluates the snapshot twice
        let first = SelftestScanner.evaluate(&snapshot);
        let second = SelftestScanner.evaluate(&snapshot);
        // Then both evaluations report "<outcome>"
        assert_eq!(first, second, "evaluation is deterministic");
        assert_eq!(first, expected);
    }
}
