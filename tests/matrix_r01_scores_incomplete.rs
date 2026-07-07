// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — an ERROR result marks the scores incomplete. A corpus carrying a
//! control result whose status is ERROR renders that ERROR on the Results sheet
//! and marks the Summary sheet's scores as incomplete. Covers issue #170.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The framework the corpus covers.
const FRAMEWORK: &str = "gdpr-eprivacy";
/// The control the errored result evaluates.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The rule whose execution failed.
const RULE: &str = "consent.detect-trackers-without-consent-evidence";

/// Builds a control result whose execution errored, carrying the reason the SDK
/// requires for any non-PASS status.
fn errored_result() -> ControlResult {
    ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(RULE)
        .status(Status::Error)
        .severity("major")
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0")
        .reason("execution failed; no compliance conclusion can be drawn")
        .build()
        .expect("the errored fixture result validates")
}

#[test]
fn an_error_result_marks_the_scores_incomplete() {
    // Given a compliance corpus that contains a control result with status "ERROR",
    // exported to a compliance matrix.
    let corpus = Corpus::new(EXECUTED_AT).with_control_result(FRAMEWORK, errored_result());
    let workbook = matrix::export(&corpus);

    // Then the "Results" worksheet has a row with status "ERROR".
    let results = matrix_support::rows(matrix_support::worksheet(&workbook, "Results"));
    assert!(
        results
            .iter()
            .any(|cells| cells.iter().any(|cell| cell == "ERROR")),
        "the Results worksheet has a row with status ERROR (rows: {results:?})"
    );

    // And the "Summary" worksheet marks the scores as incomplete.
    let summary = matrix_support::rows(matrix_support::worksheet(&workbook, "Summary"));
    assert!(
        summary
            .iter()
            .any(|cells| cells.iter().any(|cell| cell.contains("incomplete"))),
        "the Summary worksheet marks the scores as incomplete (rows: {summary:?})"
    );
}
