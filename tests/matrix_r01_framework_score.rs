// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the Summary worksheet shows a concrete framework score. A corpus whose
//! only control has a single result scores 100.0% when it passes and 0.0% when it
//! fails, read from the MAT-87 score, never recomputed. Covers issue #169.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The framework the consent corpus covers.
const FRAMEWORK: &str = "gdpr-eprivacy";
/// The single control the corpus evaluates.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The rule the single result records.
const RULE: &str = "consent.detect-trackers-without-consent-evidence";

/// Builds the corpus's single consent `ControlResult` at `status`, carrying the
/// control's catalogued severity and weight so the SDK can score it.
fn single_result(status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(RULE)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

#[test]
fn summary_shows_a_concrete_framework_score() {
    for (status, score) in [(Status::Pass, "100.0%"), (Status::Fail, "0.0%")] {
        // Given a compliance corpus whose only control "consent.tracker.prior-consent"
        // has a single "<status>" result, exported to a compliance matrix.
        let corpus = Corpus::new(EXECUTED_AT).with_control_result(FRAMEWORK, single_result(status));
        let workbook = matrix::export(&corpus);

        // Then the "Summary" worksheet shows framework score "<score>" for "gdpr-eprivacy".
        let summary = matrix_support::worksheet(&workbook, "Summary");
        let rows = matrix_support::rows(summary);
        let shows_score = rows.iter().any(|cells| {
            cells.iter().any(|cell| cell == "Framework score")
                && cells.iter().any(|cell| cell == FRAMEWORK)
                && cells.iter().any(|cell| cell == score)
        });
        assert!(
            shows_score,
            "the Summary worksheet shows framework score {score} for {FRAMEWORK} \
             when the only control is {status:?} (rows: {rows:?})"
        );
    }
}
