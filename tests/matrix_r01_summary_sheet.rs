// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the Summary worksheet shows status counts by framework and names every
//! MAT-87 score scope. Exported from the persisted consent corpus, the Summary
//! sheet shows the count "1" for gdpr-eprivacy FAIL and PASS, and lists the
//! control, framework, and environment scores. Covers issue #168.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The framework the consent corpus covers.
const FRAMEWORK: &str = "gdpr-eprivacy";
/// The single control both consent results evaluate.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The rule that fails: a non-essential tracker with no consent evidence.
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The rule that passes: the consent-management platform is configured.
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";

/// Builds one consent `ControlResult` for `rule_id` at `status`, mirroring the
/// Background row values (control, severity, weight, evidence id, executed-at).
fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
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

/// Whether any row's cells carry every value in `needles`.
fn row_has_all(rows: &[Vec<String>], needles: &[&str]) -> bool {
    rows.iter().any(|cells| {
        needles
            .iter()
            .all(|needle| cells.iter().any(|cell| cell == needle))
    })
}

#[test]
fn summary_shows_status_counts_and_names_every_score_scope() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = Corpus::new(EXECUTED_AT)
        .with_framework(
            FRAMEWORK,
            "2016-679",
            "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        )
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass));
    let workbook = matrix::export(&corpus);
    let summary = matrix_support::worksheet(&workbook, "Summary");
    let rows = matrix_support::rows(summary);

    // Then the "Summary" worksheet shows the count "1" for framework "gdpr-eprivacy" status "FAIL".
    assert!(
        row_has_all(&rows, &[FRAMEWORK, "FAIL", "1"]),
        "the Summary worksheet shows count 1 for {FRAMEWORK} status FAIL (rows: {rows:?})"
    );

    // And the "Summary" worksheet shows the count "1" for framework "gdpr-eprivacy" status "PASS".
    assert!(
        row_has_all(&rows, &[FRAMEWORK, "PASS", "1"]),
        "the Summary worksheet shows count 1 for {FRAMEWORK} status PASS (rows: {rows:?})"
    );

    // And the "Summary" worksheet lists the control, framework, and environment scores.
    for scope in ["Control score", "Framework score", "Environment score"] {
        assert!(
            rows.iter()
                .any(|cells| cells.iter().any(|cell| cell == scope)),
            "the Summary worksheet lists the {scope} (rows: {rows:?})"
        );
    }
}
