// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — the Gaps row is stably identified by its framework, control, and rule.
//! Exported from the "shopfront-2026-06-24" consent corpus, the Gaps sheet's row
//! for the failing tracker rule is keyed by the composed gap id
//! `framework:control:rule` and carries the framework, control, rule, and evidence
//! ids that trace it back to the persisted corpus. Covers #175.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn the_gaps_row_is_stably_identified_by_its_framework_control_and_rule() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);

    // Then the "Gaps" worksheet has a row for gap id
    // "gdpr-eprivacy:consent.tracker.prior-consent:consent.detect-trackers-without-consent-evidence".
    let gap_id = format!(
        "{}:{}:{}",
        matrix_support::FRAMEWORK,
        matrix_support::CONTROL,
        matrix_support::TRACKER_RULE
    );
    let gaps = matrix_support::worksheet(&workbook, "Gaps");
    let rows = matrix_support::rows(gaps);
    let row = matrix_support::row_containing(&rows, &gap_id).unwrap_or_else(|| {
        panic!("the Gaps worksheet has a row for gap id {gap_id} (rows: {rows:?})")
    });

    // And that row carries framework id "gdpr-eprivacy".
    assert!(
        row.iter().any(|cell| cell == matrix_support::FRAMEWORK),
        "the gap row carries framework id {} (row: {row:?})",
        matrix_support::FRAMEWORK
    );

    // And that row carries control id "consent.tracker.prior-consent".
    assert!(
        row.iter().any(|cell| cell == matrix_support::CONTROL),
        "the gap row carries control id {} (row: {row:?})",
        matrix_support::CONTROL
    );

    // And that row carries rule id "consent.detect-trackers-without-consent-evidence".
    assert!(
        row.iter().any(|cell| cell == matrix_support::TRACKER_RULE),
        "the gap row carries rule id {} (row: {row:?})",
        matrix_support::TRACKER_RULE
    );

    // And that row carries evidence id "ev-0001".
    assert!(
        row.iter().any(|cell| cell == "ev-0001"),
        "the gap row carries evidence id ev-0001 (row: {row:?})"
    );
}
