// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — each Results row carries its control, rule, and evidence ids, so every
//! row traces back to the persisted corpus. Covers issue #174.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn each_results_row_carries_its_control_rule_and_evidence_ids() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);
    let results = matrix_support::rows(matrix_support::worksheet(&workbook, "Results"));

    for rule in [matrix_support::TRACKER_RULE, matrix_support::CMP_RULE] {
        // Then the "Results" worksheet has a row for rule "<rule>".
        let row = matrix_support::row_containing(&results, rule).unwrap_or_else(|| {
            panic!("the Results worksheet has a row for rule {rule} (rows: {results:?})")
        });

        // And that row carries control id "consent.tracker.prior-consent".
        assert!(
            row.iter().any(|cell| cell == matrix_support::CONTROL),
            "the row for rule {rule} carries the control id (row: {row:?})"
        );
        // And that row carries rule id "<rule>".
        assert!(
            row.iter().any(|cell| cell == rule),
            "the row carries rule id {rule} (row: {row:?})"
        );
        // And that row carries evidence id "ev-0001".
        assert!(
            row.iter().any(|cell| cell == "ev-0001"),
            "the row for rule {rule} carries evidence id ev-0001 (row: {row:?})"
        );
    }
}
