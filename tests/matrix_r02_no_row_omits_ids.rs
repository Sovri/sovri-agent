// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — no row omits the ids that trace it to the corpus. Every Results row
//! carries a non-empty control id and rule id, every Evidence row a non-empty
//! evidence id, and every Gaps row a non-empty gap id. Covers issue #178.

mod matrix_support;

use sovri_agent::matrix;

/// The composed gap id for the consent corpus's tracker-rule FAIL.
const GAP_ID: &str =
    "gdpr-eprivacy:consent.tracker.prior-consent:consent.detect-trackers-without-consent-evidence";

/// Whether a row is a Results data row, identified by its status cell rather than
/// a column position (a header row, added later, never carries a status label).
fn is_result_row(cells: &[String]) -> bool {
    cells
        .iter()
        .any(|cell| ["PASS", "FAIL", "WARNING", "SKIPPED", "ERROR"].contains(&cell.as_str()))
}

#[test]
fn no_row_omits_the_ids_that_trace_it_to_the_corpus() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);

    // Then every "Results" row carries a non-empty control id and rule id.
    let results = matrix_support::rows(matrix_support::worksheet(&workbook, "Results"));
    let result_rows: Vec<&Vec<String>> = results
        .iter()
        .filter(|cells| is_result_row(cells))
        .collect();
    assert!(
        !result_rows.is_empty(),
        "the corpus has Results rows to check"
    );
    for row in &result_rows {
        assert!(
            row.iter().any(|cell| cell == matrix_support::CONTROL),
            "every Results row carries a non-empty control id (row: {row:?})"
        );
        assert!(
            row.iter().any(
                |cell| cell == matrix_support::TRACKER_RULE || cell == matrix_support::CMP_RULE
            ),
            "every Results row carries a non-empty rule id (row: {row:?})"
        );
    }

    // And every "Evidence" row carries a non-empty evidence id.
    let evidence = matrix_support::rows(matrix_support::worksheet(&workbook, "Evidence"));
    let evidence_row = matrix_support::row_containing(&evidence, "ev-0001")
        .expect("the Evidence sheet carries the corpus's record");
    assert!(
        evidence_row.iter().any(|cell| cell == "ev-0001"),
        "every Evidence row carries a non-empty evidence id (row: {evidence_row:?})"
    );

    // And every "Gaps" row carries a non-empty gap id.
    let gaps = matrix_support::rows(matrix_support::worksheet(&workbook, "Gaps"));
    let gap_row = matrix_support::row_containing(&gaps, GAP_ID)
        .expect("the Gaps sheet carries the corpus's gap");
    assert!(
        gap_row.iter().any(|cell| cell == GAP_ID),
        "every Gaps row carries a non-empty gap id (row: {gap_row:?})"
    );
}
