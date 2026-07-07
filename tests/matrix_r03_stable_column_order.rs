// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 — the column order is stable regardless of input order. Exporting the
//! same corpus with its results shuffled leaves the Results header column order
//! unchanged and keeps every data row's columns in the documented order.
//! Covers issue #180.

mod matrix_support;

use sovri_agent::matrix;

/// The documented Results column order.
const RESULTS_HEADER: &str =
    "Framework, Control, Rule, Status, Severity, Score impact, Evidence ids, Remediation, Applicability";

#[test]
fn column_order_is_stable_regardless_of_input_order() {
    // Given a compliance matrix exported from the consent corpus, and the same
    // corpus exported a second time with its results supplied in shuffled order.
    let ordered = matrix::export(&matrix_support::consent_corpus());
    let shuffled = matrix::export(&matrix_support::consent_corpus_results_shuffled());
    let ordered_rows = matrix_support::rows(matrix_support::worksheet(&ordered, "Results"));
    let shuffled_rows = matrix_support::rows(matrix_support::worksheet(&shuffled, "Results"));

    // Then the "Results" worksheet header column order is unchanged.
    let ordered_header = ordered_rows
        .first()
        .expect("the Results sheet has a header row");
    let shuffled_header = shuffled_rows
        .first()
        .expect("the Results sheet has a header row");
    assert_eq!(ordered_header.join(", "), RESULTS_HEADER);
    assert_eq!(
        shuffled_header, ordered_header,
        "the Results header column order is unchanged regardless of input order"
    );

    // And every data row keeps its columns in the documented order: in both exports
    // the tracker-rule FAIL row carries each value at its documented column index.
    for rows in [&ordered_rows, &shuffled_rows] {
        let row = rows
            .iter()
            .find(|cells| {
                cells
                    .get(2)
                    .is_some_and(|c| c == matrix_support::TRACKER_RULE)
            })
            .expect("a Results row with the tracker rule at the documented Rule column");
        assert_eq!(row[0], matrix_support::FRAMEWORK, "Framework at column 0");
        assert_eq!(row[1], matrix_support::CONTROL, "Control at column 1");
        assert_eq!(row[2], matrix_support::TRACKER_RULE, "Rule at column 2");
        assert_eq!(row[3], "FAIL", "Status at column 3");
        assert_eq!(row[4], "major", "Severity at column 4");
        assert_eq!(row[6], "ev-0001", "Evidence ids at column 6");
        assert_eq!(row[8], "applicable", "Applicability at column 8");
    }
}
