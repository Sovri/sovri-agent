// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — rows render in a stable order regardless of input order. Exporting a
//! corpus whose results are supplied in a shuffled order lays the Results rows out
//! by control id then rule id, and yields a workbook byte-identical to the one
//! exported from the same results in any other input order. Covers issue #192.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn rows_render_in_a_stable_order_regardless_of_input_order() {
    // Given a corpus whose results are supplied in a shuffled order, and the same
    // results supplied in another input order for the byte-identity comparison.
    let shuffled = matrix_support::consent_corpus_results_shuffled();
    let other_order = matrix_support::consent_corpus();

    // When the compliance matrix is exported.
    let workbook = matrix::export(&shuffled);
    let other_workbook = matrix::export(&other_order);

    // Then Results rows are ordered by control id then rule id, regardless of the
    // order the results were supplied in.
    for book in [&workbook, &other_workbook] {
        let results = matrix_support::rows(matrix_support::worksheet(book, "Results"));
        let keys: Vec<(&str, &str)> = results
            .iter()
            .skip(1) // the header row is not a data row and is not sorted
            .map(|row| (row[1].as_str(), row[2].as_str())) // the Control, then Rule columns
            .collect();
        let mut ordered = keys.clone();
        ordered.sort_unstable();
        assert_eq!(
            keys, ordered,
            "Results rows are ordered by control id then rule id (rows: {results:?})"
        );
    }

    // And the workbook is byte-identical to the one exported from the same results
    // in any other input order.
    assert_eq!(
        workbook, other_workbook,
        "the workbook is byte-identical regardless of input order"
    );
}
