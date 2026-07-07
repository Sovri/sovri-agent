// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 — the Results header never drifts from its documented columns. The
//! Results worksheet's header is exactly the documented column list, and no row
//! carries a column outside that header. Covers issue #181.

mod matrix_support;

use sovri_agent::matrix;

/// The exact documented Results header.
const RESULTS_HEADER: &str =
    "Framework, Control, Rule, Status, Severity, Score impact, Evidence ids, Remediation, Applicability";

#[test]
fn the_results_header_never_drifts_from_its_documented_columns() {
    // Given a compliance matrix exported from the consent corpus.
    let workbook = matrix::export(&matrix_support::consent_corpus());
    let rows = matrix_support::rows(matrix_support::worksheet(&workbook, "Results"));

    // Then the "Results" worksheet header is exactly the documented columns.
    let header = rows.first().expect("the Results sheet has a header row");
    assert_eq!(
        header.join(", "),
        RESULTS_HEADER,
        "the Results header is exactly its documented columns"
    );

    // And the "Results" worksheet has no column outside that header: every row
    // carries exactly as many columns as the header, no more, no fewer.
    let width = header.len();
    for row in &rows {
        assert_eq!(
            row.len(),
            width,
            "no Results row has a column outside the documented header (row: {row:?})"
        );
    }
}
