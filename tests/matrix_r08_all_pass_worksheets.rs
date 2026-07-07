// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — an all-PASS corpus still produces every worksheet. A corpus where
//! every control passes yields all six sheets, a Summary PASS count of two, and
//! the no-gaps placeholder on the Gaps sheet. Covers issue #196.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn an_all_pass_corpus_still_produces_every_worksheet() {
    // Given a compliance corpus where every control passes.
    let workbook = matrix::export(&matrix_support::all_pass_corpus());

    // Then the workbook has worksheets Controls, Results, Gaps, Evidence, Frameworks, Summary.
    for sheet in [
        "Controls",
        "Results",
        "Gaps",
        "Evidence",
        "Frameworks",
        "Summary",
    ] {
        assert!(
            workbook.contains(&format!("ss:Name=\"{sheet}\"")),
            "the workbook has the {sheet} worksheet"
        );
    }

    // And the "Summary" worksheet shows the count "2" for status "PASS".
    let summary = matrix_support::rows(matrix_support::worksheet(&workbook, "Summary"));
    assert!(
        summary
            .iter()
            .any(|row| row.iter().any(|cell| cell == "PASS") && row.iter().any(|cell| cell == "2")),
        "the Summary worksheet shows count 2 for status PASS (rows: {summary:?})"
    );

    // And the "Gaps" worksheet shows the explanatory row "No potential gaps observed".
    let gaps = matrix_support::worksheet(&workbook, "Gaps");
    assert!(
        gaps.contains("No potential gaps observed"),
        "the Gaps worksheet shows the no-gaps placeholder row"
    );
}
