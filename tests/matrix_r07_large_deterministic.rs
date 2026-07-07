// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — a large workbook stays deterministic across regenerations. A corpus of
//! 120 control results exports byte-identically when regenerated. Covers #193.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn a_large_workbook_stays_deterministic_across_regenerations() {
    // Given a large compliance corpus of 120 control results with a fixed executed-at.
    let corpus = matrix_support::large_corpus();

    // When the compliance matrix is exported from the large corpus, and exported a
    // second time.
    let first = matrix::export(&corpus);
    let second = matrix::export(&corpus);

    // Then the two workbooks are byte-identical.
    assert_eq!(
        first, second,
        "a 120-result workbook regenerates byte-identically"
    );
    // Sanity: the large corpus really produced a large Results sheet.
    let results = matrix_support::rows(matrix_support::worksheet(&first, "Results"));
    assert_eq!(
        results.len(),
        121,
        "the Results sheet has a header row plus 120 result rows (rows: {})",
        results.len()
    );
}
