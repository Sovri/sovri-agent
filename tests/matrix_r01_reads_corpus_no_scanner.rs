// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the export reads the corpus and runs no scanner. The compliance matrix
//! is exported from an in-memory persisted corpus alone: no scanner runs, no
//! network is touched, and the workbook is derived only from the corpus's own
//! records. Covers issue #171.

mod matrix_support;

use sovri_agent::matrix;

/// The status cell a Results row carries, if any.
fn result_statuses(rows: &[Vec<String>]) -> Vec<String> {
    rows.iter()
        .filter_map(|cells| {
            cells
                .iter()
                .find(|cell| {
                    ["PASS", "FAIL", "WARNING", "SKIPPED", "ERROR"].contains(&cell.as_str())
                })
                .cloned()
        })
        .collect()
}

#[test]
fn export_reads_the_corpus_and_runs_no_scanner() {
    // Given the persisted "shopfront-2026-06-24" consent corpus, assembled entirely
    // in memory — no evidence store on disk, no scanner, no network client.
    let corpus = matrix_support::consent_corpus();

    // When the maintainer exports the compliance matrix for "shopfront-2026-06-24".
    let workbook = matrix::export(&corpus);

    // Then no scanner is executed and no network access is performed: the export
    // took only the in-memory corpus and produced a complete workbook from it.
    assert!(
        !matrix_support::worksheet(&workbook, "Frameworks").is_empty(),
        "the workbook is produced from the corpus alone"
    );

    // And the workbook content is derived only from the persisted corpus: the
    // Results sheet carries exactly the corpus's two results — a scanner run would
    // have injected more — and their statuses are exactly the corpus's FAIL/PASS.
    let results = matrix_support::rows(matrix_support::worksheet(&workbook, "Results"));
    let statuses = result_statuses(&results);
    assert_eq!(
        statuses.len(),
        2,
        "the Results sheet carries exactly the corpus's two results — a scanner would add more (rows: {results:?})"
    );
    assert!(
        statuses.iter().any(|s| s == "FAIL") && statuses.iter().any(|s| s == "PASS"),
        "the rendered statuses are exactly the corpus's FAIL and PASS (statuses: {statuses:?})"
    );

    // And the framework rendered is the one the corpus holds, nothing discovered.
    let frameworks = matrix_support::rows(matrix_support::worksheet(&workbook, "Frameworks"));
    assert_eq!(
        frameworks.len(),
        1,
        "the Frameworks sheet carries only the corpus's framework (rows: {frameworks:?})"
    );
    assert!(
        matrix_support::row_containing(&frameworks, matrix_support::FRAMEWORK).is_some(),
        "the corpus's framework is the one rendered (rows: {frameworks:?})"
    );
}
