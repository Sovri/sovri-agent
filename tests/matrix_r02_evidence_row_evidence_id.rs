// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — the Evidence row carries its evidence id, so the collected evidence
//! traces back to the persisted corpus. Exported from the "shopfront-2026-06-24"
//! consent corpus, the Evidence sheet's row for `ev-0001` carries the built asset
//! location the consent gap is anchored at. Covers #176.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn the_evidence_row_carries_its_evidence_id() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);

    // Then the "Evidence" worksheet has a row for evidence id "ev-0001".
    let evidence = matrix_support::worksheet(&workbook, "Evidence");
    let rows = matrix_support::rows(evidence);
    let row = matrix_support::row_containing(&rows, "ev-0001")
        .expect("the Evidence worksheet has a row for evidence id ev-0001");

    // And that row carries location "dist/main.js".
    assert!(
        row.iter().any(|cell| cell == "dist/main.js"),
        "the evidence row carries location \"dist/main.js\" (row: {row:?})"
    );
}
