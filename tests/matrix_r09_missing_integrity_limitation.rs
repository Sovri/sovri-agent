// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 — a record without integrity metadata shows a collection limitation. An
//! evidence record with no digest renders "integrity metadata not available" on
//! the Evidence sheet, with redaction status "none". Covers issue #200.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};

#[test]
fn a_record_without_integrity_metadata_shows_a_collection_limitation() {
    // Given a persisted evidence store holds a record "ev-0003" with no integrity
    // metadata, exported to a compliance matrix.
    let corpus =
        Corpus::new(matrix_support::EXECUTED_AT).with_evidence("ev-0003", "dist/legacy.js");
    let workbook = matrix::export(&corpus);

    // Then the "Evidence" worksheet has a row for evidence id "ev-0003".
    let evidence = matrix_support::rows(matrix_support::worksheet(&workbook, "Evidence"));
    let row = matrix_support::row_containing(&evidence, "ev-0003")
        .expect("the Evidence sheet has a row for ev-0003");

    // And it shows integrity "integrity metadata not available".
    assert!(
        row.iter()
            .any(|cell| cell == "integrity metadata not available"),
        "the row shows the collection limitation for the missing digest (row: {row:?})"
    );

    // And it shows redaction status "none".
    assert!(
        row.iter().any(|cell| cell == "none"),
        "the row shows redaction status none (row: {row:?})"
    );
}
