// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 — the `AutoFilter` covers the full width of the data, not a partial range.
//! The Results worksheet's `AutoFilter` range spans all of its documented
//! columns, so no column falls outside the filter. Covers issue #185.

mod matrix_support;

use sovri_agent::matrix;

/// The 1-based first and last columns the sheet's `AutoFilter` range spans.
fn autofilter_columns(worksheet: &str) -> (usize, usize) {
    let at = worksheet
        .find("x:Range=\"")
        .expect("the sheet carries an AutoFilter range");
    let rest = &worksheet[at + "x:Range=\"".len()..];
    let range = &rest[..rest.find('"').expect("the range attribute is closed")];
    let (start, end) = range
        .split_once(':')
        .expect("the range spans a start and an end");
    let column = |cell: &str| -> usize {
        cell.rsplit_once('C')
            .expect("the range cell names a column")
            .1
            .parse()
            .expect("the column is a number")
    };
    (column(start), column(end))
}

#[test]
fn the_autofilter_covers_the_full_width_of_the_data() {
    // Given a compliance matrix exported from the "mixed-2026-06-24" run.
    let workbook = matrix::export(&matrix_support::mixed_corpus());
    let sheet = matrix_support::worksheet(&workbook, "Results");
    let header = matrix_support::rows(sheet);
    let documented_columns = header
        .first()
        .expect("the Results sheet has a header row")
        .len();

    // Then the "Results" worksheet AutoFilter range spans all of its documented columns.
    let (first, last) = autofilter_columns(sheet);
    assert_eq!(first, 1, "the AutoFilter range starts at the first column");
    assert_eq!(
        last, documented_columns,
        "the AutoFilter range spans all {documented_columns} documented Results columns"
    );

    // And no documented "Results" column falls outside the AutoFilter range: the
    // range's width equals the header's column count, so none is left uncovered.
    assert_eq!(
        last - first + 1,
        documented_columns,
        "no documented Results column falls outside the AutoFilter range"
    );
}
