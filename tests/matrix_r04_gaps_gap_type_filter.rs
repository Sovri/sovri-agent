// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 — the Gaps sheet holds only FAIL and WARNING rows, filterable by gap
//! type. In the mixed corpus the Gaps sheet carries the FAIL and WARNING gaps but
//! not the SKIPPED control, and its `AutoFilter` covers the Gap type column.
//! Covers issue #184.

mod matrix_support;

use sovri_agent::matrix;

/// The 1-based index of the last column the sheet's `AutoFilter` range spans.
fn autofilter_last_column(worksheet: &str) -> usize {
    let at = worksheet
        .find("x:Range=\"")
        .expect("the sheet carries an AutoFilter range");
    let rest = &worksheet[at + "x:Range=\"".len()..];
    let range = &rest[..rest.find('"').expect("the range attribute is closed")];
    let end = range.rsplit_once(':').map_or(range, |(_, end)| end);
    let cols = end
        .rsplit_once('C')
        .expect("the range end names a column")
        .1;
    cols.parse().expect("the range end column is a number")
}

#[test]
fn gaps_holds_only_fail_and_warning_filterable_by_gap_type() {
    // Given a compliance matrix exported from the "mixed-2026-06-24" run.
    let workbook = matrix::export(&matrix_support::mixed_corpus());
    let sheet = matrix_support::worksheet(&workbook, "Gaps");
    let rows = matrix_support::rows(sheet);
    let header = rows.first().expect("the Gaps sheet has a header row");
    let gap_type = header
        .iter()
        .position(|name| name == "Gap type")
        .expect("the Gaps header has a Gap type column");
    let gap_types: Vec<&str> = rows[1..]
        .iter()
        .filter_map(|row| row.get(gap_type).map(String::as_str))
        .collect();

    // Then the "Gaps" worksheet has a row with gap type "FAIL".
    assert!(
        gap_types.contains(&"FAIL"),
        "Gaps has a FAIL gap-type row (types: {gap_types:?})"
    );
    // And the "Gaps" worksheet has a row with gap type "WARNING".
    assert!(
        gap_types.contains(&"WARNING"),
        "Gaps has a WARNING gap-type row (types: {gap_types:?})"
    );

    // And the "Gaps" worksheet has no row for the SKIPPED control "host.ssh.protocol-v1".
    assert!(
        !sheet.contains("host.ssh.protocol-v1"),
        "the SKIPPED control is not a gap and must not appear on the Gaps sheet"
    );

    // And the "Gaps" worksheet AutoFilter covers the "Gap type" column.
    assert!(
        autofilter_last_column(sheet) > gap_type,
        "the Gaps AutoFilter range covers the Gap type column (column {})",
        gap_type + 1
    );
}
