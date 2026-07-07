// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — the wall clock never leaks in and breaks byte-identity. Exported at two
//! different wall-clock moments the workbook is byte-identical, and its generated
//! date is the fixed executed-at, never the current time. Covers issue #194.

mod matrix_support;

use sovri_agent::matrix;

/// The text of the workbook's `<Created>` generated-date element.
fn created_date(xml: &str) -> &str {
    let start = xml
        .find("<Created>")
        .expect("the workbook has a creation date")
        + "<Created>".len();
    let end = start
        + xml[start..]
            .find("</Created>")
            .expect("the creation date is closed");
    &xml[start..end]
}

#[test]
fn the_wall_clock_never_leaks_in_and_breaks_byte_identity() {
    let corpus = matrix_support::consent_corpus();

    // When the compliance matrix is exported at two different wall-clock moments —
    // the export reads no clock, so the moment it runs cannot change the bytes.
    let first = matrix::export(&corpus);
    let second = matrix::export(&corpus);

    // Then the two workbooks remain byte-identical.
    assert_eq!(
        first, second,
        "the wall clock never leaks in and breaks byte-identity"
    );

    // And neither workbook's generated date reflects the wall clock: it is the
    // fixed past executed-at, not the current time.
    assert_eq!(
        created_date(&first),
        matrix_support::EXECUTED_AT,
        "the generated date is the fixed executed-at, not the wall clock"
    );
    assert_eq!(created_date(&second), matrix_support::EXECUTED_AT);
}
