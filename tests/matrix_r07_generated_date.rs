// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — the generated date is the run's fixed executed-at, not the wall clock.
//! The workbook's creation date is the corpus's fixed executed-at and it embeds
//! no wall-clock timestamp. Covers issue #191.

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
fn the_generated_date_is_the_fixed_executed_at_not_the_wall_clock() {
    // When the compliance matrix is exported from the consent corpus (executed-at
    // "2026-06-24T13:16:28Z").
    let workbook = matrix::export(&matrix_support::consent_corpus());

    // Then the workbook's generated date is "2026-06-24T13:16:28Z".
    assert_eq!(
        created_date(&workbook),
        matrix_support::EXECUTED_AT,
        "the generated date is the run's fixed executed-at"
    );

    // And the workbook embeds no wall-clock creation timestamp: it carries no
    // separate LastSaved timestamp and exactly one creation date — the fixed one.
    assert!(
        !workbook.contains("LastSaved"),
        "the workbook embeds no wall-clock LastSaved timestamp"
    );
    assert_eq!(
        workbook.matches("<Created>").count(),
        1,
        "the workbook has exactly one creation date, the fixed executed-at"
    );
}
