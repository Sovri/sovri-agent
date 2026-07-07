// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — a Controls row carries the stable ids and catalogued fields that trace
//! it back to the corpus. Exported from the "shopfront-2026-06-24" consent corpus,
//! the Controls sheet's row for `consent.tracker.prior-consent` carries its
//! framework id, control id, catalogued title, severity, and weight. Covers #173.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn the_controls_row_carries_its_ids_and_catalogued_fields() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);

    // Then the "Controls" worksheet has a row for control "consent.tracker.prior-consent".
    let controls = matrix_support::worksheet(&workbook, "Controls");
    let rows = matrix_support::rows(controls);
    let row = matrix_support::row_containing(&rows, matrix_support::CONTROL)
        .expect("the Controls worksheet has a row for consent.tracker.prior-consent");

    // And that row carries framework id "gdpr-eprivacy".
    assert!(
        row.iter().any(|cell| cell == matrix_support::FRAMEWORK),
        "the control row carries framework id {} (row: {row:?})",
        matrix_support::FRAMEWORK
    );

    // And that row carries control id "consent.tracker.prior-consent".
    assert!(
        row.iter().any(|cell| cell == matrix_support::CONTROL),
        "the control row carries control id {} (row: {row:?})",
        matrix_support::CONTROL
    );

    // And that row shows title "Prior consent for tracker access".
    assert!(
        row.iter()
            .any(|cell| cell == "Prior consent for tracker access"),
        "the control row shows title \"Prior consent for tracker access\" (row: {row:?})"
    );

    // And that row shows severity "major".
    assert!(
        row.iter().any(|cell| cell == "major"),
        "the control row shows severity \"major\" (row: {row:?})"
    );

    // And that row shows weight "8".
    assert!(
        row.iter().any(|cell| cell == "8"),
        "the control row shows weight \"8\" (row: {row:?})"
    );
}
