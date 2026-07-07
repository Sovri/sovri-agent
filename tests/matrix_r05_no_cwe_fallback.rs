// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 — no cell in the workbook falls back to a CWE reference. Exported from
//! the consent corpus, no cell contains a `CWE-` reference and the Gaps row for
//! the consent control shows its own framework reference. Covers issue #187.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn no_cell_in_the_workbook_falls_back_to_a_cwe_reference() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let workbook = matrix::export(&matrix_support::consent_corpus());

    // Then no cell in the workbook contains a reference beginning with "CWE-".
    assert!(
        !workbook.contains("CWE-"),
        "no cell in the workbook falls back to a CWE reference"
    );

    // And the "Gaps" row for control "consent.tracker.prior-consent" shows
    // reference "gdpr-eprivacy:2016-679:Art.7".
    let gaps = matrix_support::rows(matrix_support::worksheet(&workbook, "Gaps"));
    let row = matrix_support::row_containing(&gaps, matrix_support::CONTROL)
        .expect("the Gaps sheet has a row for the consent control");
    assert!(
        row.iter()
            .any(|cell| cell == matrix_support::CONTROL_REFERENCE),
        "the consent Gaps row shows its framework reference {} (row: {row:?})",
        matrix_support::CONTROL_REFERENCE
    );
}
