// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 — the Evidence sheet shows the `sha256:…` digest and the redaction status a
//! stored, unclassified record carries in the persisted store. Exported from a store
//! holding `ev-0001` — the built asset `dist/main.js` with its integrity digest — the
//! record's Evidence row shows that location, that digest verbatim, and a `none`
//! redaction status. Covers #198.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn the_evidence_sheet_shows_the_digest_and_redaction_status_for_a_stored_record() {
    // Given a persisted evidence store holds a record for control
    // "consent.tracker.prior-consent": ev-0001, file, dist/main.js, sha256:ba78…20015ad
    // And a compliance matrix exported from that store.
    let workbook = matrix::export(&matrix_support::stored_evidence_corpus());
    let evidence = matrix_support::rows(matrix_support::worksheet(&workbook, "Evidence"));

    // Then the "Evidence" worksheet has a row for evidence id "ev-0001".
    let row = matrix_support::row_containing(&evidence, matrix_support::STORED_EVIDENCE_ID)
        .unwrap_or_else(|| {
            panic!(
                "the Evidence sheet has a row for evidence id {} (rows: {evidence:?})",
                matrix_support::STORED_EVIDENCE_ID
            )
        });

    // And it shows location "dist/main.js".
    assert!(
        row.iter()
            .any(|cell| cell == matrix_support::STORED_EVIDENCE_LOCATION),
        "the Evidence row for {} shows location {} (row: {row:?})",
        matrix_support::STORED_EVIDENCE_ID,
        matrix_support::STORED_EVIDENCE_LOCATION
    );

    // And it shows integrity "sha256:ba7816bf…f20015ad".
    assert!(
        row.iter()
            .any(|cell| cell == matrix_support::STORED_EVIDENCE_INTEGRITY),
        "the Evidence row for {} shows integrity {} (row: {row:?})",
        matrix_support::STORED_EVIDENCE_ID,
        matrix_support::STORED_EVIDENCE_INTEGRITY
    );

    // And it shows redaction status "none".
    assert!(
        row.iter().any(|cell| cell == "none"),
        "the Evidence row for {} shows redaction status none (row: {row:?})",
        matrix_support::STORED_EVIDENCE_ID
    );
}
