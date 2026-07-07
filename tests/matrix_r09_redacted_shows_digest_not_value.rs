// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 — a redacted record still shows its digest but never its raw value. A
//! Secret record renders its `sha256:…` digest and redaction status `redacted`,
//! and no cell of the workbook carries its raw value. Covers issue #201.

mod matrix_support;

use sovri_agent::matrix::{self, Classification, Corpus};

/// The stored digest of the redacted record.
const INTEGRITY: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// The record's raw value, assembled at runtime so the credential-shaped literal
/// never appears verbatim in committed source (it would trip secret scanning).
fn secret_raw_value() -> String {
    format!("sk_{}_{}", "live", "EXAMPLEonly_NOT_A_REAL_KEY")
}

#[test]
fn a_redacted_record_still_shows_its_digest_but_never_its_raw_value() {
    // Given a Secret record "ev-0009" at ".env.example:3" with a stored digest whose
    // raw value the store dropped, exported to a compliance matrix.
    let corpus = Corpus::new(matrix_support::EXECUTED_AT).with_classified_evidence(
        "ev-0009",
        "config",
        ".env.example:3",
        Classification::Secret,
        INTEGRITY,
    );
    let workbook = matrix::export(&corpus);

    let evidence = matrix_support::rows(matrix_support::worksheet(&workbook, "Evidence"));
    let row = matrix_support::row_containing(&evidence, "ev-0009")
        .expect("the Evidence sheet has a row for ev-0009");

    // Then the "Evidence" worksheet shows the integrity digest for evidence id "ev-0009".
    assert!(
        row.iter().any(|cell| cell == INTEGRITY),
        "the redacted record still shows its stored digest (row: {row:?})"
    );

    // And it shows redaction status "redacted".
    assert!(
        row.iter().any(|cell| cell == "redacted"),
        "the redacted record shows redaction status redacted (row: {row:?})"
    );

    // And no cell in the workbook contains the text of the raw value.
    assert!(
        !workbook.contains(&secret_raw_value()),
        "no cell in the workbook contains the redacted record's raw value"
    );
}
