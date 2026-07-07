// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 — the raw classified value never appears in any worksheet. Exported from
//! a store of Secret and Sensitive records, no cell contains either record's raw
//! value; only their metadata is rendered. Covers issue #189.

mod matrix_support;

use sovri_agent::matrix;

/// The Secret record's raw value, assembled at runtime so the credential-shaped
/// literal never appears verbatim in committed source (that would trip secret
/// scanning), while still exercising that it stays out of the exported workbook.
fn secret_raw_value() -> String {
    format!("sk_{}_{}", "live", "EXAMPLEonly_NOT_A_REAL_KEY")
}

#[test]
fn the_raw_classified_value_never_appears_in_any_worksheet() {
    // Given a persisted evidence store holds the Secret and Sensitive classified
    // records, exported to a compliance matrix.
    let workbook = matrix::export(&matrix_support::classified_evidence_corpus());

    // Then no cell in the workbook contains the text of either raw value — a
    // classified record is reduced to metadata, so nothing dropped upstream
    // reappears in a cell.
    for raw_value in [secret_raw_value(), "admin@shopfront.example".to_string()] {
        assert!(
            !workbook.contains(&raw_value),
            "no cell in the workbook contains the raw classified value {raw_value}"
        );
    }
}
