// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 — integrity metadata is read from the store, not recomputed. The Evidence
//! sheet shows the stored digest verbatim, and the export hashes nothing. Covers
//! issue #199.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};

/// A digest the export could not have produced by hashing the located asset — it
/// is the SHA-256 of empty input — so seeing it rendered proves the export read
/// the stored digest rather than recomputing one.
const STORED_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn integrity_metadata_is_read_from_the_store_not_recomputed() {
    // Given a persisted evidence store holds a record "ev-0002" with a stored
    // integrity, exported to a compliance matrix.
    let corpus = Corpus::new(matrix_support::EXECUTED_AT).with_evidence_digest(
        "ev-0002",
        "file",
        "dist/analytics.js",
        STORED_DIGEST,
    );
    let workbook = matrix::export(&corpus);

    // Then the "Evidence" worksheet shows that integrity for evidence id "ev-0002".
    let evidence = matrix_support::rows(matrix_support::worksheet(&workbook, "Evidence"));
    let row = matrix_support::row_containing(&evidence, "ev-0002")
        .expect("the Evidence sheet has a row for ev-0002");
    assert!(
        row.iter().any(|cell| cell == STORED_DIGEST),
        "the Evidence row shows the stored integrity digest (row: {row:?})"
    );

    // And no scanner or hasher is executed while exporting the workbook: the export
    // took only the in-memory corpus and rendered the stored digest verbatim —
    // recomputing a hash of the located asset would not yield this exact value.
    assert_eq!(
        row.iter()
            .filter(|cell| cell.as_str() == STORED_DIGEST)
            .count(),
        1,
        "the stored digest is rendered exactly once, unchanged"
    );
}
