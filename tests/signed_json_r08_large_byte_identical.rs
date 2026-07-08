// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — a large corpus stays byte-identical across signed JSON regenerations.
//! Covers issue #281.

mod matrix_support;
mod signed_json_support;

use signed_json_support::{string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn a_large_corpus_stays_byte_identical_across_regenerations() {
    // Given a large compliance corpus of 120 control results with the fixture
    // executed-at.
    let corpus = matrix_support::large_corpus();

    // When the signed JSON is exported from the large corpus.
    let first = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // And the signed JSON is exported from the large corpus a second time.
    let second = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    assert_eq!(
        string_member(&first, "executed_at").as_deref(),
        Some(matrix_support::EXECUTED_AT),
        "the large signed JSON export carries the fixture executed-at"
    );

    // Then the two documents are byte-identical.
    assert_eq!(
        first.as_bytes(),
        second.as_bytes(),
        "a 120-result signed JSON export regenerates byte-identically"
    );
}
