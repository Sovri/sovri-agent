// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — the same corpus produces a byte-identical signed document. Exporting
//! the fixed "shopfront-2026-06-24" consent corpus twice with the same fixture
//! signing seed yields identical signed JSON bytes. Covers issue #273.

mod signed_json_support;

use signed_json_support::{consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn the_same_corpus_produces_a_byte_identical_signed_document() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at.
    let corpus = consent_corpus();

    // When the signed JSON is exported from the corpus, and exported from the
    // same corpus a second time.
    let first = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let second = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then the two documents are byte-identical.
    assert_eq!(
        first.as_bytes(),
        second.as_bytes(),
        "exporting the same corpus twice yields byte-identical signed JSON"
    );
}
