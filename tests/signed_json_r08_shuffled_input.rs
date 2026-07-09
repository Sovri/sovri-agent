// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 - shuffled input yields the same canonical document.
//! The fixed "shopfront-2026-06-24" consent corpus produces byte-identical signed
//! JSON even when the same corpus results are supplied in a different order.
//! Covers issue #275.

mod signed_json_support;

use signed_json_support::{consent_corpus, shuffled_consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn shuffled_input_yields_the_same_canonical_document() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z".
    let corpus = consent_corpus();
    // Given the corpus results are supplied in a shuffled order.
    let shuffled = shuffled_consent_corpus();

    // When the signed JSON is exported.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let shuffled_document = signed_json::export(&shuffled, &FIXTURE_SIGNING_SEED);

    // Then the document is byte-identical to the one exported from the same results in any other input order.
    assert_eq!(shuffled_document, document);
}
