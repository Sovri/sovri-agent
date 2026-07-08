// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — a valid signature on an untouched export verifies. Covers issue #276.

mod signed_json_support;

use signed_json_support::{consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn a_valid_signature_on_an_untouched_export_verifies() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z".
    let corpus = consent_corpus();

    // Given a signed JSON export of the corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // When the document is verified.
    let outcome = signed_json::verify(&document);

    // Then verification succeeds.
    assert_eq!(outcome, Ok(()));
}
