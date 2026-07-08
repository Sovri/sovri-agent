// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — an all-PASS corpus still produces a signed document that verifies.
//! Covers issue #277.

mod signed_json_support;

use signed_json_support::{all_pass_consent_corpus_without_evidence, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn an_all_pass_corpus_still_produces_a_signed_document_that_verifies() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z".
    // Given an all-PASS compliance corpus with no gaps and no evidence.
    let corpus = all_pass_consent_corpus_without_evidence();

    // And a signed JSON export of that corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // When the document is verified.
    let outcome = signed_json::verify(&document);

    // Then verification succeeds.
    assert_eq!(outcome, Ok(()));
}
