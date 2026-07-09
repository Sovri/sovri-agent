// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 — the signed JSON export declares Ed25519 as its signature algorithm.
//! Covers issue #282.

mod signed_json_support;

use signed_json_support::{consent_corpus, section_value, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn the_declared_signature_algorithm_is_ed25519() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);
    let verification = section_value(&document, "verification");

    // Then member "verification.algorithm" equals "Ed25519".
    assert_eq!(
        string_member(verification, "algorithm").as_deref(),
        Some("Ed25519"),
        "verification.algorithm declares Ed25519"
    );
}
