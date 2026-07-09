// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 - the public key embedded in the signed JSON export is sufficient to
//! verify the export. Covers issue #285.

mod signed_json_support;

use signed_json_support::{consent_corpus, section_value, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn the_public_key_alone_is_sufficient_to_verify_the_export() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);

    // The only verification key available to verify() is the public key carried
    // inside the document's verification block.
    let verification = section_value(&document, "verification");
    let public_key =
        string_member(verification, "public_key").expect("the export embeds a public key");
    assert!(
        !public_key.is_empty(),
        "the export carries a non-empty public key"
    );

    // When the document is verified using only its embedded public key,
    // Then verification succeeds.
    assert_eq!(signed_json::verify(&document), Ok(()));
}
