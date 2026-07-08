// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — unsupported signature algorithms are rejected explicitly. Covers issue
//! #279.

mod signed_json_support;

use signed_json_support::{consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

const ED25519_ALGORITHM_MEMBER: &str = "\"algorithm\":\"Ed25519\"";
const RSA_ALGORITHM_MEMBER: &str = "\"algorithm\":\"RSA\"";
const UNSUPPORTED_ALGORITHM_MESSAGE: &str =
    "the export declares an unsupported signature algorithm";

#[test]
fn an_unsupported_signature_algorithm_is_rejected() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z".
    let corpus = consent_corpus();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Given a signed JSON export whose "verification.algorithm" is "RSA".
    let variant = document.replace(ED25519_ALGORITHM_MEMBER, RSA_ALGORITHM_MEMBER);
    assert!(
        variant.contains(RSA_ALGORITHM_MEMBER),
        "the variant declares RSA as its verification algorithm (variant: {variant})"
    );

    // When the document is verified.
    let rejection = signed_json::verify(&variant).expect_err("RSA is not a supported algorithm");

    // Then verification is rejected as "unsupported algorithm".
    assert_eq!(rejection.to_string(), UNSUPPORTED_ALGORITHM_MESSAGE);
}
