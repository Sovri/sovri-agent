// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — unsupported signature algorithms are rejected explicitly. Covers issue
//! #279.

mod signed_json_support;

use serde_json::Value;
use signed_json_support::{consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

const UNSUPPORTED_ALGORITHM: &str = "RSA";
const UNSUPPORTED_ALGORITHM_MESSAGE: &str =
    "the export declares an unsupported signature algorithm";

#[test]
fn an_unsupported_signature_algorithm_is_rejected() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z".
    let corpus = consent_corpus();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Given a signed JSON export whose "verification.algorithm" is "RSA".
    let mut variant: Value =
        serde_json::from_str(&document).expect("the signed JSON export parses as JSON");
    let supported_algorithm = variant
        .get("verification")
        .and_then(|verification| verification.get("algorithm"))
        .and_then(Value::as_str)
        .expect("the signed JSON export declares its supported algorithm")
        .to_owned();
    {
        let verification = variant
            .get_mut("verification")
            .and_then(Value::as_object_mut)
            .expect("the signed JSON export carries verification metadata");
        verification.insert(
            "algorithm".to_owned(),
            Value::String(UNSUPPORTED_ALGORITHM.to_owned()),
        );
        assert_eq!(
            verification.get("algorithm").and_then(Value::as_str),
            Some(UNSUPPORTED_ALGORITHM),
            "the variant declares RSA as its verification algorithm"
        );
    }
    variant
        .as_object_mut()
        .expect("the signed JSON export is a top-level object")
        .insert("algorithm".to_owned(), Value::String(supported_algorithm));
    let variant = serde_json::to_string(&variant).expect("the RSA variant serializes as JSON");

    // When the document is verified.
    let rejection = signed_json::verify(&variant).expect_err("RSA is not a supported algorithm");

    // Then verification is rejected as "unsupported algorithm".
    assert_eq!(rejection.to_string(), UNSUPPORTED_ALGORITHM_MESSAGE);
}
