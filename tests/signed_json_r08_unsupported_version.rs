// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — unsupported schema versions are rejected before signature checking.
//! Covers issue #278.

mod signed_json_support;

use signed_json_support::{consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json::{self, VerifyError};

const SUPPORTED_SCHEMA_VERSION_MEMBER: &str = "\"schema_version\":1";
const UNSUPPORTED_SCHEMA_VERSION_MEMBER: &str = "\"schema_version\":99";
const DECIMAL_SCHEMA_VERSION_MEMBER: &str = "\"schema_version\":1.0";
const EXPONENT_SCHEMA_VERSION_MEMBER: &str = "\"schema_version\":1e2";

#[test]
fn an_unsupported_schema_version_is_rejected_before_the_signature_is_checked() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z".
    let corpus = consent_corpus();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Given a signed JSON export whose "payload.schema.schema_version" is the integer 99.
    let variant = document.replace(
        SUPPORTED_SCHEMA_VERSION_MEMBER,
        UNSUPPORTED_SCHEMA_VERSION_MEMBER,
    );
    assert!(
        variant.contains(UNSUPPORTED_SCHEMA_VERSION_MEMBER),
        "the variant declares schema_version 99 (variant: {variant})"
    );

    // When the document is verified.
    let outcome = signed_json::verify(&variant);

    // Then verification is rejected as "unsupported version".
    assert_eq!(outcome, Err(VerifyError::UnsupportedVersion));

    // And the rejection is not reported as an invalid signature.
    assert_ne!(outcome, Err(VerifyError::InvalidSignature));
}

#[test]
fn a_non_integer_schema_version_token_is_rejected_before_signature_checking() {
    let corpus = consent_corpus();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    for invalid_member in [
        DECIMAL_SCHEMA_VERSION_MEMBER,
        EXPONENT_SCHEMA_VERSION_MEMBER,
    ] {
        let variant = document.replace(SUPPORTED_SCHEMA_VERSION_MEMBER, invalid_member);

        let outcome = signed_json::verify(&variant);

        assert_eq!(
            outcome,
            Err(VerifyError::UnsupportedVersion),
            "schema_version token {invalid_member} is not accepted as integer 1"
        );
        assert_ne!(outcome, Err(VerifyError::InvalidSignature));
    }
}

#[test]
fn only_payload_schema_schema_version_satisfies_the_version_gate() {
    let corpus = consent_corpus();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let unsupported_payload_version = document.replace(
        SUPPORTED_SCHEMA_VERSION_MEMBER,
        UNSUPPORTED_SCHEMA_VERSION_MEMBER,
    );
    let variant = unsupported_payload_version.replacen(
        "{\"payload\":",
        "{\"schema_version\":1,\"payload\":",
        1,
    );

    let outcome = signed_json::verify(&variant);

    assert_eq!(
        outcome,
        Err(VerifyError::UnsupportedVersion),
        "a decoy top-level schema_version must not satisfy payload.schema.schema_version"
    );
    assert_ne!(outcome, Err(VerifyError::InvalidSignature));
}
