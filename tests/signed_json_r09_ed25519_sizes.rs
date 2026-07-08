// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 — the signed JSON export carries Ed25519-sized public key and signature
//! fields. Covers issue #283.

mod signed_json_support;

use signed_json_support::{consent_corpus, section_value, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

/// Returns the byte length of a hex-encoded string, or `None` when the input is
/// odd-length or contains a non-hex character.
fn hex_byte_len(value: &str) -> Option<usize> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.len() / 2)
}

#[test]
fn the_signature_and_public_key_have_ed25519_sizes() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);
    let verification = section_value(&document, "verification");

    // Then "verification" carries a 32-byte public key.
    let public_key = string_member(verification, "public_key").unwrap_or_default();
    assert_eq!(
        hex_byte_len(&public_key),
        Some(32),
        "verification.public_key is a valid hex-encoded 32-byte Ed25519 public key"
    );

    // And member "signature" is a 64-byte Ed25519 signature.
    let signature = string_member(&document, "signature").unwrap_or_default();
    assert_eq!(
        hex_byte_len(&signature),
        Some(64),
        "signature is a valid hex-encoded 64-byte Ed25519 signature"
    );
}
