// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 - the signed JSON export never embeds private key material. Covers
//! issue #284.

mod signed_json_support;

use serde_json::{json, Value};
use signed_json_support::{consent_corpus, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;
use std::fmt::Write as _;

const FORBIDDEN_MEMBERS: [&str; 3] = ["private_key", "secret_key", "seed"];

/// Returns true when a parsed JSON value contains an object member named
/// `member` anywhere in the document.
fn contains_member_named(value: &Value, member: &str) -> bool {
    match value {
        Value::Object(members) => {
            members.contains_key(member)
                || members
                    .values()
                    .any(|child| contains_member_named(child, member))
        }
        Value::Array(values) => values
            .iter()
            .any(|child| contains_member_named(child, member)),
        _ => false,
    }
}

/// Returns true when any string value in a parsed JSON value contains `needle`.
fn string_values_contain(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Object(members) => members
            .values()
            .any(|child| string_values_contain(child, needle)),
        Value::Array(values) => values
            .iter()
            .any(|child| string_values_contain(child, needle)),
        _ => false,
    }
}

/// Encodes bytes as lowercase hexadecimal, the form the fixture seed would take
/// if it leaked into a signed JSON string value.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

#[test]
fn no_private_key_material_appears_anywhere_in_the_document() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);
    let parsed: Value = serde_json::from_str(&document).expect("the signed export parses as JSON");

    // Then the document contains no "<forbidden_member>" member.
    for forbidden_member in FORBIDDEN_MEMBERS {
        assert!(
            !contains_member_named(&parsed, forbidden_member),
            "the document contains no {forbidden_member:?} member"
        );
    }

    // And no string value in the document contains the fixture's private key.
    let fixture_private_key = to_hex(&FIXTURE_SIGNING_SEED);
    assert!(
        !string_values_contain(&parsed, &fixture_private_key),
        "no string value contains the fixture private key"
    );
}

#[test]
fn string_value_scan_reaches_deeply_nested_arrays() {
    let fixture_private_key = to_hex(&FIXTURE_SIGNING_SEED);
    let nested = json!({
        "payload": [
            [
                "metadata",
                {"values": ["prefix", format!("leaked:{fixture_private_key}")]}
            ]
        ]
    });

    assert!(
        string_values_contain(&nested, &fixture_private_key),
        "nested array string values are included in private key leakage checks"
    );
}
