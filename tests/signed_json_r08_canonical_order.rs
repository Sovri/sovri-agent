// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 - the canonical payload orders object keys and records deterministically.
//! A signed export of the fixed "shopfront-2026-06-24" consent corpus emits every
//! payload object with lexicographically ordered keys, and orders `payload.results`
//! by control id then rule id. Covers issue #274.

mod signed_json_support;

use serde_json::Value;
use signed_json_support::{consent_corpus, section_value, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

const CONTROL: &str = "consent.tracker.prior-consent";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";

#[test]
fn the_canonical_payload_orders_object_keys_and_records_deterministically() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at.
    let corpus = consent_corpus();

    // When the signed JSON is exported from the corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let payload = section_value(&document, "payload");

    // Then every JSON object in the payload has its keys in lexicographic order.
    assert_payload_object_keys_are_lexicographic(payload);

    // And "payload.results" entries are ordered by control id then rule id.
    let result_keys = result_sort_keys(section_value(payload, "results"));
    assert_eq!(
        result_keys,
        vec![
            (CONTROL.to_owned(), CMP_RULE.to_owned()),
            (CONTROL.to_owned(), TRACKER_RULE.to_owned()),
        ],
        "payload.results entries are ordered by control id then rule id"
    );
}

fn result_sort_keys(results: &str) -> Vec<(String, String)> {
    let values: Vec<Value> =
        serde_json::from_str(results).expect("payload.results is a JSON array");
    values
        .iter()
        .map(|value| {
            let control_id = value
                .get("control_id")
                .and_then(Value::as_str)
                .expect("a result record carries control_id");
            let rule_id = value
                .get("rule_id")
                .and_then(Value::as_str)
                .expect("a result record carries rule_id");
            (control_id.to_owned(), rule_id.to_owned())
        })
        .collect()
}

fn assert_payload_object_keys_are_lexicographic(payload: &str) {
    let mut cursor = 0;
    walk_value(payload, &mut cursor);
    skip_whitespace(payload, &mut cursor);
    assert_eq!(
        cursor,
        payload.len(),
        "the full payload JSON value was consumed"
    );
}

fn walk_value(json: &str, cursor: &mut usize) {
    skip_whitespace(json, cursor);
    match json.as_bytes().get(*cursor).copied() {
        Some(b'{') => walk_object(json, cursor),
        Some(b'[') => walk_array(json, cursor),
        Some(b'"') => {
            read_string(json, cursor);
        }
        Some(_) => skip_primitive(json, cursor),
        None => panic!("expected a JSON value"),
    }
}

fn walk_object(json: &str, cursor: &mut usize) {
    let start = *cursor;
    expect_byte(json, cursor, b'{');
    let mut keys = Vec::new();
    skip_whitespace(json, cursor);
    if consume_byte(json, cursor, b'}') {
        return;
    }

    loop {
        let key = read_string(json, cursor);
        keys.push(key);
        expect_byte(json, cursor, b':');
        walk_value(json, cursor);
        skip_whitespace(json, cursor);
        if consume_byte(json, cursor, b'}') {
            break;
        }
        expect_byte(json, cursor, b',');
    }

    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys,
        sorted,
        "payload object keys are lexicographic in {}",
        &json[start..*cursor]
    );
}

fn walk_array(json: &str, cursor: &mut usize) {
    expect_byte(json, cursor, b'[');
    skip_whitespace(json, cursor);
    if consume_byte(json, cursor, b']') {
        return;
    }

    loop {
        walk_value(json, cursor);
        skip_whitespace(json, cursor);
        if consume_byte(json, cursor, b']') {
            break;
        }
        expect_byte(json, cursor, b',');
    }
}

fn read_string(json: &str, cursor: &mut usize) -> String {
    expect_byte(json, cursor, b'"');
    let mut value = String::new();
    while let Some(ch) = json[*cursor..].chars().next() {
        *cursor += ch.len_utf8();
        match ch {
            '"' => return value,
            '\\' => {
                let escaped = json[*cursor..]
                    .chars()
                    .next()
                    .expect("escaped JSON string character");
                *cursor += escaped.len_utf8();
                value.push('\\');
                value.push(escaped);
            }
            _ => value.push(ch),
        }
    }
    panic!("unterminated JSON string");
}

fn skip_primitive(json: &str, cursor: &mut usize) {
    while let Some(byte) = json.as_bytes().get(*cursor).copied() {
        if matches!(byte, b',' | b']' | b'}') {
            break;
        }
        *cursor += 1;
    }
}

fn skip_whitespace(json: &str, cursor: &mut usize) {
    while matches!(
        json.as_bytes().get(*cursor),
        Some(b' ' | b'\n' | b'\r' | b'\t')
    ) {
        *cursor += 1;
    }
}

fn expect_byte(json: &str, cursor: &mut usize, expected: u8) {
    skip_whitespace(json, cursor);
    assert_eq!(
        json.as_bytes().get(*cursor).copied(),
        Some(expected),
        "expected byte {:?}",
        char::from(expected)
    );
    *cursor += 1;
}

fn consume_byte(json: &str, cursor: &mut usize, expected: u8) -> bool {
    skip_whitespace(json, cursor);
    if json.as_bytes().get(*cursor).copied() == Some(expected) {
        *cursor += 1;
        true
    } else {
        false
    }
}
