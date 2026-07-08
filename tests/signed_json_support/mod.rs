// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-97 signed-JSON export acceptance tests.
//!
//! Holds the non-production signing seed that keeps the signed artifact
//! byte-stable across runs, plus small readers over the compact canonical JSON
//! the exporter emits. Each `signed_json_*` test binary pulls in what it needs;
//! not every binary uses every helper.
#![allow(dead_code)]

use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

/// A fixed, non-production Ed25519 signing seed.
///
/// Committed only so the signed export is deterministic and snapshot-testable.
/// It signs test fixtures and nothing else — never a real compliance artifact.
pub const FIXTURE_SIGNING_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const RUN_ID: &str = "shopfront-2026-06-24";
const FRAMEWORK: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const CONTROL: &str = "consent.tracker.prior-consent";
const CONTROL_TITLE: &str = "Prior consent for tracker access";
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const CONTROL_SEVERITY: &str = "major";
const CONTROL_WEIGHT: u32 = 8;
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const EVIDENCE_ID: &str = "ev-0001";
const EXECUTION_METADATA: &str = "engine_version=0.3.0";

fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
        .status(status)
        .severity(CONTROL_SEVERITY)
        .weight(CONTROL_WEIGHT)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata(EXECUTION_METADATA);
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

/// Returns the fixed `shopfront-2026-06-24` consent corpus used by MAT-97 signed
/// JSON acceptance tests.
#[must_use]
pub fn consent_corpus() -> Corpus {
    consent_corpus_with_results(&[(TRACKER_RULE, Status::Fail), (CMP_RULE, Status::Pass)])
}

/// Returns the fixed consent corpus with the same results as [`consent_corpus`],
/// supplied in the opposite order.
#[must_use]
pub fn shuffled_consent_corpus() -> Corpus {
    consent_corpus_with_results(&[(CMP_RULE, Status::Pass), (TRACKER_RULE, Status::Fail)])
}

fn consent_corpus_with_results(results: &[(&str, Status)]) -> Corpus {
    let mut corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            CONTROL_SEVERITY,
            CONTROL_WEIGHT,
            CONTROL_REFERENCE,
        );
    for &(rule_id, status) in results {
        corpus = corpus.with_control_result(FRAMEWORK, consent_result(rule_id, status));
    }
    corpus.with_evidence(EVIDENCE_ID, "dist/main.js")
}

/// Returns true when the compact JSON document carries a top-level-visible
/// member named `name` (matched as `"name":`).
///
/// Adequate for the exporter's canonical, space-free output where a member name
/// appears exactly where the document places it.
#[must_use]
pub fn has_member(doc: &str, name: &str) -> bool {
    doc.contains(&format!("\"{name}\":"))
}

/// Returns the string value of the first `"name":"..."` member in a compact
/// JSON document, or `None` if the member is absent or not a string.
///
/// Reads until the closing unescaped quote. The exporter emits no whitespace
/// between tokens, so the `"name":"` anchor is exact.
#[must_use]
pub fn string_member(doc: &str, name: &str) -> Option<String> {
    let anchor = format!("\"{name}\":\"");
    let start = doc.find(&anchor)? + anchor.len();
    let mut out = String::new();
    let mut chars = doc[start..].chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                out.push('\\');
                out.push(chars.next()?);
            }
            '"' => return Some(out),
            _ => out.push(ch),
        }
    }
    None
}

/// Returns the JSON value of the member `name` — the balanced `{...}` object or
/// `[...]` array that follows `"name":` in the compact document — so a test can
/// scope an assertion to one section (a payload array, the verification object,
/// and so on).
///
/// Nesting depth is tracked through string values, so the matching close
/// delimiter, not a brace or bracket inside a string, ends the slice. Handles
/// both object and array values, which is why no separate array scoper is needed.
/// Standard-library only.
///
/// # Panics
///
/// Panics when the document carries no `"name":` member, so a test that scopes a
/// missing section fails with a clear message.
#[must_use]
pub fn section_value<'a>(doc: &'a str, name: &str) -> &'a str {
    let anchor = format!("\"{name}\":");
    let start = doc
        .find(&anchor)
        .unwrap_or_else(|| panic!("the document has a {name:?} member"))
        + anchor.len();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in doc[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return &doc[start..start + offset + ch.len_utf8()];
                }
            }
            _ => {}
        }
    }
    &doc[start..]
}

/// Asserts that every JSON object inside `json` emits its member keys in
/// lexicographic order.
///
/// This walks the raw compact JSON text instead of parsing into a map, because a
/// map would erase the key order the exporter actually emitted.
///
/// # Panics
///
/// Panics when `json` is malformed or when any object is not ordered.
pub fn assert_object_keys_are_lexicographic(json: &str) {
    let mut cursor = 0;
    walk_json_value(json, &mut cursor);
    skip_json_whitespace(json, &mut cursor);
    assert_eq!(cursor, json.len(), "the full JSON value was consumed");
}

fn walk_json_value(json: &str, cursor: &mut usize) {
    skip_json_whitespace(json, cursor);
    match json.as_bytes().get(*cursor).copied() {
        Some(b'{') => walk_json_object(json, cursor),
        Some(b'[') => walk_json_array(json, cursor),
        Some(b'"') => {
            read_json_string(json, cursor);
        }
        Some(_) => skip_json_primitive(json, cursor),
        None => panic!("expected a JSON value"),
    }
}

fn walk_json_object(json: &str, cursor: &mut usize) {
    let start = *cursor;
    expect_json_byte(json, cursor, b'{');
    let mut keys = Vec::new();
    skip_json_whitespace(json, cursor);
    if consume_json_byte(json, cursor, b'}') {
        return;
    }

    loop {
        let key = read_json_string(json, cursor);
        keys.push(key);
        expect_json_byte(json, cursor, b':');
        walk_json_value(json, cursor);
        skip_json_whitespace(json, cursor);
        if consume_json_byte(json, cursor, b'}') {
            break;
        }
        expect_json_byte(json, cursor, b',');
    }

    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys,
        sorted,
        "JSON object keys are lexicographic in {}",
        &json[start..*cursor]
    );
}

fn walk_json_array(json: &str, cursor: &mut usize) {
    expect_json_byte(json, cursor, b'[');
    skip_json_whitespace(json, cursor);
    if consume_json_byte(json, cursor, b']') {
        return;
    }

    loop {
        walk_json_value(json, cursor);
        skip_json_whitespace(json, cursor);
        if consume_json_byte(json, cursor, b']') {
            break;
        }
        expect_json_byte(json, cursor, b',');
    }
}

fn read_json_string(json: &str, cursor: &mut usize) -> String {
    expect_json_byte(json, cursor, b'"');
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

fn skip_json_primitive(json: &str, cursor: &mut usize) {
    while let Some(byte) = json.as_bytes().get(*cursor).copied() {
        if matches!(byte, b',' | b']' | b'}') {
            break;
        }
        *cursor += 1;
    }
}

fn skip_json_whitespace(json: &str, cursor: &mut usize) {
    while matches!(
        json.as_bytes().get(*cursor),
        Some(b' ' | b'\n' | b'\r' | b'\t')
    ) {
        *cursor += 1;
    }
}

fn expect_json_byte(json: &str, cursor: &mut usize, expected: u8) {
    skip_json_whitespace(json, cursor);
    assert_eq!(
        json.as_bytes().get(*cursor).copied(),
        Some(expected),
        "expected byte {:?}",
        char::from(expected)
    );
    *cursor += 1;
}

fn consume_json_byte(json: &str, cursor: &mut usize, expected: u8) -> bool {
    skip_json_whitespace(json, cursor);
    if json.as_bytes().get(*cursor).copied() == Some(expected) {
        *cursor += 1;
        true
    } else {
        false
    }
}
