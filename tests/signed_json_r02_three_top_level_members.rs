// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — the document exposes exactly the three documented top-level members. A
//! signed export of the persisted "shopfront-2026-06-24" consent corpus is a JSON
//! object whose members are exactly "payload", "verification", and "signature" —
//! no more, no fewer — so a consumer reads a stable, documented envelope. Covers
//! issue #251.

mod signed_json_support;

use signed_json_support::FIXTURE_SIGNING_SEED;
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, carried verbatim from the Background.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The framework the consent corpus covers.
const FRAMEWORK: &str = "gdpr-eprivacy";
/// The consent framework's catalog version.
const FRAMEWORK_VERSION: &str = "2016-679";
/// The consent framework's source URL.
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
/// The single control both consent results evaluate.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The catalogued title of that control.
const CONTROL_TITLE: &str = "Prior consent for tracker access";
/// The non-CWE framework reference the consent control maps to.
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
/// The rule that fails: a non-essential tracker with no consent evidence.
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The rule that passes: the consent-management platform is configured.
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";

/// The three top-level members the export documents, sorted as the canonical
/// serializer emits them.
const DOCUMENTED_MEMBERS: [&str; 3] = ["payload", "signature", "verification"];

/// Builds one consent `ControlResult` for `rule_id` at `status`, carrying the
/// control's catalogued severity, weight, and evidence id from the Background.
fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

/// Returns the keys of the top-level JSON object in `document`, sorted.
///
/// Scans the compact document tracking nesting depth so only keys at the root
/// object's depth are collected: a `{` inside a nested value never counts, and a
/// key is a string in key position (at depth 1, immediately followed by a colon),
/// which excludes a string *value* at depth 1 such as the top-level signature.
fn top_level_members(document: &str) -> Vec<String> {
    let bytes = document.as_bytes();
    let mut members = Vec::new();
    let mut depth: i32 = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                if depth == 1 && end + 1 < bytes.len() && bytes[end + 1] == b':' {
                    members.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
                }
                index = end + 1;
            }
            b'{' | b'[' => {
                depth += 1;
                index += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    members.sort();
    members
}

#[test]
fn the_document_exposes_exactly_the_three_top_level_members() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let corpus = Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass))
        .with_evidence("ev-0001", "dist/main.js");
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then the document is a JSON object whose members are exactly "payload",
    // "verification", and "signature" — no more, no fewer.
    let members = top_level_members(&document);
    assert_eq!(
        members, DOCUMENTED_MEMBERS,
        "the document's top-level members are exactly payload, verification, and signature (members: {members:?})"
    );
}
