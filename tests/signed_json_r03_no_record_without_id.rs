// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 (violation) — no record is emitted without an id. A signed export of the
//! persisted "shopfront-2026-06-24" run, whose FAIL result produces a gap, carries
//! a non-empty id on every record — framework, control, rule, result, gap,
//! evidence, and scan — so a downstream system can key off each one. Covers issue
//! #258.

mod signed_json_support;

use signed_json_support::{string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, carried verbatim from the Background.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The stable id of the compliance run.
const RUN_ID: &str = "shopfront-2026-06-24";
/// The framework the consent corpus covers.
const FRAMEWORK: &str = "gdpr-eprivacy";
/// The consent framework's catalog version.
const FRAMEWORK_VERSION: &str = "2016-679";
/// The consent framework's source URL.
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
/// The single control the corpus catalogues.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The catalogued title of that control.
const CONTROL_TITLE: &str = "Prior consent for tracker access";
/// The non-CWE framework reference the consent control maps to.
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
/// The rule whose FAIL result produces the gap.
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The stable id of the evidence record the run collected.
const EVIDENCE_ID: &str = "ev-0001";

/// Every record type that must carry a non-empty id, as the scenario's record
/// name, the payload section it is emitted under, and the member its id is filed
/// under. The rule record's id is the `rule_id` a result carries.
const RECORD_IDS: [(&str, &str, &str); 7] = [
    ("framework", "frameworks", "id"),
    ("control", "controls", "id"),
    ("rule", "results", "rule_id"),
    ("result", "results", "id"),
    ("gap", "gaps", "id"),
    ("evidence", "evidence", "id"),
    ("scan", "scan", "id"),
];

/// Builds one consent `ControlResult` for `rule_id` at `status`, carrying the
/// control's catalogued severity, weight, and evidence id from the Background.
fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

/// Returns the JSON value of the top-level payload member `name` — the balanced
/// `{...}` object or `[...]` array following `"name":`. Nesting depth is tracked
/// through strings, so the matching close delimiter, not one inside a value, ends
/// the slice.
fn section_value<'a>(document: &'a str, name: &str) -> &'a str {
    let anchor = format!("\"{name}\":");
    let start = document
        .find(&anchor)
        .unwrap_or_else(|| panic!("the payload has a {name:?} member"))
        + anchor.len();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in document[start..].char_indices() {
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
                    return &document[start..start + offset + ch.len_utf8()];
                }
            }
            _ => {}
        }
    }
    &document[start..]
}

#[test]
fn no_record_is_emitted_without_a_non_empty_id() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24"
    // whose FAIL result on consent.tracker.prior-consent produces a gap, And a signed
    // JSON export of that corpus.
    let corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
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
        .with_evidence(EVIDENCE_ID, "dist/main.js");
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then every framework, control, rule, result, gap, evidence, and scan record
    // has a non-empty id.
    for (record, section, key) in RECORD_IDS {
        let slice = section_value(&document, section);
        let id = string_member(slice, key).unwrap_or_default();
        assert!(
            !id.is_empty(),
            "the {record} record has a non-empty id (section {section:?}: {slice})"
        );
    }
}
