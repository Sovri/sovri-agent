// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 — each record type exposes its known stable id. A signed export of the
//! persisted "shopfront-2026-06-24" run carries the run's own id on the scan
//! record and the known framework, control, rule, and evidence ids on their
//! records, so a downstream system can key off each. Covers issue #255.

mod signed_json_support;

use signed_json_support::FIXTURE_SIGNING_SEED;
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, carried verbatim from the Background.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The stable id of the compliance run the scan record carries.
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
/// The rule whose FAIL result the run records.
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The stable id of the evidence record the run collected.
const EVIDENCE_ID: &str = "ev-0001";

/// Each record type the Scenario Outline enumerates, as the payload section it is
/// emitted under, the member the record files its id under, and its known id.
const KNOWN_IDS: [(&str, &str, &str); 5] = [
    ("scan", "id", RUN_ID),
    ("frameworks", "id", FRAMEWORK),
    ("controls", "id", CONTROL),
    ("results", "rule_id", TRACKER_RULE),
    ("evidence", "id", EVIDENCE_ID),
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
fn each_record_type_exposes_its_known_stable_id() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24"
    // (framework gdpr-eprivacy, control consent.tracker.prior-consent, a FAIL result
    // for the tracker rule, and the ev-0001 evidence) And a signed JSON export of it.
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

    // Then the "<record>" record carries id "<id>", for each known record.
    for (section, key, id) in KNOWN_IDS {
        let record = section_value(&document, section);
        let known_id = format!("\"{key}\":\"{id}\"");
        assert!(
            record.contains(&known_id),
            "the {section} record carries its known id {id:?} (record: {record})"
        );
    }
}
