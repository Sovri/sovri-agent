// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 — re-exporting the same corpus yields identical record ids. Two signed
//! exports of the persisted "shopfront-2026-06-24" run carry the same id on every
//! record — scan, framework, control, rule, result, gap, and evidence — because
//! the ids derive only from stable corpus keys, with no wall-clock or randomness.
//! Covers issue #257.

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

/// Each record id the export carries, as the payload section it is emitted under
/// and the member it is filed under — the scan, framework, control, rule, result,
/// gap, and evidence ids two re-exports must agree on.
const RECORD_IDS: [(&str, &str); 7] = [
    ("scan", "id"),
    ("frameworks", "id"),
    ("controls", "id"),
    ("results", "id"),
    ("results", "rule_id"),
    ("gaps", "id"),
    ("evidence", "id"),
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
fn re_exporting_the_same_corpus_yields_identical_record_ids() {
    // Given a signed JSON export of the "shopfront-2026-06-24" corpus.
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
    let first = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // And a second signed JSON export of the same corpus.
    let second = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then every record id in the second export equals the matching record id in
    // the first.
    for (section, key) in RECORD_IDS {
        let first_id = string_member(section_value(&first, section), key);
        let second_id = string_member(section_value(&second, section), key);
        assert!(
            first_id.is_some(),
            "the {section} record carries a {key} to compare (first: {first})"
        );
        assert_eq!(
            first_id, second_id,
            "the {section} record's {key} is identical across re-exports"
        );
    }

    // And, more strongly, the whole document is byte-identical, which entails every
    // record id matches — the export is deterministic in the corpus alone.
    assert_eq!(
        first, second,
        "re-exporting the same corpus yields a byte-identical document"
    );
}
