// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 — the document verifies offline from its embedded metadata alone. With no
//! external keyring and no network access, a signed export of the persisted
//! "shopfront-2026-06-24" consent corpus verifies using only its own embedded
//! verification metadata: `verify()` takes just the document string and reads the
//! public key embedded in it. Covers issue #263.

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
/// The stable id of the evidence record the run collected.
const EVIDENCE_ID: &str = "ev-0001";

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

/// The shopfront consent corpus the R-05 Background exports.
fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
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
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass))
        .with_evidence(EVIDENCE_ID, "dist/main.js")
}

/// Returns the JSON value of the top-level payload member `name` — the balanced
/// `{...}` object or `[...]` array following `"name":`. Nesting depth is tracked
/// through strings, so the matching close delimiter, not one inside a value, ends
/// the slice.
fn section_value<'a>(document: &'a str, name: &str) -> &'a str {
    let anchor = format!("\"{name}\":");
    let start = document
        .find(&anchor)
        .unwrap_or_else(|| panic!("the document has a {name:?} member"))
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
fn the_document_verifies_offline_from_its_embedded_metadata_alone() {
    // Given no external keyring and no network access are available: verify() takes
    // only the document string — the API has no key argument and performs no I/O.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);

    // The only verification key available is the one embedded in the document.
    let verification = section_value(&document, "verification");
    let embedded_key = string_member(verification, "public_key").unwrap_or_default();
    assert!(
        !embedded_key.is_empty(),
        "the document embeds its own public verification key (verification: {verification})"
    );

    // When the document is verified using only its own embedded metadata,
    // Then verification succeeds.
    let outcome = signed_json::verify(&document);
    assert!(
        outcome.is_ok(),
        "the document verifies offline from its embedded metadata alone (outcome: {outcome:?})"
    );
}
