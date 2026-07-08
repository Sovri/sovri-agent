// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 (technical) — every section stays present, never omitted, on an all-PASS
//! corpus. A signed export of a corpus whose only control is all PASS with no gaps
//! and no evidence still carries a `gaps` member that is an empty array and an
//! `evidence` member that is an empty array, and omits none of the seven required
//! sections. This pins that empty sections are present-but-empty, guarding against
//! a future change that would drop them. Covers issue #247.

mod signed_json_support;

use signed_json_support::{has_member, FIXTURE_SIGNING_SEED};
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
/// The single control the corpus catalogues, whose only result is a PASS.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The catalogued title of that control.
const CONTROL_TITLE: &str = "Prior consent for tracker access";
/// The non-CWE framework reference the consent control maps to.
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
/// The rule whose result passes, so the run records no gap.
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";

/// The seven payload sections that must never be omitted.
const REQUIRED_SECTIONS: [&str; 7] = [
    "scan",
    "frameworks",
    "controls",
    "results",
    "gaps",
    "evidence",
    "scores",
];

/// Builds one consent `ControlResult` for `rule_id` at `status`, carrying the
/// control's catalogued severity, weight, and evidence id.
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

/// Whether the compact export carries `name` as an empty JSON array (`"name":[]`).
fn has_empty_array_member(document: &str, name: &str) -> bool {
    document.contains(&format!("\"{name}\":[]"))
}

#[test]
fn every_section_stays_present_on_an_all_pass_corpus() {
    // Given a compliance corpus whose only control "consent.tracker.prior-consent" is
    // all PASS with no gaps and no evidence.
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
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Pass));

    // And a signed JSON export of that corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then the payload still has a "gaps" member that is an empty array.
    assert!(
        has_empty_array_member(&document, "gaps"),
        "the payload still has an empty gaps array (document: {document})"
    );

    // And the payload still has an "evidence" member that is an empty array.
    assert!(
        has_empty_array_member(&document, "evidence"),
        "the payload still has an empty evidence array (document: {document})"
    );

    // And no required section is omitted from the payload.
    for section in REQUIRED_SECTIONS {
        assert!(
            has_member(&document, section),
            "the payload still carries a {section:?} member (document: {document})"
        );
    }
}
