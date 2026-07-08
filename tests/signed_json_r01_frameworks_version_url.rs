// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the frameworks section carries each framework's version and source URL.
//! A signed export of the persisted "shopfront-2026-06-24" consent corpus has a
//! `payload.frameworks` entry for framework "gdpr-eprivacy" that shows its catalog
//! version "2016-679" and its source URL. Covers issue #246.

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

/// Returns the `payload.frameworks` array slice of the compact export — from the
/// `[` after the `"frameworks":` key to its closing `]`. Framework records hold no
/// nested array, so the first closing bracket ends it.
fn frameworks_array(document: &str) -> &str {
    let anchor = "\"frameworks\":";
    let start = document
        .find(anchor)
        .expect("the payload carries a frameworks member")
        + anchor.len();
    let rest = &document[start..];
    let end = rest.find(']').expect("the frameworks array is closed") + 1;
    &rest[..end]
}

#[test]
fn the_frameworks_section_carries_version_and_source_url() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24":
    // the gdpr-eprivacy framework, its consent.tracker.prior-consent control, that
    // control's FAIL and PASS results, and the ev-0001 evidence at dist/main.js.
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

    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let frameworks = frameworks_array(&document);

    // Then the "payload.frameworks" array has an entry for framework "gdpr-eprivacy".
    assert!(
        frameworks.contains(&format!("\"id\":\"{FRAMEWORK}\"")),
        "the frameworks array has an entry for {FRAMEWORK:?} (frameworks: {frameworks})"
    );

    // And that entry shows version "2016-679".
    assert!(
        frameworks.contains(&format!("\"version\":\"{FRAMEWORK_VERSION}\"")),
        "the {FRAMEWORK:?} entry shows version {FRAMEWORK_VERSION:?} (frameworks: {frameworks})"
    );

    // And that entry shows source URL "https://eur-lex.europa.eu/eli/reg/2016/679/oj".
    assert!(
        frameworks.contains(&format!("\"source_url\":\"{FRAMEWORK_URL}\"")),
        "the {FRAMEWORK:?} entry shows source URL {FRAMEWORK_URL:?} (frameworks: {frameworks})"
    );
}
