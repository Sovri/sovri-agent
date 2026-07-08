// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — the scores section names every scope and ties the framework score to its
//! framework. A signed export of the persisted "shopfront-2026-06-24" consent
//! corpus carries a `payload.scores` object with a control score, a framework
//! score, and an environment score, and the framework score is tied to framework
//! "gdpr-eprivacy". Covers issue #269.

mod signed_json_support;

use signed_json_support::{has_member, section_value, string_member, FIXTURE_SIGNING_SEED};
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

/// The three score scopes the section names.
const SCORE_SCOPES: [&str; 3] = ["control", "framework", "environment"];

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

/// The shopfront consent corpus: the gdpr-eprivacy framework, its
/// consent.tracker.prior-consent control, that control's FAIL and PASS results,
/// and the ev-0001 evidence — scored under the gdpr-eprivacy framework.
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

#[test]
fn the_scores_section_names_every_scope_and_ties_the_framework_score_to_its_framework() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);
    let scores = section_value(&document, "scores");

    // Then "payload.scores" carries a control score, a framework score, and an
    // environment score.
    for scope in SCORE_SCOPES {
        assert!(
            has_member(scores, scope),
            "the scores section carries a {scope} score (scores: {scores})"
        );
    }

    // And the framework score is tied to framework "gdpr-eprivacy".
    let framework_scores = section_value(scores, "framework");
    assert!(
        framework_scores.contains(&format!("\"framework_id\":\"{FRAMEWORK}\"")),
        "the framework score is tied to framework {FRAMEWORK} (framework scores: {framework_scores})"
    );
    assert!(
        string_member(framework_scores, "score").is_some(),
        "the framework score record carries a score value (framework scores: {framework_scores})"
    );
}
