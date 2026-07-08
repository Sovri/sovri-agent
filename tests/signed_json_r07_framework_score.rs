// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — a framework score reflects its single control result. A signed export
//! of a corpus whose only control has a single PASS or FAIL result carries the
//! gdpr-eprivacy framework score as the exact MAT-87 fixed-decimal percentage
//! string. Covers issue #270.

mod signed_json_support;

use signed_json_support::{section_value, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, carried verbatim from the corpus.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The stable id of the compliance run.
const RUN_ID: &str = "shopfront-2026-06-24";
/// The framework the consent corpus covers.
const FRAMEWORK: &str = "gdpr-eprivacy";
/// The single control the corpus evaluates.
const CONTROL: &str = "consent.tracker.prior-consent";
/// The rule the single result records.
const RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The stable id of the evidence record the result references.
const EVIDENCE_ID: &str = "ev-0001";

/// Builds the corpus's single consent `ControlResult` at `status`, carrying the
/// control's catalogued severity and weight so the SDK can score it.
fn single_result(status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(RULE)
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

/// Builds a single-result corpus for the gdpr-eprivacy consent framework.
fn single_result_corpus(status: Status) -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_control_result(FRAMEWORK, single_result(status))
}

#[test]
fn a_framework_score_reflects_its_single_control_result() {
    for (status, score) in [(Status::Pass, "100.0%"), (Status::Fail, "0.0%")] {
        // Given a compliance corpus whose only control
        // "consent.tracker.prior-consent" has a single "<status>" result.
        let corpus = single_result_corpus(status);

        // And a signed JSON export of that corpus.
        let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
        let scores = section_value(&document, "scores");
        let framework_scores = section_value(scores, "framework");

        // Then the framework score for "gdpr-eprivacy" is "<score>".
        assert!(
            framework_scores.contains(&format!(
                "\"framework_id\":\"{FRAMEWORK}\",\"score\":\"{score}\""
            )),
            "the framework score for {FRAMEWORK} is {score} when the only control is {status:?} \
             (framework scores: {framework_scores})"
        );

        // And that score is a fixed-decimal percentage string, not a JSON number.
        assert_eq!(
            string_member(framework_scores, "score").as_deref(),
            Some(score),
            "the framework score is emitted as a JSON string (framework scores: {framework_scores})"
        );
        assert!(
            !framework_scores.contains(&format!("\"score\":{}", score.trim_end_matches('%'))),
            "the framework score is not emitted as a JSON number (framework scores: {framework_scores})"
        );
    }
}
