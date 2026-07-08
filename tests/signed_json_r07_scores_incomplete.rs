// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — an ERROR result marks signed JSON scores incomplete. A signed export of
//! a corpus containing an ERROR control result carries an explicit incomplete
//! marker under `payload.scores`. Covers issue #271.

mod signed_json_support;

use signed_json_support::{section_value, FIXTURE_SIGNING_SEED};
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
/// The rule the errored result records.
const RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The catalogued severity of the consent control.
const SEVERITY: &str = "major";
/// The stable id of the evidence record the result references.
const EVIDENCE_ID: &str = "ev-0001";

/// Builds the corpus's errored consent `ControlResult`, carrying the control's
/// catalogued severity and weight so the SDK can mark the score incomplete.
fn error_result() -> ControlResult {
    ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(RULE)
        .status(Status::Error)
        .severity(SEVERITY)
        .weight(8)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0")
        .reason("Consent evidence collection errored.")
        .build()
        .expect("the consent fixture result validates")
}

#[test]
fn an_error_result_marks_the_scores_incomplete() {
    // Given a compliance corpus that contains a control result with status "ERROR".
    let corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_control_result(FRAMEWORK, error_result());

    // And a signed JSON export of that corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then "payload.scores" is marked incomplete.
    let scores = section_value(&document, "scores");
    assert!(
        scores.contains("\"incomplete\":true"),
        "expected scores to contain '\"incomplete\":true' after an ERROR result, got: {scores}"
    );
}
