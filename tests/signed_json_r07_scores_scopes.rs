// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — the scores section names every scope and ties the framework score to its
//! framework. A signed export of the persisted "shopfront-2026-06-24" consent
//! corpus carries a `payload.scores` object with a control score, a framework
//! score, and an environment score, and the framework score is tied to framework
//! "gdpr-eprivacy". Covers issue #269.

mod signed_json_support;

use signed_json_support::{
    consent_corpus, has_member, section_value, string_member, CMP_RULE, FIXTURE_SIGNING_SEED,
    FRAMEWORK, TRACKER_RULE,
};
use sovri_agent::signed_json;

/// The three score scopes the section names.
const SCORE_SCOPES: [&str; 3] = ["control", "framework", "environment"];

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

    // And each control score identifies the rule that produced that score.
    let control_scores = section_value(scores, "control");
    for rule_id in [TRACKER_RULE, CMP_RULE] {
        assert!(
            control_scores.contains(&format!("\"rule_id\":\"{rule_id}\"")),
            "the control score records carry rule id {rule_id} (control scores: {control_scores})"
        );
    }
}
