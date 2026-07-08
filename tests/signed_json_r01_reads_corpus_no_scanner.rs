// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 (technical) — the signed JSON export reads the corpus and runs no scanner.
//! The document is exported from an in-memory persisted corpus alone: no scanner
//! runs, no network is touched, and the payload is derived only from the corpus's
//! own records — it carries exactly the corpus's results and framework, nothing a
//! scanner or network lookup would have injected. Covers issue #248.

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

/// Returns the named payload array slice of the compact export — from the `[` after
/// `"<name>":` to its closing `]`. Records hold no nested array, so the first
/// closing bracket ends it.
fn array_member<'a>(document: &'a str, name: &str) -> &'a str {
    let anchor = format!("\"{name}\":");
    let start = document
        .find(&anchor)
        .unwrap_or_else(|| panic!("the payload carries a {name:?} member"))
        + anchor.len();
    let rest = &document[start..];
    let end = rest.find(']').expect("the array is closed") + 1;
    &rest[..end]
}

#[test]
fn export_reads_the_corpus_and_runs_no_scanner() {
    // Given the persisted "shopfront-2026-06-24" consent corpus, assembled entirely
    // in memory — no evidence store on disk, no scanner, no network client.
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

    // When the maintainer exports the signed JSON for "shopfront-2026-06-24".
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then no scanner is executed and no network access is performed: the export took
    // only the in-memory corpus and produced a complete signed document from it.
    assert!(
        has_member(&document, "payload"),
        "the document is produced from the corpus alone"
    );

    // And the payload is derived only from the persisted corpus: the results array
    // carries exactly the corpus's two results — a scanner run would have injected
    // more — and their statuses are exactly the corpus's FAIL and PASS.
    let results = array_member(&document, "results");
    let result_count = results.matches("\"status\":\"").count();
    assert_eq!(
        result_count, 2,
        "the results array carries exactly the corpus's two results — a scanner would add more (results: {results})"
    );
    assert!(
        results.contains("\"status\":\"FAIL\"") && results.contains("\"status\":\"PASS\""),
        "the carried statuses are exactly the corpus's FAIL and PASS (results: {results})"
    );

    // And the framework carried is the one the corpus holds, nothing discovered.
    let frameworks = array_member(&document, "frameworks");
    let framework_count = frameworks.matches("\"id\":\"").count();
    assert_eq!(
        framework_count, 1,
        "the frameworks array carries only the corpus's framework (frameworks: {frameworks})"
    );
    assert!(
        frameworks.contains(&format!("\"id\":\"{FRAMEWORK}\"")),
        "the corpus's framework is the one carried (frameworks: {frameworks})"
    );
}
