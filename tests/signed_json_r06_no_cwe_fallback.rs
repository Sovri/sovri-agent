// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 (violation) — no string anywhere in the payload falls back to a CWE
//! reference. A signed export of the persisted "shopfront-2026-06-24" consent
//! corpus carries only the catalogued non-CWE references verbatim, so no payload
//! string begins with "CWE-", and the gap for consent.tracker.prior-consent shows
//! its own `gdpr-eprivacy:2016-679:Art.7` reference. Covers issue #267.

mod signed_json_support;

use signed_json_support::{section_value, string_member, FIXTURE_SIGNING_SEED};
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
/// The single control the corpus catalogues, whose gap carries the reference.
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

/// The shopfront consent corpus: the gdpr-eprivacy framework, its
/// consent.tracker.prior-consent control catalogued with its non-CWE reference,
/// the control's FAIL (a gap) and PASS results, and the ev-0001 evidence.
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
fn no_string_in_the_payload_falls_back_to_a_cwe_reference() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);

    // Then no string value in the payload begins with "CWE-": the export emits only
    // verbatim non-CWE references, so "CWE-" appears nowhere in the payload.
    let payload = section_value(&document, "payload");
    assert!(
        !payload.contains("CWE-"),
        "the payload carries no CWE reference (payload: {payload})"
    );

    // And the gap record for "consent.tracker.prior-consent" shows its own non-CWE
    // reference, so the absence of CWE is not just an empty reference.
    let gap = section_value(&document, "gaps");
    assert_eq!(
        string_member(gap, "reference").as_deref(),
        Some(CONTROL_REFERENCE),
        "the gap for {CONTROL} shows its non-CWE reference (gap: {gap})"
    );
}
