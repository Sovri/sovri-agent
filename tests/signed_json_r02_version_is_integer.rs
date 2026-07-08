// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 (technical) — the schema version is a JSON integer, not a string. A signed
//! export of the persisted "shopfront-2026-06-24" consent corpus renders
//! `payload.schema.schema_version` as the unquoted JSON number `1`, never the
//! quoted string `"1"`, so a consumer can gate on a monotonic integer rather than
//! parse a free-form string. Covers issue #252.

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

/// The schema version rendered as an unquoted JSON number — the integer form.
const SCHEMA_VERSION_NUMBER: &str = "\"schema_version\":1";
/// The schema version rendered as a quoted JSON string — the form the export must
/// never emit.
const SCHEMA_VERSION_STRING: &str = "\"schema_version\":\"1\"";

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

#[test]
fn the_schema_version_is_an_integer_not_a_string() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
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
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then member "payload.schema.schema_version" is a JSON number.
    assert!(
        document.contains(SCHEMA_VERSION_NUMBER),
        "schema_version is rendered as the unquoted JSON number 1 (document: {document})"
    );

    // And it is not the JSON string "1".
    assert!(
        !document.contains(SCHEMA_VERSION_STRING),
        "schema_version is not the quoted string \"1\" (document: {document})"
    );
}
