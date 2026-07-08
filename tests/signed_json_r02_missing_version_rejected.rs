// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 (violation) — a document with no schema version is not a valid export.
//! When a signed JSON document is missing its `payload.schema.schema_version`
//! member, verification rejects it as an unsupported version — a distinct,
//! well-typed failure the verifier reaches before any other check. Covers issue
//! #254.

mod signed_json_support;

use signed_json_support::FIXTURE_SIGNING_SEED;
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json::{self, VerifyError};
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

/// The canonical schema-version member the exporter emits, stripped to build a
/// document that declares no version. `format` sorts before `schema_version`, so
/// the version member is preceded by a comma in the canonical schema object.
const SCHEMA_VERSION_MEMBER: &str = ",\"schema_version\":1";

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
fn a_document_with_no_schema_version_is_rejected() {
    // Given a signed JSON document with no "payload.schema.schema_version" member:
    // a normal export of the shopfront corpus with its version member stripped.
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
    let variant = document.replace(SCHEMA_VERSION_MEMBER, "");
    assert!(
        !variant.contains("schema_version"),
        "the variant document declares no schema_version member (variant: {variant})"
    );

    // When the document is verified, Then verification is rejected as "unsupported
    // version".
    assert_eq!(
        signed_json::verify(&variant),
        Err(VerifyError::UnsupportedVersion),
        "a document with no schema version is rejected as an unsupported version"
    );
}
