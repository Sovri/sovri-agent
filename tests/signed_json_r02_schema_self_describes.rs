// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — the document self-describes its schema format and version. A signed
//! export of the persisted "shopfront-2026-06-24" consent corpus carries
//! `payload.schema.format` equal to "sovri.compliance-export/v1" and
//! `payload.schema.schema_version` equal to the integer 1 — a JSON number, not a
//! quoted string — so a consumer can tell which schema it is reading and gate on
//! the version. Covers issue #250.

mod signed_json_support;

use signed_json_support::{string_member, FIXTURE_SIGNING_SEED};
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

/// The self-describing schema format the export declares.
const SCHEMA_FORMAT: &str = "sovri.compliance-export/v1";

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

/// Returns the JSON integer value of a `"name":<digits>` member — the unquoted
/// digit run after the key — or `None` if the member is absent or a quoted string.
///
/// A quoted value (`"name":"1"`) is a JSON string, so it yields `None`; only an
/// unquoted digit run is read, which is how an integer member is distinguished
/// from a string one.
fn integer_member<'a>(document: &'a str, name: &str) -> Option<&'a str> {
    let anchor = format!("\"{name}\":");
    let start = document.find(&anchor)? + anchor.len();
    let rest = &document[start..];
    if rest.starts_with('"') {
        return None;
    }
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

#[test]
fn the_document_self_describes_its_schema_format_and_version() {
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

    // Then member "payload.schema.format" equals "sovri.compliance-export/v1".
    assert_eq!(
        string_member(&document, "format").as_deref(),
        Some(SCHEMA_FORMAT),
        "payload.schema.format is the declared export format (document: {document})"
    );

    // And member "payload.schema.schema_version" equals the integer 1.
    assert_eq!(
        integer_member(&document, "schema_version"),
        Some("1"),
        "payload.schema.schema_version is the integer 1, not a quoted string (document: {document})"
    );
}
