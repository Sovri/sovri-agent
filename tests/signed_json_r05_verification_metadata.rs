// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 — the verification block carries algorithm, key id, and an inline public
//! key, and no private key. A signed export of the persisted "shopfront-2026-06-24"
//! consent corpus embeds its own verification metadata — algorithm "Ed25519", a
//! non-empty key id, and the public verification key inline — so a consumer can
//! verify it offline, and no private key material travels. Covers issue #262.

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
/// The signature algorithm the verification block names.
const ALGORITHM: &str = "Ed25519";

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

/// The shopfront consent corpus the R-05 Background exports.
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

/// Encodes bytes as lowercase hexadecimal — the form the raw signing seed would
/// take if it ever leaked into the document.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from_digit(u32::from(byte) >> 4, 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte) & 0x0f, 16).unwrap_or('0'));
    }
    out
}

#[test]
fn the_verification_block_carries_algorithm_key_id_and_inline_public_key() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);
    let verification = section_value(&document, "verification");

    // Then member "verification.algorithm" equals "Ed25519".
    assert_eq!(
        string_member(verification, "algorithm").as_deref(),
        Some(ALGORITHM),
        "verification.algorithm is Ed25519 (verification: {verification})"
    );

    // And "verification" carries a non-empty "key_id".
    let key_id = string_member(verification, "key_id").unwrap_or_default();
    assert!(
        !key_id.is_empty(),
        "verification carries a non-empty key_id (verification: {verification})"
    );

    // And "verification" carries an inline public key.
    let public_key = string_member(verification, "public_key").unwrap_or_default();
    assert!(
        !public_key.is_empty(),
        "verification carries an inline public key (verification: {verification})"
    );

    // And "verification" carries no private key: no private-key member, and the raw
    // signing seed never appears anywhere in the document.
    assert!(
        !document.contains("\"private_key\""),
        "the document carries no private_key member (document: {document})"
    );
    assert!(
        !document.contains("\"secret_key\""),
        "the document carries no secret_key member (document: {document})"
    );
    assert!(
        !document.contains(&to_hex(&FIXTURE_SIGNING_SEED)),
        "the raw signing seed never appears in the document"
    );
}
