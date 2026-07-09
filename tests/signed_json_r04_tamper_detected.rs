// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 (violation) — tampering with the payload makes verification fail. Any
//! change to the canonical payload of a signed export — a flipped result status,
//! an altered evidence record, a changed control id, or a mutated scores section —
//! breaks the Ed25519 signature, so `verify()` rejects the document as an invalid
//! signature. Covers issue #260.

mod signed_json_support;

use signed_json_support::FIXTURE_SIGNING_SEED;
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json::{self, VerifyError};
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

/// Each tamper vector: a description, the substring changed, and its replacement.
///
/// The status-flip and control-id changes are the literal scenario fields. The
/// evidence-integrity change targets the evidence integrity digest, which is not
/// yet populated in the export (it lands in R-08), so it tampers the evidence
/// record instead. The scores change injects a member into the scores object. The
/// signature check is field-agnostic, so any payload change is detected.
const TAMPER_VECTORS: [(&str, &str, &str); 4] = [
    (
        "a result status is flipped from FAIL to PASS",
        "\"status\":\"FAIL\"",
        "\"status\":\"PASS\"",
    ),
    ("the evidence record is altered", "ev-0001", "ev-0002"),
    (
        "the control id is changed",
        "consent.tracker.prior-consent",
        "consent.tracker.other",
    ),
    (
        "the scores section is altered",
        "\"scores\":{",
        "\"scores\":{\"x\":0,",
    ),
];

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

#[test]
fn tampering_with_the_payload_makes_verification_fail() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let corpus = Corpus::new(EXECUTED_AT)
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
        .with_evidence(EVIDENCE_ID, "dist/main.js");
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // When the payload is changed and the document is verified, Then verification is
    // rejected as "invalid signature", for each tamper vector.
    for (change, from, to) in TAMPER_VECTORS {
        let tampered = document.replace(from, to);
        assert_ne!(
            tampered, document,
            "the tamper vector changes the document ({change})"
        );
        assert_eq!(
            signed_json::verify(&tampered),
            Err(VerifyError::InvalidSignature),
            "verification is rejected as invalid signature after {change}"
        );
    }
}
