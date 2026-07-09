// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 (technical) — swapping the embedded public key makes verification fail.
//! Replacing a signed export's embedded verification key with a different valid
//! Ed25519 public key breaks verification: the signature no longer matches the
//! embedded key over the (now changed) canonical bytes, so `verify()` rejects the
//! document as an invalid signature. Covers issue #261.

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

/// A second fixed, non-production Ed25519 signing seed, distinct from the fixture
/// seed. Signing the same corpus with it yields a different valid public key to
/// swap in — the test needs a different key, not a coupling to `ed25519-dalek`.
const OTHER_SIGNING_SEED: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
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

/// The shopfront consent corpus the R-04 Background exports.
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

/// Returns the hex of the public key embedded in the document's verification block.
fn public_key_hex(document: &str) -> &str {
    let anchor = "\"public_key\":\"";
    let start = document
        .find(anchor)
        .expect("the document has a public_key member")
        + anchor.len();
    let len = document[start..]
        .find('"')
        .expect("the public_key hex is closed");
    &document[start..start + len]
}

#[test]
fn swapping_the_embedded_public_key_fails_verification() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus
    // produced with the fixture's test Ed25519 key.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);

    // When the embedded public key is replaced with a different valid Ed25519 public
    // key — the key from signing the same corpus with a second distinct seed.
    let other = signed_json::export(&consent_corpus(), &OTHER_SIGNING_SEED);
    let original_key = public_key_hex(&document);
    let other_key = public_key_hex(&other);
    assert_ne!(
        original_key, other_key,
        "the two seeds produce different public keys"
    );
    let swapped = document.replace(original_key, other_key);
    assert_ne!(
        swapped, document,
        "swapping the embedded public key changes the document"
    );

    // And the document is verified, Then verification is rejected as "invalid
    // signature".
    assert_eq!(
        signed_json::verify(&swapped),
        Err(VerifyError::InvalidSignature),
        "swapping the embedded public key is rejected as an invalid signature"
    );
}
