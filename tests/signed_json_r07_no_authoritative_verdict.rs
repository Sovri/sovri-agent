// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — the signed JSON export carries no authoritative verdict derived from
//! scores. Scores are present only as the `payload.scores` posture summary; the
//! payload has no overall compliant or risk-rating member. Covers issue #272.

mod signed_json_support;

use signed_json_support::{consent_corpus, has_member, section_value, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

/// Counts exact member-name occurrences in the compact canonical JSON text.
fn member_count(doc: &str, name: &str) -> usize {
    doc.match_indices(&format!("\"{name}\":")).count()
}

/// Asserts the payload does not carry an authoritative summary member.
fn assert_payload_lacks_member(payload: &str, member: &str, description: &str) {
    assert!(
        !has_member(payload, member),
        "the payload has no {description} member (payload: {payload})"
    );
}

#[test]
fn the_export_carries_no_authoritative_verdict_derived_from_scores() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);
    let payload = section_value(&document, "payload");

    // Then the payload has no overall "compliant" verdict member.
    assert_payload_lacks_member(payload, "compliant", "overall compliant verdict");

    // And the payload has no "risk_rating" member.
    assert_payload_lacks_member(payload, "risk_rating", "risk_rating");

    // And the scores appear only under "payload.scores" as a posture summary.
    let payload_json: serde_json::Value =
        serde_json::from_str(payload).expect("payload is valid JSON");
    let payload_object = payload_json.as_object().expect("payload is a JSON object");
    let payload_members = payload_object
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert!(
        payload_object.contains_key("scores"),
        "the payload carries scores as a direct posture summary member (members: {payload_members:?})"
    );
    assert_eq!(
        member_count(&document, "scores"),
        1,
        "the export contains exactly one scores section under payload (document: {document})"
    );
}
