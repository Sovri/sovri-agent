// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — classified evidence records are reduced to metadata in signed JSON.
//! Covers issue #280.

mod matrix_support;
mod signed_json_support;

use serde_json::Value;
use signed_json_support::FIXTURE_SIGNING_SEED;
use sovri_agent::signed_json;

struct Example {
    classification: &'static str,
    evidence_id: &'static str,
    locator: &'static str,
    raw_value: String,
    integrity: &'static str,
}

fn secret_raw_value() -> String {
    format!("sk_{}_{}", "live", "EXAMPLEonly_NOT_A_REAL_KEY")
}

fn examples() -> Vec<Example> {
    vec![
        Example {
            classification: "Secret",
            evidence_id: "ev-0007",
            locator: ".env.example:3",
            raw_value: secret_raw_value(),
            integrity: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
        Example {
            classification: "Sensitive",
            evidence_id: "ev-0008",
            locator: "config/users.yaml:12",
            raw_value: "admin@shopfront.example".to_owned(),
            integrity: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    ]
}

#[test]
fn a_classified_evidence_record_is_reduced_to_metadata_in_the_json() {
    // Given a persisted evidence store holds a "<classification>" evidence record
    // "<evidence_id>" at "<locator>" with raw value "<raw_value>" and integrity
    // "<integrity>".
    let corpus = matrix_support::classified_evidence_corpus();

    // And a signed JSON export of that store.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let export: Value = serde_json::from_str(&document).expect("the signed export parses as JSON");
    let evidence = export
        .pointer("/payload/evidence")
        .and_then(Value::as_array)
        .expect("the signed export carries payload.evidence records");

    for example in examples() {
        let record = evidence
            .iter()
            .find(|record| string_member(record, "id") == Some(example.evidence_id))
            .unwrap_or_else(|| {
                panic!(
                    "the signed export has evidence record {} for {} classified evidence",
                    example.evidence_id, example.classification
                )
            });

        // Then the evidence record "<evidence_id>" shows its type, locator, and
        // integrity "<integrity>".
        assert!(
            string_member(record, "type").is_some_and(|value| !value.is_empty()),
            "evidence record {} shows its type (record: {record})",
            example.evidence_id
        );
        assert_eq!(
            string_member(record, "locator"),
            Some(example.locator),
            "evidence record {} shows locator {} (record: {record})",
            example.evidence_id,
            example.locator
        );
        assert_eq!(
            string_member(record, "integrity"),
            Some(example.integrity),
            "evidence record {} shows integrity {} (record: {record})",
            example.evidence_id,
            example.integrity
        );

        // And it shows redaction status "redacted".
        assert_eq!(
            string_member(record, "redaction_status"),
            Some("redacted"),
            "evidence record {} shows redaction status redacted (record: {record})",
            example.evidence_id
        );

        // And no string value in the document contains "<raw_value>".
        assert!(
            !document.contains(&example.raw_value),
            "the signed export does not contain the raw classified value for {}",
            example.evidence_id
        );
    }
}

#[test]
fn an_unclassified_evidence_record_is_marked_not_redacted_in_the_json() {
    let corpus = matrix_support::stored_evidence_corpus();

    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let export: Value = serde_json::from_str(&document).expect("the signed export parses as JSON");
    let evidence = export
        .pointer("/payload/evidence")
        .and_then(Value::as_array)
        .expect("the signed export carries payload.evidence records");
    let record = evidence
        .iter()
        .find(|record| string_member(record, "id") == Some(matrix_support::STORED_EVIDENCE_ID))
        .unwrap_or_else(|| {
            panic!(
                "the signed export has unclassified evidence record {}",
                matrix_support::STORED_EVIDENCE_ID
            )
        });

    assert_eq!(
        string_member(record, "type"),
        Some(matrix_support::STORED_EVIDENCE_KIND),
        "the unclassified evidence record shows its type (record: {record})"
    );
    assert_eq!(
        string_member(record, "locator"),
        Some(matrix_support::STORED_EVIDENCE_LOCATION),
        "the unclassified evidence record shows its locator (record: {record})"
    );
    assert_eq!(
        string_member(record, "integrity"),
        Some(matrix_support::STORED_EVIDENCE_INTEGRITY),
        "the unclassified evidence record shows its integrity (record: {record})"
    );
    assert_eq!(
        string_member(record, "redaction_status"),
        Some("none"),
        "the unclassified evidence record shows redaction status none (record: {record})"
    );
}

fn string_member<'a>(record: &'a Value, name: &str) -> Option<&'a str> {
    record.get(name).and_then(Value::as_str)
}
