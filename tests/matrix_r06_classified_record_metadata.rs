// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 — a classified evidence record is summarized to its metadata on the
//! Evidence sheet. Exported from a store holding the Secret `ev-0007` and the
//! Sensitive `ev-0008`, each record's Evidence row shows only its type, location,
//! `sha256:…` integrity, and a `redacted` redaction status — the raw value the
//! store dropped never reaches a cell. Covers #188.

mod matrix_support;

use sovri_agent::matrix;

/// One row of the Scenario Outline's Examples: the classified record's evidence
/// id and the type, location, and `sha256:…` integrity its Evidence row must show.
/// Every classified record's row shows the same `redacted` redaction status.
struct Example {
    evidence_id: &'static str,
    kind: &'static str,
    locator: &'static str,
    integrity: &'static str,
}

/// The Scenario Outline's Examples table, verbatim: the Secret `ev-0007` and the
/// Sensitive `ev-0008`, each reduced to the metadata its Evidence row renders.
const EXAMPLES: [Example; 2] = [
    Example {
        evidence_id: "ev-0007",
        kind: "config",
        locator: ".env.example:3",
        integrity: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    Example {
        evidence_id: "ev-0008",
        kind: "config",
        locator: "config/users.yaml:12",
        integrity: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
];

#[test]
fn a_classified_record_is_summarized_to_its_metadata() {
    // Given a persisted evidence store holds the classified records, and a
    // compliance matrix exported from that store.
    let workbook = matrix::export(&matrix_support::classified_evidence_corpus());
    let evidence = matrix_support::rows(matrix_support::worksheet(&workbook, "Evidence"));

    for example in EXAMPLES {
        // Then the "Evidence" worksheet has a row for evidence id "<evidence_id>".
        let row =
            matrix_support::row_containing(&evidence, example.evidence_id).unwrap_or_else(|| {
                panic!(
                    "the Evidence sheet has a row for evidence id {} (rows: {evidence:?})",
                    example.evidence_id
                )
            });

        // And it shows type "<kind>".
        assert!(
            row.iter().any(|cell| cell == example.kind),
            "the Evidence row for {} shows type {} (row: {row:?})",
            example.evidence_id,
            example.kind
        );

        // And it shows location "<locator>".
        assert!(
            row.iter().any(|cell| cell == example.locator),
            "the Evidence row for {} shows location {} (row: {row:?})",
            example.evidence_id,
            example.locator
        );

        // And it shows integrity "<integrity>".
        assert!(
            row.iter().any(|cell| cell == example.integrity),
            "the Evidence row for {} shows integrity {} (row: {row:?})",
            example.evidence_id,
            example.integrity
        );

        // And it shows redaction status "redacted".
        assert!(
            row.iter().any(|cell| cell == "redacted"),
            "the Evidence row for {} shows redaction status redacted (row: {row:?})",
            example.evidence_id
        );
    }
}
