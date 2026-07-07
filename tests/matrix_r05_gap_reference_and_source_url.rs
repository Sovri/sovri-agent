// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 — each Gaps row shows its own framework reference and source URL, never a
//! CWE fallback. Exported from a corpus whose two gaps carry distinct non-CWE
//! references under two frameworks, each Gaps row renders that control's own
//! reference, its framework's source URL, and its severity, and no cell in the row
//! begins with a CWE id. Covers #186.

mod matrix_support;

use sovri_agent::matrix;

/// One row of the Scenario Outline's Examples: the control whose gap the Gaps sheet
/// renders, and the reference, source URL, and severity that row must show.
struct Example {
    control: &'static str,
    reference: &'static str,
    url: &'static str,
    severity: &'static str,
}

/// The Scenario Outline's Examples table, verbatim: two controls whose gaps carry
/// their own non-CWE framework reference, source URL, and severity.
const EXAMPLES: [Example; 2] = [
    Example {
        control: "consent.tracker.prior-consent",
        reference: "gdpr-eprivacy:2016-679:Art.7",
        url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        severity: "major",
    },
    Example {
        control: "host.ssh.permit-root-login",
        reference: "iso-27001:2022:A.8.2",
        url: "https://www.iso.org/standard/27001",
        severity: "major",
    },
];

#[test]
fn a_gaps_row_shows_its_own_framework_reference_and_source_url() {
    // Given a compliance matrix whose gap for control "<control>" carries reference
    // "<reference>", source URL "<url>", and severity "<severity>".
    let workbook = matrix::export(&matrix_support::gap_references_corpus());
    let gaps = matrix_support::rows(matrix_support::worksheet(&workbook, "Gaps"));

    for example in EXAMPLES {
        let row = matrix_support::row_containing(&gaps, example.control).unwrap_or_else(|| {
            panic!(
                "the Gaps sheet has a row for control {} (rows: {gaps:?})",
                example.control
            )
        });

        // Then the "Gaps" row for control "<control>" shows reference "<reference>".
        assert!(
            row.iter().any(|cell| cell == example.reference),
            "the Gaps row for {} shows reference {} (row: {row:?})",
            example.control,
            example.reference
        );

        // And it shows source URL "<url>".
        assert!(
            row.iter().any(|cell| cell == example.url),
            "the Gaps row for {} shows source URL {} (row: {row:?})",
            example.control,
            example.url
        );

        // And it shows severity "<severity>".
        assert!(
            row.iter().any(|cell| cell == example.severity),
            "the Gaps row for {} shows severity {} (row: {row:?})",
            example.control,
            example.severity
        );

        // And it shows no reference beginning with "CWE-".
        assert!(
            row.iter().all(|cell| !cell.starts_with("CWE-")),
            "no cell in the Gaps row for {} begins with CWE- (row: {row:?})",
            example.control
        );
    }
}
