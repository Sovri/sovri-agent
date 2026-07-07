// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 — every worksheet's first row is its documented header. Exported from the
//! "shopfront-2026-06-24" consent corpus, each of the six sheets opens with a
//! header row that names its columns in the documented order. Covers issue #179.

mod matrix_support;

use sovri_agent::matrix;

/// Each worksheet paired with the documented header its first row must carry, as
/// the scenario's Examples table fixes them: the column names joined by ", ".
const DOCUMENTED_HEADERS: [(&str, &str); 6] = [
    (
        "Controls",
        "Framework, Control, Title, Severity, Weight, Applicability, Applicability reason",
    ),
    (
        "Results",
        "Framework, Control, Rule, Status, Severity, Score impact, Evidence ids, Remediation, Applicability",
    ),
    (
        "Gaps",
        "Gap id, Framework, Control, Rule, Reference, Source URL, Severity, Gap type, Evidence ids, Remediation",
    ),
    (
        "Evidence",
        "Evidence id, Type, Location, Collector, Integrity, Redaction status",
    ),
    ("Frameworks", "Framework, Version, Source URL"),
    ("Summary", "Framework, Status, Count"),
];

#[test]
fn each_worksheets_first_row_is_its_documented_header() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);

    for (sheet, headers) in DOCUMENTED_HEADERS {
        // Then the first row of the "<sheet>" worksheet is the header "<headers>".
        let rows = matrix_support::rows(matrix_support::worksheet(&workbook, sheet));
        let first_row = rows
            .first()
            .unwrap_or_else(|| panic!("the {sheet} worksheet has a first row (rows: {rows:?})"));
        assert_eq!(
            first_row.join(", "),
            headers,
            "the first row of the {sheet} worksheet is its documented header (row: {first_row:?})"
        );
    }
}
