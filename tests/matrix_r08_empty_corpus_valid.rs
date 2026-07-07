// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — an empty corpus does not produce an empty or broken workbook. An empty
//! corpus still yields a non-empty workbook rooted at `Workbook`, every sheet
//! present with its header row, and a Summary that explains no controls were
//! evaluated. Covers issue #197.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};

/// The name of the first real element (skipping the XML declaration and any
/// processing instructions).
fn root_element(xml: &str) -> &str {
    let mut rest = xml;
    loop {
        let lt = rest.find('<').expect("the document has an element");
        rest = &rest[lt + 1..];
        if let Some(after) = rest.strip_prefix('?') {
            let close = after
                .find("?>")
                .expect("a processing instruction is closed");
            rest = &after[close + "?>".len()..];
            continue;
        }
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        return &rest[..end];
    }
}

const DOCUMENTED_HEADERS: [(&str, &str); 6] = [
    ("Controls", "Framework, Control, Title, Severity, Weight, Applicability, Applicability reason"),
    ("Results", "Framework, Control, Rule, Status, Severity, Score impact, Evidence ids, Remediation, Applicability"),
    ("Gaps", "Gap id, Framework, Control, Rule, Reference, Source URL, Severity, Gap type, Evidence ids, Remediation"),
    ("Evidence", "Evidence id, Type, Location, Collector, Integrity, Redaction status"),
    ("Frameworks", "Framework, Version, Source URL"),
    ("Summary", "Framework, Status, Count"),
];

#[test]
fn an_empty_corpus_does_not_produce_an_empty_or_broken_workbook() {
    // Given an empty compliance corpus.
    let workbook = matrix::export(&Corpus::new(matrix_support::EXECUTED_AT));

    // Then a non-empty SpreadsheetML workbook is produced.
    assert!(!workbook.is_empty(), "a non-empty workbook is produced");

    // And its root element is "Workbook".
    assert_eq!(
        root_element(&workbook),
        "Workbook",
        "the root element is Workbook"
    );

    // And every one of the six worksheets is present with its header row.
    for (sheet, header) in DOCUMENTED_HEADERS {
        let rows = matrix_support::rows(matrix_support::worksheet(&workbook, sheet));
        let first = rows
            .first()
            .unwrap_or_else(|| panic!("the {sheet} worksheet has a header row"));
        assert_eq!(
            first.join(", "),
            header,
            "the {sheet} worksheet is present with its documented header row"
        );
    }

    // And the "Summary" worksheet explains that no controls were evaluated.
    let summary = matrix_support::worksheet(&workbook, "Summary");
    assert!(
        summary.contains("No controls were evaluated"),
        "the Summary worksheet explains that no controls were evaluated"
    );
}
