// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 — an absent section renders its header plus an explanatory row.
//!
//! A corpus that lacks gaps, evidence, or scores still yields that worksheet with
//! its documented header row first and an explanatory placeholder row that names
//! why the section is empty — never a missing sheet, an empty file, or a bare
//! self-closing `SpreadsheetML` table. Covers issue #195.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};

/// One row of the Scenario Outline's Examples: the section `absent` from the
/// corpus, the `sheet` it leaves empty, that sheet's documented `header`, the
/// explanatory `placeholder` it must still show, and the builder that yields the
/// corpus missing exactly that section.
struct Example {
    absent: &'static str,
    sheet: &'static str,
    header: &'static str,
    placeholder: &'static str,
    corpus: fn() -> Corpus,
}

/// The Scenario Outline's three examples, one per absent section.
fn examples() -> [Example; 3] {
    [
        Example {
            absent: "no gaps (all controls PASS)",
            sheet: "Gaps",
            header: "Gap id, Framework, Control, Rule, Reference, Source URL, Severity, Gap type, Evidence ids, Remediation",
            placeholder: "No potential gaps observed",
            corpus: matrix_support::all_pass_corpus,
        },
        Example {
            absent: "no evidence records",
            sheet: "Evidence",
            header: "Evidence id, Type, Location, Collector, Integrity, Redaction status",
            placeholder: "No evidence records were collected",
            corpus: matrix_support::no_evidence_corpus,
        },
        Example {
            absent: "no scores",
            sheet: "Summary",
            header: "Framework, Status, Count",
            placeholder: "Scores are not available for this run",
            corpus: matrix_support::no_scores_corpus,
        },
    ]
}

#[test]
fn an_absent_section_renders_its_header_plus_an_explanatory_row() {
    for example in examples() {
        let Example {
            absent,
            sheet,
            header,
            placeholder,
            corpus,
        } = example;

        // Given a compliance corpus with <absent>.
        let corpus = corpus();

        // When the compliance matrix is exported.
        let workbook = matrix::export(&corpus);

        // Then a non-empty SpreadsheetML workbook is produced.
        assert!(
            !workbook.is_empty(),
            "a non-empty workbook is produced for the {absent:?} example"
        );

        // And the workbook has a worksheet named "<sheet>".
        let sheet_xml = matrix_support::worksheet(&workbook, sheet);
        let rows = matrix_support::rows(sheet_xml);

        // And the first row of the "<sheet>" worksheet is its documented header.
        let first_row = rows
            .first()
            .unwrap_or_else(|| panic!("the {sheet} worksheet has a first row (rows: {rows:?})"));
        assert_eq!(
            first_row.join(", "),
            header,
            "the first row of the {sheet} worksheet is its documented header (row: {first_row:?})"
        );

        // And the "<sheet>" worksheet shows the explanatory row "<placeholder>".
        assert!(
            matrix_support::row_containing(&rows, placeholder).is_some(),
            "the {sheet} worksheet shows the explanatory row {placeholder:?} (rows: {rows:?})"
        );
    }
}
