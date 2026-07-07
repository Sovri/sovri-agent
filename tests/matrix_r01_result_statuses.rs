// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — every control-result status renders as a row on the Results
//! worksheet. A corpus carrying a single result of a given status exports a
//! workbook whose Results sheet has a row with that status, for each of PASS,
//! FAIL, WARNING, SKIPPED, and ERROR. Covers issue #166.

use sovri_agent::matrix::{self, Corpus};
use sovri_sdk::Status;

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

/// The five statuses the Scenario Outline's Examples enumerate, each expected
/// to render as its own row on the Results worksheet.
const EVERY_STATUS: [Status; 5] = [
    Status::Pass,
    Status::Fail,
    Status::Warning,
    Status::Skipped,
    Status::Error,
];

/// Returns the `Results` worksheet's XML slice, from its opening `<Worksheet>`
/// tag to the matching `</Worksheet>`, so assertions inspect only that sheet.
fn results_worksheet(xml: &str) -> &str {
    let mut rest = xml;
    loop {
        let at = rest
            .find("<Worksheet")
            .expect("the workbook has a Results worksheet");
        let after = &rest[at..];
        let tag_end = after
            .find('>')
            .expect("the worksheet opening tag is closed");
        if after[..tag_end].contains(r#"ss:Name="Results""#) {
            let end = after
                .find("</Worksheet>")
                .expect("the Results worksheet is closed")
                + "</Worksheet>".len();
            return &after[..end];
        }
        rest = &after[tag_end..];
    }
}

/// Collects the cell values of each `<Row>` in the worksheet, one inner `Vec`
/// per row, reading the text of every `<Data>` cell.
fn worksheet_rows(worksheet: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut rest = worksheet;
    while let Some(at) = rest.find("<Row") {
        let after = &rest[at..];
        let end = after
            .find("</Row>")
            .map_or(after.len(), |e| e + "</Row>".len());
        rows.push(cell_values(&after[..end]));
        rest = &after[end..];
    }
    rows
}

/// Reads the text of every `<Data>` cell in a single `<Row>` fragment.
fn cell_values(row: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = row;
    while let Some(at) = rest.find("<Data") {
        let after = &rest[at..];
        let Some(open_end) = after.find('>') else {
            break;
        };
        let inner = &after[open_end + 1..];
        let Some(close) = inner.find("</Data>") else {
            break;
        };
        values.push(inner[..close].to_string());
        rest = &inner[close + "</Data>".len()..];
    }
    values
}

#[test]
fn every_result_status_renders_on_the_results_sheet() {
    for status in EVERY_STATUS {
        // Given a compliance corpus containing a single control result with status "<status>".
        let corpus = Corpus::new(EXECUTED_AT).with_result(status);

        // And a compliance matrix exported from that corpus.
        let workbook = matrix::export(&corpus);

        // Then the "Results" worksheet has a row with status "<status>".
        let rows = worksheet_rows(results_worksheet(&workbook));
        assert!(
            rows.iter()
                .any(|cells| cells.iter().any(|value| value.as_str() == status.label())),
            "the Results worksheet has a row with status {:?} (rows: {rows:?})",
            status.label()
        );
    }
}
