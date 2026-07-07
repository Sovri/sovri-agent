// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the exported `SpreadsheetML` workbook carries a worksheet for each of
//! the six required sheets: Controls, Results, Gaps, Evidence, Frameworks, and
//! Summary. Covers issue #165.

use sovri_agent::matrix::{self, Corpus};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

/// The six worksheets the Scenario Outline's Examples require, in the order the
/// feature lists them.
const REQUIRED_WORKSHEETS: [&str; 6] = [
    "Controls",
    "Results",
    "Gaps",
    "Evidence",
    "Frameworks",
    "Summary",
];

/// Collects the `ss:Name` of every `<Worksheet>` element in the workbook.
///
/// `SpreadsheetML` names each sheet with the `ss:Name` attribute on its
/// `<Worksheet>` element, so this scans the opening tags and returns the names
/// in document order.
fn worksheet_names(xml: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find("<Worksheet") {
        rest = &rest[at + "<Worksheet".len()..];
        let tag_end = rest.find('>').unwrap_or(rest.len());
        let opening = &rest[..tag_end];
        if let Some(name_at) = opening.find("ss:Name=\"") {
            let after = &opening[name_at + "ss:Name=\"".len()..];
            if let Some(end) = after.find('"') {
                names.push(&after[..end]);
            }
        }
        rest = &rest[tag_end..];
    }
    names
}

#[test]
fn the_workbook_contains_every_required_worksheet() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24"
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let corpus = Corpus::new(EXECUTED_AT);

    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let workbook = matrix::export(&corpus);
    let names = worksheet_names(&workbook);

    // Then the workbook has a worksheet named "<sheet>" for each required sheet.
    for sheet in REQUIRED_WORKSHEETS {
        assert!(
            names.contains(&sheet),
            "the workbook has a worksheet named {sheet:?} (found worksheets: {names:?})"
        );
    }
}
