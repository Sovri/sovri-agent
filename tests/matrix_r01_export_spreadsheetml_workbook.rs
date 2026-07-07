// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — a `SpreadsheetML` compliance-matrix workbook is exported from the
//! persisted consent corpus, without re-running a scanner. Covers issue #164.

use sovri_agent::matrix::{self, Corpus};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The processing instruction that makes Excel open the flat XML as a workbook.
const MSO_APPLICATION_PI: &str = r#"<?mso-application progid="Excel.Sheet"?>"#;

/// Returns the name of the workbook's root element, skipping the XML
/// declaration and any processing instructions, comments, or whitespace.
fn root_element_name(xml: &str) -> Option<&str> {
    let mut rest = xml;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("<?") {
            rest = &after[after.find("?>")? + "?>".len()..];
        } else if let Some(after) = rest.strip_prefix("<!--") {
            rest = &after[after.find("-->")? + "-->".len()..];
        } else {
            break;
        }
    }
    let after_lt = rest.strip_prefix('<')?;
    let name_end = after_lt
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(after_lt.len());
    Some(&after_lt[..name_end])
}

/// Extracts the text of the workbook's `<Created>` generated-date element.
fn generated_date(xml: &str) -> Option<&str> {
    let start = xml.find("<Created>")? + "<Created>".len();
    let end = start + xml[start..].find("</Created>")?;
    Some(&xml[start..end])
}

#[test]
fn export_a_spreadsheetml_workbook_from_the_persisted_corpus() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24"
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let corpus = Corpus::new(EXECUTED_AT);

    // When the maintainer exports the compliance matrix for "shopfront-2026-06-24".
    let workbook = matrix::export(&corpus);

    // Then a non-empty SpreadsheetML workbook is produced.
    assert!(!workbook.is_empty(), "the workbook has content");

    // And its root element is "Workbook".
    assert_eq!(
        root_element_name(&workbook),
        Some("Workbook"),
        "the workbook root element is <Workbook>"
    );

    // And it carries the mso-application processing instruction for progid "Excel.Sheet".
    assert!(
        workbook.contains(MSO_APPLICATION_PI),
        "the workbook carries the mso-application progid=\"Excel.Sheet\" instruction"
    );

    // And the workbook's generated date is "2026-06-24T13:16:28Z".
    assert_eq!(
        generated_date(&workbook),
        Some(EXECUTED_AT),
        "the workbook generated date is the run's fixed executed-at"
    );
}
