// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the MAT-96 matrix acceptance tests.
//!
//! Query an exported `SpreadsheetML` workbook by worksheet name and read the
//! cell values of its rows, so each acceptance test asserts against the sheet it
//! cares about without re-parsing the XML by hand.

#![allow(dead_code)]

/// Returns the `<Worksheet>` … `</Worksheet>` slice whose `ss:Name` is `name`.
///
/// # Panics
/// Panics if no worksheet with that name is present, so a test that names a
/// missing sheet fails with a clear message.
#[must_use]
pub fn worksheet<'a>(xml: &'a str, name: &str) -> &'a str {
    let needle = format!("ss:Name=\"{name}\"");
    let mut rest = xml;
    loop {
        let at = rest
            .find("<Worksheet")
            .unwrap_or_else(|| panic!("the workbook has a worksheet named {name:?}"));
        let after = &rest[at..];
        let tag_end = after
            .find('>')
            .expect("the worksheet opening tag is closed");
        if after[..tag_end].contains(&needle) {
            let end =
                after.find("</Worksheet>").expect("the worksheet is closed") + "</Worksheet>".len();
            return &after[..end];
        }
        rest = &after[tag_end..];
    }
}

/// Returns the cell values of every `<Row>` in `fragment`, one inner `Vec` per
/// row, reading the text of each `<Data>` cell in order.
#[must_use]
pub fn rows(fragment: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = fragment;
    while let Some(at) = rest.find("<Row") {
        let after = &rest[at..];
        let end = after
            .find("</Row>")
            .map_or(after.len(), |e| e + "</Row>".len());
        out.push(cell_values(&after[..end]));
        rest = &after[end..];
    }
    out
}

/// Reads the text of every `<Data>` cell in a single `<Row>` fragment.
#[must_use]
pub fn cell_values(row: &str) -> Vec<String> {
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

/// Returns the first row whose cells contain `value`, if any.
#[must_use]
pub fn row_containing<'a>(rows: &'a [Vec<String>], value: &str) -> Option<&'a Vec<String>> {
    rows.iter().find(|cells| cells.iter().any(|c| c == value))
}
