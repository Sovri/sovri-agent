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

use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

/// The fixed executed-at the consent corpus records, reused as the generated date.
pub const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The framework the consent corpus covers.
pub const FRAMEWORK: &str = "gdpr-eprivacy";
/// The consent framework's catalog version.
pub const FRAMEWORK_VERSION: &str = "2016-679";
/// The consent framework's source URL.
pub const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
/// The single control both consent results evaluate.
pub const CONTROL: &str = "consent.tracker.prior-consent";
/// The catalogued title of that control, as read from the persisted catalog.
pub const CONTROL_TITLE: &str = "Prior consent for tracker access";
/// The rule that fails: a non-essential tracker with no consent evidence.
pub const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The rule that passes: the consent-management platform is configured.
pub const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";

/// Builds one consent `ControlResult` for `rule_id` at `status`, carrying the
/// control's catalogued severity, weight, and evidence id from the Background.
#[must_use]
pub fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

/// The canonical "shopfront-2026-06-24" consent corpus: the gdpr-eprivacy
/// framework, its catalogued `consent.tracker.prior-consent` control, and that
/// control's FAIL + PASS results.
#[must_use]
pub fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(FRAMEWORK, CONTROL, CONTROL_TITLE, "major", 8)
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass))
}
