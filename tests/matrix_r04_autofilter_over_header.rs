// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 — each data sheet exposes an `AutoFilter` over its header row. Exported from
//! the "mixed-2026-06-24" run, the Controls, Results, and Gaps worksheets each
//! carry an `<AutoFilter>` whose range starts at the header's first cell and spans
//! the full width of the documented header row, so a spreadsheet application shows
//! a filter dropdown on every column when it opens the sheet. Covers issue #182.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

/// The data sheets the Scenario Outline's Examples name, each of which must carry
/// an `AutoFilter` spanning its header row.
const DATA_SHEETS: [&str; 3] = ["Controls", "Results", "Gaps"];

/// Builds the "mixed-2026-06-24" run the Background fixes: three control results
/// across two frameworks — a `gdpr-eprivacy` FAIL, an `iso-27001` WARNING, and an
/// `iso-27001` SKIPPED — each over its own catalogued control, so the Controls,
/// Results, and Gaps sheets all carry rows to filter. Applicability follows from
/// the status (SKIPPED is not applicable, the rest are applicable), matching the
/// Background's applicability column.
fn mixed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_control(
            "gdpr-eprivacy",
            "consent.tracker.prior-consent",
            "Prior consent for tracker access",
            "major",
            8,
        )
        .with_control(
            "iso-27001",
            "host.ssh.weak-crypto",
            "Strong SSH cryptography enforced",
            "minor",
            3,
        )
        .with_control(
            "iso-27001",
            "host.ssh.protocol-v1",
            "SSH protocol version 1 disabled",
            "major",
            5,
        )
        .with_control_result(
            "gdpr-eprivacy",
            mixed_result(
                "consent.tracker.prior-consent",
                "consent.detect-trackers-without-consent-evidence",
                "major",
                8,
                Status::Fail,
            ),
        )
        .with_control_result(
            "iso-27001",
            mixed_result(
                "host.ssh.weak-crypto",
                "host.ssh.detect-weak-cryptography",
                "minor",
                3,
                Status::Warning,
            ),
        )
        .with_control_result(
            "iso-27001",
            mixed_result(
                "host.ssh.protocol-v1",
                "host.ssh.detect-protocol-v1",
                "major",
                5,
                Status::Skipped,
            ),
        )
}

/// Builds one control result for the mixed run carrying the control id, rule id,
/// severity, weight, and status the Background fixes for its row.
fn mixed_result(
    control_id: &str,
    rule_id: &str,
    severity: &str,
    weight: u32,
    status: Status,
) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity(severity)
        .weight(weight)
        .evidence_refs(std::iter::empty::<&str>())
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("recorded for the mixed run");
    }
    builder.build().expect("the mixed fixture result validates")
}

/// Returns the R1C1-notation range declared on the worksheet's `<AutoFilter>`
/// element, reading whichever namespace-prefixed `Range` attribute carries it, or
/// `None` when the worksheet has no `AutoFilter`.
fn autofilter_range(worksheet: &str) -> Option<String> {
    let at = worksheet.find("<AutoFilter")?;
    let after = &worksheet[at..];
    let tag_end = after.find('>')?;
    let opening = &after[..tag_end];
    let range_at = opening.find("Range=\"")? + "Range=\"".len();
    let value = &opening[range_at..];
    let close = value.find('"')?;
    Some(value[..close].to_string())
}

/// The column index the R1C1-notation `range` ends at, e.g. `R1C1:R4C7` → 7.
fn range_end_column(range: &str) -> usize {
    let end_cell = range
        .rsplit(':')
        .next()
        .expect("the range names an end cell");
    let column = end_cell
        .rsplit('C')
        .next()
        .expect("the end cell names a column");
    column.parse().expect("the end column is a number")
}

#[test]
fn each_data_sheet_carries_an_autofilter_spanning_its_header_row() {
    // Given a persisted compliance run "mixed-2026-06-24" holds three control results,
    // and a compliance matrix exported from that run.
    let workbook = matrix::export(&mixed_corpus());

    for sheet in DATA_SHEETS {
        // Then the "<sheet>" worksheet carries an AutoFilter spanning its header row.
        let worksheet = matrix_support::worksheet(&workbook, sheet);
        let range = autofilter_range(worksheet)
            .unwrap_or_else(|| panic!("the {sheet} worksheet carries an <AutoFilter> element"));
        let header_width = matrix_support::rows(worksheet)
            .first()
            .unwrap_or_else(|| panic!("the {sheet} worksheet has a header row"))
            .len();
        assert!(
            range.starts_with("R1C1:"),
            "the {sheet} AutoFilter range starts at the header's first cell (range: {range})"
        );
        assert_eq!(
            range_end_column(&range),
            header_width,
            "the {sheet} AutoFilter spans all {header_width} columns of the header row (range: {range})"
        );
    }
}
