// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 — each filter dimension spans two values so it can partition rows. In the
//! mixed corpus every filterable column (framework, status, severity,
//! applicability on Results; gap type on Gaps) shows two distinct values across
//! its rows. Covers issue #183.

mod matrix_support;

use sovri_agent::matrix;

/// A filter dimension: the sheet and column that owns it, and two values the
/// corpus makes it span.
struct Dimension {
    sheet: &'static str,
    column: &'static str,
    value_a: &'static str,
    value_b: &'static str,
}

const DIMENSIONS: [Dimension; 5] = [
    Dimension {
        sheet: "Results",
        column: "Framework",
        value_a: "gdpr-eprivacy",
        value_b: "iso-27001",
    },
    Dimension {
        sheet: "Results",
        column: "Status",
        value_a: "FAIL",
        value_b: "WARNING",
    },
    Dimension {
        sheet: "Results",
        column: "Severity",
        value_a: "major",
        value_b: "minor",
    },
    Dimension {
        sheet: "Results",
        column: "Applicability",
        value_a: "applicable",
        value_b: "not applicable",
    },
    Dimension {
        sheet: "Gaps",
        column: "Gap type",
        value_a: "FAIL",
        value_b: "WARNING",
    },
];

#[test]
fn each_filter_dimension_spans_two_values() {
    // Given a compliance matrix exported from the "mixed-2026-06-24" run.
    let workbook = matrix::export(&matrix_support::mixed_corpus());

    for dim in DIMENSIONS {
        let rows = matrix_support::rows(matrix_support::worksheet(&workbook, dim.sheet));
        let header = rows.first().expect("the sheet has a header row");

        // Then the sheet has a filterable column "<dimension>".
        let index = header
            .iter()
            .position(|name| name == dim.column)
            .unwrap_or_else(|| {
                panic!(
                    "the {} sheet has a filterable column {} (header: {header:?})",
                    dim.sheet, dim.column
                )
            });

        // And that column shows both "<value_a>" and "<value_b>" across its rows.
        let column: Vec<&str> = rows[1..]
            .iter()
            .filter_map(|row| row.get(index).map(String::as_str))
            .collect();
        assert!(
            column.contains(&dim.value_a),
            "the {} column shows {} across its rows (values: {column:?})",
            dim.column,
            dim.value_a
        );
        assert!(
            column.contains(&dim.value_b),
            "the {} column shows {} across its rows (values: {column:?})",
            dim.column,
            dim.value_b
        );
    }
}
