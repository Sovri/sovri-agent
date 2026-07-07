// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the workbook contains no control absent from the corpus. Exported from
//! the consent corpus, the Controls worksheet has exactly one control row, for
//! `consent.tracker.prior-consent`, and no row for any other control. Covers #172.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn the_workbook_contains_no_control_absent_from_the_corpus() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = matrix_support::consent_corpus();
    let workbook = matrix::export(&corpus);
    let controls = matrix_support::worksheet(&workbook, "Controls");
    let rows = matrix_support::rows(controls);

    // Then the "Controls" worksheet has exactly one control row (naming the corpus's
    // single control; a header row, added later, never names a control id).
    let control_rows = rows
        .iter()
        .filter(|cells| cells.iter().any(|cell| cell == matrix_support::CONTROL))
        .count();
    assert_eq!(
        control_rows,
        1,
        "exactly one control row for {} (rows: {rows:?})",
        matrix_support::CONTROL
    );

    // And it has no row for a control other than "consent.tracker.prior-consent":
    // controls that never appeared in the corpus must not leak into the sheet.
    for absent in [
        "host.ssh.permit-root-login",
        "host.ssh.weak-crypto",
        "container.base-image.supported",
    ] {
        assert!(
            !controls.contains(absent),
            "a control absent from the corpus must not appear: {absent}"
        );
    }
}
