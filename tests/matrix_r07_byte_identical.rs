// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — exporting the workbook twice yields byte-identical XML. The export is a
//! pure function of the corpus with a fixed generated date, so a second export of
//! the same corpus is byte-for-byte identical. Covers issue #190.

mod matrix_support;

use sovri_agent::matrix;

#[test]
fn exporting_the_workbook_twice_yields_byte_identical_xml() {
    // Given the "shopfront-2026-06-24" consent corpus with a fixed executed-at.
    let corpus = matrix_support::consent_corpus();

    // When the compliance matrix is exported from the corpus, and exported a
    // second time from the same corpus.
    let first = matrix::export(&corpus);
    let second = matrix::export(&corpus);

    // Then the two workbooks are byte-identical.
    assert_eq!(
        first, second,
        "exporting the same corpus twice yields byte-identical XML"
    );
}
