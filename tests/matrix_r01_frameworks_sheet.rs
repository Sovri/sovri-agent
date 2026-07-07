// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the Frameworks worksheet renders each framework's version and source
//! URL. Exported from the persisted consent corpus, the Frameworks sheet has a
//! row for `gdpr-eprivacy` showing its version and source URL. Covers #167.

mod matrix_support;

use sovri_agent::matrix::{self, Corpus};

/// The run's fixed executed-at, reused as the workbook's generated date.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

#[test]
fn frameworks_sheet_renders_version_and_source_url() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus.
    let corpus = Corpus::new(EXECUTED_AT).with_framework(
        "gdpr-eprivacy",
        "2016-679",
        "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    );
    let workbook = matrix::export(&corpus);

    // Then the "Frameworks" worksheet has a row for framework "gdpr-eprivacy".
    let sheet = matrix_support::worksheet(&workbook, "Frameworks");
    let rows = matrix_support::rows(sheet);
    let row = matrix_support::row_containing(&rows, "gdpr-eprivacy")
        .expect("the Frameworks worksheet has a row for gdpr-eprivacy");

    // And that row shows version "2016-679".
    assert!(
        row.iter().any(|cell| cell == "2016-679"),
        "the gdpr-eprivacy row shows version 2016-679 (row: {row:?})"
    );

    // And that row shows source URL "https://eur-lex.europa.eu/eli/reg/2016/679/oj".
    assert!(
        row.iter()
            .any(|cell| cell == "https://eur-lex.europa.eu/eli/reg/2016/679/oj"),
        "the gdpr-eprivacy row shows its source URL (row: {row:?})"
    );
}
