// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — re-exporting the same corpus preserves every id. The export is a pure
//! function of the corpus, so a second export carries the same framework,
//! control, rule, evidence, and gap ids as the first. Covers issue #177.

mod matrix_support;

use sovri_agent::matrix;

/// The composed gap id for the consent corpus's tracker-rule FAIL.
const GAP_ID: &str =
    "gdpr-eprivacy:consent.tracker.prior-consent:consent.detect-trackers-without-consent-evidence";

#[test]
fn reexporting_the_same_corpus_preserves_every_id() {
    // Given a compliance matrix exported from the "shopfront-2026-06-24" consent corpus,
    // and the compliance matrix is exported from it a second time.
    let corpus = matrix_support::consent_corpus();
    let first = matrix::export(&corpus);
    let second = matrix::export(&corpus);

    // Then every framework, control, rule, evidence, and gap id is identical between
    // the two workbooks (the whole document is, since the export derives only from
    // the corpus and reads no wall clock).
    assert_eq!(
        first, second,
        "re-exporting the same corpus yields the same ids in the same places"
    );

    // Sanity: each id kind the scenario names is actually present to be preserved.
    for id in [
        matrix_support::FRAMEWORK,
        matrix_support::CONTROL,
        matrix_support::TRACKER_RULE,
        matrix_support::CMP_RULE,
        "ev-0001",
        GAP_ID,
    ] {
        assert!(
            first.contains(id) && second.contains(id),
            "the id {id} appears in both workbooks"
        );
    }
}
