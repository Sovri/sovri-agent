// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 (technical) — every section stays present, never omitted, on an all-PASS
//! corpus. A signed export of a corpus whose only control is all PASS with no gaps
//! and no evidence still carries a `gaps` member that is an empty array and an
//! `evidence` member that is an empty array, and omits none of the seven required
//! sections. This pins that empty sections are present-but-empty, guarding against
//! a future change that would drop them. Covers issue #247.

mod signed_json_support;

use signed_json_support::{
    all_pass_consent_corpus_without_evidence, has_member, FIXTURE_SIGNING_SEED,
};
use sovri_agent::signed_json;

/// The seven payload sections that must never be omitted.
const REQUIRED_SECTIONS: [&str; 7] = [
    "scan",
    "frameworks",
    "controls",
    "results",
    "gaps",
    "evidence",
    "scores",
];

/// Whether the compact export carries `name` as an empty JSON array (`"name":[]`).
fn has_empty_array_member(document: &str, name: &str) -> bool {
    document.contains(&format!("\"{name}\":[]"))
}

#[test]
fn every_section_stays_present_on_an_all_pass_corpus() {
    // Given a compliance corpus whose only control "consent.tracker.prior-consent" is
    // all PASS with no gaps and no evidence.
    let corpus = all_pass_consent_corpus_without_evidence();

    // And a signed JSON export of that corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then the payload still has a "gaps" member that is an empty array.
    assert!(
        has_empty_array_member(&document, "gaps"),
        "the payload still has an empty gaps array (document: {document})"
    );

    // And the payload still has an "evidence" member that is an empty array.
    assert!(
        has_empty_array_member(&document, "evidence"),
        "the payload still has an empty evidence array (document: {document})"
    );

    // And no required section is omitted from the payload.
    for section in REQUIRED_SECTIONS {
        assert!(
            has_member(&document, section),
            "the payload still carries a {section:?} member (document: {document})"
        );
    }
}
