// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 (technical) — a record without a CWE carries no CWE field at all. The
//! control and gap records for "consent.tracker.prior-consent" in a signed export
//! of the persisted "shopfront-2026-06-24" consent corpus carry no "cwe" member:
//! a compliance reference is emitted as `reference`, never forced into a `cwe`
//! field a record has no value for. Covers issue #268.

mod signed_json_support;

use signed_json_support::{consent_corpus, section_value, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

#[test]
fn a_record_without_a_cwe_carries_no_cwe_field() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);

    // Then the control record for "consent.tracker.prior-consent" has no "cwe" member.
    let controls = section_value(&document, "controls");
    assert!(
        !controls.contains("\"cwe\""),
        "the control record carries no cwe member (controls: {controls})"
    );

    // And the gap record for "consent.tracker.prior-consent" has no "cwe" member.
    let gaps = section_value(&document, "gaps");
    assert!(
        !gaps.contains("\"cwe\""),
        "the gap record carries no cwe member (gaps: {gaps})"
    );
}
