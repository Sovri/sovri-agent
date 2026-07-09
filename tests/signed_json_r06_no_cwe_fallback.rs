// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 (violation) — no string anywhere in the payload falls back to a CWE
//! reference. A signed export of the persisted "shopfront-2026-06-24" consent
//! corpus carries only the catalogued non-CWE references verbatim, so no payload
//! string begins with "CWE-", and the gap for consent.tracker.prior-consent shows
//! its own `gdpr-eprivacy:2016-679:Art.7` reference. Covers issue #267.

mod signed_json_support;

use signed_json_support::{
    consent_corpus, section_value, string_member, CONTROL, CONTROL_REFERENCE, FIXTURE_SIGNING_SEED,
};
use sovri_agent::signed_json;

#[test]
fn no_string_in_the_payload_falls_back_to_a_cwe_reference() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&consent_corpus(), &FIXTURE_SIGNING_SEED);

    // Then no string value in the payload begins with "CWE-": the export emits only
    // verbatim non-CWE references, so "CWE-" appears nowhere in the payload.
    let payload = section_value(&document, "payload");
    assert!(
        !payload.contains("CWE-"),
        "the payload carries no CWE reference (payload: {payload})"
    );

    // And the gap record for "consent.tracker.prior-consent" shows its own non-CWE
    // reference, so the absence of CWE is not just an empty reference.
    let gap = section_value(&document, "gaps");
    assert_eq!(
        string_member(gap, "reference").as_deref(),
        Some(CONTROL_REFERENCE),
        "the gap for {CONTROL} shows its non-CWE reference (gap: {gap})"
    );
}
