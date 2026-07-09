// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — the signed JSON export's payload carries every required section. A
//! signed export of the persisted "shopfront-2026-06-24" consent corpus has a
//! payload member for each of scan, frameworks, controls, results, gaps,
//! evidence, and scores, so a downstream consumer finds every section of the
//! compliance run in the one document. Covers issue #244.

mod signed_json_support;

use signed_json_support::{consent_corpus, has_member, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

/// The seven payload sections the Scenario Outline's Examples require, in the
/// order the feature lists them.
const REQUIRED_SECTIONS: [&str; 7] = [
    "scan",
    "frameworks",
    "controls",
    "results",
    "gaps",
    "evidence",
    "scores",
];

#[test]
fn the_payload_contains_every_required_section() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24":
    // the gdpr-eprivacy framework, its consent.tracker.prior-consent control, that
    // control's FAIL and PASS results, and the ev-0001 evidence at dist/main.js.
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let corpus = consent_corpus();

    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then the payload has a "<section>" member, for each required section.
    for section in REQUIRED_SECTIONS {
        assert!(
            has_member(&document, section),
            "the payload carries a {section:?} member (document: {document})"
        );
    }
}
