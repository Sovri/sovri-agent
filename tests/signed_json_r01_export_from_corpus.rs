// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — a signed JSON compliance export is produced from the persisted consent
//! corpus: a JSON object carrying `payload`, `verification`, and `signature`, its
//! schema format and the run's executed-at read straight from the corpus. Covers
//! issue #243.

mod signed_json_support;

use signed_json_support::{has_member, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;

/// The run's fixed executed-at, carried verbatim into the payload's scan record.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The self-describing schema format the export declares.
const SCHEMA_FORMAT: &str = "sovri.compliance-export/v1";

#[test]
fn export_a_signed_json_document_from_the_persisted_corpus() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24"
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let corpus = Corpus::new(EXECUTED_AT);

    // When the maintainer exports the signed JSON for "shopfront-2026-06-24".
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then a non-empty JSON document is produced.
    assert!(!document.is_empty(), "the signed JSON document has content");

    // And it is a JSON object with members "payload", "verification", and "signature".
    assert!(
        has_member(&document, "payload"),
        "the document carries a payload member"
    );
    assert!(
        has_member(&document, "verification"),
        "the document carries a verification member"
    );
    assert!(
        has_member(&document, "signature"),
        "the document carries a signature member"
    );

    // And member "payload.schema.format" equals "sovri.compliance-export/v1".
    assert_eq!(
        string_member(&document, "format").as_deref(),
        Some(SCHEMA_FORMAT),
        "payload.schema.format is the declared export format"
    );

    // And member "payload.scan.executed_at" equals "2026-06-24T13:16:28Z".
    assert_eq!(
        string_member(&document, "executed_at").as_deref(),
        Some(EXECUTED_AT),
        "payload.scan.executed_at is the run's fixed executed-at"
    );
}
