// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — the same schema version is emitted whatever the corpus holds. A signed
//! export of a compliance corpus with no gaps and no evidence still carries
//! `payload.schema.schema_version` equal to the integer 1 and
//! `payload.schema.format` equal to "sovri.compliance-export/v1" — the schema
//! block is constant, independent of the corpus content. Covers issue #253.

mod signed_json_support;

use signed_json_support::{
    all_pass_consent_corpus_without_evidence, integer_member, string_member, FIXTURE_SIGNING_SEED,
};
use sovri_agent::signed_json;

/// The self-describing schema format the export declares.
const SCHEMA_FORMAT: &str = "sovri.compliance-export/v1";

#[test]
fn the_same_schema_version_is_emitted_whatever_the_corpus_holds() {
    // Given a signed JSON export of a compliance corpus with no gaps and no evidence
    // (its only control passes, and no evidence record is collected).
    let corpus = all_pass_consent_corpus_without_evidence();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then member "payload.schema.schema_version" equals the integer 1.
    assert_eq!(
        integer_member(&document, "schema_version"),
        Some("1"),
        "payload.schema.schema_version is the integer 1 whatever the corpus holds (document: {document})"
    );

    // And member "payload.schema.format" equals "sovri.compliance-export/v1".
    assert_eq!(
        string_member(&document, "format").as_deref(),
        Some(SCHEMA_FORMAT),
        "payload.schema.format is the declared export format whatever the corpus holds (document: {document})"
    );
}
