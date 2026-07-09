// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — the document self-describes its schema format and version. A signed
//! export of the persisted "shopfront-2026-06-24" consent corpus carries
//! `payload.schema.format` equal to "sovri.compliance-export/v1" and
//! `payload.schema.schema_version` equal to the integer 1 — a JSON number, not a
//! quoted string — so a consumer can tell which schema it is reading and gate on
//! the version. Covers issue #250.

mod signed_json_support;

use signed_json_support::{consent_corpus, integer_member, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::signed_json;

/// The self-describing schema format the export declares.
const SCHEMA_FORMAT: &str = "sovri.compliance-export/v1";

#[test]
fn the_document_self_describes_its_schema_format_and_version() {
    // Given a signed JSON export of the "shopfront-2026-06-24" consent corpus.
    let corpus = consent_corpus();
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

    // Then member "payload.schema.format" equals "sovri.compliance-export/v1".
    assert_eq!(
        string_member(&document, "format").as_deref(),
        Some(SCHEMA_FORMAT),
        "payload.schema.format is the declared export format (document: {document})"
    );

    // And member "payload.schema.schema_version" equals the integer 1.
    assert_eq!(
        integer_member(&document, "schema_version"),
        Some("1"),
        "payload.schema.schema_version is the integer 1, not a quoted string (document: {document})"
    );
}
