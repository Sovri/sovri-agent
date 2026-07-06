// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test: scanner evidence carries a real SHA-256 content digest
//! (MAT-93), derived from the record's own bytes, never a placeholder token.
//!
//! Wiring the SDK's content hashing into the agent scanners means each record's
//! `content_hash` is the canonical SHA-256 of the bytes the scanner observed. A
//! non-redacted record hashes its retained excerpt; a redacted record keeps the
//! same real hash while dropping the bytes.

mod scan_support;

use scan_support::{system_debian, user_single_root};
use sovri_agent::scanners::system::SupportStatus;
use sovri_sdk::{content_digest, is_canonical, Classification, Evidence};

/// The placeholder token the scanners carried before real hashing was wired.
const PLACEHOLDER: &str = "sha256:unverified";

/// The evidence a Debian 9 system scanner emits (os-release plus package
/// inventory), none of it redacted.
fn system_records() -> Vec<Evidence> {
    system_debian("9", SupportStatus::EndOfSupport)
        .evidence_log()
        .records()
        .to_vec()
}

/// The evidence a single-root user scanner emits: one redacted account record.
fn user_records() -> Vec<Evidence> {
    user_single_root().evidence_log().records().to_vec()
}

/// Scenario: a non-redacted record's hash is the SHA-256 of its own bytes.
#[test]
fn a_non_redacted_record_hash_is_the_digest_of_its_bytes() {
    let records = system_records();
    // The os-release config record keeps its excerpt (textual, in-bounds, public).
    let record = records
        .iter()
        .find(|record| record.excerpt().is_some())
        .expect("a non-redacted record with a retained excerpt");
    let excerpt = record.excerpt().expect("the retained excerpt");

    // The content hash is the canonical SHA-256 of exactly those bytes.
    let expected = content_digest(excerpt.as_bytes()).to_canonical();
    assert_eq!(record.content_hash(), expected.as_str());
    // It is a canonical sha256:<hex> value, not the old placeholder token.
    assert!(is_canonical(record.content_hash()));
    assert_ne!(record.content_hash(), PLACEHOLDER);
}

/// Scenario: a redacted account record keeps a real hash but no raw bytes.
#[test]
fn a_redacted_record_keeps_a_real_hash_without_the_bytes() {
    let records = user_records();
    let record = records
        .iter()
        .find(|record| {
            record
                .classification()
                .is_some_and(Classification::redacts_raw_value)
        })
        .expect("a redacted account record");

    // Redaction drops the excerpt...
    assert!(record.excerpt().is_none());
    // ...but the record still carries a real, canonical digest, not the placeholder.
    assert!(is_canonical(record.content_hash()));
    assert_ne!(record.content_hash(), PLACEHOLDER);
}

/// Scenario: no scanner record carries the pre-MAT-93 placeholder token.
#[test]
fn no_scanner_record_carries_the_placeholder_token() {
    let mut records = system_records();
    records.extend(user_records());
    assert!(!records.is_empty());

    for record in &records {
        assert!(
            is_canonical(record.content_hash()),
            "record {} has a non-canonical hash",
            record.id()
        );
        assert_ne!(
            record.content_hash(),
            PLACEHOLDER,
            "record {} still carries the placeholder",
            record.id()
        );
    }
}
