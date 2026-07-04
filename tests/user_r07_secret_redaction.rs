// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-07 — account evidence is `Sensitive` and `shadow`
//! evidence `Secret`; both drop the raw excerpt, keeping only a content hash and
//! size. A fixture password hash therefore appears in no evidence and no gap
//! explanation, even when a rule fails.
//!
//! Mirrors `specs/mat-89-user-scanner/r07-secret-redaction.feature`.

mod user_support;

use user_support::{
    no_empty_password_catalog, result_for, run, scanner, FAKE_HASH, NO_EMPTY_PASSWORD_CONTROL,
};

use sovri_agent::scanners::user::{UserSnapshot, NO_EMPTY_PASSWORD_RULE};
use sovri_sdk::Status;

/// A snapshot where alice carries the fixture hash and dave is passwordless.
fn snapshot_with_hash_and_finding() -> UserSnapshot {
    UserSnapshot::builder()
        .account("alice", 1000, "/bin/bash")
        .hashed("alice", FAKE_HASH)
        .account("dave", 1003, "/bin/bash")
        .empty_password("dave")
        .build()
}

/// Scenario: A fixture password hash is absent from all evidence.
#[test]
fn a_fixture_password_hash_is_absent_from_all_evidence() {
    let scanner = scanner(snapshot_with_hash_and_finding());
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    let result = result_for(&results, NO_EMPTY_PASSWORD_RULE);

    let log = scanner.evidence_log();
    for record in log.records() {
        assert!(
            !record.exposes_value(FAKE_HASH),
            "no evidence excerpt contains the hash: {}",
            record.id()
        );
        if let Some(key) = record.key() {
            assert!(
                !key.contains(FAKE_HASH),
                "no evidence key contains the hash"
            );
        }
        assert!(!record.content_hash().contains(FAKE_HASH));
        assert!(!record.locator().contains(FAKE_HASH));
        assert!(!record.id().contains(FAKE_HASH));
    }
    assert!(
        !log.explain_gap(result).mentions(FAKE_HASH),
        "no gap explanation contains the hash"
    );
}

/// Scenario: Account evidence redacts the raw line, keeping hash and size.
#[test]
fn account_evidence_redacts_the_raw_line_keeping_hash_and_size() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("alice", 1000, "/bin/bash")
            .hashed("alice", FAKE_HASH)
            .build(),
    );
    let log = scanner.evidence_log();

    let shadow = log
        .resolve("host.shadow.alice")
        .expect("a shadow evidence record");
    assert!(shadow.excerpt().is_none(), "the shadow excerpt is dropped");
    assert!(
        !shadow.content_hash().is_empty(),
        "the content hash is kept"
    );
    assert!(
        shadow.size_bytes().is_some_and(|bytes| bytes > 0),
        "size_bytes is kept"
    );

    let account = log
        .resolve("host.account.alice")
        .expect("an account evidence record");
    assert!(
        account.excerpt().is_none(),
        "the account excerpt is dropped"
    );
    assert!(
        !account.content_hash().is_empty(),
        "the account content hash is kept"
    );
    assert!(
        account.size_bytes().is_some_and(|bytes| bytes > 0),
        "the account size_bytes is kept"
    );
}

/// Scenario: A failing finding cites the account but not its hash.
#[test]
fn a_failing_finding_cites_the_account_but_not_its_hash() {
    let scanner = scanner(snapshot_with_hash_and_finding());
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    let result = result_for(&results, NO_EMPTY_PASSWORD_RULE);

    assert_eq!(result.status(), Status::Fail);
    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(reason.contains("dave"), "the reason names dave: {reason}");
    assert!(!reason.contains(FAKE_HASH), "the reason carries no hash");

    let log = scanner.evidence_log();
    assert!(!log.explain_gap(result).mentions(FAKE_HASH));
    for record in log.records() {
        assert!(!record.exposes_value(FAKE_HASH));
    }
}
