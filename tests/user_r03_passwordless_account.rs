// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-03 — an unlocked account with a login shell and an empty
//! `shadow` password field can log in with no password, so it fails — human or
//! system. A locked or non-login account is not a finding even with an empty field.
//!
//! Mirrors `specs/mat-89-user-scanner/r03-passwordless-account.feature`.

mod user_support;

use user_support::{
    no_empty_password_catalog, result_for, run, scanner, status_of, NO_EMPTY_PASSWORD_CONTROL,
};

use sovri_agent::scanners::user::{UserSnapshot, NO_EMPTY_PASSWORD_RULE};
use sovri_sdk::Status;

/// Scenario: Accounts that all have a password or are locked pass.
#[test]
fn accounts_that_all_have_a_password_or_are_locked_pass() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("alice", 1000, "/bin/bash")
            .account("carol", 1002, "/bin/bash")
            .locked("carol", "!")
            .account("svc", 1001, "/usr/sbin/nologin")
            .empty_password("svc")
            .build(),
    );
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    assert_eq!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Pass);
}

/// Scenario Outline: A non-locked login account with an empty password fails,
/// over a human and a system account.
#[test]
fn a_non_locked_login_account_with_an_empty_password_fails() {
    let cases = [("dave", 1003u32, "/bin/bash"), ("legacy", 400, "/bin/sh")];
    for (name, uid, shell) in cases {
        let scanner = scanner(
            UserSnapshot::builder()
                .account(name, uid, shell)
                .empty_password(name)
                .build(),
        );
        let results = run(
            &scanner,
            &no_empty_password_catalog(),
            &[NO_EMPTY_PASSWORD_CONTROL],
        );
        let result = result_for(&results, NO_EMPTY_PASSWORD_RULE);

        assert_eq!(result.status(), Status::Fail, "{name}");
        let reason = result.reason().expect("a FAIL carries a reason");
        assert!(
            reason.contains(name) && reason.to_lowercase().contains("without a password"),
            "the reason names {name} as able to log in without a password: {reason}"
        );

        let log = scanner.evidence_log();
        assert!(
            log.explain_gap(result).mentions(name),
            "the evidence cites {name}"
        );
        for record in log.records() {
            assert!(
                !record.exposes_value("$6$"),
                "no password hash in the evidence"
            );
        }
    }
}

/// Scenario: A locked account is not a finding even without a usable password.
#[test]
fn a_locked_account_is_not_a_finding() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("ghost", 1004, "/bin/bash")
            .locked("ghost", "!")
            .build(),
    );
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    assert_eq!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Pass);
}

/// Scenario: An empty password on a non-login account is not a finding.
#[test]
fn an_empty_password_on_a_non_login_account_is_not_a_finding() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("sync", 5, "/usr/sbin/nologin")
            .empty_password("sync")
            .build(),
    );
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    assert_eq!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Pass);
}
