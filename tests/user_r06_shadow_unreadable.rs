// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-06 — when `shadow` cannot be read the password rule
//! errors rather than passing, while rules sourced from a readable file (the uid-0
//! count from `passwd`) still evaluate. The error is scoped to the shadow-dependent
//! rules.
//!
//! Mirrors `specs/mat-89-user-scanner/r06-shadow-unreadable.feature`.

mod user_support;

use user_support::{
    full_catalog, no_empty_password_catalog, run, scanner, status_of, FAKE_HASH,
    NO_EMPTY_PASSWORD_CONTROL, SINGLE_ROOT_CONTROL,
};

use sovri_agent::scanners::user::{UserSnapshot, NO_EMPTY_PASSWORD_RULE, SINGLE_ROOT_RULE};
use sovri_sdk::Status;

/// Scenario: A readable shadow lets the password rule reach a real verdict.
#[test]
fn a_readable_shadow_reaches_a_real_verdict() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("alice", 1000, "/bin/bash")
            .hashed("alice", FAKE_HASH)
            .build(),
    );
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    assert_ne!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Error);
}

/// Scenario: An unreadable shadow errors the password rule and never passes.
#[test]
fn an_unreadable_shadow_errors_the_password_rule_and_never_passes() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("alice", 1000, "/bin/bash")
            .shadow_unreadable()
            .build(),
    );
    let results = run(
        &scanner,
        &no_empty_password_catalog(),
        &[NO_EMPTY_PASSWORD_CONTROL],
    );
    assert_eq!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Error);
    assert_ne!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Pass);
}

/// Scenario: An unreadable shadow does not stop the uid-0 rule sourced from passwd.
#[test]
fn an_unreadable_shadow_does_not_stop_the_uid0_rule() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("backdoor", 0, "/bin/bash")
            .shadow_unreadable()
            .build(),
    );
    let results = run(
        &scanner,
        &full_catalog(),
        &[SINGLE_ROOT_CONTROL, NO_EMPTY_PASSWORD_CONTROL],
    );
    assert_eq!(status_of(&results, SINGLE_ROOT_RULE), Status::Fail);
    assert_eq!(status_of(&results, NO_EMPTY_PASSWORD_RULE), Status::Error);
    // The error is scoped to the shadow-dependent rules only.
    assert_ne!(status_of(&results, SINGLE_ROOT_RULE), Status::Error);
}
