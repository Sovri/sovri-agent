// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-04 — an eligible account (login shell, not locked) warns
//! when its last login predates the 90-day threshold, when it has never logged in,
//! or when its expiry has passed. Inactivity is measured against the snapshot
//! reference date, so exactly 90 days passes and only beyond it warns.
//!
//! Mirrors `specs/mat-89-user-scanner/r04-dormant-account.feature`.

mod user_support;

use user_support::{dormant_catalog, result_for, run, scanner, status_of, DORMANT_CONTROL};

use sovri_agent::scanners::user::{UserSnapshot, DORMANT_ACCOUNT_RULE};
use sovri_sdk::Status;

/// Scenario: A recently used active account passes.
#[test]
fn a_recently_used_active_account_passes() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("alice", 1000, "/bin/bash")
            .last_login_days("alice", 3)
            .build(),
    );
    let results = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    assert_eq!(status_of(&results, DORMANT_ACCOUNT_RULE), Status::Pass);
}

/// Scenario: A long-dormant active account warns.
#[test]
fn a_long_dormant_active_account_warns() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("eve", 1002, "/bin/bash")
            .last_login_days("eve", 200)
            .build(),
    );
    let results = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    let result = result_for(&results, DORMANT_ACCOUNT_RULE);
    assert_eq!(result.status(), Status::Warning);
    let reason = result.reason().expect("a WARNING carries a reason");
    assert!(
        reason.contains("eve") && reason.contains("90"),
        "the reason names eve as dormant beyond the 90-day threshold: {reason}"
    );
}

/// Scenario Outline: The boundary is 90 days — dormant only beyond it.
#[test]
fn the_boundary_is_90_days_dormant_only_beyond_it() {
    let cases = [
        (89u32, Status::Pass),
        (90, Status::Pass),
        (91, Status::Warning),
        (200, Status::Warning),
    ];
    for (days, expected) in cases {
        let scanner = scanner(
            UserSnapshot::builder()
                .account("user", 1000, "/bin/bash")
                .last_login_days("user", days)
                .build(),
        );
        let results = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
        assert_eq!(
            status_of(&results, DORMANT_ACCOUNT_RULE),
            expected,
            "{days} days"
        );
    }
}

/// Scenario: An active account that has never logged in warns as dormant.
#[test]
fn an_active_account_that_never_logged_in_warns() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("newbie", 1000, "/bin/bash")
            .never_logged_in("newbie")
            .build(),
    );
    let results = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    let result = result_for(&results, DORMANT_ACCOUNT_RULE);
    assert_eq!(result.status(), Status::Warning);
    let reason = result.reason().expect("a WARNING carries a reason");
    assert!(
        reason.contains("newbie") && reason.to_lowercase().contains("never"),
        "the reason names newbie as never having logged in: {reason}"
    );
}

/// Scenario: A locked account is not eligible and is not warned for dormancy.
#[test]
fn a_locked_account_is_not_eligible_for_dormancy() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("carol", 1002, "/bin/bash")
            .locked("carol", "!")
            .last_login_days("carol", 300)
            .build(),
    );
    let results = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    assert_eq!(status_of(&results, DORMANT_ACCOUNT_RULE), Status::Pass);
}

/// Scenario: An account whose shadow expiry date has passed warns.
#[test]
fn an_account_whose_expiry_has_passed_warns() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("temp", 1000, "/bin/bash")
            .expired("temp")
            .build(),
    );
    let results = run(&scanner, &dormant_catalog(), &[DORMANT_CONTROL]);
    let result = result_for(&results, DORMANT_ACCOUNT_RULE);
    assert_eq!(result.status(), Status::Warning);
    let reason = result.reason().expect("a WARNING carries a reason");
    assert!(
        reason.contains("temp") && reason.to_lowercase().contains("expired"),
        "the reason names temp as expired: {reason}"
    );
}
