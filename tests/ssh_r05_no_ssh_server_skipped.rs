// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-05 — a host with no SSH server is SKIPPED, never a false
//! PASS; a present-but-unreadable server ERRORs rather than skipping or passing;
//! and a server installed but not running is still assessed, since `sshd -T` parses
//! the config without the daemon.
//!
//! Mirrors `specs/mat-90-ssh-scanner/r05-no-ssh-server-skipped.feature`.

mod ssh_support;

use ssh_support::{
    effective_directive, policy, result_for, root_login_catalog, run, status_of, ROOT_LOGIN_CONTROL,
};

use sovri_agent::scanners::ssh::{SshScanner, SshSnapshot, PERMIT_ROOT_LOGIN_RULE};
use sovri_sdk::Status;

/// Scenario: No SSH server is not applicable and is skipped.
#[test]
fn no_ssh_server_is_not_applicable_and_is_skipped() {
    let scanner = SshScanner::new(SshSnapshot::builder().absent().build(), policy());
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, PERMIT_ROOT_LOGIN_RULE);

    assert_eq!(result.status(), Status::Skipped);
    assert_ne!(result.status(), Status::Pass);
    let reason = result
        .reason()
        .expect("a SKIPPED carries a reason")
        .to_lowercase();
    assert!(
        reason.contains("no ssh server"),
        "the reason states no SSH server is present: {reason}"
    );
}

/// Scenario: A present but unreadable server errors, never skips and never passes.
#[test]
fn a_present_but_unreadable_server_errors_never_skips_never_passes() {
    let scanner = SshScanner::new(SshSnapshot::builder().unassessable().build(), policy());
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, PERMIT_ROOT_LOGIN_RULE);

    assert_eq!(result.status(), Status::Error);
    assert_ne!(result.status(), Status::Skipped);
    assert_ne!(result.status(), Status::Pass);
}

/// Scenario: A server that is installed but not running is still assessed.
#[test]
fn a_server_installed_but_not_running_is_still_assessed() {
    // sshd -T parses the config without the daemon, so a captured effective config
    // is assessable even when the service is not running.
    let scanner = effective_directive("permitrootlogin no");
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);

    assert_ne!(
        status_of(&results, PERMIT_ROOT_LOGIN_RULE),
        Status::Skipped,
        "an assessable configuration is graded, not skipped"
    );
}
