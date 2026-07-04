// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-03 — `PasswordAuthentication` must be `no`: `no` PASSes,
//! `yes` FAILs quoting the effective value, and an unconfigured host is caught at
//! the OpenSSH effective default `yes` rather than slipping through as unset.
//!
//! Mirrors `specs/mat-90-ssh-scanner/r03-password-authentication.feature`.

mod ssh_support;

use ssh_support::{
    asserts_legal_conclusion, effective, effective_directive, password_auth_catalog, result_for,
    run, PASSWORD_AUTH_CONTROL,
};

use sovri_agent::scanners::ssh::{PASSWORD_AUTH_RULE, SSHD_CONFIG_LOCATOR};
use sovri_sdk::{EvidenceKind, Status, Target};

/// Scenario: Key-only authentication passes, carrying Command evidence.
#[test]
fn key_only_authentication_passes_with_command_evidence() {
    let scanner = effective_directive("passwordauthentication no");
    let results = run(&scanner, &password_auth_catalog(), &[PASSWORD_AUTH_CONTROL]);
    let result = result_for(&results, PASSWORD_AUTH_RULE);

    assert_eq!(result.status(), Status::Pass);

    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a PASS evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("passwordauthentication no")),
        "the Command evidence quotes the effective 'passwordauthentication no' value"
    );
}

/// Scenario: Password authentication enabled fails, quoting the value.
#[test]
fn password_authentication_enabled_fails_quoting_the_value() {
    let scanner = effective_directive("passwordauthentication yes");
    let results = run(&scanner, &password_auth_catalog(), &[PASSWORD_AUTH_CONTROL]);
    let result = result_for(&results, PASSWORD_AUTH_RULE);

    assert_eq!(result.status(), Status::Fail);
    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(
        reason.contains("passwordauthentication yes"),
        "the reason quotes the effective value: {reason}"
    );
    assert!(
        !asserts_legal_conclusion(reason),
        "the reason asserts no legal conclusion: {reason}"
    );
}

/// Scenario: An unconfigured host is caught at the effective default.
#[test]
fn an_unconfigured_host_is_caught_at_the_effective_default() {
    // sshd -T folds in the OpenSSH default, so an otherwise-default host reports
    // `passwordauthentication yes` in the effective dump.
    let scanner = effective("permitrootlogin no\npasswordauthentication yes\n");
    let results = run(&scanner, &password_auth_catalog(), &[PASSWORD_AUTH_CONTROL]);

    assert_eq!(
        result_for(&results, PASSWORD_AUTH_RULE).status(),
        Status::Fail
    );
}

/// Scenario: The FAIL evidence is anchored on the sshd config file.
#[test]
fn the_fail_evidence_is_anchored_on_the_config_file() {
    let scanner = effective_directive("passwordauthentication yes");
    let results = run(&scanner, &password_auth_catalog(), &[PASSWORD_AUTH_CONTROL]);
    let result = result_for(&results, PASSWORD_AUTH_RULE);

    assert_eq!(result.status(), Status::Fail);
    assert!(
        result
            .targets()
            .iter()
            .any(|target| *target == Target::file(SSHD_CONFIG_LOCATOR)),
        "the FAIL is anchored on the sshd config file via a file target"
    );
}
