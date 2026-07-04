// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-02 — `PermitRootLogin`: `no` PASSes, `yes` FAILs, the
//! non-password paths WARN under the default catalogue and FAIL under a hardened
//! one, and the `without-password` alias is treated as `prohibit-password`. Every
//! non-pass result quotes the effective value and asserts no legal conclusion.
//!
//! Mirrors `specs/mat-90-ssh-scanner/r02-permit-root-login.feature`.

mod ssh_support;

use ssh_support::{
    asserts_legal_conclusion, effective_directive, hardened_root_login_catalog, policy, result_for,
    root_login_catalog, run, ROOT_LOGIN_CONTROL,
};

use sovri_agent::scanners::ssh::{
    SshScanner, SshSnapshot, PERMIT_ROOT_LOGIN_RULE, ROOT_LOGIN_KEY_ONLY_RULE, SSHD_CONFIG_LOCATOR,
};
use sovri_sdk::{EvidenceKind, Status, Target};

/// Scenario: Root login disabled passes, carrying Command evidence.
#[test]
fn root_login_disabled_passes_with_command_evidence() {
    let scanner = effective_directive("permitrootlogin no");
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, PERMIT_ROOT_LOGIN_RULE);

    assert_eq!(result.status(), Status::Pass);

    let log = scanner.evidence_log();
    let ref_id = result
        .evidence_refs()
        .first()
        .expect("the PASS carries a configuration evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("permitrootlogin no")),
        "the Command evidence quotes the effective 'permitrootlogin no' value"
    );
}

/// Scenario: Root login enabled fails, quoting the effective value.
#[test]
fn root_login_enabled_fails_quoting_the_value() {
    let scanner = effective_directive("permitrootlogin yes");
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, PERMIT_ROOT_LOGIN_RULE);

    assert_eq!(result.status(), Status::Fail);
    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(
        reason.contains("permitrootlogin yes"),
        "the reason quotes the effective value: {reason}"
    );
    assert!(
        !asserts_legal_conclusion(reason),
        "the reason asserts no legal conclusion: {reason}"
    );
}

/// Scenario Outline: Root login permitted only by a non-password path warns under
/// the default catalogue.
#[test]
fn non_password_paths_warn_under_the_default_catalogue() {
    for value in ["prohibit-password", "forced-commands-only"] {
        let scanner = effective_directive(&format!("permitrootlogin {value}"));
        let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
        let result = result_for(&results, ROOT_LOGIN_KEY_ONLY_RULE);

        assert_eq!(result.status(), Status::Warning, "value {value}");
        let reason = result
            .reason()
            .expect("a WARNING carries a reason")
            .to_lowercase();
        assert!(
            reason.contains("without a password"),
            "the reason notes root login is permitted without a password: {reason}"
        );
        assert!(
            reason.contains("permitrootlogin no") && reason.contains("review"),
            "the reason recommends 'no' for review: {reason}"
        );
    }
}

/// Scenario Outline: A hardened catalogue turns any non-password root login into a
/// failure.
#[test]
fn a_hardened_catalogue_fails_non_password_paths() {
    for value in ["prohibit-password", "forced-commands-only"] {
        let scanner = effective_directive(&format!("permitrootlogin {value}"));
        let results = run(
            &scanner,
            &hardened_root_login_catalog(),
            &[ROOT_LOGIN_CONTROL],
        );

        assert_eq!(
            result_for(&results, ROOT_LOGIN_KEY_ONLY_RULE).status(),
            Status::Fail,
            "value {value}"
        );
    }
}

/// Scenario: The `without-password` alias is treated as `prohibit-password` on the
/// fallback path.
#[test]
fn without_password_alias_is_prohibit_password_on_the_fallback_path() {
    let scanner = SshScanner::new(
        SshSnapshot::builder()
            .parsed_config("PermitRootLogin without-password\n")
            .build(),
        policy(),
    );
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, ROOT_LOGIN_KEY_ONLY_RULE);

    assert_eq!(result.status(), Status::Warning);
    let reason = result
        .reason()
        .expect("a WARNING carries a reason")
        .to_lowercase();
    assert!(
        reason.contains("without-password") && reason.contains("prohibit-password"),
        "the reason treats 'without-password' as the 'prohibit-password' posture: {reason}"
    );
}

/// Scenario: The FAIL evidence is anchored on the sshd config file.
#[test]
fn the_fail_evidence_is_anchored_on_the_config_file() {
    let scanner = effective_directive("permitrootlogin yes");
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, PERMIT_ROOT_LOGIN_RULE);

    assert_eq!(result.status(), Status::Fail);
    assert!(
        result
            .targets()
            .iter()
            .any(|target| *target == Target::file(SSHD_CONFIG_LOCATOR)),
        "the FAIL is anchored on the sshd config file via a file target"
    );

    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
    assert_eq!(
        log.resolve(ref_id).expect("evidence resolves").kind(),
        EvidenceKind::Command,
        "a Command evidence backs the FAIL"
    );
}
