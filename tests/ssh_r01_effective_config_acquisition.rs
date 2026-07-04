// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-01 — the scanner reads the effective `sshd` configuration
//! from `sshd -T`, falls back to parsing the config file when the dump is
//! unavailable, and errors rather than passing a directive that could hide inside
//! an unreadable `Include`.
//!
//! Mirrors `specs/mat-90-ssh-scanner/r01-effective-config-acquisition.feature`.

mod ssh_support;

use ssh_support::{
    effective, password_auth_catalog, policy, result_for, root_login_catalog, run,
    PASSWORD_AUTH_CONTROL, ROOT_LOGIN_CONTROL,
};

use sovri_agent::scanners::ssh::{
    ConfigSource, SshScanner, SshSnapshot, EFFECTIVE_CONFIG_EVIDENCE_ID, PASSWORD_AUTH_RULE,
    PERMIT_ROOT_LOGIN_RULE, SSHD_EFFECTIVE_COMMAND,
};
use sovri_sdk::{EvidenceKind, Status};

/// Scenario: The effective dump from `sshd -T` is the configuration source.
#[test]
fn the_effective_dump_from_sshd_t_is_the_configuration_source() {
    let scanner = effective("permitrootlogin no\npasswordauthentication no\n");

    assert_eq!(scanner.source(), ConfigSource::EffectiveDump);

    let log = scanner.evidence_log();
    let evidence = log
        .resolve(EFFECTIVE_CONFIG_EVIDENCE_ID)
        .expect("the effective dump is recorded as evidence");
    assert_eq!(
        evidence.kind(),
        EvidenceKind::Command,
        "a Command evidence records the sshd -T invocation"
    );
    assert_eq!(evidence.locator(), SSHD_EFFECTIVE_COMMAND);
}

/// Scenario: `sshd -T` unavailable falls back to the parsed config file.
#[test]
fn sshd_t_unavailable_falls_back_to_the_parsed_config_file() {
    let scanner = SshScanner::new(
        SshSnapshot::builder()
            .parsed_config("permitrootlogin no\n")
            .build(),
        policy(),
    );

    assert_eq!(scanner.source(), ConfigSource::ParsedFallback);

    let note = scanner
        .acquisition_note()
        .expect("the parsed-fallback path notes the dump was unavailable")
        .to_lowercase();
    assert!(
        note.contains("effective") && note.contains("unavailable"),
        "the acquisition notes the effective dump was unavailable: {note}"
    );
}

/// Scenario: A resolvable directive is still graded despite an unreadable `Include`.
#[test]
fn a_resolvable_directive_is_graded_despite_an_unreadable_include() {
    let scanner = SshScanner::new(
        SshSnapshot::builder()
            .parsed_config("permitrootlogin no\n")
            .unresolved_include()
            .build(),
        policy(),
    );

    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    assert_eq!(
        result_for(&results, PERMIT_ROOT_LOGIN_RULE).status(),
        Status::Pass,
        "a directive readable in the config is graded normally"
    );

    let caveat = scanner
        .acquisition_caveat()
        .expect("an unresolved Include carries a WARNING caveat")
        .to_lowercase();
    assert!(
        caveat.contains("include") && caveat.contains("resolv"),
        "the caveat states an Include was unresolved: {caveat}"
    );
}

/// Scenario: A directive that could hide inside an unreadable `Include` errors,
/// never passes.
#[test]
fn a_directive_hidden_in_an_unreadable_include_errors_never_passes() {
    // The readable config sets PermitRootLogin but not PasswordAuthentication, and
    // an Include could not be read — the missing directive could be set inside it.
    let scanner = SshScanner::new(
        SshSnapshot::builder()
            .parsed_config("permitrootlogin no\n")
            .unresolved_include()
            .build(),
        policy(),
    );

    let results = run(&scanner, &password_auth_catalog(), &[PASSWORD_AUTH_CONTROL]);
    let result = result_for(&results, PASSWORD_AUTH_RULE);

    assert_eq!(result.status(), Status::Error);
    assert_ne!(result.status(), Status::Pass);
    let reason = result
        .reason()
        .expect("an ERROR carries a reason")
        .to_lowercase();
    assert!(
        reason.contains("could not be confirmed") && reason.contains("include"),
        "the reason notes the value could not be confirmed because an Include was unresolved: {reason}"
    );
}
