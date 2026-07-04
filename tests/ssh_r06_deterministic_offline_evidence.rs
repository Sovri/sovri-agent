// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-06 — evaluation is a pure function of the captured
//! `sshd -T` dump: the same dump yields byte-for-byte identical results and
//! evidence, every non-pass result carries a Command evidence quoting the effective
//! directive anchored on the config file, and an injected dump drives the outcome
//! rather than the real host.
//!
//! Mirrors `specs/mat-90-ssh-scanner/r06-deterministic-offline-evidence.feature`.

mod ssh_support;

use ssh_support::{
    effective, effective_directive, full_catalog, result_for, root_login_catalog, run, status_of,
    CRYPTO_CONTROL, PASSWORD_AUTH_CONTROL, ROOT_LOGIN_CONTROL,
};

use sovri_agent::scanners::ssh::{PERMIT_ROOT_LOGIN_RULE, SSHD_CONFIG_LOCATOR};
use sovri_sdk::{EvidenceKind, Status, Target};

/// A lax effective dump that exercises a finding under every control.
const LAX_DUMP: &str = "permitrootlogin yes\npasswordauthentication yes\nciphers 3des-cbc\n";

const CONTROLS: [&str; 3] = [ROOT_LOGIN_CONTROL, PASSWORD_AUTH_CONTROL, CRYPTO_CONTROL];

/// Scenario: The same dump yields identical results and evidence.
#[test]
fn the_same_dump_yields_identical_results_and_evidence() {
    let first = effective(LAX_DUMP);
    let second = effective(LAX_DUMP);

    let first_results = run(&first, &full_catalog(), &CONTROLS);
    let second_results = run(&second, &full_catalog(), &CONTROLS);
    assert_eq!(
        first_results, second_results,
        "both runs produce the same results in the same order"
    );

    assert_eq!(
        first.evidence_log().records(),
        second.evidence_log().records(),
        "the evidence records are byte-for-byte identical across the two runs"
    );
}

/// Scenario: A non-pass result carries anchored command evidence quoting the
/// effective value.
#[test]
fn a_non_pass_result_carries_anchored_command_evidence() {
    let scanner = effective_directive("permitrootlogin yes");
    let results = run(&scanner, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]);
    let result = result_for(&results, PERMIT_ROOT_LOGIN_RULE);

    assert_eq!(result.status(), Status::Fail);

    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("permitrootlogin yes")),
        "the Command evidence quotes the effective 'permitrootlogin yes' value"
    );
    assert!(
        result
            .targets()
            .iter()
            .any(|target| *target == Target::file(SSHD_CONFIG_LOCATOR)),
        "the evidence is anchored on the sshd config file via a file target"
    );
}

/// Scenario: Evaluation is offline and reads only the captured dump.
#[test]
fn evaluation_reads_only_the_captured_dump() {
    // Same binary, same host, different injected dumps yield different results, so
    // evaluation consulted the captured dump rather than the real host.
    let disabled = effective_directive("permitrootlogin no");
    let enabled = effective_directive("permitrootlogin yes");

    assert_eq!(
        status_of(
            &run(&disabled, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]),
            PERMIT_ROOT_LOGIN_RULE
        ),
        Status::Pass
    );
    assert_eq!(
        status_of(
            &run(&enabled, &root_login_catalog(), &[ROOT_LOGIN_CONTROL]),
            PERMIT_ROOT_LOGIN_RULE
        ),
        Status::Fail
    );
}
