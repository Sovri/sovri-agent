// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-02 — root must be the only uid-0 account. Exactly one
//! passes; more than one fails, citing each offending account by name and uid 0
//! (never a password hash), anchored on `passwd`.
//!
//! Mirrors `specs/mat-89-user-scanner/r02-single-root.feature`.

mod user_support;

use user_support::{
    asserts_legal_conclusion, result_for, run, scanner, single_root_catalog, status_of,
    SINGLE_ROOT_CONTROL,
};

use sovri_agent::scanners::user::{UserSnapshot, PASSWD_LOCATOR, SINGLE_ROOT_RULE};
use sovri_sdk::{EvidenceKind, Status};

/// Scenario: A single uid-0 account passes.
#[test]
fn a_single_uid0_account_passes() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("alice", 1000, "/bin/bash")
            .build(),
    );
    let results = run(&scanner, &single_root_catalog(), &[SINGLE_ROOT_CONTROL]);
    assert_eq!(status_of(&results, SINGLE_ROOT_RULE), Status::Pass);
}

/// Scenario Outline: More than one uid-0 account fails.
#[test]
fn more_than_one_uid0_account_fails() {
    let cases: [&[&str]; 2] = [&["root", "backdoor"], &["root", "toor", "admin"]];
    for roots in cases {
        let mut builder = UserSnapshot::builder().account("alice", 1000, "/bin/bash");
        for &name in roots {
            builder = builder.account(name, 0, "/bin/bash");
        }
        let scanner = scanner(builder.build());
        let results = run(&scanner, &single_root_catalog(), &[SINGLE_ROOT_CONTROL]);
        let result = result_for(&results, SINGLE_ROOT_RULE);

        assert_eq!(result.status(), Status::Fail, "{roots:?}");
        let reason = result.reason().expect("a FAIL carries a reason");
        for &name in roots {
            assert!(reason.contains(name), "the reason names {name}: {reason}");
        }

        let log = scanner.evidence_log();
        let gap = log.explain_gap(result);
        for &name in roots {
            assert!(gap.mentions(name), "the gap cites {name}");
            let evidence = log
                .resolve(&format!("host.account.{name}"))
                .expect("an account evidence record");
            let key = evidence.key().expect("an evidence key");
            assert!(
                key.contains(name) && key.contains("uid 0"),
                "the evidence cites {name} by name and uid 0: {key}"
            );
        }
        for record in log.records() {
            assert!(
                !record.exposes_value("$6$"),
                "no password hash in the evidence"
            );
        }
    }
}

/// Scenario: The FAIL evidence is anchored on the passwd file.
#[test]
fn the_fail_evidence_is_anchored_on_the_passwd_file() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("backdoor", 0, "/bin/bash")
            .build(),
    );
    let results = run(&scanner, &single_root_catalog(), &[SINGLE_ROOT_CONTROL]);
    let result = result_for(&results, SINGLE_ROOT_RULE);
    assert_eq!(result.status(), Status::Fail);

    let log = scanner.evidence_log();
    let anchored = result
        .evidence_refs()
        .iter()
        .filter_map(|reference| log.resolve(reference))
        .any(|record| record.kind() == EvidenceKind::Config && record.locator() == PASSWD_LOCATOR);
    assert!(anchored, "a Config evidence is anchored on the passwd file");

    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(
        !asserts_legal_conclusion(reason),
        "the reason asserts no legal conclusion: {reason}"
    );
}
