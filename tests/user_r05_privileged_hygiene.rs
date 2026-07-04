// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-05 — the scanner inventories privileged accounts (uid 0,
//! sudo / wheel members, sudoers grants) and carries that inventory as evidence. A
//! privileged account outside the catalogue's expected set warns; the inventory
//! cites names and sources, never a password hash.
//!
//! Mirrors `specs/mat-89-user-scanner/r05-privileged-hygiene.feature`.

mod user_support;

use user_support::{
    privileged_catalog, result_for, run, scanner, status_of, FAKE_HASH, PRIVILEGED_CONTROL,
};

use sovri_agent::scanners::user::{UserSnapshot, PRIVILEGED_EXPECTED_RULE};
use sovri_sdk::Status;

/// Scenario: Only expected accounts are privileged.
#[test]
fn only_expected_accounts_are_privileged() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("alice", 1000, "/bin/bash")
            .sudo_member("alice")
            .build(),
    );
    let results = run(&scanner, &privileged_catalog(), &[PRIVILEGED_CONTROL]);
    assert_eq!(status_of(&results, PRIVILEGED_EXPECTED_RULE), Status::Pass);

    let log = scanner.evidence_log();
    for name in ["root", "alice"] {
        let evidence = log
            .resolve(&format!("host.privileged.{name}"))
            .expect("a privileged-inventory evidence record");
        assert!(
            evidence.key().expect("an evidence key").contains(name),
            "the inventory lists {name}"
        );
    }
}

/// Scenario Outline: A privileged account outside the expected set warns.
#[test]
fn a_privileged_account_outside_the_expected_set_warns() {
    let cases = [
        ("mallory", "sudo group"),
        ("oncall", "wheel group"),
        ("bob", "sudoers.d grant"),
    ];
    for (name, source) in cases {
        let base = UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account(name, 1005, "/bin/bash");
        let builder = match source {
            "sudo group" => base.sudo_member(name),
            "wheel group" => base.wheel_member(name),
            _ => base.sudoers_grant(name),
        };
        let scanner = scanner(builder.build());
        let results = run(&scanner, &privileged_catalog(), &[PRIVILEGED_CONTROL]);
        let result = result_for(&results, PRIVILEGED_EXPECTED_RULE);

        assert_eq!(result.status(), Status::Warning, "{name} via {source}");
        let reason = result.reason().expect("a WARNING carries a reason");
        assert!(
            reason.contains(name) && reason.to_lowercase().contains("unexpected"),
            "the reason names {name} as an unexpected privileged account: {reason}"
        );
    }
}

/// Scenario: An expected sudoer does not warn.
#[test]
fn an_expected_sudoer_does_not_warn() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("alice", 1000, "/bin/bash")
            .sudo_member("alice")
            .build(),
    );
    let results = run(&scanner, &privileged_catalog(), &[PRIVILEGED_CONTROL]);
    assert_eq!(status_of(&results, PRIVILEGED_EXPECTED_RULE), Status::Pass);
}

/// Scenario: The privileged inventory cites names and sources, never a hash.
#[test]
fn the_privileged_inventory_cites_names_and_sources_never_a_hash() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("mallory", 1005, "/bin/bash")
            .hashed("mallory", FAKE_HASH)
            .sudo_member("mallory")
            .build(),
    );
    let _ = run(&scanner, &privileged_catalog(), &[PRIVILEGED_CONTROL]);

    let log = scanner.evidence_log();
    let evidence = log
        .resolve("host.privileged.mallory")
        .expect("a privileged-inventory evidence record");
    let key = evidence.key().expect("an evidence key");
    assert!(
        key.contains("mallory") && key.contains("sudo group"),
        "the inventory lists mallory by name and grant source: {key}"
    );
    for record in log.records() {
        assert!(
            !record.exposes_value(FAKE_HASH),
            "no password hash in the evidence"
        );
        if let Some(key) = record.key() {
            assert!(
                !key.contains(FAKE_HASH),
                "no password hash in an evidence key"
            );
        }
    }
}
