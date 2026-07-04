// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-01 — the scanner classifies each account human vs system
//! from its uid and shell, records its lock state cross-checked from `shadow`, and
//! the inventory itself never FAILs or ERRORs.
//!
//! Mirrors `specs/mat-89-user-scanner/r01-account-inventory.feature`.

mod user_support;

use user_support::{inventory_catalog, run, scanner, status_of, INVENTORY_CONTROL};

use sovri_agent::scanners::user::{
    AccountClass, AccountRecord, LockState, SystemReason, UserSnapshot, INVENTORY_RULE,
};
use sovri_sdk::Status;

/// The five-account background snapshot: alice unlocked, carol locked.
fn background() -> UserSnapshot {
    UserSnapshot::builder()
        .account("root", 0, "/bin/bash")
        .account("daemon", 1, "/usr/sbin/nologin")
        .account("alice", 1000, "/bin/bash")
        .account("svc", 1001, "/usr/sbin/nologin")
        .account("carol", 1002, "/bin/bash")
        .locked("carol", "!")
        .build()
}

/// The inventory record for `name`.
fn record<'a>(inventory: &'a [AccountRecord], name: &str) -> &'a AccountRecord {
    inventory
        .iter()
        .find(|record| record.name() == name)
        .unwrap_or_else(|| panic!("an inventory record for {name}"))
}

/// Scenario: Accounts are classified human vs system with their lock state.
#[test]
fn accounts_are_classified_human_vs_system_with_lock_state() {
    let scanner = scanner(background());
    let inventory = scanner.account_inventory();

    assert!(record(&inventory, "alice").is_active_human());
    assert_eq!(record(&inventory, "alice").lock(), LockState::Unlocked);
    assert_eq!(record(&inventory, "carol").class(), AccountClass::Human);
    assert_eq!(record(&inventory, "carol").lock(), LockState::Locked);
    assert_eq!(
        record(&inventory, "svc").class(),
        AccountClass::System(SystemReason::NonLoginShell)
    );
    assert_eq!(
        record(&inventory, "daemon").class(),
        AccountClass::System(SystemReason::LowUid)
    );
    assert!(matches!(
        record(&inventory, "root").class(),
        AccountClass::System(_)
    ));

    let results = run(&scanner, &inventory_catalog(), &[INVENTORY_CONTROL]);
    assert_eq!(status_of(&results, INVENTORY_RULE), Status::Pass);
}

/// Scenario Outline: The human boundary is uid 1000 with an interactive shell.
#[test]
fn the_human_boundary_is_uid_1000_with_an_interactive_shell() {
    let cases = [
        ("edge", 1000u32, "/bin/bash", true),
        ("belowmin", 999, "/bin/bash", false),
        ("nolog", 1500, "/usr/sbin/nologin", false),
    ];
    for (name, uid, shell, human) in cases {
        let scanner = scanner(UserSnapshot::builder().account(name, uid, shell).build());
        let class = record(&scanner.account_inventory(), name).class();
        if human {
            assert_eq!(class, AccountClass::Human, "{name} is human");
        } else {
            assert!(matches!(class, AccountClass::System(_)), "{name} is system");
        }
    }
}

/// Scenario: An unreadable shadow leaves lock state undetermined without failing
/// the inventory.
#[test]
fn an_unreadable_shadow_leaves_lock_state_undetermined_without_failing() {
    let scanner = scanner(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .account("daemon", 1, "/usr/sbin/nologin")
            .account("alice", 1000, "/bin/bash")
            .account("svc", 1001, "/usr/sbin/nologin")
            .account("carol", 1002, "/bin/bash")
            .shadow_unreadable()
            .build(),
    );
    let inventory = scanner.account_inventory();

    for name in ["root", "alice", "svc", "daemon", "carol"] {
        assert!(
            inventory.iter().any(|record| record.name() == name),
            "the inventory still lists {name}"
        );
        assert_eq!(record(&inventory, name).lock(), LockState::Undetermined);
    }

    let results = run(&scanner, &inventory_catalog(), &[INVENTORY_CONTROL]);
    assert_ne!(status_of(&results, INVENTORY_RULE), Status::Fail);
    assert_ne!(status_of(&results, INVENTORY_RULE), Status::Error);
}
