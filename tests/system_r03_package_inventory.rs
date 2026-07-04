// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-03 — packages are inventoried through the distro package
//! manager. A present manager PASSes with a bounded, hashed Command evidence; no
//! manager at all is an ERROR, never a PASS. The excerpt is inlined up to the
//! 4096-byte cap and dropped beyond it, while the hash and size are always kept.
//!
//! Mirrors `specs/mat-88-system-scanner/r03-package-inventory.feature`.

mod system_support;

use system_support::{
    inventory_of_size, packages_catalog, policy, result_for, run, status_of, PACKAGES_CONTROL,
};

use sovri_agent::scanners::system::{
    Manager, SystemScanner, SystemSnapshot, PACKAGE_INVENTORY_RULE,
};
use sovri_sdk::{ControlResult, EvidenceKind, Status};

fn run_packages(scanner: &SystemScanner) -> Vec<ControlResult> {
    run(scanner, &packages_catalog(), &[PACKAGES_CONTROL])
}

/// Scenario Outline: A present package manager passes with Command evidence.
#[test]
fn a_present_package_manager_passes_with_command_evidence() {
    let cases = [
        (
            Manager::Dpkg,
            "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
            "openssh-server\t1:9.6p1-3\nnginx\t1.24.0-2",
        ),
        (
            Manager::Rpm,
            "ID=rhel\nVERSION_ID=\"9\"\n",
            "openssh-server-9.3p1-1.el9\nnginx-1.24.0-1.el9",
        ),
    ];
    for (manager, os_release, inventory) in cases {
        let scanner = SystemScanner::new(
            SystemSnapshot::builder()
                .os_release(os_release)
                .package_manager(manager)
                .inventory(inventory)
                .build(),
            policy(),
        );
        let results = run_packages(&scanner);
        let result = result_for(&results, PACKAGE_INVENTORY_RULE);

        assert_eq!(result.status(), Status::Pass, "manager {manager:?}");

        let log = scanner.evidence_log();
        let ref_id = result
            .evidence_refs()
            .first()
            .expect("the PASS records a Command evidence ref");
        let evidence = log.resolve(ref_id).expect("evidence resolves");
        assert_eq!(evidence.kind(), EvidenceKind::Command);
        assert!(
            !evidence.content_hash().is_empty(),
            "the evidence carries a content hash"
        );
        assert_eq!(
            evidence.size_bytes(),
            Some(inventory.len() as u64),
            "the evidence records the inventory size"
        );
    }
}

/// Scenario: No package manager is an error, never a pass.
#[test]
fn no_package_manager_is_an_error_never_a_pass() {
    let scanner = SystemScanner::new(SystemSnapshot::builder().build(), policy());
    let results = run_packages(&scanner);
    let result = result_for(&results, PACKAGE_INVENTORY_RULE);

    assert_eq!(result.status(), Status::Error);
    assert_ne!(result.status(), Status::Pass);
}

/// Scenario: A present manager reporting no packages passes with empty evidence.
#[test]
fn an_empty_inventory_passes_with_size_zero_evidence() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .package_manager(Manager::Dpkg)
            .inventory("")
            .build(),
        policy(),
    );
    let results = run_packages(&scanner);
    let result = result_for(&results, PACKAGE_INVENTORY_RULE);

    assert_eq!(result.status(), Status::Pass);
    let log = scanner.evidence_log();
    let ref_id = result
        .evidence_refs()
        .first()
        .expect("an empty inventory still records evidence");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert_eq!(evidence.size_bytes(), Some(0), "the inventory is empty");
}

/// Scenario: With both managers present the distro ID selects the manager.
///
/// The Debian family selects dpkg, the RHEL family rpm — triangulated over both.
#[test]
fn with_both_managers_present_the_distro_id_selects_the_manager() {
    for (os_id, expected) in [("ubuntu", Manager::Dpkg), ("rhel", Manager::Rpm)] {
        let scanner = SystemScanner::new(
            SystemSnapshot::builder()
                .os_release(format!("ID={os_id}\nVERSION_ID=\"1\"\n"))
                .package_manager(Manager::Dpkg)
                .package_manager(Manager::Rpm)
                .inventory("nginx\t1.24.0-2")
                .build(),
            policy(),
        );
        let results = run_packages(&scanner);

        assert_eq!(
            scanner.selected_package_manager(),
            Some(expected),
            "the {os_id} ID selects {expected:?}"
        );
        assert_eq!(status_of(&results, PACKAGE_INVENTORY_RULE), Status::Pass);
    }
}

/// Scenario Outline: The excerpt is inlined up to the 4096-byte cap and dropped
/// beyond it; the hash and size are always kept.
#[test]
fn the_excerpt_is_capped_at_4096_bytes_but_hash_and_size_are_kept() {
    let cases = [
        (180usize, true),
        (4096, true),
        (4097, false),
        (12048, false),
    ];
    for (size, excerpt_included) in cases {
        let inventory = inventory_of_size(size);
        assert_eq!(inventory.len(), size, "fixture is exactly {size} bytes");

        let scanner = SystemScanner::new(
            SystemSnapshot::builder()
                .package_manager(Manager::Dpkg)
                .inventory(inventory)
                .build(),
            policy(),
        );
        let results = run_packages(&scanner);
        let result = result_for(&results, PACKAGE_INVENTORY_RULE);
        assert_eq!(result.status(), Status::Pass, "{size} bytes");

        let log = scanner.evidence_log();
        let ref_id = result.evidence_refs().first().expect("evidence ref");
        let evidence = log.resolve(ref_id).expect("evidence resolves");

        assert_eq!(
            evidence.excerpt().is_some(),
            excerpt_included,
            "excerpt inclusion at {size} bytes"
        );
        assert!(
            !evidence.content_hash().is_empty(),
            "the hash is kept at {size} bytes"
        );
        assert_eq!(
            evidence.size_bytes(),
            Some(size as u64),
            "the size is recorded at {size} bytes"
        );
    }
}
