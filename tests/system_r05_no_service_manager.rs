// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-05 — the services rule evaluates when a service manager
//! (systemd or a non-systemd fallback) is present, and is SKIPPED, not falsely
//! passed, only when no service manager is present at all.
//!
//! Mirrors `specs/mat-88-system-scanner/r05-no-service-manager.feature`.

mod system_support;

use system_support::{policy, result_for, run, services_catalog, SERVICES_CONTROL};

use sovri_agent::scanners::system::{ServiceManager, SystemScanner, SystemSnapshot, SERVICES_RULE};
use sovri_sdk::{ControlResult, Status};

fn run_services(scanner: &SystemScanner) -> Vec<ControlResult> {
    run(scanner, &services_catalog(), &[SERVICES_CONTROL])
}

/// Scenario: A present service manager lets the services rule evaluate.
#[test]
fn a_present_service_manager_lets_the_rule_evaluate() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Systemd)
            .service("nginx.service", true)
            .build(),
        policy(),
    );
    let result = result_for(&run_services(&scanner), SERVICES_RULE).status();

    assert_eq!(result, Status::Pass);
    assert_ne!(result, Status::Skipped);
}

/// Scenario: A non-systemd fallback still evaluates the services rule.
#[test]
fn a_non_systemd_fallback_still_evaluates_the_rule() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Fallback)
            .service("nginx", true)
            .build(),
        policy(),
    );
    let result = result_for(&run_services(&scanner), SERVICES_RULE).status();

    assert_eq!(result, Status::Pass);
    assert_ne!(result, Status::Skipped);
}

/// Scenario: No service manager skips the services rule with a reason.
#[test]
fn no_service_manager_skips_the_rule_with_a_reason() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder().no_service_manager().build(),
        policy(),
    );
    let results = run_services(&scanner);
    let result = result_for(&results, SERVICES_RULE);

    assert_eq!(result.status(), Status::Skipped);
    assert_ne!(result.status(), Status::Pass);
    let reason = result.reason().expect("a SKIPPED carries a reason");
    assert!(
        reason.to_lowercase().contains("no service manager"),
        "the reason states no service manager is present: {reason}"
    );
}
