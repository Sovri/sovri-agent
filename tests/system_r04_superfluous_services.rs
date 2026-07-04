// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-04 — running services are compared to the catalogue's
//! interdiction list. An interdicted service that is active WARNs and names the
//! service; a clean set, an interdicted-but-stopped service, an empty
//! interdiction list, and no running services all PASS.
//!
//! Mirrors `specs/mat-88-system-scanner/r04-superfluous-services.feature`.

mod system_support;

use system_support::{result_for, run, services_catalog, support_policy, SERVICES_CONTROL};

use sovri_agent::scanners::system::{
    ServiceManager, ServicePolicy, SupportPolicy, SystemPolicy, SystemScanner, SystemSnapshot,
    SERVICES_RULE,
};
use sovri_sdk::{ControlResult, Status};

/// The standard catalogue policy (systemd interdiction list is the shared one).
fn interdicting_policy() -> SystemPolicy {
    SystemPolicy::new(
        support_policy(),
        ServicePolicy::interdicting(["telnet", "rsh", "rlogin", "tftp", "ftp", "vsftpd"]),
    )
}

fn empty_interdiction_policy() -> SystemPolicy {
    SystemPolicy::new(SupportPolicy::new(), ServicePolicy::none())
}

fn run_services(scanner: &SystemScanner) -> Vec<ControlResult> {
    run(scanner, &services_catalog(), &[SERVICES_CONTROL])
}

/// Scenario: No interdicted service running passes.
#[test]
fn no_interdicted_service_running_passes() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Systemd)
            .service("nginx.service", true)
            .service("ssh.service", true)
            .build(),
        interdicting_policy(),
    );
    assert_eq!(
        result_for(&run_services(&scanner), SERVICES_RULE).status(),
        Status::Pass
    );
}

/// Scenario Outline: An active interdicted service warns and names the service.
#[test]
fn an_active_interdicted_service_warns_and_names_it() {
    for service in ["telnet", "tftp", "vsftpd"] {
        let scanner = SystemScanner::new(
            SystemSnapshot::builder()
                .service_manager(ServiceManager::Systemd)
                .service(format!("{service}.service"), true)
                .build(),
            interdicting_policy(),
        );
        let results = run_services(&scanner);
        let result = result_for(&results, SERVICES_RULE);

        assert_eq!(result.status(), Status::Warning, "{service} is active");
        let reason = result.reason().expect("a WARNING carries a reason");
        assert!(
            reason.contains(service),
            "the reason names {service} as unnecessary: {reason}"
        );
    }
}

/// Scenario: An interdicted service installed but not running does not warn.
#[test]
fn an_interdicted_service_that_is_not_running_does_not_warn() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Systemd)
            .service("nginx.service", true)
            .service("telnet.service", false)
            .build(),
        interdicting_policy(),
    );
    assert_eq!(
        result_for(&run_services(&scanner), SERVICES_RULE).status(),
        Status::Pass
    );
}

/// Scenario: An empty interdiction list passes regardless of running services.
#[test]
fn an_empty_interdiction_list_passes() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Systemd)
            .service("telnet.service", true)
            .build(),
        empty_interdiction_policy(),
    );
    assert_eq!(
        result_for(&run_services(&scanner), SERVICES_RULE).status(),
        Status::Pass
    );
}

/// Scenario: No running services passes.
#[test]
fn no_running_services_passes() {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Systemd)
            .build(),
        interdicting_policy(),
    );
    assert_eq!(
        result_for(&run_services(&scanner), SERVICES_RULE).status(),
        Status::Pass
    );
}
