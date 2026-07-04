// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-07 — no result, reason, or evidence asserts a legal or
//! regulatory conclusion; every reason describes the technical cause and stays
//! technical across FAIL, WARNING, SKIPPED, and ERROR outcomes.
//!
//! Mirrors `specs/mat-88-system-scanner/r07-no-legal-conclusions.feature`.

mod system_support;

use system_support::{
    asserts_legal_conclusion, os_support_catalog, policy, result_for, run, services_catalog,
    OS_SUPPORT_CONTROL, SERVICES_CONTROL,
};

use sovri_agent::scanners::system::{
    ServiceManager, SystemScanner, SystemSnapshot, OS_EOL_RULE, OS_SUPPORT_UNDETERMINED_RULE,
    SERVICES_RULE,
};

/// The reason a run produces for `rule_id`, evaluating `scanner` over `catalog`.
fn reason_for(scanner: &SystemScanner, catalog_control: &str, rule_id: &str) -> String {
    let catalog = if catalog_control == OS_SUPPORT_CONTROL {
        os_support_catalog()
    } else {
        services_catalog()
    };
    let results = run(scanner, &catalog, &[catalog_control]);
    result_for(&results, rule_id)
        .reason()
        .expect("a non-pass result carries a reason")
        .to_string()
}

fn os_scanner(raw: &str) -> SystemScanner {
    SystemScanner::new(SystemSnapshot::builder().os_release(raw).build(), policy())
}

/// The FAIL reason: the OS version is out of support.
fn fail_reason() -> String {
    reason_for(
        &os_scanner("ID=ubuntu\nVERSION_ID=\"18.04\"\n"),
        OS_SUPPORT_CONTROL,
        OS_EOL_RULE,
    )
}

/// The WARNING reason: an interdicted service is running.
fn service_warning_reason() -> String {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder()
            .service_manager(ServiceManager::Systemd)
            .service("telnet.service", true)
            .build(),
        policy(),
    );
    reason_for(&scanner, SERVICES_CONTROL, SERVICES_RULE)
}

/// The WARNING reason: the OS support status could not be determined.
fn undetermined_reason() -> String {
    reason_for(
        &os_scanner("ID=ubuntu\nVERSION_ID=\"30.10\"\n"),
        OS_SUPPORT_CONTROL,
        OS_SUPPORT_UNDETERMINED_RULE,
    )
}

/// The SKIPPED reason: no service manager is present.
fn skipped_reason() -> String {
    let scanner = SystemScanner::new(
        SystemSnapshot::builder().no_service_manager().build(),
        policy(),
    );
    reason_for(&scanner, SERVICES_CONTROL, SERVICES_RULE)
}

/// The ERROR reason: the os-release file could not be read.
fn error_reason() -> String {
    reason_for(
        &SystemScanner::new(
            SystemSnapshot::builder().os_release_unreadable().build(),
            policy(),
        ),
        OS_SUPPORT_CONTROL,
        OS_EOL_RULE,
    )
}

/// Scenario Outline: Result reasons stay technical, never legal, across every
/// non-pass status.
#[test]
fn every_non_pass_reason_is_technical_and_states_no_legal_conclusion() {
    let cases = [
        ("out of support", fail_reason()),
        ("service", service_warning_reason()),
        ("determined", undetermined_reason()),
        ("service manager", skipped_reason()),
        ("os-release", error_reason()),
    ];
    for (technical_cause, reason) in cases {
        assert!(
            reason.to_lowercase().contains(technical_cause),
            "the reason describes the technical cause '{technical_cause}': {reason}"
        );
        assert!(
            !asserts_legal_conclusion(&reason),
            "the reason contains no legal or regulatory conclusion: {reason}"
        );
    }
}
