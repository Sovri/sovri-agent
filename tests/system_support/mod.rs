// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-88 system-scanner acceptance tests.
//!
//! Each integration test file is its own crate and pulls this in with
//! `mod system_support;`. A helper unused by a given test binary would otherwise
//! trip `dead_code`, so it is allowed here rather than at every call site. The
//! crate ships zero dependencies, so every helper is standard-library only.
#![allow(dead_code)]

use sovri_agent::scanners::system::{
    Manager, ServiceManager, SupportPolicy, SupportStatus, SystemPolicy, SystemScanner,
    SystemSnapshot, OS_EOL_RULE, OS_SUPPORT_UNDETERMINED_RULE, PACKAGE_INVENTORY_RULE,
    SERVICES_RULE,
};
use sovri_sdk::{Catalog, Control, ControlResult, Engine, Rule, Selection, Status};

/// The catalogued OS-support control.
pub const OS_SUPPORT_CONTROL: &str = "host.os.support";
/// The catalogued package-inventory control.
pub const PACKAGES_CONTROL: &str = "host.packages.baseline";
/// The catalogued running-services control.
pub const SERVICES_CONTROL: &str = "host.services.footprint";

/// A timezone-qualified ISO-8601 execution timestamp shared by the fixtures.
pub const EXECUTED_AT: &str = "2026-07-04T09:00:00Z";
/// Execution metadata for runs that do not exercise host identity (R-01 owns identity).
pub const METADATA: &str = "engine=sovri-agent";

/// The starter interdiction list the catalogue supplies for R-04.
pub const INTERDICTED: [&str; 6] = ["telnet", "rsh", "rlogin", "tftp", "ftp", "vsftpd"];

/// The OS-support policy the catalogue supplies for R-02: two distros, each with a
/// supported and an end-of-support version.
#[must_use]
pub fn support_policy() -> SupportPolicy {
    SupportPolicy::new()
        .with("ubuntu", "24.04", SupportStatus::Supported)
        .with("ubuntu", "18.04", SupportStatus::EndOfSupport)
        .with("debian", "12", SupportStatus::Supported)
        .with("debian", "10", SupportStatus::EndOfSupport)
}

/// The catalogue-driven policy: the OS-support table plus the interdiction list.
#[must_use]
pub fn policy() -> SystemPolicy {
    SystemPolicy::new(
        support_policy(),
        sovri_agent::scanners::system::ServicePolicy::interdicting(INTERDICTED),
    )
}

/// An engine carrying the shared timestamp and metadata.
///
/// # Panics
/// Panics if the shared timestamp is not a valid execution timestamp — a fixture bug.
#[must_use]
pub fn engine() -> Engine {
    Engine::new(EXECUTED_AT, METADATA).expect("valid engine timestamp")
}

/// An engine carrying the shared timestamp and the given execution `metadata`.
///
/// # Panics
/// Panics if the shared timestamp is not a valid execution timestamp — a fixture bug.
#[must_use]
pub fn engine_with_metadata(metadata: &str) -> Engine {
    Engine::new(EXECUTED_AT, metadata).expect("valid engine timestamp")
}

/// The OS-support control with its fail-policy EOL rule and warn-policy
/// support-undetermined rule.
#[must_use]
pub fn os_support_catalog() -> Catalog {
    let control = Control::new(
        OS_SUPPORT_CONTROL,
        "major",
        8,
        "Upgrade to a vendor-supported release that still receives security updates.",
    );
    let rules = vec![
        Rule::new(OS_EOL_RULE, OS_SUPPORT_CONTROL, "static-analysis").with_result_policy("fail"),
        Rule::new(
            OS_SUPPORT_UNDETERMINED_RULE,
            OS_SUPPORT_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The package-inventory control and its single inventory rule (PASS or ERROR).
#[must_use]
pub fn packages_catalog() -> Catalog {
    let control = Control::new(
        PACKAGES_CONTROL,
        "minor",
        3,
        "Ensure a distro package manager is available so installed packages can be inventoried.",
    );
    let rules = vec![Rule::new(
        PACKAGE_INVENTORY_RULE,
        PACKAGES_CONTROL,
        "static-analysis",
    )];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The running-services control and its single warn-policy no-superfluous rule.
#[must_use]
pub fn services_catalog() -> Catalog {
    let control = Control::new(
        SERVICES_CONTROL,
        "major",
        5,
        "Disable network services the host does not need.",
    );
    let rules = vec![
        Rule::new(SERVICES_RULE, SERVICES_CONTROL, "static-analysis").with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// A catalog carrying every system control and rule.
#[must_use]
pub fn full_catalog() -> Catalog {
    let controls = vec![
        Control::new(
            OS_SUPPORT_CONTROL,
            "major",
            8,
            "Upgrade to a vendor-supported release that still receives security updates.",
        ),
        Control::new(
            PACKAGES_CONTROL,
            "minor",
            3,
            "Ensure a distro package manager is available so installed packages can be inventoried.",
        ),
        Control::new(
            SERVICES_CONTROL,
            "major",
            5,
            "Disable network services the host does not need.",
        ),
    ];
    let rules = vec![
        Rule::new(OS_EOL_RULE, OS_SUPPORT_CONTROL, "static-analysis").with_result_policy("fail"),
        Rule::new(
            OS_SUPPORT_UNDETERMINED_RULE,
            OS_SUPPORT_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
        Rule::new(PACKAGE_INVENTORY_RULE, PACKAGES_CONTROL, "static-analysis"),
        Rule::new(SERVICES_RULE, SERVICES_CONTROL, "static-analysis").with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), controls, rules, Vec::new())
}

/// Execute `control_ids` against `scanner` with the shared engine, returning the
/// per-rule results.
///
/// # Panics
/// Panics if execution fails, which for the fixed fixtures would be a bug.
#[must_use]
pub fn run(scanner: &SystemScanner, catalog: &Catalog, control_ids: &[&str]) -> Vec<ControlResult> {
    engine()
        .execute(
            catalog,
            &Selection::controls(control_ids.iter().copied()),
            scanner,
        )
        .expect("execution succeeds")
}

/// The single result produced by rule `rule_id`.
///
/// # Panics
/// Panics if no result carries `rule_id`, which would be a fixture bug.
#[must_use]
pub fn result_for<'a>(results: &'a [ControlResult], rule_id: &str) -> &'a ControlResult {
    results
        .iter()
        .find(|result| result.rule_id() == rule_id)
        .unwrap_or_else(|| panic!("a result for rule {rule_id}"))
}

/// The status of the result produced by rule `rule_id`.
///
/// # Panics
/// Panics if no result carries `rule_id`.
#[must_use]
pub fn status_of(results: &[ControlResult], rule_id: &str) -> Status {
    result_for(results, rule_id).status()
}

/// A healthy snapshot: supported OS, dpkg present with a small inventory, systemd
/// running a clean service set. Identity is set from `hostname` / `fqdn`.
#[must_use]
pub fn healthy_snapshot(hostname: Option<&str>, fqdn: Option<&str>) -> SystemSnapshot {
    let mut builder = SystemSnapshot::builder()
        .os_release("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
        .package_manager(Manager::Dpkg)
        .inventory("openssh-server\t1:9.6p1-3\nnginx\t1.24.0-2")
        .service_manager(ServiceManager::Systemd)
        .service("nginx.service", true)
        .service("ssh.service", true);
    if let Some(name) = hostname {
        builder = builder.hostname(name);
    }
    if let Some(name) = fqdn {
        builder = builder.fqdn(name);
    }
    builder.build()
}

/// A scanner over `snapshot` with the shared catalogue policy.
#[must_use]
pub fn scanner(snapshot: SystemSnapshot) -> SystemScanner {
    SystemScanner::new(snapshot, policy())
}

/// Whether `text` states a legal or regulatory conclusion, which no system-scanner
/// reason, result, or evidence may do (R-07). A conservative phrase set: the scan
/// describes the technical situation, never its legality.
#[must_use]
pub fn asserts_legal_conclusion(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "illegal",
        "unlawful",
        "violation of law",
        "breach of law",
        "violates the law",
        "legal violation",
        "regulatory violation",
        "gdpr",
        "nis2",
        "non-compliant",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

/// A serialized package inventory of exactly `size` bytes, shaped like `dpkg`
/// output. Used to exercise the excerpt cap in R-03.
#[must_use]
pub fn inventory_of_size(size: usize) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    let mut index = 0u32;
    while text.len() < size {
        let _ = writeln!(text, "package-{index:05}\t1.0.0-{index}");
        index += 1;
    }
    text.truncate(size); // ASCII only, so truncation lands on a char boundary
    text
}
