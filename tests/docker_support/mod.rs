// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-91 Docker-scanner acceptance tests.
//!
//! Each integration test file is its own crate and pulls this in with
//! `mod docker_support;`. A helper unused by a given test binary would otherwise
//! trip `dead_code`, so it is allowed here rather than at every call site. The crate
//! ships zero dependencies, so every helper is standard-library only.
#![allow(dead_code)]

use sovri_agent::scanners::docker::{
    DockerPolicy, DockerScanner, DockerSnapshot, HardeningOption, DAEMON_HARDENING_RULE,
    DAEMON_VERSION_EOL_RULE, DAEMON_VERSION_OBSOLETE_RULE, INSECURE_REGISTRIES_RULE,
    TCP_SOCKET_TLS_RULE,
};
use sovri_sdk::{Catalog, Control, ControlResult, Engine, Rule, Selection, Status};

/// The catalogued daemon-version control (carries the EOL and obsolete rules).
pub const DAEMON_VERSION_CONTROL: &str = "container.docker.daemon-version";
/// The catalogued insecure-registries control.
pub const REGISTRIES_CONTROL: &str = "container.docker.registries";
/// The catalogued daemon-socket control.
pub const SOCKET_CONTROL: &str = "container.docker.socket";
/// The catalogued daemon-hardening control.
pub const HARDENING_CONTROL: &str = "container.docker.hardening";

/// A timezone-qualified ISO-8601 execution timestamp shared by the fixtures.
pub const EXECUTED_AT: &str = "2026-07-04T09:00:00Z";
/// Execution metadata shared by the fixtures.
pub const METADATA: &str = "engine=sovri-agent";

/// The catalogue baseline: minimum-supported `24.0`, minimum-recommended `27.0`, and
/// the four expected hardening options.
#[must_use]
pub fn policy() -> DockerPolicy {
    DockerPolicy::new(
        "24.0",
        "27.0",
        [
            HardeningOption::set("log-driver"),
            HardeningOption::enabled("live-restore"),
            HardeningOption::disabled("userland-proxy"),
            HardeningOption::enabled("no-new-privileges"),
        ],
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

/// A scanner over `snapshot` with the shared catalogue policy.
#[must_use]
pub fn scanner(snapshot: DockerSnapshot) -> DockerScanner {
    DockerScanner::new(snapshot, policy())
}

/// A scanner over a reachable daemon with the given `daemon.json`.
#[must_use]
pub fn reachable_json(raw: &str) -> DockerScanner {
    scanner(
        DockerSnapshot::builder()
            .reachable()
            .daemon_json(raw)
            .build(),
    )
}

/// A scanner over a reachable daemon reporting `version` and no `daemon.json`.
#[must_use]
pub fn reachable_version(version: &str) -> DockerScanner {
    scanner(
        DockerSnapshot::builder()
            .reachable()
            .server_version(version)
            .build(),
    )
}

/// The daemon-version control with its fail-policy EOL rule and warn-policy obsolete
/// rule, both graded from the same version.
#[must_use]
pub fn version_catalog() -> Catalog {
    let control = Control::new(
        DAEMON_VERSION_CONTROL,
        "major",
        7,
        "Run a supported, current Docker engine; end-of-life releases receive no security fixes.",
    );
    let rules = vec![
        Rule::new(
            DAEMON_VERSION_EOL_RULE,
            DAEMON_VERSION_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(
            DAEMON_VERSION_OBSOLETE_RULE,
            DAEMON_VERSION_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The insecure-registries control and its single fail-policy rule.
#[must_use]
pub fn registries_catalog() -> Catalog {
    let control = Control::new(
        REGISTRIES_CONTROL,
        "major",
        8,
        "Pull images only from registries with verified TLS; trust no insecure registry.",
    );
    let rules = vec![Rule::new(
        INSECURE_REGISTRIES_RULE,
        REGISTRIES_CONTROL,
        "static-analysis",
    )
    .with_result_policy("fail")];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The daemon-socket control and its single fail-policy rule.
#[must_use]
pub fn socket_catalog() -> Catalog {
    let control = Control::new(
        SOCKET_CONTROL,
        "major",
        9,
        "Do not expose the daemon API over TCP without mutually-authenticated TLS.",
    );
    let rules = vec![
        Rule::new(TCP_SOCKET_TLS_RULE, SOCKET_CONTROL, "static-analysis")
            .with_result_policy("fail"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The daemon-hardening control and its single warn-policy rule.
#[must_use]
pub fn hardening_catalog() -> Catalog {
    let control = Control::new(
        HARDENING_CONTROL,
        "major",
        6,
        "Set the daemon hardening options to their hardened values.",
    );
    let rules = vec![
        Rule::new(DAEMON_HARDENING_RULE, HARDENING_CONTROL, "static-analysis")
            .with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// A catalog carrying every Docker control and rule, for runs that evaluate the whole
/// posture at once.
#[must_use]
pub fn full_catalog() -> Catalog {
    let controls = vec![
        Control::new(
            DAEMON_VERSION_CONTROL,
            "major",
            7,
            "Run a supported, current Docker engine.",
        ),
        Control::new(
            REGISTRIES_CONTROL,
            "major",
            8,
            "Trust no insecure registry.",
        ),
        Control::new(
            SOCKET_CONTROL,
            "major",
            9,
            "Do not expose the daemon API over TCP without mutually-authenticated TLS.",
        ),
        Control::new(
            HARDENING_CONTROL,
            "major",
            6,
            "Set the daemon hardening options to their hardened values.",
        ),
    ];
    let rules = vec![
        Rule::new(
            DAEMON_VERSION_EOL_RULE,
            DAEMON_VERSION_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(
            DAEMON_VERSION_OBSOLETE_RULE,
            DAEMON_VERSION_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
        Rule::new(
            INSECURE_REGISTRIES_RULE,
            REGISTRIES_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(TCP_SOCKET_TLS_RULE, SOCKET_CONTROL, "static-analysis")
            .with_result_policy("fail"),
        Rule::new(DAEMON_HARDENING_RULE, HARDENING_CONTROL, "static-analysis")
            .with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), controls, rules, Vec::new())
}

/// Execute `control_ids` against `scanner` with the shared engine, returning the
/// per-rule results.
///
/// # Panics
/// Panics if execution fails, which for the fixed fixtures would be a bug.
#[must_use]
pub fn run(scanner: &DockerScanner, catalog: &Catalog, control_ids: &[&str]) -> Vec<ControlResult> {
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

/// The aggregate verdict of the two-rule daemon-version control: FAIL if the EOL rule
/// failed, else WARNING if the obsolete rule warned, else PASS.
///
/// # Panics
/// Panics if either version rule is missing from `results`.
#[must_use]
pub fn version_status(results: &[ControlResult]) -> Status {
    if status_of(results, DAEMON_VERSION_EOL_RULE) == Status::Fail {
        Status::Fail
    } else if status_of(results, DAEMON_VERSION_OBSOLETE_RULE) == Status::Warning {
        Status::Warning
    } else {
        Status::Pass
    }
}

/// Whether `text` states a legal or regulatory conclusion, which no Docker-scanner
/// reason may do: the scan describes the technical situation, never its legality.
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
