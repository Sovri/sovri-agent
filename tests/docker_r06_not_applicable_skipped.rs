// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-06 — Docker is optional infrastructure. When the daemon is
//! absent, unreachable, or the probe is denied permission, every Docker control is
//! SKIPPED (not-applicable) rather than errored or failed: a host that does not run
//! Docker cannot fail a Docker control. Only a reachable daemon is assessed.
//!
//! Mirrors `specs/mat-91-docker-scanner/r06-not-applicable-skipped.feature`.

mod docker_support;

use docker_support::{result_for, run, scanner, socket_catalog, SOCKET_CONTROL};

use sovri_agent::scanners::docker::{DockerSnapshot, TCP_SOCKET_TLS_RULE};
use sovri_sdk::Status;

/// Scenario: An absent Docker daemon skips the control, stating Docker is not present.
#[test]
fn an_absent_daemon_skips_the_control() {
    let scanner = scanner(DockerSnapshot::builder().absent().build());
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    let result = result_for(&results, TCP_SOCKET_TLS_RULE);

    assert_eq!(result.status(), Status::Skipped);
    assert_ne!(result.status(), Status::Pass, "absence is not a pass");
    let reason = result.reason().expect("a SKIPPED carries a reason");
    assert!(
        reason.contains("not present"),
        "the reason states Docker is not present: {reason}"
    );
}

/// Scenario: An unreachable daemon skips rather than errors.
#[test]
fn an_unreachable_daemon_skips_rather_than_errors() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .unreachable("cannot connect to the Docker daemon socket")
            .build(),
    );
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    let result = result_for(&results, TCP_SOCKET_TLS_RULE);

    assert_eq!(result.status(), Status::Skipped);
    assert_ne!(
        result.status(),
        Status::Error,
        "unreachable is not an error"
    );
    assert_ne!(result.status(), Status::Pass, "unreachable is not a pass");
}

/// Scenario: A stale daemon.json left behind by an unreachable daemon does not fail the
/// control — it is skipped, not graded.
#[test]
fn a_stale_config_under_an_unreachable_daemon_is_not_graded() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .unreachable("cannot connect to the Docker daemon socket")
            .daemon_json(r#"{"hosts": ["tcp://0.0.0.0:2375"]}"#)
            .build(),
    );
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    let result = result_for(&results, TCP_SOCKET_TLS_RULE);

    assert_eq!(result.status(), Status::Skipped);
    assert_ne!(
        result.status(),
        Status::Fail,
        "an unreachable daemon's stale config is not graded to a FAIL"
    );
}

/// Scenario: A permission-denied probe skips rather than errors.
#[test]
fn a_permission_denied_probe_skips_rather_than_errors() {
    let scanner = scanner(DockerSnapshot::builder().permission_denied().build());
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    let result = result_for(&results, TCP_SOCKET_TLS_RULE);

    assert_eq!(result.status(), Status::Skipped);
    assert_ne!(
        result.status(),
        Status::Error,
        "a denied probe is optional infrastructure, not a scan error"
    );
}

/// Scenario: A reachable daemon is assessed, not skipped.
#[test]
fn a_reachable_daemon_is_assessed_not_skipped() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .daemon_json(r#"{"hosts": ["unix:///var/run/docker.sock"]}"#)
            .build(),
    );
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    assert_ne!(
        result_for(&results, TCP_SOCKET_TLS_RULE).status(),
        Status::Skipped,
        "a reachable daemon is assessed"
    );
}
