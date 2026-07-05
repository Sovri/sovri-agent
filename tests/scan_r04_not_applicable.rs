// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 — an absent subsystem yields SKIPPED (never a false PASS) and is excluded
//! from the compliance gaps. Covers issues #75-#78.

mod scan_support;

use scan_support::{
    canonical_host, catalog, gaps_section, host_with_eol_docker, host_without_ssh, run, status_of,
    DOCKER_CONTROL, ROOT_CONTROL, SSH_ROOT_CONTROL,
};
use sovri_agent::scan::FailOn;
use sovri_sdk::{Selection, Status};

// #75 @nominal — no Docker daemon yields SKIPPED, not PASS.
#[test]
fn no_docker_daemon_yields_skipped_not_pass() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([DOCKER_CONTROL]),
        &canonical_host(),
        FailOn::Fail,
    );

    assert_eq!(
        status_of(outcome.results(), DOCKER_CONTROL),
        Status::Skipped
    );
    assert!(
        outcome.results().iter().all(|r| r.status() != Status::Pass),
        "no control is reported as PASS",
    );
    assert!(
        !gaps_section(outcome.report()).contains(DOCKER_CONTROL),
        "the SKIPPED docker control is not a gap",
    );
}

// #76 @violation — an absent SSH server never reports the control as satisfied.
#[test]
fn an_absent_ssh_server_never_reports_the_control_as_satisfied() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([SSH_ROOT_CONTROL]),
        &host_without_ssh(),
        FailOn::Fail,
    );

    assert_eq!(
        status_of(outcome.results(), SSH_ROOT_CONTROL),
        Status::Skipped,
    );
    assert_ne!(
        status_of(outcome.results(), SSH_ROOT_CONTROL),
        Status::Pass,
        "an absent server is never a satisfied control",
    );
}

// #77 @technical — SKIPPED controls do not affect the failure posture.
#[test]
fn skipped_controls_do_not_affect_the_failure_posture() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([DOCKER_CONTROL, SSH_ROOT_CONTROL, ROOT_CONTROL]),
        &host_without_ssh(),
        FailOn::Fail,
    );

    assert_eq!(
        status_of(outcome.results(), DOCKER_CONTROL),
        Status::Skipped
    );
    assert_eq!(status_of(outcome.results(), ROOT_CONTROL), Status::Pass);
    assert_eq!(
        status_of(outcome.results(), SSH_ROOT_CONTROL),
        Status::Skipped,
    );
    assert!(
        gaps_section(outcome.report()).contains("No compliance gaps were found"),
        "two SKIPPED and one PASS leave no gaps",
    );
    assert_eq!(outcome.exit_code(), 0, "SKIPPED does not raise the posture");
}

// #78 @technical — a present but non-compliant subsystem is FAIL, not SKIPPED.
#[test]
fn a_present_but_non_compliant_subsystem_is_fail_not_skipped() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([DOCKER_CONTROL]),
        &host_with_eol_docker(),
        FailOn::Fail,
    );

    assert_eq!(status_of(outcome.results(), DOCKER_CONTROL), Status::Fail);
    assert_ne!(
        status_of(outcome.results(), DOCKER_CONTROL),
        Status::Skipped,
        "a present, end-of-life daemon is a FAIL, not a SKIP",
    );
    assert!(
        gaps_section(outcome.report()).contains(DOCKER_CONTROL),
        "the FAIL docker control is a gap",
    );
}
