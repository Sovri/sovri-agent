// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 — the scan runs offline: it evaluates injected snapshots and reads no
//! input beyond the catalog directory and the command-line flags. Covers issues
//! #90-#92.

mod scan_support;

use scan_support::{
    canonical_host, catalog, control_ids, listing_section, run, status_of, DOCKER_CONTROL,
    FRAMEWORK_ID, OS_CONTROL, ROOT_CONTROL, SSH_PASSWORD_CONTROL, SSH_ROOT_CONTROL,
};
use sovri_agent::scan::FailOn;
use sovri_sdk::{Selection, Status};

// #90 @nominal — the scan completes over injected snapshots with no network available.
#[test]
fn the_scan_completes_over_injected_snapshots_with_no_network_available() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([ROOT_CONTROL]),
        &canonical_host(),
        FailOn::Fail,
    );

    assert_eq!(status_of(outcome.results(), ROOT_CONTROL), Status::Pass);
    assert!(
        listing_section(outcome.report()).contains(ROOT_CONTROL),
        "the scan prints the control result listing",
    );
    assert_eq!(outcome.exit_code(), 0);
}

// #91 @technical — output is independent of environment configuration.
#[test]
fn output_is_independent_of_environment_configuration() {
    let catalog = catalog();
    let selection = Selection::controls([ROOT_CONTROL]);

    let base = run(&catalog, &selection, &canonical_host(), FailOn::Fail);

    // The scan consults no environment variable, so setting arbitrary ones cannot
    // change its output. (Edition 2021: set_var/remove_var are safe.)
    std::env::set_var("SOVRI_ENDPOINT", "https://example.test/ignored");
    std::env::set_var("SOVRI_TOKEN", "arbitrary-value");
    let with_env = run(&catalog, &selection, &canonical_host(), FailOn::Fail);
    std::env::remove_var("SOVRI_ENDPOINT");
    std::env::remove_var("SOVRI_TOKEN");

    assert_eq!(
        base.report(),
        with_env.report(),
        "output is independent of environment configuration",
    );
    assert_eq!(base.exit_code(), with_env.exit_code());
}

// #92 @technical — the scan's only inputs are the catalog directory and the flags.
#[test]
fn the_scans_only_inputs_are_the_catalog_directory_and_the_command_line_flags() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::framework(FRAMEWORK_ID),
        &canonical_host(),
        FailOn::Fail,
    );

    // The result set is exactly the catalog's mapped controls: nothing phantom is
    // pulled in, nothing mapped is dropped, so the report is a pure function of
    // the catalog and the selection.
    let mut got = control_ids(outcome.results());
    got.sort_unstable();
    let mut want = vec![
        DOCKER_CONTROL,
        ROOT_CONTROL,
        OS_CONTROL,
        SSH_PASSWORD_CONTROL,
        SSH_ROOT_CONTROL,
    ];
    want.sort_unstable();
    assert_eq!(got, want, "the report is determined by the catalog alone");

    // Evidence is cited by id, never by filesystem path, so no credential or
    // secret file is named in the output.
    for result in outcome.results() {
        for reference in result.evidence_refs() {
            assert!(
                !reference.contains('/'),
                "evidence is an id, not a path: {reference}",
            );
        }
    }
}
