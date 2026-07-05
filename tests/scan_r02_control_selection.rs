// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — selection by framework id or control ids drives which controls run;
//! exactly one selection is required. Covers issues #63-#71.

mod scan_e2e_support;
mod scan_support;

use scan_e2e_support::{scan, CATALOG, INVALID_CATALOG};
use scan_support::{
    canonical_host, catalog, control_ids, run, DOCKER_CONTROL, FRAMEWORK_ID, OS_CONTROL,
    ROOT_CONTROL, SSH_PASSWORD_CONTROL, SSH_ROOT_CONTROL,
};
use sovri_agent::scan::{resolve_selection, FailOn};

// #63 @nominal @use-case — selecting a framework runs exactly the controls mapped to it.
#[test]
fn selecting_a_framework_runs_exactly_the_controls_mapped_to_it() {
    let catalog = catalog();
    let selection =
        resolve_selection(&catalog, Some(FRAMEWORK_ID), None).expect("a known framework resolves");
    let outcome = run(&catalog, &selection, &canonical_host(), FailOn::Fail);

    assert_eq!(
        control_ids(outcome.results()),
        vec![
            DOCKER_CONTROL,
            ROOT_CONTROL,
            OS_CONTROL,
            SSH_PASSWORD_CONTROL,
            SSH_ROOT_CONTROL,
        ],
        "exactly the mapped controls run, and no other",
    );
}

// #64 @nominal @use-case — selecting explicit control ids runs only those controls.
#[test]
fn selecting_explicit_control_ids_runs_only_those_controls() {
    let catalog = catalog();
    let selection = resolve_selection(
        &catalog,
        None,
        Some("host.ssh.root-access,host.os.lifecycle"),
    )
    .expect("known control ids resolve");
    let outcome = run(&catalog, &selection, &canonical_host(), FailOn::Fail);

    // Ordered by control id, so os.lifecycle precedes ssh.root-access.
    assert_eq!(
        control_ids(outcome.results()),
        vec![OS_CONTROL, SSH_ROOT_CONTROL],
    );
    let executed = control_ids(outcome.results());
    assert!(!executed.contains(&ROOT_CONTROL));
    assert!(!executed.contains(&DOCKER_CONTROL));
    assert!(!executed.contains(&SSH_PASSWORD_CONTROL));
}

// #68 @technical @use-case — duplicate control ids are deduplicated, not rejected.
#[test]
fn duplicate_control_ids_in_the_selection_are_deduplicated_not_rejected() {
    let catalog = catalog();
    let selection = resolve_selection(&catalog, None, Some("host.os.lifecycle,host.os.lifecycle"))
        .expect("duplicate ids resolve, not rejected");
    let outcome = run(&catalog, &selection, &canonical_host(), FailOn::Fail);

    assert_eq!(control_ids(outcome.results()), vec![OS_CONTROL]);
    assert_eq!(
        outcome
            .results()
            .iter()
            .filter(|r| r.control_id() == OS_CONTROL)
            .count(),
        1,
        "the control is executed once",
    );
}

// #65 @violation @e2e — an unknown control id is a usage error, not a scan finding.
#[test]
fn an_unknown_control_id_is_a_usage_error_not_a_scan_finding() {
    let run = scan(&[
        "--catalog",
        CATALOG,
        "--control",
        "host.ssh.root-access,host.unknown.control",
    ]);
    assert_eq!(run.code, Some(64));
    let combined = run.combined();
    assert!(combined.contains("unknown control"));
    assert!(combined.contains("host.unknown.control"));
    assert!(
        !run.printed_listing(),
        "no control result listing is printed"
    );
}

// #66 @violation @e2e — an unknown framework id is a usage error, not a silent empty scan.
#[test]
fn an_unknown_framework_id_is_a_usage_error_not_a_silent_empty_scan() {
    let run = scan(&["--catalog", CATALOG, "--framework", "cis-lynux"]);
    assert_eq!(run.code, Some(64));
    let combined = run.combined();
    assert!(combined.contains("unknown framework"));
    assert!(combined.contains("cis-lynux"));
    assert!(
        !run.printed_listing(),
        "no control result listing is printed"
    );
}

// #67 @violation @e2e — a catalog that loads but fails validation is a usage error.
#[test]
fn a_catalog_that_loads_but_fails_validation_is_a_usage_error() {
    let run = scan(&["--catalog", INVALID_CATALOG, "--framework", "cis-linux"]);
    assert_eq!(run.code, Some(64));
    assert!(
        run.combined().contains("catalog is invalid"),
        "the command reports that the catalog is invalid",
    );
    assert!(
        !run.printed_listing(),
        "no control result listing is printed"
    );
}

// #69 @violation @e2e — an empty control id entry in the selection is a usage error.
#[test]
fn an_empty_control_id_entry_in_the_selection_is_a_usage_error() {
    let run = scan(&["--catalog", CATALOG, "--control", "host.os.lifecycle,"]);
    assert_eq!(run.code, Some(64));
    assert!(
        run.combined().contains("empty control id"),
        "the command reports an empty control id in the selection",
    );
    assert!(
        !run.printed_listing(),
        "no control result listing is printed"
    );
}

// #70 @technical @e2e — providing no selection is a usage error.
#[test]
fn providing_no_selection_is_a_usage_error() {
    let run = scan(&["--catalog", CATALOG]);
    assert_eq!(run.code, Some(64));
    assert!(run
        .combined()
        .contains("exactly one of --framework or --control is required"),);
}

// #71 @technical @e2e — providing both selection modes is a usage error.
#[test]
fn providing_both_selection_modes_is_a_usage_error() {
    let run = scan(&[
        "--catalog",
        CATALOG,
        "--framework",
        "cis-linux",
        "--control",
        "host.os.lifecycle",
    ]);
    assert_eq!(run.code, Some(64));
    assert!(run
        .combined()
        .contains("--framework and --control are mutually exclusive"),);
}
