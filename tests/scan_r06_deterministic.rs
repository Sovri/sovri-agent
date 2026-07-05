// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 — output is byte-identical for the same catalog and host state, with no
//! wall-clock value in the listing. Covers issues #87-#89.

mod scan_support;

use scan_support::{
    canonical_host, canonical_host_reversed, catalog, control_ids, run, DOCKER_CONTROL,
    EXECUTED_AT, FRAMEWORK_ID, OS_CONTROL, ROOT_CONTROL, SSH_PASSWORD_CONTROL, SSH_ROOT_CONTROL,
};
use sovri_agent::scan::FailOn;
use sovri_sdk::Selection;

// #87 @nominal — two runs over the same inputs produce identical output.
#[test]
fn two_runs_over_the_same_inputs_produce_identical_output() {
    let catalog = catalog();
    let registry = canonical_host();
    let selection = Selection::framework(FRAMEWORK_ID);

    let first = run(&catalog, &selection, &registry, FailOn::Fail);
    let second = run(&catalog, &selection, &registry, FailOn::Fail);

    assert_eq!(first.report(), second.report(), "byte-identical output");
    assert_eq!(first.exit_code(), second.exit_code(), "the same exit code");
}

// #88 @technical — output order is independent of scanner registration order.
#[test]
fn output_order_is_independent_of_scanner_registration_order() {
    let catalog = catalog();
    let selection = Selection::framework(FRAMEWORK_ID);

    let normal = run(&catalog, &selection, &canonical_host(), FailOn::Fail);
    let reversed = run(
        &catalog,
        &selection,
        &canonical_host_reversed(),
        FailOn::Fail,
    );

    // The listing is ordered by control id then rule id regardless of registration.
    assert_eq!(
        control_ids(reversed.results()),
        vec![
            DOCKER_CONTROL,
            ROOT_CONTROL,
            OS_CONTROL,
            SSH_PASSWORD_CONTROL,
            SSH_ROOT_CONTROL,
        ],
    );
    assert_eq!(
        reversed.report(),
        normal.report(),
        "reversed registration produces identical output",
    );
}

// #89 @limit — the printed listing embeds no wall-clock value.
#[test]
fn the_printed_listing_embeds_no_wall_clock_value() {
    let catalog = catalog();
    let registry = canonical_host();
    let selection = Selection::controls([ROOT_CONTROL]);

    let first = run(&catalog, &selection, &registry, FailOn::Fail);
    let second = run(&catalog, &selection, &registry, FailOn::Fail);

    assert_eq!(
        first.report(),
        second.report(),
        "the listing is identical across runs",
    );
    // The execution timestamp is never printed, so no run timestamp can vary.
    assert!(
        !first.report().contains("2026-07-05"),
        "the listing contains no wall-clock date",
    );
    assert!(
        !first.report().contains(EXECUTED_AT),
        "the listing does not embed the execution timestamp",
    );
}
