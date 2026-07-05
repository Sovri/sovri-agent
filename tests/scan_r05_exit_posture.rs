// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 — the exit code reflects the run's posture; `--fail-on` tunes the
//! threshold; usage and load errors use a distinct code. Covers issues #79-#86.

mod scan_e2e_support;
mod scan_support;

use scan_e2e_support::{scan, CATALOG, MISSING_CATALOG};
use scan_support::{
    canonical_host, catalog, catalog_with_audit, run, status_of, OS_CONTROL, ROOT_CONTROL,
};
use sovri_agent::scan::{posture_exit_code, FailOn};
use sovri_sdk::{Selection, Status};

/// A status vector with `fails` FAIL results followed by `warns` WARNING results.
fn statuses(fails: usize, warns: usize) -> Vec<Status> {
    let mut out = Vec::with_capacity(fails + warns);
    for _ in 0..fails {
        out.push(Status::Fail);
    }
    for _ in 0..warns {
        out.push(Status::Warning);
    }
    out
}

// #79 @nominal @use-case — a run with at least one FAIL exits non-zero.
#[test]
fn a_run_with_at_least_one_fail_exits_non_zero() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([OS_CONTROL]),
        &canonical_host(),
        FailOn::Fail,
    );
    assert_eq!(status_of(outcome.results(), OS_CONTROL), Status::Fail);
    assert_eq!(outcome.exit_code(), 2);
}

// #80 @nominal @use-case — a run with no FAIL exits zero.
#[test]
fn a_run_with_no_fail_exits_zero() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::controls([ROOT_CONTROL]),
        &canonical_host(),
        FailOn::Fail,
    );
    assert_eq!(status_of(outcome.results(), ROOT_CONTROL), Status::Pass);
    assert_eq!(outcome.exit_code(), 0);
}

// #81 @limit @use-case — the FAIL boundary decides the default exit code.
#[test]
fn the_fail_boundary_decides_the_default_exit_code() {
    // (fails, warns, expected code) under the default threshold.
    let examples = [(0, 0, 0), (0, 3, 0), (1, 0, 2), (5, 2, 2)];
    for (fails, warns, code) in examples {
        assert_eq!(
            posture_exit_code(&statuses(fails, warns), FailOn::Fail),
            code,
            "{fails} FAIL / {warns} WARNING under the default threshold",
        );
    }
}

// #82 @technical @use-case — --fail-on tunes the threshold.
#[test]
fn fail_on_tunes_the_threshold() {
    // (threshold, fails, warns, expected code).
    let examples = [
        ("fail", 1, 0, 2),
        ("warning", 0, 1, 2),
        ("warning", 0, 0, 0),
        ("never", 3, 0, 0),
    ];
    for (threshold, fails, warns, code) in examples {
        let fail_on = FailOn::parse(threshold).expect("a known threshold parses");
        assert_eq!(
            posture_exit_code(&statuses(fails, warns), fail_on),
            code,
            "{fails} FAIL / {warns} WARNING with --fail-on={threshold}",
        );
    }
}

// #83 @technical @use-case — an ERROR result but no FAIL still exits non-zero.
#[test]
fn a_run_with_an_error_result_but_no_fail_still_exits_non_zero() {
    let catalog = catalog_with_audit();
    let outcome = run(
        &catalog,
        &Selection::controls(["host.audit.trail", "host.accounts.root"]),
        &canonical_host(), // no scanner registered for host.audit.enabled
        FailOn::Fail,
    );

    assert_eq!(
        status_of(outcome.results(), "host.audit.trail"),
        Status::Error
    );
    assert_eq!(
        status_of(outcome.results(), "host.accounts.root"),
        Status::Pass
    );
    assert!(
        outcome.results().iter().all(|r| r.status() != Status::Fail),
        "no control has status FAIL",
    );
    assert_eq!(outcome.exit_code(), 2, "an ERROR alone raises the posture");
}

// #84 @violation @e2e — a missing catalog is a usage error with a distinct exit code.
#[test]
fn a_missing_catalog_is_a_usage_error_with_a_distinct_exit_code() {
    let run = scan(&["--catalog", MISSING_CATALOG, "--framework", "cis-linux"]);
    assert_eq!(run.code, Some(64));
    assert!(
        run.combined().contains("could not be loaded"),
        "the command reports that the catalog could not be loaded",
    );
    assert!(
        !run.printed_listing(),
        "no control result listing is printed"
    );
}

// #85 @violation @e2e — an unrecognized --fail-on value is a usage error.
#[test]
fn an_unrecognized_fail_on_value_is_a_usage_error() {
    let run = scan(&[
        "--catalog",
        CATALOG,
        "--framework",
        "cis-linux",
        "--fail-on=bogus",
    ]);
    assert_eq!(run.code, Some(64));
    assert!(
        run.combined()
            .contains(r#"invalid --fail-on value "bogus""#),
        "the command reports an invalid --fail-on value",
    );
    assert!(
        !run.printed_listing(),
        "no control result listing is printed"
    );
}

// #86 @nominal @e2e — the exit codes are documented in help.
#[test]
fn the_exit_codes_are_documented_in_help() {
    let run = scan(&["--help"]);
    assert_eq!(run.code, Some(0));
    let text = run.combined();
    assert!(
        text.contains("0 when clean")
            && text.contains("2 on a FAIL or execution error")
            && text.contains("64 on a usage error"),
        "the help text documents the exit codes",
    );
}
