// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 — FAIL and WARNING controls are projected as compliance gaps; PASS,
//! SKIPPED and ERROR are not. Covers issues #72-#74.

mod scan_support;

use scan_support::{
    canonical_host, catalog, compliant_host, gaps_section, result_with_status, run, DOCKER_CONTROL,
    FRAMEWORK_ID, OS_CONTROL, ROOT_CONTROL, SSH_PASSWORD_CONTROL, SSH_ROOT_CONTROL,
};
use sovri_agent::scan::{render_report, FailOn};
use sovri_sdk::{Selection, Status};

// #72 @nominal — failing and warning controls appear in the compliance gaps section.
#[test]
fn failing_and_warning_controls_appear_in_the_compliance_gaps_section() {
    let catalog = catalog();
    let outcome = run(
        &catalog,
        &Selection::framework(FRAMEWORK_ID),
        &canonical_host(),
        FailOn::Fail,
    );
    let gaps = gaps_section(outcome.report());

    // FAIL and WARNING controls are projected, each with its control id and reason.
    for control_id in [OS_CONTROL, SSH_PASSWORD_CONTROL, SSH_ROOT_CONTROL] {
        assert!(gaps.contains(control_id), "gaps list {control_id}");
        let reason = outcome
            .results()
            .iter()
            .find(|r| r.control_id() == control_id)
            .and_then(|r| r.reason())
            .expect("a projected control carries a reason");
        assert!(
            gaps.contains(reason),
            "the {control_id} gap shows its reason"
        );
    }

    // PASS and SKIPPED controls are not gaps.
    assert!(!gaps.contains(ROOT_CONTROL), "a PASS control is not a gap");
    assert!(
        !gaps.contains(DOCKER_CONTROL),
        "a SKIPPED control is not a gap",
    );
}

// #73 @violation — a fully compliant scan reports no compliance gaps.
#[test]
fn a_fully_compliant_scan_reports_no_compliance_gaps() {
    let catalog = catalog();
    let selection = Selection::controls([
        SSH_ROOT_CONTROL,
        SSH_PASSWORD_CONTROL,
        OS_CONTROL,
        ROOT_CONTROL,
    ]);
    let outcome = run(&catalog, &selection, &compliant_host(), FailOn::Fail);

    // No control is a gap.
    for result in outcome.results() {
        assert_eq!(
            result.status(),
            Status::Pass,
            "{} is compliant",
            result.control_id(),
        );
    }
    assert!(
        gaps_section(outcome.report()).contains("No compliance gaps were found"),
        "the section reports that no gaps were found",
    );
}

// #74 @nominal @technical — only FAIL and WARNING controls become gaps.
#[test]
fn only_fail_and_warning_controls_become_gaps() {
    let catalog = catalog();
    // One result per status, each on a distinct catalog control.
    let results = vec![
        result_with_status(OS_CONTROL, "host.os.eol", Status::Fail),
        result_with_status(
            SSH_PASSWORD_CONTROL,
            "host.ssh.password-auth",
            Status::Warning,
        ),
        result_with_status(ROOT_CONTROL, "host.account.single-root", Status::Pass),
        result_with_status(
            DOCKER_CONTROL,
            "container.docker.daemon-version-eol",
            Status::Skipped,
        ),
        result_with_status(
            SSH_ROOT_CONTROL,
            "host.ssh.permit-root-login",
            Status::Error,
        ),
    ];
    let report = render_report(&results, &catalog);
    let gaps = gaps_section(&report);

    // FAIL and WARNING appear.
    assert!(gaps.contains(OS_CONTROL), "FAIL appears in the gaps");
    assert!(
        gaps.contains(SSH_PASSWORD_CONTROL),
        "WARNING appears in the gaps",
    );
    // PASS, SKIPPED and ERROR do not.
    assert!(!gaps.contains(ROOT_CONTROL), "PASS does not appear");
    assert!(!gaps.contains(DOCKER_CONTROL), "SKIPPED does not appear");
    assert!(!gaps.contains(SSH_ROOT_CONTROL), "ERROR does not appear");
}
