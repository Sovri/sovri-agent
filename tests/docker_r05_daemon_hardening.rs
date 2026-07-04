// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-05 — the daemon hardening options must each carry their
//! hardened value. Any option that is absent or set to a non-hardened value WARNs
//! (advisory, not a hard failure), and the finding lists every un-hardened option in a
//! single Config-anchored result. A fully-hardened daemon PASSes.
//!
//! Mirrors `specs/mat-91-docker-scanner/r05-daemon-hardening.feature`.

mod docker_support;

use docker_support::{hardening_catalog, reachable_json, result_for, run, HARDENING_CONTROL};

use sovri_agent::scanners::docker::{DAEMON_HARDENING_RULE, DAEMON_JSON_EVIDENCE_ID};
use sovri_sdk::Status;

/// Scenario: A fully-hardened daemon passes.
#[test]
fn a_fully_hardened_daemon_passes() {
    let scanner = reachable_json(&daemon_json(
        Some("journald"),
        Some(true),
        Some(false),
        Some(true),
    ));
    let results = run(&scanner, &hardening_catalog(), &[HARDENING_CONTROL]);
    assert_eq!(
        result_for(&results, DAEMON_HARDENING_RULE).status(),
        Status::Pass
    );
}

/// Scenario Outline: A single un-hardened option warns, naming that option in the
/// daemon-config finding.
#[test]
fn a_single_un_hardened_option_warns_naming_it() {
    // Each row hardens every option except one, which is either absent or set to its
    // non-hardened value.
    let rows = [
        (
            daemon_json(None, Some(true), Some(false), Some(true)),
            "log-driver",
        ),
        (
            daemon_json(Some("journald"), Some(false), Some(false), Some(true)),
            "live-restore",
        ),
        (
            daemon_json(Some("journald"), Some(true), Some(true), Some(true)),
            "userland-proxy",
        ),
        (
            daemon_json(Some("journald"), Some(true), Some(false), None),
            "no-new-privileges",
        ),
    ];

    for (raw, option) in rows {
        let scanner = reachable_json(&raw);
        let results = run(&scanner, &hardening_catalog(), &[HARDENING_CONTROL]);
        let result = result_for(&results, DAEMON_HARDENING_RULE);

        assert_eq!(result.status(), Status::Warning, "config {raw}");
        assert!(
            result
                .evidence_refs()
                .iter()
                .any(|reference| reference == DAEMON_JSON_EVIDENCE_ID),
            "the WARNING is anchored on the daemon.json evidence: {raw}"
        );

        let log = scanner.evidence_log();
        let evidence = log
            .resolve(DAEMON_JSON_EVIDENCE_ID)
            .expect("the daemon.json evidence resolves");
        let excerpt = evidence
            .excerpt()
            .expect("the Config evidence has an excerpt");
        assert!(
            excerpt.contains("not hardened") && excerpt.contains(option),
            "the finding lists {option} among the un-hardened options: {excerpt}"
        );
    }
}

/// Scenario: Several un-hardened options fold into a single warning listing them all.
#[test]
fn several_un_hardened_options_fold_into_one_warning() {
    // live-restore absent and userland-proxy left on: two deviations, one finding.
    let scanner = reachable_json(&daemon_json(Some("journald"), None, Some(true), Some(true)));
    let results = run(&scanner, &hardening_catalog(), &[HARDENING_CONTROL]);
    let result = result_for(&results, DAEMON_HARDENING_RULE);

    assert_eq!(result.status(), Status::Warning);
    let log = scanner.evidence_log();
    let excerpt = log
        .resolve(DAEMON_JSON_EVIDENCE_ID)
        .and_then(|evidence| evidence.excerpt().map(str::to_owned))
        .expect("the Config evidence has an excerpt");
    assert!(
        excerpt.contains("live-restore") && excerpt.contains("userland-proxy"),
        "one warning lists both un-hardened options: {excerpt}"
    );
}

/// Scenario: An empty daemon.json warns once, listing all four options.
#[test]
fn an_empty_daemon_json_warns_listing_all_four_options() {
    let scanner = reachable_json("{}");
    let results = run(&scanner, &hardening_catalog(), &[HARDENING_CONTROL]);
    let result = result_for(&results, DAEMON_HARDENING_RULE);

    assert_eq!(result.status(), Status::Warning);
    let log = scanner.evidence_log();
    let excerpt = log
        .resolve(DAEMON_JSON_EVIDENCE_ID)
        .and_then(|evidence| evidence.excerpt().map(str::to_owned))
        .expect("the Config evidence has an excerpt");
    for option in [
        "log-driver",
        "live-restore",
        "userland-proxy",
        "no-new-privileges",
    ] {
        assert!(
            excerpt.contains(option),
            "the single warning lists {option}: {excerpt}"
        );
    }
}

/// Renders a `daemon.json` carrying only the hardening options that are `Some`. Using
/// `Option<bool>` keeps each option tri-state (hardened / non-hardened / absent) without
/// tripping the excessive-bool-arguments lint.
fn daemon_json(
    log_driver: Option<&str>,
    live_restore: Option<bool>,
    userland_proxy: Option<bool>,
    no_new_privileges: Option<bool>,
) -> String {
    let mut entries: Vec<String> = Vec::new();
    if let Some(driver) = log_driver {
        entries.push(format!(r#""log-driver": "{driver}""#));
    }
    if let Some(value) = live_restore {
        entries.push(format!(r#""live-restore": {value}"#));
    }
    if let Some(value) = userland_proxy {
        entries.push(format!(r#""userland-proxy": {value}"#));
    }
    if let Some(value) = no_new_privileges {
        entries.push(format!(r#""no-new-privileges": {value}"#));
    }
    format!("{{{}}}", entries.join(", "))
}
