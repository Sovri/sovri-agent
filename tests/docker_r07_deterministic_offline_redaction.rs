// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-07 — the scan is deterministic and offline: the same snapshot
//! always yields byte-identical results and evidence, and no secret material (registry
//! log-opt tokens, TLS private keys) ever reaches an excerpt. Secret-classified
//! evidence keeps a redacted identity — a key and a content hash — but drops the raw
//! value. The verdict is a pure function of the injected snapshot; nothing touches the
//! network.
//!
//! Mirrors `specs/mat-91-docker-scanner/r07-deterministic-offline-redaction.feature`.

mod docker_support;

use docker_support::{
    full_catalog, hardening_catalog, reachable_json, run, scanner, socket_catalog,
    DAEMON_VERSION_CONTROL, HARDENING_CONTROL, REGISTRIES_CONTROL, SOCKET_CONTROL,
};

use sovri_agent::scanners::docker::{DockerSnapshot, DAEMON_JSON_EVIDENCE_ID};
use sovri_sdk::Classification;

/// A fake Splunk logging token — never a real credential — used to prove the scanner
/// redacts secret log-opt values.
const SPLUNK_TOKEN: &str = "dckr_splunk_A1B2C3";

/// Scenario: The same snapshot yields identical results and identical evidence.
#[test]
fn the_same_snapshot_yields_identical_results_and_evidence() {
    let snapshot = DockerSnapshot::builder()
        .reachable()
        .server_version("27.3.1")
        .daemon_json(
            r#"{
                "insecure-registries": ["10.0.0.5:5000"],
                "hosts": ["unix:///var/run/docker.sock"],
                "tlsverify": true,
                "log-driver": "journald",
                "live-restore": true,
                "userland-proxy": false,
                "no-new-privileges": true
            }"#,
        )
        .build();
    let first = scanner(snapshot.clone());
    let second = scanner(snapshot);

    let ids = [
        DAEMON_VERSION_CONTROL,
        REGISTRIES_CONTROL,
        SOCKET_CONTROL,
        HARDENING_CONTROL,
    ];
    let first_results = run(&first, &full_catalog(), &ids);
    let second_results = run(&second, &full_catalog(), &ids);

    assert_eq!(
        first_results, second_results,
        "the same snapshot always yields the same results"
    );
    assert_eq!(
        first.evidence_log().records(),
        second.evidence_log().records(),
        "the same snapshot always yields the same evidence"
    );
}

/// Scenario: A secret log-opt value is redacted — the record keeps a key and hash but
/// never the raw token.
#[test]
fn a_secret_log_opt_value_is_redacted() {
    let scanner = reachable_json(&format!(
        r#"{{"log-opts": {{"splunk-token": "{SPLUNK_TOKEN}"}}}}"#
    ));
    let _ = run(&scanner, &hardening_catalog(), &[HARDENING_CONTROL]);

    let log = scanner.evidence_log();
    let secret = log
        .records()
        .iter()
        .find(|evidence| evidence.key() == Some("splunk-token"))
        .expect("a dedicated evidence record for the secret log-opt");

    assert_eq!(
        secret.classification(),
        Some(Classification::Secret),
        "the log-opt token is classified Secret"
    );
    assert!(
        secret.excerpt().is_none(),
        "a Secret record drops its excerpt"
    );
    assert!(
        !secret.content_hash().is_empty(),
        "a redacted record still carries a content hash for later verification"
    );
    assert!(
        log.records()
            .iter()
            .all(|evidence| !evidence.exposes_value(SPLUNK_TOKEN)),
        "no evidence record anywhere exposes the raw token"
    );
}

/// Scenario: A TLS private-key path is cited, but no key material is ever read into an
/// excerpt.
#[test]
fn a_tls_private_key_path_is_cited_without_leaking_key_material() {
    let scanner = reachable_json(
        r#"{"tlskey": "/etc/docker/certs/server-key.pem", "hosts": ["tcp://0.0.0.0:2376"], "tlsverify": true}"#,
    );
    let log = scanner.evidence_log();

    let config = log
        .resolve(DAEMON_JSON_EVIDENCE_ID)
        .expect("a Config evidence record");
    assert!(
        config
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("/etc/docker/certs/server-key.pem")),
        "the Config evidence cites the tlskey path"
    );

    // The scanner reads daemon.json, which holds the path — never the key file — so no
    // PEM material can appear in any excerpt.
    assert!(
        log.records()
            .iter()
            .all(|evidence| match evidence.excerpt() {
                Some(excerpt) =>
                    !excerpt.contains("-----BEGIN") && !excerpt.contains("PRIVATE KEY"),
                None => true,
            }),
        "no excerpt contains TLS private-key material"
    );

    // The socket control still grades from the injected snapshot without touching disk.
    let _ = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
}

/// Scenario: The verdict is a pure function of the snapshot — different snapshots give
/// different results with no network access.
#[test]
fn the_verdict_tracks_the_snapshot_not_the_network() {
    let unix_only = reachable_json(r#"{"hosts": ["unix:///var/run/docker.sock"]}"#);
    let exposed_tcp = reachable_json(r#"{"hosts": ["tcp://0.0.0.0:2375"]}"#);

    let unix_results = run(&unix_only, &socket_catalog(), &[SOCKET_CONTROL]);
    let exposed_results = run(&exposed_tcp, &socket_catalog(), &[SOCKET_CONTROL]);

    assert_ne!(
        unix_results, exposed_results,
        "the verdict follows the injected snapshot, not any live host or network"
    );
}
