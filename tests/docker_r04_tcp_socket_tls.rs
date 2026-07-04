// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-04 — the daemon API bound to a TCP socket must be protected
//! by mutually-authenticated TLS. A TCP binding without verified client TLS FAILs; a
//! Unix-socket-only daemon, or a TCP binding with `tlsverify` on, PASSes. The offending
//! binding is quoted in evidence anchored on the daemon config, and the reason states
//! no legal conclusion.
//!
//! Mirrors `specs/mat-91-docker-scanner/r04-tcp-socket-tls.feature`.

mod docker_support;

use docker_support::{
    asserts_legal_conclusion, reachable_json, result_for, run, scanner, socket_catalog,
    SOCKET_CONTROL,
};

use sovri_agent::scanners::docker::{DockerSnapshot, DAEMON_JSON_LOCATOR, TCP_SOCKET_TLS_RULE};
use sovri_sdk::{EvidenceKind, Status, Target};

/// Scenario: A Unix-socket-only daemon passes.
#[test]
fn a_unix_socket_only_daemon_passes() {
    let scanner = reachable_json(r#"{"hosts": ["unix:///var/run/docker.sock"]}"#);
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    assert_eq!(
        result_for(&results, TCP_SOCKET_TLS_RULE).status(),
        Status::Pass
    );
}

/// Scenario Outline: An unprotected TCP binding fails, quoting the binding in anchored
/// Config evidence and asserting no legal conclusion.
#[test]
fn an_unprotected_tcp_binding_fails() {
    for (raw, binding) in [
        (r#"{"hosts": ["tcp://0.0.0.0:2375"]}"#, "tcp://0.0.0.0:2375"),
        (
            r#"{"hosts": ["tcp://0.0.0.0:2376"], "tls": true}"#,
            "tcp://0.0.0.0:2376",
        ),
    ] {
        let scanner = reachable_json(raw);
        let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
        let result = result_for(&results, TCP_SOCKET_TLS_RULE);

        assert_eq!(result.status(), Status::Fail, "config {raw}");
        assert!(
            result
                .targets()
                .iter()
                .any(|target| *target == Target::file(DAEMON_JSON_LOCATOR)),
            "the FAIL is anchored on the daemon.json file: {raw}"
        );

        let log = scanner.evidence_log();
        let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
        let evidence = log.resolve(ref_id).expect("evidence resolves");
        assert_eq!(evidence.kind(), EvidenceKind::Config);
        assert!(
            evidence
                .excerpt()
                .is_some_and(|excerpt| excerpt.contains(binding)),
            "a Config evidence quotes the offending binding {binding}"
        );

        let reason = result.reason().expect("a FAIL carries a reason");
        assert!(
            !asserts_legal_conclusion(reason),
            "the reason asserts no legal conclusion: {reason}"
        );
    }
}

/// Scenario: A TCP binding with mutually-authenticated TLS passes.
#[test]
fn a_tcp_binding_with_client_tls_verification_passes() {
    let scanner = reachable_json(r#"{"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": true}"#);
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    assert_eq!(
        result_for(&results, TCP_SOCKET_TLS_RULE).status(),
        Status::Pass,
        "a TCP binding guarded by tlsverify is acceptable"
    );
}

/// Scenario: A mixed Unix-and-TCP binding fails on the unprotected TCP endpoint.
#[test]
fn a_mixed_unix_and_tcp_binding_fails_on_the_tcp_endpoint() {
    let scanner =
        reachable_json(r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}"#);
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    let result = result_for(&results, TCP_SOCKET_TLS_RULE);

    assert_eq!(result.status(), Status::Fail);
    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("tcp://0.0.0.0:2375")),
        "the evidence quotes the unprotected TCP binding, not the Unix socket"
    );
}

/// Scenario: A TCP binding reported only by docker info still fails, quoted in Command
/// evidence.
#[test]
fn a_tcp_binding_reported_only_by_docker_info_still_fails() {
    let scanner = scanner(
        DockerSnapshot::builder()
            .reachable()
            .info_host("tcp://0.0.0.0:2375")
            .build(),
    );
    let results = run(&scanner, &socket_catalog(), &[SOCKET_CONTROL]);
    let result = result_for(&results, TCP_SOCKET_TLS_RULE);

    assert_eq!(result.status(), Status::Fail);
    let log = scanner.evidence_log();
    let ref_id = result.evidence_refs().first().expect("a FAIL evidence ref");
    let evidence = log.resolve(ref_id).expect("evidence resolves");
    assert_eq!(evidence.kind(), EvidenceKind::Command);
    assert!(
        evidence
            .excerpt()
            .is_some_and(|excerpt| excerpt.contains("tcp://0.0.0.0:2375")),
        "a Command evidence quotes the offending binding"
    );
}
