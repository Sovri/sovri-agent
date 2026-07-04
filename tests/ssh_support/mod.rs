// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-90 SSH-scanner acceptance tests.
//!
//! Each integration test file is its own crate and pulls this in with
//! `mod ssh_support;`. A helper unused by a given test binary would otherwise trip
//! `dead_code`, so it is allowed here rather than at every call site. The crate
//! ships zero dependencies, so every helper is standard-library only.
#![allow(dead_code)]

use sovri_agent::scanners::ssh::{
    SshPolicy, SshScanner, SshSnapshot, PASSWORD_AUTH_RULE, PERMIT_ROOT_LOGIN_RULE,
    PROTOCOL_V1_RULE, ROOT_LOGIN_KEY_ONLY_RULE, WEAK_CRYPTO_RULE,
};
use sovri_sdk::{Catalog, Control, ControlResult, Engine, Rule, Selection, Status};

/// The catalogued root-login hardening control.
pub const ROOT_LOGIN_CONTROL: &str = "host.ssh.root-login";
/// The catalogued password-authentication control.
pub const PASSWORD_AUTH_CONTROL: &str = "host.ssh.password-authentication";
/// The catalogued SSH-cryptography control.
pub const CRYPTO_CONTROL: &str = "host.ssh.cryptography";

/// A timezone-qualified ISO-8601 execution timestamp shared by the fixtures.
pub const EXECUTED_AT: &str = "2026-07-04T09:00:00Z";
/// Execution metadata shared by the fixtures.
pub const METADATA: &str = "engine=sovri-agent";

/// The catalogue's weak cipher list.
pub const WEAK_CIPHERS: [&str; 6] = [
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
];
/// The catalogue's weak MAC list.
pub const WEAK_MACS: [&str; 4] = ["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"];
/// The catalogue's weak key-exchange list.
pub const WEAK_KEX: [&str; 2] = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"];

/// A modern `sshd -T` dump whose every algorithm class is current.
pub const MODERN_DUMP: &str = "permitrootlogin no\npasswordauthentication no\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nmacs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256,curve25519-sha256@libssh.org\n";

/// The catalogue-driven weak-algorithm policy.
#[must_use]
pub fn policy() -> SshPolicy {
    SshPolicy::new(WEAK_CIPHERS, WEAK_MACS, WEAK_KEX)
}

/// An engine carrying the shared timestamp and metadata.
///
/// # Panics
/// Panics if the shared timestamp is not a valid execution timestamp — a fixture bug.
#[must_use]
pub fn engine() -> Engine {
    Engine::new(EXECUTED_AT, METADATA).expect("valid engine timestamp")
}

/// The root-login control with its fail-policy `PermitRootLogin yes` rule and
/// warn-policy non-password-path rule (the default catalogue).
#[must_use]
pub fn root_login_catalog() -> Catalog {
    let control = Control::new(
        ROOT_LOGIN_CONTROL,
        "major",
        8,
        "Disable direct root login over SSH; require an unprivileged account and escalation.",
    );
    let rules = vec![
        Rule::new(
            PERMIT_ROOT_LOGIN_RULE,
            ROOT_LOGIN_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(
            ROOT_LOGIN_KEY_ONLY_RULE,
            ROOT_LOGIN_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The root-login control hardened to require strict `no`: the non-password-path
/// rule becomes fail-policy, so `prohibit-password` / `forced-commands-only` FAIL.
#[must_use]
pub fn hardened_root_login_catalog() -> Catalog {
    let control = Control::new(
        ROOT_LOGIN_CONTROL,
        "major",
        8,
        "Require PermitRootLogin no strictly; no non-password root-login path is accepted.",
    );
    let rules = vec![
        Rule::new(
            PERMIT_ROOT_LOGIN_RULE,
            ROOT_LOGIN_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(
            ROOT_LOGIN_KEY_ONLY_RULE,
            ROOT_LOGIN_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The password-authentication control and its single fail-policy rule.
#[must_use]
pub fn password_auth_catalog() -> Catalog {
    let control = Control::new(
        PASSWORD_AUTH_CONTROL,
        "major",
        8,
        "Disable password authentication; require key-based authentication.",
    );
    let rules = vec![
        Rule::new(PASSWORD_AUTH_RULE, PASSWORD_AUTH_CONTROL, "static-analysis")
            .with_result_policy("fail"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// The SSH-cryptography control with its warn-policy weak-algorithm rule and
/// fail-policy `Protocol 1` guard-rail rule.
#[must_use]
pub fn crypto_catalog() -> Catalog {
    let control = Control::new(
        CRYPTO_CONTROL,
        "major",
        7,
        "Disable legacy SSH ciphers, MACs, and key-exchange algorithms, and SSHv1.",
    );
    let rules = vec![
        Rule::new(WEAK_CRYPTO_RULE, CRYPTO_CONTROL, "static-analysis").with_result_policy("warn"),
        Rule::new(PROTOCOL_V1_RULE, CRYPTO_CONTROL, "static-analysis").with_result_policy("fail"),
    ];
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}

/// A catalog carrying every SSH control and rule (default policies), for runs that
/// evaluate the whole posture at once.
#[must_use]
pub fn full_catalog() -> Catalog {
    let controls = vec![
        Control::new(
            ROOT_LOGIN_CONTROL,
            "major",
            8,
            "Disable direct root login over SSH; require an unprivileged account and escalation.",
        ),
        Control::new(
            PASSWORD_AUTH_CONTROL,
            "major",
            8,
            "Disable password authentication; require key-based authentication.",
        ),
        Control::new(
            CRYPTO_CONTROL,
            "major",
            7,
            "Disable legacy SSH ciphers, MACs, and key-exchange algorithms, and SSHv1.",
        ),
    ];
    let rules = vec![
        Rule::new(
            PERMIT_ROOT_LOGIN_RULE,
            ROOT_LOGIN_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(
            ROOT_LOGIN_KEY_ONLY_RULE,
            ROOT_LOGIN_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
        Rule::new(PASSWORD_AUTH_RULE, PASSWORD_AUTH_CONTROL, "static-analysis")
            .with_result_policy("fail"),
        Rule::new(WEAK_CRYPTO_RULE, CRYPTO_CONTROL, "static-analysis").with_result_policy("warn"),
        Rule::new(PROTOCOL_V1_RULE, CRYPTO_CONTROL, "static-analysis").with_result_policy("fail"),
    ];
    Catalog::new(Vec::new(), controls, rules, Vec::new())
}

/// A scanner over an effective `sshd -T` dump with the shared catalogue policy.
#[must_use]
pub fn effective(raw: &str) -> SshScanner {
    SshScanner::new(SshSnapshot::builder().effective_dump(raw).build(), policy())
}

/// A scanner over a single effective directive line, e.g. `"permitrootlogin no"`.
#[must_use]
pub fn effective_directive(line: &str) -> SshScanner {
    effective(&format!("{line}\n"))
}

/// Execute `control_ids` against `scanner` with the shared engine, returning the
/// per-rule results.
///
/// # Panics
/// Panics if execution fails, which for the fixed fixtures would be a bug.
#[must_use]
pub fn run(scanner: &SshScanner, catalog: &Catalog, control_ids: &[&str]) -> Vec<ControlResult> {
    engine()
        .execute(
            catalog,
            &Selection::controls(control_ids.iter().copied()),
            scanner,
        )
        .expect("execution succeeds")
}

/// The single result produced by rule `rule_id`.
///
/// # Panics
/// Panics if no result carries `rule_id`, which would be a fixture bug.
#[must_use]
pub fn result_for<'a>(results: &'a [ControlResult], rule_id: &str) -> &'a ControlResult {
    results
        .iter()
        .find(|result| result.rule_id() == rule_id)
        .unwrap_or_else(|| panic!("a result for rule {rule_id}"))
}

/// The status of the result produced by rule `rule_id`.
///
/// # Panics
/// Panics if no result carries `rule_id`.
#[must_use]
pub fn status_of(results: &[ControlResult], rule_id: &str) -> Status {
    result_for(results, rule_id).status()
}

/// Whether `text` states a legal or regulatory conclusion, which no SSH-scanner
/// reason may do: the scan describes the technical situation, never its legality.
#[must_use]
pub fn asserts_legal_conclusion(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "illegal",
        "unlawful",
        "violation of law",
        "breach of law",
        "violates the law",
        "legal violation",
        "regulatory violation",
        "gdpr",
        "nis2",
        "non-compliant",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}
