// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-04 — SSH cryptography: a modern algorithm set PASSes, a
//! catalogue-listed legacy cipher/MAC/key-exchange WARNs naming each, and an
//! explicit `Protocol 1` FAILs as a guard-rail that dominates any concurrent
//! warning.
//!
//! Mirrors `specs/mat-90-ssh-scanner/r04-weak-cryptography.feature`.

mod ssh_support;

use ssh_support::{
    crypto_catalog, effective, parsed_fallback, parsed_fallback_unresolved, result_for, run,
    status_of, CRYPTO_CONTROL,
};

use sovri_agent::scanners::ssh::{PROTOCOL_V1_RULE, WEAK_CRYPTO_RULE};
use sovri_sdk::Status;

/// Scenario: A modern algorithm set passes.
#[test]
fn a_modern_algorithm_set_passes() {
    let scanner = effective(
        "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nmacs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256,curve25519-sha256@libssh.org\n",
    );
    let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);

    assert_eq!(status_of(&results, WEAK_CRYPTO_RULE), Status::Pass);
    assert_eq!(status_of(&results, PROTOCOL_V1_RULE), Status::Pass);
}

/// Scenario Outline: A legacy algorithm of any kind warns, named as its kind.
#[test]
fn a_legacy_algorithm_of_any_kind_warns() {
    let cases = [
        ("ciphers", "3des-cbc", "cipher"),
        ("ciphers", "arcfour", "cipher"),
        ("macs", "hmac-md5", "MAC"),
        (
            "kexalgorithms",
            "diffie-hellman-group1-sha1",
            "key exchange",
        ),
    ];
    for (directive, algorithm, kind) in cases {
        let scanner = effective(&format!("{directive} {algorithm}\n"));
        let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);
        let result = result_for(&results, WEAK_CRYPTO_RULE);

        assert_eq!(result.status(), Status::Warning, "algorithm {algorithm}");
        let reason = result.reason().expect("a WARNING carries a reason");
        assert!(
            reason.contains(algorithm),
            "the reason names {algorithm}: {reason}"
        );
        assert!(
            reason.to_lowercase().contains(&kind.to_lowercase()),
            "the reason names {algorithm} as a weak {kind}: {reason}"
        );
    }
}

/// Scenario: An explicit `Protocol 1` fails as a guard-rail.
#[test]
fn an_explicit_protocol_1_fails_as_a_guard_rail() {
    let scanner = effective("Protocol 1\n");
    let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);
    let result = result_for(&results, PROTOCOL_V1_RULE);

    assert_eq!(result.status(), Status::Fail);
    let reason = result.reason().expect("a FAIL carries a reason");
    assert!(
        reason.contains("Protocol 1"),
        "the reason names 'Protocol 1': {reason}"
    );
    assert!(
        reason.to_lowercase().contains("sshv1"),
        "the reason names it as disallowed SSHv1: {reason}"
    );
}

/// Scenario: Several legacy algorithms together still warn, and every one is named.
#[test]
fn several_legacy_algorithms_together_still_warn_naming_each() {
    let scanner = effective("ciphers 3des-cbc,arcfour\nmacs hmac-md5\n");
    let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);
    let result = result_for(&results, WEAK_CRYPTO_RULE);

    assert_eq!(result.status(), Status::Warning);
    let reason = result.reason().expect("a WARNING carries a reason");
    for algorithm in ["3des-cbc", "arcfour", "hmac-md5"] {
        assert!(
            reason.contains(algorithm),
            "the reason names every weak algorithm found, including {algorithm}: {reason}"
        );
    }
}

/// Scenario: `Protocol 1` alongside legacy ciphers still fails, not warns.
#[test]
fn protocol_1_alongside_legacy_ciphers_still_fails() {
    let scanner = effective("Protocol 1\nciphers 3des-cbc\n");
    let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);

    // The guard-rail FAIL is present and dominates: the legacy cipher warns, but the
    // control still fails rather than merely warning.
    assert_eq!(status_of(&results, PROTOCOL_V1_RULE), Status::Fail);
    assert_eq!(status_of(&results, WEAK_CRYPTO_RULE), Status::Warning);
}

/// Regression: OpenSSH `+`/`^`/`-` list modifiers are normalised on the fallback
/// path. `sshd -T` resolves them to a concrete list, but a raw config parse sees
/// them prefixed — an appended or prepended algorithm is still assessed, while a
/// removal enables nothing weak.
#[test]
fn cipher_list_modifiers_are_normalised_on_the_fallback_path() {
    // '+' appends to the modern defaults: the added legacy cipher is still weak.
    let added = parsed_fallback("ciphers +3des-cbc\n");
    let added_results = run(&added, &crypto_catalog(), &[CRYPTO_CONTROL]);
    let result = result_for(&added_results, WEAK_CRYPTO_RULE);
    assert_eq!(
        result.status(),
        Status::Warning,
        "'+3des-cbc' adds a weak cipher"
    );
    assert!(
        result
            .reason()
            .is_some_and(|reason| reason.contains("3des-cbc")),
        "the reason still names the appended weak cipher"
    );

    // '^' prepends: the algorithm is assessed just the same.
    let prepended = parsed_fallback("kexalgorithms ^diffie-hellman-group1-sha1\n");
    assert_eq!(
        status_of(
            &run(&prepended, &crypto_catalog(), &[CRYPTO_CONTROL]),
            WEAK_CRYPTO_RULE
        ),
        Status::Warning,
        "'^diffie-hellman-group1-sha1' prepends a weak key exchange"
    );

    // '-' only removes from the defaults, so it can enable nothing weak.
    let removed = parsed_fallback("ciphers -3des-cbc\n");
    assert_eq!(
        status_of(
            &run(&removed, &crypto_catalog(), &[CRYPTO_CONTROL]),
            WEAK_CRYPTO_RULE
        ),
        Status::Pass,
        "'-3des-cbc' removes a cipher and enables nothing weak"
    );
}

/// Regression: an empty or malformed algorithm list grades clean rather than
/// panicking — empty tokens are filtered out.
#[test]
fn empty_or_malformed_algorithm_lists_pass_without_panicking() {
    for raw in [
        "ciphers \n",
        "macs ,,\n",
        "kexalgorithms   \n",
        "ciphers ,\n",
    ] {
        let scanner = parsed_fallback(raw);
        assert_eq!(
            status_of(
                &run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]),
                WEAK_CRYPTO_RULE
            ),
            Status::Pass,
            "a malformed list ({raw:?}) grades clean without panicking"
        );
    }
}

/// Regression: on the fallback path an unresolved `Include` could hide a weak
/// `Ciphers`/`MACs`/`KexAlgorithms` line or a `Protocol 1` directive, so a config
/// with nothing weak visible ERRORs rather than asserting a clean PASS.
#[test]
fn an_unresolved_include_blocks_a_clean_crypto_pass() {
    let scanner = parsed_fallback_unresolved(
        "ciphers chacha20-poly1305@openssh.com\nkexalgorithms curve25519-sha256\n",
    );
    let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);

    assert_eq!(
        status_of(&results, WEAK_CRYPTO_RULE),
        Status::Error,
        "an unresolved Include could hide a weak algorithm, so no clean PASS"
    );
    assert_eq!(
        status_of(&results, PROTOCOL_V1_RULE),
        Status::Error,
        "an unresolved Include could set 'Protocol 1', so no clean PASS"
    );
}

/// Regression: a weak algorithm that IS visible still WARNs even with an unresolved
/// `Include` — the finding stands regardless of the unreadable file.
#[test]
fn a_visible_weak_algorithm_warns_despite_an_unresolved_include() {
    let scanner = parsed_fallback_unresolved("ciphers 3des-cbc\n");
    let results = run(&scanner, &crypto_catalog(), &[CRYPTO_CONTROL]);
    let result = result_for(&results, WEAK_CRYPTO_RULE);

    assert_eq!(result.status(), Status::Warning);
    assert!(result
        .reason()
        .is_some_and(|reason| reason.contains("3des-cbc")));
}
