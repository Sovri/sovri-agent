// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-89 user-scanner acceptance tests.
//!
//! Each integration test file is its own crate and pulls this in with
//! `mod user_support;`. A helper unused by a given test binary would otherwise
//! trip `dead_code`, so it is allowed here rather than at every call site. The
//! crate ships zero dependencies, so every helper is standard-library only.
#![allow(dead_code)]

use sovri_agent::scanners::user::{
    UserPolicy, UserScanner, UserSnapshot, DORMANT_ACCOUNT_RULE, INVENTORY_RULE,
    NO_EMPTY_PASSWORD_RULE, PRIVILEGED_EXPECTED_RULE, SINGLE_ROOT_RULE,
};
use sovri_sdk::{Catalog, Control, ControlResult, Engine, Rule, Selection, Status};

/// The catalogued account-inventory control.
pub const INVENTORY_CONTROL: &str = "host.accounts.inventory";
/// The catalogued single-root control.
pub const SINGLE_ROOT_CONTROL: &str = "host.accounts.single-root";
/// The catalogued no-empty-password control.
pub const NO_EMPTY_PASSWORD_CONTROL: &str = "host.accounts.no-empty-password";
/// The catalogued dormant-account control.
pub const DORMANT_CONTROL: &str = "host.accounts.dormant";
/// The catalogued privileged-account control.
pub const PRIVILEGED_CONTROL: &str = "host.accounts.privileged";

/// A timezone-qualified ISO-8601 execution timestamp shared by the fixtures.
pub const EXECUTED_AT: &str = "2026-07-04T09:00:00Z";
/// Execution metadata for the fixtures.
pub const METADATA: &str = "engine=sovri-agent";

/// The catalogue inactivity threshold the fixtures use, in days.
pub const THRESHOLD_DAYS: u32 = 90;

/// The obviously-fake fixture password hash. It is the redaction target: it must
/// appear in no evidence and no gap explanation (R-07).
pub const FAKE_HASH: &str = "$6$FAKEsalt$FIXTUREHASHonly0123456789abcdef";

/// The catalogue policy: a 90-day inactivity threshold and the expected
/// privileged set `{ root, alice }`.
#[must_use]
pub fn policy() -> UserPolicy {
    UserPolicy::new(THRESHOLD_DAYS, ["root", "alice"])
}

/// An engine carrying the shared timestamp and metadata.
///
/// # Panics
/// Panics if the shared timestamp is not a valid execution timestamp — a fixture bug.
#[must_use]
pub fn engine() -> Engine {
    Engine::new(EXECUTED_AT, METADATA).expect("valid engine timestamp")
}

/// A single-rule control under `control_id`, carrying `rule_id` with `policy`.
fn one_rule_control(control_id: &str, rule_id: &str, policy: Option<&str>) -> Catalog {
    let control = Control::new(control_id, "major", 5, "Review the host's accounts.");
    let mut rule = Rule::new(rule_id, control_id, "static-analysis");
    if let Some(policy) = policy {
        rule = rule.with_result_policy(policy);
    }
    Catalog::new(Vec::new(), vec![control], vec![rule], Vec::new())
}

/// The inventory control and its always-PASS inventory rule.
#[must_use]
pub fn inventory_catalog() -> Catalog {
    one_rule_control(INVENTORY_CONTROL, INVENTORY_RULE, None)
}

/// The single-root control and its fail-policy rule.
#[must_use]
pub fn single_root_catalog() -> Catalog {
    one_rule_control(SINGLE_ROOT_CONTROL, SINGLE_ROOT_RULE, Some("fail"))
}

/// The no-empty-password control and its fail-policy rule.
#[must_use]
pub fn no_empty_password_catalog() -> Catalog {
    one_rule_control(
        NO_EMPTY_PASSWORD_CONTROL,
        NO_EMPTY_PASSWORD_RULE,
        Some("fail"),
    )
}

/// The dormant-account control and its warn-policy rule.
#[must_use]
pub fn dormant_catalog() -> Catalog {
    one_rule_control(DORMANT_CONTROL, DORMANT_ACCOUNT_RULE, Some("warn"))
}

/// The privileged-account control and its warn-policy rule.
#[must_use]
pub fn privileged_catalog() -> Catalog {
    one_rule_control(PRIVILEGED_CONTROL, PRIVILEGED_EXPECTED_RULE, Some("warn"))
}

/// A catalog carrying every user-scanner control and rule.
#[must_use]
pub fn full_catalog() -> Catalog {
    let controls = vec![
        Control::new(
            INVENTORY_CONTROL,
            "minor",
            2,
            "Review the account inventory.",
        ),
        Control::new(
            SINGLE_ROOT_CONTROL,
            "major",
            8,
            "Keep root the only uid-0 account.",
        ),
        Control::new(
            NO_EMPTY_PASSWORD_CONTROL,
            "major",
            8,
            "Set a password or lock every login account.",
        ),
        Control::new(
            DORMANT_CONTROL,
            "major",
            5,
            "Review or disable dormant accounts.",
        ),
        Control::new(
            PRIVILEGED_CONTROL,
            "major",
            5,
            "Keep privileged access to the expected accounts.",
        ),
    ];
    let rules = vec![
        Rule::new(INVENTORY_RULE, INVENTORY_CONTROL, "static-analysis"),
        Rule::new(SINGLE_ROOT_RULE, SINGLE_ROOT_CONTROL, "static-analysis")
            .with_result_policy("fail"),
        Rule::new(
            NO_EMPTY_PASSWORD_RULE,
            NO_EMPTY_PASSWORD_CONTROL,
            "static-analysis",
        )
        .with_result_policy("fail"),
        Rule::new(DORMANT_ACCOUNT_RULE, DORMANT_CONTROL, "static-analysis")
            .with_result_policy("warn"),
        Rule::new(
            PRIVILEGED_EXPECTED_RULE,
            PRIVILEGED_CONTROL,
            "static-analysis",
        )
        .with_result_policy("warn"),
    ];
    Catalog::new(Vec::new(), controls, rules, Vec::new())
}

/// Execute `control_ids` against `scanner` with the shared engine, returning the
/// per-rule results.
///
/// # Panics
/// Panics if execution fails, which for the fixed fixtures would be a bug.
#[must_use]
pub fn run(scanner: &UserScanner, catalog: &Catalog, control_ids: &[&str]) -> Vec<ControlResult> {
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

/// A scanner over `snapshot` with the shared catalogue policy.
#[must_use]
pub fn scanner(snapshot: UserSnapshot) -> UserScanner {
    UserScanner::new(snapshot, policy())
}

/// Whether `text` states a legal or regulatory conclusion, which no user-scanner
/// reason, result, or evidence may do. The scan describes the technical account
/// situation, never its legality.
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
