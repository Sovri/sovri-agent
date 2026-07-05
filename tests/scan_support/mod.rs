// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-125 `sovri-agent scan` acceptance tests.
//!
//! Each integration test file is its own crate and pulls this in with
//! `mod scan_support;`. A helper unused by a given test binary would otherwise
//! trip `dead_code`, so it is allowed here rather than at every call site. The
//! crate ships zero dependencies, so every helper is standard-library only.
//!
//! The catalog built here is the byte-for-byte in-memory twin of the checked-in
//! `tests/fixtures/cis-linux/` YAML catalog the `@e2e` tests load through the
//! binary: one framework `cis-linux`, five one-rule-per-control mappings, and the
//! canonical host (Debian 9 EOL, `PermitRootLogin yes`, `PasswordAuthentication
//! yes`, one uid-0 account, no Docker) whose per-control statuses are
//! SKIPPED / PASS / FAIL / WARNING / FAIL ordered by control id.
#![allow(dead_code)]

use std::sync::Arc;

use sovri_agent::scan::{run_scan, FailOn, ScanOutcome};
use sovri_agent::scanners::docker::{
    DockerPolicy, DockerScanner, DockerSnapshot, HardeningOption, DAEMON_VERSION_EOL_RULE,
};
use sovri_agent::scanners::ssh::{
    SshPolicy, SshScanner, SshSnapshot, PASSWORD_AUTH_RULE, PERMIT_ROOT_LOGIN_RULE,
};
use sovri_agent::scanners::system::{
    ServicePolicy, SupportPolicy, SupportStatus, SystemPolicy, SystemScanner, SystemSnapshot,
    OS_EOL_RULE,
};
use sovri_agent::scanners::user::{UserPolicy, UserScanner, UserSnapshot, SINGLE_ROOT_RULE};
use sovri_agent::scanners::Registry;
use sovri_sdk::{
    Catalog, Control, ControlResult, Framework, Mapping, Rule, RuleEvaluator, Selection, Status,
};

/// A timezone-qualified ISO-8601 execution timestamp shared by the fixtures. It
/// pins `Engine::new` so reruns are byte-identical (R-06); it is never printed.
pub const EXECUTED_AT: &str = "2026-07-05T00:00:00Z";
/// Execution metadata for the fixtures.
pub const METADATA: &str = "engine=sovri-agent";

/// The canonical framework id.
pub const FRAMEWORK_ID: &str = "cis-linux";
/// A known framework that maps no controls (R-01 empty-listing boundary).
pub const EMPTY_FRAMEWORK_ID: &str = "empty-fw";

/// The five canonical control ids, ordered by control id.
pub const DOCKER_CONTROL: &str = "container.docker.daemon";
pub const ROOT_CONTROL: &str = "host.accounts.root";
pub const OS_CONTROL: &str = "host.os.lifecycle";
pub const SSH_PASSWORD_CONTROL: &str = "host.ssh.password";
pub const SSH_ROOT_CONTROL: &str = "host.ssh.root-access";

/// A control mapped to a rule with no registered scanner (R-01/R-05 ERROR path).
pub const AUDIT_CONTROL: &str = "host.audit.trail";
/// The rule id no scanner is registered for.
pub const AUDIT_RULE: &str = "host.audit.enabled";

/// An effective `sshd -T` dump where root login and password auth are both on.
pub const ROOT_AND_PASSWORD_YES: &str = "permitrootlogin yes\npasswordauthentication yes\n";
/// An effective `sshd -T` dump where root login and password auth are both off.
pub const ROOT_AND_PASSWORD_NO: &str = "permitrootlogin no\npasswordauthentication no\n";

/// The canonical `cis-linux` framework.
fn framework() -> Framework {
    Framework::new(FRAMEWORK_ID, "1.0")
        .with_source_url("https://www.cisecurity.org/benchmark/linux")
}

/// The five canonical controls, one per scanner rule.
fn canonical_controls() -> Vec<Control> {
    vec![
        Control::new(
            DOCKER_CONTROL,
            "major",
            5,
            "Upgrade the Docker daemon to a vendor-supported release.",
        ),
        Control::new(
            ROOT_CONTROL,
            "major",
            5,
            "Keep root the only uid-0 account.",
        ),
        Control::new(
            OS_CONTROL,
            "major",
            5,
            "Run a vendor-supported operating system release.",
        ),
        Control::new(
            SSH_PASSWORD_CONTROL,
            "minor",
            3,
            "Disable SSH password authentication.",
        ),
        Control::new(
            SSH_ROOT_CONTROL,
            "major",
            5,
            "Disable direct SSH root login.",
        ),
    ]
}

/// The five canonical rules. `host.ssh.password-auth` carries no result policy,
/// so its finding defaults to WARNING; the other four are fail-policy rules.
fn canonical_rules() -> Vec<Rule> {
    vec![
        Rule::new(DAEMON_VERSION_EOL_RULE, DOCKER_CONTROL, "static-analysis")
            .with_result_policy("fail"),
        Rule::new(SINGLE_ROOT_RULE, ROOT_CONTROL, "static-analysis").with_result_policy("fail"),
        Rule::new(OS_EOL_RULE, OS_CONTROL, "static-analysis").with_result_policy("fail"),
        Rule::new(PASSWORD_AUTH_RULE, SSH_PASSWORD_CONTROL, "static-analysis"),
        Rule::new(PERMIT_ROOT_LOGIN_RULE, SSH_ROOT_CONTROL, "static-analysis")
            .with_result_policy("fail"),
    ]
}

/// The five canonical control-to-framework mappings.
fn canonical_mappings() -> Vec<Mapping> {
    vec![
        Mapping::new(DOCKER_CONTROL, FRAMEWORK_ID).with_reference("5.1"),
        Mapping::new(ROOT_CONTROL, FRAMEWORK_ID).with_reference("5.2"),
        Mapping::new(OS_CONTROL, FRAMEWORK_ID).with_reference("5.3"),
        Mapping::new(SSH_PASSWORD_CONTROL, FRAMEWORK_ID).with_reference("5.4"),
        Mapping::new(SSH_ROOT_CONTROL, FRAMEWORK_ID).with_reference("5.5"),
    ]
}

/// The canonical five-control `cis-linux` catalog.
#[must_use]
pub fn catalog() -> Catalog {
    Catalog::new(
        vec![framework()],
        canonical_controls(),
        canonical_rules(),
        canonical_mappings(),
    )
}

/// The canonical catalog extended with `host.audit.trail` → `host.audit.enabled`,
/// a rule no scanner is registered for, so it evaluates to ERROR.
#[must_use]
pub fn catalog_with_audit() -> Catalog {
    let mut controls = canonical_controls();
    controls.push(Control::new(
        AUDIT_CONTROL,
        "major",
        5,
        "Enable the host audit trail.",
    ));
    let mut rules = canonical_rules();
    rules.push(Rule::new(AUDIT_RULE, AUDIT_CONTROL, "static-analysis").with_result_policy("fail"));
    let mut mappings = canonical_mappings();
    mappings.push(Mapping::new(AUDIT_CONTROL, FRAMEWORK_ID).with_reference("5.6"));
    Catalog::new(vec![framework()], controls, rules, mappings)
}

/// The canonical catalog with a second framework `empty-fw` that maps no controls.
#[must_use]
pub fn catalog_with_empty_fw() -> Catalog {
    let frameworks = vec![
        framework(),
        Framework::new(EMPTY_FRAMEWORK_ID, "1.0")
            .with_source_url("https://example.test/empty-framework"),
    ];
    Catalog::new(
        frameworks,
        canonical_controls(),
        canonical_rules(),
        canonical_mappings(),
    )
}

/// The catalogue Docker policy: 24.0 minimum-supported, 27.0 recommended.
fn docker_policy() -> DockerPolicy {
    DockerPolicy::new("24.0", "27.0", Vec::<HardeningOption>::new())
}

/// A Docker scanner over an absent daemon (no daemon installed).
#[must_use]
pub fn docker_absent() -> DockerScanner {
    DockerScanner::new(DockerSnapshot::builder().absent().build(), docker_policy())
}

/// A Docker scanner over a reachable daemon reporting an end-of-life version.
#[must_use]
pub fn docker_eol() -> DockerScanner {
    DockerScanner::new(
        DockerSnapshot::builder()
            .reachable()
            .server_version("19.03")
            .build(),
        docker_policy(),
    )
}

/// The catalogue SSH policy. The weak-crypto lists are empty: the canonical
/// catalog exercises only the root-login and password-auth rules, which do not
/// consult them.
fn ssh_policy() -> SshPolicy {
    SshPolicy::new(Vec::<&str>::new(), Vec::<&str>::new(), Vec::<&str>::new())
}

/// An SSH scanner over the given effective `sshd -T` dump.
#[must_use]
pub fn ssh(effective_dump: &str) -> SshScanner {
    SshScanner::new(
        SshSnapshot::builder()
            .effective_dump(effective_dump)
            .build(),
        ssh_policy(),
    )
}

/// An SSH scanner over an absent server (no sshd installed).
#[must_use]
pub fn ssh_absent() -> SshScanner {
    SshScanner::new(SshSnapshot::builder().absent().build(), ssh_policy())
}

/// The catalogue user policy: a 90-day dormancy threshold, root expected privileged.
fn user_policy() -> UserPolicy {
    UserPolicy::new(90, ["root"])
}

/// A user scanner over a host with exactly one uid-0 account (`root`).
#[must_use]
pub fn user_single_root() -> UserScanner {
    UserScanner::new(
        UserSnapshot::builder()
            .account("root", 0, "/bin/bash")
            .build(),
        user_policy(),
    )
}

/// The catalogue system policy mapping Debian `version_id` to `status`.
fn system_policy(version_id: &str, status: SupportStatus) -> SystemPolicy {
    SystemPolicy::new(
        SupportPolicy::new().with("debian", version_id, status),
        ServicePolicy::interdicting(Vec::<&str>::new()),
    )
}

/// A system scanner over a Debian host at `version_id`, whose support `status`
/// the policy declares (`EndOfSupport` → FAIL, `Supported` → PASS).
#[must_use]
pub fn system_debian(version_id: &str, status: SupportStatus) -> SystemScanner {
    let snapshot = SystemSnapshot::builder()
        .os_release(format!("ID=debian\nVERSION_ID=\"{version_id}\"\n"))
        .build();
    SystemScanner::new(snapshot, system_policy(version_id, status))
}

/// Compose the five V0.4 scanners into a rule-id registry. The SSH scanner backs
/// both `host.ssh.permit-root-login` and `host.ssh.password-auth` through one
/// shared `Arc`.
#[must_use]
pub fn canonical_registry(
    docker: DockerScanner,
    user: UserScanner,
    system: SystemScanner,
    ssh: SshScanner,
) -> Registry {
    let mut registry = Registry::new();
    // The SSH scanner backs two rules, so it is shared as one trait object and
    // registered under each rule id.
    let ssh: Arc<dyn RuleEvaluator + Send + Sync> = Arc::new(ssh);
    registry.register_rule_evaluator(DAEMON_VERSION_EOL_RULE, Arc::new(docker));
    registry.register_rule_evaluator(SINGLE_ROOT_RULE, Arc::new(user));
    registry.register_rule_evaluator(OS_EOL_RULE, Arc::new(system));
    registry.register_rule_evaluator(PERMIT_ROOT_LOGIN_RULE, Arc::clone(&ssh));
    registry.register_rule_evaluator(PASSWORD_AUTH_RULE, ssh);
    registry
}

/// The same five scanners registered in reverse rule-id order (R-06: output order
/// is independent of registration order).
#[must_use]
pub fn canonical_registry_reversed(
    docker: DockerScanner,
    user: UserScanner,
    system: SystemScanner,
    ssh: SshScanner,
) -> Registry {
    let mut registry = Registry::new();
    let ssh: Arc<dyn RuleEvaluator + Send + Sync> = Arc::new(ssh);
    registry.register_rule_evaluator(PASSWORD_AUTH_RULE, Arc::clone(&ssh));
    registry.register_rule_evaluator(PERMIT_ROOT_LOGIN_RULE, ssh);
    registry.register_rule_evaluator(OS_EOL_RULE, Arc::new(system));
    registry.register_rule_evaluator(SINGLE_ROOT_RULE, Arc::new(user));
    registry.register_rule_evaluator(DAEMON_VERSION_EOL_RULE, Arc::new(docker));
    registry
}

/// The canonical host registry: Docker absent, one uid-0 account, Debian 9 EOL,
/// root login and password auth both enabled.
#[must_use]
pub fn canonical_host() -> Registry {
    canonical_registry(
        docker_absent(),
        user_single_root(),
        system_debian("9", SupportStatus::EndOfSupport),
        ssh(ROOT_AND_PASSWORD_YES),
    )
}

/// The canonical host with the five scanners registered in reverse rule-id order.
#[must_use]
pub fn canonical_host_reversed() -> Registry {
    canonical_registry_reversed(
        docker_absent(),
        user_single_root(),
        system_debian("9", SupportStatus::EndOfSupport),
        ssh(ROOT_AND_PASSWORD_YES),
    )
}

/// A fully compliant host: Docker absent, one uid-0 account, Debian 12 supported,
/// root login and password auth both disabled.
#[must_use]
pub fn compliant_host() -> Registry {
    canonical_registry(
        docker_absent(),
        user_single_root(),
        system_debian("12", SupportStatus::Supported),
        ssh(ROOT_AND_PASSWORD_NO),
    )
}

/// A host with no SSH server installed (otherwise canonical): Docker absent, one
/// uid-0 account, Debian 9 EOL, SSH absent.
#[must_use]
pub fn host_without_ssh() -> Registry {
    canonical_registry(
        docker_absent(),
        user_single_root(),
        system_debian("9", SupportStatus::EndOfSupport),
        ssh_absent(),
    )
}

/// A host running an end-of-life Docker daemon (otherwise canonical).
#[must_use]
pub fn host_with_eol_docker() -> Registry {
    canonical_registry(
        docker_eol(),
        user_single_root(),
        system_debian("9", SupportStatus::EndOfSupport),
        ssh(ROOT_AND_PASSWORD_YES),
    )
}

/// Run a scan over the fixtures with the shared execution timestamp.
///
/// # Panics
/// Panics if the scan returns a `ScanError`, which for the fixed fixtures is a bug.
#[must_use]
pub fn run(
    catalog: &Catalog,
    selection: &Selection,
    registry: &Registry,
    fail_on: FailOn,
) -> ScanOutcome {
    run_scan(catalog, selection, registry, fail_on, EXECUTED_AT)
        .expect("the scan succeeds over the fixtures")
}

/// Build a `ControlResult` carrying `status` for `control_id`/`rule_id`, so the
/// gap projection can be triangulated one status at a time (R-03).
///
/// # Panics
/// Panics if the result fails validation, which would be a fixture bug.
#[must_use]
pub fn result_with_status(control_id: &str, rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(5)
        .evidence_refs(Vec::<String>::new())
        .executed_at(EXECUTED_AT)
        .execution_metadata(METADATA);
    if status != Status::Pass {
        builder = builder.reason("fixture reason describing the observed host state");
    }
    builder.build().expect("a valid fixture control result")
}

/// The status of the result for `control_id`.
///
/// # Panics
/// Panics if no result carries `control_id`.
#[must_use]
pub fn status_of(results: &[ControlResult], control_id: &str) -> Status {
    results
        .iter()
        .find(|result| result.control_id() == control_id)
        .unwrap_or_else(|| panic!("a result for control {control_id}"))
        .status()
}

/// The control ids of `results`, in result order.
#[must_use]
pub fn control_ids(results: &[ControlResult]) -> Vec<&str> {
    results.iter().map(ControlResult::control_id).collect()
}

/// The report section before the compliance-gaps heading — the control listing.
#[must_use]
pub fn listing_section(report: &str) -> &str {
    report.split("Compliance gaps").next().unwrap_or(report)
}

/// The report section from the compliance-gaps heading onward.
#[must_use]
pub fn gaps_section(report: &str) -> &str {
    match report.split_once("Compliance gaps") {
        Some((_, tail)) => tail,
        None => "",
    }
}

/// The listing line naming `control_id`, if any.
#[must_use]
pub fn listing_line<'a>(report: &'a str, control_id: &str) -> Option<&'a str> {
    listing_section(report)
        .lines()
        .find(|line| line.contains(control_id))
}

/// Whether `text` states a legal or regulatory conclusion, which no scan reason,
/// result, or evidence may do. The scan describes the technical situation, never
/// its legality.
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
