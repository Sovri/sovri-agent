// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The Linux system scanner: the agent's first scanner.
//!
//! [`SystemScanner`] captures the host's base posture — identity, OS support,
//! installed-package inventory, and running services — into a [`SystemSnapshot`],
//! then evaluates it as catalogued rules through the MAT-85 engine as a
//! [`sovri_sdk::RuleEvaluator`]. Acquisition ([`SystemSnapshot::acquire`]) reads
//! the host with the standard library only; evaluation is a pure function of the
//! captured snapshot, so a test injects a fixture snapshot and never touches the
//! real host.
//!
//! Status follows the rule's result policy, mirroring the `ConsentScan` mould: the
//! OS-support control carries a fail-policy end-of-support rule and a warn-policy
//! support-undetermined rule, so an end-of-support release FAILs while a version
//! the policy does not know WARNs. A reason describes the technical situation and
//! never asserts a legal conclusion.

// `SystemScanner` / `SystemSnapshot` / `SystemPolicy` intentionally echo their
// module name, as `SelftestScanner` does in the sibling `selftest` module.
#![allow(clippy::module_name_repetitions)]

use std::fs;
use std::path::Path;

use sovri_sdk::{Evaluation, ExecutionFailure, RuleContext, RuleEvaluator, Target};

use super::AcquireError;
use crate::evidence::{Evidence, EvidenceKind, EvidenceLog};

/// The fail-policy rule: the installed OS release is out of support.
pub const OS_EOL_RULE: &str = "host.os.eol";
/// The warn-policy rule: the OS support status could not be determined.
pub const OS_SUPPORT_UNDETERMINED_RULE: &str = "host.os.support-undetermined";
/// The rule inventorying installed packages through the distro package manager.
pub const PACKAGE_INVENTORY_RULE: &str = "host.packages.inventory";
/// The warn-policy rule flagging active superfluous services.
pub const SERVICES_RULE: &str = "host.services.no-superfluous";

/// The locator every os-release evidence record anchors on.
pub const OS_RELEASE_LOCATOR: &str = "/etc/os-release";

/// The evidence id of the os-release configuration record.
const OS_RELEASE_EVIDENCE_ID: &str = "host.os-release";
/// The evidence id of the package-inventory command record.
const PACKAGE_INVENTORY_EVIDENCE_ID: &str = "host.package-inventory";

/// A placeholder content-hash token carried on system-scanner evidence.
///
/// Evidence carries a content hash but does not compute one; producing a real
/// SHA-256 digest is a separate concern (MAT-93). The token is non-blank so the
/// record validates, and stands in until real hashing is wired.
const UNVERIFIED_CONTENT_HASH: &str = "sha256:unverified";

/// A distro package manager the scanner can inventory through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    /// The Debian/Ubuntu package manager, queried with `dpkg-query`.
    Dpkg,
    /// The RHEL/SUSE package manager, queried with `rpm`.
    Rpm,
}

impl Manager {
    /// The command line recorded as the inventory evidence locator.
    fn inventory_command(self) -> &'static str {
        match self {
            Manager::Dpkg => "dpkg-query -W",
            Manager::Rpm => "rpm -qa",
        }
    }

    /// The program and arguments used to inventory installed packages on a host.
    fn inventory_argv(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Manager::Dpkg => ("dpkg-query", &["-W"]),
            Manager::Rpm => ("rpm", &["-qa"]),
        }
    }
}

/// The kind of service manager a host exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManager {
    /// The systemd service manager.
    Systemd,
    /// A non-systemd init fallback (e.g. sysvinit).
    Fallback,
}

/// Whether a catalogued OS version is supported or out of support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportStatus {
    /// The version still receives vendor support.
    Supported,
    /// The version is out of support (end-of-support).
    EndOfSupport,
}

/// The catalogue-driven OS-support policy: which distro versions are supported or
/// out of support. The scanner never hard-codes this; it is supplied like R-04's
/// interdiction list.
#[derive(Debug, Clone, Default)]
pub struct SupportPolicy {
    entries: Vec<(String, String, SupportStatus)>,
}

impl SupportPolicy {
    /// An empty support policy.
    #[must_use]
    pub fn new() -> Self {
        SupportPolicy::default()
    }

    /// Record `status` for distro `os` at `version`.
    #[must_use]
    pub fn with(
        mut self,
        os: impl Into<String>,
        version: impl Into<String>,
        status: SupportStatus,
    ) -> Self {
        self.entries.push((os.into(), version.into(), status));
        self
    }

    /// The support status of `os` at `version`, or `None` when the policy does not
    /// list it.
    #[must_use]
    pub fn status_of(&self, os: &str, version: &str) -> Option<SupportStatus> {
        self.entries
            .iter()
            .find(|(policy_os, policy_version, _)| policy_os == os && policy_version == version)
            .map(|(_, _, status)| *status)
    }
}

/// The catalogue-driven list of interdicted service names for R-04.
#[derive(Debug, Clone, Default)]
pub struct ServicePolicy {
    interdicted: Vec<String>,
}

impl ServicePolicy {
    /// A policy interdicting the given service names.
    #[must_use]
    pub fn interdicting<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ServicePolicy {
            interdicted: names.into_iter().map(Into::into).collect(),
        }
    }

    /// A policy interdicting nothing.
    #[must_use]
    pub fn none() -> Self {
        ServicePolicy::default()
    }

    /// Whether `service` is interdicted, comparing on the base name (a trailing
    /// `.service` unit suffix is ignored).
    #[must_use]
    pub fn interdicts(&self, service: &str) -> bool {
        let base = service_base_name(service);
        self.interdicted.iter().any(|name| name == base)
    }
}

/// The catalogue-driven policy the scanner evaluates against: the OS-support table
/// and the service interdiction list.
#[derive(Debug, Clone)]
pub struct SystemPolicy {
    support: SupportPolicy,
    services: ServicePolicy,
}

impl SystemPolicy {
    /// A policy pairing an OS-support table with a service interdiction list.
    #[must_use]
    pub fn new(support: SupportPolicy, services: ServicePolicy) -> Self {
        SystemPolicy { support, services }
    }
}

/// The os-release facts captured from the host.
#[derive(Debug, Clone)]
enum OsRelease {
    /// os-release was read: its distro id, the version id when present, and the raw
    /// content kept for evidence. A `None` version is a malformed os-release.
    Readable {
        id: String,
        version_id: Option<String>,
        raw: String,
    },
    /// The os-release file could not be read.
    Unreadable,
}

impl OsRelease {
    /// The distro id, when os-release was readable.
    fn id(&self) -> Option<&str> {
        match self {
            OsRelease::Readable { id, .. } => Some(id),
            OsRelease::Unreadable => None,
        }
    }
}

/// A running-or-known service captured from the host.
#[derive(Debug, Clone)]
struct Service {
    name: String,
    active: bool,
}

/// The service-manager facts captured from the host.
///
/// Only presence matters to evaluation (R-05): systemd and a non-systemd fallback
/// both evaluate, so the specific kind is not carried onto the snapshot.
#[derive(Debug, Clone)]
enum ServiceState {
    /// No service manager is present.
    Absent,
    /// A service manager is present, with the services it reports.
    Present { running: Vec<Service> },
}

/// The captured host state the [`SystemScanner`] evaluates.
///
/// Build one from the host with [`SystemSnapshot::acquire`], or from a fixture
/// with [`SystemSnapshot::builder`]. Evaluation is a pure function of this value.
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    hostname: Option<String>,
    fqdn: Option<String>,
    os_release: OsRelease,
    package_managers: Vec<Manager>,
    inventory: Option<String>,
    services: ServiceState,
}

impl SystemSnapshot {
    /// Start building a snapshot from fixture facts.
    #[must_use]
    pub fn builder() -> SystemSnapshotBuilder {
        SystemSnapshotBuilder::default()
    }

    /// Acquire the host's base system state offline: identity, os-release, package
    /// managers with their inventory, and the service manager with its running
    /// services. Reads the host with the standard library and local process probes
    /// only; it never touches the network.
    ///
    /// # Errors
    /// Returns an [`AcquireError`] when the host identity cannot be read.
    pub fn acquire() -> Result<Self, AcquireError> {
        let hostname = read_hostname()?;
        let os_release = read_os_release();
        let (package_managers, inventory) = probe_packages(&os_release);
        let (service_manager, running) = probe_services();
        let services = match service_manager {
            Some(_) => ServiceState::Present { running },
            None => ServiceState::Absent,
        };
        Ok(SystemSnapshot {
            hostname,
            fqdn: None,
            os_release,
            package_managers,
            inventory,
            services,
        })
    }
}

/// Builder for a fixture [`SystemSnapshot`].
#[derive(Debug, Default)]
pub struct SystemSnapshotBuilder {
    hostname: Option<String>,
    fqdn: Option<String>,
    os_release: Option<OsRelease>,
    package_managers: Vec<Manager>,
    inventory: Option<String>,
    service_manager: Option<ServiceManager>,
    running: Vec<Service>,
}

impl SystemSnapshotBuilder {
    /// Set the host's short name.
    #[must_use]
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.hostname = Some(name.into());
        self
    }

    /// Set the host's fully-qualified domain name.
    #[must_use]
    pub fn fqdn(mut self, fqdn: impl Into<String>) -> Self {
        self.fqdn = Some(fqdn.into());
        self
    }

    /// Set a readable os-release from its raw content; the distro id and version
    /// are parsed out of it.
    #[must_use]
    pub fn os_release(mut self, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let (id, version_id) = parse_os_release(&raw);
        self.os_release = Some(OsRelease::Readable {
            id,
            version_id,
            raw,
        });
        self
    }

    /// Mark the os-release file as unreadable.
    #[must_use]
    pub fn os_release_unreadable(mut self) -> Self {
        self.os_release = Some(OsRelease::Unreadable);
        self
    }

    /// Record a package manager as available on the host.
    #[must_use]
    pub fn package_manager(mut self, manager: Manager) -> Self {
        self.package_managers.push(manager);
        self
    }

    /// Set the serialized package inventory the manager reports.
    #[must_use]
    pub fn inventory(mut self, inventory: impl Into<String>) -> Self {
        self.inventory = Some(inventory.into());
        self
    }

    /// Record the service manager present on the host.
    #[must_use]
    pub fn service_manager(mut self, manager: ServiceManager) -> Self {
        self.service_manager = Some(manager);
        self
    }

    /// Record that no service manager is present.
    #[must_use]
    pub fn no_service_manager(mut self) -> Self {
        self.service_manager = None;
        self
    }

    /// Record a service and whether it is active.
    #[must_use]
    pub fn service(mut self, name: impl Into<String>, active: bool) -> Self {
        self.running.push(Service {
            name: name.into(),
            active,
        });
        self
    }

    /// Build the snapshot.
    #[must_use]
    pub fn build(self) -> SystemSnapshot {
        let services = match self.service_manager {
            Some(_) => ServiceState::Present {
                running: self.running,
            },
            None => ServiceState::Absent,
        };
        SystemSnapshot {
            hostname: self.hostname,
            fqdn: self.fqdn,
            os_release: self.os_release.unwrap_or(OsRelease::Unreadable),
            package_managers: self.package_managers,
            inventory: self.inventory,
            services,
        }
    }
}

/// The Linux system scanner: it evaluates a captured [`SystemSnapshot`] against a
/// catalogue [`SystemPolicy`], dispatching each rule by id and recording evidence.
#[derive(Debug, Clone)]
pub struct SystemScanner {
    snapshot: SystemSnapshot,
    policy: SystemPolicy,
    evidence: Vec<Evidence>,
}

impl SystemScanner {
    /// A scanner over `snapshot`, evaluated against catalogue `policy`.
    ///
    /// Evidence for os-release and the package inventory is captured up front, so
    /// [`SystemScanner::evidence_log`] can back a result without re-reading state.
    #[must_use]
    pub fn new(snapshot: SystemSnapshot, policy: SystemPolicy) -> Self {
        let mut evidence = Vec::new();
        if let OsRelease::Readable { raw, .. } = &snapshot.os_release {
            if let Ok(record) = Evidence::builder()
                .id(OS_RELEASE_EVIDENCE_ID)
                .kind(EvidenceKind::Config)
                .locator(OS_RELEASE_LOCATOR)
                .content_hash(UNVERIFIED_CONTENT_HASH)
                .excerpt(raw.clone())
                .build()
            {
                evidence.push(record);
            }
        }
        if let Some(manager) = select_manager(&snapshot) {
            let inventory = snapshot.inventory.clone().unwrap_or_default();
            if let Ok(record) = Evidence::builder()
                .id(PACKAGE_INVENTORY_EVIDENCE_ID)
                .kind(EvidenceKind::Command)
                .locator(manager.inventory_command())
                .content_hash(UNVERIFIED_CONTENT_HASH)
                .excerpt(inventory)
                .build()
            {
                evidence.push(record);
            }
        }
        SystemScanner {
            snapshot,
            policy,
            evidence,
        }
    }

    /// A scanner that acquires the host's state, evaluated against `policy`.
    ///
    /// # Errors
    /// Returns an [`AcquireError`] when the host state cannot be captured.
    pub fn acquire(policy: SystemPolicy) -> Result<Self, AcquireError> {
        Ok(SystemScanner::new(SystemSnapshot::acquire()?, policy))
    }

    /// An [`EvidenceLog`] of every evidence record the scan captured, so a result
    /// can be explained from the same records it references.
    #[must_use]
    pub fn evidence_log(&self) -> EvidenceLog {
        let mut log = EvidenceLog::new();
        for record in &self.evidence {
            log.record(record.clone());
        }
        log
    }

    /// The host identity rendered as engine execution metadata carried on every
    /// result: `host=<name>` with ` fqdn=<fqdn>` when the FQDN resolved, or empty
    /// when no hostname is available.
    #[must_use]
    pub fn identity_metadata(&self) -> String {
        match (&self.snapshot.hostname, &self.snapshot.fqdn) {
            (Some(hostname), Some(fqdn)) => format!("host={hostname} fqdn={fqdn}"),
            (Some(hostname), None) => format!("host={hostname}"),
            (None, _) => String::new(),
        }
    }

    /// The package manager the scan inventories through: the only one present, or
    /// the one the distro id selects when both are present.
    #[must_use]
    pub fn selected_package_manager(&self) -> Option<Manager> {
        select_manager(&self.snapshot)
    }

    /// Evaluate the end-of-support rule: a known EOL release is a finding, a
    /// supported release passes, an unknown version is not applicable here, and a
    /// version that cannot be extracted is an execution failure.
    fn evaluate_os_eol(&self) -> Result<Evaluation, ExecutionFailure> {
        let (id, version) = self.os_version()?;
        match self.policy.support.status_of(id, version) {
            Some(SupportStatus::EndOfSupport) => Ok(Self::os_finding(
                "the installed OS release is out of support and no longer receives security patches",
            )),
            Some(SupportStatus::Supported) => Ok(Self::os_satisfied_with_evidence()),
            None => Ok(Evaluation::not_applicable(
                "the OS version is absent from the support policy, so its end-of-support status does not apply",
            )),
        }
    }

    /// Evaluate the support-undetermined rule: a version the policy does not list is
    /// a finding (WARNING), a listed version passes, and an unextractable version is
    /// an execution failure.
    fn evaluate_os_undetermined(&self) -> Result<Evaluation, ExecutionFailure> {
        let (id, version) = self.os_version()?;
        if self.policy.support.status_of(id, version).is_none() {
            Ok(Self::os_finding(
                "the OS support status could not be determined: the release is absent from the support policy",
            ))
        } else {
            Ok(Evaluation::satisfied())
        }
    }

    /// The distro id and version, or an execution failure when os-release is
    /// unreadable or carries no version.
    fn os_version(&self) -> Result<(&str, &str), ExecutionFailure> {
        match &self.snapshot.os_release {
            OsRelease::Unreadable => Err(ExecutionFailure::new(
                "the os-release file could not be read",
            )),
            OsRelease::Readable {
                version_id: None, ..
            } => Err(ExecutionFailure::new(
                "the os-release file carries no VERSION_ID, so the OS version could not be determined",
            )),
            OsRelease::Readable {
                id,
                version_id: Some(version),
                ..
            } => Ok((id, version)),
        }
    }

    /// A finding anchored on the os-release evidence, carrying `detail` as reason.
    fn os_finding(detail: &str) -> Evaluation {
        Evaluation::finding()
            .with_evidence_refs([OS_RELEASE_EVIDENCE_ID])
            .with_targets([Target::file(OS_RELEASE_LOCATOR)])
            .with_detail(detail)
    }

    /// A satisfied evaluation anchored on the os-release evidence.
    fn os_satisfied_with_evidence() -> Evaluation {
        Evaluation::satisfied()
            .with_evidence_refs([OS_RELEASE_EVIDENCE_ID])
            .with_targets([Target::file(OS_RELEASE_LOCATOR)])
    }

    /// Evaluate the package-inventory rule: a present manager passes carrying the
    /// bounded, hashed Command evidence; no manager at all is an execution failure.
    fn evaluate_packages(&self) -> Result<Evaluation, ExecutionFailure> {
        if self.selected_package_manager().is_some() {
            Ok(Evaluation::satisfied().with_evidence_refs([PACKAGE_INVENTORY_EVIDENCE_ID]))
        } else {
            Err(ExecutionFailure::new(
                "no supported package manager (dpkg or rpm) is available to inventory installed packages",
            ))
        }
    }

    /// Evaluate the running-services rule: an active interdicted service is a
    /// finding naming it, a clean set passes, and no service manager is not
    /// applicable (SKIPPED). It never fails to execute, so it returns an
    /// [`Evaluation`] directly rather than a `Result`.
    fn evaluate_services(&self) -> Evaluation {
        let running = match &self.snapshot.services {
            ServiceState::Absent => {
                return Evaluation::not_applicable(
                    "no service manager is present, so running services cannot be evaluated",
                )
            }
            ServiceState::Present { running } => running,
        };
        let offending: Vec<&str> = running
            .iter()
            .filter(|service| service.active && self.policy.services.interdicts(&service.name))
            .map(|service| service_base_name(&service.name))
            .collect();
        if offending.is_empty() {
            Evaluation::satisfied()
        } else {
            Evaluation::finding().with_detail(format!(
                "{} is an unnecessary active service that widens the host's attack surface",
                offending.join(", ")
            ))
        }
    }
}

impl RuleEvaluator for SystemScanner {
    fn evaluate(&self, context: &RuleContext<'_>) -> Result<Evaluation, ExecutionFailure> {
        match context.rule().id() {
            OS_EOL_RULE => self.evaluate_os_eol(),
            OS_SUPPORT_UNDETERMINED_RULE => self.evaluate_os_undetermined(),
            PACKAGE_INVENTORY_RULE => self.evaluate_packages(),
            SERVICES_RULE => Ok(self.evaluate_services()),
            other => Err(ExecutionFailure::new(format!(
                "no system-scanner rule is registered for '{other}'"
            ))),
        }
    }
}

/// The package manager the scan inventories through: the only one present, or the
/// one the distro id selects when both are present.
fn select_manager(snapshot: &SystemSnapshot) -> Option<Manager> {
    select_from(&snapshot.package_managers, snapshot.os_release.id())
}

/// The base service name, ignoring a trailing `.service` systemd unit suffix.
fn service_base_name(service: &str) -> &str {
    service.strip_suffix(".service").unwrap_or(service)
}

/// Parse the distro id and version id out of raw os-release content. A missing
/// `VERSION_ID` yields `None`, marking a malformed os-release.
fn parse_os_release(raw: &str) -> (String, Option<String>) {
    let mut id = String::new();
    let mut version_id = None;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("ID=") {
            id = unquote(value).to_string();
        } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(unquote(value).to_string());
        }
    }
    (id, version_id)
}

/// Strip surrounding double quotes and whitespace from an os-release value.
fn unquote(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(trimmed)
}

/// Read the host's short name from `/proc/sys/kernel/hostname`.
fn read_hostname() -> Result<Option<String>, AcquireError> {
    match fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(content) => {
            let name = content.trim();
            Ok((!name.is_empty()).then(|| name.to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AcquireError::new(format!(
            "cannot read the host name: {error}"
        ))),
    }
}

/// Read os-release from its standard locations, falling back to unreadable.
fn read_os_release() -> OsRelease {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(raw) = fs::read_to_string(path) {
            let (id, version_id) = parse_os_release(&raw);
            return OsRelease::Readable {
                id,
                version_id,
                raw,
            };
        }
    }
    OsRelease::Unreadable
}

/// Probe which package managers resolve on the host and inventory through the one
/// the distro id selects.
fn probe_packages(os_release: &OsRelease) -> (Vec<Manager>, Option<String>) {
    let mut managers = Vec::new();
    if binary_on_path("dpkg-query") {
        managers.push(Manager::Dpkg);
    }
    if binary_on_path("rpm") {
        managers.push(Manager::Rpm);
    }
    let inventory = select_from(&managers, os_release.id()).and_then(|manager| {
        let (program, args) = manager.inventory_argv();
        run_command(program, args)
    });
    (managers, inventory)
}

/// The package manager selected from `managers` given the distro `os_id`. With
/// both present, the Debian family selects dpkg and the RHEL family rpm;
/// otherwise the first present manager is used, deterministically.
fn select_from(managers: &[Manager], os_id: Option<&str>) -> Option<Manager> {
    match managers {
        [] => None,
        [only] => Some(*only),
        _ => match os_id {
            Some("ubuntu" | "debian") => Some(Manager::Dpkg),
            Some("rhel" | "fedora") => Some(Manager::Rpm),
            _ => managers.first().copied(),
        },
    }
}

/// Probe the service manager and its running services.
fn probe_services() -> (Option<ServiceManager>, Vec<Service>) {
    if Path::new("/run/systemd/system").is_dir() {
        let running = run_command(
            "systemctl",
            &[
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--plain",
            ],
        )
        .map(|output| parse_running_services(&output))
        .unwrap_or_default();
        (Some(ServiceManager::Systemd), running)
    } else {
        (None, Vec::new())
    }
}

/// Parse `systemctl list-units` output into the running services it names.
fn parse_running_services(output: &str) -> Vec<Service> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|name| Service {
            name: name.to_string(),
            active: true,
        })
        .collect()
}

/// Whether `name` resolves to a file on any `PATH` entry.
fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
}

/// Run `program` with `args`, returning its stdout when it exits successfully.
fn run_command(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}
