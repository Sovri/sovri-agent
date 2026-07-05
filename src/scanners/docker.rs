// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The Docker scanner: the agent's fourth and final V0.4 scanner (MAT-91).
//!
//! [`DockerScanner`] reads the host's *effective* Docker daemon posture offline —
//! `docker version` / `docker info` for the engine version and effective flags
//! (Command evidence) and `/etc/docker/daemon.json` for the persisted configuration
//! (Config evidence, anchored on the file) — into a [`DockerSnapshot`], then
//! evaluates it as catalogued rules through the MAT-85 engine as a
//! [`sovri_sdk::RuleEvaluator`]. Acquisition is host I/O; evaluation is a pure
//! function of the captured snapshot, so a test injects a fixture snapshot and never
//! invokes a real daemon.
//!
//! `daemon.json` is JSON, and the crate is std-only, so a small hand-rolled
//! JSON-subset reader parses it — mirroring the SDK's hand-rolled YAML subset. A
//! `daemon.json` that is present but not valid JSON never panics: acquisition carries
//! a warning caveat, the effective flags are still used, and a signal recoverable
//! only from the unparsable file errors rather than passing (R-01).
//!
//! Docker is optional, so a host with no daemon — absent, unreachable, or a
//! permission-denied probe — is [`Evaluation::not_applicable`] → SKIPPED for every
//! rule, never PASS and, by decision, never ERROR (R-06). This is the card that most
//! visibly exercises the MAT-123 `not_applicable` extension.
//!
//! Status follows the rule's result policy, mirroring the [`super::ssh`] mould: the
//! scanner emits [`Evaluation::satisfied`], [`Evaluation::finding`], or
//! [`Evaluation::not_applicable`] and never picks WARNING versus FAIL itself. The
//! daemon version is split across two rules — a fail-policy
//! [`DAEMON_VERSION_EOL_RULE`] that fires below the minimum-supported baseline and a
//! warn-policy [`DAEMON_VERSION_OBSOLETE_RULE`] that fires below the
//! minimum-recommended baseline. A reason states the technical situation and never a
//! legal conclusion. A secret on the daemon surface — a `log-opts` credential — is
//! classified [`Classification::Secret`] and never survives in an excerpt (R-07).

// `DockerScanner` / `DockerSnapshot` / `DockerPolicy` intentionally echo their module
// name, as `SshScanner` does in the sibling `ssh` module.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use sovri_sdk::{Evaluation, ExecutionFailure, RuleContext, RuleEvaluator, Target};

use crate::evidence::{Classification, Evidence, EvidenceKind, EvidenceLog};

/// The fail-policy rule: the daemon version is below the minimum-supported baseline
/// and is end-of-life.
pub const DAEMON_VERSION_EOL_RULE: &str = "container.docker.daemon-version-eol";
/// The warn-policy rule: the daemon version is supported but below the
/// minimum-recommended baseline and is obsolete.
pub const DAEMON_VERSION_OBSOLETE_RULE: &str = "container.docker.daemon-version-obsolete";
/// The fail-policy rule: the daemon trusts one or more insecure registries.
pub const INSECURE_REGISTRIES_RULE: &str = "container.docker.insecure-registries";
/// The fail-policy rule: the daemon API is bound to a TCP socket without
/// mutually-authenticated TLS.
pub const TCP_SOCKET_TLS_RULE: &str = "container.docker.tcp-socket-tls";
/// The warn-policy rule: one or more daemon hardening options are not at their
/// hardened value.
pub const DAEMON_HARDENING_RULE: &str = "container.docker.daemon-hardening";

/// The daemon configuration file every Config result targets.
pub const DAEMON_JSON_LOCATOR: &str = "/etc/docker/daemon.json";
/// The command whose effective output every Command evidence record anchors on.
pub const DOCKER_INFO_COMMAND: &str = "docker info";

/// The evidence id of the effective `docker info` / `docker version` output.
pub const EFFECTIVE_INFO_EVIDENCE_ID: &str = "container.docker.effective-info";
/// The evidence id of the parsed `/etc/docker/daemon.json` configuration.
pub const DAEMON_JSON_EVIDENCE_ID: &str = "container.docker.daemon-json";

/// The reason a Docker control is SKIPPED when no daemon is present on the host.
const DOCKER_ABSENT_REASON: &str =
    "Docker is not present on the host (no docker binary and no /etc/docker/daemon.json), so Docker hardening does not apply";

/// A placeholder content-hash token carried on Docker-scanner evidence.
///
/// Evidence carries a content hash but does not compute one; producing a real
/// SHA-256 digest is a separate concern (MAT-93). The token is non-blank so the
/// record validates, and stands in until real hashing is wired.
const UNVERIFIED_CONTENT_HASH: &str = "sha256:unverified";

/// Whether the Docker daemon could be reached when the posture was captured.
#[derive(Debug, Clone)]
enum Daemon {
    /// `docker info` responded: the daemon is reachable and can be assessed.
    Reachable,
    /// No daemon is present: no `docker` binary and no `daemon.json`.
    Absent,
    /// A daemon is configured or installed but did not respond (down, or the probe
    /// was denied), carrying the reason the probe gave.
    Unreachable(String),
}

/// Where the effective configuration a rule reads was resolved from — it decides
/// whether the rule cites Config evidence (the file) or Command evidence (the probe).
#[derive(Debug, Clone, Copy)]
enum ConfigOrigin {
    /// Parsed from `/etc/docker/daemon.json`.
    DaemonJson,
    /// Recovered from the `docker info` effective flags.
    DockerInfo,
}

/// The parse state of `/etc/docker/daemon.json`.
#[derive(Debug, Clone, Copy, Default)]
enum DaemonJsonState {
    /// Present and valid JSON.
    Present,
    /// Present but not valid JSON: a warning caveat is carried and the effective
    /// flags are used instead.
    Malformed,
    /// Not present on the host.
    #[default]
    Absent,
}

/// A parsed value in a `daemon.json` object, restricted to the shapes the daemon
/// configuration uses.
#[derive(Debug, Clone)]
enum ConfigValue {
    /// A string, e.g. `"log-driver": "json-file"`.
    Str(String),
    /// A boolean, e.g. `"live-restore": true`.
    Bool(bool),
    /// A list of strings, e.g. `"insecure-registries": ["registry:5000"]`.
    List(Vec<String>),
    /// A nested string map, e.g. `"log-opts": { "splunk-token": "…" }`.
    Map(BTreeMap<String, String>),
}

/// The effective Docker daemon configuration, keyed by daemon.json setting name.
#[derive(Debug, Clone, Default)]
struct DaemonConfig {
    values: BTreeMap<String, ConfigValue>,
}

impl DaemonConfig {
    /// The `insecure-registries` list, empty when the setting is absent.
    fn insecure_registries(&self) -> Vec<String> {
        match self.values.get("insecure-registries") {
            Some(ConfigValue::List(list)) => list.clone(),
            _ => Vec::new(),
        }
    }

    /// The `hosts` bindings, empty when the setting is absent.
    fn hosts(&self) -> Vec<String> {
        match self.values.get("hosts") {
            Some(ConfigValue::List(list)) => list.clone(),
            _ => Vec::new(),
        }
    }

    /// Whether `tlsverify` (mutual TLS) is enabled.
    fn tls_verify(&self) -> bool {
        matches!(self.values.get("tlsverify"), Some(ConfigValue::Bool(true)))
    }

    /// The `tlskey` path, when set. The path is a locator, not a secret; the key
    /// file's contents are never read.
    fn tls_key_path(&self) -> Option<&str> {
        match self.values.get("tlskey") {
            Some(ConfigValue::Str(path)) => Some(path.as_str()),
            _ => None,
        }
    }

    /// The `log-opts` map, when set.
    fn log_opts(&self) -> Option<&BTreeMap<String, String>> {
        match self.values.get("log-opts") {
            Some(ConfigValue::Map(map)) => Some(map),
            _ => None,
        }
    }

    /// The `log-opts` keys, names only — never their values, which may be secrets.
    fn log_opt_keys(&self) -> Vec<String> {
        match self.log_opts() {
            Some(map) => map.keys().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// The `log-opts` entries whose key names a credential, returned as
    /// `(key, value)` so they can be recorded as redacted Secret evidence.
    fn secret_log_opts(&self) -> Vec<(String, String)> {
        let Some(map) = self.log_opts() else {
            return Vec::new();
        };
        map.iter()
            .filter(|(key, _)| is_secret_key(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// Whether `option` is present at its hardened value.
    fn is_hardened(&self, option: &HardeningOption) -> bool {
        match (option.expected, self.values.get(&option.name)) {
            (HardenedValue::Set, Some(ConfigValue::Str(value))) => !value.is_empty(),
            (HardenedValue::Enabled, Some(ConfigValue::Bool(enabled))) => *enabled,
            (HardenedValue::Disabled, Some(ConfigValue::Bool(enabled))) => !*enabled,
            _ => false,
        }
    }
}

/// The hardened value a daemon option is expected to carry.
#[derive(Debug, Clone, Copy)]
enum HardenedValue {
    /// Any non-empty string, e.g. `log-driver` set.
    Set,
    /// The boolean `true`, e.g. `live-restore` on.
    Enabled,
    /// The boolean `false`, e.g. `userland-proxy` off.
    Disabled,
}

/// A catalogue daemon hardening expectation: an option name and the value it must
/// carry to be considered hardened.
#[derive(Debug, Clone)]
pub struct HardeningOption {
    name: String,
    expected: HardenedValue,
}

impl HardeningOption {
    /// An option that must be set to any non-empty string, e.g. `log-driver`.
    #[must_use]
    pub fn set(name: impl Into<String>) -> Self {
        HardeningOption {
            name: name.into(),
            expected: HardenedValue::Set,
        }
    }

    /// An option that must be enabled (`true`), e.g. `live-restore`.
    #[must_use]
    pub fn enabled(name: impl Into<String>) -> Self {
        HardeningOption {
            name: name.into(),
            expected: HardenedValue::Enabled,
        }
    }

    /// An option that must be disabled (`false`), e.g. `userland-proxy`.
    #[must_use]
    pub fn disabled(name: impl Into<String>) -> Self {
        HardeningOption {
            name: name.into(),
            expected: HardenedValue::Disabled,
        }
    }
}

/// A comparable Docker version parsed as `major.minor.patch`, missing components
/// treated as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    /// Parse a dotted version, reading the leading digits of each component so a
    /// build or vendor suffix folds onto the numeric release.
    fn parse(text: &str) -> Self {
        let mut parts = text.split('.').map(parse_leading_number);
        Version {
            major: parts.next().unwrap_or(0),
            minor: parts.next().unwrap_or(0),
            patch: parts.next().unwrap_or(0),
        }
    }
}

/// The catalogue-driven Docker baseline: the version boundaries R-02 grades against
/// and the hardening options R-05 expects. The scanner never hard-codes them.
#[derive(Debug, Clone)]
pub struct DockerPolicy {
    min_supported: Version,
    min_recommended: Version,
    hardening: Vec<HardeningOption>,
}

impl DockerPolicy {
    /// A policy carrying the minimum-supported and minimum-recommended version
    /// boundaries and the hardening options expected at their hardened value.
    #[must_use]
    pub fn new<H>(min_supported: &str, min_recommended: &str, hardening: H) -> Self
    where
        H: IntoIterator<Item = HardeningOption>,
    {
        DockerPolicy {
            min_supported: Version::parse(min_supported),
            min_recommended: Version::parse(min_recommended),
            hardening: hardening.into_iter().collect(),
        }
    }

    /// The names of every hardening option not at its hardened value in `config`, in
    /// catalogue order.
    fn not_hardened(&self, config: &DaemonConfig) -> Vec<String> {
        self.hardening
            .iter()
            .filter(|option| !config.is_hardened(option))
            .map(|option| option.name.clone())
            .collect()
    }
}

/// The captured Docker posture the [`DockerScanner`] evaluates.
///
/// Build one from the host with [`DockerSnapshot::acquire`], or from fixture facts
/// with [`DockerSnapshot::builder`]. Evaluation is a pure function of this value.
#[derive(Debug, Clone)]
pub struct DockerSnapshot {
    daemon: Daemon,
    version: Option<String>,
    config: Option<DaemonConfig>,
    origin: ConfigOrigin,
    daemon_json: DaemonJsonState,
}

impl DockerSnapshot {
    /// Start building a snapshot from fixture facts.
    #[must_use]
    pub fn builder() -> DockerSnapshotBuilder {
        DockerSnapshotBuilder::default()
    }

    /// Acquire the host's effective Docker posture offline.
    ///
    /// Probes the daemon with `docker info`, reads its version, and parses
    /// `/etc/docker/daemon.json`. An absent daemon, an unreachable one, and a
    /// permission-denied probe are first-class snapshot states that R-06 turns into
    /// SKIPPED, so acquisition itself cannot fail. Reads the host with the standard
    /// library and a local process probe only; it never touches the network.
    #[must_use]
    pub fn acquire() -> Self {
        let mut builder = DockerSnapshot::builder();
        match probe_daemon() {
            DaemonProbe::Reachable(version) => {
                // `probe_daemon` captures only the engine version, not the effective
                // registry/socket flags, so the effective configuration is confirmable
                // only from a parseable daemon.json. Marking it unconfirmable keeps the
                // config-dependent rules (R-03/R-04/R-05) from passing on a synthetic
                // empty config when daemon.json is absent or malformed — they error
                // instead of falsely passing (R-01). Capturing the real effective flags
                // from `docker info` is deferred host-acquisition work.
                builder = builder.reachable().config_unconfirmable();
                if let Some(version) = version {
                    builder = builder.server_version(version);
                }
                if let Ok(raw) = std::fs::read_to_string(DAEMON_JSON_LOCATOR) {
                    builder = builder.daemon_json(raw);
                }
            }
            DaemonProbe::PermissionDenied => {
                builder = builder
                    .unreachable("the 'docker info' probe was denied with a permission error");
            }
            DaemonProbe::Unreachable => {
                builder = if docker_present() {
                    builder.unreachable("the Docker daemon did not respond to 'docker info'")
                } else {
                    builder.absent()
                };
            }
        }
        builder.build()
    }
}

/// Builder for a fixture [`DockerSnapshot`].
#[derive(Debug, Default)]
pub struct DockerSnapshotBuilder {
    daemon: Option<Daemon>,
    version: Option<String>,
    daemon_json_state: DaemonJsonState,
    daemon_json_config: Option<DaemonConfig>,
    info_config: DaemonConfig,
    config_unconfirmable: bool,
}

impl DockerSnapshotBuilder {
    /// Mark the daemon as reachable (`docker info` responded).
    #[must_use]
    pub fn reachable(mut self) -> Self {
        self.daemon = Some(Daemon::Reachable);
        self
    }

    /// Mark the daemon as unreachable, carrying the reason the probe gave.
    #[must_use]
    pub fn unreachable(mut self, reason: impl Into<String>) -> Self {
        self.daemon = Some(Daemon::Unreachable(reason.into()));
        self
    }

    /// Mark the `docker info` probe as denied with a permission error — a flavour of
    /// unreachable that is still SKIPPED, never ERROR (R-06).
    #[must_use]
    pub fn permission_denied(mut self) -> Self {
        self.daemon = Some(Daemon::Unreachable(
            "the 'docker info' probe was denied with a permission error".to_string(),
        ));
        self
    }

    /// Mark the host as having no Docker daemon (no binary and no `daemon.json`).
    #[must_use]
    pub fn absent(mut self) -> Self {
        self.daemon = Some(Daemon::Absent);
        self
    }

    /// Set the daemon version reported by `docker version`.
    #[must_use]
    pub fn server_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the persisted configuration from raw `daemon.json` text, parsing it. Valid
    /// JSON becomes the effective config; text that is not valid JSON marks the state
    /// malformed without panicking, so the effective flags are used instead.
    #[must_use]
    pub fn daemon_json(mut self, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        match JsonParser::parse(&raw)
            .ok()
            .as_ref()
            .and_then(config_from_json)
        {
            Some(config) => {
                self.daemon_json_config = Some(config);
                self.daemon_json_state = DaemonJsonState::Present;
            }
            None => self.daemon_json_state = DaemonJsonState::Malformed,
        }
        self
    }

    /// Record that the effective configuration could not be confirmed: `daemon.json`
    /// was unparsable and the `docker info` effective flags do not report the signal,
    /// so a rule reading it errors rather than pass (R-01).
    #[must_use]
    pub fn config_unconfirmable(mut self) -> Self {
        self.config_unconfirmable = true;
        self
    }

    /// Set the `insecure-registries` reported by the `docker info` effective flags,
    /// used when `daemon.json` is absent.
    #[must_use]
    pub fn info_insecure_registries<I, S>(mut self, registries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let list = registries.into_iter().map(Into::into).collect();
        self.info_config
            .values
            .insert("insecure-registries".to_string(), ConfigValue::List(list));
        self
    }

    /// Add a `hosts` binding reported by the `docker info` effective flags, used when
    /// `daemon.json` is absent.
    #[must_use]
    pub fn info_host(mut self, host: impl Into<String>) -> Self {
        let entry = self
            .info_config
            .values
            .entry("hosts".to_string())
            .or_insert_with(|| ConfigValue::List(Vec::new()));
        if let ConfigValue::List(list) = entry {
            list.push(host.into());
        }
        self
    }

    /// Build the snapshot. With no daemon state set, the host is treated as absent.
    #[must_use]
    pub fn build(self) -> DockerSnapshot {
        let daemon = self.daemon.unwrap_or(Daemon::Absent);
        let (config, origin) = match self.daemon_json_state {
            DaemonJsonState::Present => (self.daemon_json_config, ConfigOrigin::DaemonJson),
            DaemonJsonState::Malformed | DaemonJsonState::Absent => {
                if self.config_unconfirmable {
                    (None, ConfigOrigin::DockerInfo)
                } else {
                    (Some(self.info_config), ConfigOrigin::DockerInfo)
                }
            }
        };
        DockerSnapshot {
            daemon,
            version: self.version,
            config,
            origin,
            daemon_json: self.daemon_json_state,
        }
    }
}

/// The Docker scanner: it evaluates a captured [`DockerSnapshot`] against a catalogue
/// [`DockerPolicy`], dispatching each rule by id and recording evidence.
#[derive(Debug, Clone)]
pub struct DockerScanner {
    snapshot: DockerSnapshot,
    policy: DockerPolicy,
    evidence: Vec<Evidence>,
}

impl DockerScanner {
    /// A scanner over `snapshot`, evaluated against catalogue `policy`.
    ///
    /// When the daemon is reachable the effective posture is captured as evidence up
    /// front: a Command record for the `docker info` / `docker version` output, a
    /// Config record for a parsed `daemon.json`, and one redacted Secret record per
    /// `log-opts` credential — so [`DockerScanner::evidence_log`] can back a result
    /// without re-reading state and a secret never rides in an excerpt.
    #[must_use]
    pub fn new(snapshot: DockerSnapshot, policy: DockerPolicy) -> Self {
        let mut evidence = Vec::new();
        if matches!(snapshot.daemon, Daemon::Reachable) {
            push_evidence(
                &mut evidence,
                EFFECTIVE_INFO_EVIDENCE_ID,
                EvidenceKind::Command,
                DOCKER_INFO_COMMAND,
                None,
                None,
                Some(command_excerpt(&snapshot, &policy)),
            );
            if matches!(snapshot.daemon_json, DaemonJsonState::Present) {
                if let Some(config) = &snapshot.config {
                    push_evidence(
                        &mut evidence,
                        DAEMON_JSON_EVIDENCE_ID,
                        EvidenceKind::Config,
                        DAEMON_JSON_LOCATOR,
                        None,
                        None,
                        Some(config_summary(config, &policy)),
                    );
                    for (key, value) in config.secret_log_opts() {
                        let id = format!("container.docker.log-opt.{key}");
                        push_evidence(
                            &mut evidence,
                            &id,
                            EvidenceKind::Config,
                            DAEMON_JSON_LOCATOR,
                            Some(key),
                            Some(Classification::Secret),
                            Some(value),
                        );
                    }
                }
            }
        }
        DockerScanner {
            snapshot,
            policy,
            evidence,
        }
    }

    /// A scanner that acquires the host's effective Docker posture, evaluated against
    /// `policy`.
    #[must_use]
    pub fn acquire(policy: DockerPolicy) -> Self {
        DockerScanner::new(DockerSnapshot::acquire(), policy)
    }

    /// An [`EvidenceLog`] of every evidence record the scan captured, so a result can
    /// be explained from the same records it references.
    #[must_use]
    pub fn evidence_log(&self) -> EvidenceLog {
        let mut log = EvidenceLog::new();
        for record in &self.evidence {
            log.record(record.clone());
        }
        log
    }

    /// The acquisition caveat when `daemon.json` was present but unparsable, or
    /// `None` when it parsed or was absent.
    #[must_use]
    pub fn acquisition_caveat(&self) -> Option<String> {
        matches!(self.snapshot.daemon_json, DaemonJsonState::Malformed).then(|| {
            format!(
                "{DAEMON_JSON_LOCATOR} is present but is not valid JSON; the 'docker info' effective flags were used instead"
            )
        })
    }

    /// The effective configuration a rule needs, or an execution failure when it
    /// cannot be confirmed — `daemon.json` was unparsable and the signal is not in
    /// the effective flags, so the rule errors rather than pass (R-01).
    fn require_config(&self) -> Result<&DaemonConfig, ExecutionFailure> {
        self.snapshot.config.as_ref().ok_or_else(|| {
            ExecutionFailure::new(
                "the effective Docker configuration could not be confirmed: /etc/docker/daemon.json is not valid JSON and the 'docker info' effective flags do not report the signal",
            )
        })
    }

    /// The daemon version, or an execution failure when it is unknown.
    fn require_version(&self) -> Result<&str, ExecutionFailure> {
        self.snapshot.version.as_deref().ok_or_else(|| {
            ExecutionFailure::new(
                "the effective Docker daemon version could not be determined from 'docker version'",
            )
        })
    }

    /// Anchor an evaluation on the effective configuration evidence — the Config
    /// record and daemon.json file when the signal came from `daemon.json`, the
    /// Command record when it came from the `docker info` effective flags.
    fn config_anchored(&self, evaluation: Evaluation) -> Evaluation {
        match self.snapshot.origin {
            ConfigOrigin::DaemonJson => evaluation
                .with_evidence_refs([DAEMON_JSON_EVIDENCE_ID])
                .with_targets([Target::file(DAEMON_JSON_LOCATOR)]),
            ConfigOrigin::DockerInfo => evaluation.with_evidence_refs([EFFECTIVE_INFO_EVIDENCE_ID]),
        }
    }

    /// Evaluate [`DAEMON_VERSION_EOL_RULE`]: a version below the minimum-supported
    /// baseline is a finding; every supported version passes here.
    fn evaluate_version_eol(&self) -> Result<Evaluation, ExecutionFailure> {
        let version = self.require_version()?;
        if Version::parse(version) < self.policy.min_supported {
            Ok(command_anchored(Evaluation::finding().with_detail(format!(
                "the Docker daemon version '{version}' is end-of-life: it is below the catalogue's minimum-supported baseline. Upgrade to a supported release."
            ))))
        } else {
            Ok(command_anchored(Evaluation::satisfied()))
        }
    }

    /// Evaluate [`DAEMON_VERSION_OBSOLETE_RULE`]: a version at or above
    /// minimum-supported but below minimum-recommended is a finding; a current
    /// version and an end-of-life one both pass here (the latter is the EOL rule's
    /// call).
    fn evaluate_version_obsolete(&self) -> Result<Evaluation, ExecutionFailure> {
        let version = self.require_version()?;
        let parsed = Version::parse(version);
        if parsed >= self.policy.min_supported && parsed < self.policy.min_recommended {
            Ok(command_anchored(Evaluation::finding().with_detail(format!(
                "the Docker daemon version '{version}' is supported but obsolete: it is below the catalogue's minimum-recommended baseline. Plan an upgrade to a current release."
            ))))
        } else {
            Ok(command_anchored(Evaluation::satisfied()))
        }
    }

    /// Evaluate [`INSECURE_REGISTRIES_RULE`]: a non-empty `insecure-registries` list
    /// is a finding quoting it; an empty or absent list passes.
    fn evaluate_insecure_registries(&self) -> Result<Evaluation, ExecutionFailure> {
        let config = self.require_config()?;
        let registries = config.insecure_registries();
        if registries.is_empty() {
            Ok(self.config_anchored(Evaluation::satisfied()))
        } else {
            Ok(self.config_anchored(Evaluation::finding().with_detail(format!(
                "the Docker daemon trusts insecure registries ({}): images are pulled without verified TLS. Remove the insecure-registries entries.",
                registries.join(", ")
            ))))
        }
    }

    /// Evaluate [`TCP_SOCKET_TLS_RULE`]: any `tcp://` binding without `tlsverify` is a
    /// finding quoting every offending binding, even alongside a local socket; a
    /// local-only socket or a `tcp://` binding with `tlsverify` passes.
    fn evaluate_socket(&self) -> Result<Evaluation, ExecutionFailure> {
        let config = self.require_config()?;
        let tcp_bindings: Vec<String> = config
            .hosts()
            .into_iter()
            .filter(|host| host.starts_with("tcp://"))
            .collect();
        if tcp_bindings.is_empty() || config.tls_verify() {
            Ok(self.config_anchored(Evaluation::satisfied()))
        } else {
            Ok(self.config_anchored(Evaluation::finding().with_detail(format!(
                "the Docker daemon API is bound to a TCP socket without mutually-authenticated TLS ({}): this exposes a root-equivalent remote API. Require 'tlsverify' or bind only to a local socket.",
                tcp_bindings.join(", ")
            ))))
        }
    }

    /// Evaluate [`DAEMON_HARDENING_RULE`]: any catalogue hardening option not at its
    /// hardened value — absent or present at an un-hardened value — is a single
    /// finding enumerating them; every option hardened passes.
    fn evaluate_hardening(&self) -> Result<Evaluation, ExecutionFailure> {
        let config = self.require_config()?;
        let not_hardened = self.policy.not_hardened(config);
        if not_hardened.is_empty() {
            Ok(self.config_anchored(Evaluation::satisfied()))
        } else {
            Ok(self.config_anchored(Evaluation::finding().with_detail(format!(
                "Docker daemon hardening options are not at their hardened value ({}): review and set them.",
                not_hardened.join(", ")
            ))))
        }
    }
}

impl RuleEvaluator for DockerScanner {
    fn evaluate(&self, context: &RuleContext<'_>) -> Result<Evaluation, ExecutionFailure> {
        // Reachability gate first (R-06): a daemon that is absent, unreachable, or
        // whose probe was denied is SKIPPED for every rule — never PASS, never ERROR.
        match &self.snapshot.daemon {
            Daemon::Absent => return Ok(Evaluation::not_applicable(DOCKER_ABSENT_REASON)),
            Daemon::Unreachable(reason) => {
                return Ok(Evaluation::not_applicable(format!(
                    "the Docker daemon could not be assessed ({reason}), so Docker hardening does not apply"
                )))
            }
            Daemon::Reachable => {}
        }
        match context.rule().id() {
            DAEMON_VERSION_EOL_RULE => self.evaluate_version_eol(),
            DAEMON_VERSION_OBSOLETE_RULE => self.evaluate_version_obsolete(),
            INSECURE_REGISTRIES_RULE => self.evaluate_insecure_registries(),
            TCP_SOCKET_TLS_RULE => self.evaluate_socket(),
            DAEMON_HARDENING_RULE => self.evaluate_hardening(),
            other => Err(ExecutionFailure::new(format!(
                "no docker-scanner rule is registered for '{other}'"
            ))),
        }
    }
}

/// Anchor an evaluation on the `docker info` / `docker version` Command evidence.
fn command_anchored(evaluation: Evaluation) -> Evaluation {
    evaluation.with_evidence_refs([EFFECTIVE_INFO_EVIDENCE_ID])
}

/// Build an evidence record and push it, dropping it silently if it fails to
/// validate. A `Secret`/`Sensitive` classification drops the excerpt at the builder,
/// so the identity rides in the key.
fn push_evidence(
    evidence: &mut Vec<Evidence>,
    id: &str,
    kind: EvidenceKind,
    locator: &str,
    key: Option<String>,
    classification: Option<Classification>,
    excerpt: Option<String>,
) {
    let mut builder = Evidence::builder()
        .id(id)
        .kind(kind)
        .locator(locator)
        .content_hash(UNVERIFIED_CONTENT_HASH);
    if let Some(key) = key {
        builder = builder.key(key);
    }
    if let Some(classification) = classification {
        builder = builder.classification(classification);
    }
    if let Some(excerpt) = excerpt {
        builder = builder.excerpt(excerpt);
    }
    if let Ok(record) = builder.build() {
        evidence.push(record);
    }
}

/// The excerpt for the Command evidence: the daemon version, plus the effective
/// configuration summary when the signal comes from the `docker info` flags rather
/// than `daemon.json`.
fn command_excerpt(snapshot: &DockerSnapshot, policy: &DockerPolicy) -> String {
    let mut lines = vec![format!(
        "Server Version: {}",
        snapshot.version.as_deref().unwrap_or("unknown")
    )];
    if matches!(snapshot.origin, ConfigOrigin::DockerInfo) {
        if let Some(config) = &snapshot.config {
            lines.push(config_summary(config, policy));
        }
    }
    lines.join("\n")
}

/// A safe, deterministic rendering of the effective configuration for an evidence
/// excerpt: the security-relevant settings and the names of any not-hardened options,
/// but never a `log-opts` value, which may be a secret.
fn config_summary(config: &DaemonConfig, policy: &DockerPolicy) -> String {
    let mut lines = vec![
        format!(
            "insecure-registries: {}",
            join_or_none(&config.insecure_registries())
        ),
        format!("hosts: {}", join_or_none(&config.hosts())),
        format!("tlsverify: {}", config.tls_verify()),
    ];
    if let Some(path) = config.tls_key_path() {
        lines.push(format!("tlskey: {path}"));
    }
    let log_opt_keys = config.log_opt_keys();
    if !log_opt_keys.is_empty() {
        lines.push(format!("log-opts keys: {}", log_opt_keys.join(", ")));
    }
    lines.push(format!(
        "not hardened: {}",
        join_or_none(&policy.not_hardened(config))
    ));
    lines.join("\n")
}

/// Render a list as a comma-separated string, or `(none)` when it is empty.
fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

/// Whether a `log-opts` key names a credential whose value must be redacted.
fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "token",
        "password",
        "passwd",
        "secret",
        "apikey",
        "credential",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Read the leading ASCII digits of a version component as a number, or zero.
fn parse_leading_number(part: &str) -> u32 {
    let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

/// Map a parsed JSON value to the effective configuration, keeping only the shapes
/// the daemon configuration uses. `None` when the root is not a JSON object.
fn config_from_json(value: &JsonValue) -> Option<DaemonConfig> {
    let JsonValue::Object(entries) = value else {
        return None;
    };
    let mut values = BTreeMap::new();
    for (key, entry) in entries {
        match entry {
            JsonValue::Str(text) => {
                values.insert(key.clone(), ConfigValue::Str(text.clone()));
            }
            JsonValue::Bool(flag) => {
                values.insert(key.clone(), ConfigValue::Bool(*flag));
            }
            JsonValue::Array(items) => {
                let list = items
                    .iter()
                    .filter_map(|item| match item {
                        JsonValue::Str(text) => Some(text.clone()),
                        _ => None,
                    })
                    .collect();
                values.insert(key.clone(), ConfigValue::List(list));
            }
            JsonValue::Object(inner) => {
                let mut map = BTreeMap::new();
                for (inner_key, inner_value) in inner {
                    if let JsonValue::Str(text) = inner_value {
                        map.insert(inner_key.clone(), text.clone());
                    }
                }
                values.insert(key.clone(), ConfigValue::Map(map));
            }
            JsonValue::Num | JsonValue::Null => {}
        }
    }
    Some(DaemonConfig { values })
}

/// A parsed JSON value from the hand-rolled reader.
#[derive(Debug, Clone)]
enum JsonValue {
    /// `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A number — parsed and validated, but the daemon configuration reads none, so
    /// the digits are discarded.
    Num,
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<JsonValue>),
    /// An object, preserving key order.
    Object(Vec<(String, JsonValue)>),
}

/// A JSON parse error. The daemon configuration only distinguishes valid from
/// invalid, so the error carries no detail.
#[derive(Debug)]
struct JsonError;

/// A minimal recursive-descent reader for the JSON subset `daemon.json` uses:
/// objects, arrays, strings, numbers, booleans, and null. It never panics on
/// malformed input; it returns [`JsonError`].
struct JsonParser {
    chars: Vec<char>,
    pos: usize,
}

impl JsonParser {
    /// Parse a complete JSON document, rejecting trailing non-whitespace.
    fn parse(input: &str) -> Result<JsonValue, JsonError> {
        let mut parser = JsonParser {
            chars: input.chars().collect(),
            pos: 0,
        };
        parser.skip_whitespace();
        let value = parser.parse_value()?;
        parser.skip_whitespace();
        if parser.pos == parser.chars.len() {
            Ok(value)
        } else {
            Err(JsonError)
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let current = self.peek();
        if current.is_some() {
            self.pos += 1;
        }
        current
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(JsonValue::Str(self.parse_string()?)),
            Some('t') => self.parse_keyword("true", JsonValue::Bool(true)),
            Some('f') => self.parse_keyword("false", JsonValue::Bool(false)),
            Some('n') => self.parse_keyword("null", JsonValue::Null),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(JsonError),
        }
    }

    fn parse_keyword(&mut self, word: &str, value: JsonValue) -> Result<JsonValue, JsonError> {
        for expected in word.chars() {
            if self.bump() != Some(expected) {
                return Err(JsonError);
            }
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        if self.peek() == Some('-') {
            self.pos += 1;
        }

        // Integer part: a lone `0` or a non-zero digit run, per the JSON grammar. A
        // lax scanner that accepted `1e`, `1+`, `1.`, or `007` would let a malformed
        // daemon.json parse and be treated as present, bypassing the R-01 caveat.
        match self.peek() {
            Some('0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    return Err(JsonError);
                }
            }
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(JsonError),
        }

        if self.peek() == Some('.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(JsonError);
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }

        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                return Err(JsonError);
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }

        Ok(JsonValue::Num)
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        if self.bump() != Some('"') {
            return Err(JsonError);
        }
        let mut text = String::new();
        loop {
            match self.bump() {
                None => return Err(JsonError),
                Some('"') => return Ok(text),
                Some('\\') => text.push(self.parse_escape()?),
                Some(c) if c <= '\u{001F}' => return Err(JsonError),
                Some(c) => text.push(c),
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        match self.bump() {
            Some('"') => Ok('"'),
            Some('\\') => Ok('\\'),
            Some('/') => Ok('/'),
            Some('n') => Ok('\n'),
            Some('t') => Ok('\t'),
            Some('r') => Ok('\r'),
            Some('b') => Ok('\u{0008}'),
            Some('f') => Ok('\u{000C}'),
            Some('u') => {
                let mut code = 0u32;
                for _ in 0..4 {
                    let digit = self.bump().and_then(|c| c.to_digit(16)).ok_or(JsonError)?;
                    code = code * 16 + digit;
                }
                char::from_u32(code).ok_or(JsonError)
            }
            _ => Err(JsonError),
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        if self.bump() != Some('[') {
            return Err(JsonError);
        }
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.bump() {
                Some(',') => {}
                Some(']') => return Ok(JsonValue::Array(items)),
                _ => return Err(JsonError),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        if self.bump() != Some('{') {
            return Err(JsonError);
        }
        let mut entries = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some('"') {
                return Err(JsonError);
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.bump() != Some(':') {
                return Err(JsonError);
            }
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.bump() {
                Some(',') => {}
                Some('}') => return Ok(JsonValue::Object(entries)),
                _ => return Err(JsonError),
            }
        }
    }
}

/// The outcome of probing the daemon with `docker info`.
enum DaemonProbe {
    /// The daemon responded, carrying the reported server version when present.
    Reachable(Option<String>),
    /// The probe was denied with a permission error.
    PermissionDenied,
    /// The daemon did not respond, or the `docker` binary is missing.
    Unreachable,
}

/// Probe the daemon with `docker info`, reading its server version.
fn probe_daemon() -> DaemonProbe {
    let output = std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output();
    let Ok(output) = output else {
        return DaemonProbe::Unreachable;
    };
    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return DaemonProbe::Reachable((!version.is_empty()).then_some(version));
    }
    if String::from_utf8_lossy(&output.stderr)
        .to_ascii_lowercase()
        .contains("permission denied")
    {
        DaemonProbe::PermissionDenied
    } else {
        DaemonProbe::Unreachable
    }
}

/// Whether Docker is present on the host: a `docker` binary on `PATH` or a
/// `daemon.json` on disk.
fn docker_present() -> bool {
    std::path::Path::new(DAEMON_JSON_LOCATOR).exists() || binary_on_path("docker")
}

/// Whether `name` resolves to a file on any `PATH` entry.
fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
}
