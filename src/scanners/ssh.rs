// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The Linux SSH scanner: the agent's third scanner (MAT-90).
//!
//! [`SshScanner`] reads the host's *effective* `sshd` configuration — the resolved
//! `sshd -T` dump, with `Include`s and defaults folded in — into an [`SshSnapshot`],
//! then evaluates it as catalogued rules through the MAT-85 engine as a
//! [`sovri_sdk::RuleEvaluator`]. When `sshd -T` is unavailable it falls back to
//! parsing `sshd_config` and its `sshd_config.d` drop-ins; a raw parse is subject to
//! `Include` ordering, so an unresolved `Include` carries a WARNING caveat and a
//! directive that could hide inside it errors rather than risk a false pass.
//! Acquisition is host I/O; evaluation is a pure function of the captured snapshot,
//! so a test injects a fixture dump and never invokes a real `sshd`.
//!
//! Status follows the rule's result policy, mirroring the [`super::system`] mould:
//! the scanner emits [`Evaluation::satisfied`], [`Evaluation::finding`], or
//! [`Evaluation::not_applicable`] and never picks WARNING versus FAIL itself. Root
//! login is split across two rules — a fail-policy [`PERMIT_ROOT_LOGIN_RULE`] that
//! fires on `yes` and a [`ROOT_LOGIN_KEY_ONLY_RULE`] that fires on the non-password
//! paths, warning under the default catalogue and failing under a hardened one.
//! Cryptography is split the same way: a warn-policy [`WEAK_CRYPTO_RULE`] over the
//! catalogue's legacy-algorithm lists and a fail-policy [`PROTOCOL_V1_RULE`]
//! guard-rail for an explicit `Protocol 1`. A reason states the technical situation
//! and never a legal conclusion.

// `SshScanner` / `SshSnapshot` / `SshPolicy` intentionally echo their module name,
// as `SystemScanner` does in the sibling `system` module.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use sovri_sdk::{Evaluation, ExecutionFailure, RuleContext, RuleEvaluator, Target};

use crate::evidence::{Evidence, EvidenceKind, EvidenceLog};

/// The fail-policy rule: root login is enabled (`PermitRootLogin yes`).
pub const PERMIT_ROOT_LOGIN_RULE: &str = "host.ssh.permit-root-login";
/// The rule flagging root login permitted only by a non-password path
/// (`prohibit-password` / `forced-commands-only`): warn-policy under the default
/// catalogue, fail-policy under a hardened one.
pub const ROOT_LOGIN_KEY_ONLY_RULE: &str = "host.ssh.root-login-key-only";
/// The fail-policy rule: password authentication is enabled.
pub const PASSWORD_AUTH_RULE: &str = "host.ssh.password-auth";
/// The warn-policy rule: a legacy cipher, MAC, or key-exchange algorithm is enabled.
pub const WEAK_CRYPTO_RULE: &str = "host.ssh.weak-crypto";
/// The fail-policy guard-rail rule: SSH protocol 1 (`SSHv1`) is explicitly enabled.
pub const PROTOCOL_V1_RULE: &str = "host.ssh.protocol-v1";

/// The command whose effective dump every `sshd -T` evidence record anchors on.
pub const SSHD_EFFECTIVE_COMMAND: &str = "sshd -T";
/// The configuration file every SSH result targets.
pub const SSHD_CONFIG_LOCATOR: &str = "/etc/ssh/sshd_config";

/// The evidence id of the effective `sshd -T` configuration dump.
pub const EFFECTIVE_CONFIG_EVIDENCE_ID: &str = "host.ssh.effective-config";
/// The evidence id of the parsed `sshd_config` file, captured on the fallback path.
pub const CONFIG_FILE_EVIDENCE_ID: &str = "host.ssh.config-file";

/// The `PermitRootLogin` directive name, lowercased as `sshd -T` emits it.
const PERMIT_ROOT_LOGIN: &str = "permitrootlogin";
/// The `PasswordAuthentication` directive name.
const PASSWORD_AUTHENTICATION: &str = "passwordauthentication";
/// The `Ciphers` directive name.
const CIPHERS: &str = "ciphers";
/// The `MACs` directive name.
const MACS: &str = "macs";
/// The `KexAlgorithms` directive name.
const KEX_ALGORITHMS: &str = "kexalgorithms";
/// The `Protocol` directive name (observable only on the file-parse fallback path;
/// modern `sshd -T` no longer emits it).
const PROTOCOL: &str = "protocol";

/// Where the effective SSH configuration was resolved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// The effective dump from `sshd -T`, with includes and defaults folded in.
    EffectiveDump,
    /// A parse of `sshd_config` and its `sshd_config.d` drop-ins, used when
    /// `sshd -T` is unavailable.
    ParsedFallback,
    /// An SSH server is present but could not be assessed: `sshd -T` failed and the
    /// configuration file was unreadable.
    Unassessable,
    /// No SSH server is present: no `sshd` binary and no `sshd_config`.
    Absent,
}

/// How `PermitRootLogin` resolves, with the historical `without-password` alias
/// normalised onto `prohibit-password`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootLogin {
    /// `no` — direct root login disabled.
    Disabled,
    /// `yes` — root login enabled, including by password.
    Enabled,
    /// `prohibit-password` (or its `without-password` alias) — root by key only.
    ProhibitPassword,
    /// `forced-commands-only` — root only to run a forced key command.
    ForcedCommandsOnly,
    /// An unrecognised value.
    Other,
}

/// Parse a `PermitRootLogin` value, folding the `without-password` alias onto
/// `prohibit-password`.
fn parse_root_login(value: &str) -> RootLogin {
    match value.trim().to_ascii_lowercase().as_str() {
        "no" => RootLogin::Disabled,
        "yes" => RootLogin::Enabled,
        "prohibit-password" | "without-password" => RootLogin::ProhibitPassword,
        "forced-commands-only" => RootLogin::ForcedCommandsOnly,
        _ => RootLogin::Other,
    }
}

/// The catalogue-driven lists of weak SSH algorithms R-04 flags. The scanner never
/// hard-codes them; they are supplied like the system scanner's interdiction list.
#[derive(Debug, Clone, Default)]
pub struct SshPolicy {
    ciphers: Vec<String>,
    macs: Vec<String>,
    kex: Vec<String>,
}

impl SshPolicy {
    /// A policy carrying the weak cipher, MAC, and key-exchange lists.
    #[must_use]
    pub fn new<C, M, K, S>(weak_ciphers: C, weak_macs: M, weak_kex: K) -> Self
    where
        C: IntoIterator<Item = S>,
        M: IntoIterator<Item = S>,
        K: IntoIterator<Item = S>,
        S: Into<String>,
    {
        SshPolicy {
            ciphers: weak_ciphers.into_iter().map(Into::into).collect(),
            macs: weak_macs.into_iter().map(Into::into).collect(),
            kex: weak_kex.into_iter().map(Into::into).collect(),
        }
    }

    /// The weak-algorithm list for a directive, or `None` when the directive carries
    /// no cryptographic list.
    fn weak_list(&self, directive: &str) -> Option<&[String]> {
        match directive {
            CIPHERS => Some(&self.ciphers),
            MACS => Some(&self.macs),
            KEX_ALGORITHMS => Some(&self.kex),
            _ => None,
        }
    }

    /// Whether `algorithm` is on the weak list for `directive`, compared
    /// case-insensitively.
    fn is_weak(&self, directive: &str, algorithm: &str) -> bool {
        self.weak_list(directive)
            .is_some_and(|list| list.iter().any(|weak| weak.eq_ignore_ascii_case(algorithm)))
    }
}

/// The captured SSH configuration the [`SshScanner`] evaluates.
///
/// Build one from the host with [`SshSnapshot::acquire`], or from a fixture with
/// [`SshSnapshot::builder`]. Evaluation is a pure function of this value.
#[derive(Debug, Clone)]
pub struct SshSnapshot {
    source: ConfigSource,
    directives: BTreeMap<String, String>,
    raw: String,
    unresolved_include: bool,
}

impl SshSnapshot {
    /// Start building a snapshot from fixture facts.
    #[must_use]
    pub fn builder() -> SshSnapshotBuilder {
        SshSnapshotBuilder::default()
    }

    /// Acquire the host's effective SSH configuration offline.
    ///
    /// Reads the resolved dump from `sshd -T`, falling back to parsing
    /// `sshd_config` and its `sshd_config.d` drop-ins. A present-but-unreadable
    /// server and a genuinely absent one are first-class snapshot states
    /// ([`ConfigSource::Unassessable`] / [`ConfigSource::Absent`]) that R-05 turns
    /// into ERROR and SKIPPED, so acquisition itself cannot fail. Reads the host
    /// with the standard library and a local process probe only; it never touches
    /// the network.
    #[must_use]
    pub fn acquire() -> Self {
        if let Some(dump) = run_sshd_effective() {
            return SshSnapshot::builder().effective_dump(dump).build();
        }
        match read_config_with_drop_ins() {
            Some((text, unresolved_include)) => {
                let mut builder = SshSnapshot::builder().parsed_config(text);
                if unresolved_include {
                    builder = builder.unresolved_include();
                }
                builder.build()
            }
            None if sshd_present() => SshSnapshot::builder().unassessable().build(),
            None => SshSnapshot::builder().absent().build(),
        }
    }

    /// The value of a directive, lowercased key, or `None` when it is absent.
    fn directive(&self, name: &str) -> Option<&str> {
        self.directives.get(name).map(String::as_str)
    }
}

/// Builder for a fixture [`SshSnapshot`].
#[derive(Debug, Default)]
pub struct SshSnapshotBuilder {
    source: Option<ConfigSource>,
    directives: BTreeMap<String, String>,
    raw: String,
    unresolved_include: bool,
}

impl SshSnapshotBuilder {
    /// Set the effective configuration from an `sshd -T` dump, parsing its
    /// directives. Marks the source as the effective dump.
    #[must_use]
    pub fn effective_dump(mut self, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        self.directives = parse_directives(&raw);
        self.raw = raw;
        self.source = Some(ConfigSource::EffectiveDump);
        self
    }

    /// Set the configuration from a parsed `sshd_config`, used when `sshd -T` is
    /// unavailable. Marks the source as the parsed fallback.
    #[must_use]
    pub fn parsed_config(mut self, raw: impl Into<String>) -> Self {
        let raw = raw.into();
        self.directives = parse_directives(&raw);
        self.raw = raw;
        self.source = Some(ConfigSource::ParsedFallback);
        self
    }

    /// Record that an `Include` on the fallback path could not be read.
    #[must_use]
    pub fn unresolved_include(mut self) -> Self {
        self.unresolved_include = true;
        self
    }

    /// Mark the host as having no SSH server (no binary and no config).
    #[must_use]
    pub fn absent(mut self) -> Self {
        self.source = Some(ConfigSource::Absent);
        self
    }

    /// Mark the SSH server as present but unassessable (`sshd -T` failed and the
    /// config file was unreadable).
    #[must_use]
    pub fn unassessable(mut self) -> Self {
        self.source = Some(ConfigSource::Unassessable);
        self
    }

    /// Build the snapshot. With no source set, it is treated as absent.
    #[must_use]
    pub fn build(self) -> SshSnapshot {
        SshSnapshot {
            source: self.source.unwrap_or(ConfigSource::Absent),
            directives: self.directives,
            raw: self.raw,
            unresolved_include: self.unresolved_include,
        }
    }
}

/// The Linux SSH scanner: it evaluates a captured [`SshSnapshot`] against a
/// catalogue [`SshPolicy`], dispatching each rule by id and recording evidence.
#[derive(Debug, Clone)]
pub struct SshScanner {
    snapshot: SshSnapshot,
    policy: SshPolicy,
    evidence: Vec<Evidence>,
}

impl SshScanner {
    /// A scanner over `snapshot`, evaluated against catalogue `policy`.
    ///
    /// The effective configuration is captured as one evidence record up front — a
    /// Command record on the `sshd -T` path, a Config record on the file-parse
    /// fallback — so [`SshScanner::evidence_log`] can back a result without
    /// re-reading state.
    #[must_use]
    pub fn new(snapshot: SshSnapshot, policy: SshPolicy) -> Self {
        let mut evidence = Vec::new();
        let record = match snapshot.source {
            ConfigSource::EffectiveDump => Some((
                EFFECTIVE_CONFIG_EVIDENCE_ID,
                EvidenceKind::Command,
                SSHD_EFFECTIVE_COMMAND,
            )),
            ConfigSource::ParsedFallback => Some((
                CONFIG_FILE_EVIDENCE_ID,
                EvidenceKind::Config,
                SSHD_CONFIG_LOCATOR,
            )),
            ConfigSource::Unassessable | ConfigSource::Absent => None,
        };
        if let Some((id, kind, locator)) = record {
            if let Ok(built) = Evidence::builder()
                .id(id)
                .kind(kind)
                .locator(locator)
                .content(snapshot.raw.clone().into_bytes())
                .build()
            {
                evidence.push(built);
            }
        }
        SshScanner {
            snapshot,
            policy,
            evidence,
        }
    }

    /// A scanner that acquires the host's effective SSH configuration, evaluated
    /// against `policy`.
    #[must_use]
    pub fn acquire(policy: SshPolicy) -> Self {
        SshScanner::new(SshSnapshot::acquire(), policy)
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

    /// Where the effective configuration was resolved from.
    #[must_use]
    pub fn source(&self) -> ConfigSource {
        self.snapshot.source
    }

    /// The acquisition note when the effective `sshd -T` dump was unavailable and
    /// the scan fell back to parsing the configuration file, or `None` on the
    /// effective-dump path.
    #[must_use]
    pub fn acquisition_note(&self) -> Option<String> {
        match self.snapshot.source {
            ConfigSource::ParsedFallback => Some(format!(
                "the effective '{SSHD_EFFECTIVE_COMMAND}' dump was unavailable; parsed {SSHD_CONFIG_LOCATOR} and its sshd_config.d drop-ins instead"
            )),
            _ => None,
        }
    }

    /// The WARNING caveat when an `Include` could not be resolved on the fallback
    /// path, or `None` when every `Include` resolved.
    #[must_use]
    pub fn acquisition_caveat(&self) -> Option<String> {
        if self.snapshot.unresolved_include {
            Some(
                "an Include directive could not be resolved, so a directive absent from the readable configuration cannot be confirmed"
                    .to_string(),
            )
        } else {
            None
        }
    }

    /// The evidence id backing results for the current source, or `None` when there
    /// is no configuration to cite.
    fn evidence_id(&self) -> Option<&'static str> {
        match self.snapshot.source {
            ConfigSource::EffectiveDump => Some(EFFECTIVE_CONFIG_EVIDENCE_ID),
            ConfigSource::ParsedFallback => Some(CONFIG_FILE_EVIDENCE_ID),
            ConfigSource::Unassessable | ConfigSource::Absent => None,
        }
    }

    /// Anchor an evaluation on the captured configuration evidence and the config
    /// file, so every graded result cites the effective configuration it read.
    fn anchored(&self, evaluation: Evaluation) -> Evaluation {
        match self.evidence_id() {
            Some(id) => evaluation
                .with_evidence_refs([id])
                .with_targets([Target::file(SSHD_CONFIG_LOCATOR)]),
            None => evaluation,
        }
    }

    /// The value of a directive needed to grade a rule, or an execution failure when
    /// it cannot be confirmed — absent from the readable text with an unresolved
    /// `Include` that could be hiding it, so the rule errors rather than pass.
    fn require_directive(&self, name: &str) -> Result<&str, ExecutionFailure> {
        self.snapshot.directive(name).ok_or_else(|| {
            if self.snapshot.unresolved_include {
                ExecutionFailure::new(format!(
                    "the effective '{name}' could not be confirmed because an Include was unresolved, so it may be set inside the unreadable include"
                ))
            } else {
                ExecutionFailure::new(format!(
                    "the effective '{name}' could not be confirmed: it is absent from the readable configuration"
                ))
            }
        })
    }

    /// Evaluate [`PERMIT_ROOT_LOGIN_RULE`]: `PermitRootLogin yes` is a finding; every
    /// other value passes here (the non-password paths are the key-only rule's call).
    fn evaluate_permit_root_login(&self) -> Result<Evaluation, ExecutionFailure> {
        let value = self.require_directive(PERMIT_ROOT_LOGIN)?;
        if parse_root_login(value) == RootLogin::Enabled {
            Ok(self.anchored(Evaluation::finding().with_detail(format!(
                "root login over SSH is enabled: the effective configuration reports 'permitrootlogin {value}'. Set 'permitrootlogin no' to disable direct root login."
            ))))
        } else {
            Ok(self.anchored(Evaluation::satisfied()))
        }
    }

    /// Evaluate [`ROOT_LOGIN_KEY_ONLY_RULE`]: a non-password root-login path
    /// (`prohibit-password`, `forced-commands-only`, or the `without-password`
    /// alias) is a finding; `no` and `yes` pass here.
    fn evaluate_root_login_key_only(&self) -> Result<Evaluation, ExecutionFailure> {
        let value = self.require_directive(PERMIT_ROOT_LOGIN)?;
        match parse_root_login(value) {
            RootLogin::ProhibitPassword | RootLogin::ForcedCommandsOnly => {
                Ok(self.anchored(Evaluation::finding().with_detail(non_password_reason(value))))
            }
            _ => Ok(self.anchored(Evaluation::satisfied())),
        }
    }

    /// Evaluate [`PASSWORD_AUTH_RULE`]: `PasswordAuthentication yes` is a finding —
    /// including an unconfigured host whose effective dump reports the OpenSSH
    /// default `yes` — while `no` passes.
    fn evaluate_password_auth(&self) -> Result<Evaluation, ExecutionFailure> {
        let value = self.require_directive(PASSWORD_AUTHENTICATION)?;
        if value.trim().eq_ignore_ascii_case("yes") {
            Ok(self.anchored(Evaluation::finding().with_detail(format!(
                "password authentication is enabled: the effective configuration reports 'passwordauthentication {value}'. Set 'passwordauthentication no' to require key-based authentication."
            ))))
        } else {
            Ok(self.anchored(Evaluation::satisfied()))
        }
    }

    /// Evaluate [`WEAK_CRYPTO_RULE`]: any catalogue-listed legacy cipher, MAC, or
    /// key-exchange algorithm is a finding naming each. `Ciphers` / `MACs` /
    /// `KexAlgorithms` may carry a leading modifier that adjusts the built-in
    /// defaults rather than replacing them — `+` appends, `^` prepends, `-` removes.
    /// `sshd -T` resolves these to a concrete list, but the fallback parse sees them
    /// raw, so an appended or prepended algorithm is still assessed while a removal
    /// enables nothing weak. A clean set passes, unless an unresolved `Include` could
    /// be hiding a weak algorithm, in which case it errors rather than pass.
    fn evaluate_weak_crypto(&self) -> Result<Evaluation, ExecutionFailure> {
        let mut weak = Vec::new();
        for (directive, kind) in [
            (CIPHERS, "cipher"),
            (MACS, "MAC"),
            (KEX_ALGORITHMS, "key exchange"),
        ] {
            let Some(raw) = self.snapshot.directive(directive) else {
                continue;
            };
            let raw = raw.trim();
            let list = match raw.as_bytes().first() {
                // A '-' list only removes algorithms from the modern defaults, so it
                // can enable nothing weak.
                Some(b'-') => continue,
                // '+' / '^' extend the defaults; assess the added algorithms.
                Some(b'+' | b'^') => &raw[1..],
                _ => raw,
            };
            for algorithm in list.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                if self.policy.is_weak(directive, algorithm) {
                    weak.push(format!("{algorithm} ({kind})"));
                }
            }
        }
        if !weak.is_empty() {
            return Ok(self.anchored(Evaluation::finding().with_detail(format!(
                "weak SSH cryptography is enabled: {}. Remove these legacy algorithms in favour of modern ciphers, MACs, and key-exchange methods.",
                weak.join(", ")
            ))));
        }
        // Nothing weak is visible, but on the fallback path an unresolved `Include`
        // could hide a `Ciphers` / `MACs` / `KexAlgorithms` line, so a clean PASS
        // cannot be asserted.
        if self.snapshot.unresolved_include {
            return Err(ExecutionFailure::new(
                "the SSH cryptography configuration could not be confirmed: an Include was unresolved, so a weak cipher, MAC, or key-exchange algorithm may be set inside the unreadable include",
            ));
        }
        Ok(self.anchored(Evaluation::satisfied()))
    }

    /// Evaluate [`PROTOCOL_V1_RULE`]: an explicit `Protocol 1` (obsolete `SSHv1`) is a
    /// finding; its absence passes, unless an unresolved `Include` could be hiding a
    /// `Protocol 1` directive, in which case it errors rather than pass.
    fn evaluate_protocol_v1(&self) -> Result<Evaluation, ExecutionFailure> {
        let enables_v1 = self
            .snapshot
            .directive(PROTOCOL)
            .is_some_and(|value| value.split(',').map(str::trim).any(|token| token == "1"));
        if enables_v1 {
            return Ok(self.anchored(Evaluation::finding().with_detail(
                "SSH protocol 1 (SSHv1) is explicitly enabled via 'Protocol 1'; it is obsolete and disallowed. Remove the 'Protocol 1' directive so only SSHv2 is used."
                    .to_string(),
            )));
        }
        // `Protocol` is not visible, but on the fallback path an unresolved `Include`
        // could set `Protocol 1`, so a clean PASS cannot be asserted.
        if self.snapshot.unresolved_include {
            return Err(ExecutionFailure::new(
                "SSH protocol 1 (SSHv1) could not be ruled out: an Include was unresolved, so a 'Protocol 1' directive may be set inside the unreadable include",
            ));
        }
        Ok(self.anchored(Evaluation::satisfied()))
    }
}

impl RuleEvaluator for SshScanner {
    fn evaluate(&self, context: &RuleContext<'_>) -> Result<Evaluation, ExecutionFailure> {
        // Source-level gates first (R-05): a genuinely absent server is SKIPPED for
        // every rule; a present-but-unreadable one ERRORs rather than pass or skip.
        match self.snapshot.source {
            ConfigSource::Absent => {
                return Ok(Evaluation::not_applicable(
                    "no SSH server is present on the host (no sshd binary and no sshd_config), so SSH hardening does not apply",
                ))
            }
            ConfigSource::Unassessable => {
                return Err(ExecutionFailure::new(
                    "an SSH server is present but could not be assessed: 'sshd -T' failed and the configuration file was unreadable",
                ))
            }
            ConfigSource::EffectiveDump | ConfigSource::ParsedFallback => {}
        }
        match context.rule().id() {
            PERMIT_ROOT_LOGIN_RULE => self.evaluate_permit_root_login(),
            ROOT_LOGIN_KEY_ONLY_RULE => self.evaluate_root_login_key_only(),
            PASSWORD_AUTH_RULE => self.evaluate_password_auth(),
            WEAK_CRYPTO_RULE => self.evaluate_weak_crypto(),
            PROTOCOL_V1_RULE => self.evaluate_protocol_v1(),
            other => Err(ExecutionFailure::new(format!(
                "no ssh-scanner rule is registered for '{other}'"
            ))),
        }
    }
}

/// The reason for a non-password root-login finding, treating the historical
/// `without-password` alias as the `prohibit-password` posture it resolves to.
fn non_password_reason(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("without-password") {
        format!(
            "root login is permitted without a password: the effective configuration reports 'permitrootlogin {value}', an alias for the 'prohibit-password' posture (root by key only). Set 'permitrootlogin no' for review unless key-based root access is required."
        )
    } else {
        format!(
            "root login is permitted without a password: the effective configuration reports 'permitrootlogin {value}' (root by key only). Set 'permitrootlogin no' for review unless key-based root access is required."
        )
    }
}

/// Parse an effective `sshd` dump or config text into a directive map, keyed by the
/// lowercased directive name with the remainder of the line as the value. Blank
/// lines and `#` comments are skipped.
fn parse_directives(raw: &str) -> BTreeMap<String, String> {
    let mut directives = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(name) = parts.next() else {
            continue;
        };
        let value = parts.next().unwrap_or("").trim().to_string();
        directives.insert(name.to_ascii_lowercase(), value);
    }
    directives
}

/// Run `sshd -T` and return its effective dump when it exits successfully.
fn run_sshd_effective() -> Option<String> {
    let output = std::process::Command::new("sshd").arg("-T").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Read `sshd_config` and its `sshd_config.d` drop-ins, returning the merged text
/// and whether an `Include` could not be read. `None` when the base file is
/// unreadable.
fn read_config_with_drop_ins() -> Option<(String, bool)> {
    let base = std::fs::read_to_string(SSHD_CONFIG_LOCATOR).ok()?;
    let mut merged = base.clone();
    // Any `Include` other than the standard `sshd_config.d` drop-in directory is not
    // merged by this fallback, so a directive could hide inside it; flag it unresolved
    // up front so the graded rules never treat that gap as a clean PASS.
    let mut unresolved_include = has_unmerged_include(&base);
    if references_drop_in_dir(&base) {
        match std::fs::read_dir("/etc/ssh/sshd_config.d") {
            Ok(entries) => {
                let mut paths: Vec<_> = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
                    .collect();
                paths.sort();
                for path in paths {
                    match std::fs::read_to_string(&path) {
                        Ok(text) => {
                            merged.push('\n');
                            merged.push_str(&text);
                        }
                        Err(_) => unresolved_include = true,
                    }
                }
            }
            Err(_) => unresolved_include = true,
        }
    }
    Some((merged, unresolved_include))
}

/// Whether the base config references an `Include` of the drop-in directory.
fn references_drop_in_dir(base: &str) -> bool {
    base.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .any(|line| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with("include") && lower.contains("sshd_config.d")
        })
}

/// Whether the base config has an `Include` this fallback does not merge — anything
/// other than the standard `sshd_config.d` drop-in directory. Such an include may
/// carry directives the fallback never sees, so its presence marks the parse as
/// incomplete. The primary `sshd -T` path resolves every include natively and never
/// reaches this code.
fn has_unmerged_include(base: &str) -> bool {
    base.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.to_ascii_lowercase().starts_with("include"))
        .any(|line| !line.to_ascii_lowercase().contains("sshd_config.d"))
}

/// Whether an SSH server is present on the host: an `sshd` binary on `PATH` or a
/// configuration file on disk.
fn sshd_present() -> bool {
    std::path::Path::new(SSHD_CONFIG_LOCATOR).exists() || binary_on_path("sshd")
}

/// Whether `name` resolves to a file on any `PATH` entry.
fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
}
