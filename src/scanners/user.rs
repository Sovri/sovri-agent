// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The Linux user scanner: the agent's second scanner.
//!
//! [`UserScanner`] captures the host's account state — the `passwd` base, the
//! `shadow` lock / password / expiration state, `group` and `sudoers` privilege
//! grants, and last-login times — into a [`UserSnapshot`], then evaluates it as
//! catalogued rules through the engine as a [`sovri_sdk::RuleEvaluator`].
//! Acquisition ([`UserSnapshot::acquire`]) reads the host with the standard
//! library only; evaluation is a pure function of the captured snapshot, so a
//! test injects a fixture account snapshot and never touches real accounts.
//!
//! Status follows the rule's result policy, mirroring the `SystemScanner` mould:
//! the single-root and no-empty-password rules carry a fail policy, the dormant
//! and privileged-expected rules a warn policy, so the same `finding` maps to
//! `FAIL` or `WARNING` from the catalogue. Because the source files hold secrets,
//! account evidence is classified `Sensitive` and `shadow` evidence `Secret`;
//! both drop the raw excerpt, so account identity travels as evidence keys and
//! reasons, and no password hash ever appears in evidence. A reason describes the
//! technical situation and never asserts a legal conclusion.

// `UserScanner` / `UserSnapshot` / `UserPolicy` intentionally echo their module
// name, as `SystemScanner` does in the sibling `system` module.
#![allow(clippy::module_name_repetitions)]

use std::fs;

use sovri_sdk::{Evaluation, ExecutionFailure, RuleContext, RuleEvaluator, Target};

use super::AcquireError;
use crate::evidence::{Classification, Evidence, EvidenceKind, EvidenceLog};

/// The inventory rule: classify accounts and carry the inventory as evidence.
pub const INVENTORY_RULE: &str = "host.account.inventory";
/// The fail-policy rule: root must be the only uid-0 account.
pub const SINGLE_ROOT_RULE: &str = "host.account.single-root";
/// The fail-policy rule: no active account may log in without a password.
pub const NO_EMPTY_PASSWORD_RULE: &str = "host.account.no-empty-password";
/// The warn-policy rule: an eligible account dormant beyond the threshold.
pub const DORMANT_ACCOUNT_RULE: &str = "host.account.dormant";
/// The warn-policy rule: a privileged account outside the expected set.
pub const PRIVILEGED_EXPECTED_RULE: &str = "host.account.privileged-expected";

/// The locator every `passwd`-sourced evidence record anchors on.
pub const PASSWD_LOCATOR: &str = "/etc/passwd";
/// The locator every `shadow`-sourced evidence record anchors on.
pub const SHADOW_LOCATOR: &str = "/etc/shadow";
/// The locator `group`-sourced privilege evidence anchors on.
pub const GROUP_LOCATOR: &str = "/etc/group";
/// The locator `sudoers`-sourced privilege evidence anchors on.
pub const SUDOERS_LOCATOR: &str = "/etc/sudoers";

/// The non-login shells that mark an account as unable to start an interactive
/// session, so it is a system account and never a passwordless-login finding.
const NON_LOGIN_SHELLS: [&str; 5] = [
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "",
];

/// How an account is classified from its uid and shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountClass {
    /// A human account: uid ≥ 1000 with an interactive login shell.
    Human,
    /// A system account, with the reason it is not a human account.
    System(SystemReason),
}

/// Why an account is classified as a system account rather than human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemReason {
    /// Its uid is below the 1000 human-account boundary.
    LowUid,
    /// Its shell is a non-login shell.
    NonLoginShell,
}

/// The lock state cross-checked from `shadow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// The account is not locked.
    Unlocked,
    /// The account is locked (a `!`, `*`, or `!!` `shadow` password field).
    Locked,
    /// The lock state is unknown because `shadow` could not be read.
    Undetermined,
}

/// One classified account in the [`UserScanner::account_inventory`].
#[derive(Debug, Clone)]
pub struct AccountRecord {
    name: String,
    uid: u32,
    class: AccountClass,
    lock: LockState,
}

impl AccountRecord {
    /// The account name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The account uid.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// How the account is classified.
    #[must_use]
    pub fn class(&self) -> AccountClass {
        self.class
    }

    /// The cross-checked lock state.
    #[must_use]
    pub fn lock(&self) -> LockState {
        self.lock
    }

    /// Whether the account is an active human account: classified human and not
    /// locked.
    #[must_use]
    pub fn is_active_human(&self) -> bool {
        self.class == AccountClass::Human && self.lock == LockState::Unlocked
    }
}

/// The `shadow` password field, which determines lock and passwordless state.
#[derive(Debug, Clone)]
enum PasswordState {
    /// A hashed password: the account has a usable password and is not locked.
    Hashed,
    /// An empty field: the account can authenticate with no password.
    Empty,
    /// A `!`, `*`, or `!!` field: the account is locked.
    Locked,
}

/// A last-login observation for an account.
#[derive(Debug, Clone, Copy)]
enum LastLogin {
    /// The account last logged in this many days before the snapshot reference.
    DaysBefore(u32),
    /// The account has never logged in (no `lastlog` entry).
    Never,
    /// The last login could not be determined (host acquisition without a
    /// `lastlog` read); it does not, on its own, mark an account dormant.
    Undetermined,
}

/// The `shadow`-sourced state for one account.
#[derive(Debug, Clone)]
struct ShadowEntry {
    password: PasswordState,
    last_login: LastLogin,
    /// Whether the account's `shadow` expiry date has passed.
    expiry_passed: bool,
    /// The raw `shadow` line, kept only as the (redacted, dropped) excerpt so the
    /// redaction guard is exercised over the real secret-bearing line.
    raw_line: String,
}

/// A captured account: its `passwd` base plus `shadow`-sourced state when
/// `shadow` was readable.
#[derive(Debug, Clone)]
struct Account {
    name: String,
    uid: u32,
    shell: String,
    shadow: Option<ShadowEntry>,
}

/// How an account acquired its privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantSource {
    Uid0,
    SudoGroup,
    WheelGroup,
    SudoersGrant,
}

impl GrantSource {
    /// The human-facing grant source recorded in evidence and reasons.
    fn label(self) -> &'static str {
        match self {
            GrantSource::Uid0 => "uid 0",
            GrantSource::SudoGroup => "sudo group",
            GrantSource::WheelGroup => "wheel group",
            GrantSource::SudoersGrant => "sudoers.d grant",
        }
    }

    /// The locator the grant is anchored on.
    fn locator(self) -> &'static str {
        match self {
            GrantSource::Uid0 => PASSWD_LOCATOR,
            GrantSource::SudoGroup | GrantSource::WheelGroup => GROUP_LOCATOR,
            GrantSource::SudoersGrant => SUDOERS_LOCATOR,
        }
    }
}

/// A privileged-account grant observed on the host.
#[derive(Debug, Clone)]
struct PrivilegedGrant {
    name: String,
    source: GrantSource,
}

/// The catalogue-driven policy the scanner evaluates against: the inactivity
/// threshold and the expected privileged accounts. The scanner never hard-codes
/// these; they are supplied like the system scanner's support table.
#[derive(Debug, Clone)]
pub struct UserPolicy {
    inactivity_threshold_days: u32,
    expected_privileged: Vec<String>,
}

impl UserPolicy {
    /// A policy with `inactivity_threshold_days` and the `expected_privileged`
    /// account names.
    #[must_use]
    pub fn new<I, S>(inactivity_threshold_days: u32, expected_privileged: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        UserPolicy {
            inactivity_threshold_days,
            expected_privileged: expected_privileged.into_iter().map(Into::into).collect(),
        }
    }

    /// The inactivity threshold, in days: an eligible account whose last login
    /// predates it by more than this many days is dormant.
    #[must_use]
    pub fn inactivity_threshold_days(&self) -> u32 {
        self.inactivity_threshold_days
    }

    /// Whether `name` is an expected privileged account.
    #[must_use]
    pub fn expects_privileged(&self, name: &str) -> bool {
        self.expected_privileged.iter().any(|n| n == name)
    }
}

/// The captured host account state the [`UserScanner`] evaluates.
///
/// Build one from the host with [`UserSnapshot::acquire`], or from a fixture with
/// [`UserSnapshot::builder`]. Evaluation is a pure function of this value.
#[derive(Debug, Clone)]
pub struct UserSnapshot {
    accounts: Vec<Account>,
    shadow_readable: bool,
    privileged: Vec<PrivilegedGrant>,
}

impl UserSnapshot {
    /// Start building a snapshot from fixture facts.
    #[must_use]
    pub fn builder() -> UserSnapshotBuilder {
        UserSnapshotBuilder::default()
    }

    /// Acquire the host's account state offline: the `passwd` base, the `shadow`
    /// lock / password state, and `group` / `sudoers` privilege grants. Reads the
    /// host with the standard library only; it never touches the network.
    ///
    /// Last-login and expiry inputs are left undetermined on the host path: the
    /// `lastlog` read and its reference clock are wired by the agent runtime
    /// (MAT-125), so the offline acquisition never reads the wall clock here.
    ///
    /// # Errors
    /// Returns an [`AcquireError`] when the `passwd` base cannot be read.
    pub fn acquire() -> Result<Self, AcquireError> {
        let passwd = fs::read_to_string(PASSWD_LOCATOR)
            .map_err(|error| AcquireError::new(format!("cannot read the account base: {error}")))?;
        let shadow = fs::read_to_string(SHADOW_LOCATOR).ok();
        let shadow_readable = shadow.is_some();
        let accounts = parse_accounts(&passwd, shadow.as_deref());
        // Group / sudoers membership parsing is deferred to the agent runtime
        // (MAT-125); uid-0 privilege is derived at evaluation time from `passwd`.
        Ok(UserSnapshot {
            accounts,
            shadow_readable,
            privileged: Vec::new(),
        })
    }

    /// Every account's classified inventory record.
    fn inventory(&self) -> Vec<AccountRecord> {
        self.accounts
            .iter()
            .map(|account| AccountRecord {
                name: account.name.clone(),
                uid: account.uid,
                class: classify(account.uid, &account.shell),
                lock: self.lock_state(account),
            })
            .collect()
    }

    /// The lock state of `account`: undetermined when `shadow` was unreadable,
    /// otherwise read from its `shadow` password field.
    fn lock_state(&self, account: &Account) -> LockState {
        if !self.shadow_readable {
            return LockState::Undetermined;
        }
        match &account.shadow {
            Some(entry) if matches!(entry.password, PasswordState::Locked) => LockState::Locked,
            _ => LockState::Unlocked,
        }
    }
}

/// Builder for a fixture [`UserSnapshot`].
///
/// Accounts are added with [`account`](UserSnapshotBuilder::account); the `shadow`
/// state, last login, expiry, and privilege of each are then set by name.
#[derive(Debug, Default)]
pub struct UserSnapshotBuilder {
    accounts: Vec<Account>,
    shadow_readable: bool,
    privileged: Vec<PrivilegedGrant>,
}

impl UserSnapshotBuilder {
    /// Add a `passwd` account. It starts with a hashed, unlocked `shadow` entry
    /// and a recent last login, so it is safe until overridden.
    #[must_use]
    pub fn account(mut self, name: impl Into<String>, uid: u32, shell: impl Into<String>) -> Self {
        let name = name.into();
        let shell = shell.into();
        let raw_line = format!("{name}:x:{uid}:{uid}::/home/{name}:{shell}");
        self.accounts.push(Account {
            name,
            uid,
            shell,
            shadow: Some(ShadowEntry {
                password: PasswordState::Hashed,
                last_login: LastLogin::DaysBefore(0),
                expiry_passed: false,
                raw_line,
            }),
        });
        self.shadow_readable = true;
        self
    }

    /// Set the account's `shadow` password field to the hashed `hash`.
    ///
    /// The raw `shadow` line carrying the hash is kept as the evidence excerpt, so
    /// the redaction guard is proven over the real secret-bearing line.
    #[must_use]
    pub fn hashed(mut self, name: &str, hash: &str) -> Self {
        self.set_password(name, PasswordState::Hashed, hash);
        self
    }

    /// Set the account's `shadow` password field to empty (passwordless).
    #[must_use]
    pub fn empty_password(mut self, name: &str) -> Self {
        self.set_password(name, PasswordState::Empty, "");
        self
    }

    /// Set the account's `shadow` password field to the lock marker `marker`
    /// (`!`, `*`, or `!!`), locking it.
    #[must_use]
    pub fn locked(mut self, name: &str, marker: &str) -> Self {
        self.set_password(name, PasswordState::Locked, marker);
        self
    }

    /// Record the account's last login as `days` days before the reference date.
    #[must_use]
    pub fn last_login_days(mut self, name: &str, days: u32) -> Self {
        if let Some(entry) = self.shadow_of(name) {
            entry.last_login = LastLogin::DaysBefore(days);
        }
        self
    }

    /// Record that the account has never logged in.
    #[must_use]
    pub fn never_logged_in(mut self, name: &str) -> Self {
        if let Some(entry) = self.shadow_of(name) {
            entry.last_login = LastLogin::Never;
        }
        self
    }

    /// Record that the account's `shadow` expiry date has passed.
    #[must_use]
    pub fn expired(mut self, name: &str) -> Self {
        if let Some(entry) = self.shadow_of(name) {
            entry.expiry_passed = true;
        }
        self
    }

    /// Mark `shadow` unreadable: no account carries lock, password, or expiry
    /// state, so the rules that depend on `shadow` error.
    #[must_use]
    pub fn shadow_unreadable(mut self) -> Self {
        self.shadow_readable = false;
        for account in &mut self.accounts {
            account.shadow = None;
        }
        self
    }

    /// Record a `sudo` group membership.
    #[must_use]
    pub fn sudo_member(mut self, name: impl Into<String>) -> Self {
        self.grant(name, GrantSource::SudoGroup);
        self
    }

    /// Record a `wheel` group membership.
    #[must_use]
    pub fn wheel_member(mut self, name: impl Into<String>) -> Self {
        self.grant(name, GrantSource::WheelGroup);
        self
    }

    /// Record a `sudoers` / `sudoers.d` grant.
    #[must_use]
    pub fn sudoers_grant(mut self, name: impl Into<String>) -> Self {
        self.grant(name, GrantSource::SudoersGrant);
        self
    }

    /// Build the snapshot.
    #[must_use]
    pub fn build(self) -> UserSnapshot {
        UserSnapshot {
            accounts: self.accounts,
            shadow_readable: self.shadow_readable,
            privileged: self.privileged,
        }
    }

    /// Mutable access to an account's `shadow` entry by name, if it has one.
    fn shadow_of(&mut self, name: &str) -> Option<&mut ShadowEntry> {
        self.accounts
            .iter_mut()
            .find(|account| account.name == name)
            .and_then(|account| account.shadow.as_mut())
    }

    /// Set an account's password state and rewrite the raw `shadow` line.
    fn set_password(&mut self, name: &str, state: PasswordState, field: &str) {
        if let Some(entry) = self.shadow_of(name) {
            entry.raw_line = format!("{name}:{field}:19700:0:99999:7:::");
            entry.password = state;
        }
    }

    /// Record a privilege grant.
    fn grant(&mut self, name: impl Into<String>, source: GrantSource) {
        self.privileged.push(PrivilegedGrant {
            name: name.into(),
            source,
        });
    }
}

/// The Linux user scanner: it evaluates a captured [`UserSnapshot`] against a
/// catalogue [`UserPolicy`], dispatching each rule by id and recording redacted
/// evidence.
#[derive(Debug, Clone)]
pub struct UserScanner {
    snapshot: UserSnapshot,
    policy: UserPolicy,
    evidence: Vec<Evidence>,
}

impl UserScanner {
    /// A scanner over `snapshot`, evaluated against catalogue `policy`.
    ///
    /// Account, `shadow`, and privileged-inventory evidence is captured up front
    /// — every record redacted (`Sensitive` for accounts, `Secret` for `shadow`),
    /// so [`UserScanner::evidence_log`] can back a result and no raw value or
    /// password hash ever survives.
    #[must_use]
    pub fn new(snapshot: UserSnapshot, policy: UserPolicy) -> Self {
        let mut evidence = Vec::new();
        for account in &snapshot.accounts {
            push_evidence(
                &mut evidence,
                &account_evidence_id(&account.name),
                PASSWD_LOCATOR,
                format!("{} (uid {})", account.name, account.uid),
                Classification::Sensitive,
                account_line(account),
            );
            if let Some(entry) = &account.shadow {
                push_evidence(
                    &mut evidence,
                    &shadow_evidence_id(&account.name),
                    SHADOW_LOCATOR,
                    account.name.clone(),
                    Classification::Secret,
                    entry.raw_line.clone(),
                );
            }
        }
        for (name, source) in snapshot_privileged(&snapshot) {
            push_evidence(
                &mut evidence,
                &privileged_evidence_id(&name),
                source.locator(),
                format!("{name} via {}", source.label()),
                Classification::Sensitive,
                format!("{name} granted via {}", source.label()),
            );
        }
        UserScanner {
            snapshot,
            policy,
            evidence,
        }
    }

    /// A scanner that acquires the host's account state, evaluated against
    /// `policy`.
    ///
    /// # Errors
    /// Returns an [`AcquireError`] when the account state cannot be captured.
    pub fn acquire(policy: UserPolicy) -> Result<Self, AcquireError> {
        Ok(UserScanner::new(UserSnapshot::acquire()?, policy))
    }

    /// The classified inventory of every account.
    #[must_use]
    pub fn account_inventory(&self) -> Vec<AccountRecord> {
        self.snapshot.inventory()
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

    /// Evaluate the inventory rule: it never fails on its own, so it passes
    /// carrying every account-evidence record.
    fn evaluate_inventory(&self) -> Evaluation {
        let refs: Vec<String> = self
            .snapshot
            .accounts
            .iter()
            .map(|account| account_evidence_id(&account.name))
            .collect();
        Evaluation::satisfied().with_evidence_refs(refs)
    }

    /// Evaluate the single-root rule: more than one uid-0 account is a finding
    /// naming each and anchored on `passwd`; exactly one passes. Sourced from
    /// `passwd`, it evaluates even when `shadow` is unreadable.
    fn evaluate_single_root(&self) -> Evaluation {
        let roots: Vec<&Account> = self
            .snapshot
            .accounts
            .iter()
            .filter(|account| account.uid == 0)
            .collect();
        if roots.len() <= 1 {
            return Evaluation::satisfied();
        }
        let names = join_names(roots.iter().map(|account| account.name.as_str()));
        let refs: Vec<String> = roots
            .iter()
            .map(|account| account_evidence_id(&account.name))
            .collect();
        Evaluation::finding()
            .with_evidence_refs(refs)
            .with_targets([Target::file(PASSWD_LOCATOR)])
            .with_detail(format!(
                "more than one account has uid 0 ({names}); root must be the only uid-0 account"
            ))
    }

    /// Evaluate the no-empty-password rule: an account that is not locked, has a
    /// login shell, and whose `shadow` password field is empty can log in with no
    /// password — a finding. An unreadable `shadow` is an execution failure, so
    /// the rule errors rather than passing.
    ///
    /// # Errors
    /// Returns an [`ExecutionFailure`] when `shadow` could not be read.
    fn evaluate_no_empty_password(&self) -> Result<Evaluation, ExecutionFailure> {
        if !self.snapshot.shadow_readable {
            return Err(ExecutionFailure::new(
                "the shadow file could not be read, so account passwords cannot be evaluated",
            ));
        }
        let offending: Vec<&Account> = self
            .snapshot
            .accounts
            .iter()
            .filter(|account| is_passwordless_login(account))
            .collect();
        if offending.is_empty() {
            return Ok(Evaluation::satisfied());
        }
        let names = join_names(offending.iter().map(|account| account.name.as_str()));
        let refs: Vec<String> = offending
            .iter()
            .map(|account| account_evidence_id(&account.name))
            .collect();
        Ok(Evaluation::finding()
            .with_evidence_refs(refs)
            .with_targets([Target::file(SHADOW_LOCATOR)])
            .with_detail(format!(
                "{names} can log in without a password (an empty shadow password field on an unlocked login account)"
            )))
    }

    /// Evaluate the dormant-account rule: an eligible account (login shell, not
    /// locked) that is inactive beyond the threshold, has never logged in, or has
    /// passed its expiry is a finding; otherwise it passes. It never fails to
    /// execute.
    fn evaluate_dormant(&self) -> Evaluation {
        let mut findings = Vec::new();
        for account in &self.snapshot.accounts {
            if !self.is_dormancy_eligible(account) {
                continue;
            }
            if let Some(entry) = &account.shadow {
                if let Some(reason) = self.dormancy_reason(&account.name, entry) {
                    findings.push((account.name.as_str(), reason));
                }
            }
        }
        if findings.is_empty() {
            return Evaluation::satisfied();
        }
        let refs: Vec<String> = findings
            .iter()
            .map(|(name, _)| account_evidence_id(name))
            .collect();
        let detail = findings
            .iter()
            .map(|(_, reason)| reason.clone())
            .collect::<Vec<_>>()
            .join("; ");
        Evaluation::finding()
            .with_evidence_refs(refs)
            .with_targets([Target::file(PASSWD_LOCATOR)])
            .with_detail(detail)
    }

    /// Evaluate the privileged-expected rule: a privileged account outside the
    /// expected set is a finding; the privileged inventory is carried as evidence
    /// either way. It never fails to execute.
    fn evaluate_privileged(&self) -> Evaluation {
        let privileged = snapshot_privileged(&self.snapshot);
        let refs: Vec<String> = privileged
            .iter()
            .map(|(name, _)| privileged_evidence_id(name))
            .collect();
        let unexpected: Vec<&str> = privileged
            .iter()
            .filter(|(name, _)| !self.policy.expects_privileged(name))
            .map(|(name, _)| name.as_str())
            .collect();
        if unexpected.is_empty() {
            return Evaluation::satisfied().with_evidence_refs(refs);
        }
        let names = join_names(unexpected.iter().copied());
        Evaluation::finding()
            .with_evidence_refs(refs)
            .with_detail(format!(
                "{names} is an unexpected privileged account outside the expected set"
            ))
    }

    /// Whether `account` is eligible for the dormancy check: it has a login shell
    /// and is not locked.
    fn is_dormancy_eligible(&self, account: &Account) -> bool {
        has_login_shell(&account.shell) && self.snapshot.lock_state(account) == LockState::Unlocked
    }

    /// The dormancy finding reason for `entry`, if any signal warns.
    fn dormancy_reason(&self, name: &str, entry: &ShadowEntry) -> Option<String> {
        if let LastLogin::DaysBefore(days) = entry.last_login {
            if days > self.policy.inactivity_threshold_days {
                return Some(format!(
                    "{name} is dormant beyond the {}-day threshold (last login {days} days ago)",
                    self.policy.inactivity_threshold_days
                ));
            }
        }
        if matches!(entry.last_login, LastLogin::Never) {
            return Some(format!(
                "{name} has never logged in and is treated as dormant"
            ));
        }
        if entry.expiry_passed {
            return Some(format!(
                "{name} is expired and its access should be reviewed"
            ));
        }
        None
    }
}

impl RuleEvaluator for UserScanner {
    fn evaluate(&self, context: &RuleContext<'_>) -> Result<Evaluation, ExecutionFailure> {
        match context.rule().id() {
            INVENTORY_RULE => Ok(self.evaluate_inventory()),
            SINGLE_ROOT_RULE => Ok(self.evaluate_single_root()),
            NO_EMPTY_PASSWORD_RULE => self.evaluate_no_empty_password(),
            DORMANT_ACCOUNT_RULE => Ok(self.evaluate_dormant()),
            PRIVILEGED_EXPECTED_RULE => Ok(self.evaluate_privileged()),
            other => Err(ExecutionFailure::new(format!(
                "no user-scanner rule is registered for '{other}'"
            ))),
        }
    }
}

/// Classify an account from its uid and shell. A human account is uid ≥ 1000 with
/// an interactive login shell; a low uid takes precedence in the reason.
fn classify(uid: u32, shell: &str) -> AccountClass {
    if uid < 1000 {
        AccountClass::System(SystemReason::LowUid)
    } else if !has_login_shell(shell) {
        AccountClass::System(SystemReason::NonLoginShell)
    } else {
        AccountClass::Human
    }
}

/// Whether `shell` is an interactive login shell (not a non-login shell).
fn has_login_shell(shell: &str) -> bool {
    !NON_LOGIN_SHELLS.contains(&shell)
}

/// Whether `account` is a passwordless login account: a login shell and an empty
/// `shadow` password field (an empty field is never locked).
fn is_passwordless_login(account: &Account) -> bool {
    has_login_shell(&account.shell)
        && matches!(
            account.shadow.as_ref().map(|entry| &entry.password),
            Some(PasswordState::Empty)
        )
}

/// The evidence id for an account's `passwd` record.
fn account_evidence_id(name: &str) -> String {
    format!("host.account.{name}")
}

/// The evidence id for an account's `shadow` record.
fn shadow_evidence_id(name: &str) -> String {
    format!("host.shadow.{name}")
}

/// The evidence id for a privileged account's record.
fn privileged_evidence_id(name: &str) -> String {
    format!("host.privileged.{name}")
}

/// The synthesized `passwd` line kept as the (redacted, dropped) account excerpt.
fn account_line(account: &Account) -> String {
    format!(
        "{}:x:{}:{}::/home/{}:{}",
        account.name, account.uid, account.uid, account.name, account.shell
    )
}

/// Build a redacted evidence record and push it, ignoring a builder error (a
/// blank required field would be a scanner bug, not a runtime condition).
fn push_evidence(
    evidence: &mut Vec<Evidence>,
    id: &str,
    locator: &str,
    key: String,
    classification: Classification,
    excerpt: String,
) {
    if let Ok(record) = Evidence::builder()
        .id(id)
        .kind(EvidenceKind::Config)
        .locator(locator)
        .key(key)
        .classification(classification)
        .content(excerpt.into_bytes())
        .build()
    {
        evidence.push(record);
    }
}

/// Append `name`/`source` to `privileged` unless the name is already present.
fn push_privileged(privileged: &mut Vec<(String, GrantSource)>, name: &str, source: GrantSource) {
    if !privileged.iter().any(|(existing, _)| existing == name) {
        privileged.push((name.to_string(), source));
    }
}

/// Every privileged account: each uid-0 account plus the observed grants, in a
/// deterministic order, de-duplicated by name (the first grant source wins).
fn snapshot_privileged(snapshot: &UserSnapshot) -> Vec<(String, GrantSource)> {
    let mut privileged: Vec<(String, GrantSource)> = Vec::new();
    for account in &snapshot.accounts {
        if account.uid == 0 {
            push_privileged(&mut privileged, &account.name, GrantSource::Uid0);
        }
    }
    for grant in &snapshot.privileged {
        push_privileged(&mut privileged, &grant.name, grant.source);
    }
    privileged
}

/// Join account names as `a, b, c`, preserving order.
fn join_names<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names.collect::<Vec<_>>().join(", ")
}

/// Parse `passwd`, enriching each account with its `shadow` state when `shadow`
/// content is available.
fn parse_accounts(passwd: &str, shadow: Option<&str>) -> Vec<Account> {
    let shadow_lines = shadow.map(parse_shadow);
    passwd
        .lines()
        .filter_map(parse_passwd_line)
        .map(|(name, uid, shell)| {
            let shadow = shadow_lines.as_ref().and_then(|entries| {
                entries
                    .iter()
                    .find(|(entry_name, _)| entry_name == &name)
                    .map(|(_, entry)| entry.clone())
            });
            Account {
                name,
                uid,
                shell,
                shadow,
            }
        })
        .collect()
}

/// Parse one `passwd` line into its name, uid, and shell.
fn parse_passwd_line(line: &str) -> Option<(String, u32, String)> {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 7 {
        return None;
    }
    let uid = fields[2].parse::<u32>().ok()?;
    Some((fields[0].to_string(), uid, fields[6].to_string()))
}

/// Parse `shadow` into per-account entries. The reference-relative last login and
/// expiry are undetermined here; the agent runtime supplies them (MAT-125).
fn parse_shadow(shadow: &str) -> Vec<(String, ShadowEntry)> {
    shadow
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 2 {
                return None;
            }
            let name = fields[0].to_string();
            let field = fields[1];
            let password = classify_password_field(field);
            Some((
                name,
                ShadowEntry {
                    password,
                    last_login: LastLogin::Undetermined,
                    expiry_passed: false,
                    raw_line: line.to_string(),
                },
            ))
        })
        .collect()
}

/// Classify a `shadow` password field: empty is passwordless, a lock marker is
/// locked, anything else is a hashed password.
fn classify_password_field(field: &str) -> PasswordState {
    if field.is_empty() {
        PasswordState::Empty
    } else if field == "!" || field == "*" || field == "!!" {
        PasswordState::Locked
    } else {
        PasswordState::Hashed
    }
}
