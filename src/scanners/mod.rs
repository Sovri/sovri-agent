// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Scanners: the agent's host-acquisition / pure-evaluation split, and the
//! rule-id registry that dispatches each rule to its scanner behind a
//! [`sovri_sdk::RuleEvaluator`].

use std::collections::BTreeMap;
use std::fmt;

use sovri_sdk::{Evaluation, ExecutionFailure, RuleContext, RuleEvaluator};

pub mod selftest;
pub mod ssh;
pub mod system;
pub mod user;

/// The verdict a scanner reaches from a captured snapshot, in the agent's own
/// vocabulary. It is mapped to a [`sovri_sdk::Evaluation`] at the registry
/// boundary, so a scanner's evaluation stays independent of SDK status policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The control looks satisfied from the snapshot.
    Satisfied,
    /// The snapshot shows a finding — the control looks unmet.
    Finding,
}

impl Verdict {
    /// Converts this verdict into the SDK [`Evaluation`] the engine consumes.
    #[must_use]
    pub fn into_evaluation(self) -> Evaluation {
        match self {
            Self::Satisfied => Evaluation::satisfied(),
            Self::Finding => Evaluation::finding(),
        }
    }
}

/// An error acquiring host state for a scanner.
#[derive(Debug)]
pub struct AcquireError {
    message: String,
}

impl AcquireError {
    /// Creates an acquisition error with a human-readable message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AcquireError {}

/// A compliance scanner: it acquires host state into a snapshot, then evaluates
/// that snapshot with pure logic.
///
/// The two halves are separable so evaluation can run over an injected fixture
/// snapshot in tests, never touching the host (the `ConsentScan::scan` mould
/// from the SDK). Acquisition performs host I/O; evaluation does not.
pub trait Scanner {
    /// The captured host state this scanner evaluates.
    type Snapshot;

    /// Acquires host state into a snapshot (`std::fs` / `std::process::Command`).
    ///
    /// # Errors
    /// Returns an [`AcquireError`] when the host cannot be read.
    fn acquire(&self) -> Result<Self::Snapshot, AcquireError>;

    /// Evaluates a captured snapshot with pure logic. It performs no host
    /// access, so a fixture snapshot yields the same verdict as a real one.
    fn evaluate(&self, snapshot: &Self::Snapshot) -> Verdict;
}

/// One registered scan: run it to produce an evaluation for the engine.
///
/// `Send + Sync` so the registry the V0.4 scanners plug into can cross threads.
type ScanRun = Box<dyn Fn() -> Result<Evaluation, ExecutionFailure> + Send + Sync>;

/// Maps rule ids to their scanners and dispatches each [`RuleContext`] to the
/// scanner registered for its rule id.
///
/// A rule with no registered scanner yields an [`ExecutionFailure`], which the
/// engine records as an `ERROR` result without aborting the run. The registry is
/// the [`sovri_sdk::RuleEvaluator`] the agent hands to
/// [`sovri_sdk::Engine::execute`].
#[derive(Default)]
pub struct Registry {
    runs: BTreeMap<String, ScanRun>,
}

impl Registry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a scanner for a rule id. When the rule runs, the scanner
    /// acquires host state and then evaluates it — the host path.
    pub fn register<S>(&mut self, rule_id: impl Into<String>, scanner: S)
    where
        S: Scanner + Send + Sync + 'static,
    {
        let run: ScanRun = Box::new(move || {
            let snapshot = scanner
                .acquire()
                .map_err(|error| ExecutionFailure::new(format!("acquisition failed: {error}")))?;
            Ok(scanner.evaluate(&snapshot).into_evaluation())
        });
        self.runs.insert(rule_id.into(), run);
    }

    /// Registers a scanner against a pre-captured snapshot for a rule id. The
    /// host is never read; the injected snapshot drives evaluation — the fixture
    /// path used in tests.
    pub fn register_with_snapshot<S>(
        &mut self,
        rule_id: impl Into<String>,
        scanner: S,
        snapshot: S::Snapshot,
    ) where
        S: Scanner + Send + Sync + 'static,
        S::Snapshot: Send + Sync + 'static,
    {
        let run: ScanRun = Box::new(move || Ok(scanner.evaluate(&snapshot).into_evaluation()));
        self.runs.insert(rule_id.into(), run);
    }
}

impl RuleEvaluator for Registry {
    fn evaluate(&self, context: &RuleContext<'_>) -> Result<Evaluation, ExecutionFailure> {
        let rule_id = context.rule().id();
        match self.runs.get(rule_id) {
            Some(run) => run(),
            None => Err(ExecutionFailure::new(format!(
                "no scanner registered for rule '{rule_id}'"
            ))),
        }
    }
}
