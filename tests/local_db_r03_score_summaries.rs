// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 -- score summaries are persisted with the run. Covers issue #342.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::{LocalDatabase, ScoreSummaryRecord};
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{ControlResult, Status};

const MIXED_RUN: &str = "mixed-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const GDPR_FRAMEWORK: &str = "gdpr-eprivacy";
const GDPR_VERSION: &str = "2016-679";
const GDPR_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const ISO_FRAMEWORK: &str = "iso-27001";
const ISO_VERSION: &str = "2022";
const ISO_URL: &str = "https://www.iso.org/standard/27001";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const CONSENT_TITLE: &str = "Prior consent for tracker access";
const CONSENT_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const SSH_CONTROL: &str = "host.ssh.permit-root-login";
const SSH_TITLE: &str = "Disallow SSH root login";
const SSH_REFERENCE: &str = "iso-27001:2022:A.8.2";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const SSH_RULE: &str = "host.ssh.detect-permit-root-login";
const PUBLIC_EVIDENCE_ID: &str = "ev-0001";
const SENSITIVE_EVIDENCE_ID: &str = "ev-0008";
const PUBLIC_EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SENSITIVE_EVIDENCE_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct TempDatabase {
    root: PathBuf,
    db_path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r03-score-{}-{now}-{unique}",
            std::process::id()
        ));
        TempDatabase {
            db_path: root.join("tmp").join("sovri-mat-98.db"),
            root,
        }
    }

    fn path(&self) -> &Path {
        &self.db_path
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn score_summaries_are_persisted_with_the_run() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // When the completed corpus "mixed-2026-06-24" is written to SQLite.
    local_database
        .write_completed_corpus(&mixed_completed_corpus())
        .expect("the completed corpus is written to SQLite");

    let summaries = local_database
        .score_summaries_for_run(MIXED_RUN)
        .expect("score summaries can be queried for the run");

    // Then the score summary for framework "gdpr-eprivacy" can be retrieved.
    summaries
        .iter()
        .find(|summary| summary.framework_id() == GDPR_FRAMEWORK)
        .expect("the gdpr-eprivacy score summary can be retrieved");

    // And the score summary for framework "iso-27001" can be retrieved.
    summaries
        .iter()
        .find(|summary| summary.framework_id() == ISO_FRAMEWORK)
        .expect("the iso-27001 score summary can be retrieved");

    // And the score summary includes counts for statuses "PASS", "FAIL", and "WARNING".
    let pass_count: u32 = summaries.iter().map(ScoreSummaryRecord::pass_count).sum();
    let fail_count: u32 = summaries.iter().map(ScoreSummaryRecord::fail_count).sum();
    let warning_count: u32 = summaries
        .iter()
        .map(ScoreSummaryRecord::warning_count)
        .sum();
    assert_eq!(pass_count, 1, "PASS");
    assert_eq!(fail_count, 1, "FAIL");
    assert_eq!(warning_count, 1, "WARNING");
}

#[test]
fn score_summaries_for_unwritten_run_are_empty() {
    let database = TempDatabase::new();
    let local_database = LocalDatabase::open(database.path()).expect("the local database opens");

    let summaries = local_database
        .score_summaries_for_run(MIXED_RUN)
        .expect("score summaries can be queried before any write");

    assert!(summaries.is_empty());
}

#[test]
fn temp_database_removes_directory_on_drop() {
    let database = TempDatabase::new();
    let root = database.root().to_owned();
    LocalDatabase::open(database.path()).expect("the local database opens");
    assert!(root.exists());

    drop(database);

    assert!(!root.exists());
}

fn mixed_completed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN)
        .with_framework(GDPR_FRAMEWORK, GDPR_VERSION, GDPR_URL)
        .with_framework(ISO_FRAMEWORK, ISO_VERSION, ISO_URL)
        .with_control(
            GDPR_FRAMEWORK,
            CONSENT_CONTROL,
            CONSENT_TITLE,
            "major",
            8,
            CONSENT_REFERENCE,
        )
        .with_control(
            ISO_FRAMEWORK,
            SSH_CONTROL,
            SSH_TITLE,
            "minor",
            8,
            SSH_REFERENCE,
        )
        .with_control_result(
            GDPR_FRAMEWORK,
            control_result(
                CONSENT_CONTROL,
                TRACKER_RULE,
                "major",
                Status::Fail,
                PUBLIC_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            GDPR_FRAMEWORK,
            control_result(
                CONSENT_CONTROL,
                CMP_RULE,
                "major",
                Status::Pass,
                PUBLIC_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            ISO_FRAMEWORK,
            control_result(
                SSH_CONTROL,
                SSH_RULE,
                "minor",
                Status::Warning,
                SENSITIVE_EVIDENCE_ID,
            ),
        )
        .with_evidence_digest(
            PUBLIC_EVIDENCE_ID,
            "file",
            "dist/main.js",
            PUBLIC_EVIDENCE_DIGEST,
        )
        .with_classified_evidence(
            SENSITIVE_EVIDENCE_ID,
            "config",
            "config/users.yaml:12",
            Classification::Sensitive,
            SENSITIVE_EVIDENCE_DIGEST,
        )
}

fn control_result(
    control_id: &str,
    rule_id: &str,
    severity: &str,
    status: Status,
    evidence_id: &str,
) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity(severity)
        .weight(8)
        .evidence_refs([evidence_id])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the completed corpus run.");
    }
    builder
        .build()
        .expect("the completed corpus fixture result validates")
}
