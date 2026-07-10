// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 -- every existing export path reads a persisted `SQLite` corpus. Covers #362.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const CONTROL_ID: &str = "consent.tracker.prior-consent";
const EVIDENCE_ID: &str = "ev-0001";
const SIGNING_SEED: [u8; 32] = [7; 32];
const FORMATS: [&str; 3] = ["PDF", "SpreadsheetML", "signed JSON"];
const RULE_ID: &str = "consent.detect-trackers-without-consent-evidence";
const OTHER_RUN_ID: &str = "backoffice-2026-06-24";
const OTHER_FRAMEWORK_ID: &str = "iso27001";
const OTHER_CONTROL_ID: &str = "access.mfa";
const OTHER_RULE_ID: &str = "access.require-mfa";
const OTHER_EVIDENCE_ID: &str = "ev-9001";

struct TempFixture {
    root: PathBuf,
}

impl TempFixture {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r08-exports-{}-{now}-{unique}",
            std::process::id()
        ));
        TempFixture { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("tmp").join("sovri-mat-98.db")
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn export_a_persisted_corpus_through_each_existing_export_path() {
    let fixture = TempFixture::new();

    // Given an open local database at "./tmp/sovri-mat-98.db".
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");
    // And the "shopfront-2026-06-24" consent corpus has been written to SQLite.
    // And the corpus contains framework "gdpr-eprivacy" version "2016-679".
    // And the corpus contains control "consent.tracker.prior-consent".
    // And the corpus contains evidence "ev-0001" at "dist/main.js".
    database
        .write_completed_corpus(&consent_corpus())
        .expect("the consent corpus write succeeds");

    for format in FORMATS {
        // When the operator exports "<format>" for run "shopfront-2026-06-24" from SQLite.
        let artifact = database
            .export_run(format, RUN_ID, &SIGNING_SEED)
            .expect("the persisted corpus export succeeds");

        // Then a non-empty "<format>" artifact is produced.
        assert!(!artifact.is_empty(), "the {format} artifact has bytes");
        let text = String::from_utf8_lossy(&artifact);
        // And the artifact includes run "shopfront-2026-06-24".
        assert!(
            text.contains(RUN_ID),
            "the {format} artifact includes the run"
        );
        // And the artifact includes framework "gdpr-eprivacy" version "2016-679".
        assert!(
            text.contains(FRAMEWORK_ID) && text.contains(FRAMEWORK_VERSION),
            "the {format} artifact includes the framework and version"
        );
        // And the artifact includes control "consent.tracker.prior-consent".
        assert!(
            text.contains(CONTROL_ID),
            "the {format} artifact includes the control"
        );
        // And the artifact includes evidence id "ev-0001".
        assert!(
            text.contains(EVIDENCE_ID),
            "the {format} artifact includes the evidence id"
        );
    }
}

#[test]
fn export_rehydrates_results_without_leaking_another_runs_catalog() {
    let fixture = TempFixture::new();
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");
    database
        .write_completed_corpus(&result_corpus(
            RUN_ID,
            FRAMEWORK_ID,
            FRAMEWORK_VERSION,
            CONTROL_ID,
            RULE_ID,
            EVIDENCE_ID,
            Status::Fail,
        ))
        .expect("the requested corpus write succeeds");
    database
        .write_completed_corpus(&result_corpus(
            OTHER_RUN_ID,
            OTHER_FRAMEWORK_ID,
            "2022",
            OTHER_CONTROL_ID,
            OTHER_RULE_ID,
            OTHER_EVIDENCE_ID,
            Status::Pass,
        ))
        .expect("the unrelated corpus write succeeds");

    let artifact = database
        .export_run("signed JSON", RUN_ID, &SIGNING_SEED)
        .expect("the requested persisted corpus export succeeds");
    let text = String::from_utf8(artifact).expect("signed JSON is UTF-8");

    assert!(text.contains(&format!("\"rule_id\":\"{RULE_ID}\"")));
    assert!(text.contains("\"status\":\"FAIL\""));
    assert!(text.contains("\"gaps\":[{"));
    for unrelated in [
        OTHER_RUN_ID,
        OTHER_FRAMEWORK_ID,
        OTHER_CONTROL_ID,
        OTHER_RULE_ID,
        OTHER_EVIDENCE_ID,
    ] {
        assert!(
            !text.contains(unrelated),
            "the export excludes unrelated value {unrelated}"
        );
    }
}

fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, "")
        .with_control(FRAMEWORK_ID, CONTROL_ID, "", "major", 8, "")
        .with_evidence(EVIDENCE_ID, "dist/main.js")
}

#[allow(clippy::too_many_arguments)]
fn result_corpus(
    run_id: &str,
    framework_id: &str,
    framework_version: &str,
    control_id: &str,
    rule_id: &str,
    evidence_id: &str,
    status: Status,
) -> Corpus {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs([evidence_id])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Persisted result requires review.");
    }
    let result = builder.build().expect("the control result validates");

    Corpus::new(EXECUTED_AT)
        .with_run_id(run_id)
        .with_framework(framework_id, framework_version, "")
        .with_control(framework_id, control_id, "", "major", 8, "")
        .with_control_result(framework_id, result)
        .with_evidence(evidence_id, format!("dist/{run_id}.js"))
}
