// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 -- every existing export path reads a persisted `SQLite` corpus. Covers #362.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::Corpus;

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const CONTROL_ID: &str = "consent.tracker.prior-consent";
const EVIDENCE_ID: &str = "ev-0001";
const SIGNING_SEED: [u8; 32] = [7; 32];
const FORMATS: [&str; 3] = ["PDF", "SpreadsheetML", "signed JSON"];

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

fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, "")
        .with_control(FRAMEWORK_ID, CONTROL_ID, "", "major", 8, "")
        .with_evidence(EVIDENCE_ID, "dist/main.js")
}
