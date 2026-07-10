// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 -- SQLite-backed exports do not execute host scanners or acquisition. Covers #363.

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
const EVIDENCE_LOCATOR: &str = "dist/main.js";
const SIGNING_SEED: [u8; 32] = [7; 32];
const FORMATS: [&str; 3] = ["PDF", "SpreadsheetML", "signed JSON"];
const HOST_SCANNER_PREFIXES: [&str; 4] = ["host.os.", "host.user.", "host.docker.", "host.ssh."];

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
            "sovri-agent-mat98-r08-no-scanners-{}-{now}-{unique}",
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
fn exporting_from_sqlite_does_not_execute_host_scanners() {
    let fixture = TempFixture::new();
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");
    database
        .write_completed_corpus(
            &Corpus::new(EXECUTED_AT)
                .with_run_id(RUN_ID)
                .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, "")
                .with_control(FRAMEWORK_ID, CONTROL_ID, "", "major", 8, "")
                .with_evidence(EVIDENCE_ID, EVIDENCE_LOCATOR),
        )
        .expect("the consent corpus write succeeds");

    let runs_before = database.query_runs().expect("runs can be queried");
    let evidence_before = database
        .query_evidence("id", EVIDENCE_ID)
        .expect("evidence can be queried");

    for format in FORMATS {
        // When the operator exports "<format>" for run "shopfront-2026-06-24" from SQLite.
        let artifact = database
            .export_run(format, RUN_ID, &SIGNING_SEED)
            .expect("the persisted corpus export succeeds");

        // Then no host scanner is executed.
        let text = String::from_utf8_lossy(&artifact);
        for prefix in HOST_SCANNER_PREFIXES {
            assert!(
                !text.contains(prefix),
                "the {format} artifact must not contain scanner-derived {prefix} records"
            );
        }

        // And no scan acquisition path is invoked.
        assert_eq!(
            database.query_runs().expect("runs remain queryable"),
            runs_before,
            "the {format} export does not acquire and append a run"
        );
        assert_eq!(
            database
                .query_evidence("id", EVIDENCE_ID)
                .expect("evidence remains queryable"),
            evidence_before,
            "the {format} export does not acquire or replace evidence"
        );
        assert!(
            database
                .query_results(RUN_ID, CONTROL_ID, "PASS")
                .expect("results remain queryable")
                .is_empty(),
            "the {format} export does not inject scanner results"
        );

        // And the artifact is reconstructed only from SQLite metadata and linked evidence records.
        for persisted_value in [
            RUN_ID,
            FRAMEWORK_ID,
            FRAMEWORK_VERSION,
            CONTROL_ID,
            EVIDENCE_ID,
        ] {
            assert!(
                text.contains(persisted_value),
                "the {format} artifact is missing persisted value {persisted_value}"
            );
        }
    }
}
