// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 -- a missing `SQLite` corpus is never rebuilt from host scanners. Covers #364.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::{LocalDatabase, LocalDatabaseError};

const MISSING_RUN_ID: &str = "missing-2026-06-24";
const SIGNING_SEED: [u8; 32] = [7; 32];

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
            "sovri-agent-mat98-r08-missing-corpus-{}-{now}-{unique}",
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
fn a_missing_sqlite_corpus_is_not_silently_rebuilt_by_scanning_the_host() {
    let fixture = TempFixture::new();
    let database = LocalDatabase::open(fixture.database_path()).expect("the local database opens");

    // Given run "missing-2026-06-24" is not present in SQLite.
    assert!(database
        .query_run(MISSING_RUN_ID)
        .expect("the missing run can be queried")
        .is_empty());

    // When the operator exports "PDF" for run "missing-2026-06-24" from SQLite.
    let error = database
        .export_run("PDF", MISSING_RUN_ID, &SIGNING_SEED)
        .expect_err("the missing run export must fail");

    // Then the export fails with a missing run error.
    assert!(
        matches!(error, LocalDatabaseError::MissingRun(run_id) if run_id == MISSING_RUN_ID),
        "the export reports the exact missing run"
    );

    // And no host scanner is executed.
    assert!(
        database
            .query_evidence("control", "host.ssh.permit-root-login")
            .expect("scanner evidence can be queried")
            .is_empty(),
        "the failed export does not persist scanner evidence"
    );

    // And no new run is inserted into SQLite.
    assert!(
        database
            .query_runs()
            .expect("runs can be queried")
            .is_empty(),
        "the database remains empty after the failed export"
    );
}
