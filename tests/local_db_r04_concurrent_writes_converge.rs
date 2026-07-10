// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 -- concurrent writes of the same corpus converge to one logical run.
//! Covers issue #346.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const CONTROL_ID: &str = "consent.tracker.prior-consent";
const CONTROL_TITLE: &str = "Prior consent for tracker access";
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const EVIDENCE_ID: &str = "ev-0001";
const EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

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
            "sovri-agent-mat98-r04-concurrent-writes-{}-{now}-{unique}",
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
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn concurrent_writes_of_the_same_corpus_converge_to_one_logical_run() {
    let database = TempDatabase::new();
    LocalDatabase::open(database.path()).expect("the local database schema initializes");

    // When two operators write the "shopfront-2026-06-24" corpus to SQLite at the same time.
    let write_results = write_same_corpus_concurrently(database.path());

    // Then both write attempts finish without duplicate logical records.
    assert_eq!(
        write_results,
        [Ok(()), Ok(())],
        "both concurrent write attempts should finish successfully"
    );

    // And exactly 1 run row exists for "shopfront-2026-06-24".
    assert_eq!(run_row_count(database.path(), RUN_ID), 1);

    // And exactly 2 result rows exist for run "shopfront-2026-06-24".
    assert_eq!(result_row_count_for_run(database.path(), RUN_ID), 2);

    // And evidence digest "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" is stored once.
    assert_eq!(
        evidence_digest_row_count(database.path(), EVIDENCE_DIGEST),
        1
    );
}

fn write_same_corpus_concurrently(path: &Path) -> [Result<(), String>; 2] {
    let barrier = Arc::new(Barrier::new(2));
    let handles = [0, 1].map(|_| {
        let path = path.to_path_buf();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let mut local_database =
                LocalDatabase::open(&path).map_err(|error| error.to_string())?;
            local_database
                .write_completed_corpus(&consent_corpus())
                .map_err(|error| error.to_string())
        })
    });

    handles.map(|handle| {
        handle
            .join()
            .unwrap_or_else(|panic| Err(format!("writer thread panicked: {panic:?}")))
    })
}

fn consent_corpus() -> Corpus {
    let mut corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK_ID,
            CONTROL_ID,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        );
    for result in [
        control_result(TRACKER_RULE, Status::Fail),
        control_result(CMP_RULE, Status::Pass),
    ] {
        corpus = corpus.with_control_result(FRAMEWORK_ID, result);
    }
    corpus.with_evidence_digest(
        EVIDENCE_ID,
        "file",
        "shopfront/dist/main.js",
        EVIDENCE_DIGEST,
    )
}

fn control_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL_ID)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the shopfront consent run.");
    }
    builder
        .build()
        .expect("the shopfront consent result validates")
}

fn run_row_count(path: &Path, run_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .expect("run row count can be inspected")
}

fn result_row_count_for_run(path: &Path, run_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM control_results WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .expect("result row count can be inspected")
}

fn evidence_digest_row_count(path: &Path, digest: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM evidence_metadata WHERE digest = ?1",
            params![digest],
            |row| row.get(0),
        )
        .expect("evidence digest row count can be inspected")
}
